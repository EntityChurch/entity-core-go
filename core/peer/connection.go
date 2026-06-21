package peer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/core/wire"
)

// Connection wraps a net.Conn and manages wire framing and connection state.
//
// Client side (created via Peer.Connect → PerformConnect):
//   - After handshake completes, a background reader goroutine demultiplexes
//     incoming EXECUTE_RESPONSE frames by request_id into per-request response
//     channels. Multiple Execute calls may be in flight concurrently; their
//     responses are matched by request_id (V7 wire contract).
//   - writeMu serializes envelope WRITES only — cheap, just prevents byte
//     interleaving on the wire; does NOT block readers.
//   - Per-request deadlines are enforced via select+timer at the caller; the
//     connection-wide net.Conn deadline is not used after handshake.
//
// Server side (created via accept → serve):
//   - The serve() loop reads incoming frames and dispatches them concurrently
//     in worker goroutines. SendEnvelope (responses) shares writeMu with any
//     client-side Execute calls — only the byte-write phase is serialized.
//   - The server side does NOT call Execute on its own Connection; outbound
//     dispatch from inside a server-side handler uses Peer.remoteExecute which
//     resolves to the pooled CLIENT-side Connection for the destination peer.
//
// Class G / F-WB28 fix: this multiplexed design replaces the previous
// single-pending-per-pooled-connection pattern, which deadlocked under
// bidirectional symmetric load — peer A's subscription engine held the
// outbound mutex on A's pooled connection to B while waiting for B's
// response; the handler processing B's inbound (on A's server side) then
// reentered A's pooled connection to B for a cross-peer fetch, blocking on
// the same held mutex. Workbench-go's STAGE-4 round-1 surfaced this at the
// canonical 2-peer bidirectional concurrent-write shape. See the
// stage-3 claim-amendment review and the Stage 4 round-1
// coordination memo §4.
type Connection struct {
	peer      *Peer
	conn      net.Conn
	connState *protocol.ConnectionState
	session   *Session
	debugLog  *log.Logger

	// writeMu serializes envelope writes on the wire (prevents byte
	// interleaving). Held briefly per write — does NOT span recv.
	writeMu sync.Mutex

	// Close synchronization. closed is read by Execute / SendEnvelope to
	// fail fast when the connection has been torn down.
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once

	// Client-side multiplexing state. Initialized via startReader after
	// PerformConnect completes; nil/closed on server-side connections that
	// never call PerformConnect.
	//
	// pending maps requestID → chan responseResult. Reader goroutine
	// LoadAndDeletes on response arrival; Execute Stores before send and
	// Deletes on early exit (timeout, ctx cancel, reader exit).
	//
	// readerDone closes when the reader goroutine exits; closeErr holds
	// the read-side error that triggered exit (or ErrConnClosed on Close).
	// Both are nil/zero on server-side connections.
	pending    sync.Map
	readerOnce sync.Once
	readerDone chan struct{}
	closeErr   error
}

func newConnection(p *Peer, conn net.Conn) *Connection {
	return &Connection{
		peer:       p,
		conn:       conn,
		connState:  protocol.NewConnectionState(),
		debugLog:   p.debugLog,
		readerDone: make(chan struct{}),
	}
}

func (c *Connection) debugf(format string, args ...any) {
	if c.debugLog != nil {
		c.debugLog.Printf(format, args...)
	}
}

// validateRecv validates all entity hashes in a received envelope. On mismatch,
// dumps full diagnostic info (data bytes, claimed vs recomputed hash, ECF hash
// input) to the debug log before returning the error.
func (c *Connection) validateRecv(label string, env entity.Envelope) error {
	if err := env.ValidateAll(); err != nil {
		if c.debugLog != nil {
			c.debugLog.Printf("[%s] hash mismatch in %s — dumping all entities:", c.conn.RemoteAddr(), label)
			c.debugLog.Printf("root:\n%s", env.Root.DiagnoseHash())
			for h, ent := range env.Included {
				c.debugLog.Printf("included[%s]:\n%s", h, ent.DiagnoseHash())
			}
		}
		return fmt.Errorf("validate %s: %w", label, err)
	}
	return nil
}

// Session returns the connection's session state (available after connect).
func (c *Connection) Session() *Session {
	return c.session
}

// ConnState returns the connection's handshake state.
func (c *Connection) ConnState() *protocol.ConnectionState {
	return c.connState
}

// SendEnvelope writes an envelope to the connection. Serialized on writeMu
// to prevent byte interleaving — does NOT block the read side. Multiple
// goroutines may call SendEnvelope concurrently; each frame writes atomically.
//
// Wire hooks (GUIDE-INSPECTABILITY v1.1 §2.1 #7) fire post-write with the
// raw CBOR frame bytes when registered on the owning peer.
func (c *Connection) SendEnvelope(env entity.Envelope) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if len(c.peer.wireHooks) == 0 {
		return wire.WriteEnvelope(c.conn, env)
	}
	// Encode once, write, then fire the hook with the same bytes. Avoids
	// double-encode cost in the observed-peer case.
	data, err := ecf.Encode(env)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}
	if err := wire.WriteFrame(c.conn, data); err != nil {
		return err
	}
	c.fireWireHooks(WireEvent{
		Direction:   WireOutbound,
		FrameBytes:  data,
		PeerAddress: c.conn.RemoteAddr().String(),
		RequestID:   bestEffortRequestID(env.Root),
		RootType:    env.Root.Type,
		Timestamp:   time.Now(),
	})
	return nil
}

// SendRawFrame writes pre-encoded envelope bytes verbatim as a length-prefixed
// frame. Used by the RELAY OutboundDispatcher at the terminal hop (§3.1.1):
// the inner envelope is opaque to the relay (§9 / §10.4); we copy bytes onto
// the destination's inbound frame without decoding or re-encoding so the
// destination sees the source's signed envelope exactly as on a direct
// connection.
//
// Wire hooks fire post-write with the bytes themselves; the RequestID /
// RootType fields are intentionally empty because the relay MUST NOT inspect
// the inner.
func (c *Connection) SendRawFrame(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := wire.WriteFrame(c.conn, data); err != nil {
		return err
	}
	if len(c.peer.wireHooks) > 0 {
		c.fireWireHooks(WireEvent{
			Direction:   WireOutbound,
			FrameBytes:  data,
			PeerAddress: c.conn.RemoteAddr().String(),
			Timestamp:   time.Now(),
		})
	}
	return nil
}

// RecvEnvelope reads and decodes an envelope from the connection.
// Hash validation is performed separately by the caller (serve, PerformConnect)
// so that diagnostic output can be produced on mismatch.
//
// After PerformConnect starts the client-side reader goroutine, callers MUST
// NOT call RecvEnvelope on a client connection — responses are demuxed
// through Execute's per-request response channels. RecvEnvelope remains
// callable from the server-side serve() loop and from PerformConnect's
// handshake phase.
//
// Wire hooks (GUIDE-INSPECTABILITY v1.1 §2.1 #7) fire post-decode with the
// raw CBOR frame bytes when registered on the owning peer.
func (c *Connection) RecvEnvelope() (entity.Envelope, error) {
	if len(c.peer.wireHooks) == 0 {
		return wire.ReadEnvelopeNoValidate(c.conn)
	}
	data, err := wire.ReadFrame(c.conn)
	if err != nil {
		return entity.Envelope{}, err
	}
	var env entity.Envelope
	if err := ecf.Decode(data, &env); err != nil {
		return entity.Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	c.fireWireHooks(WireEvent{
		Direction:   WireInbound,
		FrameBytes:  data,
		PeerAddress: c.conn.RemoteAddr().String(),
		RequestID:   bestEffortRequestID(env.Root),
		RootType:    env.Root.Type,
		Timestamp:   time.Now(),
	})
	return env, nil
}

// fireWireHooks invokes every registered wire hook with the event. Inline
// on the wire hot path — hooks MUST be fast.
func (c *Connection) fireWireHooks(evt WireEvent) {
	for _, h := range c.peer.wireHooks {
		h.Fn(evt)
	}
}

// Close closes the connection. Safe to call multiple times. Drains any
// pending client-side response channels with ErrConnClosed so blocked
// Execute callers unblock instead of hanging until their per-request
// deadline.
func (c *Connection) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	c.peer.removeConnection(c)

	// Close the underlying net.Conn first — this unblocks any in-flight
	// read in the reader goroutine, which then drives pending-response
	// cleanup via closeOnce in the reader's defer. If no reader is
	// running (server-side connection or never-handshaked client), we
	// still need to drain pending — closeOnce ensures it runs exactly
	// once regardless of who gets there first.
	err := c.conn.Close()
	c.closeOnce.Do(func() {
		if c.closeErr == nil {
			c.closeErr = ErrConnClosed
		}
		c.failPending(c.closeErr)
	})
	return err
}

// ErrConnClosed is returned to in-flight Execute callers when the
// connection is closed (either by an explicit Close or by the reader
// goroutine exiting on a wire-level read error).
var ErrConnClosed = fmt.Errorf("connection closed")

// failPending delivers err to every registered pending response channel
// and clears the map. Idempotent — second call finds an empty map.
func (c *Connection) failPending(err error) {
	c.pending.Range(func(k, v any) bool {
		c.pending.Delete(k)
		select {
		case v.(chan responseResult) <- responseResult{err: err}:
		default:
			// Channel was already delivered to (race with reader);
			// nothing more to do.
		}
		return true
	})
}

// responseResult carries one demuxed response from the reader goroutine
// to a waiting Execute caller. err is non-nil for connection-level
// failures (wire read error, validation error, connection closed); env
// is the response envelope on success.
type responseResult struct {
	env entity.Envelope
	err error
}

// startReader spawns the client-side multiplexed reader goroutine.
// Called from PerformConnect after the handshake completes; idempotent
// via readerOnce so accidental double-start is safe.
//
// The reader runs until the wire read errors (peer disconnected, framing
// error, or local Close closed the underlying net.Conn). On exit it:
//   - records the read-side error as closeErr (or ErrConnClosed if Close
//     beat it to the punch)
//   - drains pending response channels with closeErr so blocked callers
//     unblock with a meaningful error
//   - closes readerDone so any selecting caller sees the connection-gone
//     signal
func (c *Connection) startReader() {
	c.readerOnce.Do(func() {
		go c.reader()
	})
}

func (c *Connection) reader() {
	var exitErr error
	defer func() {
		c.closeOnce.Do(func() {
			if exitErr == nil {
				exitErr = ErrConnClosed
			}
			c.closeErr = exitErr
			c.failPending(exitErr)
		})
		close(c.readerDone)
	}()

	for {
		env, err := wire.ReadEnvelopeNoValidate(c.conn)
		if err != nil {
			exitErr = fmt.Errorf("connection read: %w", err)
			return
		}
		reqID, ok := responseRequestID(env)
		if !ok {
			// Frame doesn't carry a request_id — could be an unexpected
			// server-pushed envelope or a malformed response. Log and
			// drop; do not tear down the connection on a single bad
			// frame (the per-request deadline will fire for any caller
			// expecting this response).
			c.debugf("[%s] reader: response without request_id (type=%s); dropped", c.conn.RemoteAddr(), env.Root.Type)
			continue
		}
		ch, found := c.pending.LoadAndDelete(reqID)
		if !found {
			// Orphan response — no caller is waiting for this
			// request_id. Could be a late response after the caller's
			// deadline fired. Drop quietly with a debug log.
			c.debugf("[%s] reader: orphan response request_id=%q (caller deadline likely fired)", c.conn.RemoteAddr(), reqID)
			continue
		}
		// Validate on the reader goroutine — the caller's select wakes
		// once we deliver, so any validation cost is the same wall-clock
		// either way. Diagnostic output on mismatch still goes to the
		// debug log.
		var result responseResult
		if vErr := c.validateRecv("execute_response", env); vErr != nil {
			result = responseResult{err: vErr}
		} else {
			result = responseResult{env: env}
		}
		select {
		case ch.(chan responseResult) <- result:
		default:
			// Buffered chan with cap=1; this branch only fires if the
			// caller already received a result via another path (e.g.,
			// connection-closed shutdown raced ahead of the response).
			// Drop quietly.
		}
	}
}

// responseRequestID extracts the request_id from an EXECUTE_RESPONSE
// envelope. Returns ("", false) if the root entity isn't a recognizable
// response shape — the caller logs and drops.
func responseRequestID(env entity.Envelope) (string, bool) {
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return "", false
	}
	if respData.RequestID == "" {
		return "", false
	}
	return respData.RequestID, true
}

// IsClosed reports whether the connection has been closed (either via an
// explicit Close call or because the reader goroutine exited on a
// wire-level read error). Safe to call concurrently.
func (c *Connection) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// RemoteAddr returns the remote address.
func (c *Connection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// maxConcurrentHandlers bounds the number of in-flight inbound dispatches per
// connection. Holds the work in a buffered semaphore so a slow handler can't
// unbounded-queue inbound frames.
const maxConcurrentHandlers = 64

// serve handles incoming messages on a server-side connection.
//
// Frames received before the handshake completes (HELLO, AUTHENTICATE) are
// dispatched synchronously — they mutate connState and the protocol requires
// strict ordering. Once connState.Completed is true, subsequent frames are
// dispatched in worker goroutines so a long-running handler can't block the
// read loop. SendEnvelope is mutex-serialized, so concurrent worker responses
// interleave safely on the wire; the request_id field correlates each EXECUTE
// to its EXECUTE_RESPONSE so out-of-order replies are demuxed by the caller.
//
// This unblocks bidirectional P2P where each side dispatches outbound EXECUTEs
// from inside a handler — previously the symmetric case deadlocked because each
// side's serve loop couldn't read the other's outbound while busy in its own
// handler. See the workbench persistence-feedback review, Finding 9b.
func (c *Connection) serve(ctx context.Context) {
	var wg sync.WaitGroup
	defer func() {
		wg.Wait() // let in-flight handlers finish writing responses
		// Unregister §6.11 reentry inbound entry if one was registered
		// during this connection's lifetime. Idempotent and only deletes
		// when the registered entry is THIS connection (a newer inbound
		// from the same peer-id may have overwritten us first).
		if c.peer != nil && c.connState != nil && c.connState.RemotePeerID != "" {
			c.peer.unregisterInboundForReentry(c.connState.RemotePeerID, c)
		}
		c.debugf("[%s] connection closed", c.conn.RemoteAddr())
		c.Close()
	}()

	sem := make(chan struct{}, maxConcurrentHandlers)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		env, err := c.RecvEnvelope()
		if err != nil {
			c.debugf("[%s] recv error: %v", c.conn.RemoteAddr(), err)
			// V7 §4.10(a) (v7.75 §9.1 floor MUST): oversize frames must be
			// rejected with 413 payload_too_large before unbounded buffering. We caught
			// the length prefix in wire.ReadFrame so nothing past the prefix
			// was read. Emit a best-effort coded frame (empty request_id —
			// the body never reached us) before tearing down. Spec-allowed
			// shape per the handoff: "correlated by request_id if available,
			// else a coded frame + close".
			if errors.Is(err, ecerrors.ErrFrameTooLarge) {
				if respEnv, perr := buildPayloadTooLargeResponse(); perr == nil {
					_ = c.SendEnvelope(respEnv)
				}
			}
			return
		}
		c.debugf("[%s] <- envelope root_type=%s", c.conn.RemoteAddr(), env.Root.Type)
		if err := c.validateRecv("incoming", env); err != nil {
			c.debugf("[%s] %v", c.conn.RemoteAddr(), err)
			return
		}

		// Handshake frames mutate connState and require strict ordering.
		if !c.connState.Completed {
			respEnv, err := c.peer.dispatcher.DispatchEnvelope(ctx, env, c.connState)
			if err != nil {
				c.debugf("[%s] dispatch error: %v", c.conn.RemoteAddr(), err)
				continue
			}
			c.debugf("[%s] -> response root_type=%s", c.conn.RemoteAddr(), respEnv.Root.Type)
			if err := c.SendEnvelope(respEnv); err != nil {
				c.debugf("[%s] send error: %v", c.conn.RemoteAddr(), err)
				return
			}
			// V7 §6.11 reentry seam: once handshake completes, register the
			// inbound connection as the pooled outbound endpoint for the
			// remote peer-id. Any handler invoked over this connection that
			// originates outbound EXECUTE to the remote peer will then reuse
			// THIS connection (the substantive surface §10.2 / GUIDE-
			// CONFORMANCE §7a.2a verifies). Without this, outbound dispatch
			// requires a published transport profile + fresh dial — which the
			// validator-as-B case doesn't have (no listener).
			//
			// Idempotent on second post-handshake frame via session-nil check.
			if c.connState.Completed && c.session == nil {
				c.initServerSessionLocked()
			}
			continue
		}

		// Post-handshake: EXECUTE_RESPONSE frames route to the per-request
		// pending map (so Connection.Execute over the SAME connection — the
		// §6.11 reentry path — can demux its responses); EXECUTE frames
		// dispatch concurrently as before.
		if env.Root.Type == types.TypeExecuteResponse {
			c.routeServerResponse(env)
			continue
		}

		// Post-handshake: dispatch concurrently. Acquire a slot or abort on
		// shutdown rather than queueing more reads behind a saturated pool.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(env entity.Envelope) {
			defer wg.Done()
			defer func() { <-sem }()

			respEnv, err := c.peer.dispatcher.DispatchEnvelope(ctx, env, c.connState)
			if err != nil {
				c.debugf("[%s] dispatch error: %v", c.conn.RemoteAddr(), err)
				return
			}
			c.debugf("[%s] -> response root_type=%s", c.conn.RemoteAddr(), respEnv.Root.Type)
			if err := c.SendEnvelope(respEnv); err != nil {
				c.debugf("[%s] send error: %v", c.conn.RemoteAddr(), err)
				// Don't tear down the connection here — the read loop will
				// surface a recv error if the link is actually broken.
				return
			}
		}(env)
	}
}

// initServerSessionLocked initializes c.session on the server side once
// the handshake completes. It mirrors the client-side initialization at
// the end of PerformConnect, using state populated by the connect
// dispatcher (cs.RemotePeerID / cs.GrantedCapability) on the same
// connection. Also registers the connection in the outbound endpoint
// pool keyed by remote peer-id so V7 §6.11 reentry-from-this-connection
// reuses it for outbound dispatch (GUIDE-CONFORMANCE §7a.2a — the
// substantive surface §10.2 verifies).
//
// Called at most once per server-side connection by the serve loop after
// the handshake-complete check fires.
func (c *Connection) initServerSessionLocked() {
	cs := c.connState
	if cs == nil || !cs.Completed {
		return
	}
	c.session = &Session{
		RemotePeerID: cs.RemotePeerID,
	}
	if cs.GrantedCapability != nil {
		capCopy := *cs.GrantedCapability
		c.session.Capability = &capCopy
	}
	if c.peer != nil {
		c.peer.registerInboundForReentry(cs.RemotePeerID, c)
	}
}

// routeServerResponse delivers an inbound EXECUTE_RESPONSE on the
// server-side connection to a pending Connection.Execute waiter (the
// §6.11 reentry path: this connection sent an outbound EXECUTE and is
// now receiving its response on the same wire). Orphans drop quietly.
func (c *Connection) routeServerResponse(env entity.Envelope) {
	reqID, ok := responseRequestID(env)
	if !ok {
		c.debugf("[%s] serve: response without request_id (type=%s); dropped", c.conn.RemoteAddr(), env.Root.Type)
		return
	}
	ch, found := c.pending.LoadAndDelete(reqID)
	if !found {
		c.debugf("[%s] serve: orphan response request_id=%q (caller deadline likely fired)", c.conn.RemoteAddr(), reqID)
		return
	}
	var result responseResult
	if vErr := c.validateRecv("execute_response", env); vErr != nil {
		result = responseResult{err: vErr}
	} else {
		result = responseResult{env: env}
	}
	select {
	case ch.(chan responseResult) <- result:
	default:
	}
}

// PerformConnect initiates the connection handshake as a client.
func (c *Connection) PerformConnect(ctx context.Context) error {
	kp := c.peer.keypair
	addr := c.conn.RemoteAddr()

	// 1. Send hello.
	helloEnv, ourNonce, err := protocol.CreateHelloExecute(kp, nil)
	if err != nil {
		return fmt.Errorf("create hello: %w", err)
	}
	c.debugf("[%s] -> HELLO", addr)
	if err := c.SendEnvelope(helloEnv); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// 2. Receive their hello response.
	theirHelloResp, err := c.RecvEnvelope()
	if err != nil {
		return fmt.Errorf("recv hello response: %w", err)
	}
	c.debugf("[%s] <- envelope root_type=%s included=%d", addr, theirHelloResp.Root.Type, len(theirHelloResp.Included))
	if err := c.validateRecv("hello_response", theirHelloResp); err != nil {
		return fmt.Errorf("hello response: %w", err)
	}

	// Extract their nonce, peer ID, and advertised hash_formats from the
	// hello response.
	theirNonce, remotePeerID, theirHashFormats, err := extractHelloResponse(theirHelloResp)
	if err != nil {
		return fmt.Errorf("extract hello response: %w", err)
	}
	c.debugf("[%s] <- HELLO_RESPONSE peer_id=%s hash_formats=%v", addr, remotePeerID, theirHashFormats)

	// V7 v7.69 §4.5 — derive the connection's active content_hash_format.
	// First match in our preference order that is also in the responder's
	// advertised set. Empty intersection fails the connection.
	activeFormat, activeFormatString, ok := protocol.NegotiateActiveHashFormat(
		protocol.DefaultAdvertisedHashFormats(),
		theirHashFormats,
	)
	if !ok {
		return fmt.Errorf("hash_formats negotiation failed: ours=%v theirs=%v (V7 v7.69 §4.5 — incompatible_hash_format)",
			protocol.DefaultAdvertisedHashFormats(), theirHashFormats)
	}
	c.debugf("[%s] negotiated active content_hash_format=%s", addr, activeFormatString)
	c.connState.OurNonce = ourNonce
	c.connState.TheirNonce = theirNonce
	c.connState.Phase = "awaiting_authenticate"
	c.connState.ActiveHashFormat = activeFormat

	// 3. Send authenticate with their nonce, authored under the
	//    negotiated active content_hash_format (V7 v7.69 §4.5a).
	authenticateEnv, err := protocol.CreateAuthenticateExecuteFormat(kp, theirNonce, activeFormat)
	if err != nil {
		return fmt.Errorf("create authenticate: %w", err)
	}
	c.debugf("[%s] -> AUTHENTICATE", addr)
	if err := c.SendEnvelope(authenticateEnv); err != nil {
		return fmt.Errorf("send authenticate: %w", err)
	}

	// 4. Receive authenticate response (contains capability grant).
	authenticateResp, err := c.RecvEnvelope()
	if err != nil {
		return fmt.Errorf("recv authenticate response: %w", err)
	}
	c.debugf("[%s] <- envelope root_type=%s included=%d", addr, authenticateResp.Root.Type, len(authenticateResp.Included))
	if err := c.validateRecv("authenticate_response", authenticateResp); err != nil {
		return fmt.Errorf("authenticate response: %w", err)
	}
	c.debugf("[%s] <- AUTHENTICATE_RESPONSE", addr)

	c.connState.Completed = true
	c.connState.Phase = "completed"
	c.connState.RemotePeerID = remotePeerID

	// Extract capability from authenticate response.
	c.session = &Session{
		RemotePeerID: remotePeerID,
		Envelope:     authenticateResp,
	}

	capEntity, err := extractCapabilityFromResponse(authenticateResp)
	if err == nil {
		c.session.Capability = &capEntity
	}

	// V7 §6.5 envelope-included signature ingestion: persist the
	// AUTHENTICATE_RESPONSE envelope's signatures + granter identities
	// into the local content store + invariant-pointer-path index. The
	// connect handshake bypasses the dispatch entry point (which is the
	// other ingest call site), so without this step the conferred cap
	// sits in `Session.Capability` while its signature + granter identity
	// remain unpersisted. Any subsequent code that chain-walks the cap
	// (e.g. `core/capability.CollectChainBundle` for re-attenuated
	// continuations) then hits `chain_unreachable` until the next
	// dispatched op happens to populate them via the dispatch path's
	// own ingest.
	//
	// Idempotent on already-persisted entries; conflicts only surface for
	// genuinely malformed envelopes. Soft-fail with a debug log so the
	// connection still completes — the conflict's downstream surface
	// (chain-walk failure) will then be diagnosable at the call site
	// rather than masking the handshake itself.
	if c.peer != nil {
		if ingestErr := protocol.IngestEnvelopeSignatures(c.peer.Store(), c.peer.LocationIndex(), authenticateResp.Included); ingestErr != nil {
			c.debugf("[%s] envelope ingest after handshake: %v", addr, ingestErr)
		}
	}

	// R6 §9 (Architecture rulings, commit 523cdc5): persist the held side
	// of the per-peer session entity to the local tree at
	// /{local}/system/peer/session/{remote}. This is the durable record of
	// the cap remote granted us — the authoritative source for outbound
	// dispatch's cap selection (Connection.Execute reads it via
	// ReadHeldCapability). The in-memory c.session.Capability above remains
	// as a fast-path fallback when the tree read misses (e.g. legacy peers).
	//
	// WriteHeldSession is read-modify-write: any minted_capability already
	// at this path (from a prior server-side handshake where we were
	// granter) is preserved (§9.1 R6-a). One entity per peer, two cap
	// fields — no bidirectional collision.
	//
	// Soft-fail with a debug log on cap absence or write error: a missing
	// cap is already a non-fatal path above (older test peers); a write
	// error would only surface as a session-read miss on later Execute
	// calls (which falls back to the in-memory cap). Diagnosable downstream.
	if c.peer != nil && err == nil {
		grantedAt := uint64(time.Now().UnixMilli())
		capData, capErr := types.CapabilityTokenDataFromEntity(capEntity)
		var expiresAt uint64
		if capErr == nil && capData.ExpiresAt != nil {
			expiresAt = *capData.ExpiresAt
		}
		// V7.64: derive the remote's canonical identity hash before writing
		// the session entity (path key under v7.64 path-encoding alignment).
		// For identity-form remotes (v7.64 default) this is a pure local
		// computation; for SHA-256-form remotes we'd need the remote's
		// public_key which isn't directly in this dialer scope yet —
		// gracefully skip the held-session write in that case and fall
		// back to the in-memory cap (legacy peers, transitional).
		remoteIdentityHash, hashErr := protocol.ResolveRemoteIdentityHash(remotePeerID, nil)
		if hashErr != nil {
			c.debugf("[%s] R6 session entity skipped: %v", addr, hashErr)
		} else {
			if _, writeErr := protocol.WriteHeldSession(
				c.peer.Store(),
				c.peer.LocationIndex(),
				string(c.peer.PeerID()),
				string(remotePeerID),
				[]byte(nil),
				remoteIdentityHash,
				capEntity,
				grantedAt,
				expiresAt,
			); writeErr != nil {
				c.debugf("[%s] R6 session entity write: %v", addr, writeErr)
			}
		}
	}

	c.debugf("[%s] connect complete remote_peer=%s", addr, remotePeerID)

	// Class G fix: start the multiplexed reader now that handshake is
	// complete. From this point on, all incoming frames on this client
	// connection are EXECUTE_RESPONSEs and the reader demuxes them by
	// request_id into per-request response channels. Handshake frames
	// (HELLO, AUTHENTICATE) were strictly ordered and read synchronously
	// above — they do not flow through the reader.
	c.startReader()
	return nil
}

// extractHelloResponse decodes the hello response to get the remote peer's nonce and peer ID.
func extractHelloResponse(env entity.Envelope) (nonce []byte, peerID crypto.PeerID, hashFormats []string, err error) {
	// The response is an EXECUTE_RESPONSE with a hello entity as result.
	respData, e := types.ExecuteResponseDataFromEntity(env.Root)
	if e != nil {
		return nil, "", nil, fmt.Errorf("decode response: %w", e)
	}
	if respData.Status != 200 {
		return nil, "", nil, fmt.Errorf("hello response status %d", respData.Status)
	}

	var helloResultEntity entity.Entity
	if e := ecf.Decode(respData.Result, &helloResultEntity); e != nil {
		return nil, "", nil, fmt.Errorf("decode hello result: %w", e)
	}

	helloData, e := types.HelloDataFromEntity(helloResultEntity)
	if e != nil {
		return nil, "", nil, fmt.Errorf("decode hello data: %w", e)
	}

	return helloData.Nonce, crypto.PeerID(helloData.PeerID), helloData.HashFormats, nil
}

// extractCapabilityFromResponse extracts the capability entity from an authenticate response.
func extractCapabilityFromResponse(env entity.Envelope) (entity.Entity, error) {
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return entity.Entity{}, err
	}

	var grantResultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &grantResultEntity); err != nil {
		return entity.Entity{}, err
	}

	var grantData types.CapabilityGrantData
	if err := ecf.Decode(grantResultEntity.Data, &grantData); err != nil {
		return entity.Entity{}, err
	}

	capEntity, ok := env.FindIncluded(grantData.Token)
	if !ok {
		return entity.Entity{}, fmt.Errorf("capability token not in included")
	}

	return capEntity, nil
}

// Session holds per-connection state after the connect handshake.
//
// requestSeq is incremented atomically per outgoing Execute. The
// surrounding mutex on Connection serializes the send+recv pair
// (so responses can't interleave), but the increment itself must
// be atomic because concurrent Execute callers race on it before
// reaching the mutex. Surfaced by the workbench's bidirectional
// sync test under `-race` — see the workbench persistence-feedback
// review, Finding 9 (workbench-side).
type Session struct {
	RemotePeerID crypto.PeerID
	Envelope     entity.Envelope
	Capability   *entity.Entity
	requestSeq   atomic.Int64
}

// Execute sends an authenticated EXECUTE to the remote peer and returns the
// response envelope. The connection must be established first.
func (c *Connection) Execute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, async ...*protocol.AsyncDelivery) (entity.Envelope, error) {
	if c.session == nil || c.session.Capability == nil {
		return entity.Envelope{}, fmt.Errorf("connection not established")
	}

	requestID := fmt.Sprintf("req-%d", c.session.requestSeq.Add(1))

	// EXTENSION-CONTINUATION §4.2 case 3 / §8.1 + V7 §6.8 (no silent
	// escalation): the cross-peer EXECUTE is authorized by the
	// installer-provided scoped dispatch_capability
	// (async[0].CapabilityOverride), NOT by a silent fallback to the broad
	// connection session cap. Per v1.11 §4.2 case 3 (iii) that cap is
	// B-rooted (i), installer in-chain as leaf granter (ii), and granted to
	// THIS host peer (iii) — which is exactly the identity signing here
	// (c.peer.keypair / c.peer.identity), so B's `grantee == author` check
	// (V7 §5.2) passes. Authoring as the host peer is not an escalation:
	// authority is bounded by the scoped, B-rooted, installer-attenuated
	// chain, not by the signing identity. The cap's full chain travels in
	// `async` Extras (CollectChainBundle, §4.3). Nil override = ordinary
	// connection-authorized EXECUTE — authoritative cap source is the R6
	// session entity's held_capability at /{local}/system/peer/session/
	// {remote} per §9.0 ("session entity is THE answer to 'do I already
	// hold a valid cap?'"). The in-memory c.session.Capability is the
	// fast-path fallback when the tree read misses (legacy peers).
	var effectiveCap entity.Entity
	if c.peer != nil {
		// V7.64: derive the canonical remote identity hash for the session
		// path lookup. Failure (SHA-256-form remote without public_key
		// threading) falls through to the in-memory cap.
		var heldCap entity.Entity
		var heldOK bool
		if remoteHash, hashErr := protocol.ResolveRemoteIdentityHash(c.session.RemotePeerID, nil); hashErr == nil {
			heldCap, heldOK = protocol.ReadHeldCapability(
				c.peer.Store(),
				c.peer.LocationIndex(),
				string(c.peer.PeerID()),
				remoteHash,
			)
		}
		if heldOK {
			effectiveCap = heldCap
		} else {
			effectiveCap = *c.session.Capability
		}
	} else {
		effectiveCap = *c.session.Capability
	}
	if len(async) > 0 && async[0] != nil && async[0].CapabilityOverride != nil {
		effectiveCap = *async[0].CapabilityOverride
	}
	env, err := protocol.CreateAuthenticatedExecute(
		c.peer.keypair,
		c.peer.identity,
		effectiveCap,
		requestID,
		uri,
		operation,
		params,
		resource,
		async...,
	)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("create execute: %w", err)
	}

	// Include entities from the authenticate response (granter identity, capability
	// signatures, etc.) — required for capability chain verification on the server.
	for h, ent := range c.session.Envelope.Included {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	// Multiplexed dispatch (Class G fix): register a response channel for
	// this request_id BEFORE sending so the reader can route the response
	// back to us. Multiple Execute calls may be in flight concurrently;
	// the reader demuxes by request_id. Per-request deadline is enforced
	// at the select below — net.Conn.SetDeadline would race across
	// concurrent Execute callers and is no longer used.
	if c.IsClosed() {
		return entity.Envelope{}, fmt.Errorf("execute: %w", ErrConnClosed)
	}
	respCh := make(chan responseResult, 1)
	c.pending.Store(requestID, respCh)
	cleanup := func() {
		// Only deletes if still present — if the reader already
		// LoadAndDelete'd, this is a no-op.
		c.pending.Delete(requestID)
	}

	if err := c.SendEnvelope(env); err != nil {
		cleanup()
		return entity.Envelope{}, fmt.Errorf("send execute: %w", err)
	}

	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(15 * time.Second)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	var resp entity.Envelope
	select {
	case r := <-respCh:
		if r.err != nil {
			return entity.Envelope{}, r.err
		}
		resp = r.env
	case <-timer.C:
		cleanup()
		return entity.Envelope{}, fmt.Errorf("recv response: i/o timeout")
	case <-ctx.Done():
		cleanup()
		return entity.Envelope{}, fmt.Errorf("recv response: %w", ctx.Err())
	case <-c.readerDone:
		// Reader exited; closeErr was set before readerDone closed.
		err := c.closeErr
		if err == nil {
			err = ErrConnClosed
		}
		return entity.Envelope{}, fmt.Errorf("recv response: %w", err)
	}

	return resp, nil
}

// ExecuteWithIncluded behaves like Execute but lets the caller attach
// additional included entities to the outgoing EXECUTE envelope. Used by
// the RELAY OutboundDispatcher to carry the inner envelope (§9 opacity:
// the inner rides verbatim in the included set, keyed by its content hash)
// when forwarding to an intermediate hop.
func (c *Connection) ExecuteWithIncluded(
	ctx context.Context,
	uri, operation string,
	params entity.Entity,
	resource *types.ResourceTarget,
	extras map[hash.Hash]entity.Entity,
	async ...*protocol.AsyncDelivery,
) (entity.Envelope, error) {
	if c.session == nil || c.session.Capability == nil {
		return entity.Envelope{}, fmt.Errorf("connection not established")
	}

	requestID := fmt.Sprintf("req-%d", c.session.requestSeq.Add(1))

	var effectiveCap entity.Entity
	if c.peer != nil {
		var heldCap entity.Entity
		var heldOK bool
		if remoteHash, hashErr := protocol.ResolveRemoteIdentityHash(c.session.RemotePeerID, nil); hashErr == nil {
			heldCap, heldOK = protocol.ReadHeldCapability(
				c.peer.Store(),
				c.peer.LocationIndex(),
				string(c.peer.PeerID()),
				remoteHash,
			)
		}
		if heldOK {
			effectiveCap = heldCap
		} else {
			effectiveCap = *c.session.Capability
		}
	} else {
		effectiveCap = *c.session.Capability
	}
	if len(async) > 0 && async[0] != nil && async[0].CapabilityOverride != nil {
		effectiveCap = *async[0].CapabilityOverride
	}
	env, err := protocol.CreateAuthenticatedExecute(
		c.peer.keypair,
		c.peer.identity,
		effectiveCap,
		requestID,
		uri,
		operation,
		params,
		resource,
		async...,
	)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("create execute: %w", err)
	}

	for h, ent := range c.session.Envelope.Included {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}
	for h, ent := range extras {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	if c.IsClosed() {
		return entity.Envelope{}, fmt.Errorf("execute: %w", ErrConnClosed)
	}
	respCh := make(chan responseResult, 1)
	c.pending.Store(requestID, respCh)
	cleanup := func() {
		c.pending.Delete(requestID)
	}

	if err := c.SendEnvelope(env); err != nil {
		cleanup()
		return entity.Envelope{}, fmt.Errorf("send execute: %w", err)
	}

	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(15 * time.Second)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	var resp entity.Envelope
	select {
	case r := <-respCh:
		if r.err != nil {
			return entity.Envelope{}, r.err
		}
		resp = r.env
	case <-timer.C:
		cleanup()
		return entity.Envelope{}, fmt.Errorf("recv response: i/o timeout")
	case <-ctx.Done():
		cleanup()
		return entity.Envelope{}, fmt.Errorf("recv response: %w", ctx.Err())
	case <-c.readerDone:
		err := c.closeErr
		if err == nil {
			err = ErrConnClosed
		}
		return entity.Envelope{}, fmt.Errorf("recv response: %w", err)
	}

	return resp, nil
}

// buildPayloadTooLargeResponse builds a best-effort 413 payload_too_large
// EXECUTE_RESPONSE envelope, used by the serve loop when wire.ReadFrame
// rejects an oversize length prefix. The body was never buffered (per V7
// §4.10(a) v7.75), so we cannot correlate by request_id — emit an empty
// request_id and close the connection after writing.
func buildPayloadTooLargeResponse() (entity.Envelope, error) {
	errData := types.ErrorData{
		Code:    "payload_too_large",
		Message: fmt.Sprintf("inbound frame exceeds max payload (%d bytes)", wire.MaxFrameSize),
	}
	errEntity, err := errData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	resultRaw, err := ecf.Encode(errEntity)
	if err != nil {
		return entity.Envelope{}, err
	}
	respData := types.ExecuteResponseData{
		RequestID: "",
		Status:    413,
		Result:    resultRaw,
	}
	respEntity, err := respData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(respEntity, map[hash.Hash]entity.Entity{
		errEntity.ContentHash: errEntity,
	}), nil
}
