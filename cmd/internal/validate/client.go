package validate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// PeerClient provides low-level validated communication with a remote peer.
// Unlike peer.Connection, it works at the envelope-pair level
// (writeEnvelope → readFrame) to preserve raw bytes for encoding checks.
//
// Transport is chosen at Connect time from the address scheme: TCP when
// addr is a host:port; HTTP (EXTENSION-NETWORK §6.5.2c Amendment 3) when
// addr starts with http:// or https://. The validator's strict
// write-then-read pattern works identically over either substrate; the
// difference lives in cmd/internal/validate/client_transport.go.
type PeerClient struct {
	addr      string
	transport peerTransport

	// Client identity.
	keypair        crypto.Keypair
	identityEntity entity.Entity

	// Session state populated after connect.
	remotePeerID           crypto.PeerID
	remotePeerIdentityHash hash.Hash // granter identity hash from capability token
	capEntity              entity.Entity
	capGrants              []types.GrantEntry
	authenticateIncluded   map[hash.Hash]entity.Entity // entities from authenticate response (granter identity, cap sig, etc.)

	// V7 v7.69 §4.5a — the connection's negotiated active
	// content_hash_format. Set during PerformHandshake after parsing the
	// responder's hello.HashFormats; consumed by per-request authoring
	// (cap mint, signature, identity-reference rebuild) to keep all
	// authored entities on this connection under the same format.
	activeHashFormat byte

	// Raw bytes from connect responses, for encoding checks.
	HelloResponseBytes        []byte
	AuthenticateResponseBytes []byte
	HelloResponseEnvelope     entity.Envelope
	AuthenticateResponseEnv   entity.Envelope

	// requestSeq is atomic so the concurrency category can fire N parallel
	// SendExecutes through the same client. Auto-increment IDs ("validate-N")
	// must be unique across goroutines to keep the bg reader's per-id demux
	// from cross-talking. Pre-concurrency the suite was strictly single-in-
	// flight and a non-atomic int was harmless.
	requestSeq atomic.Int64
	verbose    bool

	// V7 v7.72 §9.0 conformance profile ("core" or "full"). Read by
	// per-check carve-outs in security/authz/handlers/typesystem to
	// gate extension-targeted vectors out of --profile core runs.
	profile string

	// Background reader (streaming/TCP transport only). Started after a
	// successful PerformHandshake via startBackgroundReader; nil/false on the
	// HTTP transport (paired POST request/response — nothing accumulates on a
	// socket to drain). It continuously reads inbound frames and routes
	// EXECUTE_RESPONSEs by request_id to the waiting send, while draining
	// unsolicited inbound EXECUTEs *between* requests, not only during a
	// response wait. That continuous drain is what prevents the TCP
	// write-backpressure deadlock against peers (Rust/Python) that push
	// reverse-leg or delivery frames between our requests: left unread, those
	// frames fill the kernel socket buffer until our next write blocks. This
	// mirrors core/peer/connection.go's reader-task demux (V7 §6.11(a/b)).
	bgReader  bool
	bgPending sync.Map     // requestID → chan bgFrame (cap 1)
	bgWaiters atomic.Int32 // count of outstanding waiters (single-in-flight ⇒ ≤1)
	bgDone    chan struct{}
	bgErr     error // read-side error; set before bgDone closes

	// writeMu serializes outbound writes on the shared connection. The
	// suite is single-in-flight on the request side, but the GUIDE-
	// CONFORMANCE §7a.2a reentry flow has the background reader writing
	// EXECUTE_RESPONSEs back for inbound system/validate/echo requests
	// while a foreground SendExecute is awaiting its own response — two
	// goroutines may attempt to write to the conn. Length-prefixed
	// framing only survives if those writes don't interleave.
	writeMu sync.Mutex

	// reentryEcho, when non-nil, is the validator-side B-role echo
	// handler installed for the duration of a §7a.2a probe. The bg
	// reader checks inbound EXECUTEs against it before draining — when
	// the URI/op matches, the handler writes back an EXECUTE_RESPONSE
	// on the same connection. nil = drain-as-before behavior preserved.
	reentryEcho *reentryEchoState
}

// bgFrame carries one routed frame from the background reader to a waiting
// send. err is non-nil for connection-level failures (wire read error,
// connection closed).
type bgFrame struct {
	raw []byte
	err error
}

// NewPeerClient creates a client for validating the peer at addr.
// Uses an ephemeral keypair — the peer grants connection-level access.
func NewPeerClient(addr string) (*PeerClient, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return newPeerClientWithKeypair(addr, kp)
}

// NewPeerClientWithIdentity creates a client using a named identity
// from ~/.entity/identities/. Use this for admin access or when the
// peer has identity-specific grants.
func NewPeerClientWithIdentity(addr, identityName string) (*PeerClient, error) {
	kp, err := crypto.LoadIdentity(identityName)
	if err != nil {
		return nil, fmt.Errorf("load identity %q: %w", identityName, err)
	}
	return newPeerClientWithKeypair(addr, kp)
}

// NewPeerClientWithKeypair creates a client using a caller-supplied keypair.
// Used by the peer-to-peer dispatch model (EXTENSION-CONTINUATION v1.11
// §4.2 case 3) where the dispatching host peer wields the remote peer's
// connect-grant directly — the client identity must equal the peer's own
// identity so grantee == EXECUTE author at advance time. See cycle_test
// and entity-sync for the canonical callers.
func NewPeerClientWithKeypair(addr string, kp crypto.Keypair) (*PeerClient, error) {
	return newPeerClientWithKeypair(addr, kp)
}

func newPeerClientWithKeypair(addr string, kp crypto.Keypair) (*PeerClient, error) {
	identity, err := kp.IdentityEntity()
	if err != nil {
		return nil, fmt.Errorf("create identity: %w", err)
	}
	return &PeerClient{
		addr:           addr,
		keypair:        kp,
		identityEntity: identity,
	}, nil
}

// Connect establishes the transport. TCP for host:port addresses; HTTP
// (POST EXECUTE per Amendment 3 §6.5.2c) for http(s):// URLs.
func (c *PeerClient) Connect(ctx context.Context) error {
	if isHTTPAddr(c.addr) {
		c.transport = newHTTPTransport(c.addr)
		return nil
	}
	t, err := newTCPTransport(ctx, c.addr)
	if err != nil {
		return err
	}
	c.transport = t
	return nil
}

// Addr returns the peer's address.
func (c *PeerClient) Addr() string { return c.addr }

// Close closes the transport.
func (c *PeerClient) Close() error {
	if c.transport != nil {
		return c.transport.Close()
	}
	return nil
}

// perRequestTimeout caps a single request/response exchange independently of
// the run-wide budget. Without it, ioDeadline returned the *run* deadline as
// the per-frame deadline, so one non-answering probe (e.g. a peer that holds a
// tampered-handshake connection open without replying — the §4.6
// proof-of-possession probes hit exactly this on peers that don't enforce it)
// blocked until the whole -timeout elapsed, exhausting the budget. Every
// category after it then instant-failed with a past-deadline `write i/o
// timeout` — a budget-exhaustion cascade that masked the real per-category
// results (the "full shared-connection run collapses partway" symptom).
// Capping each exchange turns one slow probe into one fast FAIL, leaving the
// rest of the run its budget. Legit exchanges in the suite top out around 2s
// (compute ~1.9s, subscriptions ~1.1s), so 20s is generous headroom — it bounds
// a hang, never clips real work.
const perRequestTimeout = 20 * time.Second

// ioDeadline derives the per-frame socket deadline from ctx. The validation
// suite exists to catch peers that mishandle requests — including the
// deadlock/hang class the concurrency work has been chasing. wire.ReadFrame /
// wire.WriteEnvelope are raw socket ops that do NOT observe ctx, so without
// an explicit deadline a peer that accepts the connection then never answers
// would hang the validator forever and it would report nothing instead of a
// FAIL. The deadline is the earlier of the per-request cap and the run
// budget: the cap stops one hang from eating the whole run (turning "hang"
// into a single recorded timeout FAIL); the run budget is the hard ceiling.
func ioDeadline(ctx context.Context) time.Time {
	capped := time.Now().Add(perRequestTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(capped) {
		return d
	}
	return capped
}

// readFrame reads one envelope-frame bounded by the context deadline.
// Delegates to the active transport (TCP: socket-deadline-bounded
// wire.ReadFrame; HTTP: POSTs the buffered envelope and returns the bare
// ECF response body).
func (c *PeerClient) readFrame(ctx context.Context) ([]byte, error) {
	return c.transport.ReadFrame(ctx)
}

// maxDrainFrames bounds the unsolicited inbound frames readResponseFrame will
// skip while waiting for the response to the current request.
const maxDrainFrames = 16

// readResponseFrame reads frames until it gets the response to the current
// (single-in-flight) request, draining any unsolicited inbound EXECUTE the
// peer pushes in between — e.g. a reverse leg-3 authenticate, or a delivery
// push. A strict write-then-read mis-reads such a frame as the response and
// desyncs the whole run; left unread, the frames accumulate into a TCP
// write-backpressure deadlock (the S2 defect that mis-reported the C# leg-3
// case and cascades whole categories). This is the test-client side of the
// V7 §6.11(b) out-of-order / unsolicited-frame tolerance the peer runtime
// already implements (core/peer/connection.go reader-task demux).
//
// The normal case (the response is the next frame) returns on the first
// iteration — no extra reads. The handshake reads (hello/authenticate) keep
// their own leg-typing and intentionally do not route through here.
func (c *PeerClient) readResponseFrame(ctx context.Context) ([]byte, error) {
	for i := 0; i < maxDrainFrames; i++ {
		raw, err := c.readFrame(ctx)
		if err != nil {
			return raw, err
		}
		var env entity.Envelope
		if err := ecf.Decode(raw, &env); err != nil {
			// Not a decodable envelope — hand it back; the caller's own
			// decode surfaces the error in its context.
			return raw, nil
		}
		if env.Root.Type == types.TypeExecute {
			// Unsolicited inbound request, not our response. Drain it.
			if c.verbose {
				fmt.Fprintf(progressOut, "  [drain] skipped unsolicited inbound EXECUTE while awaiting response\n")
			}
			continue
		}
		return raw, nil
	}
	return nil, fmt.Errorf("no response frame after draining %d unsolicited inbound EXECUTEs", maxDrainFrames)
}

// writeEnvelope writes one envelope bounded by the context deadline.
// Delegates to the active transport (TCP: socket-deadline-bounded
// wire.WriteEnvelope; HTTP: buffers the envelope until the paired
// readFrame flushes it as one POST). Mutex-guarded so the bg reader's
// §7a.2a reentry-response writes don't interleave with foreground sends.
func (c *PeerClient) writeEnvelope(ctx context.Context, env entity.Envelope) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.transport.WriteEnvelope(ctx, env)
}

// startBackgroundReader spawns the continuous reader goroutine on transports
// that hold a persistent socket (TCP). It is the test-client analog of the
// peer runtime's reader-task (core/peer/connection.go): after the handshake,
// all inbound frames are demuxed here by request_id, and unsolicited inbound
// EXECUTEs are drained continuously so they never back up the peer's writes.
// Called once at the end of a successful PerformHandshake. The HTTP transport
// has no persistent socket — readResponseFrame's in-line drain still covers
// its (impossible-to-deadlock) paired exchanges, so this is a no-op there.
func (c *PeerClient) startBackgroundReader() {
	br, ok := c.transport.(backgroundReadable)
	if !ok {
		return
	}
	c.bgReader = true
	c.bgDone = make(chan struct{})
	go c.runBackgroundReader(br)
}

// runBackgroundReader is the continuous read loop. It exits when the socket
// read errors (peer disconnect, framing error, or Close closed the conn),
// failing any outstanding waiter with that error.
func (c *PeerClient) runBackgroundReader(br backgroundReadable) {
	defer close(c.bgDone)
	for {
		raw, err := br.ReadFrameBlocking()
		if err != nil {
			c.bgErr = err
			c.failBGPending(err)
			return
		}
		var env entity.Envelope
		if decErr := ecf.Decode(raw, &env); decErr == nil && env.Root.Type == types.TypeExecute {
			// Unsolicited inbound request. Normally drained (V7 §6.11(b):
			// inbound EXECUTE is never our response). But the §7a.2a
			// reentry probe arms a validator-side echo handler so the
			// target peer's outbound dispatch-outbound EXECUTE reaches
			// the validator-as-B over the same connection — when armed,
			// the handler builds + writes an EXECUTE_RESPONSE here.
			if c.handleReentryEcho(env) {
				continue
			}
			if c.verbose {
				fmt.Fprintf(progressOut, "  [drain] bg reader skipped unsolicited inbound EXECUTE\n")
			}
			continue
		}
		c.routeBGResponse(raw, env)
	}
}

// routeBGResponse delivers a response frame to its waiting send. It matches by
// request_id (the spec demux key, V7 §6.11(b)). A response whose request_id
// matches no live waiter is a late orphan — its caller already timed out and
// its waiter was cleaned up — so it is dropped, never delivered. Only a frame
// that carries NO request_id falls back to the lone outstanding waiter; with
// 0 or N≥2 outstanding the frame is dropped (under N≥2 we can't guess which
// waiter to route to). The fallback exists to tolerate the rare non-conformant
// peer that omits request_id; under the §6.11(b)-conformant gate the path is
// dead. The concurrency category drives N=16 in flight: the missing-id
// fallback then short-circuits at the bgWaiters≥2 check, which is the correct
// behavior — no off-by-one risk because matched-id routing has already fired
// for every conformant response.
//
// The drop-on-unmatched-request_id is load-bearing: when a request times out
// under load, its response is still in flight on the shared socket. Delivering
// that stale frame to the *next* request's waiter (the old behavior — it fell
// through to the positional fallback below) put the connection one response out
// of phase and cascaded a mismatched assertion through every subsequent
// content-asserting check — the "~56 failures starting at behavioral_role under
// load" S2 desync. A non-matching request_id is unambiguously not our response.
func (c *PeerClient) routeBGResponse(raw []byte, env entity.Envelope) {
	if reqID := responseRequestIDOf(env); reqID != "" {
		if chv, ok := c.bgPending.LoadAndDelete(reqID); ok {
			c.bgWaiters.Add(-1)
			chv.(chan bgFrame) <- bgFrame{raw: raw}
			return
		}
		// request_id present but not awaited: a late response draining off the
		// socket after its caller timed out. Drop it — positionally delivering
		// an identifiable orphan is exactly the off-by-one that desyncs the run.
		if c.verbose {
			fmt.Fprintf(progressOut, "  [drain] bg reader dropped late orphan response request_id=%s\n", reqID)
		}
		return
	}
	if c.bgWaiters.Load() == 1 {
		delivered := false
		c.bgPending.Range(func(k, v any) bool {
			c.bgPending.Delete(k)
			c.bgWaiters.Add(-1)
			v.(chan bgFrame) <- bgFrame{raw: raw}
			delivered = true
			return false
		})
		if delivered {
			return
		}
	}
	if c.verbose {
		fmt.Fprintf(progressOut, "  [drain] bg reader dropped orphan response (no waiter)\n")
	}
}

// failBGPending delivers err to every outstanding waiter and clears the map.
func (c *PeerClient) failBGPending(err error) {
	c.bgPending.Range(func(k, v any) bool {
		c.bgPending.Delete(k)
		c.bgWaiters.Add(-1)
		select {
		case v.(chan bgFrame) <- bgFrame{err: err}:
		default:
		}
		return true
	})
}

// responseRequestIDOf extracts the request_id from an EXECUTE_RESPONSE
// envelope, returning "" when the root isn't a decodable response shape.
func responseRequestIDOf(env entity.Envelope) string {
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return ""
	}
	return respData.RequestID
}

// sendAndReadResponse writes env and returns the response frame. When the
// background reader is active (TCP), it registers a per-request waiter keyed by
// requestID before the write, then awaits the routed response — bounded by the
// context deadline (capped at perRequestTimeout via ioDeadline) so a
// non-answering peer still turns into a recorded timeout, never a hang. When
// the reader is inactive (HTTP / pre-handshake), it falls back to the strict
// write-then-read with in-line drain.
func (c *PeerClient) sendAndReadResponse(ctx context.Context, requestID string, env entity.Envelope) ([]byte, error) {
	if !c.bgReader {
		if err := c.writeEnvelope(ctx, env); err != nil {
			return nil, fmt.Errorf("send execute: %w", err)
		}
		return c.readResponseFrame(ctx)
	}

	ch := make(chan bgFrame, 1)
	c.bgPending.Store(requestID, ch)
	c.bgWaiters.Add(1)
	cleanup := func() {
		if _, ok := c.bgPending.LoadAndDelete(requestID); ok {
			c.bgWaiters.Add(-1)
		}
	}

	if err := c.writeEnvelope(ctx, env); err != nil {
		cleanup()
		return nil, fmt.Errorf("send execute: %w", err)
	}

	timer := time.NewTimer(time.Until(ioDeadline(ctx)))
	defer timer.Stop()

	select {
	case f := <-ch:
		if f.err != nil {
			return nil, f.err
		}
		return f.raw, nil
	case <-timer.C:
		cleanup()
		return nil, fmt.Errorf("read response: i/o timeout")
	case <-ctx.Done():
		cleanup()
		return nil, fmt.Errorf("read response: %w", ctx.Err())
	case <-c.bgDone:
		err := c.bgErr
		if err == nil {
			err = fmt.Errorf("connection closed")
		}
		return nil, fmt.Errorf("read response: %w", err)
	}
}

// SetVerbose enables wire trace output on stderr.
// SetProfile sets the V7 v7.72 §9.0 conformance profile the client
// reports for per-check carve-outs ("core" or "full"). Called from the
// suite right after newClient; unused outside the validate package.
func (c *PeerClient) SetProfile(profile string) {
	c.profile = profile
}

// Profile returns the active conformance profile, defaulting to "full"
// when unset. Per-check carve-outs gate on `c.Profile() == ProfileCore`.
func (c *PeerClient) Profile() string {
	if c.profile == ProfileCore {
		return ProfileCore
	}
	return ProfileFull
}

func (c *PeerClient) SetVerbose(v bool) {
	c.verbose = v
}

// traceExchange prints a structured summary of a request/response exchange to stderr.
func (c *PeerClient) traceExchange(label string, uri, operation string, params entity.Entity, respEnv entity.Envelope) {
	var b strings.Builder

	fmt.Fprintf(&b, "  ── %s EXECUTE %s op=%s ──\n", label, uri, operation)

	// Request params.
	fmt.Fprintf(&b, "  → params type=%s\n", params.Type)
	var reqDecoded interface{}
	if err := ecf.Decode(params.Data, &reqDecoded); err == nil {
		var val strings.Builder
		entity.FormatInlineValue(&val, reqDecoded)
		fmt.Fprintf(&b, "    %s\n", val.String())
	}

	// Response.
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		fmt.Fprintf(&b, "  ← (decode error: %v)\n", err)
		fmt.Fprint(os.Stderr, b.String())
		return
	}

	// Decode result entity.
	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		fmt.Fprintf(&b, "  ← status=%d (result decode error: %v)\n", respData.Status, err)
		fmt.Fprint(os.Stderr, b.String())
		return
	}

	fmt.Fprintf(&b, "  ← status=%d type=%s\n", respData.Status, resultEntity.Type)
	var respDecoded interface{}
	if err := ecf.Decode(resultEntity.Data, &respDecoded); err == nil {
		var val strings.Builder
		entity.FormatInlineValue(&val, respDecoded)
		fmt.Fprintf(&b, "    %s\n", val.String())
	}

	fmt.Fprint(os.Stderr, b.String())
}

// PerformHandshake performs the hello/authenticate handshake and returns check results
// for each sub-step. On success, the client is ready for authenticated requests.
func (c *PeerClient) PerformHandshake(ctx context.Context) []CheckResult {
	const cat = "connectivity"
	var checks []CheckResult

	// --- Send hello ---
	helloEnv, ourNonce, err := protocol.CreateHelloExecute(c.keypair, nil)
	if err != nil {
		checks = append(checks, fail(cat, "hello_create", "V7 §4.1", "failed to create hello: "+err.Error()))
		return checks
	}
	_ = ourNonce

	if err := c.writeEnvelope(ctx, helloEnv); err != nil {
		checks = append(checks, fail(cat, "hello_send", "V7 §4.1", "failed to send hello: "+err.Error()))
		return checks
	}

	// --- Receive hello response (raw bytes) ---
	helloRespBytes, err := c.readFrame(ctx)
	if err != nil {
		checks = append(checks, fail(cat, "hello_response_recv", "V7 §4.1", "failed to read hello response frame: "+err.Error()))
		return checks
	}
	c.HelloResponseBytes = helloRespBytes

	var helloRespEnv entity.Envelope
	if err := ecf.Decode(helloRespBytes, &helloRespEnv); err != nil {
		checks = append(checks, fail(cat, "hello_response_decode", "V7 §4.1", "failed to decode hello response envelope: "+err.Error()))
		return checks
	}
	c.HelloResponseEnvelope = helloRespEnv

	// Check: hello response format should be EXECUTE_RESPONSE.
	if helloRespEnv.Root.Type == types.TypeExecuteResponse {
		checks = append(checks, pass(cat, "hello_response_format", "V7 §4.1", "hello response is EXECUTE_RESPONSE"))
	} else if helloRespEnv.Root.Type == types.TypeExecute {
		checks = append(checks, fail(cat, "hello_response_format", "V7 §4.1",
			fmt.Sprintf("hello response is EXECUTE (should be EXECUTE_RESPONSE per updated §4.1)")))
		return checks
	} else {
		checks = append(checks, fail(cat, "hello_response_format", "V7 §4.1",
			fmt.Sprintf("hello response root type is %q (expected %q)", helloRespEnv.Root.Type, types.TypeExecuteResponse)))
		return checks
	}

	// Decode the execute response.
	respData, err := types.ExecuteResponseDataFromEntity(helloRespEnv.Root)
	if err != nil {
		checks = append(checks, fail(cat, "hello_response_decode_data", "V7 §4.1", "failed to decode response data: "+err.Error()))
		return checks
	}
	if respData.Status != 200 {
		checks = append(checks, fail(cat, "hello_response_status", "V7 §4.1",
			fmt.Sprintf("hello response status %d (expected 200)", respData.Status)))
		return checks
	}

	// Decode hello result entity from response.
	var helloResultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &helloResultEntity); err != nil {
		checks = append(checks, fail(cat, "hello_result_decode", "V7 §4.2", "failed to decode hello result entity: "+err.Error()))
		return checks
	}

	helloData, err := types.HelloDataFromEntity(helloResultEntity)
	if err != nil {
		checks = append(checks, fail(cat, "hello_data_decode", "V7 §4.2", "failed to decode hello data: "+err.Error()))
		return checks
	}

	// Check: nonce present and 32 bytes.
	if len(helloData.Nonce) == 32 {
		checks = append(checks, pass(cat, "hello_nonce_present", "V7 §4.2", "32-byte nonce present"))
	} else {
		checks = append(checks, fail(cat, "hello_nonce_present", "V7 §4.2",
			fmt.Sprintf("nonce length %d (expected 32)", len(helloData.Nonce))))
	}

	// Check: peer ID is valid Base58.
	remotePeerID := crypto.PeerID(helloData.PeerID)
	if err := remotePeerID.Validate(); err != nil {
		checks = append(checks, fail(cat, "hello_peerid_valid", "V7 §4.2",
			fmt.Sprintf("invalid peer_id %q: %v", helloData.PeerID, err)))
	} else {
		checks = append(checks, pass(cat, "hello_peerid_valid", "V7 §4.2", "valid Base58 PeerID"))
	}
	c.remotePeerID = remotePeerID

	// Check: at least one protocol version string.
	if len(helloData.Protocols) > 0 {
		checks = append(checks, pass(cat, "hello_protocols_present", "V7 §4.2",
			fmt.Sprintf("protocols: %v", helloData.Protocols)))
	} else {
		checks = append(checks, fail(cat, "hello_protocols_present", "V7 §4.2", "no protocol versions"))
	}

	// V7 v7.69 §4.5 / §4.5a — derive the connection's active
	// content_hash_format from the negotiation: our advertised list
	// (DefaultAdvertisedHashFormats from the protocol package) crossed
	// with the responder's helloData.HashFormats, in our preference order.
	// authenticate + identity + signature MUST be authored under this
	// active format.
	activeFormat, activeFormatString, ok := protocol.NegotiateActiveHashFormat(
		protocol.DefaultAdvertisedHashFormats(),
		helloData.HashFormats,
	)
	if !ok {
		checks = append(checks, fail(cat, "negotiate_active_hash_format", "V7 v7.69 §4.5",
			fmt.Sprintf("no common content_hash_format with responder: ours=%v theirs=%v",
				protocol.DefaultAdvertisedHashFormats(), helloData.HashFormats)))
		return checks
	}
	c.activeHashFormat = activeFormat
	_ = activeFormatString // logged downstream if needed

	// --- Send authenticate with their nonce ---
	authenticateEnv, err := protocol.CreateAuthenticateExecuteFormat(c.keypair, helloData.Nonce, activeFormat)
	if err != nil {
		checks = append(checks, fail(cat, "authenticate_create", "V7 §4.3", "failed to create authenticate: "+err.Error()))
		return checks
	}
	if err := c.writeEnvelope(ctx, authenticateEnv); err != nil {
		checks = append(checks, fail(cat, "authenticate_send", "V7 §4.3", "failed to send authenticate: "+err.Error()))
		return checks
	}

	// --- Receive authenticate response (raw bytes) ---
	authenticateRespBytes, err := c.readFrame(ctx)
	if err != nil {
		checks = append(checks, fail(cat, "authenticate_response_recv", "V7 §4.3", "failed to read authenticate response frame: "+err.Error()))
		return checks
	}
	c.AuthenticateResponseBytes = authenticateRespBytes

	var authenticateRespEnv entity.Envelope
	if err := ecf.Decode(authenticateRespBytes, &authenticateRespEnv); err != nil {
		checks = append(checks, fail(cat, "authenticate_response_decode", "V7 §4.3", "failed to decode authenticate response: "+err.Error()))
		return checks
	}
	c.AuthenticateResponseEnv = authenticateRespEnv

	// Check: authenticate response status.
	authenticateResp, err := types.ExecuteResponseDataFromEntity(authenticateRespEnv.Root)
	if err != nil {
		checks = append(checks, fail(cat, "authenticate_response_status", "V7 §4.3", "failed to decode authenticate response: "+err.Error()))
		return checks
	}
	if authenticateResp.Status == 200 {
		checks = append(checks, pass(cat, "authenticate_response_status", "V7 §4.3", "authenticate response status 200"))
	} else {
		checks = append(checks, fail(cat, "authenticate_response_status", "V7 §4.3",
			fmt.Sprintf("authenticate response status %d (expected 200)", authenticateResp.Status)))
		return checks
	}

	// Decode result entity from authenticate response.
	var grantResultEntity entity.Entity
	if err := ecf.Decode(authenticateResp.Result, &grantResultEntity); err != nil {
		checks = append(checks, fail(cat, "authenticate_result_type", "V7 §4.4", "failed to decode authenticate result entity: "+err.Error()))
		return checks
	}

	// Check: result type is system/capability/grant.
	if grantResultEntity.Type == types.TypeCapGrant {
		checks = append(checks, pass(cat, "authenticate_result_type", "V7 §4.4", "result type is system/capability/grant"))
	} else {
		checks = append(checks, fail(cat, "authenticate_result_type", "V7 §4.4",
			fmt.Sprintf("result type is %q (expected %q)", grantResultEntity.Type, types.TypeCapGrant)))
	}

	// Check: token hash in result.data.token.
	var grantData types.CapabilityGrantData
	if err := ecf.Decode(grantResultEntity.Data, &grantData); err != nil {
		checks = append(checks, fail(cat, "authenticate_token_in_result", "V7 §4.4", "failed to decode grant data: "+err.Error()))
		return checks
	}
	if grantData.Token.IsZero() {
		checks = append(checks, fail(cat, "authenticate_token_in_result", "V7 §4.4", "grant data.token is zero/missing"))
	} else {
		checks = append(checks, pass(cat, "authenticate_token_in_result", "V7 §4.4", "token hash present in result.data.token"))
	}

	// Check: capability token entity in included.
	capEntity, capFound := authenticateRespEnv.FindIncluded(grantData.Token)
	if capFound {
		checks = append(checks, pass(cat, "authenticate_capability_in_included", "V7 §4.4", "capability token entity found in included"))
		c.capEntity = capEntity
		// Save all included entities — needed for authenticated requests (granter identity, cap signature, etc.)
		c.authenticateIncluded = authenticateRespEnv.Included
	} else {
		checks = append(checks, fail(cat, "authenticate_capability_in_included", "V7 §4.4", "capability token entity NOT found in included"))
		return checks
	}

	// Decode cap token to find granter and inspect grants.
	capTokenData, err := types.CapabilityTokenDataFromEntity(capEntity)
	if err != nil {
		checks = append(checks, fail(cat, "authenticate_capability_decode", "V7 §4.4", "failed to decode capability token: "+err.Error()))
		return checks
	}
	c.capGrants = capTokenData.Grants
	if c.verbose {
		fmt.Fprintf(os.Stderr, "[VERBOSE] received %d connection grants:\n", len(capTokenData.Grants))
		for i, g := range capTokenData.Grants {
			fmt.Fprintf(os.Stderr, "  [%d] handlers=%v resources=%v operations=%v\n",
				i, g.Handlers.Include, g.Resources.Include, g.Operations.Include)
		}
	}
	// Connection-time caps are nearly always single-sig; multi-sig is rare
	// here. We extract the single-sig hash; multi-sig caps fall through with
	// a zero hash, which downstream checks will surface.
	if h, single := capTokenData.Granter.SingleHash(); single {
		c.remotePeerIdentityHash = h
	}

	// Check: connection grants cover spec-required scopes (V7 §4.4).
	checks = append(checks, checkConnectionGrants(capTokenData.Grants)...)

	// Check: granter identity entity in included.
	granterIdentity, granterFound := authenticateRespEnv.FindIncluded(c.remotePeerIdentityHash)
	if granterFound {
		checks = append(checks, pass(cat, "authenticate_granter_identity", "V7 §4.4", "granter identity entity found in included"))
	} else {
		checks = append(checks, fail(cat, "authenticate_granter_identity", "V7 §4.4", "granter identity entity NOT found in included"))
	}

	// Check: valid signature on capability token in included.
	capSigEntity, capSigFound := authenticateRespEnv.FindSignatureFor(capEntity.ContentHash)
	if !capSigFound {
		checks = append(checks, fail(cat, "authenticate_capability_signature", "V7 §5.5", "no signature for capability token in included"))
	} else {
		sigData, err := types.SignatureDataFromEntity(capSigEntity)
		if err != nil {
			checks = append(checks, fail(cat, "authenticate_capability_signature", "V7 §5.5", "failed to decode cap signature: "+err.Error()))
		} else if !granterFound {
			checks = append(checks, warn(cat, "authenticate_capability_signature", "V7 §5.5", "cannot verify signature: granter identity missing"))
		} else {
			// Verify: signer must equal granter identity hash.
			if sigData.Signer != granterIdentity.ContentHash {
				checks = append(checks, fail(cat, "authenticate_capability_signature", "V7 §5.5",
					fmt.Sprintf("cap signature signer %s != granter identity %s", sigData.Signer, granterIdentity.ContentHash)))
			} else {
				// Verify signature, dispatching on granter's declared key_type
				// (v7.67 §3 crypto-agility).
				var idData types.PeerData
				if err := ecf.Decode(granterIdentity.Data, &idData); err != nil {
					checks = append(checks, fail(cat, "authenticate_capability_signature", "V7 §5.5", "failed to decode granter identity: "+err.Error()))
				} else if ktByte, ktOK := idData.KeyTypeByte(); !ktOK {
					checks = append(checks, fail(cat, "authenticate_capability_signature", "V7 §5.5",
						fmt.Sprintf("unsupported granter key_type %q", idData.KeyType)))
				} else if crypto.Verify(ktByte, idData.PublicKey, capEntity.ContentHash.Bytes(), sigData.Signature) {
					checks = append(checks, pass(cat, "authenticate_capability_signature", "V7 §5.5",
						fmt.Sprintf("valid %s signature on capability token", idData.KeyType)))
				} else {
					checks = append(checks, fail(cat, "authenticate_capability_signature", "V7 §5.5",
						fmt.Sprintf("%s signature verification failed", idData.KeyType)))
				}
			}
		}
	}

	// Check: all included entities have valid content hashes.
	allValid := true
	for h, ent := range authenticateRespEnv.Included {
		if err := ent.Validate(); err != nil {
			checks = append(checks, fail(cat, "authenticate_entity_hashes", "V7 §1.5",
				fmt.Sprintf("included entity %s hash invalid: %v", h, err)))
			allValid = false
			break
		}
	}
	if allValid {
		checks = append(checks, pass(cat, "authenticate_entity_hashes", "V7 §1.5",
			fmt.Sprintf("all %d included entities have valid content hashes", len(authenticateRespEnv.Included))))
	}

	// Handshake complete. Start the continuous background reader so that, from
	// here on, every inbound frame is demuxed by request_id and unsolicited
	// inbound EXECUTEs are drained between requests — not just during a wait.
	// The HELLO/AUTHENTICATE legs above were strictly ordered and read
	// synchronously (readFrame); they do not flow through the reader.
	c.startBackgroundReader()

	return checks
}

// RemotePeerID returns the remote peer's ID (available after connect).
func (c *PeerClient) RemotePeerID() crypto.PeerID {
	return c.remotePeerID
}

// LocalPeerID returns the validator's own keypair-derived PeerID — the
// Base58 identity the remote peer will see as the authenticated caller.
// Used by probes that need to construct entities whose fields reference
// the caller (e.g. RELAY §3.2 put_by == authenticated caller).
func (c *PeerClient) LocalPeerID() crypto.PeerID {
	return c.keypair.PeerID()
}

// Connected returns true if the client has completed the connect handshake.
func (c *PeerClient) Connected() bool {
	return !c.capEntity.ContentHash.IsZero()
}

// ActiveHashFormat returns the content_hash_format code negotiated with the
// peer at handshake (v7.67 §4 / v7.69 §1.8). Used by the suite to align the
// process-global authoring default with the peer's active format so locally
// authored entities (delivery tokens, comparison blobs, etc.) hash under the
// same algorithm the peer will use to verify or compare them.
func (c *PeerClient) ActiveHashFormat() byte {
	return c.activeHashFormat
}

// SendExecute sends an authenticated EXECUTE and returns the response envelope
// plus the raw frame bytes.
func (c *PeerClient) SendExecute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (entity.Envelope, []byte, error) {
	requestID := fmt.Sprintf("validate-%d", c.requestSeq.Add(1))

	env, err := protocol.CreateAuthenticatedExecute(
		c.keypair,
		c.identityEntity,
		c.capEntity,
		requestID,
		uri,
		operation,
		params,
		resource,
	)
	if err != nil {
		return entity.Envelope{}, nil, fmt.Errorf("create execute: %w", err)
	}

	// Include entities from the authenticate response (granter identity, capability
	// signature, etc.) — required for verifyCapabilityChain on the server side.
	for h, ent := range c.authenticateIncluded {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	rawBytes, err := c.sendAndReadResponse(ctx, requestID, env)
	if err != nil {
		return entity.Envelope{}, nil, err
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(rawBytes, &respEnv); err != nil {
		return entity.Envelope{}, rawBytes, fmt.Errorf("decode response: %w", err)
	}

	if c.verbose {
		c.traceExchange(requestID, uri, operation, params, respEnv)
	}

	return respEnv, rawBytes, nil
}

// SendExecuteWithExplicitID sends an EXECUTE carrying a caller-chosen
// request_id (not the auto-incrementing validate-N counter) and returns the
// request_id echoed back on the EXECUTE_RESPONSE plus its status. Used by
// the §6.11/§3.3 request_id-correlation probe — a distinctive id lets the
// probe confirm the peer reflects the *sent* id, not a coincidental counter.
func (c *PeerClient) SendExecuteWithExplicitID(ctx context.Context, requestID, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (gotID string, status uint, err error) {
	env, err := protocol.CreateAuthenticatedExecute(
		c.keypair, c.identityEntity, c.capEntity, requestID, uri, operation, params, resource,
	)
	if err != nil {
		return "", 0, fmt.Errorf("create execute: %w", err)
	}
	for h, ent := range c.authenticateIncluded {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}
	rawBytes, err := c.sendAndReadResponse(ctx, requestID, env)
	if err != nil {
		return "", 0, err
	}
	var respEnv entity.Envelope
	if err := ecf.Decode(rawBytes, &respEnv); err != nil {
		return "", 0, fmt.Errorf("decode response: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return "", 0, fmt.Errorf("decode response data: %w", err)
	}
	return respData.RequestID, respData.Status, nil
}

// SendExecuteAsync sends an EXECUTE with deliver_to and deliver_token for async delivery.
// The peer should return 202 and deliver the handler result to the deliver_to URI.
func (c *PeerClient) SendExecuteAsync(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, deliverTo *types.DeliverySpec, deliverToken entity.Entity, deliverTokenSig entity.Entity) (entity.Envelope, []byte, error) {
	requestID := fmt.Sprintf("validate-%d", c.requestSeq.Add(1))

	async := &protocol.AsyncDelivery{
		DeliverTo:    deliverTo,
		DeliverToken: deliverToken,
	}

	env, err := protocol.CreateAuthenticatedExecute(
		c.keypair,
		c.identityEntity,
		c.capEntity,
		requestID,
		uri,
		operation,
		params,
		resource,
		async,
	)
	if err != nil {
		return entity.Envelope{}, nil, fmt.Errorf("create execute: %w", err)
	}

	// Include auth entities from the authenticate response.
	for h, ent := range c.authenticateIncluded {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	// Include deliver token signature entity.
	if !deliverTokenSig.ContentHash.IsZero() {
		env.Include(deliverTokenSig)
	}

	rawBytes, err := c.sendAndReadResponse(ctx, requestID, env)
	if err != nil {
		return entity.Envelope{}, nil, err
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(rawBytes, &respEnv); err != nil {
		return entity.Envelope{}, rawBytes, fmt.Errorf("decode response: %w", err)
	}

	if c.verbose {
		c.traceExchange(requestID, uri, operation, params, respEnv)
	}

	return respEnv, rawBytes, nil
}

// SendExecuteAsyncWithDurability sends an EXECUTE carrying BOTH deliver_to
// (async delivery) AND a durability_request. The peer MUST answer with a
// 202 acknowledgement whose durability field reflects what was applied —
// the durability verdict rides the same async-ack 202 (EXTENSION-DURABILITY §5;
// the §7.1 202 meaning is reused). Probes the 202-with-durability code path,
// which is distinct from the synchronous 200-with-durability path.
func (c *PeerClient) SendExecuteAsyncWithDurability(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, dur *types.DurabilityRequestData, deliverTo *types.DeliverySpec, deliverToken entity.Entity, deliverTokenSig entity.Entity) (entity.Envelope, string, []byte, error) {
	requestID := fmt.Sprintf("validate-%d", c.requestSeq.Add(1))

	async := &protocol.AsyncDelivery{
		DeliverTo:         deliverTo,
		DeliverToken:      deliverToken,
		DurabilityRequest: dur,
	}

	env, err := protocol.CreateAuthenticatedExecute(
		c.keypair,
		c.identityEntity,
		c.capEntity,
		requestID,
		uri,
		operation,
		params,
		resource,
		async,
	)
	if err != nil {
		return entity.Envelope{}, requestID, nil, fmt.Errorf("create execute: %w", err)
	}

	for h, ent := range c.authenticateIncluded {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}
	if !deliverTokenSig.ContentHash.IsZero() {
		env.Include(deliverTokenSig)
	}

	rawBytes, err := c.sendAndReadResponse(ctx, requestID, env)
	if err != nil {
		return entity.Envelope{}, requestID, nil, err
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(rawBytes, &respEnv); err != nil {
		return entity.Envelope{}, requestID, rawBytes, fmt.Errorf("decode response: %w", err)
	}

	if c.verbose {
		c.traceExchange(requestID, uri, operation, params, respEnv)
	}

	return respEnv, requestID, rawBytes, nil
}

// SendExecuteWithDurabilityID is SendExecuteWithDurability with an explicit
// request_id (instead of auto-incrementing). Used by the §9.2.4 duplicate-id
// MUST check, where two requests MUST carry the same (author, request_id).
func (c *PeerClient) SendExecuteWithDurabilityID(ctx context.Context, requestID, uri, operation string, params entity.Entity, resource *types.ResourceTarget, dur *types.DurabilityRequestData) (entity.Envelope, string, []byte, error) {
	return c.sendExecuteDurabilityImpl(ctx, requestID, uri, operation, params, resource, dur)
}

// SendExecuteWithDurability sends an EXECUTE carrying the optional request-side
// durability marker (EXTENSION-DURABILITY §2), with no deliver_to. The peer MUST
// answer observably with status + the durability field (§10.5 / V7 §3.2 —
// never silently discarded).
func (c *PeerClient) SendExecuteWithDurability(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, dur *types.DurabilityRequestData) (entity.Envelope, string, []byte, error) {
	requestID := fmt.Sprintf("validate-%d", c.requestSeq.Add(1))
	return c.sendExecuteDurabilityImpl(ctx, requestID, uri, operation, params, resource, dur)
}

func (c *PeerClient) sendExecuteDurabilityImpl(ctx context.Context, requestID, uri, operation string, params entity.Entity, resource *types.ResourceTarget, dur *types.DurabilityRequestData) (entity.Envelope, string, []byte, error) {

	async := &protocol.AsyncDelivery{DurabilityRequest: dur}

	env, err := protocol.CreateAuthenticatedExecute(
		c.keypair,
		c.identityEntity,
		c.capEntity,
		requestID,
		uri,
		operation,
		params,
		resource,
		async,
	)
	if err != nil {
		return entity.Envelope{}, requestID, nil, fmt.Errorf("create execute: %w", err)
	}

	for h, ent := range c.authenticateIncluded {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	rawBytes, err := c.sendAndReadResponse(ctx, requestID, env)
	if err != nil {
		return entity.Envelope{}, requestID, nil, err
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(rawBytes, &respEnv); err != nil {
		return entity.Envelope{}, requestID, rawBytes, fmt.Errorf("decode response: %w", err)
	}

	if c.verbose {
		c.traceExchange(requestID, uri, operation, params, respEnv)
	}

	return respEnv, requestID, rawBytes, nil
}

// TreeGet fetches an entity from the remote peer's tree. Returns the result
// entity, the raw response bytes, and any error.
func (c *PeerClient) TreeGet(ctx context.Context, path string) (entity.Entity, []byte, error) {
	params, resource, err := tree.CreateGetRequest(path, "entity")
	if err != nil {
		return entity.Entity{}, nil, fmt.Errorf("create get request: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/tree", c.remotePeerID)
	env, rawBytes, err := c.SendExecute(ctx, uri, "get", params, resource)
	if err != nil {
		return entity.Entity{}, rawBytes, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return entity.Entity{}, rawBytes, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return entity.Entity{}, rawBytes, fmt.Errorf("tree get status %d", respData.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return entity.Entity{}, rawBytes, fmt.Errorf("decode result entity: %w", err)
	}

	return resultEntity, rawBytes, nil
}

// TreeListing fetches a directory listing from the remote peer's tree.
func (c *PeerClient) TreeListing(ctx context.Context, prefix string) (map[string]interface{}, []byte, error) {
	params, resource, err := tree.CreateGetRequest(prefix, "")
	if err != nil {
		return nil, nil, fmt.Errorf("create listing request: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/tree", c.remotePeerID)
	env, rawBytes, err := c.SendExecute(ctx, uri, "get", params, resource)
	if err != nil {
		return nil, rawBytes, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return nil, rawBytes, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return nil, rawBytes, fmt.Errorf("listing status %d", respData.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return nil, rawBytes, fmt.Errorf("decode result entity: %w", err)
	}

	listingData, err := types.ListingDataFromEntity(resultEntity)
	if err != nil {
		return nil, rawBytes, fmt.Errorf("decode listing: %w", err)
	}

	return listingData.Entries, rawBytes, nil
}

// Grants returns the connection capability grants.
func (c *PeerClient) Grants() []types.GrantEntry {
	return c.capGrants
}

// GrantsAllow checks whether the connection grants cover a given handler+resource
// pattern for the "get" operation. Uses simple prefix/wildcard matching.
func (c *PeerClient) GrantsAllow(resourcePattern string) bool {
	return grantsAllow(c.capGrants, "system/tree", resourcePattern, "get")
}

// grantsAllow checks if any grant covers the given handler, resource, and operation.
func grantsAllow(grants []types.GrantEntry, handler, resource, operation string) bool {
	for _, g := range grants {
		opMatch := false
		for _, op := range g.Operations.Include {
			if op == operation || op == "*" {
				opMatch = true
				break
			}
		}
		if !opMatch {
			continue
		}
		// Check handler matches.
		handlerMatch := false
		for _, h := range g.Handlers.Include {
			if resourceMatches(handler, h) {
				handlerMatch = true
				break
			}
		}
		if !handlerMatch {
			continue
		}
		// Resource dimension. Per §5.2:2048 a grant with an empty
		// resources.include authorizes handler access only — it is
		// resource-agnostic for a path-less handler (the §4.4 standard grant
		// ships system/capability:request exactly this way). Likewise a caller
		// asking with an empty resource is probing handler+operation coverage,
		// not a specific path. In both cases the handler+operation match above
		// is sufficient (A4/F5 — previously this returned false, so the whole
		// capability category SKIPped a grant shape the spec itself mandates).
		if len(g.Resources.Include) == 0 || resource == "" {
			return true
		}
		for _, res := range g.Resources.Include {
			if resourceMatches(resource, res) {
				return true
			}
		}
	}
	return false
}

// resourceMatches checks if a resource path is covered by a grant pattern.
// Delegates to core/capability so the validator's grant-coverage check
// stays in sync with the protocol layer's PR-8 cap-resource canonicalization
// (bare "*" is peer-local; "/*/*" is the cross-peer universal form).
func resourceMatches(resource, pattern string) bool {
	// The validator doesn't have a peer ID context here, so we pass an
	// empty PeerID — bare "*" canonicalizes to "/<empty>/*" which still
	// matches absolute paths starting with "/" via the peer-wildcard rule
	// when the pattern is "/*/*". For the validator's purposes (checking
	// whether published grants cover spec-required scopes), this is
	// correct: "/*/*" covers anything; bare "*" covers only the empty-
	// peer (effectively local) namespace; specific paths match by prefix.
	canonResource := capability.Canonicalize(resource, "")
	canonPattern := capability.Canonicalize(pattern, "")
	return capability.MatchesPattern(canonResource, canonPattern)
}

// checkConnectionGrants produces checks for whether the connection grants cover
// the spec-required scopes.
func checkConnectionGrants(grants []types.GrantEntry) []CheckResult {
	const cat = "connectivity"
	var checks []CheckResult

	grantSummary := formatGrants(grants)

	// V7 §4.4: connection should grant tree handler access.
	if grantsAllow(grants, "system/tree", "system/type/system/peer", "get") {
		checks = append(checks, pass(cat, "connection_grants_tree_handler", "V7 §4.4",
			fmt.Sprintf("connection grants cover system/tree handler scope (%s)", grantSummary)))
	} else {
		checks = append(checks, fail(cat, "connection_grants_tree_handler", "V7 §4.4",
			fmt.Sprintf("connection grants do NOT cover system/tree handler scope (%s)", grantSummary)))
	}

	// V7 §4.4: connection should grant type definition read access.
	if grantsAllow(grants, "system/tree", "system/type/system/peer", "get") {
		checks = append(checks, pass(cat, "connection_grants_types", "V7 §4.4",
			fmt.Sprintf("connection grants cover system/types/* path scope (%s)", grantSummary)))
	} else {
		checks = append(checks, warn(cat, "connection_grants_types", "V7 §4.4",
			fmt.Sprintf("connection grants do NOT cover system/types/* — type_system checks will be skipped (%s)", grantSummary)))
	}

	// V7 §4.4: connection should grant handler manifest read access.
	if grantsAllow(grants, "system/tree", "system/handler/system/tree", "get") {
		checks = append(checks, pass(cat, "connection_grants_handlers", "V7 §4.4",
			fmt.Sprintf("connection grants cover system/handler/* path scope (%s)", grantSummary)))
	} else {
		checks = append(checks, warn(cat, "connection_grants_handlers", "V7 §4.4",
			fmt.Sprintf("connection grants do NOT cover system/handler/* — handlers checks will be skipped (%s)", grantSummary)))
	}

	return checks
}

// formatGrants returns a brief summary of grant entries.
func formatGrants(grants []types.GrantEntry) string {
	var parts []string
	for _, g := range grants {
		parts = append(parts, fmt.Sprintf("{handlers:%v resources:%v ops:%v}", g.Handlers.Include, g.Resources.Include, g.Operations.Include))
	}
	return fmt.Sprintf("[%s]", joinStrings(parts, ", "))
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}

// SendExecuteWithIncluded is like SendExecute but includes additional entities
// in the EXECUTE envelope beyond the standard authentication entities.
func (c *PeerClient) SendExecuteWithIncluded(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, extras map[hash.Hash]entity.Entity) (entity.Envelope, []byte, error) {
	requestID := fmt.Sprintf("validate-%d", c.requestSeq.Add(1))

	env, err := protocol.CreateAuthenticatedExecute(
		c.keypair,
		c.identityEntity,
		c.capEntity,
		requestID,
		uri,
		operation,
		params,
		resource,
	)
	if err != nil {
		return entity.Envelope{}, nil, fmt.Errorf("create execute: %w", err)
	}

	// Include auth entities from the authenticate response.
	for h, ent := range c.authenticateIncluded {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	// Include extra entities (e.g., snapshot entities for diff/merge).
	for h, ent := range extras {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	rawBytes, err := c.sendAndReadResponse(ctx, requestID, env)
	if err != nil {
		return entity.Envelope{}, nil, err
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(rawBytes, &respEnv); err != nil {
		return entity.Envelope{}, rawBytes, fmt.Errorf("decode response: %w", err)
	}

	if c.verbose {
		c.traceExchange(requestID, uri, operation, params, respEnv)
	}

	return respEnv, rawBytes, nil
}

// SendExecuteWithCap is like SendExecute but uses a custom capability
// (and its signature) for the EXECUTE instead of the connection default.
// Used to drive negative tests where a narrower cap should be rejected
// (RL2 enforcement, etc.). The custom cap MUST chain to the connection
// cap or to a cap the remote can verify; CreateDispatchCapability is the
// canonical helper for minting one rooted at the connection grant.
//
// extras MAY be nil; when set, the entries are added to the envelope
// beyond the cap + signature (which are always included). The connection's
// authenticateIncluded entities (granter identity, etc.) are also
// included — they're still needed for the chain walk on the remote side.
func (c *PeerClient) SendExecuteWithCap(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, customCap entity.Entity, customCapSig entity.Entity, extras map[hash.Hash]entity.Entity) (entity.Envelope, []byte, error) {
	requestID := fmt.Sprintf("validate-%d", c.requestSeq.Add(1))

	env, err := protocol.CreateAuthenticatedExecute(
		c.keypair,
		c.identityEntity,
		customCap, // <-- custom cap instead of c.capEntity
		requestID,
		uri,
		operation,
		params,
		resource,
	)
	if err != nil {
		return entity.Envelope{}, nil, fmt.Errorf("create execute: %w", err)
	}

	// Include connection-default auth entities (granter identity, parent
	// cap chain, etc.) so the remote can walk customCap's chain back
	// through c.capEntity to the root.
	for h, ent := range c.authenticateIncluded {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	// Include the custom cap itself + its signature so the remote can
	// resolve customCap.parent → c.capEntity (already in authenticateIncluded)
	// and verify the granter signed customCap.
	env.Include(customCap)
	if !customCapSig.ContentHash.IsZero() {
		env.Include(customCapSig)
	}

	for h, ent := range extras {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	rawBytes, err := c.sendAndReadResponse(ctx, requestID, env)
	if err != nil {
		return entity.Envelope{}, nil, err
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(rawBytes, &respEnv); err != nil {
		return entity.Envelope{}, rawBytes, fmt.Errorf("decode response: %w", err)
	}

	if c.verbose {
		c.traceExchange(requestID, uri, operation, params, respEnv)
	}

	return respEnv, rawBytes, nil
}

// TreePut stores an entity at the given tree path. Returns the stored content hash.
func (c *PeerClient) TreePut(ctx context.Context, path string, ent entity.Entity) (hash.Hash, error) {
	params, resource, err := tree.CreatePutRequest(path, &ent)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("create put request: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/tree", c.remotePeerID)
	env, _, err := c.SendExecute(ctx, uri, "put", params, resource)
	if err != nil {
		return hash.Hash{}, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return hash.Hash{}, fmt.Errorf("tree put status %d", respData.Status)
	}

	return ent.ContentHash, nil
}

// TreePutCAS stores an entity at the given tree path conditionally on the
// current binding matching expectedHash (V7 §3.9). Returns the response status
// (200 success, 409 mismatch, others on protocol error) so callers can assert
// CAS semantics explicitly.
func (c *PeerClient) TreePutCAS(ctx context.Context, path string, ent entity.Entity, expectedHash hash.Hash) (uint, error) {
	params, resource, err := tree.CreatePutRequestCAS(path, &ent, &expectedHash)
	if err != nil {
		return 0, fmt.Errorf("create CAS put request: %w", err)
	}
	uri := fmt.Sprintf("entity://%s/system/tree", c.remotePeerID)
	env, _, err := c.SendExecute(ctx, uri, "put", params, resource)
	if err != nil {
		return 0, err
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	return respData.Status, nil
}

// TreeSnapshot takes a snapshot of the given tree prefix.
// Returns the decoded snapshot data and the raw snapshot entity.
func (c *PeerClient) TreeSnapshot(ctx context.Context, prefix string) (types.SnapshotData, entity.Entity, error) {
	snapReq := types.SnapshotRequestData{Prefix: prefix}
	params, err := snapReq.ToEntity()
	if err != nil {
		return types.SnapshotData{}, entity.Entity{}, fmt.Errorf("create snapshot request: %w", err)
	}

	resource := &types.ResourceTarget{Targets: []string{prefix}}
	uri := fmt.Sprintf("entity://%s/system/tree", c.remotePeerID)
	env, _, err := c.SendExecute(ctx, uri, "snapshot", params, resource)
	if err != nil {
		return types.SnapshotData{}, entity.Entity{}, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.SnapshotData{}, entity.Entity{}, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return types.SnapshotData{}, entity.Entity{}, fmt.Errorf("snapshot status %d", respData.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return types.SnapshotData{}, entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
	}

	snapData, err := types.SnapshotDataFromEntity(resultEntity)
	if err != nil {
		return types.SnapshotData{}, entity.Entity{}, fmt.Errorf("decode snapshot data: %w", err)
	}

	return snapData, resultEntity, nil
}

// TreeDiff computes the diff between two snapshots. The snapshot entities are
// included in the EXECUTE envelope so the server can resolve them.
func (c *PeerClient) TreeDiff(ctx context.Context, baseSnap, targetSnap entity.Entity) (types.DiffData, error) {
	diffReq := types.DiffRequestData{
		Base:   baseSnap.ContentHash,
		Target: targetSnap.ContentHash,
	}
	params, err := diffReq.ToEntity()
	if err != nil {
		return types.DiffData{}, fmt.Errorf("create diff request: %w", err)
	}

	extras := map[hash.Hash]entity.Entity{
		baseSnap.ContentHash:   baseSnap,
		targetSnap.ContentHash: targetSnap,
	}

	uri := fmt.Sprintf("entity://%s/system/tree", c.remotePeerID)
	env, _, err := c.SendExecuteWithIncluded(ctx, uri, "diff", params, nil, extras)
	if err != nil {
		return types.DiffData{}, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.DiffData{}, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return types.DiffData{}, fmt.Errorf("diff status %d", respData.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return types.DiffData{}, fmt.Errorf("decode result entity: %w", err)
	}

	diffData, err := types.DiffDataFromEntity(resultEntity)
	if err != nil {
		return types.DiffData{}, fmt.Errorf("decode diff data: %w", err)
	}

	return diffData, nil
}

// TreeExtract extracts a subtree as a transferable envelope.
func (c *PeerClient) TreeExtract(ctx context.Context, prefix string) (entity.Entity, error) {
	extractReq := types.ExtractRequestData{Prefix: prefix}
	params, err := extractReq.ToEntity()
	if err != nil {
		return entity.Entity{}, fmt.Errorf("create extract request: %w", err)
	}

	resource := &types.ResourceTarget{Targets: []string{prefix}}
	uri := fmt.Sprintf("entity://%s/system/tree", c.remotePeerID)
	env, _, err := c.SendExecute(ctx, uri, "extract", params, resource)
	if err != nil {
		return entity.Entity{}, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return entity.Entity{}, fmt.Errorf("extract status %d", respData.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
	}

	return resultEntity, nil
}

// TreeMerge merges a snapshot into the tree.
// The snapshot entity is included in the EXECUTE envelope so the server can resolve it.
//
// Optional prefix args (variadic, but always passed as one or zero pairs):
//
//	sourcePrefix, targetPrefix string
//
// Snapshots no longer carry a prefix (EXTENSION-TREE I3); callers that snapshotted
// at a non-root prefix MUST pass targetPrefix to apply bindings back to the
// originating subtree (otherwise relative binding paths land at peer root and
// the merge hits the !exists branch instead of hash_equals).
func (c *PeerClient) TreeMerge(ctx context.Context, sourceSnap entity.Entity, strategy string, dryRun bool, prefixes ...string) (types.MergeResultData, error) {
	mergeReq := types.MergeRequestData{
		Source:   sourceSnap.ContentHash,
		Strategy: strategy,
	}
	if dryRun {
		t := true
		mergeReq.DryRun = &t
	}
	if len(prefixes) >= 1 {
		mergeReq.SourcePrefix = prefixes[0]
	}
	if len(prefixes) >= 2 {
		mergeReq.TargetPrefix = prefixes[1]
	}
	params, err := mergeReq.ToEntity()
	if err != nil {
		return types.MergeResultData{}, fmt.Errorf("create merge request: %w", err)
	}

	extras := map[hash.Hash]entity.Entity{
		sourceSnap.ContentHash: sourceSnap,
	}

	uri := fmt.Sprintf("entity://%s/system/tree", c.remotePeerID)
	env, _, err := c.SendExecuteWithIncluded(ctx, uri, "merge", params, nil, extras)
	if err != nil {
		return types.MergeResultData{}, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.MergeResultData{}, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return types.MergeResultData{}, fmt.Errorf("merge status %d", respData.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return types.MergeResultData{}, fmt.Errorf("decode result entity: %w", err)
	}

	mergeData, err := types.MergeResultDataFromEntity(resultEntity)
	if err != nil {
		return types.MergeResultData{}, fmt.Errorf("decode merge data: %w", err)
	}

	return mergeData, nil
}

// RemotePeerIdentityHash returns the remote peer's identity entity hash
// (available after connect).
func (c *PeerClient) RemotePeerIdentityHash() hash.Hash {
	return c.remotePeerIdentityHash
}

// Keypair returns the client's keypair.
func (c *PeerClient) Keypair() crypto.Keypair {
	return c.keypair
}

// IdentityEntity returns the client's identity entity.
func (c *PeerClient) IdentityEntity() entity.Entity {
	return c.identityEntity
}

// CapEntity returns the connection capability entity.
func (c *PeerClient) CapEntity() entity.Entity {
	return c.capEntity
}

// AuthenticateIncluded returns the included entities from the authenticate response.
func (c *PeerClient) AuthenticateIncluded() map[hash.Hash]entity.Entity {
	return c.authenticateIncluded
}

// SendRawEnvelope writes a pre-built envelope to the connection and reads the
// response. Returns the decoded response envelope, raw bytes, and any error.
// Unlike SendExecute, this does NOT add authentication entities — the caller
// has full control over envelope contents.
func (c *PeerClient) SendRawEnvelope(env entity.Envelope) (entity.Envelope, []byte, error) {
	// No caller context here; bound by perRequestTimeout via ioDeadline (ctx
	// carries no deadline) so a non-answering peer can't hang this path either.
	ctx := context.Background()
	// Route by the envelope's own request_id when the reader is active; if the
	// raw envelope isn't a decodable EXECUTE the id is "" and the reader's
	// single-in-flight fallback delivers the response anyway.
	var rawReqID string
	if execData, derr := types.ExecuteDataFromEntity(env.Root); derr == nil {
		rawReqID = execData.RequestID
	}
	rawBytes, err := c.sendAndReadResponse(ctx, rawReqID, env)
	if err != nil {
		return entity.Envelope{}, nil, err
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(rawBytes, &respEnv); err != nil {
		return entity.Envelope{}, rawBytes, fmt.Errorf("decode response: %w", err)
	}

	return respEnv, rawBytes, nil
}

// NextRequestID returns a unique request ID for this client session.
func (c *PeerClient) NextRequestID() string {
	return fmt.Sprintf("validate-%d", c.requestSeq.Add(1))
}

// CreateDeliveryToken creates a capability token and signature for use as a
// delivery token in subscribe requests. The token grants access to the inbox
// handler at deliverURI for the given operation.
//
// CreateDeliveryToken creates a delegated capability token for async delivery.
// The token delegates from the connection grant (granter=peer, grantee=validator)
// to a child token (granter=validator, grantee=peer) with the parent field set.
// This allows the peer to verify the chain: child → parent → root (peer).
func (c *PeerClient) CreateDeliveryToken(deliverURI, deliverOp string) (entity.Entity, entity.Entity, error) {
	return c.CreateDeliveryTokenWithTTL(deliverURI, deliverOp, 5*time.Minute)
}

// CreateDeliveryTokenWithTTL creates a delivery token with a specified TTL.
func (c *PeerClient) CreateDeliveryTokenWithTTL(deliverURI, deliverOp string, ttl time.Duration) (entity.Entity, entity.Entity, error) {
	now := uint64(time.Now().UnixMilli())
	expiresMs := now + uint64(ttl.Milliseconds())

	parentHash := c.capEntity.ContentHash
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/inbox"}},
				Resources:  types.CapabilityScope{Include: []string{deliverURI}},
				Operations: types.CapabilityScope{Include: []string{deliverOp}},
			},
		},
		Granter:   types.SingleSigGranter(c.identityEntity.ContentHash), // Validator is the granter (delegator)
		Grantee:   c.remotePeerIdentityHash,                             // Server is the grantee (will deliver)
		Parent:    &parentHash,                                          // Connection grant (peer→validator)
		CreatedAt: now,
		ExpiresAt: &expiresMs,
	}

	tokenEntity, err := tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create delivery token entity: %w", err)
	}

	// Sign with the subscriber's keypair (we are the granter).
	sig := c.keypair.Sign(tokenEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    tokenEntity.ContentHash,
		Signer:    c.identityEntity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create delivery token signature: %w", err)
	}

	return tokenEntity, sigEntity, nil
}

// Subscribe sends a subscribe EXECUTE to the system/subscription handler.
// Returns the subscription ID, the response envelope, raw bytes, and any error.
func (c *PeerClient) Subscribe(ctx context.Context, pattern, deliverURI, deliverOp string, tokenEntity, tokenSigEntity entity.Entity, events []string, limits *types.SubscriptionLimitsData) (string, entity.Envelope, []byte, error) {
	return c.SubscribeWithPayload(ctx, pattern, deliverURI, deliverOp, tokenEntity, tokenSigEntity, events, limits, false)
}

// SubscribeWithPayload is Subscribe with the EXTENSION-SUBSCRIPTION v3.14
// include_payload option. When includePayload=true, the source will bundle
// the changed entity into the delivery envelope's `included` map (§4.2),
// gated server-side on the v3.13 read-authorization check (caller MUST hold
// tree:get on the subscribed resource else 403 payload_unauthorized).
func (c *PeerClient) SubscribeWithPayload(ctx context.Context, pattern, deliverURI, deliverOp string, tokenEntity, tokenSigEntity entity.Entity, events []string, limits *types.SubscriptionLimitsData, includePayload bool) (string, entity.Envelope, []byte, error) {
	subReq := types.SubscriptionRequestData{
		Events: events,
		DeliverTo: types.DeliverySpec{
			URI:       deliverURI,
			Operation: deliverOp,
		},
		DeliverToken:   tokenEntity.ContentHash,
		Limits:         limits,
		IncludePayload: includePayload,
	}

	params, err := subReq.ToEntity()
	if err != nil {
		return "", entity.Envelope{}, nil, fmt.Errorf("create subscribe request: %w", err)
	}

	resource := &types.ResourceTarget{Targets: []string{pattern}}
	extras := map[hash.Hash]entity.Entity{
		tokenEntity.ContentHash:    tokenEntity,
		tokenSigEntity.ContentHash: tokenSigEntity,
	}

	uri := fmt.Sprintf("entity://%s/system/subscription", c.remotePeerID)
	env, rawBytes, err := c.SendExecuteWithIncluded(ctx, uri, "subscribe", params, resource, extras)
	if err != nil {
		return "", entity.Envelope{}, rawBytes, err
	}

	// Decode response to extract subscription_id.
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return "", env, rawBytes, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return "", env, rawBytes, fmt.Errorf("subscribe status %d", respData.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return "", env, rawBytes, fmt.Errorf("decode result entity: %w", err)
	}

	subData, err := types.SubscriptionDataFromEntity(resultEntity)
	if err != nil {
		return "", env, rawBytes, fmt.Errorf("decode subscription data: %w", err)
	}

	return subData.SubscriptionID, env, rawBytes, nil
}

// Unsubscribe cancels a subscription by ID via the system/subscription handler.
func (c *PeerClient) Unsubscribe(ctx context.Context, subscriptionID string) (entity.Envelope, []byte, error) {
	cancelReq := types.SubscriptionCancelData{SubscriptionID: subscriptionID}
	params, err := cancelReq.ToEntity()
	if err != nil {
		return entity.Envelope{}, nil, fmt.Errorf("create unsubscribe request: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/subscription", c.remotePeerID)
	return c.SendExecute(ctx, uri, "unsubscribe", params, nil)
}

// ForeignCapability builds a self-loop capability whose granter is a fresh
// peer identity unrelated to the validator's identity. Used to exercise R1
// rejection paths: when the validator embeds this cap as dispatch_capability,
// deliver_token, or compute/apply.capability, the chain-root check MUST
// reject because the validator (EXECUTE author) is nowhere in the granter
// chain. Mirrors proposal §10's "adversary references admin's cap" vector.
//
// Returns the cap entity, its signature, and the foreign identity entity.
// All three must be added to the EXECUTE envelope's Included so the chain
// walk can resolve the granter identity.
func (c *PeerClient) ForeignCapability(handlers, resources, operations []string) (entity.Entity, entity.Entity, entity.Entity, error) {
	foreignKP, err := crypto.Generate()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("generate foreign keypair: %w", err)
	}
	foreignIdentity, err := foreignKP.IdentityEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("foreign identity entity: %w", err)
	}
	now := uint64(time.Now().UnixMilli())
	expires := now + uint64(time.Hour.Milliseconds())
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: handlers},
				Resources:  types.CapabilityScope{Include: resources},
				Operations: types.CapabilityScope{Include: operations},
			},
		},
		Granter:   types.SingleSigGranter(foreignIdentity.ContentHash),
		Grantee:   foreignIdentity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	tokenEntity, err := tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("foreign cap entity: %w", err)
	}
	sig := foreignKP.Sign(tokenEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    tokenEntity.ContentHash,
		Signer:    foreignIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{}, fmt.Errorf("foreign cap signature: %w", err)
	}
	return tokenEntity, sigEntity, foreignIdentity, nil
}

// CreateDispatchCapability builds an attenuated capability suitable for
// embedding as a continuation's dispatch_capability (or similar embedded-cap
// fields). The validator's identity is the granter, so R1 chain-root checks
// pass: the validator (EXECUTE author) appears at the leaf granter.
//
// Grantee is the remote peer's identity so the remote handler can wield the
// cap when it dispatches. Parent is the connection grant, anchoring the
// chain in the cap the validator legitimately holds.
//
// Returns (capEntity, signatureEntity, error). Both must be in the EXECUTE
// envelope's Included set when sending the install request so the install
// handler can resolve and walk the chain.
// CreateDispatchCapabilityWithGrants is the multi-grant-entry variant of
// CreateDispatchCapability. Used by tests that need a cap whose authority
// is split across multiple grant dimensions (e.g., SI-15 skipped_grantees
// — one entry authorizes the dispatch on system/role:re-derive, a second
// covers the role's templated grants for a SPECIFIC assignee but not for
// others).
//
// CRITICAL DIFFERENCES from CreateDispatchCapability:
//   - Grantee is the CLIENT's identity (a self-cap), not the remote
//     peer's. This is correct for tests where the CLIENT wields the cap
//     directly via SendExecuteWithCap. (CreateDispatchCapability's
//     grantee=remote is for continuation-install style use where the
//     remote stores the cap and dispatches with it later.)
//   - Expiration inherits from the connection cap. Per V7 §5.6
//     attenuation, a child cap with nil expires_at chained from a
//     parent with finite expires_at is invalid (Python's chain validator
//     rejects this strictly; Go and Rust currently accept). To avoid
//     that cross-impl divergence in test caps, we explicitly inherit
//     the connection cap's expiration. If the connection cap has nil,
//     the test cap also has nil.
//
// Granter = client identity (signs the cap).
// Grantee = client identity (self-cap; the wielder).
// Parent  = client's connection cap (anchors chain to root).
func (c *PeerClient) CreateDispatchCapabilityWithGrants(grants []types.GrantEntry) (entity.Entity, entity.Entity, error) {
	now := uint64(time.Now().UnixMilli())

	// Inherit expiration from the connection cap (V7 §5.6 attenuation).
	parentExpires, err := c.connectionCapExpiresAt()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, err
	}

	parentHash := c.capEntity.ContentHash
	tokenData := types.CapabilityTokenData{
		Grants:    grants,
		Granter:   types.SingleSigGranter(c.identityEntity.ContentHash),
		Grantee:   c.identityEntity.ContentHash, // self-cap; client wields directly
		Parent:    &parentHash,
		CreatedAt: now,
		ExpiresAt: parentExpires,
	}
	tokenEntity, err := tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create multi-grant dispatch cap entity: %w", err)
	}
	sig := c.keypair.Sign(tokenEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    tokenEntity.ContentHash,
		Signer:    c.identityEntity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create multi-grant dispatch cap signature: %w", err)
	}
	return tokenEntity, sigEntity, nil
}

// CreateDispatchCapabilityWithGrantsExpiry is the explicit-expiry
// variant of CreateDispatchCapabilityWithGrants. Equivalent to
// CreateChainedCap(connectionCap, grants, expiresAt).
func (c *PeerClient) CreateDispatchCapabilityWithGrantsExpiry(grants []types.GrantEntry, expiresAt *uint64) (entity.Entity, entity.Entity, error) {
	return c.CreateChainedCap(c.capEntity, grants, expiresAt)
}

// CreateChainedCap mints a self-cap parented at `parentEnt`. The parent
// must be a cap whose grantee == client identity so the client can
// legitimately wield the chained child. Used by adversarial tests that
// need a multi-link chain — e.g., a finite-expiry intermediate followed
// by a nil-expiry child to drive V7 §5.6 chain rejection.
// CreateChainedCapGrantedTo is CreateChainedCap with an explicit grantee
// (not self-wielded). Required for cross-peer continuation dispatch_capability
// per EXTENSION-CONTINUATION v1.11 §4.2 case 3 (iii): granter = this
// (installer, in-chain), grantee = the dispatching host peer (the EXECUTE
// author), parent = the B-conferred root.
func (c *PeerClient) CreateChainedCapGrantedTo(parentEnt entity.Entity, grants []types.GrantEntry, grantee hash.Hash, expiresAt *uint64) (entity.Entity, entity.Entity, error) {
	now := uint64(time.Now().UnixMilli())
	parentHash := parentEnt.ContentHash
	tokenData := types.CapabilityTokenData{
		Grants:    grants,
		Granter:   types.SingleSigGranter(c.identityEntity.ContentHash),
		Grantee:   grantee,
		Parent:    &parentHash,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	tokenEntity, err := tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create chained cap entity: %w", err)
	}
	sig := c.keypair.Sign(tokenEntity.ContentHash.Bytes())
	sigEntity, err := types.SignatureData{
		Target:    tokenEntity.ContentHash,
		Signer:    c.identityEntity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create chained cap signature: %w", err)
	}
	return tokenEntity, sigEntity, nil
}

func (c *PeerClient) CreateChainedCap(parentEnt entity.Entity, grants []types.GrantEntry, expiresAt *uint64) (entity.Entity, entity.Entity, error) {
	now := uint64(time.Now().UnixMilli())
	parentHash := parentEnt.ContentHash
	tokenData := types.CapabilityTokenData{
		Grants:    grants,
		Granter:   types.SingleSigGranter(c.identityEntity.ContentHash),
		Grantee:   c.identityEntity.ContentHash,
		Parent:    &parentHash,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	tokenEntity, err := tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create chained cap entity: %w", err)
	}
	sig := c.keypair.Sign(tokenEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    tokenEntity.ContentHash,
		Signer:    c.identityEntity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create chained cap signature: %w", err)
	}
	return tokenEntity, sigEntity, nil
}

// ConnectionCapExpiresAt is the exported form of connectionCapExpiresAt,
// used by behavioral tests that need to compare a minted cap's expiry
// against the validate-peer client's connection cap.
func (c *PeerClient) ConnectionCapExpiresAt() (*uint64, error) {
	return c.connectionCapExpiresAt()
}

// connectionCapExpiresAt returns the expiration on the validate-peer
// client's connection cap, or nil if the cap has no expiration. Used by
// CreateDispatchCapabilityWithGrants to inherit expiration on minted
// child caps (V7 §5.6 attenuation rule).
func (c *PeerClient) connectionCapExpiresAt() (*uint64, error) {
	if c.capEntity.ContentHash.IsZero() {
		return nil, nil // no connection cap yet
	}
	connCap, err := types.CapabilityTokenDataFromEntity(c.capEntity)
	if err != nil {
		return nil, fmt.Errorf("decode connection cap: %w", err)
	}
	return connCap.ExpiresAt, nil
}

func (c *PeerClient) CreateDispatchCapability(handlers, resources, operations []string) (entity.Entity, entity.Entity, error) {
	now := uint64(time.Now().UnixMilli())
	expiresMs := now + uint64(time.Hour.Milliseconds())

	parentHash := c.capEntity.ContentHash
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: handlers},
				Resources:  types.CapabilityScope{Include: resources},
				Operations: types.CapabilityScope{Include: operations},
			},
		},
		Granter:   types.SingleSigGranter(c.identityEntity.ContentHash),
		Grantee:   c.remotePeerIdentityHash,
		Parent:    &parentHash,
		CreatedAt: now,
		ExpiresAt: &expiresMs,
	}
	tokenEntity, err := tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create dispatch cap entity: %w", err)
	}
	sig := c.keypair.Sign(tokenEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    tokenEntity.ContentHash,
		Signer:    c.identityEntity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("create dispatch cap signature: %w", err)
	}
	return tokenEntity, sigEntity, nil
}

// SendInstall sends a system/continuation:install EXECUTE. continuationEnt
// must be a system/continuation or system/continuation/join entity (the
// install handler discriminates on params.type per V7 §3.2 path-as-resource
// — install path lives in resource, not params). The dispatch_capability
// cap entity (and its signature plus any parent chain entities) must be in
// extras so the install handler can resolve and walk the chain.
func (c *PeerClient) SendInstall(ctx context.Context, installPath string, continuationEnt entity.Entity, extras map[hash.Hash]entity.Entity) (entity.Envelope, []byte, error) {
	uri := fmt.Sprintf("entity://%s/system/continuation", c.remotePeerID)
	resource := &types.ResourceTarget{Targets: []string{installPath}}
	return c.SendExecuteWithIncluded(ctx, uri, "install", continuationEnt, resource, extras)
}

// SendAdvance sends an advance operation to the system/continuation handler.
// Returns the response envelope, raw bytes, and any error.
func (c *PeerClient) SendAdvance(ctx context.Context, path string, result cbor.RawMessage, status *uint) (entity.Envelope, []byte, error) {
	return c.SendAdvanceWithIncluded(ctx, path, result, status, nil)
}

// SendAdvanceWithIncluded is SendAdvance with envelope `included` extras.
// Required when the continuation's result_transform uses deref_included
// (EXTENSION-CONTINUATION v1.17): the op resolves a hash field by looking
// up the entity in the envelope's included map. The included entries must
// be on the advance EXECUTE envelope so the continuation engine sees them
// at apply time, per V7 §3.3 v7.51 request-side preservation.
func (c *PeerClient) SendAdvanceWithIncluded(ctx context.Context, path string, result cbor.RawMessage, status *uint, extras map[hash.Hash]entity.Entity) (entity.Envelope, []byte, error) {
	advanceReq := types.ContinuationAdvanceRequestData{
		Result: result,
		Status: status,
	}
	params, err := advanceReq.ToEntity()
	if err != nil {
		return entity.Envelope{}, nil, fmt.Errorf("create advance request: %w", err)
	}

	resource := &types.ResourceTarget{Targets: []string{path}}
	uri := fmt.Sprintf("entity://%s/system/continuation", c.remotePeerID)
	return c.SendExecuteWithIncluded(ctx, uri, "advance", params, resource, extras)
}

// SendExecuteRaw sends an authenticated EXECUTE and returns the response envelope,
// raw bytes, and the decoded ExecuteResponseData. Unlike SendExecute, this also
// decodes the response data for convenience.
func (c *PeerClient) SendExecuteRaw(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (types.ExecuteResponseData, entity.Envelope, []byte, error) {
	env, rawBytes, err := c.SendExecute(ctx, uri, operation, params, resource)
	if err != nil {
		return types.ExecuteResponseData{}, env, rawBytes, err
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.ExecuteResponseData{}, env, rawBytes, fmt.Errorf("decode response: %w", err)
	}
	return respData, env, rawBytes, nil
}
