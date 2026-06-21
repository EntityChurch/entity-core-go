// HTTPConnection wires the §5 / Amendment 3 http live transport into the
// outbound pool. Wraps an http.Client + session correlation header
// (X-Entity-Session) per httplive's existing connector pattern, and runs
// the same HELLO → AUTHENTICATE handshake the TCP Connection runs — over
// POST round-trips instead of streamed wire frames.
//
// Once both peers publish an HTTP profile, A→B and B→A are independent
// outbound endpoints; the F-WB28 / Class G deadlock that motivated TCP's
// multiplexed reader cannot recur because each Execute is a fresh POST
// goroutine with no shared in-flight state. After PerformConnect returns,
// sessionID and session are effectively immutable, so Execute reads them
// concurrently without per-endpoint serialization.

package peer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// HTTPConnection is the HTTP-substrate outbound endpoint type used in the
// remote pool. Concurrency-safe for Execute calls after PerformConnect.
type HTTPConnection struct {
	peer       *Peer
	url        string
	httpClient *http.Client

	// Set during PerformConnect (single goroutine); read-only after
	// PerformConnect returns successfully. Subsequent Execute callers
	// observe these through the pool insertion's happens-before edge,
	// so no further synchronization is needed.
	sessionID string
	session   *Session

	// closed is checked at Execute entry; flipped by Close. Atomic
	// because Close races with in-flight Executes.
	closed atomic.Bool
}

// newHTTPConnection builds an HTTPConnection bound to a POST endpoint URL
// (e.g. "https://peer.example/entity") but does NOT perform the
// handshake — call PerformConnect next.
func newHTTPConnection(p *Peer, url string) *HTTPConnection {
	return &HTTPConnection{
		peer:       p,
		url:        url,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Session returns the post-handshake session, or nil if PerformConnect
// has not yet completed.
func (c *HTTPConnection) Session() *Session {
	return c.session
}

// SessionID returns the X-Entity-Session value the server allocated for
// this endpoint. Empty before the first round-trip.
func (c *HTTPConnection) SessionID() string {
	return c.sessionID
}

// IsClosed reports whether the endpoint has been torn down.
func (c *HTTPConnection) IsClosed() bool {
	return c.closed.Load()
}

// Close marks the endpoint dead so the pool drops it. HTTP has no
// persistent socket; there is no listener to wake. Idempotent.
func (c *HTTPConnection) Close() error {
	c.closed.Store(true)
	return nil
}

// PerformConnect runs HELLO → HELLO_RESPONSE → AUTHENTICATE →
// AUTHENTICATE_RESPONSE over successive POSTs. Mirrors *Connection.
// PerformConnect but uses HTTP round-trips instead of the streamed
// wire codec. After it returns success, sessionID and session are
// effectively immutable.
func (c *HTTPConnection) PerformConnect(ctx context.Context) error {
	kp := c.peer.keypair

	// 1. HELLO → HELLO_RESPONSE.
	helloEnv, _, err := protocol.CreateHelloExecute(kp, nil)
	if err != nil {
		return fmt.Errorf("create hello: %w", err)
	}
	helloResp, err := c.roundTrip(ctx, helloEnv, true /* capture session id */)
	if err != nil {
		return fmt.Errorf("hello round-trip: %w", err)
	}
	if err := c.validateEnv("hello_response", helloResp); err != nil {
		return err
	}

	theirNonce, remotePeerID, theirHashFormats, err := extractHelloResponse(helloResp)
	if err != nil {
		return fmt.Errorf("extract hello response: %w", err)
	}

	// V7 v7.69 §4.5 — derive the connection's active content_hash_format
	// from our preference list crossed with the responder's hello.
	activeFormat, _, ok := protocol.NegotiateActiveHashFormat(
		protocol.DefaultAdvertisedHashFormats(),
		theirHashFormats,
	)
	if !ok {
		return fmt.Errorf("hash_formats negotiation failed: ours=%v theirs=%v (V7 v7.69 §4.5 — incompatible_hash_format)",
			protocol.DefaultAdvertisedHashFormats(), theirHashFormats)
	}

	// 2. AUTHENTICATE → AUTHENTICATE_RESPONSE — authored under the
	//    negotiated active content_hash_format (V7 v7.69 §4.5a).
	authEnv, err := protocol.CreateAuthenticateExecuteFormat(kp, theirNonce, activeFormat)
	if err != nil {
		return fmt.Errorf("create authenticate: %w", err)
	}
	authResp, err := c.roundTrip(ctx, authEnv, false /* session id already pinned */)
	if err != nil {
		return fmt.Errorf("authenticate round-trip: %w", err)
	}
	if err := c.validateEnv("authenticate_response", authResp); err != nil {
		return err
	}

	c.session = &Session{
		RemotePeerID: remotePeerID,
		Envelope:     authResp,
	}
	if capEntity, capErr := extractCapabilityFromResponse(authResp); capErr == nil {
		c.session.Capability = &capEntity
	}

	// Envelope-included signature ingestion — parity with
	// *Connection.PerformConnect (V7 §6.5). Without it, the conferred
	// cap sits in Session.Capability while its signature + granter
	// identity remain unpersisted; subsequent chain-walks hit
	// chain_unreachable until another dispatched op happens to populate
	// them via the dispatch path's own ingest.
	if c.peer != nil {
		if ingestErr := protocol.IngestEnvelopeSignatures(c.peer.Store(), c.peer.LocationIndex(), authResp.Included); ingestErr != nil {
			c.peer.debugf("http-connect: envelope ingest after handshake: %v", ingestErr)
		}
	}

	return nil
}

// Execute sends an authenticated EXECUTE over POST and returns the
// response envelope. Safe for concurrent callers (sessionID + session
// are read-only post-PerformConnect; each call gets its own POST).
func (c *HTTPConnection) Execute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, async ...*protocol.AsyncDelivery) (entity.Envelope, error) {
	if c.IsClosed() {
		return entity.Envelope{}, fmt.Errorf("execute: %w", ErrConnClosed)
	}
	if c.session == nil || c.session.Capability == nil {
		return entity.Envelope{}, fmt.Errorf("connection not established")
	}

	requestID := fmt.Sprintf("req-%d", c.session.requestSeq.Add(1))

	// EXTENSION-CONTINUATION §4.2 case 3 / §8.1: scoped dispatch cap
	// override path, parity with *Connection.Execute. Nil override =
	// ordinary connection-authorized EXECUTE.
	effectiveCap := *c.session.Capability
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

	// Include entities from the authenticate response (granter identity,
	// capability signatures) so the server can verify the chain.
	for h, ent := range c.session.Envelope.Included {
		env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	return c.roundTrip(ctx, env, false)
}

// ExecuteWithIncluded mirrors *Connection.ExecuteWithIncluded — the TCP
// path that powers RELAY intermediate-hop forwarding. Builds a normal
// authenticated EXECUTE for (uri, operation, params, resource), then
// merges `extras` into the envelope's Included map so the receiver's
// `lookupIncluded` resolves the carried entities (the inner envelope on
// a forward-request, per §3.1 + §10.4 opacity).
func (c *HTTPConnection) ExecuteWithIncluded(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, extras map[hash.Hash]entity.Entity, async ...*protocol.AsyncDelivery) (entity.Envelope, error) {
	if c.IsClosed() {
		return entity.Envelope{}, fmt.Errorf("execute: %w", ErrConnClosed)
	}
	if c.session == nil || c.session.Capability == nil {
		return entity.Envelope{}, fmt.Errorf("connection not established")
	}

	requestID := fmt.Sprintf("req-%d", c.session.requestSeq.Add(1))
	effectiveCap := *c.session.Capability
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

	return c.roundTrip(ctx, env, false)
}

// SendRawFrame POSTs pre-encoded envelope bytes verbatim to the
// destination's HTTP-live endpoint. The transport-agnostic counterpart
// of *Connection.SendRawFrame: RELAY §3.1.1 says "deliver the inner
// envelope verbatim"; on HTTP-live, that means POST the bytes as the
// request body (the server-side decodes the body as a bare ECF envelope
// and dispatches through the same path TCP uses — see
// ext/httplive/server.go ServeHTTP).
//
// The relay's HTTPConnection to the destination is already authenticated
// (PerformConnect ran HELLO → AUTHENTICATE); the X-Entity-Session header
// pins this POST to that session so the destination's dispatcher sees
// the inbound EXECUTE as arriving on an authenticated connection. The
// inner envelope's own signature + cap chain (signed by the *originator*,
// not by us) is then verified per-envelope by VerifyRequestWithBinding
// exactly as on TCP — the relay never sees the inner's caller identity.
//
// Fire-and-forget like the TCP raw-frame path: any response from the
// destination flows back via INBOX deliver_to per §3.1, not through the
// HTTP response of this POST. We read + discard the response body to
// drain the connection; non-200 surfaces as an error so the relay can
// trigger §6.2.1 fallback.
func (c *HTTPConnection) SendRawFrame(ctx context.Context, data []byte) error {
	if c.IsClosed() {
		return fmt.Errorf("raw-frame: %w", ErrConnClosed)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build raw-frame request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cbor")
	if c.sessionID != "" {
		req.Header.Set(httplive.SessionHeader, c.sessionID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST raw-frame %s: %w", c.url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("raw-frame http %d: %s", resp.StatusCode, truncateBody(string(body), 200))
	}
	return nil
}

// roundTrip POSTs one envelope and returns the decoded response. When
// captureSession is true the server-allocated X-Entity-Session header
// is read into c.sessionID — used during PerformConnect's first HELLO
// round-trip. Post-handshake calls pass false; the server echoes the
// same ID and we don't need to re-read it.
func (c *HTTPConnection) roundTrip(ctx context.Context, env entity.Envelope, captureSession bool) (entity.Envelope, error) {
	reqBytes, err := ecf.Encode(env)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("encode request envelope: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBytes))
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cbor")
	if c.sessionID != "" {
		req.Header.Set(httplive.SessionHeader, c.sessionID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("POST %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return entity.Envelope{}, fmt.Errorf("http %d: %s", resp.StatusCode, truncateBody(string(body), 200))
	}

	if captureSession {
		if id := resp.Header.Get(httplive.SessionHeader); id != "" {
			c.sessionID = id
		}
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(body, &respEnv); err != nil {
		return entity.Envelope{}, fmt.Errorf("decode response envelope: %w", err)
	}
	return respEnv, nil
}

// validateEnv runs envelope hash validation with the same diagnostic
// log path the TCP Connection uses. The peer's debug log gets dumped on
// mismatch.
func (c *HTTPConnection) validateEnv(label string, env entity.Envelope) error {
	if err := env.ValidateAll(); err != nil {
		if c.peer != nil {
			c.peer.debugf("http-connect: hash mismatch in %s: %v", label, err)
		}
		return fmt.Errorf("validate %s: %w", label, err)
	}
	return nil
}

func truncateBody(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
