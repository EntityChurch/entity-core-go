// PeerClient transport abstraction.
//
// validate.PeerClient drives the V7 wire protocol (HELLO/AUTHENTICATE/
// EXECUTE) one envelope-pair at a time — every test in the suite follows
// the strict write-then-read pattern, never two writes back-to-back, never
// multiplexed responses. That property lets the transport layer be a thin
// shim under a `WriteEnvelope` / `ReadFrame` interface: TCP holds an open
// net.Conn and uses the streaming wire codec; HTTP buffers the write into
// a pending envelope and flushes it on the next ReadFrame as one POST.
//
// Per EXTENSION-NETWORK Amendment 3 §6.5.2c, the HTTP body is a bare ECF
// envelope — NO inner 4-byte length prefix — and session continuity across
// the HELLO → AUTHENTICATE → EXECUTE handshake rides the X-Entity-Session
// header (allocated by the server on the first response, echoed by the
// client thereafter). The existing ext/httplive.Client implements both
// rules, so the HTTP transport just wraps it.

package validate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/wire"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// peerTransport carries a single envelope-pair exchange between
// validate.PeerClient and a peer. Implementations are NOT required to be
// concurrent-safe — the suite drives one exchange at a time per client.
type peerTransport interface {
	WriteEnvelope(ctx context.Context, env entity.Envelope) error
	ReadFrame(ctx context.Context) ([]byte, error)
	Close() error
}

// backgroundReadable is implemented by transports that hold a persistent
// socket the validator's background reader can drain continuously. TCP
// implements it; HTTP does not (each ReadFrame is a fresh POST, so there is
// no socket to drain between requests and no backpressure to deadlock on).
// PeerClient.startBackgroundReader type-asserts this to decide whether to
// spawn the reader goroutine.
type backgroundReadable interface {
	// ReadFrameBlocking reads one envelope frame with no deadline, blocking
	// until a frame arrives or the connection is closed. Close()ing the
	// transport unblocks an in-flight call with an error.
	ReadFrameBlocking() ([]byte, error)
}

// tcpTransport is the TCP wire-codec transport. Preserves the validator's
// pre-HTTP behavior exactly: socket-deadline-bounded read/write of
// length-prefixed envelope frames (V7 §1.6).
type tcpTransport struct {
	conn net.Conn
}

func newTCPTransport(ctx context.Context, addr string) (*tcpTransport, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &tcpTransport{conn: conn}, nil
}

func (t *tcpTransport) WriteEnvelope(ctx context.Context, env entity.Envelope) error {
	if err := t.conn.SetWriteDeadline(ioDeadline(ctx)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	defer t.conn.SetWriteDeadline(time.Time{})
	return wire.WriteEnvelope(t.conn, env)
}

func (t *tcpTransport) ReadFrame(ctx context.Context) ([]byte, error) {
	if err := t.conn.SetReadDeadline(ioDeadline(ctx)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	defer t.conn.SetReadDeadline(time.Time{})
	return wire.ReadFrame(t.conn)
}

// ReadFrameBlocking reads one frame with no socket deadline, for the
// background reader's continuous loop. Unlike ReadFrame (which bounds each
// read by the per-request ctx deadline), this blocks until a frame arrives
// or Close() shuts the socket down — the per-request timeout is enforced by
// the caller's select in sendAndReadResponse, mirroring the peer runtime's
// reader-task + per-request deadline split (core/peer/connection.go).
func (t *tcpTransport) ReadFrameBlocking() ([]byte, error) {
	if err := t.conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear read deadline: %w", err)
	}
	return wire.ReadFrame(t.conn)
}

func (t *tcpTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

// httpTransport implements the EXTENSION-NETWORK §6.5.2c http live transport
// (Amendment 3) by buffering one envelope on WriteEnvelope and flushing it
// as one POST when ReadFrame is called. Each write/read pair = one POST.
// The validator's strict pairing makes this safe — multiplexed responses
// or back-to-back writes would not survive this design, but the suite has
// never produced either.
type httpTransport struct {
	url        string
	httpClient *http.Client
	sessionID  string
	pending    []byte
}

// newHTTPTransport binds to the http(s):// POST endpoint. Per Amendment 3
// the URL is the operator's choice — typically /entity (httplive.Server's
// default) but anything the live listener accepts.
func newHTTPTransport(url string) *httpTransport {
	return &httpTransport{
		url:        url,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (t *httpTransport) WriteEnvelope(ctx context.Context, env entity.Envelope) error {
	if t.pending != nil {
		return fmt.Errorf("http transport: previous envelope not yet flushed (validator did two writes without an intervening read)")
	}
	body, err := ecf.Encode(env)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}
	t.pending = body
	return nil
}

func (t *httpTransport) ReadFrame(ctx context.Context) ([]byte, error) {
	if t.pending == nil {
		return nil, fmt.Errorf("http transport: ReadFrame with no pending write (validator did a bare read)")
	}
	body := t.pending
	t.pending = nil

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cbor")
	if t.sessionID != "" {
		req.Header.Set(httplive.SessionHeader, t.sessionID)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", t.url, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, truncateClientBody(string(respBody), 200))
	}

	// Capture the server-allocated session ID on the first round-trip;
	// subsequent POSTs echo it via the header so HELLO →
	// AUTHENTICATE → EXECUTE share one logical handshake context.
	if id := resp.Header.Get(httplive.SessionHeader); id != "" {
		t.sessionID = id
	}

	// Amendment 3 §6.5.2c: the HTTP body is the bare ECF envelope. No
	// inner length prefix — return the bytes verbatim. Callers ecf.Decode
	// directly (same as the TCP path, where wire.ReadFrame strips the
	// length prefix before returning the same shape of bytes).
	return respBody, nil
}

func (t *httpTransport) Close() error {
	// HTTP has no persistent socket. Clear pending so a reused transport
	// (none in practice today) doesn't leak buffered bytes.
	t.pending = nil
	return nil
}

// isHTTPAddr returns true when addr looks like an HTTP-live URL. Used by
// NewPeerClient to choose the transport without an extra flag.
func isHTTPAddr(addr string) bool {
	return strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://")
}

func truncateClientBody(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
