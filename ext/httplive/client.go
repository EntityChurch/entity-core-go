// HTTP-live connector side. RoundTrip wraps one envelope-in /
// envelope-out exchange in a single HTTP POST. Session correlation
// across multiple round-trips is preserved via SessionHeader so the
// HELLO → AUTHENTICATE → EXECUTE handshake works identically to TCP.
//
// Wire shape per Amendment 3: bare ECF envelope as the HTTP body, no
// inner length prefix — HTTP's Content-Length / chunked frames it.

package httplive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
)

// Client performs HTTP-live POSTs against a peer's `http` profile URL.
// Holds session state across round-trips so the connect handshake
// works the same way it does over TCP.
//
// Not safe for concurrent use across goroutines — one Client maps to
// one logical connection.
type Client struct {
	httpClient *http.Client
	url        string
	sessionID  string // set by the server on the first response
}

// NewClient builds a Client targeting the given http profile URL
// (e.g. "https://peer.example/entity"). A nil http.Client falls
// back to a default with 30s timeout.
func NewClient(client *http.Client, url string) *Client {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{httpClient: client, url: url}
}

// SessionID returns the session ID the server allocated, or "" if
// no round-trip has happened yet. Useful for diagnostics + tests.
func (c *Client) SessionID() string {
	return c.sessionID
}

// RoundTrip POSTs a single bare ECF envelope and returns the decoded
// response envelope per Amendment 3 (no inner length prefix; HTTP's
// own framing delimits the body). The first round-trip's server-
// allocated session ID is captured and echoed back on subsequent calls.
func (c *Client) RoundTrip(ctx context.Context, env entity.Envelope) (entity.Envelope, error) {
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
		req.Header.Set(SessionHeader, c.sessionID)
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

	// HTTP transport failures (405 method, 502 dispatch, etc.) surface
	// as non-200; we treat them as connection-level errors rather than
	// trying to decode a non-envelope body.
	if resp.StatusCode != http.StatusOK {
		return entity.Envelope{}, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	if id := resp.Header.Get(SessionHeader); id != "" {
		c.sessionID = id
	}

	var respEnv entity.Envelope
	if err := ecf.Decode(body, &respEnv); err != nil {
		return entity.Envelope{}, fmt.Errorf("decode response envelope: %w", err)
	}
	if err := respEnv.ValidateAll(); err != nil {
		return entity.Envelope{}, fmt.Errorf("validate response envelope: %w", err)
	}
	return respEnv, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
