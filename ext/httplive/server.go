// Package httplive implements the §5 / §4.x http live transport — POST
// EXECUTE → EXECUTE-RESPONSE over HTTP, half-duplex, no server-push.
// Per PROPOSAL-EXTENSION-NETWORK-TRANSPORT-FAMILY §5 + cohort handoff
// §10 (Chunk D) + EXTENSION-NETWORK v1.4 Amendment 3 §6.5.2c
// (arch ruling, commit 4583a65).
//
// Wire shape (per Amendment 3): a POST request body carries ONE bare
// ECF-encoded envelope — NO inner 4-byte length prefix. HTTP's own
// Content-Length / chunked framing delimits the body. The TCP wire
// codec's length prefix MUST NOT be applied here. This matches
// V7 §1.6: "the 4-byte length prefix is the default TCP framing;
// other transports define their own framing and limits." HTTP
// already frames the body; an inner prefix gives two disagreeing
// length authorities AND breaks fetch/curl/CDN/proxy composition —
// which is the entire reason this transport exists.
//
// Multi-step handshakes (HELLO → HELLO_RESPONSE → AUTHENTICATE →
// AUTHENTICATE_RESPONSE → EXECUTE → EXECUTE-RESPONSE) are spread
// across multiple POSTs correlated by the `X-Entity-Session` header.
//
// Caps accrue across the request sequence per §5.3: the server maintains
// per-session ConnectionState in memory with a TTL. The connect handshake
// rules + dispatcher behavior are identical to TCP; only the framing
// substrate is HTTP.

package httplive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/protocol"
)

// SessionHeader is the HTTP header connector + server use to correlate
// multiple POSTs into one logical connection sequence. Server returns
// its allocated ID on the first response; connector echoes it on
// subsequent POSTs.
const SessionHeader = "X-Entity-Session"

// DefaultSessionTTL is how long a server keeps an idle session's
// ConnectionState before evicting it. Operators MAY override.
const DefaultSessionTTL = 30 * time.Minute

// sessionEntry holds per-session ConnectionState + last-touched stamp
// for TTL eviction.
type sessionEntry struct {
	state *protocol.ConnectionState
	touch time.Time
}

// sessionStore is a goroutine-safe map of session-id → ConnectionState.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionEntry
	ttl      time.Duration
	now      func() time.Time
}

func newSessionStore(ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return &sessionStore{
		sessions: make(map[string]*sessionEntry),
		ttl:      ttl,
		now:      time.Now,
	}
}

// getOrCreate returns the session for id, creating one if absent. When
// id is empty a fresh random ID is allocated and returned. The returned
// ID is what the server echoes back via SessionHeader.
func (s *sessionStore) getOrCreate(id string) (string, *protocol.ConnectionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if id != "" {
		if e, ok := s.sessions[id]; ok {
			e.touch = s.now()
			return id, e.state
		}
	}
	newID := allocSessionID()
	st := protocol.NewConnectionState()
	s.sessions[newID] = &sessionEntry{state: st, touch: s.now()}
	return newID, st
}

// sweepLocked evicts sessions older than ttl. Called under mu.
func (s *sessionStore) sweepLocked() {
	cutoff := s.now().Add(-s.ttl)
	for id, e := range s.sessions {
		if e.touch.Before(cutoff) {
			delete(s.sessions, id)
		}
	}
}

func allocSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Server wraps the existing protocol.Dispatcher with an HTTP POST
// surface. One server can be Handler-mounted at any URL path; the
// path is operator choice per cohort handoff §10.1 G1.
type Server struct {
	dispatcher *protocol.Dispatcher
	sessions   *sessionStore
}

// NewServer constructs an HTTP wrapper around an existing dispatcher.
// Pass the same Dispatcher the peer uses for TCP — the protocol is
// substrate-agnostic.
func NewServer(d *protocol.Dispatcher) *Server {
	return &Server{
		dispatcher: d,
		sessions:   newSessionStore(DefaultSessionTTL),
	}
}

// WithSessionTTL overrides the default TTL on idle sessions.
func (s *Server) WithSessionTTL(ttl time.Duration) *Server {
	s.sessions.ttl = ttl
	return s
}

// ServeHTTP implements http.Handler. POST-only — every other method
// returns 405 per §5.2 ("Every execute is a point-in-time live ask;
// lookups aren't safe to cache as fresh. GET is not a verb of EXECUTE
// — it belongs to http-poll").
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body as a bare ECF envelope per Amendment 3 —
	// HTTP's Content-Length / chunked framing delimits it; NO inner
	// 4-byte length prefix.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var reqEnv entity.Envelope
	if err := ecf.Decode(body, &reqEnv); err != nil {
		http.Error(w, "decode envelope: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := reqEnv.ValidateAll(); err != nil {
		http.Error(w, "validate envelope: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Look up or allocate a per-session ConnectionState. The server's
	// chosen ID is echoed back to the client on every response so the
	// connector can pin it for the next POST.
	clientSession := r.Header.Get(SessionHeader)
	sessionID, connState := s.sessions.getOrCreate(clientSession)

	// Dispatch through the same path TCP uses. handleExecute and the
	// connect-path branches both run; ConnectionState evolves as
	// HELLO → HELLO_RESPONSE → AUTHENTICATE → AUTHENTICATE_RESPONSE
	// → EXECUTE → EXECUTE-RESPONSE flows over successive POSTs.
	respEnv, err := s.dispatcher.DispatchEnvelope(r.Context(), reqEnv, connState)
	if err != nil {
		http.Error(w, "dispatch: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Encode the response envelope as a bare ECF body per Amendment 3.
	respBytes, err := ecf.Encode(respEnv)
	if err != nil {
		http.Error(w, "encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set(SessionHeader, sessionID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// ListenAndServe binds to addr and serves the §5 surface at urlPath.
// Blocks until ctx is canceled or the listener returns. Operators
// typically run this in a goroutine alongside the peer's TCP listener.
func (s *Server) ListenAndServe(ctx context.Context, addr, urlPath string) error {
	if urlPath == "" {
		urlPath = "/entity"
	}
	mux := http.NewServeMux()
	mux.Handle(urlPath, s)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("http listener: %w", err)
	}
}
