package network

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// session is the in-memory bookkeeping for one maintained peer relationship.
// Per §12.4 session/backoff/concurrency handling is implementation-defined;
// the durable half (the continuation graph, the subscriptions) lives in the
// tree — this struct only carries what the retry loop needs between requests.
type session struct {
	mu sync.Mutex

	peerID     crypto.PeerID
	remoteHash hash.Hash // canonical identity hash — the status-path key
	sessionID  string
	chainID    string

	// params is the maintain-request this session was created with; the
	// backoff continuation re-EXECUTEs maintain-peer with exactly these.
	params types.MaintainRequestData

	// subscriptionIDs are the lifecycle subscriptions (on-disconnect +
	// on-reconnect deliveries); release-peer unsubscribes them.
	subscriptionIDs []string

	// attempt counts consecutive failed reconnect attempts since the last
	// successful establish; drives the §2.2 backoff delay.
	attempt uint64

	// retryTimer is the pending backoff-advance timer, if any. Guarded by
	// mu; release-peer stops it.
	retryTimer *time.Timer

	// graphInstalled marks that the §4.1 continuations + subscriptions
	// exist in the tree, so re-entries (backoff retries) skip re-creation
	// of the subscriptions (continuation re-puts are content-idempotent).
	graphInstalled bool
}

// getSession returns the session for peerID, if any.
func (h *Handler) getSession(peerID crypto.PeerID) *session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[peerID]
}

// getOrCreateSession returns the existing session for peerID or creates one.
// The bool reports whether it already existed.
func (h *Handler) getOrCreateSession(peerID crypto.PeerID, remoteHash hash.Hash, params types.MaintainRequestData) (*session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.sessions[peerID]; ok {
		return s, true
	}
	sid := newSessionID()
	s := &session{
		peerID:     peerID,
		remoteHash: remoteHash,
		sessionID:  sid,
		chainID:    "network/maintain/" + sid,
		params:     params,
	}
	h.sessions[peerID] = s
	return s, false
}

// dropSession removes and returns the session for peerID, stopping any
// pending retry timer.
func (h *Handler) dropSession(peerID crypto.PeerID) *session {
	h.mu.Lock()
	s := h.sessions[peerID]
	delete(h.sessions, peerID)
	h.mu.Unlock()
	if s != nil {
		s.mu.Lock()
		if s.retryTimer != nil {
			s.retryTimer.Stop()
			s.retryTimer = nil
		}
		s.mu.Unlock()
	}
	return s
}

// newSessionID generates a random 16-hex-char session identifier.
func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback: time-derived — uniqueness within a peer's lifetime is
		// all the session id carries.
		return hex.EncodeToString([]byte(time.Now().String()))[:16]
	}
	return hex.EncodeToString(b[:])
}

// backoffDelay computes the §2.2 delay for the given consecutive-failure
// attempt count (1-based) under the session's backoff config.
func backoffDelay(cfg types.BackoffConfigData, attempt uint64) time.Duration {
	minMs := cfg.EffectiveMinMs()
	maxMs := cfg.EffectiveMaxMs()
	if maxMs < minMs {
		maxMs = minMs
	}
	var ms uint64
	switch cfg.EffectiveStrategy() {
	case "constant":
		ms = minMs
	case "linear":
		ms = minMs * attempt
	default: // "exponential"
		ms = minMs
		for i := uint64(1); i < attempt; i++ {
			ms *= 2
			if ms >= maxMs {
				break
			}
		}
	}
	if ms > maxMs {
		ms = maxMs
	}
	return time.Duration(ms) * time.Millisecond
}

// Path scheme for the §4.1 graph. The two inbox residents are
// subscription-delivery targets (delivery EXECUTEs `receive`, which is the
// inbox handler's advance seam); the backoff continuation lives in the §11
// managed namespace and is advanced directly by the handler — never via
// system/inbox/* (marker-proposal §5 discipline).
func onDisconnectPath(peerID crypto.PeerID) string {
	return "system/inbox/network/" + string(peerID) + "/on-disconnect"
}

func onReconnectPath(peerID crypto.PeerID) string {
	return "system/inbox/network/" + string(peerID) + "/on-reconnect"
}

func backoffPath(peerID crypto.PeerID) string {
	return "system/network/peers/" + string(peerID) + "/on-reconnect-backoff"
}

func inboxPrefix(peerID crypto.PeerID) string {
	return "system/inbox/network/" + string(peerID) + "/"
}

func managedPrefix(peerID crypto.PeerID) string {
	return "system/network/peers/" + string(peerID) + "/"
}
