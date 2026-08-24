package network

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
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

	// failingSince is a FALLBACK episode start (ms since epoch, 0 = not
	// failing) for the derived §2.2 pacing. The authoritative stamp is the
	// status entity's failing_since, written by the demotion seam and read
	// back from the tree — that is the copy that survives a restart, and the
	// one retryState prefers.
	//
	// This exists because a peer that never connected has no demotion
	// transition to stamp: a failed DIAL writes no status entity (only a
	// transport error on an established connection does). Without a local
	// stamp its pacing would restart from min_ms on every attempt. Whether
	// a failed dial against a MAINTAINED peer should itself write a §3.13
	// demotion is a real cross-impl question, routed to arch 2026-07-16
	// ("failing_since when never connected").
	// Until it is ruled, this keeps the never-connected curve growing without
	// inventing a write site.
	failingSince uint64

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
		chainID:    newChainID("network-maintain", sid),
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

// newChainID builds a §3.11 chain id from a label and a discriminator.
//
// A chain_id MUST be a SINGLE PATH SEGMENT: it is a path segment in the §3.10.6
// marker tree (.../lost/{chain_id}/{step_index}/{reason}/{marker}), so a value
// containing "/" silently forks into extra levels and the nominal shape stops
// being walkable at a fixed depth. Hence "network-maintain-{sid}", not the
// "network/maintain/{sid}" this used to mint. Separators are normalised rather
// than trusted, since the label and discriminator both come from callers.
//
// The value is otherwise OPAQUE — §3.11 gives chain_id no format, and nothing
// parses one. The label is there for a human reading a marker path.
func newChainID(label, discriminator string) string {
	seg := label + "-" + discriminator
	return strings.ReplaceAll(seg, "/", "-")
}

// newSubChainID mints a fresh §3.11 chain id for a sub-chain dispatched under
// parent. The parent edge is carried by bounds.parent_chain_id, NOT by nesting
// it into this string — that is exactly the mistake the single-segment rule
// exists to prevent.
func newSubChainID(label string) string {
	return newChainID(label, newSessionID())
}

// retryState derives the §2.2 pacing for the session's current failure
// episode as of nowMs, and reports the episode start it used.
//
// Nothing counts attempts. The episode start is the only state, and the
// TREE's failing_since wins when present: it is durable, so a process that
// restarts beside a long-dead peer re-derives a large attempt count and a
// max-length wait instead of redialing in min_ms. sess.failingSince is only
// the fallback for a peer that never connected (see the field's comment).
//
// A caller that has just observed a failure and finds no episode anywhere is
// starting one — hence stamp, below.
func (h *Handler) retryState(sess *session, nowMs uint64) (types.RetryState, uint64) {
	failingSince := uint64(0)
	if st, ok := h.readPeerStatus(sess); ok {
		failingSince = st.FailingSince
	}
	if failingSince == 0 {
		sess.mu.Lock()
		failingSince = sess.failingSince
		sess.mu.Unlock()
	}
	if failingSince == 0 {
		return types.RetryState{}, 0
	}
	sess.mu.Lock()
	cfg := sess.params.EffectiveBackoff()
	sess.mu.Unlock()
	return cfg.DeriveRetryState(failingSince, nowMs), failingSince
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
