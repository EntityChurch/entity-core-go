package types

import (
	"encoding/hex"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// TypePeerStatus is the §3.13 operational-state entity that carries a peer's
// connection liveness. It is the sanctioned liveness home for the whole
// cohort: the session entity (system/peer/session) deliberately DROPPED its
// own `status`/`last_active` fields (session.go, §9.1 R6-b/R6-c) precisely
// because they duplicated this entity — a prior go/rust-vs-python divergence.
//
// The entity lives at /{local_peer_id}/system/peer/status/{remote_peer_id_hex}
// (see PeerStatusPath). It is an ordinary tree entity, so a write fires any
// system/subscription on the path — the "no poll" liveness signal consumers
// block on (EXTENSION-NETWORK §4.1, Amendment 12 A3: the liveness slice).
//
// This is the minimal composable slice (Amendment 12 §A3): writing this entity
// on connection state change requires none of maintain-peer, the continuation
// graph, or the §8 outbox; those compose on top of it.
const TypePeerStatus = "system/peer/status"

// Peer-status lifecycle values (EXTENSION-NETWORK §3.13 enum). The status
// entity's `status` field is one of these.
const (
	// PeerStatusConnected — a live connection is established (§6.2).
	PeerStatusConnected = "connected"
	// PeerStatusSuspect — a single transport error was observed on a
	// connection believed active (Amendment 12 §A1). One failure is not
	// proof of a dead peer; a consumer stops trusting "Connected" without
	// tearing the session down. The keepalive/grace path (§5.4) is what
	// escalates suspect → disconnected.
	PeerStatusSuspect = "suspect"
	// PeerStatusDisconnected — the peer is gone: keepalive miss (§5.4),
	// release (§4.2), or graceful close (§4.4).
	PeerStatusDisconnected = "disconnected"
	// NOTE: the status entity is a THREE-state enum (ENTITY-CORE-PROTOCOL
	// §3.13; Amendment 12 §A2 rung-1 ask D). "reconnecting" is NOT a
	// system/peer/status value — it is a system/network/peer-summary (§2.8)
	// value, the derived status-op output. Transitions: (unknown) → connected
	// → suspect → disconnected; reconnection returns to connected.
)

// Peer-status transition reasons (Amendment 12 §A2). OPTIONAL kebab enum on
// the status entity: why the status last changed, so a consumer or the
// reconnect continuation can pick a recovery. A reader treats an unrecognized
// value as generic (MUST-ignore-unknowns, ADR-0002) and falls back to backoff.
//
// Recovery mapping (§A2):
//   - transport-error, keepalive-miss → backoff-reconnect (§4.1)
//   - auth-rejected                   → re-handshake (§6.3), do NOT reuse held cap
//   - peer-shutdown, local-release    → terminal; session ended deliberately (§6.1)
//   - peer-idle, peer-migration       → preserve subscriptions; expect resume (§9.1)
const (
	PeerStatusReasonTransportError = "transport-error"
	PeerStatusReasonKeepaliveMiss  = "keepalive-miss"
	PeerStatusReasonAuthRejected   = "auth-rejected"
	PeerStatusReasonPeerShutdown   = "peer-shutdown"
	PeerStatusReasonPeerIdle       = "peer-idle"
	PeerStatusReasonPeerMigration  = "peer-migration"
	PeerStatusReasonLocalRelease   = "local-release"
	// PeerStatusReasonRetryExhausted — an OPTIONAL §2.2 retry bound
	// (max_attempts / max_elapsed_ms) was reached and the relationship is
	// abandoned. Terminal, like local-release: the reconnect loop is over and
	// re-establishing needs a fresh maintain-peer.
	//
	// This is a `reason`, NOT a fourth status: the §3.13 enum is three-state
	// (rung 1, ruling D), and "we stopped trying" is a statement about WHY the
	// peer is disconnected, not a different way of being disconnected. Never
	// reached under the default config, which is retry-forever.
	PeerStatusReasonRetryExhausted = "retry-exhausted"
)

// PeerStatusData is the system/peer/status entity payload. The concrete shape
// is pinned by EXTENSION-NETWORK's put sites ({peer_id, status}); Reason and
// LastError are the Amendment 12 §A2 additive OPTIONAL fields.
//
// Additive/forward-compatible: Reason and LastError are omitempty pointers-in-
// spirit (empty string ⇒ absent under CoreDetEncOptions omitempty), so a peer
// that never sets them emits byte-identical entities to the pre-Amendment-12
// shape. MUST-ignore-unknowns (ADR-0002) covers the reverse direction.
//
// Ownership note (§A2 open question, routed to core-protocol owner): whether
// reason/last_error are declared at ENTITY-CORE-PROTOCOL §3.13 or as a
// NETWORK-local annotation is not settled. We land them additively here and
// flag the declaration-home question rather than block. NETWORK owns the enum
// semantics + recovery mapping regardless of where the declaration sits.
type PeerStatusData struct {
	// PeerID is the remote peer's Base58 peer-id string (mirrors
	// SessionData.RemotePeerID — the data-field identity, distinct from the
	// hex path segment).
	PeerID string `cbor:"peer_id"`
	// Status is one of the PeerStatus* lifecycle values.
	Status string `cbor:"status"`
	// Reason is the OPTIONAL §A2 transition reason (a PeerStatusReason*
	// value, or an unknown value a reader treats as generic-backoff).
	Reason string `cbor:"reason,omitempty"`
	// LastError is OPTIONAL coded/opaque detail for humans + logs, never
	// parsed by a recovery path (§A2).
	LastError string `cbor:"last_error,omitempty"`
	// ConnectedAt is the OPTIONAL §3.13 establish timestamp, ms since
	// epoch — written once at handshake completion (§6.2).
	ConnectedAt uint64 `cbor:"connected_at,omitempty"`
	// LastSeen is the OPTIONAL §3.13 liveness timestamp, ms since epoch —
	// a SNAPSHOT taken at the transition write ("when I last heard from
	// this peer as of this transition"; on a demotion write it is the
	// demotion's evidence). NEVER cadence-refreshed to the tree: the status
	// entity is transition-written only, and per-tick freshness is
	// implementation-internal bookkeeping (§A4, rung-2 ruling 1 — the §6.6
	// write-amplification rationale applied to the status entity).
	LastSeen uint64 `cbor:"last_seen,omitempty"`
	// Connection is the OPTIONAL §3.13 path ref to the peer's
	// system/connection/{peer_id} entity (ruling C: that entity is MUST at
	// full NETWORK conformance, not in the §A3 floor).
	Connection string `cbor:"connection,omitempty"`
	// FailingSince is the OPTIONAL ms-since-epoch stamp of the transition out
	// of `connected` that began the current failure episode — the single
	// durable input the §2.2 retry pacing is derived from.
	//
	// Written ONCE, at the first demotion (connected → suspect, or straight to
	// disconnected), and PRESERVED across every later demotion write in the
	// same episode (suspect → disconnected must not re-stamp it — that would
	// restart the backoff curve on escalation). The `connected` write omits it,
	// which clears it: recovery ends the episode. Absent ⇒ not currently
	// failing.
	//
	// It is deliberately the only retry state that exists: `attempt` and
	// `next_attempt_at` are DERIVED from (failing_since, backoff cfg, now) —
	// never stored, never written per attempt (§A4: the status entity is
	// transition-written only). Because it is durable in the tree rather than
	// an in-memory counter, a peer that restarts beside a long-dead remote
	// resumes the curve where it left off instead of hammering from min_ms.
	FailingSince uint64 `cbor:"failing_since,omitempty"`
}

// ToEntity creates a system/peer/status entity.
func (d PeerStatusData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeerStatus, cbor.RawMessage(raw))
}

// PeerStatusDataFromEntity decodes a system/peer/status entity's data.
func PeerStatusDataFromEntity(e entity.Entity) (PeerStatusData, error) {
	var d PeerStatusData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PeerStatusData{}, err
	}
	return d, nil
}

// PeerStatusPath returns the canonical status-entity path:
//
//	/{local_peer_id}/system/peer/status/{remote_peer_id_hex}
//
// The leading /{local_peer_id}/ is the universal-tree-root form (Base58 per
// V7 §1.4 positional rule). The {remote_peer_id_hex} non-root segment is the
// lowercase hex of the remote peer's system/peer content_hash — the same
// path-encoding convention as SessionPath and ComputePeerIdentityHash's
// documented {peer_id_hex} non-root position (crypto.go).
func PeerStatusPath(localPeerID string, remoteIdentityHash hash.Hash) string {
	return "/" + localPeerID + "/" + TypePeerStatus + "/" + hex.EncodeToString(remoteIdentityHash.Bytes())
}
