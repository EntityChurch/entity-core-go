package protocol

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// WritePeerStatus writes the §3.13 operational liveness entity for a remote
// peer to the local tree at /{local}/system/peer/status/{remote_hex}
// (EXTENSION-NETWORK Amendment 12 §A3 — the liveness slice).
//
// The write goes through the location index, so on a NotifyingLocationIndex it
// fires any system/subscription bound to the path — the "no poll" liveness
// signal consumers block on. This is the single primitive the whole reactive
// half composes on; it needs none of maintain-peer, the continuation graph, or
// the §8 outbox.
//
// Straight write (not read-modify-write): the status entity has no field the
// caller must preserve (unlike the session entity's minted/held split). The
// §A1 no-clobber discipline — do not demote a concurrently-established live
// re-entry — is the CALLER's responsibility at the transport-error seam (pool
// pointer-identity guard, the Arc::ptr_eq analog), because only the caller
// knows whether the failed connection is still the bound one.
//
// data is the full §3.13 shape (per rung-1 ruling D the canonical field set
// lives at ENTITY-CORE-PROTOCOL §3.13; put-sites are minimal writes). All
// optional fields encode omitempty, so a bare {peer_id, status} write is
// byte-identical to the pre-Amendment-12 shape. data.PeerID must be the
// remote's Base58 peer-id.
func WritePeerStatus(
	cs store.ContentStore,
	li store.LocationIndex,
	localPeerID string,
	remoteIdentityHash hash.Hash,
	data types.PeerStatusData,
) (hash.Hash, error) {
	// §9.1 R6-f analog: no self-status. A peer never writes a liveness entity
	// keyed by its own peer_id; local dispatch has no connection to observe.
	if data.PeerID == localPeerID {
		return hash.Hash{}, nil
	}
	// The hex path key requires the remote's canonical identity hash. A zero
	// hash means the caller's derivation failed (SHA-256-form remote without
	// public_key threaded through) — same contract as WriteHeldSession.
	if remoteIdentityHash.IsZero() {
		return hash.Hash{}, fmt.Errorf("WritePeerStatus: remoteIdentityHash is zero (path key required); derive via ResolveRemoteIdentityHash")
	}
	ent, err := data.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("peer-status encode: %w", err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("peer-status store: %w", err)
	}
	if err := li.Set(types.PeerStatusPath(localPeerID, remoteIdentityHash), h); err != nil {
		return hash.Hash{}, fmt.Errorf("peer-status bind: %w", err)
	}
	return h, nil
}

// NOTE: there is deliberately no cadence-refresh read/modify helper here.
// Per §A4 (rung-2 ruling 1) the status entity is TRANSITION-written only —
// keepalive success updates impl-internal freshness, never the tree.
