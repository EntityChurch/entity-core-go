package protocol

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// sessionCapBlock returns a freshly-walked SessionCapability for the given
// cap entity. Chain is leaf→root, length ≥ 1 (§9.1 R6-d).
func sessionCapBlock(leaf entity.Entity, cs store.ContentStore) (*types.SessionCapability, error) {
	resolve := capability.EntityResolver(func(h hash.Hash) (entity.Entity, bool) {
		return cs.Get(h)
	})
	chain, err := capability.CollectAuthorityChain(leaf, resolve)
	if err != nil {
		return nil, err
	}
	out := make([]hash.Hash, 0, len(chain))
	for _, e := range chain {
		out = append(out, e.ContentHash)
	}
	return &types.SessionCapability{Hash: leaf.ContentHash, Chain: out}, nil
}

// WriteHeldSession persists the dialer-side cap into the per-peer session
// entity (§9.1 R6-a held_capability). Read-modify-write: any existing
// minted_capability is preserved; any existing remote_public_key /
// remote_identity_hash from a prior granter-side write is preserved
// unless the caller supplies a non-zero replacement (then it's overwritten).
//
// V7.64: the session path is keyed by `remoteIdentityHash` (hex form). If
// the caller does not have the canonical hash, ResolveRemoteIdentityHash
// derives it locally for identity-form PeerIDs; SHA-256-form PeerIDs require
// the caller to thread the remote's public_key.
//
// Called by the dialer after AUTHENTICATE_RESPONSE — records "the cap
// remote granted me," which is what Connection.Execute reads to authorize
// outbound dispatch (replaces the pre-§9 Connection.session.Capability).
func WriteHeldSession(
	cs store.ContentStore,
	li store.LocationIndex,
	localPeerID string,
	remotePeerID string,
	remotePublicKey []byte,
	remoteIdentityHash hash.Hash,
	capEntity entity.Entity,
	grantedAt uint64,
	expiresAt uint64,
) (hash.Hash, error) {
	// §9.1 R6-f: no self-session. A peer never writes a session entity
	// keyed by its own peer_id; local dispatch short-circuits in memory.
	if remotePeerID == localPeerID {
		return hash.Hash{}, nil
	}
	// V7.64: caller must provide the canonical identity hash. The dialer
	// flow at connection.go derives it from the AUTHENTICATE response
	// before reaching here; a zero hash means the derivation failed
	// (SHA-256-form remote without public_key threaded through).
	if remoteIdentityHash.IsZero() {
		return hash.Hash{}, fmt.Errorf("v7.64 WriteHeldSession: remoteIdentityHash is zero (path key required); caller must derive via ResolveRemoteIdentityHash or thread the remote public_key")
	}
	held, err := sessionCapBlock(capEntity, cs)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("held-session chain walk: %w", err)
	}
	prev, _, hasPrev := loadSessionData(cs, li, localPeerID, remoteIdentityHash)
	data := types.SessionData{
		RemotePeerID:       remotePeerID,
		RemoteIdentityHash: remoteIdentityHash,
		RemotePublicKey:    remotePublicKey,
		HeldCapability:     held,
		GrantedAt:          grantedAt,
		ExpiresAt:          expiresAt,
	}
	if hasPrev {
		// Preserve granter-side bookkeeping the dialer write doesn't own.
		data.MintedCapability = prev.MintedCapability
		if len(data.RemotePublicKey) == 0 {
			data.RemotePublicKey = prev.RemotePublicKey
		}
	}
	return commitSession(cs, li, localPeerID, remoteIdentityHash, data)
}

// WriteMintedSession persists the granter-side cap into the per-peer
// session entity (§9.1 R6-a minted_capability — R3a anchor). Read-
// modify-write: any existing held_capability is preserved.
//
// Called by the connect handler after minting a cap for a connecting
// peer. Lookup of this field on the next handshake gives idempotent
// cap reuse (same content hash) when grants haven't changed.
func WriteMintedSession(
	cs store.ContentStore,
	li store.LocationIndex,
	localPeerID string,
	remotePeerID string,
	remotePublicKey []byte,
	remoteIdentityHash hash.Hash,
	capEntity entity.Entity,
	grantedAt uint64,
	expiresAt uint64,
) (hash.Hash, error) {
	// §9.1 R6-f: no self-session. See WriteHeldSession for rationale.
	if remotePeerID == localPeerID {
		return hash.Hash{}, nil
	}
	if remoteIdentityHash.IsZero() {
		return hash.Hash{}, fmt.Errorf("v7.64 WriteMintedSession: remoteIdentityHash is zero (path key required)")
	}
	minted, err := sessionCapBlock(capEntity, cs)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("minted-session chain walk: %w", err)
	}
	prev, _, hasPrev := loadSessionData(cs, li, localPeerID, remoteIdentityHash)
	data := types.SessionData{
		RemotePeerID:       remotePeerID,
		RemoteIdentityHash: remoteIdentityHash,
		RemotePublicKey:    remotePublicKey,
		MintedCapability:   minted,
		GrantedAt:          grantedAt,
		ExpiresAt:          expiresAt,
	}
	if hasPrev {
		data.HeldCapability = prev.HeldCapability
		if len(data.RemotePublicKey) == 0 {
			data.RemotePublicKey = prev.RemotePublicKey
		}
	}
	return commitSession(cs, li, localPeerID, remoteIdentityHash, data)
}

// ReadHeldCapability returns the cap the local peer holds for the remote
// (the cap remote granted us). Used by Connection.Execute as the
// authoritative cap source for outbound dispatch (§9.0 — session entity
// is THE answer to "do I hold a valid cap").
func ReadHeldCapability(
	cs store.ContentStore,
	li store.LocationIndex,
	localPeerID string,
	remoteIdentityHash hash.Hash,
) (entity.Entity, bool) {
	if remoteIdentityHash.IsZero() {
		return entity.Entity{}, false
	}
	data, _, ok := loadSessionData(cs, li, localPeerID, remoteIdentityHash)
	if !ok || data.HeldCapability == nil {
		return entity.Entity{}, false
	}
	return cs.Get(data.HeldCapability.Hash)
}

// ReadMintedCapability returns the cap the local peer minted for the
// remote (R3a idempotency anchor). Used by the connect handler at
// AUTHENTICATE time to decide whether to reuse or mint fresh.
func ReadMintedCapability(
	cs store.ContentStore,
	li store.LocationIndex,
	localPeerID string,
	remoteIdentityHash hash.Hash,
) (entity.Entity, bool) {
	if remoteIdentityHash.IsZero() {
		return entity.Entity{}, false
	}
	data, _, ok := loadSessionData(cs, li, localPeerID, remoteIdentityHash)
	if !ok || data.MintedCapability == nil {
		return entity.Entity{}, false
	}
	return cs.Get(data.MintedCapability.Hash)
}

// ReadSessionEntity loads the raw SessionData and the entity envelope.
// Useful for inspectors / validate-peer.
func ReadSessionEntity(
	cs store.ContentStore,
	li store.LocationIndex,
	localPeerID string,
	remoteIdentityHash hash.Hash,
) (types.SessionData, entity.Entity, bool) {
	if remoteIdentityHash.IsZero() {
		return types.SessionData{}, entity.Entity{}, false
	}
	return loadSessionData(cs, li, localPeerID, remoteIdentityHash)
}

func loadSessionData(cs store.ContentStore, li store.LocationIndex, localPeerID string, remoteIdentityHash hash.Hash) (types.SessionData, entity.Entity, bool) {
	h, ok := li.Get(types.SessionPath(localPeerID, remoteIdentityHash))
	if !ok {
		return types.SessionData{}, entity.Entity{}, false
	}
	sessionEntity, ok := cs.Get(h)
	if !ok {
		return types.SessionData{}, entity.Entity{}, false
	}
	data, err := types.SessionDataFromEntity(sessionEntity)
	if err != nil {
		return types.SessionData{}, entity.Entity{}, false
	}
	return data, sessionEntity, true
}

func commitSession(cs store.ContentStore, li store.LocationIndex, localPeerID string, remoteIdentityHash hash.Hash, data types.SessionData) (hash.Hash, error) {
	sessionEntity, err := data.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("session encode: %w", err)
	}
	h, err := cs.Put(sessionEntity)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("session store: %w", err)
	}
	if err := li.Set(types.SessionPath(localPeerID, remoteIdentityHash), h); err != nil {
		return hash.Hash{}, fmt.Errorf("session bind: %w", err)
	}
	return h, nil
}

// ResolveRemoteIdentityHash computes the canonical {peer_id_hex} path key for
// the remote peer. Under v7.65 the canonical content_hash is invariant under
// wire-form peer_id choice — both branches produce the same hash for the same
// (public_key, key_type). Two paths exist for input shape:
//
//   - identity-form PeerID (v7.65 canonical for Ed25519): derive public_key
//     locally from the PeerID. Pure local computation; no out-of-band data.
//   - SHA-256-form PeerID (§5 wire-acceptance carve-out, legacy decode):
//     the caller MUST provide remotePublicKey from the handshake's
//     AUTHENTICATE response. Returns an error if remotePublicKey is empty.
//
// Both branches return content_hash(system/peer({public_key, key_type})),
// which is the canonical form for storage and tree-path use per v7.65 §5.
func ResolveRemoteIdentityHash(remotePeerID crypto.PeerID, remotePublicKey []byte) (hash.Hash, error) {
	if h, err := types.ComputePeerIdentityHashFromPeerID(remotePeerID); err == nil {
		return h, nil
	}
	if len(remotePublicKey) == 0 {
		return hash.Hash{}, fmt.Errorf("resolve remote identity hash: peer_id %s is SHA-256 form and no public_key provided", remotePeerID)
	}
	// Decode the peer_id's key_type prefix so the system/peer entity is
	// built with the matching entity-data string. v7.67 §3 crypto-agility:
	// SHA-256-form peer_ids can carry either Ed25519 (legacy) or Ed448
	// (canonical) keys; the key_type byte selects the entity-data string.
	dec, err := remotePeerID.Decode()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("resolve remote identity hash: decode peer_id: %w", err)
	}
	return types.ComputePeerIdentityHash(remotePublicKey, dec.KeyType)
}
