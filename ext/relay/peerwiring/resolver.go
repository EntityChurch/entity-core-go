package peerwiring

import (
	"encoding/hex"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/relay"
)

// TreeInboxRelayResolver reads §3.5 inbox-relay declarations from the
// local peer's tree and applies the forged-redirection defense per spec:
// the declaration is returned only if its V7 §5.2 signature verifies
// against the destination peer's public key.
//
// v1 simplification: the canonical primary holder per §3.5 is REGISTRY
// (always-on); the peer's own tree is documented as offline-exactly-when-
// needed. For our cohort tests we publish declarations into B's local
// tree (the test fixture) — same lookup shape, different authority origin.
// Production wiring would chain through REGISTRY before the local-tree
// fallback.
type TreeInboxRelayResolver struct {
	store store.ContentStore
	index store.LocationIndex
	// localPeerID names the namespace where lookups are anchored. All
	// LocationIndex paths are absolute (CLAUDE.md "Path Model").
	localPeerID string
}

// NewTreeInboxRelayResolver wires the resolver to a *peer.Peer.
func NewTreeInboxRelayResolver(p *peer.Peer) *TreeInboxRelayResolver {
	return &TreeInboxRelayResolver{
		store:       p.Store(),
		index:       p.LocationIndex(),
		localPeerID: string(p.PeerID()),
	}
}

var _ relay.InboxRelayResolver = (*TreeInboxRelayResolver)(nil)

// Resolve looks up `system/peer/inbox-relay/{destination_peer_id}` in the
// local tree, fetches the V7 §5.2 invariant-pointer signature, and verifies
// it against the destination peer's public key derived from its peer-id
// (v7.64 identity-multihash form). Returns (decl, true) on verify; (_, false)
// on any failure — never a silently-trusted declaration.
func (r *TreeInboxRelayResolver) Resolve(destinationPeerID string) (types.InboxRelayData, bool) {
	if destinationPeerID == "" {
		return types.InboxRelayData{}, false
	}

	// 1) Path resolution. The declaration lives at the peer-local form
	//    system/peer/inbox-relay/{destination_peer_id} under the local
	//    namespace.
	relPath := types.InboxRelayStoragePath(destinationPeerID)
	absPath := "/" + r.localPeerID + "/" + relPath
	declHash, ok := r.index.Get(absPath)
	if !ok {
		return types.InboxRelayData{}, false
	}
	declEnt, ok := r.store.Get(declHash)
	if !ok {
		return types.InboxRelayData{}, false
	}

	// 2) Decode the declaration data. Type sanity check before trusting.
	if declEnt.Type != types.TypePeerInboxRelay {
		return types.InboxRelayData{}, false
	}
	decl, err := types.InboxRelayDataFromEntity(declEnt)
	if err != nil {
		return types.InboxRelayData{}, false
	}

	// 3) Locate the V7 §5.2 invariant-pointer signature for the declaration
	//    under the local peer's namespace. The destination peer signed the
	//    declaration; the signature is bound at the destination's pointer
	//    (not ours). The cross-peer convention: the destination's namespace
	//    served by REGISTRY (or, in our test fixture, replicated locally).
	//
	//    For v1 we look first under the local peer's namespace (where the
	//    fixture publishes for B's view) and fall back to a peer-relative
	//    form when not found.
	sigPathLocal := "/" + r.localPeerID + "/system/signature/" + hex.EncodeToString(declHash.Bytes())
	sigHash, ok := r.index.Get(sigPathLocal)
	if !ok {
		// Try under the destination's namespace (REGISTRY would replicate
		// the signature under its publisher's authority).
		sigPathDest := "/" + destinationPeerID + "/system/signature/" + hex.EncodeToString(declHash.Bytes())
		sigHash, ok = r.index.Get(sigPathDest)
		if !ok {
			return types.InboxRelayData{}, false
		}
	}
	sigEnt, ok := r.store.Get(sigHash)
	if !ok {
		return types.InboxRelayData{}, false
	}
	sigData, sigErr := types.SignatureDataFromEntity(sigEnt)
	if sigErr != nil {
		return types.InboxRelayData{}, false
	}
	if sigData.Target != declHash {
		return types.InboxRelayData{}, false
	}

	// 4) Derive the destination's (public_key, key_type) from its peer-id.
	//    v7.64 identity-multihash form encodes both — no out-of-band data
	//    needed. SHA-256-form peer-ids (v7.67) would require a stashed
	//    system/peer entity; v1 falls closed on that case (the v7.64-form
	//    peer-ids the test fixture uses are the common case).
	pub, keyType, ok := crypto.DerivePeerFromPeerID(crypto.PeerID(destinationPeerID))
	if !ok {
		return types.InboxRelayData{}, false
	}

	// 5) Cross-check: signer hash MUST equal the destination's canonical
	//    identity hash (i.e. the destination really signed it, not a
	//    look-alike peer).
	destHash, ihErr := types.ComputePeerIdentityHash(pub, keyType)
	if ihErr != nil {
		return types.InboxRelayData{}, false
	}
	if sigData.Signer != destHash {
		return types.InboxRelayData{}, false
	}

	// 6) V7 §5.2 fail-closed signature verification.
	if !crypto.Verify(keyType, pub, declHash.Bytes(), sigData.Signature) {
		return types.InboxRelayData{}, false
	}

	return decl, true
}
