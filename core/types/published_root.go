package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// TypePeerPublishedRoot is the standalone signed-root-pointer entity type
// per PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 (NORMATIVE-LOCKED).
//
// One of three entities under the §7 Q1 layering (5-team convergence):
//   - system/peer/published-root — this entity; standalone signed tree-root pointer.
//   - system/peer/manifest       — self-description bundle (§3); references this
//                                  by named-pointer (NOT by-hash) so root updates
//                                  do not force a manifest re-sign.
//   - system/substitute/snapshot-manifest — content-index optimization (untouched).
const TypePeerPublishedRoot = "system/peer/published-root"

// PublishedRootData is the data payload for system/peer/published-root.
//
// Verification per §4 (cross-impl-run absorption, Ruling-1):
//  1. PeerID is the Base58 peer-id per V7 §1.5 — pubkey IS identity, derivable
//     locally via crypto.DerivePeerFromPeerID. The signature on this
//     published-root MUST verify against that derived public key. Carriage is
//     V7 §5.2/§975 refless target-matching at the invariant-pointer path
//     system/signature/{hex(published_root.content_hash)} — same convention
//     REGISTRY §3 and DISCOVERY §2.1 use. No refs: block on data.
//  2. Seq monotonicity prevents rollback: consumers reject seq < cached_seq
//     for the same PeerID per snapshot-manifest §3-RES.4 freshness discipline.
//  3. TREE_GET walks the hash-chain from RootHash; every binding reachable from
//     the signed root is therefore hash-chained from it (§1.1 tree-binding
//     fabrication is the core threat this defends against).
type PublishedRootData struct {
	// PeerID is the publishing peer's Base58 peer-id per V7 §1.5
	// (key_type || hash_type || digest, Base58-encoded). The signature on
	// this published-root MUST verify against the public key derivable from
	// PeerID via crypto.DerivePeerFromPeerID (identity-form) or held
	// out-of-band (SHA-256-form). Changed from system/hash to Base58 per
	// cross-impl-run absorption Ruling-1: pubkey IS identity, and
	// every other peer_id field in the cohort (REGISTRY §3 target_peer_id,
	// NETWORK §6.5.1 errata bdfb545) is Base58 since the V7 §1.5 multikey
	// erratum landed.
	PeerID string `cbor:"peer_id"`
	// RootHash is the current tree-root hash the publisher commits to. All
	// reachable bindings are hash-chained from here; consumers walk TREE_GET
	// from RootHash and never trust paths the host claims outside that chain.
	RootHash hash.Hash `cbor:"root_hash"`
	// Seq is the per-peer monotonic freshness counter. Same discipline as
	// snapshot-manifest §3-RES.4: consumers cache the highest seq observed
	// per peer and reject any incoming published-root whose seq is less.
	Seq uint64 `cbor:"seq"`
	// PublishedAt is wall-clock ms-since-epoch at signing time.
	PublishedAt uint64 `cbor:"published_at"`
	// Predecessor optionally chains this root to the prior published-root for
	// audit. Nil on the first published-root. When present, it is the
	// content_hash of the previous system/peer/published-root entity.
	Predecessor *hash.Hash `cbor:"predecessor,omitempty"`
}

// ToEntity creates a system/peer/published-root entity.
func (d PublishedRootData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeerPublishedRoot, cbor.RawMessage(raw))
}

// PublishedRootDataFromEntity decodes a system/peer/published-root entity's data.
func PublishedRootDataFromEntity(e entity.Entity) (PublishedRootData, error) {
	var d PublishedRootData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PublishedRootData{}, err
	}
	return d, nil
}

// PublishedRootStoragePath returns the canonical local storage path for a
// peer's published-root entity. Pinned to the entity-type path + Base58
// peer-id segment so a consumer can locate "the current published-root for
// peer X" without enumerating the type's content-addressed siblings.
//
//	system/peer/published-root/{base58_peer_id}
//
// Changed from {peer_id_hex} to {base58_peer_id} per Ruling-1: every peer-id
// surface in the cohort is Base58 since the V7 §1.5 multikey erratum.
//
// This is the path MANIFEST_GET resolves against (§4 cross-ref Q5: supersedes
// the legacy `signed_pointer: "system/peer/published-root"` string in
// NETWORK §6.5.3 with this entity).
func PublishedRootStoragePath(peerID string) string {
	return "system/peer/published-root/" + peerID
}
