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
//     by named-pointer (NOT by-hash) so root updates
//     do not force a manifest re-sign.
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
	// Prefix is the absolute prefix this root's trie keys are relative to —
	// REQUIRED per EXTENSION-TREE §3.3a (landed 2026-08-08, D1/D2). MUST end
	// with "/"; "/" designates the universal tree.
	//
	// This is the field the type was missing, and its absence is why three
	// conformant implementations published mutually unreadable keys: §3.3
	// reconstructs full paths as `absolute_prefix + relative_key`, and a
	// published root has no request channel to carry the operand the way
	// snapshot/extract/merge do. Without it a consumer holds relative keys and
	// cannot rebuild a single absolute path — the hash-chain walk that is the
	// whole security model is underspecified at its first step.
	//
	// Required rather than optional-with-a-default: any default would have to
	// be one of §3.3's three admissible shapes, which silently promotes one
	// implementation's convention to "the answer you get for saying nothing".
	//
	// Go publishes the peer-relative subtree, so this is "system/" and keys are
	// relative to /{peer_id}/system/ (§3.3's first table row).
	Prefix string `cbor:"prefix"`
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

// PublishedRootStoragePath returns the peer-relative storage path for a peer's
// published-root entity. It is a per-peer SINGLETON at a fixed path, like the
// issuer-policy — the peer namespace is supplied by qualification, so the
// qualified form is `/{peer_id}/system/peer/published-root` and a consumer
// locating peer X's root reads `/{X}/system/peer/published-root`.
//
//	system/peer/published-root
//
// NO trailing peer-id segment. Appending the Base58 peer-id (the prior form)
// named the peer TWICE — the namespace already carries it — and diverged from
// rust and py, which bind at `{peer}/system/peer/published-root`. Ruled
// 2026-08-18 (arch, from workbench-go's cross-impl run): a path helper MUST NOT
// re-qualify a namespace the peer prefix already supplies (D12 / the
// double-qualify foreground invariant). The writer (publisher.go) and reader
// (closure_scope.go) shared this helper, so Go-on-Go passed deceptively; the
// cross-impl FAIL against a Rust consumer was the true signal.
func PublishedRootStoragePath() string {
	return "system/peer/published-root"
}
