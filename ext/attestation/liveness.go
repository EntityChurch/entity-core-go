package attestation

import (
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// IsAttestationLive performs the composite liveness check per §4.3:
// not expired, not superseded (by a live successor in the forward chain),
// not self-revoked.
//
// asOf is an optional epoch-millisecond timestamp for time-traveling
// validation; pass 0 to use the current wall-clock time. Recursion uses the
// same asOf when checking successors and revocations.
//
// Self-revocation only is checked here. Authority-revocation rules (where a
// non-self peer revokes the attestation) are consumer-specific and are
// applied on top via FindRevocationsFor + the consumer's authority predicate
// per §4.4.
//
// Implementation note (transitive supersession). The §4.3 pseudocode reads
// as a direct-successor recursion: "if any direct successor is itself live,
// I'm dead." That phrasing is bistable on chains > 2 — for a0 → a1 → a2
// (all good), a1 looks dead because a2 supersedes it, which makes a0 think
// it's not superseded (its only successor a1 returned false). The right
// interpretation per Python's review and Go's joint reading is "I'm dead
// iff any non-revoked, non-expired transitive descendant exists in my
// forward chain" — i.e., walk forward until we find an effectively-live
// node anywhere down the supersedes graph. Tracked as SI-2 in
// docs/validation/spec-issues/IDENTITY-V3.2-MIGRATION-SPEC-ISSUES.md.
func IsAttestationLive(
	cs store.ContentStore,
	li store.LocationIndex,
	ix *Index,
	attHash hash.Hash,
	att types.AttestationData,
	asOf uint64,
) bool {
	now := asOf
	if now == 0 {
		now = uint64(time.Now().UnixMilli())
	}
	if !shallowEffective(att, now) {
		return false
	}
	// Transitive supersession: dead iff any descendant is itself
	// effectively live (full predicate, not just shallowEffective). Walks
	// forward through the entire supersedes graph reachable from this hash.
	if hasEffectivelyLiveDescendant(cs, li, ix, attHash, now) {
		return false
	}
	// Self-revocation: dead iff att.Attesting issued a still-live
	// revocation targeting this attestation.
	for _, revHash := range FindRevocationsFor(ix, attHash) {
		rev, err := loadAttestation(cs, revHash)
		if err != nil {
			continue
		}
		if rev.Attesting != att.Attesting {
			continue
		}
		if IsAttestationLive(cs, li, ix, revHash, rev, now) {
			return false
		}
	}
	return true
}

// shallowEffective returns true iff the attestation passes the
// expiration / not_before time checks at `now`. Used to break the
// supersession-revocation recursion cycle while preserving the spec's
// composite intent.
func shallowEffective(att types.AttestationData, now uint64) bool {
	if att.NotBefore != nil && now < *att.NotBefore {
		return false
	}
	if att.ExpiresAt != nil && now >= *att.ExpiresAt {
		return false
	}
	return true
}

// hasEffectivelyLiveDescendant walks the supersedes-DAG forward from root
// and returns true iff any reachable descendant is itself effectively live
// (passes the full IsAttestationLive predicate). The walk is bounded by
// the visited set; the supersedes graph is acyclic by content-hash
// uniqueness, so no cycle can form.
//
// Termination: each `IsAttestationLive` call on a descendant `succ` opens
// its own walk over `succ`'s descendants, but the visited set is
// per-outer-call — that's intentional. The bounded depth comes from the
// finite forward chain length. Realistic deployments have chain depth ≪
// 32 (the §5.1 max_depth default).
func hasEffectivelyLiveDescendant(
	cs store.ContentStore,
	li store.LocationIndex,
	ix *Index,
	root hash.Hash,
	now uint64,
) bool {
	visited := make(map[hash.Hash]struct{})
	var walk func(h hash.Hash) bool
	walk = func(h hash.Hash) bool {
		for _, succHash := range ix.FindBySupersedes(h) {
			if _, seen := visited[succHash]; seen {
				continue
			}
			visited[succHash] = struct{}{}
			succ, err := loadAttestation(cs, succHash)
			if err != nil {
				continue
			}
			if IsAttestationLive(cs, li, ix, succHash, succ, now) {
				return true
			}
			// succ is dead — descend into its forward chain in case any
			// further descendant is effectively live (the rescuing-grandchild
			// case the spec's literal pseudocode mishandles).
			if walk(succHash) {
				return true
			}
		}
		return false
	}
	return walk(root)
}
