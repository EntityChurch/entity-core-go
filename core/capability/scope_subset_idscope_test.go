package capability

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// TestGrantCovers_OperationsAreIdScopeNotPathMatcher pins the 0.8.2.16 fix:
// the `operations` dimension of a delegation subset check matches by the §5.2
// id-scope grammar (literal + bare "*" + trailing "/*"), NOT the §5.4 path
// matcher. A superset path matcher on a subset check over-grants.
//
// Mutation witness: reverting grantCovers' operations arm from idScopeSubset
// back to the MatchesPattern loop reddens the "/*/get over-grant" row — the
// path matcher's "/*/" interior wildcard would judge "/other/get" covered,
// while the id-scope grammar (correctly) treats "/*/get" as a literal that
// "/other/get" does not equal.
func TestGrantCovers_OperationsAreIdScopeNotPathMatcher(t *testing.T) {
	pid := testPeerID

	// SI-24 must still hold: a wildcard parent covers a concrete child, and a
	// trailing "/*" covers any segment-prefixed op — the id-scope grammar
	// carries exactly these two wildcard forms.
	starParent := types.CapabilityTokenData{Grants: []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}}}
	concreteChild := types.CapabilityTokenData{Grants: []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"compute/apply"}},
	}}}
	if !IsAttenuated(concreteChild, starParent, pid, pid, pid) {
		t.Fatal("bare-* parent operations must cover any child operation (SI-24)")
	}

	prefixParent := types.CapabilityTokenData{Grants: []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"compute/*"}},
	}}}
	if !IsAttenuated(concreteChild, prefixParent, pid, pid, pid) {
		t.Fatal("trailing-/* parent operation must cover a segment-prefixed child op (compute/* ⊇ compute/apply)")
	}

	// The over-grant the path matcher would allow and the id-scope grammar must
	// reject: a "/*/get" parent operation pattern is a LITERAL under id-scope,
	// so a child op "/other/get" is NOT a subset of it. Under the §5.4 path
	// matcher the "/*/" interior wildcard would (wrongly) cover it.
	pathFormParent := types.CapabilityTokenData{Grants: []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"/*/get"}},
	}}}
	pathFormChild := types.CapabilityTokenData{Grants: []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"/other/get"}},
	}}}
	if IsAttenuated(pathFormChild, pathFormParent, pid, pid, pid) {
		t.Fatal("id-scope operations must NOT apply the §5.4 /*/ interior wildcard: /other/get is not a subset of the literal /*/get")
	}
}

// TestGrantCovers_PeersDimensionAttenuated pins the second half of the
// 0.8.2.16 fix: the `peers` dimension is checked in the delegation subset, so a
// child grant cannot widen its `peers` scope past the parent.
//
// Mutation witness: deleting the peers-subset block in grantCovers reddens the
// "widened child" row — a child peers scope broader than the parent's would be
// judged a valid subset (the escalation nobody re-checks down a chain).
func TestGrantCovers_PeersDimensionAttenuated(t *testing.T) {
	pid := testPeerID
	const peerA = "peerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const peerB = "peerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	mk := func(peers []string) types.CapabilityTokenData {
		return types.CapabilityTokenData{Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
			Peers:      &types.CapabilityScope{Include: peers},
		}}}
	}

	parent := mk([]string{peerA})

	// Equal peers scope: covered.
	if !IsAttenuated(mk([]string{peerA}), parent, pid, pid, pid) {
		t.Fatal("child with identical peers scope must be a subset")
	}
	// Widened peers scope: NOT covered.
	if IsAttenuated(mk([]string{peerA, peerB}), parent, pid, pid, pid) {
		t.Fatal("child that ADDS peerB must NOT be a subset of a parent scoped to peerA — peers widening down a delegation chain is the escalation the check exists to close")
	}
	// A "*" parent covers a concrete child; a concrete parent does not cover "*".
	if !IsAttenuated(mk([]string{peerA}), mk([]string{"*"}), pid, pid, pid) {
		t.Fatal("bare-* parent peers must cover a concrete child peer")
	}
	if IsAttenuated(mk([]string{"*"}), parent, pid, pid, pid) {
		t.Fatal("child with * peers must NOT be a subset of a parent scoped to one peer")
	}
}
