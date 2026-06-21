package attestation

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestLiveness_TransitiveSupersession_ChainOfThree exercises the case Python's
// review identified as the bistable bug in §4.3 is_attestation_live's literal
// pseudocode (see SI-2). Chain a0 → a1 → a2, all otherwise good.
//
// Expected: a2 is live (head); a0 and a1 are both dead.
//
// Buggy implementation (direct-successor recursion as written in the spec)
// produces a0 live because IsAttestationLive(a1) returns false (a2
// supersedes a1), so a0's check "is my direct successor a1 live?" finds a1
// dead and concludes "I'm not superseded by a live successor" → a0 returns
// true. Wrong.
func TestLiveness_TransitiveSupersession_ChainOfThree(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x10)
	target := makeFakeHash(0x20)

	a0 := makeAttestationFor(attesting, target, "k")
	hA0 := f.putAttestation(t, a0)

	a1 := makeAttestationFor(attesting, target, "k")
	a1.Supersedes = &hA0
	hA1 := f.putAttestation(t, a1)

	a2 := makeAttestationFor(attesting, target, "k")
	a2.Supersedes = &hA1
	hA2 := f.putAttestation(t, a2)

	if !IsAttestationLive(f.cs, f.li, f.ix, hA2, a2, 0) {
		t.Errorf("a2 (live head) expected live; got dead")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA1, a1, 0) {
		t.Errorf("a1 expected dead (superseded by a2); got live")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA0, a0, 0) {
		t.Errorf("a0 expected dead (transitively superseded by a2); got live — bistable bug")
	}
}

// TestLiveness_RevocationOfSuccessor_ResurrectsPredecessor exercises the
// Python-aligned semantics: if a0 → a1 and a1 is then revoked (no a2), a0
// comes back to life. This matches Python's stated interpretation —
// "att is dead iff a non-revoked, non-expired transitive descendant exists" —
// and provides intuitive UX (an accidental supersede can be rolled back).
//
// SI-2 also flags this. Architecture team: please confirm this is the
// intended semantics (or pin the alternative — once-superseded-stays-dead).
func TestLiveness_RevocationOfSuccessor_ResurrectsPredecessor(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x10)
	target := makeFakeHash(0x20)

	a0 := makeAttestationFor(attesting, target, "k")
	hA0 := f.putAttestation(t, a0)

	a1 := makeAttestationFor(attesting, target, "k")
	a1.Supersedes = &hA0
	hA1 := f.putAttestation(t, a1)

	// Self-revocation of a1 by attesting (which is a1.Attesting).
	rev := makeAttestationFor(attesting, hA1, types.KindRevocation)
	f.putAttestation(t, rev)

	if IsAttestationLive(f.cs, f.li, f.ix, hA1, a1, 0) {
		t.Errorf("a1 expected dead (self-revoked); got live")
	}
	if !IsAttestationLive(f.cs, f.li, f.ix, hA0, a0, 0) {
		t.Errorf("a0 expected live (a1 revoked, no other successor); got dead")
	}
}

// TestLiveness_ChainWithRevokedMiddleAndLiveTail exercises the harder case
// from Python's review notes: a0 → a1 → a2, a1 revoked, a2 fine. Expected:
// a2 is live (the tail); a0 is dead (a2 is an effectively-live transitive
// descendant); a1 is dead (revoked).
func TestLiveness_ChainWithRevokedMiddleAndLiveTail(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x10)
	target := makeFakeHash(0x20)

	a0 := makeAttestationFor(attesting, target, "k")
	hA0 := f.putAttestation(t, a0)

	a1 := makeAttestationFor(attesting, target, "k")
	a1.Supersedes = &hA0
	hA1 := f.putAttestation(t, a1)

	a2 := makeAttestationFor(attesting, target, "k")
	a2.Supersedes = &hA1
	hA2 := f.putAttestation(t, a2)

	rev := makeAttestationFor(attesting, hA1, types.KindRevocation)
	f.putAttestation(t, rev)

	if !IsAttestationLive(f.cs, f.li, f.ix, hA2, a2, 0) {
		t.Errorf("a2 expected live (tail beyond revocation); got dead")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA1, a1, 0) {
		t.Errorf("a1 expected dead (revoked); got live")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA0, a0, 0) {
		t.Errorf("a0 expected dead (a2 is an effectively-live transitive descendant); got live")
	}
}

// TestLiveness_FindLiveHead_OnChainOfThree confirms the FindLiveHead helper
// returns a2 (the head) given any starting point in the chain.
func TestLiveness_FindLiveHead_OnChainOfThree(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x10)
	target := makeFakeHash(0x20)

	a0 := makeAttestationFor(attesting, target, "k")
	hA0 := f.putAttestation(t, a0)
	a1 := makeAttestationFor(attesting, target, "k")
	a1.Supersedes = &hA0
	hA1 := f.putAttestation(t, a1)
	a2 := makeAttestationFor(attesting, target, "k")
	a2.Supersedes = &hA1
	hA2 := f.putAttestation(t, a2)

	for label, start := range map[string]struct {
		h hash.Hash
		d types.AttestationData
	}{
		"from-a0": {hA0, a0},
		"from-a1": {hA1, a1},
		"from-a2": {hA2, a2},
	} {
		gotHash, _, ok := FindLiveHead(f.cs, f.li, f.ix, start.h, start.d, 0)
		if !ok {
			t.Errorf("%s: FindLiveHead returned not-found", label)
			continue
		}
		if gotHash != hA2 {
			t.Errorf("%s: FindLiveHead = %s, want a2 (%s)", label, gotHash, hA2)
		}
	}
}
