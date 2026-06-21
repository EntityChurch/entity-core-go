package attestation

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// TV-A8 (per PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md §3.3, SI-1 Option A):
// Attestation A targets P. A has no valid signature bound (e.g., raw
// tree:put bypassed :create validation). DefaultFindAuthorizing returns A.
//
// Per v1.1 the substrate is signature-agnostic — `is_attestation_live` and
// `default_find_authorizing` do NOT signature-check. Consumers (identity)
// layer signature validation per topology via IdentityVerifyCert; that
// rejection is exercised in TV-I-A8 (in ext/identity tests).
//
// Pre-v1.1, TV-A8 expected null on the assumption signature-check was part
// of liveness; the v1.1 amendment ratifies the substrate-agnostic posture
// (Go's literal-spec behavior all along).
func TestTV_A8_SubstrateSignatureAgnostic(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x10)
	target := makeFakeHash(0x20)
	a := makeAttestationFor(attesting, target, "test-kind")
	hA := f.putAttestation(t, a)
	// No signatures bound for A. The substrate doesn't care.

	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	got, ok := find(target)
	if !ok {
		t.Fatalf("TV-A8 (v1.1): expected substrate to return A, got none")
	}
	if got.Hash != hA {
		t.Fatalf("TV-A8 (v1.1): returned %s, want %s", got.Hash, hA)
	}
}

// TV-A4a (per §3.1): chain of three, all valid → a2 live, a1 dead, a0 dead.
// (Same as TestLiveness_TransitiveSupersession_ChainOfThree; explicit TV
// label for cross-impl matrix mapping.)
func TestTV_A4a_ChainOfThree(t *testing.T) {
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
		t.Errorf("TV-A4a: a2 expected live")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA1, a1, 0) {
		t.Errorf("TV-A4a: a1 expected dead")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA0, a0, 0) {
		t.Errorf("TV-A4a: a0 expected dead (transitive)")
	}
}

// TV-A4b (per §3.1): chain of three; a2 expired → a1 live, a0 dead.
func TestTV_A4b_ChainOfThree_TailExpired(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x10)
	target := makeFakeHash(0x20)

	a0 := makeAttestationFor(attesting, target, "k")
	hA0 := f.putAttestation(t, a0)
	a1 := makeAttestationFor(attesting, target, "k")
	a1.Supersedes = &hA0
	hA1 := f.putAttestation(t, a1)
	a2 := makeExpiredAttestationFor(attesting, target, "k")
	a2.Supersedes = &hA1
	hA2 := f.putAttestation(t, a2)

	if IsAttestationLive(f.cs, f.li, f.ix, hA2, a2, 0) {
		t.Errorf("TV-A4b: a2 expected dead (expired)")
	}
	if !IsAttestationLive(f.cs, f.li, f.ix, hA1, a1, 0) {
		t.Errorf("TV-A4b: a1 expected live (no live descendant)")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA0, a0, 0) {
		t.Errorf("TV-A4b: a0 expected dead (a1 is live transitive descendant)")
	}
}

// TV-A4c (per §3.1): a0 → a1; a1 revoked; no a2 → a0 live (predecessor
// revival). Same as TestLiveness_RevocationOfSuccessor_ResurrectsPredecessor.
func TestTV_A4c_PredecessorRevival(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x10)
	target := makeFakeHash(0x20)

	a0 := makeAttestationFor(attesting, target, "k")
	hA0 := f.putAttestation(t, a0)
	a1 := makeAttestationFor(attesting, target, "k")
	a1.Supersedes = &hA0
	hA1 := f.putAttestation(t, a1)

	rev := makeAttestationFor(attesting, hA1, types.KindRevocation)
	f.putAttestation(t, rev)

	if IsAttestationLive(f.cs, f.li, f.ix, hA1, a1, 0) {
		t.Errorf("TV-A4c: a1 expected dead (self-revoked)")
	}
	if !IsAttestationLive(f.cs, f.li, f.ix, hA0, a0, 0) {
		t.Errorf("TV-A4c: a0 expected live (predecessor revival)")
	}
}

// TV-A4d (per §3.1): a0 → a1 → a2; a1 revoked; a2 valid → a2 live, a1
// dead, a0 dead (via transitive a2). Same as
// TestLiveness_ChainWithRevokedMiddleAndLiveTail.
func TestTV_A4d_RevokedMiddleLiveTail(t *testing.T) {
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
		t.Errorf("TV-A4d: a2 expected live")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA1, a1, 0) {
		t.Errorf("TV-A4d: a1 expected dead (revoked)")
	}
	if IsAttestationLive(f.cs, f.li, f.ix, hA0, a0, 0) {
		t.Errorf("TV-A4d: a0 expected dead (a2 is live transitive descendant)")
	}
}
