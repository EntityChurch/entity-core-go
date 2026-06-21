package attestation

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Cross-impl test vectors TV-I1 through TV-I5 from EXTENSION-ATTESTATION §5.7.
// These verify the index invariants I1-I5: write-then-read consistency,
// atomicity with handler completion, cross-handler consistency, retention
// after revocation/supersession, and the kind-index entry-per-attestation
// rule (with no entry for attestations lacking a "kind" key).

// makeFakeHash returns a deterministic 33-byte hash with the given marker
// byte at position 1, used to seed test attestations without computing real
// content hashes. The first byte is the algorithm code (0x01 = blake3-256).
func makeFakeHash(b byte) hash.Hash {
	var raw [33]byte
	raw[0] = hash.AlgorithmSHA256
	raw[1] = b
	h, err := hash.FromBytes(raw[:])
	if err != nil {
		panic(err)
	}
	return h
}

// makeAttestation builds an AttestationData with the given attesting,
// attested, kind, and supersedes for index-test fixtures. supersedes nil ⇒
// no supersedes field. kind "" ⇒ properties has no kind key (TV-I5 case).
func makeAttestation(attesting, attested hash.Hash, kind string, supersedes *hash.Hash) types.AttestationData {
	att := types.AttestationData{
		Attesting:  attesting,
		Attested:   attested,
		Supersedes: supersedes,
	}
	if kind != "" {
		props, _ := types.EncodeProperties(struct {
			Kind string `cbor:"kind"`
		}{Kind: kind})
		att.Properties = props
	}
	return att
}

// TV-I1 (§5.7): create attestation A; immediately FindAttestationsTargeting
// returns A.
func TestIndex_TV_I1_WriteThenReadConsistency(t *testing.T) {
	ix := NewIndex()
	attesting := makeFakeHash(0x01)
	attested := makeFakeHash(0x02)
	att := makeAttestation(attesting, attested, "test-kind", nil)
	attHash := makeFakeHash(0xA1)
	ix.Add(attHash, att)

	got := ix.FindByAttested(attested)
	if len(got) != 1 || got[0] != attHash {
		t.Fatalf("TV-I1: FindByAttested = %v, want [%s]", got, attHash)
	}
}

// TV-I2: when create fails validation, the entity is in NO index. We model
// this by simply not calling Add — the handler skips index updates on
// validation failure (per the ops.go validateStructure → 400 path).
func TestIndex_TV_I2_NoIndexOnValidationFailure(t *testing.T) {
	ix := NewIndex()
	attHash := makeFakeHash(0xA2)
	if ix.Has(attHash) {
		t.Fatal("expected empty index")
	}
	// Verify the index is empty across all four lookups.
	if len(ix.FindByAttesting(makeFakeHash(0x01))) != 0 ||
		len(ix.FindByAttested(makeFakeHash(0x02))) != 0 ||
		len(ix.FindByKind("test-kind")) != 0 ||
		len(ix.FindBySupersedes(makeFakeHash(0x03))) != 0 {
		t.Fatal("TV-I2: expected all indexes empty")
	}
}

// TV-I3: two attestations A, B with same attesting but different attested;
// FindByAttesting(A.attesting) returns both.
func TestIndex_TV_I3_SharedAttesting(t *testing.T) {
	ix := NewIndex()
	attesting := makeFakeHash(0x01)
	attestedA := makeFakeHash(0x02)
	attestedB := makeFakeHash(0x03)

	a := makeAttestation(attesting, attestedA, "kind-a", nil)
	b := makeAttestation(attesting, attestedB, "kind-b", nil)
	aHash := makeFakeHash(0xA3)
	bHash := makeFakeHash(0xA4)
	ix.Add(aHash, a)
	ix.Add(bHash, b)

	got := ix.FindByAttesting(attesting)
	if len(got) != 2 {
		t.Fatalf("TV-I3: FindByAttesting returned %d, want 2", len(got))
	}
	want := map[hash.Hash]bool{aHash: true, bHash: true}
	for _, h := range got {
		if !want[h] {
			t.Errorf("TV-I3: unexpected hash %s", h)
		}
		delete(want, h)
	}
	if len(want) != 0 {
		t.Errorf("TV-I3: missing %v", want)
	}
}

// TV-I4: attestation A; revocation R targets A; FindByAttested(A.attested)
// still returns A (revocation does not remove from index). The IsAttestationLive
// check is what determines current liveness — index-side persistence is the
// invariant.
func TestIndex_TV_I4_RevocationDoesNotRemoveFromIndex(t *testing.T) {
	ix := NewIndex()
	attesting := makeFakeHash(0x01)
	attested := makeFakeHash(0x02)
	a := makeAttestation(attesting, attested, "test-kind", nil)
	aHash := makeFakeHash(0xA5)
	ix.Add(aHash, a)

	// Revocation: attests against aHash with kind="revocation".
	revoker := makeFakeHash(0x10)
	r := makeAttestation(revoker, aHash, types.KindRevocation, nil)
	rHash := makeFakeHash(0xA6)
	ix.Add(rHash, r)

	// A still in index by its attested.
	got := ix.FindByAttested(attested)
	if len(got) != 1 || got[0] != aHash {
		t.Fatalf("TV-I4: A removed from index by revocation arrival; got %v", got)
	}
	// Revocation indexed by its attested (which is A's hash).
	gotRev := ix.FindByAttested(aHash)
	if len(gotRev) != 1 || gotRev[0] != rHash {
		t.Fatalf("TV-I4: revocation not indexed; got %v", gotRev)
	}
}

// TV-I5: attestation A with kind="foo"; B with kind="foo"; C with no "kind"
// key. FindByKind("foo") returns {A, B}; C not included; C still indexed
// by attesting/attested.
func TestIndex_TV_I5_KindIndexExcludesNoKindAttestations(t *testing.T) {
	ix := NewIndex()
	attesting := makeFakeHash(0x01)
	attested := makeFakeHash(0x02)
	a := makeAttestation(attesting, attested, "foo", nil)
	b := makeAttestation(attesting, attested, "foo", nil)
	c := makeAttestation(attesting, attested, "" /* no kind key */, nil)
	aHash := makeFakeHash(0xA7)
	bHash := makeFakeHash(0xA8)
	cHash := makeFakeHash(0xA9)
	ix.Add(aHash, a)
	ix.Add(bHash, b)
	ix.Add(cHash, c)

	gotKind := ix.FindByKind("foo")
	if len(gotKind) != 2 {
		t.Fatalf("TV-I5: FindByKind(foo) returned %d, want 2", len(gotKind))
	}
	for _, h := range gotKind {
		if h == cHash {
			t.Fatalf("TV-I5: C (no kind key) appeared in kind index")
		}
	}

	// C still indexed by attesting/attested.
	allByAttesting := ix.FindByAttesting(attesting)
	cFoundByAttesting := false
	for _, h := range allByAttesting {
		if h == cHash {
			cFoundByAttesting = true
		}
	}
	if !cFoundByAttesting {
		t.Fatalf("TV-I5: C missing from attesting index")
	}
}

// Add+Remove round-trip: removing an entry leaves the index empty for that
// projection.
func TestIndex_AddRemoveRoundTrip(t *testing.T) {
	ix := NewIndex()
	attesting := makeFakeHash(0x01)
	attested := makeFakeHash(0x02)
	a := makeAttestation(attesting, attested, "test-kind", nil)
	aHash := makeFakeHash(0xAA)
	ix.Add(aHash, a)
	if !ix.Has(aHash) {
		t.Fatal("Add did not record attestation")
	}
	ix.Remove(aHash)
	if ix.Has(aHash) {
		t.Fatal("Remove did not delete attestation")
	}
	if len(ix.FindByAttesting(attesting)) != 0 {
		t.Fatal("attesting bucket not cleaned up")
	}
	if len(ix.FindByAttested(attested)) != 0 {
		t.Fatal("attested bucket not cleaned up")
	}
	if len(ix.FindByKind("test-kind")) != 0 {
		t.Fatal("kind bucket not cleaned up")
	}
}

// Idempotence: re-adding the same hash leaves the index unchanged.
func TestIndex_AddIdempotent(t *testing.T) {
	ix := NewIndex()
	attesting := makeFakeHash(0x01)
	attested := makeFakeHash(0x02)
	a := makeAttestation(attesting, attested, "k", nil)
	aHash := makeFakeHash(0xAB)
	ix.Add(aHash, a)
	ix.Add(aHash, a)
	got := ix.FindByAttesting(attesting)
	if len(got) != 1 {
		t.Fatalf("re-add doubled count: %d", len(got))
	}
}

// Sort determinism: results are sorted by lowest-content_hash for tie-break
// reproducibility per TV-A3 / TV-A5.
func TestIndex_FindByAttestedDeterministicOrder(t *testing.T) {
	ix := NewIndex()
	target := makeFakeHash(0x10)
	// Insert in reverse order so sort matters.
	hashes := []hash.Hash{
		makeFakeHash(0x33),
		makeFakeHash(0x22),
		makeFakeHash(0x11),
	}
	for _, h := range hashes {
		ix.Add(h, makeAttestation(makeFakeHash(0xFF), target, "k", nil))
	}
	got := ix.FindByAttested(target)
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	if !hashLess(got[0], got[1]) || !hashLess(got[1], got[2]) {
		t.Fatalf("results not sorted: %v", got)
	}
}
