package attestation

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// fixture wires a content store + location index + index for graph tests.
// putAttestation stores the entity in the content store and adds it to the
// index, but does not bind it at any tree path (graph tests don't need the
// path layer — they exercise the index + content-store directly).
type fixture struct {
	cs *store.MemoryContentStore
	li *store.MemoryLocationIndex
	ix *Index
}

func newFixture() *fixture {
	return &fixture{
		cs: store.NewMemoryContentStore(),
		li: store.NewMemoryLocationIndex(),
		ix: NewIndex(),
	}
}

func (f *fixture) putAttestation(t *testing.T, att types.AttestationData) hash.Hash {
	t.Helper()
	ent, err := att.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if _, err := f.cs.Put(ent); err != nil {
		t.Fatalf("cs.Put: %v", err)
	}
	f.ix.Add(ent.ContentHash, att)
	return ent.ContentHash
}

// makeAttestationFor builds an AttestationData with an explicit kind value.
func makeAttestationFor(attesting, attested hash.Hash, kind string) types.AttestationData {
	att := types.AttestationData{
		Attesting: attesting,
		Attested:  attested,
	}
	props, _ := types.EncodeProperties(struct {
		Kind string `cbor:"kind"`
	}{Kind: kind})
	att.Properties = props
	return att
}

// makeExpiredAttestationFor builds an attestation whose expires_at is the
// epoch-millisecond past so IsAttestationLive returns false.
func makeExpiredAttestationFor(attesting, attested hash.Hash, kind string) types.AttestationData {
	att := makeAttestationFor(attesting, attested, kind)
	expired := uint64(1) // epoch-ms in the deep past
	att.ExpiresAt = &expired
	return att
}

// TV-A1 (§5.1): single live attestation at peer P → DefaultFindAuthorizing
// returns it.
func TestDefaultFindAuthorizing_TV_A1_SingleLive(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x10)
	target := makeFakeHash(0x20)
	att := makeAttestationFor(attesting, target, "test-kind")
	attHash := f.putAttestation(t, att)

	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	got, ok := find(target)
	if !ok {
		t.Fatalf("TV-A1: expected authorizing attestation, got none")
	}
	if got.Hash != attHash {
		t.Fatalf("TV-A1: returned %s, want %s", got.Hash, attHash)
	}
}

// TV-A2: no attestations targeting P → returns null.
func TestDefaultFindAuthorizing_TV_A2_None(t *testing.T) {
	f := newFixture()
	target := makeFakeHash(0x20)
	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	if _, ok := find(target); ok {
		t.Fatalf("TV-A2: expected null, got authorizing attestation")
	}
}

// TV-A3: three live attestations targeting P, all in distinct supersedes
// chains → DefaultFindAuthorizing returns the one with lowest content_hash.
func TestDefaultFindAuthorizing_TV_A3_DeterministicTieBreak(t *testing.T) {
	f := newFixture()
	target := makeFakeHash(0x20)
	// Three distinct attesting peers with different first-byte markers — the
	// content hashes will reflect the differences (fields are encoded into
	// the entity's data bytes).
	a := makeAttestationFor(makeFakeHash(0x11), target, "k1")
	b := makeAttestationFor(makeFakeHash(0x12), target, "k2")
	c := makeAttestationFor(makeFakeHash(0x13), target, "k3")
	hA := f.putAttestation(t, a)
	hB := f.putAttestation(t, b)
	hC := f.putAttestation(t, c)

	// Lowest content_hash among hA/hB/hC wins.
	winner := hA
	for _, h := range []hash.Hash{hB, hC} {
		if hashLess(h, winner) {
			winner = h
		}
	}

	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	got, ok := find(target)
	if !ok {
		t.Fatalf("TV-A3: expected authorizing")
	}
	if got.Hash != winner {
		t.Fatalf("TV-A3: returned %s, want lowest %s", got.Hash, winner)
	}
}

// TV-A4: three attestations forming a supersedes chain (A → A' → A”), all
// live → DefaultFindAuthorizing returns the live head A”.
func TestDefaultFindAuthorizing_TV_A4_SupersedesChainHead(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x11)
	target := makeFakeHash(0x20)

	a := makeAttestationFor(attesting, target, "k")
	hA := f.putAttestation(t, a)

	aPrime := makeAttestationFor(attesting, target, "k")
	aPrime.Supersedes = &hA
	hAPrime := f.putAttestation(t, aPrime)

	aDoublePrime := makeAttestationFor(attesting, target, "k")
	aDoublePrime.Supersedes = &hAPrime
	hAPP := f.putAttestation(t, aDoublePrime)

	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	got, ok := find(target)
	if !ok {
		t.Fatalf("TV-A4: expected authorizing")
	}
	if got.Hash != hAPP {
		t.Fatalf("TV-A4: returned %s, want live head %s", got.Hash, hAPP)
	}
}

// TV-A5: two distinct supersedes chains: {A, A'} (A' supersedes A) and {B},
// both targeting P → DefaultFindAuthorizing compares A' (live head of first
// chain) with B by content_hash; lowest wins.
func TestDefaultFindAuthorizing_TV_A5_TwoChainsTieBreak(t *testing.T) {
	f := newFixture()
	target := makeFakeHash(0x20)

	a := makeAttestationFor(makeFakeHash(0x11), target, "k")
	hA := f.putAttestation(t, a)
	aPrime := makeAttestationFor(makeFakeHash(0x11), target, "k")
	aPrime.Supersedes = &hA
	hAPrime := f.putAttestation(t, aPrime)

	b := makeAttestationFor(makeFakeHash(0x12), target, "k2")
	hB := f.putAttestation(t, b)

	winner := hAPrime
	if hashLess(hB, hAPrime) {
		winner = hB
	}

	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	got, ok := find(target)
	if !ok {
		t.Fatalf("TV-A5: expected authorizing")
	}
	if got.Hash != winner {
		t.Fatalf("TV-A5: returned %s, want %s", got.Hash, winner)
	}
}

// TV-A6: attestation A targets P; A is expired (expires_at < now) → null.
func TestDefaultFindAuthorizing_TV_A6_Expired(t *testing.T) {
	f := newFixture()
	target := makeFakeHash(0x20)
	a := makeExpiredAttestationFor(makeFakeHash(0x11), target, "k")
	f.putAttestation(t, a)

	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	if _, ok := find(target); ok {
		t.Fatalf("TV-A6: expected null for expired attestation")
	}
}

// TV-A7: attestation A targets P; self-revocation R targets A → null.
// Per IsAttestationLive's self-revocation check: a revocation attesting from
// A.Attesting that targets A and is itself live makes A dead.
func TestDefaultFindAuthorizing_TV_A7_SelfRevoked(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x11)
	target := makeFakeHash(0x20)
	a := makeAttestationFor(attesting, target, "k")
	hA := f.putAttestation(t, a)

	// Self-revocation: same attesting peer revokes its own attestation A.
	rev := makeAttestationFor(attesting, hA, types.KindRevocation)
	f.putAttestation(t, rev)

	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	if _, ok := find(target); ok {
		t.Fatalf("TV-A7: expected null for self-revoked attestation")
	}
}

// TV-A9: as_of parameter set to a timestamp before A's not_before → null
// (A not yet effective).
func TestDefaultFindAuthorizing_TV_A9_NotYetEffective(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x11)
	target := makeFakeHash(0x20)
	a := makeAttestationFor(attesting, target, "k")
	notBefore := uint64(1_000_000)
	a.NotBefore = &notBefore
	f.putAttestation(t, a)

	asOf := uint64(500_000) // before not_before
	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, asOf)
	if _, ok := find(target); ok {
		t.Fatalf("TV-A9: expected null when as_of < not_before")
	}

	// And valid when as_of >= not_before.
	asOf2 := uint64(2_000_000)
	find2 := DefaultFindAuthorizing(f.cs, f.li, f.ix, asOf2)
	if _, ok := find2(target); !ok {
		t.Fatalf("TV-A9: expected authorizing when as_of >= not_before")
	}
}

// TV-A10: attestation A targets P with kind="reputation" (not authorization-
// conferring). Default behavior is kind-agnostic — A is returned.
func TestDefaultFindAuthorizing_TV_A10_KindAgnostic(t *testing.T) {
	f := newFixture()
	attesting := makeFakeHash(0x11)
	target := makeFakeHash(0x20)
	a := makeAttestationFor(attesting, target, "reputation")
	hA := f.putAttestation(t, a)

	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	got, ok := find(target)
	if !ok || got.Hash != hA {
		t.Fatalf("TV-A10: expected reputation-kind A returned (default kind-agnostic)")
	}
}

// TV-A11: multi-context peer P with two unrelated authorizing attestations
// (e.g., a controller cert from quorum_A AND an agent cert from controller_B,
// both targeting P). Default tie-break picks one deterministically by
// content_hash. A custom find_authorizing_fn that filters by storage path or
// attesting-membership returns the consumer-intended chain.
func TestDefaultFindAuthorizing_TV_A11_MultiContext(t *testing.T) {
	f := newFixture()
	target := makeFakeHash(0x20)
	a1 := makeAttestationFor(makeFakeHash(0xA1), target, "identity-cert")
	a2 := makeAttestationFor(makeFakeHash(0xB2), target, "identity-cert")
	hA1 := f.putAttestation(t, a1)
	hA2 := f.putAttestation(t, a2)

	// Default behavior: lowest content_hash wins.
	winner := hA1
	if hashLess(hA2, hA1) {
		winner = hA2
	}
	def := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	got, ok := def(target)
	if !ok || got.Hash != winner {
		t.Fatalf("TV-A11 default: returned %s, want %s", got.Hash, winner)
	}

	// Custom override that filters to A2's attesting peer specifically.
	custom := func(peerHash hash.Hash) (AttestationRef, bool) {
		candidates := FindAttestationsTargeting(f.cs, f.ix, peerHash, func(_ hash.Hash, att types.AttestationData) bool {
			return att.Attesting == makeFakeHash(0xB2)
		})
		if len(candidates) == 0 {
			return AttestationRef{}, false
		}
		return candidates[0], true
	}
	gotCustom, ok := custom(target)
	if !ok || gotCustom.Hash != hA2 {
		t.Fatalf("TV-A11 custom: returned %s, want A2 %s", gotCustom.Hash, hA2)
	}
}

// WalkAttestingChain: simple chain A → B → C terminating at C (where C's
// attesting matches the terminate predicate's marker hash).
func TestWalkAttestingChain_BasicChain(t *testing.T) {
	f := newFixture()
	root := makeFakeHash(0xFF) // terminating "quorum" marker
	mid := makeFakeHash(0xCC)  // intermediate peer
	leaf := makeFakeHash(0xDD) // leaf peer

	// C: attesting=root, attested=mid (root authorizes mid)
	c := makeAttestationFor(root, mid, "identity-cert")
	hC := f.putAttestation(t, c)

	// B: attesting=mid, attested=leaf (mid authorizes leaf)
	b := makeAttestationFor(mid, leaf, "identity-cert")
	hB := f.putAttestation(t, b)

	// Start from B; terminate when attesting==root.
	terminate := func(att AttestationRef) bool {
		return att.Data.Attesting == root
	}
	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)
	chain, ok := WalkAttestingChain(hB, b, terminate, find, 0)
	if !ok {
		t.Fatalf("expected chain to terminate")
	}
	if len(chain) != 2 {
		t.Fatalf("chain length %d, want 2", len(chain))
	}
	if chain[0].Hash != hB || chain[1].Hash != hC {
		t.Fatalf("chain order wrong: %v", chain)
	}
}

// WalkAttestingChain returns null when the chain doesn't terminate within
// max_depth.
func TestWalkAttestingChain_MaxDepthExceeded(t *testing.T) {
	f := newFixture()
	// Build a chain with no terminator — each cert's attester has another
	// authorizing cert above it ad infinitum (5 levels here).
	peers := []hash.Hash{
		makeFakeHash(0x01),
		makeFakeHash(0x02),
		makeFakeHash(0x03),
		makeFakeHash(0x04),
		makeFakeHash(0x05),
	}
	// Each peers[i] has an attestation where attesting=peers[i+1] authorizes peers[i].
	hashes := make([]hash.Hash, len(peers))
	for i := 0; i < len(peers)-1; i++ {
		att := makeAttestationFor(peers[i+1], peers[i], "k")
		hashes[i] = f.putAttestation(t, att)
	}
	// Top peer has no authorizing cert above.

	terminate := func(att AttestationRef) bool { return false } // never
	find := DefaultFindAuthorizing(f.cs, f.li, f.ix, 0)

	// Start from the bottom; with maxDepth=2 the walk runs out before the
	// chain ends.
	startHash := hashes[0]
	startData, _ := loadAttestation(f.cs, startHash)
	chain, ok := WalkAttestingChain(startHash, startData, terminate, find, 2)
	if ok {
		t.Fatalf("expected non-termination, got chain of length %d", len(chain))
	}
}
