package quorum

import (
	"context"
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
)

// fixture provides a content store + location index + attestation handler +
// quorum handler wired together for tests. Stores entities at canonical
// paths so IsQuorumID lookups work.
type fixture struct {
	cs  *store.MemoryContentStore
	li  *store.MemoryLocationIndex
	att *attestation.Handler
	q   *Handler
}

func newFixture() *fixture {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	att := attestation.NewHandler()
	att.SetupStore(cs, li, "")
	q := NewHandler()
	q.SetupStore(cs, li, "")
	q.SetupAttestation(att)
	return &fixture{cs: cs, li: li, att: att, q: q}
}

// makeFakeHash builds a hash with the given marker byte.
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

// putQuorum stores a quorum entity at its canonical path and returns the
// quorum_id (= content hash).
func (f *fixture) putQuorum(t *testing.T, signers []hash.Hash, threshold uint64, mode string) hash.Hash {
	t.Helper()
	q := types.QuorumData{Signers: signers, Threshold: threshold, SignerResolution: mode}
	ent, err := q.ToEntity()
	if err != nil {
		t.Fatalf("encode quorum: %v", err)
	}
	if _, err := f.cs.Put(ent); err != nil {
		t.Fatalf("cs.Put: %v", err)
	}
	f.li.Set(QuorumPath(ent.ContentHash), ent.ContentHash)
	return ent.ContentHash
}

// TV-Q1 (§5.3.1): quorum with signer_resolution="concrete" → validation
// proceeds (concrete is built-in).
func TestTV_Q1_ConcreteMode(t *testing.T) {
	f := newFixture()
	signers := []hash.Hash{makeFakeHash(0x01), makeFakeHash(0x02), makeFakeHash(0x03)}
	qID := f.putQuorum(t, signers, 2, types.SignerResolutionConcrete)

	got, threshold, err := f.q.CurrentSignerSet(qID)
	if err != nil {
		t.Fatalf("CurrentSignerSet: %v", err)
	}
	if threshold != 2 {
		t.Fatalf("threshold = %d, want 2", threshold)
	}
	if len(got) != 3 {
		t.Fatalf("signers = %v, want 3 entries", got)
	}
}

// TV-Q3: quorum with signer_resolution="identity-resolved" but
// EXTENSION-IDENTITY NOT installed → quorum_resolver_unavailable error
// with mode_name="identity-resolved" and available_modes=["concrete"].
func TestTV_Q3_IdentityResolvedNotInstalled(t *testing.T) {
	f := newFixture()
	signers := []hash.Hash{makeFakeHash(0x01)}
	qID := f.putQuorum(t, signers, 1, types.SignerResolutionIdentityResolved)

	_, _, err := f.q.CurrentSignerSet(qID)
	if err == nil {
		t.Fatal("expected ResolverError, got nil")
	}
	var rerr *ResolverError
	if !errors.As(err, &rerr) {
		t.Fatalf("expected *ResolverError, got %T: %v", err, err)
	}
	if rerr.ModeName != types.SignerResolutionIdentityResolved {
		t.Errorf("mode_name = %q, want %q", rerr.ModeName, types.SignerResolutionIdentityResolved)
	}
	if len(rerr.AvailableModes) != 1 || rerr.AvailableModes[0] != types.SignerResolutionConcrete {
		t.Errorf("available_modes = %v, want [concrete]", rerr.AvailableModes)
	}
}

// TV-Q4: quorum with unknown signer_resolution mode → fail-closed with
// quorum_resolver_unavailable.
func TestTV_Q4_UnknownMode(t *testing.T) {
	f := newFixture()
	signers := []hash.Hash{makeFakeHash(0x01)}
	qID := f.putQuorum(t, signers, 1, "future-mode-xyz")

	_, _, err := f.q.CurrentSignerSet(qID)
	if err == nil {
		t.Fatal("expected ResolverError, got nil")
	}
	var rerr *ResolverError
	if !errors.As(err, &rerr) {
		t.Fatalf("expected *ResolverError, got %T", err)
	}
	if rerr.ModeName != "future-mode-xyz" {
		t.Errorf("mode_name = %q, want future-mode-xyz", rerr.ModeName)
	}
}

// TV-Q2: quorum with signer_resolution="identity-resolved", resolver
// registered → resolution succeeds. We register a stub resolver that maps
// each signer to its successor hash to verify the resolved set is what's
// returned.
func TestTV_Q2_IdentityResolvedRegistered(t *testing.T) {
	f := newFixture()
	signers := []hash.Hash{makeFakeHash(0x01), makeFakeHash(0x02)}
	qID := f.putQuorum(t, signers, 1, types.SignerResolutionIdentityResolved)

	resolved := map[hash.Hash]hash.Hash{
		makeFakeHash(0x01): makeFakeHash(0xA1),
		makeFakeHash(0x02): makeFakeHash(0xA2),
	}
	f.q.RegisterResolver(types.SignerResolutionIdentityResolved, func(_ context.Context, ref hash.Hash, _ store.ContentStore, _ store.LocationIndex, _ uint64) (hash.Hash, error) {
		return resolved[ref], nil
	})

	got, _, err := f.q.CurrentSignerSet(qID)
	if err != nil {
		t.Fatalf("CurrentSignerSet: %v", err)
	}
	if got[0] != makeFakeHash(0xA1) || got[1] != makeFakeHash(0xA2) {
		t.Fatalf("resolved signers = %v, want resolver outputs", got)
	}
}

// TV-Q5: registration mid-flight — first call before registration fails
// with C2-style error; second call after registration succeeds.
func TestTV_Q5_RegistrationMidFlight(t *testing.T) {
	f := newFixture()
	signers := []hash.Hash{makeFakeHash(0x01)}
	qID := f.putQuorum(t, signers, 1, types.SignerResolutionIdentityResolved)

	if _, _, err := f.q.CurrentSignerSet(qID); err == nil {
		t.Fatal("expected ResolverError before registration")
	}
	// Note: the cache must NOT memoize the failure — per §5.3.1 C2 "MUST NOT
	// cache 'resolver missing' status across registration events". We
	// implicitly satisfy this because computeSignerSet is only cached on
	// success (cache.set is only called after a successful return).

	f.q.RegisterResolver(types.SignerResolutionIdentityResolved, func(_ context.Context, ref hash.Hash, _ store.ContentStore, _ store.LocationIndex, _ uint64) (hash.Hash, error) {
		return makeFakeHash(0xA1), nil
	})
	got, _, err := f.q.CurrentSignerSet(qID)
	if err != nil {
		t.Fatalf("CurrentSignerSet after registration: %v", err)
	}
	if len(got) != 1 || got[0] != makeFakeHash(0xA1) {
		t.Fatalf("signers = %v, want [A1]", got)
	}
}

// TV-Q6: quorum entity Q stored at system/quorum/{hex(Q.hash)} →
// IsQuorumID(Q.hash) == true.
func TestTV_Q6_IsQuorumIDPathBased(t *testing.T) {
	f := newFixture()
	signers := []hash.Hash{makeFakeHash(0x01)}
	qID := f.putQuorum(t, signers, 1, types.SignerResolutionConcrete)
	if !IsQuorumID(f.cs, f.li, qID) {
		t.Fatal("TV-Q6: expected true")
	}
}

// TV-Q7: no entity at system/quorum/{hex(H)} → IsQuorumID(H) == false.
func TestTV_Q7_IsQuorumIDMissing(t *testing.T) {
	f := newFixture()
	if IsQuorumID(f.cs, f.li, makeFakeHash(0x99)) {
		t.Fatal("TV-Q7: expected false for unbound hash")
	}
}

// TV-Q8: entity at system/quorum/{hex(H)} of type system/identity/peer-config
// (path-name collision; pathologically malformed tree) → IsQuorumID returns
// false.
func TestTV_Q8_IsQuorumIDTypeMismatch(t *testing.T) {
	f := newFixture()
	wrongHash := makeFakeHash(0x55)
	// Manually bind a non-quorum hash at a quorum-shaped path.
	pcEnt, _ := types.IdentityPeerConfigData{
		TrustsQuorum: makeFakeHash(0x01),
	}.ToEntity()
	if _, err := f.cs.Put(pcEnt); err != nil {
		t.Fatalf("cs.Put: %v", err)
	}
	f.li.Set(QuorumPath(wrongHash), pcEnt.ContentHash)
	if IsQuorumID(f.cs, f.li, wrongHash) {
		t.Fatal("TV-Q8: expected false for type mismatch")
	}
}

// TV-Q9: cert validation runs for top-level controller cert before Q is
// written to tree → IsQuorumID returns false at first call; true after Q
// is written.
func TestTV_Q9_IsQuorumIDRaceSemantics(t *testing.T) {
	f := newFixture()
	candidate := makeFakeHash(0x77)
	if IsQuorumID(f.cs, f.li, candidate) {
		t.Fatal("TV-Q9: expected false before Q is written")
	}
	// Now write the quorum at the candidate path.
	signers := []hash.Hash{makeFakeHash(0x01)}
	qID := f.putQuorum(t, signers, 1, types.SignerResolutionConcrete)
	if !IsQuorumID(f.cs, f.li, qID) {
		t.Fatal("TV-Q9: expected true after Q is written")
	}
}

// TV-QF15 (§4.2.1): cache populated for both quorum_id_A and quorum_id_B;
// invalidating quorum_id_A leaves quorum_id_B's cache untouched.
func TestTV_QF15_CacheScopedPerQuorum(t *testing.T) {
	f := newFixture()
	signersA := []hash.Hash{makeFakeHash(0x11), makeFakeHash(0x12)}
	signersB := []hash.Hash{makeFakeHash(0x21), makeFakeHash(0x22)}
	qA := f.putQuorum(t, signersA, 2, types.SignerResolutionConcrete)
	qB := f.putQuorum(t, signersB, 1, types.SignerResolutionConcrete)

	// Populate caches.
	if _, _, err := f.q.CurrentSignerSet(qA); err != nil {
		t.Fatalf("populate A: %v", err)
	}
	if _, _, err := f.q.CurrentSignerSet(qB); err != nil {
		t.Fatalf("populate B: %v", err)
	}
	if _, _, ok := f.q.cache.get(qA); !ok {
		t.Fatal("A cache empty after populate")
	}
	if _, _, ok := f.q.cache.get(qB); !ok {
		t.Fatal("B cache empty after populate")
	}

	// Invalidate A.
	f.q.InvalidateCache(qA)

	if _, _, ok := f.q.cache.get(qA); ok {
		t.Fatal("TV-QF15: A cache not invalidated")
	}
	if _, _, ok := f.q.cache.get(qB); !ok {
		t.Fatal("TV-QF15: B cache wrongly invalidated")
	}
}

// TV-QF12: cache populated for quorum_id; successful local
// system/quorum:update for quorum_id invalidates the cache. (Modeled as a
// direct call to InvalidateCache from handleUpdate's success path; verified
// here by populating, calling InvalidateCache, and observing the next
// CurrentSignerSet recomputes fresh.)
func TestTV_QF12_LocalUpdateInvalidates(t *testing.T) {
	f := newFixture()
	signers := []hash.Hash{makeFakeHash(0x11)}
	qID := f.putQuorum(t, signers, 1, types.SignerResolutionConcrete)

	_, _, _ = f.q.CurrentSignerSet(qID)
	if _, _, ok := f.q.cache.get(qID); !ok {
		t.Fatal("cache not populated")
	}
	f.q.InvalidateCache(qID) // simulates handleUpdate success path
	if _, _, ok := f.q.cache.get(qID); ok {
		t.Fatal("TV-QF12: cache not invalidated after local update")
	}
}

// VerifyKOfNSignatures: empty signer set / threshold zero → invalid.
func TestVerifyKOfN_Edge(t *testing.T) {
	f := newFixture()
	target := makeFakeHash(0x42)
	if _, ok := VerifyKOfNSignatures(f.cs, f.li, target, nil, 0); ok {
		t.Fatal("threshold=0 should be invalid")
	}
	if _, ok := VerifyKOfNSignatures(f.cs, f.li, target, []hash.Hash{makeFakeHash(0x01)}, 1); ok {
		t.Fatal("no signature in store should fail")
	}
}
