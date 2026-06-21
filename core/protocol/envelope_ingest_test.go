package protocol

import (
	"sync/atomic"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// countingContentStore wraps a ContentStore counting Put + Has + Get calls.
// Used by the H-G3 pin tests to assert ingest's dedup paths fire.
type countingContentStore struct {
	inner store.ContentStore
	put   atomic.Int64
	has   atomic.Int64
	get   atomic.Int64
}

func (c *countingContentStore) Put(e entity.Entity) (hash.Hash, error) {
	c.put.Add(1)
	return c.inner.Put(e)
}
func (c *countingContentStore) Get(h hash.Hash) (entity.Entity, bool) {
	c.get.Add(1)
	return c.inner.Get(h)
}
func (c *countingContentStore) Has(h hash.Hash) bool {
	c.has.Add(1)
	return c.inner.Has(h)
}
func (c *countingContentStore) Remove(h hash.Hash) bool { return c.inner.Remove(h) }
func (c *countingContentStore) Len() int                { return c.inner.Len() }

type countingLocationIndex struct {
	inner store.LocationIndex
	get   atomic.Int64
	set   atomic.Int64
}

func (c *countingLocationIndex) Set(path string, h hash.Hash) error {
	c.set.Add(1)
	return c.inner.Set(path, h)
}
func (c *countingLocationIndex) Get(path string) (hash.Hash, bool) {
	c.get.Add(1)
	return c.inner.Get(path)
}
func (c *countingLocationIndex) Has(path string) bool              { return c.inner.Has(path) }
func (c *countingLocationIndex) Remove(path string) (hash.Hash, bool) { return c.inner.Remove(path) }
func (c *countingLocationIndex) List(prefix string) []store.LocationEntry {
	return c.inner.List(prefix)
}
func (c *countingLocationIndex) LenPrefix(prefix string) int { return c.inner.LenPrefix(prefix) }
func (c *countingLocationIndex) CompareAndSwap(path string, expected, new hash.Hash) error {
	return c.inner.CompareAndSwap(path, expected, new)
}
func (c *countingLocationIndex) CompareAndRemove(path string, expected hash.Hash) error {
	return c.inner.CompareAndRemove(path, expected)
}

// buildIngestFixture creates a (signer-identity, signature) pair ready for
// IngestEnvelopeSignatures.
func buildIngestFixture(t *testing.T) (entity.Entity, entity.Entity, hash.Hash, string) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	idEnt, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	idData, err := types.PeerDataFromEntity(idEnt)
	if err != nil {
		t.Fatal(err)
	}

	// Synthetic target hash — content doesn't matter for ingest semantics.
	var target hash.Hash
	target.Digest[0] = 0x11
	sigBytes := kp.Sign(target.Bytes())

	sigEnt, err := types.SignatureData{
		Target:    target,
		Signer:    idEnt.ContentHash,
		Algorithm: "ed25519",
		Signature: sigBytes,
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	// v7.65 §1.5: peer_id derives from public_key.
	pid := crypto.PeerIDFromEd25519PublicKey(idData.PublicKey)
	path := types.InvariantSignaturePath(string(pid), target)
	return idEnt, sigEnt, target, path
}

// H-G3 fix A: re-ingesting an already-bound signature is a full no-op —
// no cs.Put, no li.Set, no cascade walk. Pins the path-check-first
// reordering in envelope_ingest.go.
func TestHG3_ReIngestAlreadyBoundIsFullNoop(t *testing.T) {
	cs := &countingContentStore{inner: store.NewMemoryContentStore()}
	li := &countingLocationIndex{inner: store.NewMemoryLocationIndex()}

	idEnt, sigEnt, _, _ := buildIngestFixture(t)
	included := map[hash.Hash]entity.Entity{
		idEnt.ContentHash:  idEnt,
		sigEnt.ContentHash: sigEnt,
	}

	if err := IngestEnvelopeSignatures(cs, li, included); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	put1, set1 := cs.put.Load(), li.set.Load()
	if put1 == 0 || set1 == 0 {
		t.Fatalf("first ingest must Put + Set at least once: put=%d set=%d", put1, set1)
	}

	// Re-ingest the same envelope. Expected: zero new Puts, zero new Sets.
	if err := IngestEnvelopeSignatures(cs, li, included); err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if delta := cs.put.Load() - put1; delta != 0 {
		t.Errorf("re-ingest should not Put: got %d new Put calls", delta)
	}
	if delta := li.set.Load() - set1; delta != 0 {
		t.Errorf("re-ingest should not Set: got %d new Set calls", delta)
	}
}

// H-G3 fix A: when an identity entity is already present, ingest skips
// cs.Put on the first pass. Pins the Has-before-Put dedup for identities.
func TestHG3_IdentityAlreadyPresentSkipsPut(t *testing.T) {
	memCS := store.NewMemoryContentStore()
	cs := &countingContentStore{inner: memCS}
	li := &countingLocationIndex{inner: store.NewMemoryLocationIndex()}

	idEnt, _, _, _ := buildIngestFixture(t)
	// Pre-populate identity. cs.put counter is incremented by this call.
	if _, err := cs.Put(idEnt); err != nil {
		t.Fatal(err)
	}
	putAfterPrep := cs.put.Load()

	// Ingest envelope with only the identity (no signature).
	included := map[hash.Hash]entity.Entity{idEnt.ContentHash: idEnt}
	if err := IngestEnvelopeSignatures(cs, li, included); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if delta := cs.put.Load() - putAfterPrep; delta != 0 {
		t.Errorf("identity already present: expected 0 new Put, got %d", delta)
	}
}

// H-G3 fix A: a different signature for the same signer reuses the
// identity (no re-Put) but persists + binds the new signature.
func TestHG3_DifferentSignatureSameSignerReusesIdentity(t *testing.T) {
	cs := &countingContentStore{inner: store.NewMemoryContentStore()}
	li := &countingLocationIndex{inner: store.NewMemoryLocationIndex()}

	idEnt, sigA, _, _ := buildIngestFixture(t)

	// First ingest — both Put.
	if err := IngestEnvelopeSignatures(cs, li, map[hash.Hash]entity.Entity{
		idEnt.ContentHash: idEnt, sigA.ContentHash: sigA,
	}); err != nil {
		t.Fatal(err)
	}
	put1 := cs.put.Load()

	// Build a second signature for the SAME signer over a different target.
	idData, _ := types.PeerDataFromEntity(idEnt)
	_ = idData
	kp, _ := crypto.Generate()
	var target2 hash.Hash
	target2.Digest[0] = 0x22
	// We need the signature signer to match idEnt.ContentHash, so re-derive
	// the keypair-bound entity isn't possible from a different kp. Instead
	// build a sigEnt with a synthetic signer field that points at idEnt —
	// signer-field hash binds the lookup, signature content is opaque for
	// the ingest path.
	_ = kp
	sigB, err := types.SignatureData{
		Target:    target2,
		Signer:    idEnt.ContentHash,
		Algorithm: "ed25519",
		Signature: []byte{0xde, 0xad, 0xbe, 0xef}, // opaque — ingest doesn't verify
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	if err := IngestEnvelopeSignatures(cs, li, map[hash.Hash]entity.Entity{
		idEnt.ContentHash: idEnt, sigB.ContentHash: sigB,
	}); err != nil {
		t.Fatal(err)
	}
	put2 := cs.put.Load()

	// Identity skipped on second ingest (already present); new signature
	// persisted ⇒ exactly +1 Put.
	if delta := put2 - put1; delta != 1 {
		t.Errorf("expected exactly 1 new Put for new sig (identity reused), got %d", delta)
	}
}

// H-G3 fix B: NotifyingContentStore.Put on an already-stored hash skips
// inner.Put. Pins the short-circuit so the SQLite INSERT-OR-REPLACE
// round-trip is elided on duplicate Puts (the cross-peer ingest hot path).
func TestHG3_NotifyingContentStorePutShortCircuit(t *testing.T) {
	inner := &countingContentStore{inner: store.NewMemoryContentStore()}
	ncs := store.NewNotifyingContentStore(inner)

	idEnt, _, _, _ := buildIngestFixture(t)
	if _, err := ncs.Put(idEnt); err != nil {
		t.Fatal(err)
	}
	innerPut1 := inner.put.Load()
	if innerPut1 == 0 {
		t.Fatal("first ncs.Put must hit inner.Put once")
	}

	// Second Put of the same entity — inner.Put MUST NOT run again.
	if _, err := ncs.Put(idEnt); err != nil {
		t.Fatal(err)
	}
	if delta := inner.put.Load() - innerPut1; delta != 0 {
		t.Errorf("duplicate ncs.Put must short-circuit inner.Put; got %d additional inner.Put", delta)
	}
}
