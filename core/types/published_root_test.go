package types

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// fakeHash returns a deterministic hash.Hash for fixture use. Algorithm is
// SHA-256; digest is the lo byte repeated into the first slot then zero-padded.
func fakeHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

// fakePeerID returns a fixed Base58 peer-id for fixture use. Not a real
// peer-id (no cryptographic derivation); just a deterministic string so
// round-trip / hash-stability tests have something concrete to compare.
// The cross-impl cohort fixture peer-id lives in cmd/internal/validate.
const fakePeerID = "2KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestPublishedRootRoundtrip(t *testing.T) {
	predecessor := fakeHash(0x01)
	d := PublishedRootData{
		PeerID:      fakePeerID,
		RootHash:    fakeHash(0xBB),
		Seq:         42,
		PublishedAt: 1_730_000_000_000,
		Predecessor: &predecessor,
	}

	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypePeerPublishedRoot {
		t.Fatalf("entity type: want %s, got %s", TypePeerPublishedRoot, e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("entity hash validate: %v", err)
	}

	decoded, err := PublishedRootDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if decoded.PeerID != d.PeerID {
		t.Fatalf("PeerID drift: want %q got %q", d.PeerID, decoded.PeerID)
	}
	if decoded.RootHash != d.RootHash {
		t.Fatalf("RootHash drift")
	}
	if decoded.Seq != 42 {
		t.Fatalf("Seq: want 42 got %d", decoded.Seq)
	}
	if decoded.PublishedAt != 1_730_000_000_000 {
		t.Fatalf("PublishedAt drift: got %d", decoded.PublishedAt)
	}
	if decoded.Predecessor == nil {
		t.Fatal("Predecessor: lost on round-trip")
	}
	if !bytes.Equal(decoded.Predecessor.Bytes(), predecessor.Bytes()) {
		t.Fatalf("Predecessor drift")
	}
}

func TestPublishedRootNoPredecessor(t *testing.T) {
	// First published-root: no predecessor. ECF omitempty must drop the field
	// so first-root hashes do not collide with later-root null encodings.
	d := PublishedRootData{
		PeerID:      fakePeerID,
		RootHash:    fakeHash(0xBB),
		Seq:         1,
		PublishedAt: 1_730_000_000_000,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	decoded, err := PublishedRootDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if decoded.Predecessor != nil {
		t.Fatalf("Predecessor: expected nil, got %+v", decoded.Predecessor)
	}
}

func TestPublishedRootHashStability(t *testing.T) {
	// Same fields → same content_hash. Guards against accidental drift in
	// CBOR encoding options (must use ECF deterministic).
	d1 := PublishedRootData{
		PeerID:      fakePeerID,
		RootHash:    fakeHash(0x22),
		Seq:         7,
		PublishedAt: 1_700_000_000_000,
	}
	e1, _ := d1.ToEntity()
	d2 := PublishedRootData{
		PeerID:      fakePeerID,
		RootHash:    fakeHash(0x22),
		Seq:         7,
		PublishedAt: 1_700_000_000_000,
	}
	e2, _ := d2.ToEntity()
	if e1.ContentHash != e2.ContentHash {
		t.Fatalf("hash drift across equal inputs: %x vs %x",
			e1.ContentHash.Bytes(), e2.ContentHash.Bytes())
	}

	// Seq increments → different content_hash (no field collapse).
	d3 := d1
	d3.Seq = 8
	e3, _ := d3.ToEntity()
	if e1.ContentHash == e3.ContentHash {
		t.Fatal("hash collision across distinct Seq values")
	}
}

func TestPublishedRootStoragePath(t *testing.T) {
	got := PublishedRootStoragePath(fakePeerID)
	want := "system/peer/published-root/" + fakePeerID
	if got != want {
		t.Fatalf("path: want %q got %q", want, got)
	}
}

func TestPublishedRootRegistered(t *testing.T) {
	// Confirms RegisterCoreTypes wires the type into the registry so
	// validate / probe-peer see it as a first-class entity type.
	r := NewTypeRegistry()
	RegisterCoreTypes(r)
	def, ok := r.Get(TypePeerPublishedRoot)
	if !ok {
		t.Fatalf("type %q not registered", TypePeerPublishedRoot)
	}
	if def.Name != TypePeerPublishedRoot {
		t.Fatalf("registry name drift: %q", def.Name)
	}
	for _, f := range []string{"peer_id", "root_hash", "seq", "published_at"} {
		if _, ok := def.Fields[f]; !ok {
			t.Errorf("missing field %q in reflected definition", f)
		}
	}
	if fs, ok := def.Fields["predecessor"]; !ok || !fs.Optional {
		t.Errorf("predecessor must be present and optional, got %+v", fs)
	}
}
