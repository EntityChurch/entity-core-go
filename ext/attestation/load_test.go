package attestation

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestHandler_Load rebuilds the in-memory attestation index from existing
// tree state — the load-bearing recovery path for restart with persistent
// storage. See DESIGN-SQLITE-PERSISTENCE.md §4.3.
func TestHandler_Load(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// Seed two attestations into cs+li without going through the handler
	// (simulates state that survived a process restart).
	attesting := makeFakeHash(0x01)
	attested := makeFakeHash(0x02)
	a1 := makeAttestation(attesting, attested, "binding", nil)
	a2 := makeAttestation(attesting, makeFakeHash(0x03), "binding", nil)

	for i, att := range []types.AttestationData{a1, a2} {
		ent, err := att.ToEntity()
		if err != nil {
			t.Fatalf("attestation %d to entity: %v", i, err)
		}
		h, err := cs.Put(ent)
		if err != nil {
			t.Fatalf("put attestation %d: %v", i, err)
		}
		li.Set("/peer/system/attestation/abc/"+string(rune('a'+i)), h)
	}

	// Bind a non-attestation entity at another path; Load must skip it.
	other, _ := types.RoleData{Name: "noise"}.ToEntity()
	otherHash, _ := cs.Put(other)
	li.Set("/peer/system/role/def/role/noise", otherHash)

	// Fresh handler — pre-Load index is empty.
	h := NewHandler()
	h.SetupStore(cs, li, crypto.PeerID(""))
	if got := h.Index().FindByAttesting(attesting); len(got) != 0 {
		t.Fatalf("pre-load: expected empty index, got %d entries", len(got))
	}

	// Load.
	h.Load()

	// Both attestations indexed.
	got := h.Index().FindByAttesting(attesting)
	if len(got) != 2 {
		t.Fatalf("post-load FindByAttesting: got %d, want 2", len(got))
	}
	if k := h.Index().FindByKind("binding"); len(k) != 2 {
		t.Fatalf("post-load FindByKind(binding): got %d, want 2", len(k))
	}
}

// TestHandler_Load_NoStore is a no-op when SetupStore hasn't been called.
func TestHandler_Load_NoStore(t *testing.T) {
	h := NewHandler()
	h.Load() // must not panic
}
