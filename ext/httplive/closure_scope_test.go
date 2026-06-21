package httplive

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// TestClosureScope verifies the Amendment 10 served-set floor: a hash is in
// scope iff it is reachable from the published-root head (root entity,
// interior CHAMP nodes, leaf-bound values, plus the §5.2 signature pointer).
// Hashes outside the closure are not served — including ones in the same
// content-store but not bound under the head.
func TestClosureScope(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// Build a small trie of two leaf entities.
	leafA := mustPutEntity(t, cs, mustNewEntity(t, "test/leaf", "a"))
	leafB := mustPutEntity(t, cs, mustNewEntity(t, "test/leaf", "b"))
	rootHash, err := tree.BuildTrie(cs, []tree.Binding{
		{Path: "a", Hash: leafA},
		{Path: "b", Hash: leafB},
	})
	if err != nil {
		t.Fatalf("BuildTrie: %v", err)
	}

	const peerID = "peer-alpha"

	// Mint a published-root entity covering this trie root.
	pr := types.PublishedRootData{
		PeerID:      peerID,
		RootHash:    rootHash,
		Seq:         1,
		PublishedAt: 1,
	}
	prEnt, err := pr.ToEntity()
	if err != nil {
		t.Fatalf("PublishedRoot ToEntity: %v", err)
	}
	if _, err := cs.Put(prEnt); err != nil {
		t.Fatalf("Put publishedRoot: %v", err)
	}

	li.Set(types.PublishedRootStoragePath(peerID), prEnt.ContentHash)

	// Synthesize an "authenticating signature" leaf at the invariant pointer
	// so the closure also covers it.
	sigEnt := mustNewEntity(t, "test/sig", "sig-bytes")
	if _, err := cs.Put(sigEnt); err != nil {
		t.Fatalf("Put sig: %v", err)
	}
	li.Set(types.InvariantSignaturePath(peerID, prEnt.ContentHash), sigEnt.ContentHash)

	// An unrelated hash held by the content-store but NOT in the closure.
	stranger := mustPutEntity(t, cs, mustNewEntity(t, "test/leaf", "stranger"))

	scope := &ClosureScope{
		Store:       cs,
		Index:       li,
		LocalPeerID: peerID,
	}

	ctx := context.Background()

	check := func(name string, h hash.Hash, want bool) {
		t.Helper()
		got, err := scope.InScope(ctx, h)
		if err != nil {
			t.Fatalf("%s: InScope error: %v", name, err)
		}
		if got != want {
			t.Errorf("%s: InScope=%v, want %v", name, got, want)
		}
	}

	check("published-root head", prEnt.ContentHash, true)
	check("trie root node", rootHash, true)
	check("leaf A", leafA, true)
	check("leaf B", leafB, true)
	check("signature", sigEnt.ContentHash, true)
	check("stranger (not reachable)", stranger, false)
	check("zero hash", hash.Hash{}, false)
}

func TestClosureScope_NothingPublished(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	leaf := mustPutEntity(t, cs, mustNewEntity(t, "test/leaf", "leaf"))
	scope := &ClosureScope{
		Store:       cs,
		Index:       li,
		LocalPeerID: "peer-empty",
	}

	got, err := scope.InScope(context.Background(), leaf)
	if err != nil {
		t.Fatalf("InScope: %v", err)
	}
	if got {
		t.Errorf("expected nothing-published peer to serve nothing, but leaf was in scope")
	}
}

func mustPutEntity(t *testing.T, cs store.ContentStore, e entity.Entity) hash.Hash {
	t.Helper()
	if _, err := cs.Put(e); err != nil {
		t.Fatalf("Put entity: %v", err)
	}
	return e.ContentHash
}

func mustNewEntity(t *testing.T, typeName, payload string) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(payload)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	e, err := entity.NewEntity(typeName, cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	return e
}
