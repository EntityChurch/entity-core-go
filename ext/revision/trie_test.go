package revision

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// --- P2: Trie Determinism ---

func TestTrieDeterminism_SameBindings_SameRoot(t *testing.T) {
	// Two independent content stores, same bindings → same root hash.
	// Under v4.0 HAMT + CHAMP this is the cross-impl convergence anchor.
	csA := store.NewMemoryContentStore()
	csB := store.NewMemoryContentStore()

	hashR := storeTestEntity(t, csA, "app/doc", map[string]string{"title": "readme"})
	storeTestEntity(t, csB, "app/doc", map[string]string{"title": "readme"})
	hashM := storeTestEntity(t, csA, "app/doc", map[string]string{"title": "main"})
	storeTestEntity(t, csB, "app/doc", map[string]string{"title": "main"})
	hashC := storeTestEntity(t, csA, "app/doc", map[string]string{"title": "config"})
	storeTestEntity(t, csB, "app/doc", map[string]string{"title": "config"})

	bindings := []tree.Binding{
		{Path: "data/readme", Hash: hashR},
		{Path: "data/src/main", Hash: hashM},
		{Path: "config", Hash: hashC},
	}

	rootA, err := tree.BuildTrie(csA, bindings)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := tree.BuildTrie(csB, bindings)
	if err != nil {
		t.Fatal(err)
	}

	if rootA != rootB {
		t.Fatalf("trie determinism failed: rootA=%v rootB=%v", rootA, rootB)
	}
}

func TestTrieDeterminism_DifferentBindingOrder(t *testing.T) {
	// Same bindings in different order → same root hash. CHAMP-canonical
	// form guarantees permutation-invariance.
	cs := store.NewMemoryContentStore()

	hashA := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	hashB := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})
	hashC := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "c"})

	root1, err := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x/a", Hash: hashA},
		{Path: "x/b", Hash: hashB},
		{Path: "y", Hash: hashC},
	})
	if err != nil {
		t.Fatal(err)
	}

	root2, err := tree.BuildTrie(cs, []tree.Binding{
		{Path: "y", Hash: hashC},
		{Path: "x/b", Hash: hashB},
		{Path: "x/a", Hash: hashA},
	})
	if err != nil {
		t.Fatal(err)
	}

	if root1 != root2 {
		t.Fatalf("binding order should not affect root hash: root1=%v root2=%v", root1, root2)
	}
}

func TestTrieDeterminism_RepeatedBuild(t *testing.T) {
	// Building the same trie twice on the same store produces identical root.
	cs := store.NewMemoryContentStore()
	hashR := storeTestEntity(t, cs, "app/doc", map[string]string{"x": "y"})

	bindings := []tree.Binding{
		{Path: "a/b/c", Hash: hashR},
		{Path: "a/b/d", Hash: hashR},
		{Path: "a/e", Hash: hashR},
	}

	root1, _ := tree.BuildTrie(cs, bindings)
	root2, _ := tree.BuildTrie(cs, bindings)

	if root1 != root2 {
		t.Fatal("repeated build should produce identical root")
	}
}

func TestTrieEmptyCanonical(t *testing.T) {
	// Empty bindings on two stores → identical canonical empty-root.
	csA := store.NewMemoryContentStore()
	csB := store.NewMemoryContentStore()

	rootA, err := tree.BuildTrie(csA, nil)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := tree.BuildTrie(csB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rootA != rootB {
		t.Fatalf("empty roots differ: %v vs %v", rootA, rootB)
	}
}

// --- Round-Trip ---

func TestTrieRoundTrip_CollectAllBindings(t *testing.T) {
	cs := store.NewMemoryContentStore()
	hashA := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	hashB := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})
	hashC := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "c"})

	original := []tree.Binding{
		{Path: "x/a", Hash: hashA},
		{Path: "x/b", Hash: hashB},
		{Path: "y/z", Hash: hashC},
	}

	root, err := tree.BuildTrie(cs, original)
	if err != nil {
		t.Fatal(err)
	}

	recovered := tree.CollectAllBindings(cs, root, "")
	if len(recovered) != len(original) {
		t.Fatalf("expected %d bindings, got %d", len(original), len(recovered))
	}
	for _, b := range original {
		got, ok := recovered[b.Path]
		if !ok {
			t.Fatalf("missing binding for path %q", b.Path)
		}
		if got != b.Hash {
			t.Fatalf("hash mismatch for path %q", b.Path)
		}
	}
}

func TestTrieRoundTrip_DeepPaths(t *testing.T) {
	// Deep relative_key round-trip — under hash-keyed routing the key's
	// internal "/" boundaries are not interpreted, only used in SHA-256.
	cs := store.NewMemoryContentStore()
	hashR := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "r"})

	bindings := []tree.Binding{
		{Path: "a/b/c/d/e", Hash: hashR},
	}

	root, _ := tree.BuildTrie(cs, bindings)
	recovered := tree.CollectAllBindings(cs, root, "")

	if len(recovered) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(recovered))
	}
	if recovered["a/b/c/d/e"] != hashR {
		t.Fatal("deep path round-trip failed")
	}
}

// --- P4: Version Entry Determinism ---

func TestVersionEntryDeterminism(t *testing.T) {
	// Same root + same parents → same version hash on independent stores.
	csA := store.NewMemoryContentStore()
	csB := store.NewMemoryContentStore()

	hashR := storeTestEntity(t, csA, "app/doc", map[string]string{"x": "y"})
	storeTestEntity(t, csB, "app/doc", map[string]string{"x": "y"})

	trieRoot, _ := tree.BuildTrie(csA, []tree.Binding{{Path: "data/file", Hash: hashR}})
	tree.BuildTrie(csB, []tree.Binding{{Path: "data/file", Hash: hashR}})

	parent1 := storeVersionEntry(t, csA, hash.Hash{}, nil)
	storeVersionEntry(t, csB, hash.Hash{}, nil)

	parent2 := storeVersionEntry(t, csA, hash.Hash{}, nil)
	storeVersionEntry(t, csB, hash.Hash{}, nil)

	versionA := storeVersionEntry(t, csA, trieRoot, []hash.Hash{parent2, parent1})
	versionB := storeVersionEntry(t, csB, trieRoot, []hash.Hash{parent1, parent2})

	if versionA != versionB {
		t.Fatalf("version entry determinism failed: A=%v B=%v", versionA, versionB)
	}
}

// --- SortedParents ---

func TestSortedParents_Order(t *testing.T) {
	h1 := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}
	h2 := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x02})}
	h3 := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x03})}

	sorted1 := tree.SortedParents([]hash.Hash{h3, h1, h2})
	sorted2 := tree.SortedParents([]hash.Hash{h2, h3, h1})
	sorted3 := tree.SortedParents([]hash.Hash{h1, h2, h3})

	for i := 0; i < 3; i++ {
		if sorted1[i] != sorted2[i] || sorted2[i] != sorted3[i] {
			t.Fatalf("sortedParents not deterministic at index %d", i)
		}
	}

	if sorted1[0] != h1 || sorted1[1] != h2 || sorted1[2] != h3 {
		t.Fatal("sortedParents should sort ascending by binary comparison")
	}
}

func TestSortedParents_Single(t *testing.T) {
	h := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x42})}
	sorted := tree.SortedParents([]hash.Hash{h})
	if len(sorted) != 1 || sorted[0] != h {
		t.Fatal("single parent should pass through unchanged")
	}
}

func TestSortedParents_Empty(t *testing.T) {
	sorted := tree.SortedParents(nil)
	if len(sorted) != 0 {
		t.Fatal("nil parents should return empty")
	}
}

// --- helpers ---

func storeVersionEntry(t *testing.T, cs store.ContentStore, root hash.Hash, parents []hash.Hash) hash.Hash {
	t.Helper()
	version := types.RevisionEntryData{
		Root:    root,
		Parents: tree.SortedParents(parents),
	}
	ent, err := version.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
