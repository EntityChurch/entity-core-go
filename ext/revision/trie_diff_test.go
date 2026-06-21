package revision

import (
	"math/rand"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
)

func TestTrieDiff_Identical(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})

	root, err := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x/a", Hash: h1},
		{Path: "x/b", Hash: h2},
		{Path: "y", Hash: h1},
	})
	if err != nil {
		t.Fatal(err)
	}

	added, removed, changed, unchanged := tree.TrieDiff(cs, root, root)

	if len(added) != 0 {
		t.Fatalf("expected 0 added, got %d", len(added))
	}
	if len(removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(removed))
	}
	if len(changed) != 0 {
		t.Fatalf("expected 0 changed, got %d", len(changed))
	}
	if unchanged != 3 {
		t.Fatalf("expected 3 unchanged, got %d", unchanged)
	}
}

func TestTrieDiff_SingleAdd(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})

	rootA, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x/a", Hash: h1},
	})
	rootB, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x/a", Hash: h1},
		{Path: "x/b", Hash: h2},
	})

	added, removed, changed, unchanged := tree.TrieDiff(cs, rootA, rootB)

	if len(added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(added))
	}
	if added["x/b"] != h2 {
		t.Fatal("added path should be x/b")
	}
	if len(removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(removed))
	}
	if len(changed) != 0 {
		t.Fatalf("expected 0 changed, got %d", len(changed))
	}
	if unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", unchanged)
	}
}

func TestTrieDiff_SingleRemove(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})

	rootA, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x/a", Hash: h1},
		{Path: "x/b", Hash: h2},
	})
	rootB, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x/a", Hash: h1},
	})

	added, removed, changed, unchanged := tree.TrieDiff(cs, rootA, rootB)

	if len(added) != 0 {
		t.Fatalf("expected 0 added, got %d", len(added))
	}
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(removed))
	}
	if removed["x/b"] != h2 {
		t.Fatal("removed path should be x/b")
	}
	if len(changed) != 0 {
		t.Fatalf("expected 0 changed, got %d", len(changed))
	}
	if unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", unchanged)
	}
}

func TestTrieDiff_SingleChange(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})
	h3 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "c"})

	rootA, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x/a", Hash: h1},
		{Path: "y", Hash: h2},
	})
	rootB, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x/a", Hash: h1},
		{Path: "y", Hash: h3},
	})

	added, removed, changed, unchanged := tree.TrieDiff(cs, rootA, rootB)

	if len(added) != 0 {
		t.Fatalf("expected 0 added, got %d", len(added))
	}
	if len(removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(removed))
	}
	if len(changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(changed))
	}
	ch, ok := changed["y"]
	if !ok {
		t.Fatal("expected changed path y")
	}
	if ch.BaseHash != h2 || ch.TargetHash != h3 {
		t.Fatal("changed hashes mismatch")
	}
	if unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", unchanged)
	}
}

func TestTrieDiff_SubtreeSkip(t *testing.T) {
	// Large unchanged subtree should be skipped efficiently.
	cs := store.NewMemoryContentStore()
	var sharedBindings []tree.Binding
	for i := 0; i < 100; i++ {
		h := storeTestEntity(t, cs, "app/doc", map[string]string{
			"idx": string(rune('a' + (i % 26))),
			"num": string(rune('0' + (i % 10))),
		})
		path := "shared/" + string(rune('a'+(i/26))) + "/" + string(rune('a'+(i%26)))
		sharedBindings = append(sharedBindings, tree.Binding{Path: path, Hash: h})
	}

	hNew := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "new"})

	bindingsA := make([]tree.Binding, len(sharedBindings))
	copy(bindingsA, sharedBindings)

	bindingsB := make([]tree.Binding, len(sharedBindings))
	copy(bindingsB, sharedBindings)
	bindingsB = append(bindingsB, tree.Binding{Path: "other/new", Hash: hNew})

	rootA, _ := tree.BuildTrie(cs, bindingsA)
	rootB, _ := tree.BuildTrie(cs, bindingsB)

	added, removed, changed, unchanged := tree.TrieDiff(cs, rootA, rootB)

	if len(added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(added))
	}
	if len(removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(removed))
	}
	if len(changed) != 0 {
		t.Fatalf("expected 0 changed, got %d", len(changed))
	}
	if unchanged != 100 {
		t.Fatalf("expected 100 unchanged, got %d", unchanged)
	}
}

func TestTrieDiff_CompressionMismatch(t *testing.T) {
	// Different compression structures should still produce correct diff.
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})

	// A has single deep path (fully compressed): "a/b/c" → h1
	rootA, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "a/b/c", Hash: h1},
	})
	// B has two paths under a/b, breaking compression: "a/b/c" → h1, "a/b/d" → h2
	rootB, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "a/b/c", Hash: h1},
		{Path: "a/b/d", Hash: h2},
	})

	added, removed, changed, unchanged := tree.TrieDiff(cs, rootA, rootB)

	if len(added) != 1 {
		t.Fatalf("expected 1 added, got %d: %v", len(added), added)
	}
	if added["a/b/d"] != h2 {
		t.Fatal("expected added a/b/d")
	}
	if len(removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(removed))
	}
	if len(changed) != 0 {
		t.Fatalf("expected 0 changed, got %d", len(changed))
	}
	if unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", unchanged)
	}
}

func TestTrieDiff_EmptyToPopulated(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})

	rootEmpty, _ := tree.BuildTrie(cs, nil)
	rootPop, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "x", Hash: h1},
	})

	added, removed, _, _ := tree.TrieDiff(cs, rootEmpty, rootPop)
	if len(added) != 1 || added["x"] != h1 {
		t.Fatal("expected x added")
	}
	if len(removed) != 0 {
		t.Fatal("expected nothing removed")
	}

	// Reverse direction.
	added2, removed2, _, _ := tree.TrieDiff(cs, rootPop, rootEmpty)
	if len(removed2) != 1 || removed2["x"] != h1 {
		t.Fatal("expected x removed")
	}
	if len(added2) != 0 {
		t.Fatal("expected nothing added")
	}
}

func TestTrieDiff_DeepCompressionMismatch(t *testing.T) {
	// A: "a/b/c/d" (fully compressed) → h1
	// B: "a/b/x"   (fully compressed) → h2
	// Different paths diverge at "a/b".
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})

	rootA, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "a/b/c/d", Hash: h1},
	})
	rootB, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "a/b/x", Hash: h2},
	})

	added, removed, changed, unchanged := tree.TrieDiff(cs, rootA, rootB)

	if len(removed) != 1 || removed["a/b/c/d"] != h1 {
		t.Fatalf("expected a/b/c/d removed, got removed=%v", removed)
	}
	if len(added) != 1 || added["a/b/x"] != h2 {
		t.Fatalf("expected a/b/x added, got added=%v", added)
	}
	if len(changed) != 0 {
		t.Fatalf("expected 0 changed, got %d", len(changed))
	}
	if unchanged != 0 {
		t.Fatalf("expected 0 unchanged, got %d", unchanged)
	}
}

func TestTrieDiff_EntireSubtreeRemoved(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "a"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "b"})
	h3 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "c"})

	rootA, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "data/x", Hash: h1},
		{Path: "data/y", Hash: h2},
		{Path: "other", Hash: h3},
	})
	// Remove entire "data" subtree.
	rootB, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "other", Hash: h3},
	})

	added, removed, changed, unchanged := tree.TrieDiff(cs, rootA, rootB)

	if len(added) != 0 {
		t.Fatalf("expected 0 added, got %d", len(added))
	}
	if len(removed) != 2 {
		t.Fatalf("expected 2 removed, got %d: %v", len(removed), removed)
	}
	if removed["data/x"] != h1 || removed["data/y"] != h2 {
		t.Fatal("removed hashes mismatch")
	}
	if len(changed) != 0 {
		t.Fatalf("expected 0 changed, got %d", len(changed))
	}
	if unchanged != 1 {
		t.Fatalf("expected 1 unchanged (other), got %d", unchanged)
	}
}

func TestTrieDiff_MixedAddRemoveChange(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h1 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "v1"})
	h2 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "v2"})
	h3 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "v3"})
	h4 := storeTestEntity(t, cs, "app/doc", map[string]string{"k": "v4"})

	rootA, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "keep", Hash: h1},
		{Path: "modify", Hash: h2},
		{Path: "remove", Hash: h3},
	})
	rootB, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "keep", Hash: h1},
		{Path: "modify", Hash: h4},
		{Path: "add", Hash: h3},
	})

	added, removed, changed, unchanged := tree.TrieDiff(cs, rootA, rootB)

	if len(added) != 1 || added["add"] != h3 {
		t.Fatal("expected add=h3")
	}
	if len(removed) != 1 || removed["remove"] != h3 {
		t.Fatal("expected remove=h3")
	}
	if len(changed) != 1 {
		t.Fatal("expected 1 changed")
	}
	if changed["modify"].BaseHash != h2 || changed["modify"].TargetHash != h4 {
		t.Fatal("changed hashes wrong")
	}
	if unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", unchanged)
	}
}

func TestTrieDiff_MatchesFlatDiff(t *testing.T) {
	// Compare recursive diff against flat diff for random binding sets.
	cs := store.NewMemoryContentStore()
	rng := rand.New(rand.NewSource(42))

	paths := []string{
		"a", "a/b", "a/b/c", "a/b/d", "a/e",
		"b", "b/x", "b/x/y", "c/d/e/f",
		"data/readme", "data/src/main", "config",
	}

	for trial := 0; trial < 10; trial++ {
		var bindingsA, bindingsB []tree.Binding
		for _, p := range paths {
			if rng.Float64() < 0.7 {
				h := storeTestEntity(t, cs, "app/doc", map[string]interface{}{"trial": trial, "path": p, "side": "a", "r": rng.Int()})
				bindingsA = append(bindingsA, tree.Binding{Path: p, Hash: h})
			}
			if rng.Float64() < 0.7 {
				h := storeTestEntity(t, cs, "app/doc", map[string]interface{}{"trial": trial, "path": p, "side": "b", "r": rng.Int()})
				bindingsB = append(bindingsB, tree.Binding{Path: p, Hash: h})
			}
		}

		rootA, _ := tree.BuildTrie(cs, bindingsA)
		rootB, _ := tree.BuildTrie(cs, bindingsB)

		// Recursive diff.
		rAdded, rRemoved, rChanged, rUnchanged := tree.TrieDiff(cs, rootA, rootB)

		// Flat diff.
		flatA := trieToBindings(cs, rootA)
		flatB := trieToBindings(cs, rootB)
		fAdded := make(map[string]hash.Hash)
		fRemoved := make(map[string]hash.Hash)
		fChanged := make(map[string][2]hash.Hash)
		var fUnchanged uint64
		for p, hB := range flatB {
			hA, inA := flatA[p]
			if !inA {
				fAdded[p] = hB
			} else if hA != hB {
				fChanged[p] = [2]hash.Hash{hA, hB}
			} else {
				fUnchanged++
			}
		}
		for p, hA := range flatA {
			if _, inB := flatB[p]; !inB {
				fRemoved[p] = hA
			}
		}

		// Compare.
		if len(rAdded) != len(fAdded) {
			t.Fatalf("trial %d: added count mismatch: recursive=%d flat=%d", trial, len(rAdded), len(fAdded))
		}
		for p, h := range fAdded {
			if rAdded[p] != h {
				t.Fatalf("trial %d: added hash mismatch at %s", trial, p)
			}
		}
		if len(rRemoved) != len(fRemoved) {
			t.Fatalf("trial %d: removed count mismatch: recursive=%d flat=%d", trial, len(rRemoved), len(fRemoved))
		}
		for p, h := range fRemoved {
			if rRemoved[p] != h {
				t.Fatalf("trial %d: removed hash mismatch at %s", trial, p)
			}
		}
		if len(rChanged) != len(fChanged) {
			t.Fatalf("trial %d: changed count mismatch: recursive=%d flat=%d", trial, len(rChanged), len(fChanged))
		}
		for p, hPair := range fChanged {
			rc, ok := rChanged[p]
			if !ok {
				t.Fatalf("trial %d: missing changed path %s in recursive", trial, p)
			}
			if rc.BaseHash != hPair[0] || rc.TargetHash != hPair[1] {
				t.Fatalf("trial %d: changed hash mismatch at %s", trial, p)
			}
		}
		if rUnchanged != fUnchanged {
			t.Fatalf("trial %d: unchanged count mismatch: recursive=%d flat=%d", trial, rUnchanged, fUnchanged)
		}
	}
}
