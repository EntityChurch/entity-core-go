package tree

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/store"
)

// TestBuildTrieForPrefix_ParityWithBuildTrie confirms that driving trie
// construction through the location-index helper yields the same root hash as
// calling BuildTrie directly on the same bindings. This is the guardrail any
// future O(depth) incremental implementation must keep passing.
func TestBuildTrieForPrefix_ParityWithBuildTrie(t *testing.T) {
	r := rand.New(rand.NewSource(0xC0FFEE))
	for trial := 0; trial < 20; trial++ {
		cs := store.NewMemoryContentStore()
		rawLI := store.NewMemoryLocationIndex()
		kp, _ := crypto.Generate()
		li := store.NewNamespacedIndex(rawLI, string(kp.PeerID()))

		prefix := "project/"
		n := 1 + r.Intn(40)
		bindings := make([]Binding, 0, n)
		seen := map[string]bool{}
		for i := 0; i < n; i++ {
			depth := 1 + r.Intn(4)
			segs := make([]string, depth)
			for d := range segs {
				segs[d] = fmt.Sprintf("s%d", r.Intn(6))
			}
			key := joinSegs(segs)
			if seen[key] {
				continue
			}
			seen[key] = true
			e := makeEntity(t, "test/b", map[string]int{"i": i})
			cs.Put(e)
			li.Set(prefix+key, e.ContentHash)
			bindings = append(bindings, Binding{Path: key, Hash: e.ContentHash})
		}

		sort.Slice(bindings, func(i, j int) bool { return bindings[i].Path < bindings[j].Path })

		directRoot, err := BuildTrie(cs, bindings)
		if err != nil {
			t.Fatalf("trial %d: BuildTrie: %v", trial, err)
		}
		indirectRoot, err := BuildTrieForPrefix(cs, li, kp.PeerID(), prefix)
		if err != nil {
			t.Fatalf("trial %d: BuildTrieForPrefix: %v", trial, err)
		}
		if directRoot != indirectRoot {
			t.Fatalf("trial %d: root mismatch\n  BuildTrie         = %s\n  BuildTrieForPrefix = %s",
				trial, directRoot.String(), indirectRoot.String())
		}
	}
}

// TestBuildTrieForPrefix_StabilityThroughMutations asserts the deterministic
// property that matters for interop: same binding set → same root hash,
// regardless of insertion / removal order.
func TestBuildTrieForPrefix_StabilityThroughMutations(t *testing.T) {
	cs := store.NewMemoryContentStore()
	rawLI := store.NewMemoryLocationIndex()
	kp, _ := crypto.Generate()
	li := store.NewNamespacedIndex(rawLI, string(kp.PeerID()))

	prefix := "project/"

	seed := func(keys []string) {
		for _, k := range keys {
			e := makeEntity(t, "test/b", k)
			cs.Put(e)
			li.Set(prefix+k, e.ContentHash)
		}
	}

	seed([]string{"src/a.go", "src/b.go", "docs/r.md"})
	root1, err := BuildTrieForPrefix(cs, li, kp.PeerID(), prefix)
	if err != nil {
		t.Fatal(err)
	}

	// Remove one and re-add it.
	li.Remove(prefix + "src/a.go")
	e := makeEntity(t, "test/b", "src/a.go")
	cs.Put(e)
	li.Set(prefix+"src/a.go", e.ContentHash)

	root2, err := BuildTrieForPrefix(cs, li, kp.PeerID(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	if root1 != root2 {
		t.Fatalf("root must be stable across remove+re-add of same binding: %s vs %s",
			root1.String(), root2.String())
	}
}

func joinSegs(segs []string) string {
	out := ""
	for i, s := range segs {
		if i > 0 {
			out += "/"
		}
		out += s
	}
	return out
}
