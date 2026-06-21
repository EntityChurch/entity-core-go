package tree

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
)

// snapshotBindings is the canonical reference: it asks BuildTrie to produce
// the root from the live binding set. Any incremental update MUST equal
// this hash (EXTENSION-TREE v3.15 §3.4 byte-identical-output invariant).
func snapshotBindings(t *testing.T, cs store.ContentStore, all map[string]hash.Hash) hash.Hash {
	t.Helper()
	bindings := make([]Binding, 0, len(all))
	for path, h := range all {
		bindings = append(bindings, Binding{Path: path, Hash: h})
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Path < bindings[j].Path })
	root, err := BuildTrie(cs, bindings)
	if err != nil {
		t.Fatalf("BuildTrie: %v", err)
	}
	return root
}

// TestTriePut_MatchesBuildTrie_HandCrafted exercises every case of the
// descent (no match / exact / prefix / split) in deterministic order so a
// regression in any single branch produces an unambiguous failure.
func TestTriePut_MatchesBuildTrie_HandCrafted(t *testing.T) {
	cs := store.NewMemoryContentStore()

	puts := []string{
		// Case: no match — insert into empty root.
		"a/b/c/d",
		// Case: diverge — splits "a/b/c/d" into "a/b" → {"c/d": old, "e": new}.
		"a/b/e",
		// Case: prefix-of-key (remaining shorter than existing key) — bind at "a/b".
		"a/b",
		// Case: key-prefix-of-remaining — recurse into existing "a/b" with rest "c/d/f".
		"a/b/c/d/f",
		// Case: exact — re-bind "a/b" to a new value (rebind).
		"a/b",
		// Case: brand-new branch under root.
		"x/y/z",
	}

	values := map[string]hash.Hash{}
	root := hash.Hash{}
	for i, p := range puts {
		v := hashWithFirstByte(byte(i) + 1)
		var err error
		root, err = TriePut(cs, root, p, v)
		if err != nil {
			t.Fatalf("TriePut %q: %v", p, err)
		}
		values[p] = v
		expected := snapshotBindings(t, cs, values)
		if root != expected {
			t.Fatalf("after step %d (put %q): incremental=%s expected=%s", i, p, root, expected)
		}
	}
}

// TestTrieRemove_MatchesBuildTrie_HandCrafted exercises remove's reverse
// cases: clear-binding-no-merge, empty-child-prune, single-entry-merge
// via compression.
func TestTrieRemove_MatchesBuildTrie_HandCrafted(t *testing.T) {
	cs := store.NewMemoryContentStore()

	// Build the trie via TriePut so we share that surface; equivalent to
	// BuildTrie on the same set if TriePut is correct.
	puts := []string{"a/b/c", "a/b/d", "a/e", "x/y/z"}
	values := map[string]hash.Hash{}
	root := hash.Hash{}
	for i, p := range puts {
		v := hashWithFirstByte(byte(i) + 1)
		var err error
		root, err = TriePut(cs, root, p, v)
		if err != nil {
			t.Fatal(err)
		}
		values[p] = v
	}
	if got := snapshotBindings(t, cs, values); got != root {
		t.Fatalf("setup divergence: incremental=%s expected=%s", root, got)
	}

	// Remove "x/y/z" — whole branch should disappear.
	root, err := TrieRemove(cs, root, "x/y/z")
	if err != nil {
		t.Fatal(err)
	}
	delete(values, "x/y/z")
	if got := snapshotBindings(t, cs, values); got != root {
		t.Fatalf("after remove x/y/z: incremental=%s expected=%s", root, got)
	}

	// Remove "a/b/c" — "a/b" used to point at a node with {c, d}; after
	// removal it's single-child {d} → CompressEntry must collapse "a/b/d".
	root, err = TrieRemove(cs, root, "a/b/c")
	if err != nil {
		t.Fatal(err)
	}
	delete(values, "a/b/c")
	if got := snapshotBindings(t, cs, values); got != root {
		t.Fatalf("after remove a/b/c (compression-on-delete): incremental=%s expected=%s", root, got)
	}

	// Remove a missing path — no-op, root unchanged.
	rootBefore := root
	root, err = TrieRemove(cs, root, "not/here")
	if err != nil {
		t.Fatal(err)
	}
	if root != rootBefore {
		t.Fatalf("remove-of-absent should be no-op: before=%s after=%s", rootBefore, root)
	}

	// Remove remaining; final state = empty trie.
	for _, p := range []string{"a/b/d", "a/e"} {
		root, err = TrieRemove(cs, root, p)
		if err != nil {
			t.Fatal(err)
		}
		delete(values, p)
		if got := snapshotBindings(t, cs, values); got != root {
			t.Fatalf("after remove %s: incremental=%s expected=%s", p, root, got)
		}
	}
}

// TestTriePutRemove_Fuzz drives random Put/Remove sequences and asserts
// the incremental root equals BuildTrie(full_bindings) after EVERY step.
// This is the spec's normative byte-identical-output check.
func TestTriePutRemove_Fuzz(t *testing.T) {
	r := rand.New(rand.NewSource(0xCAFEBABE))
	const trials = 30
	const stepsPerTrial = 80

	for trial := 0; trial < trials; trial++ {
		cs := store.NewMemoryContentStore()
		root := hash.Hash{}
		values := map[string]hash.Hash{}

		// Pool of paths likely to share prefixes — drives the
		// split/compress branches.
		segPool := []string{"a", "b", "c", "d", "e", "f", "g"}
		makePath := func() string {
			depth := 1 + r.Intn(4)
			segs := make([]string, depth)
			for d := range segs {
				segs[d] = segPool[r.Intn(len(segPool))]
			}
			return joinSegs(segs)
		}

		for step := 0; step < stepsPerTrial; step++ {
			// Bias to Put while small; once bindings accumulate, mix in removes.
			doRemove := len(values) > 0 && r.Intn(3) == 0
			if doRemove {
				// Pick a random present key.
				keys := make([]string, 0, len(values))
				for k := range values {
					keys = append(keys, k)
				}
				p := keys[r.Intn(len(keys))]
				var err error
				root, err = TrieRemove(cs, root, p)
				if err != nil {
					t.Fatalf("trial %d step %d: TrieRemove %q: %v", trial, step, p, err)
				}
				delete(values, p)
			} else {
				p := makePath()
				v := hashWithFirstByte(byte(step + 1))
				var err error
				root, err = TriePut(cs, root, p, v)
				if err != nil {
					t.Fatalf("trial %d step %d: TriePut %q: %v", trial, step, p, err)
				}
				values[p] = v
			}

			expected := snapshotBindings(t, cs, values)
			if root != expected {
				t.Fatalf("trial %d step %d: incremental=%s expected=%s bindings=%v",
					trial, step, root, expected, sortedKeys(values))
			}
		}
	}
}

// TestTriePut_RootLevelBinding pins the empty-relPath case: a binding
// at the prefix root itself (the trie's root node carries Binding).
func TestTriePut_RootLevelBinding(t *testing.T) {
	cs := store.NewMemoryContentStore()
	root := hash.Hash{}
	v := hashWithFirstByte(0x42)
	root, err := TriePut(cs, root, "", v)
	if err != nil {
		t.Fatal(err)
	}
	expected := snapshotBindings(t, cs, map[string]hash.Hash{"": v})
	if root != expected {
		t.Fatalf("root-binding: incremental=%s expected=%s", root, expected)
	}

	// Add a regular child + assert the root binding remains.
	v2 := hashWithFirstByte(0x43)
	root, err = TriePut(cs, root, "a/b", v2)
	if err != nil {
		t.Fatal(err)
	}
	expected = snapshotBindings(t, cs, map[string]hash.Hash{"": v, "a/b": v2})
	if root != expected {
		t.Fatalf("root-binding + child: incremental=%s expected=%s", root, expected)
	}
}

// hashWithFirstByte produces a stable, distinct hash by varying the first
// digest byte — sufficient for tests since the trie treats hash values as
// opaque content references.
func hashWithFirstByte(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = 0x00
	h.Digest[0] = b
	return h
}

func sortedKeys(m map[string]hash.Hash) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Silence "unused" if other helpers go away.
var _ = fmt.Sprintf
