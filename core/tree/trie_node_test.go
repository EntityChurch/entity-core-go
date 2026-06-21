package tree

import (
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
)

// TestEmptyRootLiteralHex pins the canonical empty-root node CBOR encoding
// per EXTENSION-TREE v4.0 §3.1 conformance fixture #1:
//
//	A2 63 6D6170 44 00000000 64 64617461 80
//
// Bytewise byte-identical-output is the cross-impl convergence guarantee.
// Any deviation here means the wire format diverged from spec.
func TestEmptyRootLiteralHex(t *testing.T) {
	raw, err := ecf.Encode(EmptyNode())
	if err != nil {
		t.Fatalf("encode empty node: %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(raw))
	want := "A2636D617044000000006464617461" + "80"
	if got != want {
		t.Fatalf("empty-root CBOR mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestSingleBindingEmptyKeyLiteralHex pins the canonical 1-binding root
// node for relative_key="" with a fixed value_hash per EXTENSION-TREE
// v4.0 §3.1 conformance fixture #2:
//
//	A2 63 6D6170 44 10000000 64 64617461 81 81 82 60 58 21 <H>
//
// SHA-256("") = e3b0c4... → top 5 bits = 0b11100 = 28 → bit 28 → bitmap
// 0x10000000 big-endian "10 00 00 00". This is the canonical fuzzer seed
// for SHA-256-input ambiguity (relative-key vs absolute-path) and
// bitmap-convention ambiguity (LSB-indexed integer, big-endian byte order).
func TestSingleBindingEmptyKeyLiteralHex(t *testing.T) {
	// Construct a deterministic value hash: algorithm 0x00 + 32 bytes 0xAA.
	var digest [32]byte
	for i := range digest {
		digest[i] = 0xAA
	}
	valueHash := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest(digest)}

	cs := store.NewMemoryContentStore()
	rootHash, err := BuildTrie(cs, []Binding{{Path: "", Hash: valueHash}})
	if err != nil {
		t.Fatalf("BuildTrie: %v", err)
	}

	// Read the resulting node entity and verify its data CBOR matches the spec.
	ent, ok := cs.Get(rootHash)
	if !ok {
		t.Fatalf("root entity not stored")
	}
	got := strings.ToUpper(hex.EncodeToString(ent.Data))

	wantPrefix := "A2636D6170441000000064646174618181826058" + "21" + "00"
	wantHexValue := strings.ToUpper(hex.EncodeToString(valueHash.Bytes()))
	want := wantPrefix + strings.TrimPrefix(wantHexValue, "00") // value's algo byte already in wantPrefix

	if got != want {
		t.Fatalf("single-binding CBOR mismatch\n got: %s\nwant: %s", got, want)
	}

	// Sanity: SHA-256("") first 5 bits = 28.
	h := HashKey("")
	if HashSlice(h, 0) != 28 {
		t.Fatalf("HashSlice(SHA256(\"\"), 0) = %d, want 28", HashSlice(h, 0))
	}
}

// TestSingleBindingHashRecorded verifies that the hash recorded matches a
// canonical recomputation — independent confirmation that the entity's
// content hash is anchored.
func TestSingleBindingHashRecorded(t *testing.T) {
	var digest [32]byte
	for i := range digest {
		digest[i] = 0xAA
	}
	valueHash := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest(digest)}

	cs := store.NewMemoryContentStore()
	got, err := BuildTrie(cs, []Binding{{Path: "", Hash: valueHash}})
	if err != nil {
		t.Fatalf("BuildTrie: %v", err)
	}

	ent, ok := cs.Get(got)
	if !ok {
		t.Fatalf("root not in store")
	}
	want, err := hash.Compute(ent.Type, ent.Data)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if got != want {
		t.Fatalf("content hash mismatch: got %s, want %s", got, want)
	}
}

// TestBitmapSetGetClear validates the bitmap helpers' bit ordering. Bit
// p set means BitmapU32 returns (1 << p) — LSB-indexed integer, serialized
// big-endian.
func TestBitmapSetGetClear(t *testing.T) {
	cases := []struct {
		p       int
		wantHex string
	}{
		{0, "00000001"},
		{7, "00000080"},
		{8, "00000100"},
		{28, "10000000"},
		{31, "80000000"},
	}
	for _, tc := range cases {
		bm := make([]byte, BitmapBytes)
		BitmapSet(bm, tc.p)
		gotHex := strings.ToUpper(hex.EncodeToString(bm))
		want := strings.ToUpper(tc.wantHex)
		if gotHex != want {
			t.Errorf("BitmapSet(%d): got %s, want %s", tc.p, gotHex, want)
		}
		if !BitmapGet(bm, tc.p) {
			t.Errorf("BitmapGet(%d): expected true", tc.p)
		}
		BitmapClear(bm, tc.p)
		if BitmapGet(bm, tc.p) {
			t.Errorf("BitmapClear(%d): expected false", tc.p)
		}
	}
}

// TestPopcountBelow validates dense-index computation: popcount of the
// bitmap masked by ((1 << p) - 1).
func TestPopcountBelow(t *testing.T) {
	bm := make([]byte, BitmapBytes)
	for _, p := range []int{0, 5, 12, 28} {
		BitmapSet(bm, p)
	}
	for _, tc := range []struct {
		p    int
		want int
	}{
		{0, 0},
		{1, 1},
		{5, 1},
		{6, 2},
		{12, 2},
		{13, 3},
		{28, 3},
		{29, 4},
	} {
		got := PopcountBelow(bm, tc.p)
		if got != tc.want {
			t.Errorf("PopcountBelow(%d): got %d, want %d", tc.p, got, tc.want)
		}
	}
}

// TestPutRebuildEquivalence verifies that incremental TriePut reaches the
// same root as BuildTrie over the full binding set, regardless of
// insertion order. This is the byte-identical-output invariant required
// for cross-impl convergence.
func TestPutRebuildEquivalence(t *testing.T) {
	cs := store.NewMemoryContentStore()
	bindings := generateBindings(50, 0xDEADBEEF)

	// Reference: BuildTrie over the full set.
	want, err := BuildTrie(cs, bindings)
	if err != nil {
		t.Fatalf("BuildTrie reference: %v", err)
	}

	// Permute and apply incrementally; should converge to the same root.
	r := mathrand.New(mathrand.NewSource(0xC0FFEE))
	perm := r.Perm(len(bindings))
	current, err := StoreTrieNode(cs, EmptyNode())
	if err != nil {
		t.Fatalf("empty root: %v", err)
	}
	for _, i := range perm {
		current, err = TriePut(cs, current, bindings[i].Path, bindings[i].Hash)
		if err != nil {
			t.Fatalf("TriePut[%d]: %v", i, err)
		}
	}
	if current != want {
		t.Fatalf("incremental != rebuild: got %s, want %s", current, want)
	}
}

// TestPutRemoveFuzz is the CHAMP-on-delete silent-bug catcher per
// EXTENSION-TREE v4.0 §3.4.2: random insert + delete sequence, after
// every step the root MUST equal BuildTrie(current_live_set). Without
// CHAMP collapse two peers building the same set via different histories
// produce different roots — and convergent_mirror breaks at the substrate.
//
// Catches: missing canonical-form collapse on delete, off-by-one in
// branchSize threshold, bucket-sort drift, bitmap-clear misses.
func TestPutRemoveFuzz(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fuzz in -short mode")
	}
	const (
		steps = 400
		keys  = 64
	)
	cs := store.NewMemoryContentStore()
	r := mathrand.New(mathrand.NewSource(0xBADC0DE))

	keyPool := make([]string, keys)
	hashes := make(map[string]hash.Hash, keys)
	for i := 0; i < keys; i++ {
		keyPool[i] = fmt.Sprintf("k/%d", i)
		hashes[keyPool[i]] = randomHash(r)
	}

	current, err := StoreTrieNode(cs, EmptyNode())
	if err != nil {
		t.Fatalf("init root: %v", err)
	}
	live := make(map[string]hash.Hash)

	for step := 0; step < steps; step++ {
		k := keyPool[r.Intn(keys)]
		// 60% put, 40% remove
		if r.Intn(10) < 6 {
			h := randomHash(r)
			current, err = TriePut(cs, current, k, h)
			if err != nil {
				t.Fatalf("step %d TriePut(%q): %v", step, k, err)
			}
			live[k] = h
		} else {
			current, err = TrieRemove(cs, current, k)
			if err != nil {
				t.Fatalf("step %d TrieRemove(%q): %v", step, k, err)
			}
			delete(live, k)
		}

		// Reference: rebuild from live set.
		want := mustBuildFromMap(t, cs, live)
		if current != want {
			t.Fatalf("step %d: incremental root %s != rebuilt root %s (live=%d)",
				step, current, want, len(live))
		}
	}
}

// TestRemoveAbsentNoop confirms that removing a missing key yields the
// same root hash and does not allocate a new node.
func TestRemoveAbsentNoop(t *testing.T) {
	cs := store.NewMemoryContentStore()
	bindings := generateBindings(8, 0x12345)
	root, err := BuildTrie(cs, bindings)
	if err != nil {
		t.Fatalf("BuildTrie: %v", err)
	}
	got, err := TrieRemove(cs, root, "definitely/not/present")
	if err != nil {
		t.Fatalf("TrieRemove: %v", err)
	}
	if got != root {
		t.Fatalf("expected absent-key remove to no-op; got %s, want %s", got, root)
	}
}

// TestEnsureValidAfterChurn runs a churning sequence and validates that
// every intermediate trie satisfies the canonical-form invariants
// (popcount == len(data), bucket sort, bucket size ≤ BucketSize).
func TestEnsureValidAfterChurn(t *testing.T) {
	cs := store.NewMemoryContentStore()
	r := mathrand.New(mathrand.NewSource(0xF00D))
	root, err := StoreTrieNode(cs, EmptyNode())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	keys := make([]string, 30)
	for i := range keys {
		keys[i] = fmt.Sprintf("p/%d/%d", r.Intn(5), i)
	}
	for step := 0; step < 200; step++ {
		k := keys[r.Intn(len(keys))]
		if r.Intn(2) == 0 {
			root, err = TriePut(cs, root, k, randomHash(r))
		} else {
			root, err = TrieRemove(cs, root, k)
		}
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		validateAll(t, cs, root, true /* isRoot */)
	}
}

// validateAll recursively asserts EnsureValid + (for non-root nodes)
// BranchSize ≥ BucketSize+1.
func validateAll(t *testing.T, cs store.ContentStore, h hash.Hash, isRoot bool) {
	t.Helper()
	if h.IsZero() {
		return
	}
	node, ok := LoadTrieNode(cs, h)
	if !ok {
		return
	}
	if err := EnsureValid(node); err != nil {
		t.Fatalf("node %s invalid: %v", h, err)
	}
	if !isRoot {
		if bs := BranchSize(cs, node); bs < BucketSize+1 {
			t.Fatalf("non-root %s has branchSize %d < %d", h, bs, BucketSize+1)
		}
	}
	for _, entry := range node.Data {
		if entry.IsLink() {
			validateAll(t, cs, *entry.Link, false)
		}
	}
}

// ---------- helpers ----------

func generateBindings(n int, seed int64) []Binding {
	r := mathrand.New(mathrand.NewSource(seed))
	out := make([]Binding, n)
	for i := 0; i < n; i++ {
		out[i] = Binding{Path: fmt.Sprintf("seg/%d/leaf_%d", r.Intn(7), i), Hash: randomHash(r)}
	}
	return out
}

func randomHash(r *mathrand.Rand) hash.Hash {
	var d [32]byte
	r.Read(d[:])
	return hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest(d)}
}

func mustBuildFromMap(t *testing.T, cs store.ContentStore, live map[string]hash.Hash) hash.Hash {
	t.Helper()
	bs := make([]Binding, 0, len(live))
	for k, v := range live {
		bs = append(bs, Binding{Path: k, Hash: v})
	}
	h, err := BuildTrie(cs, bs)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	return h
}

