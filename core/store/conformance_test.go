package store

import (
	"sort"
	"sync"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Backend-conformance suite. Both MemoryContentStore + SqliteContentStore and
// MemoryLocationIndex + SqliteLocationIndex run through the same assertions
// to catch divergence between impls. Mirrors entity-core-rust/core/store/
// src/test_suite.rs.

func mkEntity(t *testing.T, typ string, payload any) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(payload)
	if err != nil {
		t.Fatalf("ecf encode: %v", err)
	}
	e, err := entity.NewEntity(typ, cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("entity new: %v", err)
	}
	return e
}

func mkHash(seed byte) hash.Hash {
	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = seed
	return h
}

// -----------------------------------------------------------------------------
// ContentStore conformance
// -----------------------------------------------------------------------------

type contentStoreFactory func(t *testing.T) (cs ContentStore, cleanup func())

func runContentStoreSuite(t *testing.T, factory contentStoreFactory) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(*testing.T, ContentStore)
	}{
		{"PutGet", testCSPutGet},
		{"Has", testCSHas},
		{"Remove", testCSRemove},
		{"Len", testCSLen},
		{"GetMissing", testCSGetMissing},
		{"PutOverwrite", testCSPutOverwrite},
		{"MultipleEntities", testCSMultipleEntities},
		{"DataFidelity", testCSDataFidelity},
		{"Concurrency", testCSConcurrency},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cs, cleanup := factory(t)
			defer cleanup()
			c.fn(t, cs)
		})
	}
}

func testCSPutGet(t *testing.T, cs ContentStore) {
	e := mkEntity(t, "test/a", "alpha")
	h, err := cs.Put(e)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if h != e.ContentHash {
		t.Fatalf("put returned %s, expected %s", h, e.ContentHash)
	}
	got, ok := cs.Get(h)
	if !ok {
		t.Fatal("get: not found")
	}
	if got.Type != "test/a" {
		t.Fatalf("type: got %q", got.Type)
	}
	if got.ContentHash != h {
		t.Fatalf("get content hash mismatch: got %s, want %s", got.ContentHash, h)
	}
}

func testCSHas(t *testing.T, cs ContentStore) {
	e := mkEntity(t, "test/has", "x")
	h, _ := cs.Put(e)
	if !cs.Has(h) {
		t.Fatal("has: should be true")
	}
	if cs.Has(mkHash(0xFF)) {
		t.Fatal("has: should be false for unknown hash")
	}
}

func testCSRemove(t *testing.T, cs ContentStore) {
	e := mkEntity(t, "test/rm", "x")
	h, _ := cs.Put(e)
	if !cs.Remove(h) {
		t.Fatal("remove: should return true on first remove")
	}
	if cs.Has(h) {
		t.Fatal("remove: should be gone")
	}
	if cs.Remove(h) {
		t.Fatal("remove: should return false on second remove")
	}
}

func testCSLen(t *testing.T, cs ContentStore) {
	if cs.Len() != 0 {
		t.Fatalf("initial len: got %d, want 0", cs.Len())
	}
	cs.Put(mkEntity(t, "test/len", "1"))
	cs.Put(mkEntity(t, "test/len", "2"))
	if cs.Len() != 2 {
		t.Fatalf("after 2 puts: got %d, want 2", cs.Len())
	}
}

func testCSGetMissing(t *testing.T, cs ContentStore) {
	if _, ok := cs.Get(mkHash(0x42)); ok {
		t.Fatal("get missing: should be false")
	}
}

func testCSPutOverwrite(t *testing.T, cs ContentStore) {
	e := mkEntity(t, "test/over", "x")
	h1, _ := cs.Put(e)
	h2, _ := cs.Put(e) // same content → same hash → idempotent overwrite
	if h1 != h2 {
		t.Fatal("put same entity twice: hashes differ")
	}
	if cs.Len() != 1 {
		t.Fatalf("len after dup put: got %d, want 1", cs.Len())
	}
}

func testCSMultipleEntities(t *testing.T, cs ContentStore) {
	a, _ := cs.Put(mkEntity(t, "test/a", "alpha"))
	b, _ := cs.Put(mkEntity(t, "test/b", "beta"))
	c, _ := cs.Put(mkEntity(t, "test/c", "gamma"))
	if cs.Len() != 3 {
		t.Fatalf("len: got %d, want 3", cs.Len())
	}
	for _, h := range []hash.Hash{a, b, c} {
		if !cs.Has(h) {
			t.Fatalf("missing: %s", h)
		}
	}
}

func testCSDataFidelity(t *testing.T, cs ContentStore) {
	// Roundtrip preserves data bytes exactly. This is the hash-fidelity guarantee.
	e := mkEntity(t, "test/binary", "payload with special bytes \x00\xff\x42")
	h, _ := cs.Put(e)
	got, ok := cs.Get(h)
	if !ok {
		t.Fatal("get: not found")
	}
	if string(got.Data) != string(e.Data) {
		t.Fatalf("data mismatch: got %x, want %x", got.Data, e.Data)
	}
	// Re-validate hash from roundtripped data.
	if err := got.Validate(); err != nil {
		t.Fatalf("roundtrip data fails hash validate: %v", err)
	}
}

func testCSConcurrency(t *testing.T, cs ContentStore) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := mkEntity(t, "test/conc", i)
			h, err := cs.Put(e)
			if err != nil {
				t.Errorf("put: %v", err)
				return
			}
			cs.Has(h)
			cs.Get(h)
		}(i)
	}
	wg.Wait()
}

// -----------------------------------------------------------------------------
// LocationIndex conformance
// -----------------------------------------------------------------------------

type locationIndexFactory func(t *testing.T) (li LocationIndex, cleanup func())

func runLocationIndexSuite(t *testing.T, factory locationIndexFactory) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(*testing.T, LocationIndex)
	}{
		{"SetGet", testLISetGet},
		{"Has", testLIHas},
		{"Remove", testLIRemove},
		{"GetMissing", testLIGetMissing},
		{"Overwrite", testLIOverwrite},
		{"ListPrefix", testLIListPrefix},
		{"ListAll", testLIListAll},
		{"ListEmpty", testLIListEmpty},
		{"ListNoMatch", testLIListNoMatch},
		{"ListOrdered", testLIListOrdered},
		{"LenPrefixAll", testLILenPrefixAll},
		{"LenPrefixScoped", testLILenPrefixScoped},
		{"LenPrefixEmptyStore", testLILenPrefixEmptyStore},
		{"LenPrefixAfterRemove", testLILenPrefixAfterRemove},
		{"CASSwapMatch", testLICASSwapMatch},
		{"CASSwapMismatch", testLICASSwapMismatch},
		{"CASSwapNotFound", testLICASSwapNotFound},
		{"CASRemoveMatch", testLICASRemoveMatch},
		{"CASRemoveMismatch", testLICASRemoveMismatch},
		{"CASRemoveNotFound", testLICASRemoveNotFound},
		{"Concurrency", testLIConcurrency},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			li, cleanup := factory(t)
			defer cleanup()
			c.fn(t, li)
		})
	}
}

func testLISetGet(t *testing.T, li LocationIndex) {
	h := mkHash(0x11)
	li.Set("/peer/path", h)
	got, ok := li.Get("/peer/path")
	if !ok {
		t.Fatal("get: not found")
	}
	if got != h {
		t.Fatalf("hash mismatch: got %s, want %s", got, h)
	}
}

func testLIHas(t *testing.T, li LocationIndex) {
	li.Set("/peer/x", mkHash(0x01))
	if !li.Has("/peer/x") {
		t.Fatal("has: should be true")
	}
	if li.Has("/peer/y") {
		t.Fatal("has: should be false")
	}
}

func testLIRemove(t *testing.T, li LocationIndex) {
	h := mkHash(0x02)
	li.Set("/peer/r", h)
	got, ok := li.Remove("/peer/r")
	if !ok {
		t.Fatal("remove: should return true")
	}
	if got != h {
		t.Fatalf("remove returned wrong hash: got %s, want %s", got, h)
	}
	if li.Has("/peer/r") {
		t.Fatal("remove: should be gone")
	}
	if _, ok := li.Remove("/peer/r"); ok {
		t.Fatal("remove: second call should return false")
	}
}

func testLIGetMissing(t *testing.T, li LocationIndex) {
	if _, ok := li.Get("/never/set"); ok {
		t.Fatal("get missing: should be false")
	}
}

func testLIOverwrite(t *testing.T, li LocationIndex) {
	li.Set("/peer/k", mkHash(0x03))
	li.Set("/peer/k", mkHash(0x04))
	got, _ := li.Get("/peer/k")
	if got != mkHash(0x04) {
		t.Fatalf("overwrite: got %s, want hash with seed 0x04", got)
	}
}

func testLIListPrefix(t *testing.T, li LocationIndex) {
	li.Set("/peer/a/x", mkHash(0x10))
	li.Set("/peer/a/y", mkHash(0x11))
	li.Set("/peer/b/x", mkHash(0x12))
	li.Set("/other/z", mkHash(0x13))

	got := li.List("/peer/a/")
	if len(got) != 2 {
		t.Fatalf("list /peer/a/: got %d entries, want 2", len(got))
	}
	if !sortedAscending(got) {
		t.Fatalf("list result not sorted: %v", paths(got))
	}
	if got[0].Path != "/peer/a/x" || got[1].Path != "/peer/a/y" {
		t.Fatalf("paths: %v", paths(got))
	}
}

func testLIListAll(t *testing.T, li LocationIndex) {
	li.Set("/p/c", mkHash(0x20))
	li.Set("/p/a", mkHash(0x21))
	li.Set("/p/b", mkHash(0x22))

	got := li.List("")
	if len(got) != 3 {
		t.Fatalf("list all: got %d, want 3", len(got))
	}
	if !sortedAscending(got) {
		t.Fatalf("list all not sorted: %v", paths(got))
	}
}

func testLIListEmpty(t *testing.T, li LocationIndex) {
	got := li.List("")
	if len(got) != 0 {
		t.Fatalf("list empty: got %d, want 0", len(got))
	}
}

func testLIListNoMatch(t *testing.T, li LocationIndex) {
	li.Set("/peer/a", mkHash(0x30))
	got := li.List("/nomatch/")
	if len(got) != 0 {
		t.Fatalf("list nomatch: got %d, want 0", len(got))
	}
}

func testLIListOrdered(t *testing.T, li LocationIndex) {
	// Insert in reverse-lex order; List must return ascending.
	for _, p := range []string{"/p/z", "/p/y", "/p/x", "/p/w"} {
		li.Set(p, mkHash(0x50))
	}
	got := li.List("/p/")
	want := []string{"/p/w", "/p/x", "/p/y", "/p/z"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Path != want[i] {
			t.Fatalf("at %d: got %q, want %q", i, got[i].Path, want[i])
		}
	}
}

// LenPrefix conformance: both backends must report the same counts
// for the same inputs. UI status displays rely on this — see
// the cross-impl UI-patterns feedback.

func testLILenPrefixAll(t *testing.T, li LocationIndex) {
	li.Set("/peer/a", mkHash(0x01))
	li.Set("/peer/b", mkHash(0x02))
	li.Set("/other/c", mkHash(0x03))
	if n := li.LenPrefix(""); n != 3 {
		t.Errorf("LenPrefix(\"\") = %d, want 3", n)
	}
}

func testLILenPrefixScoped(t *testing.T, li LocationIndex) {
	li.Set("/peer/a", mkHash(0x10))
	li.Set("/peer/b", mkHash(0x11))
	li.Set("/peer/sub/c", mkHash(0x12))
	li.Set("/other/d", mkHash(0x13))
	cases := []struct {
		prefix string
		want   int
	}{
		{"/peer/", 3},     // a, b, sub/c
		{"/peer/sub/", 1}, // sub/c
		{"/other/", 1},    // d
		{"/missing/", 0},
		{"/", 4},
	}
	for _, c := range cases {
		if n := li.LenPrefix(c.prefix); n != c.want {
			t.Errorf("LenPrefix(%q) = %d, want %d", c.prefix, n, c.want)
		}
	}
}

func testLILenPrefixEmptyStore(t *testing.T, li LocationIndex) {
	if n := li.LenPrefix(""); n != 0 {
		t.Errorf("LenPrefix(\"\") on empty store = %d, want 0", n)
	}
	if n := li.LenPrefix("/anything/"); n != 0 {
		t.Errorf("LenPrefix(/anything/) on empty store = %d, want 0", n)
	}
}

func testLILenPrefixAfterRemove(t *testing.T, li LocationIndex) {
	li.Set("/peer/a", mkHash(0x20))
	li.Set("/peer/b", mkHash(0x21))
	li.Set("/peer/c", mkHash(0x22))
	if n := li.LenPrefix("/peer/"); n != 3 {
		t.Fatalf("LenPrefix before remove = %d, want 3", n)
	}
	li.Remove("/peer/b")
	if n := li.LenPrefix("/peer/"); n != 2 {
		t.Errorf("LenPrefix after remove = %d, want 2", n)
	}
	if n := li.LenPrefix(""); n != 2 {
		t.Errorf("LenPrefix(\"\") after remove = %d, want 2", n)
	}
}

func testLICASSwapMatch(t *testing.T, li LocationIndex) {
	old := mkHash(0x70)
	new := mkHash(0x71)
	li.Set("/peer/cas", old)
	if err := li.CompareAndSwap("/peer/cas", old, new); err != nil {
		t.Fatalf("cas swap match: %v", err)
	}
	got, _ := li.Get("/peer/cas")
	if got != new {
		t.Fatalf("after swap: got %s, want %s", got, new)
	}
}

func testLICASSwapMismatch(t *testing.T, li LocationIndex) {
	actual := mkHash(0x80)
	wrong := mkHash(0x81)
	new := mkHash(0x82)
	li.Set("/peer/cas", actual)

	err := li.CompareAndSwap("/peer/cas", wrong, new)
	if err == nil {
		t.Fatal("cas swap mismatch: expected error, got nil")
	}
	cerr, ok := err.(*CasError)
	if !ok {
		t.Fatalf("cas swap mismatch: wrong error type: %T", err)
	}
	if cerr.NotFound {
		t.Fatal("cas swap mismatch: NotFound should be false")
	}
	if cerr.Actual != actual {
		t.Fatalf("cas swap mismatch: actual %s, want %s", cerr.Actual, actual)
	}
	// Binding unchanged.
	got, _ := li.Get("/peer/cas")
	if got != actual {
		t.Fatalf("after failed cas: binding changed to %s", got)
	}
}

func testLICASSwapNotFound(t *testing.T, li LocationIndex) {
	expected := mkHash(0x90)
	new := mkHash(0x91)
	err := li.CompareAndSwap("/peer/missing", expected, new)
	if err == nil {
		t.Fatal("cas swap not-found: expected error, got nil")
	}
	cerr, ok := err.(*CasError)
	if !ok {
		t.Fatalf("cas swap not-found: wrong error type: %T", err)
	}
	if !cerr.NotFound {
		t.Fatal("cas swap not-found: NotFound should be true")
	}
	if li.Has("/peer/missing") {
		t.Fatal("cas swap not-found: must not create binding")
	}
}

func testLICASRemoveMatch(t *testing.T, li LocationIndex) {
	h := mkHash(0xA0)
	li.Set("/peer/casrm", h)
	if err := li.CompareAndRemove("/peer/casrm", h); err != nil {
		t.Fatalf("cas remove match: %v", err)
	}
	if li.Has("/peer/casrm") {
		t.Fatal("after cas remove: binding still exists")
	}
}

func testLICASRemoveMismatch(t *testing.T, li LocationIndex) {
	actual := mkHash(0xB0)
	wrong := mkHash(0xB1)
	li.Set("/peer/casrm", actual)

	err := li.CompareAndRemove("/peer/casrm", wrong)
	cerr, ok := err.(*CasError)
	if !ok {
		t.Fatalf("cas remove mismatch: wrong error type: %T", err)
	}
	if cerr.NotFound {
		t.Fatal("cas remove mismatch: NotFound should be false")
	}
	if cerr.Actual != actual {
		t.Fatalf("cas remove mismatch: actual %s, want %s", cerr.Actual, actual)
	}
	if !li.Has("/peer/casrm") {
		t.Fatal("after failed cas remove: binding gone")
	}
}

func testLICASRemoveNotFound(t *testing.T, li LocationIndex) {
	err := li.CompareAndRemove("/peer/missing", mkHash(0xC0))
	cerr, ok := err.(*CasError)
	if !ok {
		t.Fatalf("cas remove not-found: wrong error type: %T", err)
	}
	if !cerr.NotFound {
		t.Fatal("cas remove not-found: NotFound should be true")
	}
}

func testLIConcurrency(t *testing.T, li LocationIndex) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := "/peer/conc/" + string(rune('a'+i%26))
			li.Set(p, mkHash(byte(i)))
			li.Has(p)
			li.Get(p)
			li.List("/peer/conc/")
		}(i)
	}
	wg.Wait()
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func sortedAscending(entries []LocationEntry) bool {
	return sort.SliceIsSorted(entries, func(a, b int) bool {
		return entries[a].Path < entries[b].Path
	})
}

func paths(entries []LocationEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path
	}
	return out
}

// -----------------------------------------------------------------------------
// Memory backend wired through the conformance suite
// -----------------------------------------------------------------------------

func TestMemoryContentStoreConformance(t *testing.T) {
	runContentStoreSuite(t, func(t *testing.T) (ContentStore, func()) {
		return NewMemoryContentStore(), func() {}
	})
}

func TestMemoryLocationIndexConformance(t *testing.T) {
	runLocationIndexSuite(t, func(t *testing.T) (LocationIndex, func()) {
		return NewMemoryLocationIndex(), func() {}
	})
}
