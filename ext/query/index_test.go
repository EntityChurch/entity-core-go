package query

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"

	"github.com/fxamacker/cbor/v2"
)

func makeEntity(t *testing.T, typeName string, data interface{}) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	e, err := entity.NewEntity(typeName, cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("new entity: %v", err)
	}
	h, err := hash.Compute(typeName, cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}
	e.ContentHash = h
	return e
}

func TestTypeIndex(t *testing.T) {
	idx := NewMemoryTypeIndex()

	h1 := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest([32]byte{1})}
	h2 := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest([32]byte{2})}
	h3 := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest([32]byte{3})}

	idx.Add("app/user", "app/users/alice", h1)
	idx.Add("app/user", "app/users/bob", h2)
	idx.Add("app/order", "app/orders/1", h3)

	// Exact lookup.
	entries := idx.Lookup("app/user")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Count.
	if idx.Count("app/user") != 2 {
		t.Fatalf("expected count 2, got %d", idx.Count("app/user"))
	}
	if idx.Count("app/order") != 1 {
		t.Fatalf("expected count 1, got %d", idx.Count("app/order"))
	}
	if idx.Count("app/missing") != 0 {
		t.Fatalf("expected count 0, got %d", idx.Count("app/missing"))
	}

	// Glob: wildcard.
	all := idx.LookupGlob("*")
	if len(all) != 3 {
		t.Fatalf("expected 3 entries for *, got %d", len(all))
	}

	// Glob: prefix.
	appTypes := idx.LookupGlob("app/*")
	if len(appTypes) != 3 {
		t.Fatalf("expected 3 entries for app/*, got %d", len(appTypes))
	}

	// Types.
	types := idx.Types()
	if len(types) != 2 {
		t.Fatalf("expected 2 types, got %d", len(types))
	}

	// Remove.
	if !idx.Remove("app/user", "app/users/alice", h1) {
		t.Fatal("expected remove to return true")
	}
	if idx.Count("app/user") != 1 {
		t.Fatalf("after remove: expected count 1, got %d", idx.Count("app/user"))
	}

	// Clear.
	idx.Clear()
	if idx.Count("app/user") != 0 {
		t.Fatal("expected empty after clear")
	}
}

func TestReverseHashIndex(t *testing.T) {
	idx := NewMemoryReverseHashIndex()

	ref := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest([32]byte{99})}
	idx.Add(ref, "app/doc/1", "app/doc", "content_hash")
	idx.Add(ref, "app/doc/2", "app/doc", "content_hash")

	entries := idx.Lookup(ref)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	idx.RemoveBySource("app/doc/1")
	entries = idx.Lookup(ref)
	if len(entries) != 1 {
		t.Fatalf("after remove: expected 1 entry, got %d", len(entries))
	}
	if entries[0].SourcePath != "app/doc/2" {
		t.Fatalf("wrong remaining entry: %s", entries[0].SourcePath)
	}
}

func TestPathLinkIndex(t *testing.T) {
	idx := NewMemoryPathLinkIndex()

	idx.Add("app/target", "app/link/1", "app/link", "target_path")
	idx.Add("app/target", "app/link/2", "app/link", "target_path")

	entries := idx.Lookup("app/target")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	idx.RemoveBySource("app/link/1")
	entries = idx.Lookup("app/target")
	if len(entries) != 1 {
		t.Fatalf("after remove: expected 1 entry, got %d", len(entries))
	}
}

func TestMaintainerSyncHook(t *testing.T) {
	cs := store.NewMemoryContentStore()
	maintainer := NewIndexMaintainer(cs)

	// Create test entities.
	type userData struct {
		Name string `cbor:"name"`
		City string `cbor:"city"`
	}
	e1 := makeEntity(t, "app/user", userData{Name: "Alice", City: "Seattle"})
	e2 := makeEntity(t, "app/user", userData{Name: "Bob", City: "Portland"})

	h1, _ := cs.Put(e1)
	h2, _ := cs.Put(e2)

	// Simulate tree writes via sync hook.
	maintainer.OnTreeChange(store.TreeChangeEvent{
		Path:       "peer1/app/users/alice",
		Hash:       h1,
		ChangeType: store.ChangeCreated,
	})
	maintainer.OnTreeChange(store.TreeChangeEvent{
		Path:       "peer1/app/users/bob",
		Hash:       h2,
		ChangeType: store.ChangeCreated,
	})

	// Type index should have both.
	entries := maintainer.TypeIndex().Lookup("app/user")
	if len(entries) != 2 {
		t.Fatalf("expected 2 type index entries, got %d", len(entries))
	}

	// Update: alice changes.
	e3 := makeEntity(t, "app/user", userData{Name: "Alice", City: "Denver"})
	h3, _ := cs.Put(e3)

	maintainer.OnTreeChange(store.TreeChangeEvent{
		Path:         "peer1/app/users/alice",
		Hash:         h3,
		PreviousHash: h1,
		ChangeType:   store.ChangeModified,
	})

	// Should still have 2 entries (old removed, new added).
	entries = maintainer.TypeIndex().Lookup("app/user")
	if len(entries) != 2 {
		t.Fatalf("after update: expected 2 entries, got %d", len(entries))
	}

	// Delete bob.
	maintainer.OnTreeChange(store.TreeChangeEvent{
		Path:         "peer1/app/users/bob",
		PreviousHash: h2,
		ChangeType:   store.ChangeDeleted,
	})

	entries = maintainer.TypeIndex().Lookup("app/user")
	if len(entries) != 1 {
		t.Fatalf("after delete: expected 1 entry, got %d", len(entries))
	}
}

func TestMaintainerReverseHashIndex(t *testing.T) {
	cs := store.NewMemoryContentStore()
	maintainer := NewIndexMaintainer(cs)

	// Create an entity with hash references.
	refHash := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest([32]byte{42})}
	type docData struct {
		Title      string    `cbor:"title"`
		ContentRef hash.Hash `cbor:"content_ref"`
	}
	e := makeEntity(t, "app/doc", docData{Title: "Test", ContentRef: refHash})
	h, _ := cs.Put(e)

	maintainer.OnTreeChange(store.TreeChangeEvent{
		Path:       "peer1/app/docs/test",
		Hash:       h,
		ChangeType: store.ChangeCreated,
	})

	// Reverse index should find the reference.
	entries := maintainer.ReverseHashIndex().Lookup(refHash)
	if len(entries) != 1 {
		t.Fatalf("expected 1 reverse entry, got %d", len(entries))
	}
	if entries[0].SourcePath != "peer1/app/docs/test" {
		t.Fatalf("wrong source path: %s", entries[0].SourcePath)
	}
	if entries[0].SourceType != "app/doc" {
		t.Fatalf("wrong source type: %s", entries[0].SourceType)
	}
	if entries[0].FieldName != "content_ref" {
		t.Fatalf("wrong field name: %s", entries[0].FieldName)
	}
}

func TestMaintainerRebuild(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	maintainer := NewIndexMaintainer(cs)

	// Populate stores directly (simulating startup with persisted data).
	type userData struct {
		Name string `cbor:"name"`
	}
	e1 := makeEntity(t, "app/user", userData{Name: "Alice"})
	e2 := makeEntity(t, "app/order", userData{Name: "Order1"})

	h1, _ := cs.Put(e1)
	h2, _ := cs.Put(e2)

	li.Set("peer1/app/users/alice", h1)
	li.Set("peer1/app/orders/1", h2)

	// Rebuild indexes from store.
	maintainer.Rebuild(li)

	if maintainer.TypeIndex().Count("app/user") != 1 {
		t.Fatal("expected 1 user after rebuild")
	}
	if maintainer.TypeIndex().Count("app/order") != 1 {
		t.Fatal("expected 1 order after rebuild")
	}
}

func TestExtractHashRefs(t *testing.T) {
	// Entity with a hash reference in data.
	refHash := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest([32]byte{7, 8, 9})}
	type testData struct {
		Name string    `cbor:"name"`
		Ref  hash.Hash `cbor:"ref"`
	}
	raw, _ := ecf.Encode(testData{Name: "test", Ref: refHash})

	refs := extractHashRefs(cbor.RawMessage(raw))
	if len(refs) != 1 {
		t.Fatalf("expected 1 hash ref, got %d", len(refs))
	}
	if refs[0].Hash != refHash {
		t.Fatalf("wrong hash: %v", refs[0].Hash)
	}
	if refs[0].FieldName != "ref" {
		t.Fatalf("wrong field: %s", refs[0].FieldName)
	}
}

func TestExtractHashRefsNested(t *testing.T) {
	// Entity with a hash reference inside an array.
	refHash := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest([32]byte{10})}
	type testData struct {
		Refs []hash.Hash `cbor:"refs"`
	}
	raw, _ := ecf.Encode(testData{Refs: []hash.Hash{refHash}})

	refs := extractHashRefs(cbor.RawMessage(raw))
	if len(refs) != 1 {
		t.Fatalf("expected 1 hash ref, got %d", len(refs))
	}
	if refs[0].FieldName != "refs" {
		t.Fatalf("wrong field: %s", refs[0].FieldName)
	}
}

func TestExtractPathRefs(t *testing.T) {
	type testData struct {
		Target string `cbor:"target"`
		Other  string `cbor:"other"`
	}
	raw, _ := ecf.Encode(testData{Target: "app/some/path", Other: "not-a-path"})

	pathFields := map[string]bool{"target": true}
	refs := extractPathRefs(cbor.RawMessage(raw), pathFields)
	if len(refs) != 1 {
		t.Fatalf("expected 1 path ref, got %d", len(refs))
	}
	if refs[0].Path != "app/some/path" {
		t.Fatalf("wrong path: %s", refs[0].Path)
	}
	if refs[0].FieldName != "target" {
		t.Fatalf("wrong field: %s", refs[0].FieldName)
	}
}
