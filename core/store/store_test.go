package store

import (
	"sync"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

func makeEntity(t *testing.T, typ string, data interface{}) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	e, err := entity.NewEntity(typ, cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestContentStoreCRUD(t *testing.T) {
	s := NewMemoryContentStore()

	e := makeEntity(t, "test", "hello")

	// Put.
	h, err := s.Put(e)
	if err != nil {
		t.Fatal(err)
	}
	if h != e.ContentHash {
		t.Fatal("put returned wrong hash")
	}

	// Has.
	if !s.Has(h) {
		t.Fatal("should have entity")
	}

	// Get.
	got, ok := s.Get(h)
	if !ok {
		t.Fatal("should find entity")
	}
	if got.Type != "test" {
		t.Fatalf("wrong type: %s", got.Type)
	}

	// Len.
	if s.Len() != 1 {
		t.Fatalf("expected len 1, got %d", s.Len())
	}

	// Remove.
	if !s.Remove(h) {
		t.Fatal("should remove entity")
	}
	if s.Has(h) {
		t.Fatal("should not have entity after remove")
	}
	if s.Len() != 0 {
		t.Fatal("expected len 0")
	}

	// Remove non-existent.
	if s.Remove(hash.Hash{}) {
		t.Fatal("should not remove non-existent")
	}
}

func TestLocationIndexCRUD(t *testing.T) {
	idx := NewMemoryLocationIndex()

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0x42

	// Set.
	idx.Set("system/tree/foo", h)

	// Has.
	if !idx.Has("system/tree/foo") {
		t.Fatal("should have path")
	}

	// Get.
	got, ok := idx.Get("system/tree/foo")
	if !ok {
		t.Fatal("should find path")
	}
	if got != h {
		t.Fatal("wrong hash")
	}

	// List.
	idx.Set("system/tree/bar", h)
	idx.Set("local/other", h)

	entries := idx.List("system/tree/")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Path != "system/tree/bar" {
		t.Fatalf("expected bar first (sorted), got %s", entries[0].Path)
	}

	// Remove.
	removed, ok := idx.Remove("system/tree/foo")
	if !ok {
		t.Fatal("should remove path")
	}
	if removed != h {
		t.Fatal("wrong removed hash")
	}
	if idx.Has("system/tree/foo") {
		t.Fatal("should not have path after remove")
	}
}

func TestContentStoreConcurrency(t *testing.T) {
	s := NewMemoryContentStore()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := makeEntity(t, "test", i)
			s.Put(e)
			s.Has(e.ContentHash)
			s.Get(e.ContentHash)
		}(i)
	}
	wg.Wait()
}

func TestLocationIndexConcurrency(t *testing.T) {
	idx := NewMemoryLocationIndex()
	var wg sync.WaitGroup

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "test/" + string(rune('a'+i%26))
			idx.Set(path, h)
			idx.Has(path)
			idx.Get(path)
			idx.List("test/")
		}(i)
	}
	wg.Wait()
}
