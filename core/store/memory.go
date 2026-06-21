package store

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// MemoryContentStore is an in-memory content-addressed store.
type MemoryContentStore struct {
	mu       sync.RWMutex
	entities map[hash.Hash]entity.Entity
}

// NewMemoryContentStore creates a new in-memory content store.
func NewMemoryContentStore() *MemoryContentStore {
	return &MemoryContentStore{
		entities: make(map[hash.Hash]entity.Entity),
	}
}

func (s *MemoryContentStore) Put(e entity.Entity) (hash.Hash, error) {
	// Always recompute hash from {type, data} — never trust claimed ContentHash.
	// This catches entities with zero or corrupted hashes (e.g., from envelope
	// roundtrips where content_hash was missing). Per PROTOCOL §1.8.
	// Recompute under the claimed Algorithm so SHA-384 entities verify
	// against SHA-384 (v7.67 §2.3 format-code interpretation). A zero
	// ContentHash has Algorithm=0x00 (SHA-256) — the v7.66 default.
	computed, err := hash.ComputeFormat(e.ContentHash.Algorithm, e.Type, e.Data)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("content store put: compute hash: %w", err)
	}
	if !e.ContentHash.IsZero() && e.ContentHash != computed {
		return hash.Hash{}, fmt.Errorf("content store put: hash mismatch: claimed %s, computed %s", e.ContentHash, computed)
	}
	e.ContentHash = computed
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entities[computed] = e
	return computed, nil
}

func (s *MemoryContentStore) Get(h hash.Hash) (entity.Entity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entities[h]
	return e, ok
}

func (s *MemoryContentStore) Has(h hash.Hash) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.entities[h]
	return ok
}

func (s *MemoryContentStore) Remove(h hash.Hash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entities[h]
	if ok {
		delete(s.entities, h)
	}
	return ok
}

func (s *MemoryContentStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entities)
}

// MemoryLocationIndex is an in-memory location index.
type MemoryLocationIndex struct {
	mu    sync.RWMutex
	paths map[string]hash.Hash
}

// NewMemoryLocationIndex creates a new in-memory location index.
func NewMemoryLocationIndex() *MemoryLocationIndex {
	return &MemoryLocationIndex{
		paths: make(map[string]hash.Hash),
	}
}

// Set always returns nil for the in-memory impl — a map write cannot fail.
// The error return exists to satisfy the LocationIndex contract; callers must
// still check it because SQLite/persistent impls report real failures here.
func (i *MemoryLocationIndex) Set(path string, h hash.Hash) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.paths[path] = h
	return nil
}

func (i *MemoryLocationIndex) Get(path string) (hash.Hash, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	h, ok := i.paths[path]
	return h, ok
}

func (i *MemoryLocationIndex) Has(path string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	_, ok := i.paths[path]
	return ok
}

func (i *MemoryLocationIndex) Remove(path string) (hash.Hash, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	h, ok := i.paths[path]
	if ok {
		delete(i.paths, path)
	}
	return h, ok
}

func (i *MemoryLocationIndex) CompareAndSwap(path string, expected, new hash.Hash) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	current, ok := i.paths[path]
	if !ok {
		return &CasError{NotFound: true}
	}
	if current != expected {
		return &CasError{Actual: current}
	}
	i.paths[path] = new
	return nil
}

func (i *MemoryLocationIndex) CompareAndRemove(path string, expected hash.Hash) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	current, ok := i.paths[path]
	if !ok {
		return &CasError{NotFound: true}
	}
	if current != expected {
		return &CasError{Actual: current}
	}
	delete(i.paths, path)
	return nil
}

func (i *MemoryLocationIndex) List(prefix string) []LocationEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	var entries []LocationEntry
	for path, h := range i.paths {
		if strings.HasPrefix(path, prefix) {
			entries = append(entries, LocationEntry{Path: path, Hash: h})
		}
	}
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].Path < entries[b].Path
	})
	return entries
}

// LenPrefix returns the count of bindings under prefix. Memory backend
// has no path index; a full map walk is the only option. For the
// memory store this is fine (capped corpus size in tests / ephemeral
// peers); production code uses SqliteLocationIndex.LenPrefix which is
// O(log N) via the path PRIMARY KEY.
func (i *MemoryLocationIndex) LenPrefix(prefix string) int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if prefix == "" {
		return len(i.paths)
	}
	n := 0
	for path := range i.paths {
		if strings.HasPrefix(path, prefix) {
			n++
		}
	}
	return n
}
