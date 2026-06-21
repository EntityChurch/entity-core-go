// Package query implements the system/query handler and in-memory secondary
// indexes per EXTENSION-QUERY.md v1.0.
//
// The package provides three index implementations (TypeIndex, ReverseHashIndex,
// PathLinkIndex) maintained synchronously via sync hooks on the
// NotifyingLocationIndex. The query handler depends on the index interfaces
// defined in core/store — the in-memory implementations here are swappable
// for SQL-backed implementations later.
package query

import (
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
)

// MemoryTypeIndex is an in-memory implementation of store.TypeIndex.
// Maps type_name → set of {path, hash}.
type MemoryTypeIndex struct {
	mu      sync.RWMutex
	entries map[string][]store.TypeIndexEntry
}

// NewMemoryTypeIndex creates an empty in-memory type index.
func NewMemoryTypeIndex() *MemoryTypeIndex {
	return &MemoryTypeIndex{
		entries: make(map[string][]store.TypeIndexEntry),
	}
}

func (idx *MemoryTypeIndex) Lookup(typeName string) []store.TypeIndexEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	entries := idx.entries[typeName]
	out := make([]store.TypeIndexEntry, len(entries))
	copy(out, entries)
	return out
}

func (idx *MemoryTypeIndex) LookupGlob(pattern string) []store.TypeIndexEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if pattern == "*" {
		var out []store.TypeIndexEntry
		for _, entries := range idx.entries {
			out = append(out, entries...)
		}
		return out
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1] // "app/*" → "app/"
		var out []store.TypeIndexEntry
		for typeName, entries := range idx.entries {
			if strings.HasPrefix(typeName, prefix) {
				out = append(out, entries...)
			}
		}
		return out
	}

	// Exact match.
	entries := idx.entries[pattern]
	out := make([]store.TypeIndexEntry, len(entries))
	copy(out, entries)
	return out
}

func (idx *MemoryTypeIndex) Count(typeName string) int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.entries[typeName])
}

func (idx *MemoryTypeIndex) Types() []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	names := make([]string, 0, len(idx.entries))
	for name, entries := range idx.entries {
		if len(entries) > 0 {
			names = append(names, name)
		}
	}
	return names
}

// Add inserts a type index entry. Not part of the read interface.
func (idx *MemoryTypeIndex) Add(typeName, path string, h hash.Hash) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries[typeName] = append(idx.entries[typeName], store.TypeIndexEntry{
		Path: path,
		Hash: h,
	})
}

// Remove removes a type index entry by path and hash. Returns true if found.
func (idx *MemoryTypeIndex) Remove(typeName, path string, h hash.Hash) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	entries := idx.entries[typeName]
	for i, e := range entries {
		if e.Path == path && e.Hash == h {
			idx.entries[typeName] = append(entries[:i], entries[i+1:]...)
			if len(idx.entries[typeName]) == 0 {
				delete(idx.entries, typeName)
			}
			return true
		}
	}
	return false
}

// Clear removes all entries.
func (idx *MemoryTypeIndex) Clear() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries = make(map[string][]store.TypeIndexEntry)
}

// MemoryReverseHashIndex is an in-memory implementation of store.ReverseHashIndex.
// Maps referenced_hash → set of {source_path, source_type, field_name}.
type MemoryReverseHashIndex struct {
	mu      sync.RWMutex
	entries map[hash.Hash][]store.ReverseIndexEntry
}

// NewMemoryReverseHashIndex creates an empty in-memory reverse hash index.
func NewMemoryReverseHashIndex() *MemoryReverseHashIndex {
	return &MemoryReverseHashIndex{
		entries: make(map[hash.Hash][]store.ReverseIndexEntry),
	}
}

func (idx *MemoryReverseHashIndex) Lookup(h hash.Hash) []store.ReverseIndexEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	entries := idx.entries[h]
	out := make([]store.ReverseIndexEntry, len(entries))
	copy(out, entries)
	return out
}

// Add inserts a reverse index entry.
func (idx *MemoryReverseHashIndex) Add(referenced hash.Hash, sourcePath, sourceType, fieldName string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries[referenced] = append(idx.entries[referenced], store.ReverseIndexEntry{
		SourcePath: sourcePath,
		SourceType: sourceType,
		FieldName:  fieldName,
	})
}

// RemoveBySource removes all reverse index entries with the given source path.
func (idx *MemoryReverseHashIndex) RemoveBySource(sourcePath string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for h, entries := range idx.entries {
		filtered := entries[:0]
		for _, e := range entries {
			if e.SourcePath != sourcePath {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) == 0 {
			delete(idx.entries, h)
		} else {
			idx.entries[h] = filtered
		}
	}
}

// Clear removes all entries.
func (idx *MemoryReverseHashIndex) Clear() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries = make(map[hash.Hash][]store.ReverseIndexEntry)
}

// MemoryPathLinkIndex is an in-memory implementation of store.PathLinkIndex.
// Maps referenced_path → set of {source_path, source_type, field_name}.
type MemoryPathLinkIndex struct {
	mu      sync.RWMutex
	entries map[string][]store.PathLinkEntry
}

// NewMemoryPathLinkIndex creates an empty in-memory path link index.
func NewMemoryPathLinkIndex() *MemoryPathLinkIndex {
	return &MemoryPathLinkIndex{
		entries: make(map[string][]store.PathLinkEntry),
	}
}

func (idx *MemoryPathLinkIndex) Lookup(path string) []store.PathLinkEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	entries := idx.entries[path]
	out := make([]store.PathLinkEntry, len(entries))
	copy(out, entries)
	return out
}

// Add inserts a path link entry.
func (idx *MemoryPathLinkIndex) Add(referencedPath, sourcePath, sourceType, fieldName string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries[referencedPath] = append(idx.entries[referencedPath], store.PathLinkEntry{
		SourcePath: sourcePath,
		SourceType: sourceType,
		FieldName:  fieldName,
	})
}

// RemoveBySource removes all path link entries with the given source path.
func (idx *MemoryPathLinkIndex) RemoveBySource(sourcePath string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for p, entries := range idx.entries {
		filtered := entries[:0]
		for _, e := range entries {
			if e.SourcePath != sourcePath {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) == 0 {
			delete(idx.entries, p)
		} else {
			idx.entries[p] = filtered
		}
	}
}

// Clear removes all entries.
func (idx *MemoryPathLinkIndex) Clear() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries = make(map[string][]store.PathLinkEntry)
}
