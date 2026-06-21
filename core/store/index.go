package store

import "go.entitychurch.org/entity-core-go/core/hash"

// TypeIndexEntry is a (path, hash) pair from the type index.
type TypeIndexEntry struct {
	Path string
	Hash hash.Hash
}

// TypeIndex maps entity type names to their tree locations. Implementations
// provide fast lookup by type. The query handler depends on this interface.
type TypeIndex interface {
	// Lookup returns all entries for the exact type name.
	Lookup(typeName string) []TypeIndexEntry
	// LookupGlob returns entries for types matching a glob pattern.
	// Supports trailing "/*" for prefix match and bare "*" for match-all.
	LookupGlob(pattern string) []TypeIndexEntry
	// Count returns the number of entries for the exact type name.
	Count(typeName string) int
	// Types returns all indexed type names.
	Types() []string
}

// ReverseIndexEntry records an entity that references a given hash.
type ReverseIndexEntry struct {
	SourcePath string // tree path of the referencing entity
	SourceType string // type of the referencing entity
	FieldName  string // top-level field containing the reference
}

// ReverseHashIndex maps content hashes to entities that reference them.
// Tracks all system/hash values found in entity data at any nesting depth.
type ReverseHashIndex interface {
	// Lookup returns all entities that reference the given hash.
	Lookup(h hash.Hash) []ReverseIndexEntry
}

// PathLinkEntry records an entity that references a given tree path.
type PathLinkEntry struct {
	SourcePath string // tree path of the referencing entity
	SourceType string // type of the referencing entity
	FieldName  string // top-level field containing the reference
}

// PathLinkIndex maps tree paths to entities that reference them via
// system/tree/path typed fields. Only fields declared as type_ref:
// "system/tree/path" in the type definition are indexed.
type PathLinkIndex interface {
	// Lookup returns all entities that reference the given path.
	Lookup(path string) []PathLinkEntry
}
