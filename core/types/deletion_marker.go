package types

import (
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// TypeDeletionMarker is the canonical marker entity type indicating intentional
// path deletion in a revision-tracked version's trie. Per
// PROPOSAL-DELETION-MARKERS.md Amendment 1.
//
// The marker entity has empty fields. Its ECF encoding is `{type:
// "system/deletion-marker", data: <CBOR empty map (0xa0)>}` — the natural form
// for a `fields: {}` schema, produced by any standard ECF encoder without
// special-casing.
//
// V7 v7.70 §4.9 / EXTENSION-REVISION §766: the marker is a zero-field CONTENT
// entity — its hash is `content_hash(marker)` under the trie's own home format
// (V7 §1.2). `ecf-sha256:689ae4…` is the SHA-256-space instance; it is NOT a
// universal constant. A SHA-384 trie binds the marker hash computed under
// SHA-384. Recognition is format-relative on the marker hash's format byte —
// the O(1) hash-equality path holds within a single format, and a foreign-
// format marker is identified by comparing against the marker hash recomputed
// under that hash's algorithm.
const TypeDeletionMarker = "system/deletion-marker"

// CANONICAL_DELETION_MARKER_HASH (SHA-256 instance). Pinned as the cross-impl
// regression value in TestCanonicalDeletionMarkerHash. NOT a universal
// constant — see TypeDeletionMarker docstring (v7.70 §4.9).
const CanonicalDeletionMarkerHashStringSHA256 = "ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6"

var (
	markerMu       sync.RWMutex
	markerEntities = map[byte]entity.Entity{}
	markerHashes   = map[byte]hash.Hash{}
)

// markerFor returns the canonical deletion-marker entity authored under alg,
// caching one entry per format byte. The data is always the CBOR empty map
// (0xa0) — only the hash format differs.
func markerFor(alg byte) (entity.Entity, hash.Hash, error) {
	markerMu.RLock()
	if ent, ok := markerEntities[alg]; ok {
		h := markerHashes[alg]
		markerMu.RUnlock()
		return ent, h, nil
	}
	markerMu.RUnlock()

	ent, err := entity.NewEntityFormat(alg, TypeDeletionMarker, cbor.RawMessage{0xa0})
	if err != nil {
		return entity.Entity{}, hash.Hash{}, fmt.Errorf("build deletion marker for format 0x%02x: %w", alg, err)
	}

	markerMu.Lock()
	markerEntities[alg] = ent
	markerHashes[alg] = ent.ContentHash
	markerMu.Unlock()
	return ent, ent.ContentHash, nil
}

// CanonicalDeletionMarker returns the canonical deletion-marker entity authored
// under the process-global home format (entity.DefaultHashAlgorithm). A
// SHA-256-home peer produces the 689ae4… instance; a SHA-384-home peer produces
// the SHA-384 instance. Single-format network: every peer agrees on one hash;
// the O(1) recognition path holds.
func CanonicalDeletionMarker() entity.Entity {
	ent, _, err := markerFor(entity.DefaultHashAlgorithm())
	if err != nil {
		panic(err)
	}
	return ent
}

// CanonicalDeletionMarkerHash returns the canonical deletion-marker entity's
// content hash under the process-global home format. See
// CanonicalDeletionMarker for the format-relative semantics.
func CanonicalDeletionMarkerHash() hash.Hash {
	_, h, err := markerFor(entity.DefaultHashAlgorithm())
	if err != nil {
		panic(err)
	}
	return h
}

// DeletionMarkerHashForFormat returns the canonical marker hash under the
// requested content_hash_format code. Use this when the trie's home format is
// known explicitly and may differ from the process default (foreign-format
// trie inspection, cross-format diagnostic tools).
func DeletionMarkerHashForFormat(alg byte) (hash.Hash, error) {
	_, h, err := markerFor(alg)
	return h, err
}

// IsDeletionMarker reports whether a content hash refers to the canonical
// deletion marker. Format-relative: compares h against the marker hash
// recomputed under h's algorithm byte. O(1), no I/O. Handles foreign-format
// markers natively without a content-store load.
func IsDeletionMarker(h hash.Hash) bool {
	markerHash, err := DeletionMarkerHashForFormat(h.Algorithm)
	if err != nil {
		return false
	}
	return h == markerHash
}
