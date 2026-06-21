package attestation

import (
	"sort"
	"sync"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Index maintains the four indexes mandated by EXTENSION-ATTESTATION §5.7 /
// §9.1: attesting, attested, properties.kind, supersedes. Index entries
// satisfy the I1-I5 invariants:
//
//   - I1: an attestation appears in all relevant indexes after the binding
//     write and before the next find_attestations_* call from the same
//     handler invocation can return.
//   - I2: index updates are atomic with the handler's tree write; failed
//     writes leave no partial state.
//   - I3: cross-handler consistency on the same peer.
//   - I4: revoked / superseded entries remain indexed; liveness filtering
//     happens at consumer layer via IsAttestationLive.
//   - I5: each attestation has at most one entry in the kind index;
//     attestations without a "kind" key are not in the kind index but are
//     still indexed by attesting/attested.
//
// Index is safe for concurrent use.
type Index struct {
	mu sync.RWMutex

	// byAttesting maps attesting hash to the set of attestation hashes
	// claiming it. Set-membership over hash → struct{} for O(1) add/remove.
	byAttesting map[hash.Hash]map[hash.Hash]struct{}
	byAttested  map[hash.Hash]map[hash.Hash]struct{}

	// byKind maps properties.kind values to attestation hashes. I5: only
	// attestations carrying a string-valued "kind" property appear here.
	byKind map[string]map[hash.Hash]struct{}

	// bySupersedes maps the predecessor hash to the set of successor
	// attestations that supersede it. Used by FindAttestationsWithSupersedes
	// (§5.6a) for forward-chain walks (FindLiveHead) and recursive liveness
	// (IsAttestationLive).
	bySupersedes map[hash.Hash]map[hash.Hash]struct{}

	// indexed holds the projection of each currently-bound attestation —
	// the four field values that determine its index entries — so removal
	// can locate the right buckets without re-decoding the entity.
	indexed map[hash.Hash]indexedEntry
}

type indexedEntry struct {
	attesting  hash.Hash
	attested   hash.Hash
	kind       string // empty if no "kind" key (I5)
	supersedes *hash.Hash
}

// NewIndex returns an empty Index.
func NewIndex() *Index {
	return &Index{
		byAttesting:  make(map[hash.Hash]map[hash.Hash]struct{}),
		byAttested:   make(map[hash.Hash]map[hash.Hash]struct{}),
		byKind:       make(map[string]map[hash.Hash]struct{}),
		bySupersedes: make(map[hash.Hash]map[hash.Hash]struct{}),
		indexed:      make(map[hash.Hash]indexedEntry),
	}
}

// Add records the attestation in all relevant indexes. Idempotent: re-adding
// the same hash leaves the index unchanged. If the entry's projection has
// changed (different attesting/attested/kind/supersedes for the same hash —
// not possible in practice since hash determines content, but guarded anyway)
// the old entry is removed first.
func (ix *Index) Add(attHash hash.Hash, att types.AttestationData) {
	entry := indexedEntry{
		attesting:  att.Attesting,
		attested:   att.Attested,
		kind:       att.Kind(),
		supersedes: att.Supersedes,
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if prev, ok := ix.indexed[attHash]; ok {
		if prev == entry {
			return
		}
		ix.removeLocked(attHash, prev)
	}
	ix.indexed[attHash] = entry
	addToBucket(ix.byAttesting, entry.attesting, attHash)
	addToBucket(ix.byAttested, entry.attested, attHash)
	if entry.kind != "" {
		addToStringBucket(ix.byKind, entry.kind, attHash)
	}
	if entry.supersedes != nil {
		addToBucket(ix.bySupersedes, *entry.supersedes, attHash)
	}
}

// Remove removes an attestation from all indexes. Idempotent.
func (ix *Index) Remove(attHash hash.Hash) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	entry, ok := ix.indexed[attHash]
	if !ok {
		return
	}
	ix.removeLocked(attHash, entry)
	delete(ix.indexed, attHash)
}

// Has returns whether the given attestation is currently indexed.
func (ix *Index) Has(attHash hash.Hash) bool {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	_, ok := ix.indexed[attHash]
	return ok
}

func (ix *Index) removeLocked(attHash hash.Hash, entry indexedEntry) {
	removeFromBucket(ix.byAttesting, entry.attesting, attHash)
	removeFromBucket(ix.byAttested, entry.attested, attHash)
	if entry.kind != "" {
		removeFromStringBucket(ix.byKind, entry.kind, attHash)
	}
	if entry.supersedes != nil {
		removeFromBucket(ix.bySupersedes, *entry.supersedes, attHash)
	}
}

// FindByAttesting returns all indexed attestations whose attesting field
// equals h. Returned slice is sorted by content_hash for deterministic order.
func (ix *Index) FindByAttesting(h hash.Hash) []hash.Hash {
	return ix.lookup(ix.byAttesting, h)
}

// FindByAttested returns all indexed attestations whose attested field
// equals h. Returned slice is sorted by content_hash.
func (ix *Index) FindByAttested(h hash.Hash) []hash.Hash {
	return ix.lookup(ix.byAttested, h)
}

// FindBySupersedes returns all indexed attestations whose supersedes field
// equals h (i.e., successors to h in any supersedes chain). Returned slice
// is sorted by content_hash.
func (ix *Index) FindBySupersedes(h hash.Hash) []hash.Hash {
	return ix.lookup(ix.bySupersedes, h)
}

// FindByKind returns all indexed attestations whose properties.kind equals
// kind. Returned slice is sorted by content_hash.
func (ix *Index) FindByKind(kind string) []hash.Hash {
	ix.mu.RLock()
	bucket, ok := ix.byKind[kind]
	if !ok {
		ix.mu.RUnlock()
		return nil
	}
	out := make([]hash.Hash, 0, len(bucket))
	for h := range bucket {
		out = append(out, h)
	}
	ix.mu.RUnlock()
	sortHashes(out)
	return out
}

func (ix *Index) lookup(m map[hash.Hash]map[hash.Hash]struct{}, h hash.Hash) []hash.Hash {
	ix.mu.RLock()
	bucket, ok := m[h]
	if !ok {
		ix.mu.RUnlock()
		return nil
	}
	out := make([]hash.Hash, 0, len(bucket))
	for k := range bucket {
		out = append(out, k)
	}
	ix.mu.RUnlock()
	sortHashes(out)
	return out
}

func addToBucket(m map[hash.Hash]map[hash.Hash]struct{}, key hash.Hash, val hash.Hash) {
	bucket, ok := m[key]
	if !ok {
		bucket = make(map[hash.Hash]struct{})
		m[key] = bucket
	}
	bucket[val] = struct{}{}
}

func removeFromBucket(m map[hash.Hash]map[hash.Hash]struct{}, key hash.Hash, val hash.Hash) {
	bucket, ok := m[key]
	if !ok {
		return
	}
	delete(bucket, val)
	if len(bucket) == 0 {
		delete(m, key)
	}
}

func addToStringBucket(m map[string]map[hash.Hash]struct{}, key string, val hash.Hash) {
	bucket, ok := m[key]
	if !ok {
		bucket = make(map[hash.Hash]struct{})
		m[key] = bucket
	}
	bucket[val] = struct{}{}
}

func removeFromStringBucket(m map[string]map[hash.Hash]struct{}, key string, val hash.Hash) {
	bucket, ok := m[key]
	if !ok {
		return
	}
	delete(bucket, val)
	if len(bucket) == 0 {
		delete(m, key)
	}
}

func sortHashes(s []hash.Hash) {
	sort.Slice(s, func(i, j int) bool {
		return hashLess(s[i], s[j])
	})
}

// hashLess provides deterministic ordering over hash.Hash values for tie-break
// per TV-A3 / TV-A5 ("lowest content_hash"). The comparison is byte-wise over
// the full 33-byte representation (algorithm byte first, then digest), which
// matches the cross-impl convention.
func hashLess(a, b hash.Hash) bool {
	ab := a.Bytes()
	bb := b.Bytes()
	for i := 0; i < len(ab) && i < len(bb); i++ {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return len(ab) < len(bb)
}
