package query

import (
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
)

// IndexMaintainer maintains secondary indexes in response to tree change events.
// It is registered as a synchronous hook on the NotifyingLocationIndex via
// peer.WithNamedSyncHook("query/index-maintainer", m.OnTreeChange).
type IndexMaintainer struct {
	cs         store.ContentStore
	typeIdx    *MemoryTypeIndex
	reverseIdx *MemoryReverseHashIndex
	pathIdx    *MemoryPathLinkIndex
}

// NewIndexMaintainer creates an IndexMaintainer that updates all three indexes.
// The ContentStore is needed to resolve entities from hashes during indexing.
func NewIndexMaintainer(cs store.ContentStore) *IndexMaintainer {
	return &IndexMaintainer{
		cs:         cs,
		typeIdx:    NewMemoryTypeIndex(),
		reverseIdx: NewMemoryReverseHashIndex(),
		pathIdx:    NewMemoryPathLinkIndex(),
	}
}

// TypeIndex returns the type index (read interface).
func (m *IndexMaintainer) TypeIndex() store.TypeIndex {
	return m.typeIdx
}

// ReverseHashIndex returns the reverse hash index (read interface).
func (m *IndexMaintainer) ReverseHashIndex() store.ReverseHashIndex {
	return m.reverseIdx
}

// PathLinkIndex returns the path link index (read interface).
func (m *IndexMaintainer) PathLinkIndex() store.PathLinkIndex {
	return m.pathIdx
}

// OnTreeChange processes a single tree change event and updates all indexes.
// This is designed to be registered as a named sync hook on
// NotifyingLocationIndex, ensuring indexes are consistent before the write
// returns. Returns nil (success) — query index maintenance never halts.
func (m *IndexMaintainer) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	// Remove old entries (for update/delete).
	if evt.ChangeType == store.ChangeModified || evt.ChangeType == store.ChangeDeleted {
		if !evt.PreviousHash.IsZero() {
			m.removeEntries(evt.Path, evt.PreviousHash)
		}
	}

	// Add new entries (for create/update).
	if evt.ChangeType == store.ChangeCreated || evt.ChangeType == store.ChangeModified {
		if !evt.Hash.IsZero() {
			m.addEntries(evt.Path, evt.Hash)
		}
	}
	return nil
}

// Rebuild clears all indexes and rebuilds from a full scan of the tree.
// O(all tree-bound entities). Use for recovery or startup with persisted stores.
func (m *IndexMaintainer) Rebuild(li store.LocationIndex) {
	m.typeIdx.Clear()
	m.reverseIdx.Clear()
	m.pathIdx.Clear()

	for _, entry := range li.List("") {
		m.addEntries(entry.Path, entry.Hash)
	}
}

func (m *IndexMaintainer) addEntries(path string, h hash.Hash) {
	ent, ok := m.cs.Get(h)
	if !ok {
		return
	}

	// Type index: always add.
	m.typeIdx.Add(ent.Type, path, h)

	// Reverse hash index: extract hash references from data.
	for _, ref := range extractHashRefs(ent.Data) {
		m.reverseIdx.Add(ref.Hash, path, ent.Type, ref.FieldName)
	}

	// Path link index: extract path references from known path fields.
	if fields, ok := knownPathFields[ent.Type]; ok {
		for _, ref := range extractPathRefs(ent.Data, fields) {
			m.pathIdx.Add(ref.Path, path, ent.Type, ref.FieldName)
		}
	}
}

func (m *IndexMaintainer) removeEntries(path string, h hash.Hash) {
	ent, ok := m.cs.Get(h)
	if !ok {
		// Entity no longer in content store — remove by path from all indexes.
		// Type index: we don't know the type, but we can try to remove by path.
		// This is a best-effort cleanup.
		m.reverseIdx.RemoveBySource(path)
		m.pathIdx.RemoveBySource(path)
		return
	}

	// Type index: remove exact entry.
	m.typeIdx.Remove(ent.Type, path, h)

	// Reverse hash index: remove all entries from this source path.
	m.reverseIdx.RemoveBySource(path)

	// Path link index: remove all entries from this source path.
	m.pathIdx.RemoveBySource(path)
}
