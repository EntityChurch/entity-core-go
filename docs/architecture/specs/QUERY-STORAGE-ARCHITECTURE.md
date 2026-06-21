# Query Extension & Storage Architecture

Architecture for the query extension implementation and the storage composability
model it validates. The query extension is the first feature that requires secondary
indexes maintained synchronously with tree writes — making it the forcing function
for getting the storage architecture right.

**Status**: Design — approved for implementation
**Spec**: EXTENSION-QUERY.md v1.0

---

## 1. Current Storage Layer

### 1.1 Interfaces

Two interfaces define all storage in `core/store/`:

```go
// Content-addressed entity storage: Hash → Entity
type ContentStore interface {
    Put(e entity.Entity) (hash.Hash, error)
    Get(h hash.Hash) (entity.Entity, bool)
    Has(h hash.Hash) bool
    Remove(h hash.Hash) bool
    Len() int
}

// Mutable path→hash bindings (the tree)
type LocationIndex interface {
    Set(path string, h hash.Hash)
    Get(path string) (hash.Hash, bool)
    Has(path string) bool
    Remove(path string) (hash.Hash, bool)
    List(prefix string) []LocationEntry
}
```

Both are implementation-agnostic. Handlers receive them through `HandlerContext` and
never know what backend provides them.

### 1.2 Composition Stack

The location index is wrapped in layers, each adding a concern:

```
MemoryLocationIndex          raw storage (map[string]hash.Hash, RWMutex)
    ↓ wrapped by
NotifyingLocationIndex       emits TreeChangeEvent on Set/Remove
    ↓ wrapped by
NamespacedIndex              auto-prefixes paths with peerID
    ↓ presented as
LocationIndex to handlers    via HandlerContext
```

`MemoryContentStore` stands alone — no wrapping needed (hash-keyed, immutable puts).

### 1.3 Event Flow

`NotifyingLocationIndex` emits `TreeChangeEvent` on mutations:

```go
type TreeChangeEvent struct {
    Path         string     // Qualified path ({peerID}/path)
    PeerID       string     // Extracted from Path
    Hash         hash.Hash  // Current hash (zero for deletes)
    PreviousHash hash.Hash  // Previous hash (zero for creates)
    ChangeType   ChangeType // Created, Modified, Deleted
}
```

Events are sent **non-blocking** to a buffered channel. If the channel is full,
the event is dropped. This is acceptable for subscription delivery (best-effort)
but NOT for index maintenance (must be consistent).

---

## 2. What the Query Extension Needs

### 2.1 Secondary Indexes (Level 1)

Three indexes maintained on every tree change:

| Index | Key | Value | Maintenance Cost |
|-------|-----|-------|-----------------|
| **Type** | `type_name` | `set of {path, hash}` | O(1) per write |
| **Reverse Hash** | `referenced_hash` | `set of {source_path, source_type, field_name}` | O(hash_refs) per write |
| **Path Link** | `referenced_path` | `set of {source_path, source_type, field_name}` | O(path_refs) per write |

Level 2 adds **field indexes** — selective, per (type, field) configuration. Not in
initial implementation.

### 2.2 Consistency Requirement

From EXTENSION-QUERY.md §3.3:

> Index updates MUST be consistent with tree state: after a tree write returns
> successfully, subsequent queries MUST reflect the write.

Indexes must update **synchronously** with the write that triggers them. The current
async event channel cannot guarantee this.

### 2.3 Implementation-Level, Not Protocol-Level

Index maintenance is an implementation-level hook, not a protocol subscription
(EXTENSION-QUERY.md §3.2). Using protocol subscriptions would cause:

- **Recursion**: subscription entities are tree-bound and need indexing themselves
- **Staleness**: async delivery creates windows where queries lag behind writes
- **Complexity**: subscription/capability machinery for what is an internal concern

Indexes are projections of the tree — like the tree itself, they're internal
infrastructure maintained as things change.

---

## 3. Architecture

### 3.1 Synchronous Hooks

Extend `NotifyingLocationIndex` with synchronous hook callbacks:

```go
type NotifyingLocationIndex struct {
    inner     LocationIndex
    events    chan<- TreeChangeEvent
    done      <-chan struct{}
    syncHooks []func(TreeChangeEvent)  // NEW: run inline during write
}

func (n *NotifyingLocationIndex) AddSyncHook(fn func(TreeChangeEvent)) {
    n.syncHooks = append(n.syncHooks, fn)
}
```

On `Set()`: write to inner → build event → run all syncHooks(event) → emit to
async channel. Hooks run synchronously in the write path. When a write returns,
all sync hooks have completed — guaranteeing index consistency.

The async channel continues to serve subscription delivery and other best-effort
consumers. The sync hooks serve infrastructure that must be consistent.

### 3.2 Index Interfaces

```go
// TypeIndex maps entity type names to their tree locations.
type TypeIndex interface {
    Lookup(typeName string) []TypeIndexEntry        // exact match
    LookupGlob(pattern string) []TypeIndexEntry     // glob: "app/*"
    Count(typeName string) int
}

type TypeIndexEntry struct {
    Path string
    Hash hash.Hash
}

// ReverseHashIndex maps content hashes to entities that reference them.
type ReverseHashIndex interface {
    Lookup(h hash.Hash) []ReverseIndexEntry
}

type ReverseIndexEntry struct {
    SourcePath string
    SourceType string
    FieldName  string
}

// PathLinkIndex maps tree paths to entities that reference them.
type PathLinkIndex interface {
    Lookup(path string) []PathLinkEntry
}

type PathLinkEntry struct {
    SourcePath string
    SourceType string
    FieldName  string
}
```

These are read interfaces. Maintenance is internal to the implementation. The query
handler depends on these interfaces — never on how they're maintained.

### 3.3 Index Maintenance

An `IndexMaintainer` handles tree change events and updates all indexes:

```go
type IndexMaintainer struct {
    cs        store.ContentStore    // resolves hash → entity
    typeIdx   *MemoryTypeIndex
    reverseIdx *MemoryReverseHashIndex
    pathIdx   *MemoryPathLinkIndex
}

func (m *IndexMaintainer) OnTreeChange(evt store.TreeChangeEvent) {
    // Remove old entries (for update/delete)
    if evt.ChangeType == store.ChangeModified || evt.ChangeType == store.ChangeDeleted {
        if old, ok := m.cs.Get(evt.PreviousHash); ok {
            m.removeEntries(evt.Path, old)
        }
    }
    // Add new entries (for create/update)
    if evt.ChangeType == store.ChangeCreated || evt.ChangeType == store.ChangeModified {
        if ent, ok := m.cs.Get(evt.Hash); ok {
            m.addEntries(evt.Path, ent)
        }
    }
}
```

`OnTreeChange` is registered as a sync hook on `NotifyingLocationIndex`.
It captures the `ContentStore` reference needed to resolve entities.

### 3.4 Query Handler

The query handler lives at `ext/query/` and registers at `system/query`:

```go
type Handler struct {
    typeIdx    TypeIndex
    reverseIdx ReverseHashIndex
    pathIdx    PathLinkIndex
    cs         store.ContentStore  // for include_entities
}

// Operations: find, count
// Input: system/query/expression
// Output: system/query/result (find) or primitive/uint (count)
```

The handler depends only on index interfaces and ContentStore. It does not know
whether indexes are in-memory maps, SQL tables, or anything else.

### 3.5 Module Placement

```
core/store/          Index interfaces (TypeIndex, ReverseHashIndex, PathLinkIndex)
                     Sync hook extension on NotifyingLocationIndex
                     Entry types (TypeIndexEntry, ReverseIndexEntry, PathLinkEntry)

ext/query/           Query handler (system/query, find + count ops)
                     In-memory index implementations (MemoryTypeIndex, etc.)
                     Index maintainer (OnTreeChange → update indexes)
                     Entity data walker (extract hashes, path refs)

core/types/          Query type definitions (expression, predicate, result, match, constraints)

cmd/internal/validate/   Query validation suite
```

Index interfaces live in `core/store/` because they're projections of store state —
same conceptual level as LocationIndex. Index implementations and maintenance logic
live in `ext/query/` because they need entity walking and type awareness that pulls
in dependencies beyond what core/store should have.

### 3.6 Composition

```
                             ┌──────────────────┐
                             │  Query Handler   │  ext/query/
                             │  (find, count)   │
                             └───────┬──────────┘
                                     │ depends on
                 ┌───────────────────┼────────────────────┐
                 │                   │                    │
          ┌──────▼──────┐  ┌────────▼────────┐  ┌───────▼───────┐
          │ TypeIndex    │  │ ReverseHashIndex│  │ PathLinkIndex │
          │ (interface)  │  │ (interface)     │  │ (interface)   │
          └──────┬──────┘  └────────┬────────┘  └───────┬───────┘
                 │                  │                    │
          implemented by (swappable)│                    │
                 │                  │                    │
    ┌────────────┼──────────────────┼────────────────────┼───────────┐
    │  Memory tier                  │                    │           │
    │  MemoryTypeIndex (map)  MemoryReverseIdx (map) MemoryPathIdx │
    │  ← maintained via sync hooks on NotifyingLocationIndex        │
    └───────────────────────────────────────────────────────────────┘

    ┌───────────────────────────────────────────────────────────────┐
    │  SQLite tier (future)                                         │
    │  SqliteTypeIndex (table)  SqliteReverseIdx (table) ...       │
    │  ← maintained inline by SqliteStore or via same sync hooks    │
    └───────────────────────────────────────────────────────────────┘
```

The query handler is identical for both tiers. The peer builder composes the
appropriate implementations at construction time.

---

## 4. Persistence Strategy

### 4.1 Tiers

| Tier | Stores | Indexes | Target |
|------|--------|---------|--------|
| **Memory-only** | In-memory maps | In-memory maps | Tests, ephemeral peers, initial implementation |
| **SQLite** | SQL tables | SQL tables | Servers, desktop, workbench, production |

Go skips the intermediate persistence tier (journal/snapshot). Rust needs it for
WASM/browser where SQLite isn't available. Go targets native platforms where SQLite
is always available. No point reinventing B-trees and write-ahead logging.

### 4.2 Memory-Only (Current Focus)

- ContentStore: `MemoryContentStore` (existing)
- LocationIndex: `MemoryLocationIndex` (existing)
- Query indexes: `MemoryTypeIndex`, `MemoryReverseHashIndex`, `MemoryPathLinkIndex` (new)
- All maintained via sync hooks on `NotifyingLocationIndex`
- Lost on crash — acceptable for development, testing, validation

### 4.3 SQLite (Future)

- ContentStore: `SqliteContentStore` implementing the same interface
- LocationIndex: `SqliteLocationIndex` implementing the same interface
- Query indexes: SQL tables, maintained as part of store writes or via sync hooks
- Persistent across restarts, no index rebuild needed
- Everything in one database — no divergence between stores and indexes

When everything is in SQL, the indexes are just additional tables maintained
transactionally with the primary writes. The sync hook pattern still works (hook
writes to SQL instead of maps), or the SQLite store implementations can maintain
index tables directly since they own the database connection.

### 4.4 Why No Journal Tier

A journal (append-only log replayed on startup) adds complexity without solving
the right problem:

- Journal requires compaction to avoid unbounded growth
- Compaction requires snapshot logic — now you're building a database
- The in-memory + journal approach creates a sync problem: memory is truth during
  operation, journal is truth on restart, and they must agree
- SQLite already solves all of this with WAL, crash recovery, and ACID guarantees

For Go's deployment targets (servers, desktop, workbench), SQLite is universally
available. The memory tier handles development and testing. There's no gap that
a journal tier fills.

---

## 5. Index Rebuild

All indexes can be rebuilt from a full scan of tree + content store:

```go
func (m *IndexMaintainer) Rebuild(li store.LocationIndex, cs store.ContentStore) {
    m.typeIdx.Clear()
    m.reverseIdx.Clear()
    m.pathIdx.Clear()
    for _, entry := range li.List("") {  // all bindings
        if ent, ok := cs.Get(entry.Hash); ok {
            m.addEntries(entry.Path, ent)
        }
    }
}
```

This is O(all tree-bound entities). For memory-only tier, this runs on startup
if needed (milliseconds for typical datasets). For SQLite tier, indexes persist
and rebuild is only needed for recovery.

---

## 6. Entity Data Walking

Building the reverse hash and path link indexes requires walking entity data to
find references. This is the most complex part of index maintenance.

### 6.1 Reverse Hash Index

Walk CBOR data looking for byte strings that match the hash format (33 bytes:
1 algorithm byte + 32 digest bytes). Since entity data is `cbor.RawMessage`,
this is a structural CBOR walk, not a type-aware decode.

Strategy: scan CBOR recursively. When a byte string of length 33 is found with
algorithm byte 0x01 (SHA-256), record it as a hash reference. This is heuristic
but reliable — the probability of a false positive (random 33-byte string matching
the hash format) is negligible.

### 6.2 Path Link Index

Path references are typed: a field is a path reference only if its type definition
declares `type_ref: "system/tree/path"`. This requires type-aware decoding:

1. Look up the entity's type definition in the type registry
2. Walk the type's field definitions
3. For fields with `type_ref: "system/tree/path"`, extract the string value
4. For arrays/maps containing path-typed values, walk recursively

This shares infrastructure with type validation. For Level 1, a simpler approach
is acceptable: if an entity's type definition isn't available, skip path link
indexing for that entity. System types with known path fields can be handled
directly.

---

## 7. Wiring

### 7.1 Peer Construction (Memory Tier)

```go
// In cmd/entity-peer/main.go or peer builder:

// 1. Create stores
cs := store.NewMemoryContentStore()
li := store.NewMemoryLocationIndex()

// 2. Create index maintainer (captures cs reference)
maintainer := query.NewIndexMaintainer(cs)

// 3. Create peer — sync hook registered during construction
p, err := peer.New(
    peer.WithStore(cs),
    peer.WithLocationIndex(li),
    peer.WithSyncHook(maintainer.OnTreeChange),  // NEW option
    peer.WithHandler("system/query", query.NewHandler(
        maintainer.TypeIndex(),
        maintainer.ReverseHashIndex(),
        maintainer.PathLinkIndex(),
        cs,
    )),
)
```

### 7.2 Future SQLite Tier

```go
// Same shape, different implementations:
db := sqlite.Open("peer.db")
cs := sqlite.NewContentStore(db)
li := sqlite.NewLocationIndex(db)

// Indexes could be SQL-backed or still memory-backed with rebuild
maintainer := query.NewIndexMaintainer(cs)

p, err := peer.New(
    peer.WithStore(cs),
    peer.WithLocationIndex(li),
    peer.WithSyncHook(maintainer.OnTreeChange),
    peer.WithHandler("system/query", query.NewHandler(...)),
)
```

The peer builder, handler code, and extension code are identical. Only the
store/index implementations change.

---

## 8. Validation

The query validation suite (`cmd/internal/validate/`) tests:

1. **Handler manifest** — system/query registered with find + count ops
2. **Type queries** — find by type_filter, glob patterns
3. **Reference queries** — find by ref_filter (reverse hash lookup)
4. **Path link queries** — find by path_filter
5. **Prefix restriction** — path_prefix narrows results
6. **Pagination** — cursor, limit, has_more, total
7. **Capability filtering** — results respect caller's scope
8. **Count operation** — returns filtered total
9. **Error conditions** — type_filter_required, empty_query, invalid_cursor
10. **Conjunctive composition** — multiple filters AND together

Cross-peer validation confirms Go and Rust produce the same results for the same
queries against the same data.

---

*QUERY-STORAGE-ARCHITECTURE.md — Design document for Go query extension and
storage composability. Approved for implementation.*
