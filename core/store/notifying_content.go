package store

import (
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// NotifyingContentStore wraps a ContentStore and fires ContentStoreEvent
// when a NEW entity is stored (hash not previously present). Read operations
// and Remove pass through unchanged.
//
// Named content hooks run inline during Put, after the entity is stored but
// before Put returns (Phase 1 synchronous per SYSTEM-COMPOSITION v1.2
// section 2.2). Each hook can return a *ContentConsumerResult to halt the
// cascade (non-200 status) or nil for success.
//
// Hooks must be registered before the peer starts serving — not safe to call
// concurrently with Put.
type NotifyingContentStore struct {
	inner      ContentStore
	namedHooks []NamedContentHook
}

// NewNotifyingContentStore wraps inner and fires content-store events on new
// entity puts. The caller retains ownership of inner.
func NewNotifyingContentStore(inner ContentStore) *NotifyingContentStore {
	return &NotifyingContentStore{inner: inner}
}

// AddNamedContentHook registers a named synchronous callback that runs inline
// during each Put that introduces a new hash. Hooks are called in registration
// order. A non-200 return halts the cascade — remaining hooks are skipped.
//
// Consumer ordering per SYSTEM-COMPOSITION v1.2 section 2.2:
//
//	position 0: Persistence (durability before visibility)
//	position 1: Query content indexes (hash, type, reverse hash, field, zone)
func (n *NotifyingContentStore) AddNamedContentHook(name string, fn func(ContentStoreEvent) *ContentConsumerResult) {
	n.namedHooks = append(n.namedHooks, NamedContentHook{Name: name, Fn: fn})
}

// Put stores an entity and fires a content-store event if the entity's hash
// is new to the store. If the hash already exists, the put is idempotent and
// no event fires (no-op suppression per SYSTEM-COMPOSITION v1.2 section 1.1).
//
// Short-circuit (H-G3 fix B): when Has already returns true for the computed
// hash we skip inner.Put entirely. The cross-peer envelope-ingest path
// re-Puts the same identity + signature entities on every delivery; the
// inner SQLite Put goes through an INSERT-OR-REPLACE round-trip that is
// pure overhead in that regime. Skipping is safe because inner.Put on a
// pre-existing hash is documented to be a no-op (V7 §1.8 idempotent
// content store) and SqliteContentStore/MemoryContentStore both verify the
// claimed ContentHash matches the computed one — the Has check ensures the
// stored entity has data+type equivalent to the input (any divergence
// would not collide on content hash).
func (n *NotifyingContentStore) Put(e entity.Entity) (hash.Hash, error) {
	// Pre-compute the hash to check newness before the put. Use the
	// claimed Algorithm so SHA-384 entities verify against SHA-384
	// (v7.67 §2.3). Matches MemoryContentStore.Put — {type, data} only.
	computed, err := hash.ComputeFormat(e.ContentHash.Algorithm, e.Type, e.Data)
	if err != nil {
		// Fall through to inner.Put which will also fail with the same error.
		return n.inner.Put(e)
	}
	// Preserve the inner-Put mismatch check for the bad-claim case: a
	// caller that passes a non-zero ContentHash that doesn't match the
	// computed one is buggy and should surface the same error today's
	// code does. Let inner.Put run on mismatch.
	if !e.ContentHash.IsZero() && e.ContentHash != computed {
		return n.inner.Put(e)
	}

	if n.inner.Has(computed) {
		// Already stored — no Put, no event (V7 §1.8 idempotent + no-op
		// suppression per SYSTEM-COMPOSITION v1.2 §1.1).
		return computed, nil
	}

	h, err := n.inner.Put(e)
	if err != nil {
		return h, err
	}

	n.fireContentEvent(ContentStoreEvent{Hash: h, Entity: e, IsNew: true})

	return h, nil
}

// Get retrieves an entity by its content hash.
func (n *NotifyingContentStore) Get(h hash.Hash) (entity.Entity, bool) {
	return n.inner.Get(h)
}

// Has checks whether an entity with the given hash exists.
func (n *NotifyingContentStore) Has(h hash.Hash) bool {
	return n.inner.Has(h)
}

// Remove deletes an entity by its content hash. No event is fired on removal.
// (Content-store deletion events are deferred to a future GC proposal per
// PROPOSAL-CONTENT-STORE-EVENTS section 14.)
func (n *NotifyingContentStore) Remove(h hash.Hash) bool {
	return n.inner.Remove(h)
}

// Len returns the number of entities in the store.
func (n *NotifyingContentStore) Len() int {
	return n.inner.Len()
}

// fireContentEvent dispatches the event to named hooks in order. On the first
// non-200 return, remaining hooks are skipped (halt semantics).
func (n *NotifyingContentStore) fireContentEvent(evt ContentStoreEvent) {
	for _, hook := range n.namedHooks {
		result := hook.Fn(evt)
		if result != nil && result.Status != 0 && result.Status != 200 {
			break // halt remaining consumers
		}
	}
}
