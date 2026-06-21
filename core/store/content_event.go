package store

import (
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// ContentStoreEvent describes a new entity entering the content store.
// Fired once per entity hash — when the hash is first stored. Re-puts of
// an already-stored hash do not produce events (no-op suppression per
// SYSTEM-COMPOSITION v1.2 section 1.1).
//
// IsNew is always true today: NotifyingContentStore.Put gates the event
// emission on Put returning a not-already-present signal (see
// store/notifying_content.go). The field is surfaced per GUIDE-
// INSPECTABILITY v1.1 §2.1 #1 so observers don't have to dedup or assume
// the "fires only on new" contract — the contract is in the type.
type ContentStoreEvent struct {
	Hash   hash.Hash
	Entity entity.Entity
	IsNew  bool
}

// ContentConsumerResult is returned by content-store event consumers.
// nil or Status 0/200 means success; non-200 halts remaining consumers
// (same halt semantics as tree-event cascade per section 4.2).
type ContentConsumerResult struct {
	Status    uint
	ErrorCode string
	Message   string
}

// NamedContentHook pairs a consumer name with its callback. Names are
// stable identifiers used in cascade-halt responses (e.g., "persistence",
// "query-content-index"). Ordering follows SYSTEM-COMPOSITION v1.2 section 2.2:
// persistence at position 0, query content indexes at position 1.
type NamedContentHook struct {
	Name string
	Fn   func(ContentStoreEvent) *ContentConsumerResult
}
