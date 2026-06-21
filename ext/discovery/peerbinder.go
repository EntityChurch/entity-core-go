package discovery

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// PeerBinder is the real OOBBinder used by entity-peer/main.go — a small
// adapter over store.ContentStore + store.LocationIndex that materializes
// candidates at CandidateStoragePath and reaps the watchable-prefix
// binding per §3.0 / §3.0.1. Per §7, the content-store entity is NOT
// removed on reap — historical chain history is retained per the
// `candidate_history_retention` knob; operator MAY evict separately.
type PeerBinder struct {
	store         store.ContentStore
	locationIndex store.LocationIndex
}

// NewPeerBinder wires a binder over the peer's store + location-index.
func NewPeerBinder(cs store.ContentStore, li store.LocationIndex) *PeerBinder {
	return &PeerBinder{store: cs, locationIndex: li}
}

// Bind implements OOBBinder.
func (p *PeerBinder) Bind(backend string, ent entity.Entity) error {
	if _, err := p.store.Put(ent); err != nil {
		return fmt.Errorf("peerbinder: put candidate: %w", err)
	}
	path := types.CandidateStoragePath(backend, ent.ContentHash)
	if err := p.locationIndex.Set(path, ent.ContentHash); err != nil {
		return fmt.Errorf("peerbinder: set %s: %w", path, err)
	}
	return nil
}

// Reap implements OOBBinder. Removes the watchable-prefix binding; the
// stored entity is retained per §7. LocationIndex.Remove returns
// (priorHash, existed) — we ignore both: idempotent on already-reaped.
func (p *PeerBinder) Reap(backend string, candidateHash hash.Hash) error {
	path := types.CandidateStoragePath(backend, candidateHash)
	_, _ = p.locationIndex.Remove(path)
	return nil
}

// Get implements OOBBinder.
func (p *PeerBinder) Get(candidateHash hash.Hash) (entity.Entity, bool) {
	return p.store.Get(candidateHash)
}
