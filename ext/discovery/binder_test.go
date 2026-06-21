package discovery

import (
	"sync"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// memBinder is an in-memory OOBBinder used by ext/discovery tests. Real
// peer wiring (entity-peer/main.go) injects an adapter over peer.Store() +
// peer.LocationIndex(); the substrate-side behavior is identical.
type memBinder struct {
	mu       sync.Mutex
	store    map[hash.Hash]entity.Entity
	bindings map[string]hash.Hash // candidate-path → candidate hash
}

func newMemBinder() *memBinder {
	return &memBinder{
		store:    make(map[hash.Hash]entity.Entity),
		bindings: make(map[string]hash.Hash),
	}
}

func (m *memBinder) Bind(backend string, ent entity.Entity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[ent.ContentHash] = ent
	m.bindings[types.CandidateStoragePath(backend, ent.ContentHash)] = ent.ContentHash
	return nil
}

func (m *memBinder) Reap(backend string, candidateHash hash.Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bindings, types.CandidateStoragePath(backend, candidateHash))
	// store entry retained per §7 historical chain history knob.
	return nil
}

func (m *memBinder) Get(candidateHash hash.Hash) (entity.Entity, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ent, ok := m.store[candidateHash]
	return ent, ok
}

// boundPaths returns a snapshot of currently-bound watchable-prefix paths
// for a backend. Test-only.
func (m *memBinder) boundPaths(backend string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := types.CandidatePrefix(backend)
	var out []string
	for p := range m.bindings {
		if len(p) >= len(prefix) && p[:len(prefix)] == prefix {
			out = append(out, p)
		}
	}
	return out
}
