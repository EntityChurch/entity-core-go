package capability

import (
	"sync"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// CapabilityIndex maps capability token content hashes to their tree binding
// paths (V7 v7.62 §5.1 `capability_path_for(hash) → (path, bool)`).
//
// The index is **observational**: populated by recording bindings at the moment
// they happen, not derived from the cap's data. This is the scheme-agnostic
// strategy V7 §5.1 calls out — the verifier need not know any extension's path
// scheme because it recorded where it bound things.
//
// Callers that bind a `system/capability/token` to a tree path MUST also call
// Record(capHash, path) so revocation discovery can find the binding back.
// Callers that unbind MUST call Forget(capHash). The HandlerContext.TreeSet /
// TreeRemove wrappers do this automatically when the bound entity is a cap;
// direct LocationIndex callers (which should be rare) are responsible.
//
// PathFor returns (path, true) when a binding has been observed for the cap
// and the binding is still believed-live; (path, false) when no binding has
// been observed (wire-only cap). A `false` result is always safe — the
// is_revoked algorithm falls through to the marker check, which covers wire-
// only caps and provides defense in depth for the path-bound case.
type CapabilityIndex interface {
	Record(capHash hash.Hash, path string)
	Forget(capHash hash.Hash)
	PathFor(capHash hash.Hash) (string, bool)
}

// MemoryCapabilityIndex is the in-memory implementation of CapabilityIndex.
// Safe for concurrent use.
//
// A cap MAY be bound at multiple paths (e.g., a handler-self cap also bound
// at an extension-private path for bookkeeping). The index tracks the most
// recently recorded path; tree-unbind checks key on the cap's content hash
// regardless of which path is current, so any recorded path lets is_revoked
// observe a deletion at the bound location.
type MemoryCapabilityIndex struct {
	mu    sync.RWMutex
	paths map[hash.Hash]string
}

// NewMemoryCapabilityIndex constructs an empty in-memory capability index.
func NewMemoryCapabilityIndex() *MemoryCapabilityIndex {
	return &MemoryCapabilityIndex{paths: make(map[hash.Hash]string)}
}

// Record stores capHash → path. Overwrites any prior recording for capHash.
func (m *MemoryCapabilityIndex) Record(capHash hash.Hash, path string) {
	if capHash.IsZero() || path == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paths[capHash] = path
}

// Forget drops the recording for capHash. No-op if absent.
func (m *MemoryCapabilityIndex) Forget(capHash hash.Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.paths, capHash)
}

// PathFor returns the recorded path for capHash, or ("", false) when none.
func (m *MemoryCapabilityIndex) PathFor(capHash hash.Hash) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.paths[capHash]
	return p, ok
}

// nopCapabilityIndex is a no-op implementation used when no index is wired
// (manually-built test HandlerContexts, etc.). PathFor always returns false,
// so is_revoked falls through to the marker check — the always-safe path.
type nopCapabilityIndex struct{}

func (nopCapabilityIndex) Record(hash.Hash, string)            {}
func (nopCapabilityIndex) Forget(hash.Hash)                    {}
func (nopCapabilityIndex) PathFor(hash.Hash) (string, bool)    { return "", false }

// NopCapabilityIndex returns a CapabilityIndex that records nothing. Useful
// as a default when no index is wired; the is_revoked marker-check path
// covers correctness — only the binding-check defense-in-depth is lost.
func NopCapabilityIndex() CapabilityIndex { return nopCapabilityIndex{} }
