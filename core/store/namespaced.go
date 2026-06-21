package store

import (
	"strings"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// NamespacedIndex wraps a LocationIndex and canonicalizes paths per V7 §1.5:
// if a path is already qualified (has a peer-ID prefix), use it as-is;
// otherwise, prepend the local peer's namespace. This is the spec's shorthand
// rule — an unqualified path is implicitly scoped to the local peer.
//
// All paths in the store are qualified. There are no bare paths. List returns
// qualified paths. Consumers that need relative paths strip explicitly.
type NamespacedIndex struct {
	inner   LocationIndex
	localNS string // local peer ID as string
}

// NewNamespacedIndex creates a NamespacedIndex that wraps inner and
// canonicalizes paths using localNS as the local peer namespace.
func NewNamespacedIndex(inner LocationIndex, localNS string) *NamespacedIndex {
	return &NamespacedIndex{
		inner:   inner,
		localNS: localNS,
	}
}

// canonicalize applies V7 §1.4: if path is already absolute (starts with "/"),
// return as-is; otherwise prepend "/" + local namespace. The result is validated
// to ensure the first segment is a valid peer ID (structural invariant).
//
// Panics on invalid paths — this is defense-in-depth for internal bugs.
// External input is validated at the dispatch layer (protocol boundary) before
// reaching any handler. If this panic fires, it means a handler constructed an
// invalid path, which is a programming error that should be caught immediately.
func (n *NamespacedIndex) canonicalize(path string) string {
	var abs string
	if strings.HasPrefix(path, "/") {
		abs = path
	} else {
		abs = "/" + n.localNS + "/" + path
	}
	if err := ValidateAbsolutePath(abs); err != nil {
		panic("invalid tree path: " + err.Error() + " (path=" + abs + ")")
	}
	return abs
}

// --- LocationIndex interface (canonicalized) ---

func (n *NamespacedIndex) Set(path string, h hash.Hash) error {
	return n.inner.Set(n.canonicalize(path), h)
}

// SetWithContext canonicalizes the path and delegates to the inner
// LocationIndex's SetWithContext if it implements ContextualWriter,
// otherwise falls back to plain Set.
func (n *NamespacedIndex) SetWithContext(path string, h hash.Hash, ctx *MutationContext) (*CascadeResult, error) {
	abs := n.canonicalize(path)
	if cw, ok := n.inner.(ContextualWriter); ok {
		return cw.SetWithContext(abs, h, ctx)
	}
	return nil, n.inner.Set(abs, h)
}

func (n *NamespacedIndex) Get(path string) (hash.Hash, bool) {
	return n.inner.Get(n.canonicalize(path))
}

func (n *NamespacedIndex) Has(path string) bool {
	return n.inner.Has(n.canonicalize(path))
}

func (n *NamespacedIndex) Remove(path string) (hash.Hash, bool) {
	return n.inner.Remove(n.canonicalize(path))
}

// RemoveWithContext canonicalizes the path and delegates to the inner
// LocationIndex's RemoveWithContext if it implements ContextualWriter,
// otherwise falls back to plain Remove.
func (n *NamespacedIndex) RemoveWithContext(path string, ctx *MutationContext) (hash.Hash, bool, *CascadeResult) {
	abs := n.canonicalize(path)
	if cw, ok := n.inner.(ContextualWriter); ok {
		return cw.RemoveWithContext(abs, ctx)
	}
	h, ok := n.inner.Remove(abs)
	return h, ok, nil
}

// List honors the LocationIndex interface contract (store.go:184): empty
// prefix returns every binding in the inner store. The bare absolute root
// "/" is also a universal-tree scan and routes through the same path —
// neither carries a peer-id to canonicalize, both unambiguously mean "list
// everything."
//
// Non-empty prefixes go through canonicalize:
//   - peer-relative ("foo/bar"): prepended with the local peer's namespace.
//   - already-absolute starting with another peer-id ("/{otherPeer}/...")
//     passes through unchanged — the same way Set/Get/Has handle absolute
//     paths today (line 40-41).
//
// Pre-Amendment-5 this method canonicalized "" to "/<localPeer>/", silently
// returning local-only entries to callers that expected the documented
// global-scan semantic (query/maintainer.Rebuild, subscription/engine,
// attestation/handler, inbox). That violated the interface contract; this
// restores it.
func (n *NamespacedIndex) List(prefix string) []LocationEntry {
	if prefix == "" || prefix == "/" {
		return n.inner.List("")
	}
	return n.inner.List(n.canonicalize(prefix))
}

// LenPrefix follows the same contract: empty or bare-root prefix counts
// every binding in the inner store (store.go:184); non-empty prefixes
// canonicalize per Set/Get/Has.
func (n *NamespacedIndex) LenPrefix(prefix string) int {
	if prefix == "" || prefix == "/" {
		return n.inner.LenPrefix("")
	}
	return n.inner.LenPrefix(n.canonicalize(prefix))
}

func (n *NamespacedIndex) CompareAndSwap(path string, expected, new hash.Hash) error {
	return n.inner.CompareAndSwap(n.canonicalize(path), expected, new)
}

func (n *NamespacedIndex) CompareAndRemove(path string, expected hash.Hash) error {
	return n.inner.CompareAndRemove(n.canonicalize(path), expected)
}

// --- Namespace-aware methods ---

// GetNS retrieves a hash from an explicit namespace.
func (n *NamespacedIndex) GetNS(ns, path string) (hash.Hash, bool) {
	return n.inner.Get("/" + ns + "/" + path)
}

// SetNS stores a hash under an explicit namespace.
func (n *NamespacedIndex) SetNS(ns, path string, h hash.Hash) error {
	return n.inner.Set("/"+ns+"/"+path, h)
}

// HasNS checks whether a path exists in an explicit namespace.
func (n *NamespacedIndex) HasNS(ns, path string) bool {
	return n.inner.Has("/" + ns + "/" + path)
}

// RemoveNS removes a path from an explicit namespace.
func (n *NamespacedIndex) RemoveNS(ns, path string) (hash.Hash, bool) {
	return n.inner.Remove("/" + ns + "/" + path)
}

// ListNS lists entries under an explicit namespace with the given prefix.
func (n *NamespacedIndex) ListNS(ns, prefix string) []LocationEntry {
	return n.inner.List("/" + ns + "/" + prefix)
}

// LocalNS returns the local peer namespace (peer ID string).
func (n *NamespacedIndex) LocalNS() string {
	return n.localNS
}

// Qualify prepends the local namespace to a bare path.
func (n *NamespacedIndex) Qualify(path string) string {
	return n.canonicalize(path)
}

// QualifyTo builds an absolute path from a specific namespace and bare path.
func (n *NamespacedIndex) QualifyTo(ns, path string) string {
	return "/" + ns + "/" + path
}

// Inner returns the underlying LocationIndex. Use for operations that need
// direct access (debugging, raw iteration).
func (n *NamespacedIndex) Inner() LocationIndex {
	return n.inner
}
