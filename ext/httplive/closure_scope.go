// closure_scope.go — EXTENSION-NETWORK §6.5.6 Amendment 10 served-set floor
// for a peer that advertises `signed_pointer` (PROPOSAL-PEER-MANIFEST-STATIC-
// HANDSHAKE). When a signed root is published, the served set MUST cover the
// transitive trie-node closure reachable from `published-root.root_hash`:
// the root node, every interior CHAMP sub-node, every leaf-bound value, plus
// the `published-root` entity itself and its authenticating signature.
//
// Why this is the floor and NamespaceScope alone is not: CHAMP interior
// nodes are hash-linked, not path-bound (V7 §1.7). A NamespaceScope only
// serves hashes bound under a content path, so `CONTENT_GET(root_hash)` 404s
// and a consumer's §1.1 hash-chain walk halts before the first node. This
// predicate derives its membership from the live published-root head, so it
// tracks the publisher automatically with no operator-maintained cap set.
//
// Cohort parity: this is the Go counterpart of Python's
// `entity_core.peer.serving.ClosureScope` and Rust's
// `core::peer::http_live::scope::ClosureScope` — same shape, same
// memoize-on-head pattern. Once Go + Rust ship `--serve-closure-root` the
// cohort orchestrator re-enables `--publish-root` and the three
// `published_root` probes (v4/v5/v7) convert from SKIP to PASS.

package httplive

import (
	"context"
	"sync"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// ClosureScope serves the transitive closure of the local peer's current
// signed published-root. Membership is memoized by head hash; the trie is
// re-walked only when the publisher advances the head. When no root is
// published the closure is empty — the route then serves nothing (identical
// 404, T4 — no presence oracle).
//
// Cross-impl contract:
//   - in-scope set = {head, signature-hash, transitive trie-node closure
//     reachable from head.root_hash}.
//   - tree-face: a path is in-scope iff its bound hash is in the closure.
//   - consumer-side hash-chain verification is impl-agnostic; the publisher
//     just has to cover the reachable hash set.
type ClosureScope struct {
	Store        store.ContentStore
	Index        store.LocationIndex
	LocalPeerID  string

	mu       sync.Mutex
	cached   *closureSnapshot
}

type closureSnapshot struct {
	head    hash.Hash
	members map[hash.Hash]struct{}
}

// refresh brings the cached snapshot into agreement with the current
// published-root head. Cheap when the head is unchanged (one location-index
// lookup + a compare); re-walks the trie only on head advance. Clears the
// cache when nothing is published so the predicate degrades to closed.
func (s *ClosureScope) refresh() {
	head, ok := s.Index.Get(types.PublishedRootStoragePath(s.LocalPeerID))

	s.mu.Lock()
	defer s.mu.Unlock()

	if !ok || head.IsZero() {
		s.cached = nil
		return
	}
	if s.cached != nil && s.cached.head == head {
		return
	}

	members := map[hash.Hash]struct{}{head: {}}

	if rootEntity, ok := s.Store.Get(head); ok {
		if data, err := types.PublishedRootDataFromEntity(rootEntity); err == nil {
			for h := range tree.CollectNodeClosure(s.Store, data.RootHash) {
				members[h] = struct{}{}
			}
		}
	}

	// The §5.2 invariant pointer holds the signature over `head`, signed by
	// the local peer. The publisher today writes signatures at the peer-
	// relative LocalSignaturePath; try the absolute invariant form first
	// (per spec), then fall back, so the lookup succeeds whichever form the
	// persistence layer stored.
	sigHash, sigOK := s.Index.Get(types.InvariantSignaturePath(s.LocalPeerID, head))
	if !sigOK {
		sigHash, sigOK = s.Index.Get(types.LocalSignaturePath(head))
	}
	if sigOK {
		members[sigHash] = struct{}{}
	}

	s.cached = &closureSnapshot{head: head, members: members}
}

func (s *ClosureScope) members() map[hash.Hash]struct{} {
	s.refresh()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil {
		return nil
	}
	return s.cached.members
}

// InScope reports whether h is in the current closure of the local peer's
// published-root.
func (s *ClosureScope) InScope(_ context.Context, h hash.Hash) (bool, error) {
	if h.IsZero() {
		return false, nil
	}
	members := s.members()
	if members == nil {
		return false, nil
	}
	_, ok := members[h]
	return ok, nil
}

// InScopePath resolves the local binding at path; the path is in-scope iff
// the bound hash is in the closure. Parent-only paths (no binding, only
// descendants) follow the NamespaceScope convention: in-scope if any
// descendant binding resolves to a closure member.
func (s *ClosureScope) InScopePath(ctx context.Context, path string) (bool, error) {
	if h, ok := s.Index.Get(path); ok {
		return s.InScope(ctx, h)
	}
	for _, e := range s.Index.List(path + "/") {
		ok, err := s.InScope(ctx, e.Hash)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
