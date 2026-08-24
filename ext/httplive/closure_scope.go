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
	Store       store.ContentStore
	Index       store.LocationIndex
	LocalPeerID string

	// Head, when set, supplies the published-root the closure is built
	// for. It MUST be the same source MANIFEST_GET serves from.
	//
	// Without it there are two sources of truth for "the current head":
	// MANIFEST_GET reads the publisher's in-memory Current(), this scope
	// reads the location index. The publisher binds the index entry and
	// updates Current() at different instants, so the two disagree for a
	// window — and in that window a consumer holds manifest H1 while the
	// scope only admits H2's signature, so verifying the manifest it was
	// just served 404s. Rapid republishing made the window vanishingly
	// small; adding a debounce made it reproducible (v5_outbound_dial,
	// 2/2). One source of truth removes the class rather than narrowing
	// the window.
	Head func() (hash.Hash, bool)

	mu     sync.Mutex
	cached *closureSnapshot

	// recentSigs retains the signature hashes of recently-published heads.
	//
	// Verifying a manifest takes TWO requests: fetch the manifest, then
	// fetch its signature. If the publisher republishes between them, a
	// scope that admits only the current head's signature 404s the
	// signature for the manifest it just served — the consumer cannot
	// verify anything it is handed, through no fault of its own.
	//
	// This is why a debounce surfaced it. Publishing immediately on write
	// keeps republishes inside write bursts; deferring them moves the
	// publish into the quiet period where consumers are reading, landing
	// it between the two requests. The race predates the debounce; the
	// debounce just aimed it at the window that matters.
	//
	// Retaining a bounded history of our OWN signatures over our OWN
	// published roots leaks nothing and costs a few hashes.
	recentSigs  map[hash.Hash]struct{}
	recentSigsQ []hash.Hash
}

// recentSigRetention is how many past heads' signatures stay servable.
// Sized for "a consumer's manifest→signature round trip overlapping a
// republish", which is one or two heads; 16 is slack for a slow consumer
// against a busy publisher.
const recentSigRetention = 16

// rememberSig records a head signature as servable, evicting the oldest
// beyond recentSigRetention. Caller holds s.mu.
func (s *ClosureScope) rememberSig(h hash.Hash) {
	if s.recentSigs == nil {
		s.recentSigs = make(map[hash.Hash]struct{}, recentSigRetention)
	}
	if _, seen := s.recentSigs[h]; seen {
		return
	}
	s.recentSigs[h] = struct{}{}
	s.recentSigsQ = append(s.recentSigsQ, h)
	for len(s.recentSigsQ) > recentSigRetention {
		delete(s.recentSigs, s.recentSigsQ[0])
		s.recentSigsQ = s.recentSigsQ[1:]
	}
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
	var (
		head hash.Hash
		ok   bool
	)
	if s.Head != nil {
		head, ok = s.Head()
	} else {
		head, ok = s.Index.Get(types.PublishedRootStoragePath(s.LocalPeerID))
	}

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
		s.rememberSig(sigHash)
	} else {
		// Do NOT memoize a snapshot that is missing the head's signature.
		//
		// The snapshot is keyed by head, so caching an incomplete one here
		// makes it permanent until the head advances: the manifest is served
		// and its signature 404s for as long as the publisher stays quiet.
		// The publisher now binds the signature before the head to close the
		// window, and this is the second line of defence — an unmemoized
		// miss costs one extra walk and self-heals, a memoized one does not.
		return
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
	if members != nil {
		if _, ok := members[h]; ok {
			return true, nil
		}
	}
	// A signature over a recently-published head stays servable even after
	// the head moves on — otherwise a manifest handed out moments ago
	// becomes unverifiable mid-verification.
	s.mu.Lock()
	_, recent := s.recentSigs[h]
	s.mu.Unlock()
	return recent, nil
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
