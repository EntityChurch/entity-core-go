// EXTENSION-NETWORK v1.4 Amendment 5 — HTTP serving-mode read routes.
//
// Three route families on the read surface. Every URL is a concrete object
// key — no trailing-slash listing form, no redirects (both broken on real
// static CDNs per the index-document + slash-normalization hazards the spec
// works through).
//
//	GET /content/{hex33(H)}                    CONTENT_GET   — content-by-hash
//	GET /manifest                              MANIFEST_GET  — singular, terminal
//	GET /peers{tree_listing_suffix}            TREE_GET      — universal-tree-root listing
//	GET /{peer_id}{tree_listing_suffix}        TREE_GET      — peer-root listing
//	GET /{peer_id}/{path}{tree_leaf_suffix}    TREE_GET      — entity at path
//	GET /{peer_id}/{path}{tree_listing_suffix} TREE_GET      — listing at path
//
// Defaults: tree_leaf_suffix=".bin", tree_listing_suffix=".list" — REQUIRED
// distinct. The two-suffix append-one/strip-one bijection is total for any
// name: entity `foo`→`foo.bin`, listing `foo`→`foo.list`, entity `foo.bin`→
// `foo.bin.bin`, listing `foo.bin`→`foo.bin.list`, all distinct.
//
// First-segment demux is **literal-then-peer-id-parse** (§6.5.6) — not a
// length threshold. The reserved literals `{content, manifest, peers}` are
// short ASCII; peer-ids parse as ≥46-char base58 multibase; the gap between
// them makes the check literal-or-parse, never both.
//
// Auth model (Amendment 5 §6.5.6 §5A): the request carries no auth — the
// client may not speak the protocol. The served scope IS the authorization,
// expressed as a `serve_scope` capability token evaluated by the SAME cap
// evaluator the live-EXECUTE surface uses. CapTokenScope is the recommended
// `ScopePredicate`; NamespaceScope/WholeStoreScope are warned escape hatches
// (second ACL machinery — operator owns the live↔serving consistency).
//
// Cache discipline (Amendment 5 / Amendment 4):
//   - /content/{hex} — Cache-Control: immutable, max-age long (hash addresses
//     bytes; the bytes that hash to it cannot change).
//   - /tree/...     — listings + entity bindings are MUTABLE; MUST NOT mark
//     immutable.
//   - /manifest     — manifest is mutable (revocation lives here); MUST NOT
//     mark immutable.

package httplive

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Defaults per EXTENSION-NETWORK Amendment 5 §6.5.3 endpoint.
const (
	DefaultLeafSuffix    = ".bin"
	DefaultListingSuffix = ".list"
)

// ReservedPeersWord is the §6.5.6 demux literal for the universal-tree-root
// listing — `peers{tree_listing_suffix}` (`peers.list` by default).
const ReservedPeersWord = "peers"

// peerIDMinLength is the literal-vs-parse guard: peer-ids in base58 multibase
// run ≥46 chars; the reserved-word literals are far shorter. We pre-check the
// length before attempting a base58 parse to fail fast on the short literals
// and on malformed input.
const peerIDMinLength = 46

// ScopePredicate decides whether a given content hash OR tree path is in
// the serving-side published-set. Out-of-scope answers return an identical
// 404 to not-held (Amendment 4 §1.3 T4 — no presence oracle).
//
// Two methods because Amendment 5 has two axes of address:
//   - InScope(h)      — content-keyed. /content/{hex33(H)} hits this.
//   - InScopePath(p)  — path-keyed. /{peer_id}/{path}.bin|.list hit this
//     for entity resolution + per-child listing filtering.
//
// Implementations (in order of preference):
//   - CapTokenScope    — RECOMMENDED. `serve_scope` is a literal cap token;
//     evaluator is shared with live-EXECUTE (`capability.CheckPathPermission`).
//     One ACL machinery; drift impossible. Amendment 5 §5A.
//   - NamespaceScope   — Escape hatch. §6.4.2 Hash Tree Presence; SECOND ACL
//     machinery — operator owns live↔serving consistency.
//   - WholeStoreScope  — Debug-only.
type ScopePredicate interface {
	InScope(ctx context.Context, h hash.Hash) (bool, error)
	InScopePath(ctx context.Context, path string) (bool, error)
}

// NamespaceScope serves H iff the local tree binds an entity at
// `{namespace}/{hex33(H)}`. Per CONTENT §6.4.2 Hash Tree Presence.
//
// **Second ACL machinery warning (Amendment 5):** this predicate is its own
// ACL surface separate from the live-EXECUTE cap evaluator. Drift between
// what the live surface enforces and what this scope exposes is the operator's
// responsibility to prevent. Prefer CapTokenScope for new deployments.
type NamespaceScope struct {
	Index     store.LocationIndex
	Namespace string // e.g. "system/content/public"
}

// InScope returns true iff a tree binding exists at Namespace/{hex33(H)}.
func (s NamespaceScope) InScope(_ context.Context, h hash.Hash) (bool, error) {
	if s.Namespace == "" {
		return false, fmt.Errorf("namespace scope: empty namespace")
	}
	if h.IsZero() {
		return false, nil
	}
	bindingPath := strings.TrimRight(s.Namespace, "/") + "/" + hex.EncodeToString(h.Bytes())
	return s.Index.Has(bindingPath), nil
}

// InScopePath resolves the path's bound hash and delegates to InScope. For
// parent-only paths (no binding, only descendants), returns true if any
// descendant is in scope. This preserves the Amendment 4 hash-keyed
// semantics on the path-keyed seam.
func (s NamespaceScope) InScopePath(ctx context.Context, path string) (bool, error) {
	if h, ok := s.Index.Get(path); ok {
		return s.InScope(ctx, h)
	}
	// Parent-only path: check if ANY descendant binding is in scope.
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

// WholeStoreScope is the debug opt-in: every H in the local content-store is
// served. Operator owns the consequence (T2/T3 caveats). Logs a startup
// warning when enabled.
type WholeStoreScope struct{}

// InScope always returns true.
func (WholeStoreScope) InScope(_ context.Context, _ hash.Hash) (bool, error) {
	return true, nil
}

// InScopePath always returns true (debug scope).
func (WholeStoreScope) InScopePath(_ context.Context, _ string) (bool, error) {
	return true, nil
}

// PollHandler serves the Amendment 5 read surface. Mount under the operator's
// chosen Prefix (empty for a top-level mount, "/poll" for same-listener
// composition with the live POST surface via ComposedHandler).
type PollHandler struct {
	// Prefix is the path prefix this handler is mounted under, with leading
	// slash and no trailing slash. Empty means top-level mount.
	Prefix string

	// Store is the local content-store. Required.
	Store store.ContentStore

	// Index is the local location-index. Required for tree path resolution.
	Index store.LocationIndex

	// Scope gates content lookups + listing entries. Required.
	Scope ScopePredicate

	// LocalPeerID is the peer this handler serves. Used to validate the
	// {peer_id} segment on tree URLs and to canonicalize paths to the
	// NamespacedIndex's absolute form. Required.
	LocalPeerID crypto.PeerID

	// LeafSuffix is `tree_leaf_suffix` from the endpoint profile (§6.5.3 /
	// Amendment 5). Default ".bin". MUST differ from ListingSuffix.
	LeafSuffix string

	// ListingSuffix is `tree_listing_suffix` from the endpoint profile.
	// Default ".list". MUST differ from LeafSuffix.
	ListingSuffix string

	// Manifest is the published manifest wire entity for this peer (signed
	// pointer over the published root). Nil means no manifest published —
	// MANIFEST_GET returns 404.
	Manifest *entity.Entity

	// ManifestProvider, when non-nil, is called on every MANIFEST_GET to
	// fetch the current manifest. Used by the published-root publisher to
	// serve the most recently signed root without the operator re-pointing
	// the field on every root change. Returns nil to fall back to the static
	// Manifest field (or 404 if both are nil).
	ManifestProvider func() *entity.Entity
}

// currentManifest returns the manifest to serve for this request. Prefers
// ManifestProvider (live) over the static Manifest field; nil means 404.
func (h *PollHandler) currentManifest() *entity.Entity {
	if h.ManifestProvider != nil {
		if e := h.ManifestProvider(); e != nil {
			return e
		}
	}
	return h.Manifest
}

// NewPollHandler constructs a PollHandler with the given scope predicate and
// default Amendment 5 suffixes. Prefix is normalized to leading-slash /
// no-trailing-slash (empty stays empty). Panics if local-peer-id is empty.
func NewPollHandler(prefix string, st store.ContentStore, idx store.LocationIndex, scope ScopePredicate, localPeerID crypto.PeerID) *PollHandler {
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		prefix = strings.TrimRight(prefix, "/")
	}
	if string(localPeerID) == "" {
		panic("httplive.NewPollHandler: LocalPeerID required (Amendment 5 — tree URLs are peer-id-keyed)")
	}
	return &PollHandler{
		Prefix:        prefix,
		Store:         st,
		Index:         idx,
		Scope:         scope,
		LocalPeerID:   localPeerID,
		LeafSuffix:    DefaultLeafSuffix,
		ListingSuffix: DefaultListingSuffix,
	}
}

// validateSuffixes returns an error if the two suffixes don't satisfy
// Amendment 5's "REQUIRED distinct" rule. Called once before the demux.
func (h *PollHandler) validateSuffixes() error {
	if h.LeafSuffix == "" || h.ListingSuffix == "" {
		return fmt.Errorf("both LeafSuffix and ListingSuffix must be non-empty")
	}
	if h.LeafSuffix == h.ListingSuffix {
		return fmt.Errorf("LeafSuffix (%q) must differ from ListingSuffix (%q) — Amendment 5", h.LeafSuffix, h.ListingSuffix)
	}
	return nil
}

// ServeHTTP implements http.Handler. Amendment 5 demux: literal-or-peer-id-parse
// on the first path segment; reserved literals are short ASCII, peer-ids are
// long base58.
func (h *PollHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.validateSuffixes(); err != nil {
		http.Error(w, "handler misconfigured: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Strip handler prefix; mismatch → 404.
	path := r.URL.Path
	if h.Prefix != "" {
		if !strings.HasPrefix(path, h.Prefix+"/") && path != h.Prefix {
			http.NotFound(w, r)
			return
		}
		path = strings.TrimPrefix(path, h.Prefix)
		if path == "" {
			path = "/"
		}
	}

	// Status table per §6.5.3.1 / Amendment 5 Edit D:
	//
	//   %2F (URL-encoded "/") in a path component is malformed: it would
	//   smuggle a slash through the URI delimiter into a single segment.
	//   r.URL.EscapedPath() preserves the literal encoding; check there.
	if strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%2f") {
		http.Error(w, "invalid URL: percent-encoded slash in path segment", http.StatusBadRequest)
		return
	}

	// Strip the leading slash to expose the first segment.
	path = strings.TrimPrefix(path, "/")

	// First segment + remainder.
	first, rest, hasRest := strings.Cut(path, "/")

	// Amendment 5 §6.5.6 demux — literal-or-peer-id-parse:
	switch {
	case first == "content":
		// CONTENT_GET — `content/{hex33}` only. Anything else → 404.
		if !hasRest || rest == "" {
			http.NotFound(w, r)
			return
		}
		// content/{hex} must be a terminal route — no further path segments.
		if strings.Contains(rest, "/") {
			http.NotFound(w, r)
			return
		}
		h.serveContent(w, r, rest)
		return

	case first == "manifest":
		// MANIFEST_GET — terminal; any rest (including "" trailing slash)
		// is 404.
		if hasRest {
			http.NotFound(w, r)
			return
		}
		h.serveManifest(w, r)
		return

	case first == ReservedPeersWord+h.ListingSuffix:
		// Universal-tree-root listing.
		if hasRest {
			http.NotFound(w, r)
			return
		}
		h.serveAllPeersListing(w, r)
		return

	case first == ReservedPeersWord:
		// Bare `peers` (no suffix) — 404 (a listing MUST carry its suffix).
		http.NotFound(w, r)
		return
	}

	// Try the first segment as a peer-id (or peer_id+listing_suffix).
	peerID, isRoot, ok := h.parsePeerSegment(first)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if isRoot {
		// `{peer_id}.list` form — peer-root listing. Any rest → 404.
		if hasRest {
			http.NotFound(w, r)
			return
		}
		h.serveTreeListing(w, r, peerID, "")
		return
	}

	// `{peer_id}/{path}{suffix}` form. The remainder must end in a
	// recognized suffix to be a valid leaf or listing address; otherwise 404
	// (bare no-suffix path is not a valid address — Amendment 5 §6.5.3.1).
	if !hasRest || rest == "" {
		// `{peer_id}` alone (no slash) was already covered by the root-form
		// branch above. `{peer_id}/` with empty rest is no-suffix → 404.
		http.NotFound(w, r)
		return
	}
	stem, intent, ok := h.stripSuffix(rest)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch intent {
	case "entity":
		h.serveTreeEntity(w, r, peerID, stem)
	case "listing":
		h.serveTreeListing(w, r, peerID, stem)
	}
}

// parsePeerSegment classifies the first URL segment:
//   - if it's a peer-id-shaped string, returns (peer-id, false=non-root-form, true)
//   - if it's `{peer_id}{ListingSuffix}` (peer-root listing form), returns
//     (peer-id, true=root-form, true)
//   - otherwise (false, false, false)
//
// Strips at most one recognized listing suffix from the segment before the
// base58 length check — the peer-root form is the only case where the segment
// contains both a peer-id and a suffix.
func (h *PollHandler) parsePeerSegment(seg string) (peerID string, isRoot bool, ok bool) {
	// Try the suffixed peer-root form first (longer match wins for the
	// bijection — see Amendment 5 §6.5.3.1).
	if strings.HasSuffix(seg, h.ListingSuffix) {
		candidate := strings.TrimSuffix(seg, h.ListingSuffix)
		if looksLikePeerIDSegment(candidate) {
			return candidate, true, true
		}
	}
	if looksLikePeerIDSegment(seg) {
		return seg, false, true
	}
	return "", false, false
}

// stripSuffix implements append-one/strip-one over the two-suffix set.
// Returns (stem, "entity"|"listing", true) or (rest, "", false) if no
// recognized suffix. The longer of the two suffixes is checked first — for
// the default ".bin"/".list" the length is identical so order doesn't matter;
// operators picking overlapping custom suffixes get longer-match-wins.
func (h *PollHandler) stripSuffix(path string) (stem, intent string, ok bool) {
	// Order longer-first so e.g. (".bin", ".bing") wouldn't misroute
	// `foo.bing` to entity intent. With distinct suffixes the bijection is
	// total regardless.
	if len(h.ListingSuffix) >= len(h.LeafSuffix) {
		if strings.HasSuffix(path, h.ListingSuffix) {
			return strings.TrimSuffix(path, h.ListingSuffix), "listing", true
		}
		if strings.HasSuffix(path, h.LeafSuffix) {
			return strings.TrimSuffix(path, h.LeafSuffix), "entity", true
		}
	} else {
		if strings.HasSuffix(path, h.LeafSuffix) {
			return strings.TrimSuffix(path, h.LeafSuffix), "entity", true
		}
		if strings.HasSuffix(path, h.ListingSuffix) {
			return strings.TrimSuffix(path, h.ListingSuffix), "listing", true
		}
	}
	return path, "", false
}

// serveContent — Amendment 4 §6.5.3 (unchanged in Amendment 5). Body is the
// bare hashable form ECF({type,data}); SHA-256(body)==H.digest holds.
func (h *PollHandler) serveContent(w http.ResponseWriter, r *http.Request, hexHash string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(hexHash) != hex.EncodedLen(hash.HashSize) {
		http.Error(w, "invalid hash: wrong length (expected 66 hex chars)", http.StatusBadRequest)
		return
	}
	raw, err := hex.DecodeString(hexHash)
	if err != nil {
		http.Error(w, "invalid hash: not hex", http.StatusBadRequest)
		return
	}
	H, err := hash.FromBytes(raw)
	if err != nil {
		http.Error(w, "invalid hash: "+err.Error(), http.StatusBadRequest)
		return
	}
	inScope, err := h.Scope.InScope(r.Context(), H)
	if err != nil {
		http.Error(w, "scope check failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !inScope {
		http.NotFound(w, r)
		return
	}
	ent, ok := h.Store.Get(H)
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := ecf.EncodeHashable(ent.Type, ent.Data)
	if err != nil {
		http.Error(w, "encode hashable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", `"`+hexHash+`"`)
	w.Header().Set("Content-Length", contentLengthOf(body))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// serveTreeEntity — EXTENSION-NETWORK §6.5.3.1 leaf branch, post-Amendment-6.
// Address: `{tree_prefix}/{peer_id}/{stem}{tree_leaf_suffix}`. The tree is
// `path → hash` (V7 §1.7; EXTENSION-TREE §1); the leaf route returns the
// **bound hash** as a `system/hash` 2-key bare pointer
// `ECF({type:"system/hash", data: H})`, NOT the dereferenced entity. This is
// exactly `tree:get mode:"hash"` (V7 §1.7) exposed over HTTP — the consumer
// reads `H` from `data` and second-hops `CONTENT_GET /content/{hex33(H)}` for
// the entity bytes.
//
// Why the pointer (not the dereferenced entity): returning the entity at
// every tree URL materializes a separate copy per path bound to the same
// hash, defeating V7 §1.7's content-store dedup invariant — a static CDN
// has no content-awareness and cannot recover the dedup. The dereferenced
// default-mode `tree:get` remains available in-process and over live `http`
// EXECUTE.
//
// Out-of-scope and unbound both 404 (T4 — identical body).
func (h *PollHandler) serveTreeEntity(w http.ResponseWriter, r *http.Request, peerID, stem string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject `{peer_id}.bin` (stem == "") — peer-id itself has no entity
	// bound (it's a namespace root, not a leaf). Amendment 5 status table:
	// 404.
	if stem == "" {
		http.NotFound(w, r)
		return
	}

	lookupPath := "/" + peerID + "/" + stem
	resolvedH, ok := h.Index.Get(lookupPath)
	if !ok {
		http.NotFound(w, r)
		return
	}
	inScope, err := h.Scope.InScope(r.Context(), resolvedH)
	if err != nil {
		http.Error(w, "scope check failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !inScope {
		http.NotFound(w, r)
		return
	}

	// Build the system/hash pointer: 2-key bare form
	// `ECF({type: "system/hash", data: <CBOR-bstr-of-33-byte-hash>})`. Per
	// Amendment 6 §8 + exploration EXPLORATION-TREE-LEAF-HASH-POINTER-AND-
	// UNIVERSAL-NAMESPACE §1.4 (2-key, not 3-key: a path-
	// addressed pointer has no useful self-content_hash, and a 3-key body
	// would carry two hashes — the bound `data` and the pointer's own
	// `content_hash` — forcing the consumer to disambiguate).
	dataCbor, err := ecf.Encode(resolvedH.Bytes())
	if err != nil {
		http.Error(w, "encode pointer data: "+err.Error(), http.StatusInternalServerError)
		return
	}
	body, err := ecf.EncodeHashable("system/hash", cbor.RawMessage(dataCbor))
	if err != nil {
		http.Error(w, "encode pointer: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/cbor")
	// Tree bindings are mutable; no immutable hint. Amendment 4 §6.5.3.1.
	// ETag = the bound hash (changes on rebind = correct mutable cache key),
	// NOT the pointer's self-hash. Amendment 6 (adversarial-review polish).
	w.Header().Set("ETag", `"`+hex.EncodeToString(resolvedH.Bytes())+`"`)
	w.Header().Set("Content-Length", contentLengthOf(body))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// serveTreeListing — Amendment 5 §6.5.3.1 listing branch + §6.5.6 scope-gating.
// Address: `{tree_prefix}/{peer_id}/{stem}{tree_listing_suffix}` (or `{peer_id}{listing_suffix}`
// for the root form, in which case stem == "").
//
// Renders the existing `system/tree/listing` entity (V7 §3.9): direct
// children of the prefix; entries filtered to in-scope; count = in-scope
// filtered total (TREE §1176 — never the raw subtree total). Out-of-scope or
// non-existent prefix returns identical 404 (T4). Empty in-scope prefix
// returns 200 + entries={} + count=0 (Amendment 5 Q2).
func (h *PollHandler) serveTreeListing(w http.ResponseWriter, r *http.Request, peerID, stem string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build the absolute prefix the index will walk.
	prefix := "/" + peerID
	if stem != "" {
		prefix += "/" + stem
	}

	// Walk the index for direct children of prefix, scope-gated.
	entries, total, exists, err := h.collectChildren(r.Context(), prefix)
	if err != nil {
		http.Error(w, "listing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		// Prefix has no bindings under it AND no entity bound at prefix
		// itself — indistinguishable from out-of-scope. Identical 404 (T4).
		http.NotFound(w, r)
		return
	}

	// Render the system/tree/listing entity. NextPage left nil (single page;
	// pagination by next_page chain is a publish-pipeline concern, not the
	// live-serving impl).
	listingPath := strings.TrimPrefix(prefix, "/")
	listingData := types.ListingData{
		Path:    listingPath,
		Entries: entries,
		Count:   uint64(total),
		Offset:  0,
	}
	ent, err := listingData.ToEntity()
	if err != nil {
		http.Error(w, "encode listing: "+err.Error(), http.StatusInternalServerError)
		return
	}
	body, err := ecf.Encode(ent)
	if err != nil {
		http.Error(w, "encode listing entity: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	// Listing is a mutable view; no immutable hint (re-rendered on subtree
	// change). Amendment 5 §6.5.3.1.
	w.Header().Set("ETag", `"`+hex.EncodeToString(ent.ContentHash.Bytes())+`"`)
	w.Header().Set("Content-Length", contentLengthOf(body))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// collectChildren walks the LocationIndex for direct children of prefix.
// Returns: a name → listing-entry map (entries within scope), the filtered
// total (TREE §1176), and a bool indicating whether ANY child or entity-at-
// prefix exists. The bool drives the T4 404 vs 200-empty discrimination.
//
// Scope check policy: for entries where a hash is bound, the entry is
// included iff the bound hash is in-scope. For entries that are only parent
// paths (has_children=true, hash=nil), the entry is included iff ANY
// descendant binding is in-scope. The current implementation includes
// parent-only entries unconditionally and relies on the recursive call when
// the consumer drills in; tightening this to "in-scope iff any in-scope
// descendant" is a follow-on (TREE §1176 strict reading).
func (h *PollHandler) collectChildren(ctx context.Context, prefix string) (map[string]interface{}, int, bool, error) {
	// Build the trailing-slash form so List() returns only descendants.
	walkPrefix := prefix
	if !strings.HasSuffix(walkPrefix, "/") {
		walkPrefix = walkPrefix + "/"
	}
	all := h.Index.List(walkPrefix)
	if len(all) == 0 {
		// No descendants. Check whether an entity is bound AT prefix
		// itself — that still makes the path "exist" (TREE §2.2 allows
		// entity-at-path-with-no-children). If neither, return !exists.
		_, hasSelf := h.Index.Get(prefix)
		return map[string]interface{}{}, 0, hasSelf, nil
	}

	// Aggregate by direct child name. For each binding under walkPrefix:
	//   rel := strings.TrimPrefix(binding.Path, walkPrefix)
	//   childName := first path segment of rel
	//   if rel == childName: this binding IS the child entity
	//   else (rel == childName + "/" + more): the child has descendants
	type aggEntry struct {
		hash        *hash.Hash
		hasChildren bool
	}
	agg := make(map[string]*aggEntry)
	for _, e := range all {
		rel := strings.TrimPrefix(e.Path, walkPrefix)
		if rel == "" {
			// Shouldn't happen — List(walkPrefix) returns descendants.
			continue
		}
		childName, more, hasMore := strings.Cut(rel, "/")
		a, ok := agg[childName]
		if !ok {
			a = &aggEntry{}
			agg[childName] = a
		}
		if !hasMore {
			// Direct binding at walkPrefix/childName — capture the hash if
			// in scope.
			inScope, err := h.Scope.InScope(ctx, e.Hash)
			if err != nil {
				return nil, 0, false, err
			}
			if inScope {
				hCopy := e.Hash
				a.hash = &hCopy
			}
		} else {
			_ = more
			a.hasChildren = true
		}
	}

	// Materialize entries in sorted key order. ECF map ordering is
	// canonical-by-key; emitting sorted is conformance for the in-process
	// hash check + makes diff-by-eye stable.
	names := make([]string, 0, len(agg))
	for n := range agg {
		names = append(names, n)
	}
	sort.Strings(names)
	entries := make(map[string]interface{}, len(names))
	for _, name := range names {
		a := agg[name]
		// Skip entries that are neither in-scope-bound nor have children
		// (i.e. the only binding underneath was out-of-scope; we don't
		// surface it — TREE §1176).
		if a.hash == nil && !a.hasChildren {
			continue
		}
		// Build the entry — listing-entry: {hash?, has_children}.
		entry := map[string]interface{}{
			"has_children": a.hasChildren,
		}
		if a.hash != nil {
			entry["hash"] = *a.hash
		}
		entries[name] = entry
	}

	return entries, len(entries), true, nil
}

// serveAllPeersListing — Amendment 5 §6.5.6: `peers.list` returns the universal-
// tree-root listing — every peer-id segment for which the local index holds
// at least one binding. Scope-gated like any other listing.
func (h *PollHandler) serveAllPeersListing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Walk every binding in the index — the bare absolute root "/" is the
	// universal-tree root (NamespacedIndex.List special-cases it to bypass
	// local-namespace canonicalization). For each binding: the leading
	// segment is the peer-id; aggregate by that to produce the all-peers
	// listing.
	all := h.Index.List("/")
	type aggEntry struct {
		hash        *hash.Hash
		hasChildren bool
	}
	agg := make(map[string]*aggEntry)
	for _, e := range all {
		rel := strings.TrimPrefix(e.Path, "/")
		if rel == "" {
			continue
		}
		first, more, hasMore := strings.Cut(rel, "/")
		if !looksLikePeerIDSegment(first) {
			// Skip non-peer-id top-level paths defensively. The store
			// shouldn't have those at top level by V7 §1.4, but a
			// looksLikePeerIDSegment filter keeps the listing clean.
			continue
		}
		a, ok := agg[first]
		if !ok {
			a = &aggEntry{}
			agg[first] = a
		}
		if !hasMore || more == "" {
			inScope, err := h.Scope.InScope(r.Context(), e.Hash)
			if err != nil {
				http.Error(w, "scope check failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if inScope {
				hCopy := e.Hash
				a.hash = &hCopy
			}
		} else {
			a.hasChildren = true
		}
	}

	names := make([]string, 0, len(agg))
	for n := range agg {
		names = append(names, n)
	}
	sort.Strings(names)
	entries := make(map[string]interface{}, len(names))
	for _, name := range names {
		a := agg[name]
		if a.hash == nil && !a.hasChildren {
			continue
		}
		entry := map[string]interface{}{
			"has_children": a.hasChildren,
		}
		if a.hash != nil {
			entry["hash"] = *a.hash
		}
		entries[name] = entry
	}

	listingData := types.ListingData{
		Path:    "",
		Entries: entries,
		Count:   uint64(len(entries)),
		Offset:  0,
	}
	ent, err := listingData.ToEntity()
	if err != nil {
		http.Error(w, "encode listing: "+err.Error(), http.StatusInternalServerError)
		return
	}
	body, err := ecf.Encode(ent)
	if err != nil {
		http.Error(w, "encode listing entity: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("ETag", `"`+hex.EncodeToString(ent.ContentHash.Bytes())+`"`)
	w.Header().Set("Content-Length", contentLengthOf(body))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// serveManifest — Amendment 5 §6.5.3.1: terminal route. Returns the
// published manifest wire entity, or 404 if none is published. NEVER 501 in a
// shipped peer (Amendment 5 status table). Cache-Control: mutable (manifest
// revocation lives here; MUST NOT immutable-cache, γ ruling).
func (h *PollHandler) serveManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifest := h.currentManifest()
	if manifest == nil {
		http.NotFound(w, r)
		return
	}
	body, err := ecf.Encode(*manifest)
	if err != nil {
		http.Error(w, "encode manifest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	// Mutable; no immutable hint.
	w.Header().Set("ETag", `"`+hex.EncodeToString(manifest.ContentHash.Bytes())+`"`)
	w.Header().Set("Content-Length", contentLengthOf(body))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// contentLengthOf returns the byte length as decimal string.
func contentLengthOf(b []byte) string {
	return fmt.Sprintf("%d", len(b))
}

// looksLikePeerIDSegment is the literal-vs-peer-id-parse guard:
//   - length >= peerIDMinLength (≥46 chars; the reserved-word literals are ≤8)
//   - every character is base58.
func looksLikePeerIDSegment(s string) bool {
	if len(s) < peerIDMinLength {
		return false
	}
	const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, r := range s {
		if !strings.ContainsRune(base58, r) {
			return false
		}
	}
	return true
}

// ComposedHandler routes one HTTP listener to either the live POST EXECUTE
// Server or the GET PollHandler. The POST live path (the operator's
// `--http-path`, e.g. `/entity`) dispatches to live; everything else routes
// to poll. The live path MUST NOT collide with any Amendment 5 reserved
// first-segment word (`content`, `manifest`, `peers{listing_suffix}`) or
// look like a peer-id (§6.5.6 G4 normative).
type ComposedHandler struct {
	LiveServer *Server      // POST EXECUTE handler
	LivePath   string       // exact URL path live handles (e.g. "/entity")
	Poll       *PollHandler // GET poll routes; its own Prefix gates matching
}

// ServeHTTP routes: exact-match LivePath → LiveServer; everything else
// (within Poll.Prefix if set) → Poll. Mismatches in both → 404.
func (c *ComposedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c.LivePath != "" && r.URL.Path == c.LivePath {
		c.LiveServer.ServeHTTP(w, r)
		return
	}
	c.Poll.ServeHTTP(w, r)
}
