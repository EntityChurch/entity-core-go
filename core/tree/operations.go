package tree

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// validatePrefix checks that a non-empty prefix ends with "/".
func validatePrefix(prefix string) bool {
	return prefix == "" || strings.HasSuffix(prefix, "/")
}

// resolveSnapshot looks up a snapshot entity by hash, first in the content store
// then in hctx.Included. Returns the decoded SnapshotData and true if found.
func resolveSnapshot(hctx *handler.HandlerContext, h hash.Hash) (types.SnapshotData, bool) {
	// Try content store first.
	if ent, ok := hctx.Store.Get(h); ok {
		if ent.Type == types.TypeTreeSnapshot {
			if snap, err := types.SnapshotDataFromEntity(ent); err == nil {
				return snap, true
			}
		}
	}
	// Try included entities.
	if hctx.Included != nil {
		if ent, ok := hctx.Included[h]; ok {
			if ent.Type == types.TypeTreeSnapshot {
				if snap, err := types.SnapshotDataFromEntity(ent); err == nil {
					return snap, true
				}
			}
		}
	}
	return types.SnapshotData{}, false
}

// remap performs prefix substitution per §5.4.
func remap(fullPath, sourcePrefix, targetPrefix string) string {
	if sourcePrefix == "" || targetPrefix == "" {
		return fullPath
	}
	if strings.HasPrefix(fullPath, sourcePrefix) {
		return targetPrefix + fullPath[len(sourcePrefix):]
	}
	return fullPath
}

// applyPrefix computes the target path for a trie-relative path during merge.
// Since snapshots no longer carry a prefix (I3), the merge uses source_prefix and
// target_prefix from the merge request params directly.
func applyPrefix(relPath, sourcePrefix, targetPrefix string) string {
	if targetPrefix != "" {
		return targetPrefix + relPath
	}
	if sourcePrefix != "" {
		return sourcePrefix + relPath
	}
	return relPath
}

// checkPathPerm performs Level 2 capability check if a caller capability is present.
// Returns true if allowed (or no capability to check).
func checkPathPerm(hctx *handler.HandlerContext, basePermission, path string) bool {
	if hctx.CallerCapability.ContentHash.IsZero() {
		return true
	}
	capData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
	if err != nil {
		return true
	}
	granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
	if gerr != nil {
		return false
	}
	return capability.CheckPathPermission(basePermission, path, capData, hctx.HandlerPattern, hctx.LocalPeerID, granterPeerID)
}

func (h *Handler) handleSnapshot(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing location index")
	}

	// Decode params.
	var snapReq types.SnapshotRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &snapReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode snapshot-request params")
		}
	}

	// Prefix from resource target first, fallback to params.
	prefix := snapReq.Prefix
	if hctx.Resource != nil && len(hctx.Resource.Targets) > 0 {
		prefix = hctx.Resource.Targets[0]
	}

	if !validatePrefix(prefix) {
		return handler.NewErrorResponse(400, "invalid_prefix", "non-empty prefix must end with /")
	}

	// Level 2 capability check.
	if !checkPathPerm(hctx, "get", prefix) {
		return handler.NewErrorResponse(403, "capability_denied", "insufficient capability for snapshot prefix: "+prefix)
	}

	// Short-circuit: if a tracked root is maintained for this prefix, return
	// it directly (EXTENSION-TREE v3.8 §3.4 — O(1) instead of O(N) rebuild).
	var root hash.Hash
	if h.tracker != nil {
		if r, ok := h.tracker.Root(prefix); ok {
			root = r
		}
	}

	if root.IsZero() {
		// Build trie from location index bindings per EXTENSION-TREE v3.3 §3.
		// List returns qualified paths; trim the full qualified prefix to get relative keys.
		qualifiedPrefix := store.QualifyPath(string(hctx.LocalPeerID), prefix)
		entries := hctx.LocationIndex.List(prefix)
		var bindings []Binding
		for _, e := range entries {
			rel := strings.TrimPrefix(e.Path, qualifiedPrefix)
			if rel != "" {
				bindings = append(bindings, Binding{Path: rel, Hash: e.Hash})
			}
		}

		var err error
		root, err = BuildTrie(hctx.Store, bindings)
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "failed to build trie: "+err.Error())
		}
	}

	snap := types.SnapshotData{
		Root: root,
	}
	snapEntity, err := snap.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: snapEntity}, nil
}

func (h *Handler) handleDiff(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store")
	}

	var diffReq types.DiffRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &diffReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode diff-request params")
		}
	}

	if diffReq.Base.IsZero() || diffReq.Target.IsZero() {
		return handler.NewErrorResponse(400, "invalid_params", "base and target snapshot hashes are required")
	}

	// Resolve both snapshots.
	baseSnap, ok := resolveSnapshot(hctx, diffReq.Base)
	if !ok {
		return handler.NewErrorResponse(404, "snapshot_not_found", "base snapshot not found: "+diffReq.Base.String())
	}
	targetSnap, ok := resolveSnapshot(hctx, diffReq.Target)
	if !ok {
		return handler.NewErrorResponse(404, "snapshot_not_found", "target snapshot not found: "+diffReq.Target.String())
	}

	// Compute diff using trie diff per EXTENSION-TREE v3.3 §4.
	added, removed, changed, unchanged := TrieDiff(hctx.Store, baseSnap.Root, targetSnap.Root)

	diff := types.DiffData{
		Base:      diffReq.Base,
		Target:    diffReq.Target,
		Added:     added,
		Removed:   removed,
		Changed:   changed,
		Unchanged: unchanged,
	}
	diffEntity, err := diff.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: diffEntity}, nil
}

func (h *Handler) handleMerge(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	var mergeReq types.MergeRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &mergeReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode merge-request params")
		}
	}

	// If source_envelope is provided, ingest its entities and use the root as source.
	// Accepts either a raw envelope or an entity wrapping an envelope (from continuation chains).
	if len(mergeReq.SourceEnvelope) > 0 {
		var env entity.Envelope

		// Try decoding as entity first (from continuation chain: extract result entity).
		var ent entity.Entity
		if err := ecf.Decode(mergeReq.SourceEnvelope, &ent); err == nil && ent.Type != "" {
			// It's an entity wrapping the envelope — decode entity's data as envelope.
			if err2 := ecf.Decode(ent.Data, &env); err2 != nil {
				return handler.NewErrorResponse(400, "invalid_params",
					fmt.Sprintf("could not decode entity data as envelope: %v", err2))
			}
		} else if err := ecf.Decode(mergeReq.SourceEnvelope, &env); err != nil || env.Root.Type == "" {
			return handler.NewErrorResponse(400, "invalid_params",
				"could not decode source_envelope as entity or envelope")
		}
		// Ingest all included entities into the content store.
		for _, ent := range env.Included {
			hctx.Store.Put(ent)
		}
		// Store the root (snapshot) entity and use its hash as source.
		rootHash, err := hctx.Store.Put(env.Root)
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "failed to store snapshot from envelope")
		}
		mergeReq.Source = rootHash
	}

	if mergeReq.Source.IsZero() {
		return handler.NewErrorResponse(400, "invalid_params", "source snapshot hash or source_envelope is required")
	}

	strategy := mergeReq.Strategy
	if strategy == "" {
		strategy = "no-overwrite"
	}
	if strategy != "no-overwrite" && strategy != "source-wins" && strategy != "target-wins" {
		return handler.NewErrorResponse(400, "invalid_params", "unknown merge strategy: "+strategy)
	}

	dryRun := mergeReq.DryRun != nil && *mergeReq.DryRun

	// Resolve source snapshot.
	sourceSnap, ok := resolveSnapshot(hctx, mergeReq.Source)
	if !ok {
		return handler.NewErrorResponse(404, "snapshot_not_found", "source snapshot not found: "+mergeReq.Source.String())
	}

	// Extract flat bindings from trie for merge iteration.
	sourceBindings := CollectAllBindings(hctx.Store, sourceSnap.Root, "")

	// Atomic pre-check: verify put authorization on all target paths.
	for relPath := range sourceBindings {
		targetPath := applyPrefix(relPath, mergeReq.SourcePrefix, mergeReq.TargetPrefix)
		if !checkPathPerm(hctx, "put", targetPath) {
			return handler.NewErrorResponse(403, "capability_denied", "insufficient capability for merge target path: "+targetPath)
		}
	}

	// Apply merge, tracking cascade results.
	applied := uint64(0)
	skipped := uint64(0)
	conflicts := make(map[string]types.MergeConflictData)
	var cascadeIncomplete []*store.CascadeResult

	for relPath, incomingHash := range sourceBindings {
		targetPath := applyPrefix(relPath, mergeReq.SourcePrefix, mergeReq.TargetPrefix)

		existingHash, exists := hctx.LocationIndex.Get(targetPath)

		if !exists {
			if !dryRun {
				cr, err := hctx.TreeSet(targetPath, incomingHash, "merge")
				if err != nil {
					return nil, fmt.Errorf("merge: bind %q: %w", targetPath, err)
				}
				if !cr.IsComplete() {
					cascadeIncomplete = append(cascadeIncomplete, cr)
				}
			}
			applied++
		} else if existingHash == incomingHash {
			skipped++
		} else {
			// Conflict.
			switch strategy {
			case "source-wins":
				if !dryRun {
					cr, err := hctx.TreeSet(targetPath, incomingHash, "merge")
					if err != nil {
						return nil, fmt.Errorf("merge source-wins: bind %q: %w", targetPath, err)
					}
					if !cr.IsComplete() {
						cascadeIncomplete = append(cascadeIncomplete, cr)
					}
				}
				applied++
				conflicts[targetPath] = types.MergeConflictData{
					ExistingHash: existingHash,
					IncomingHash: incomingHash,
					Resolution:   "used-incoming",
				}
			case "target-wins":
				skipped++
				conflicts[targetPath] = types.MergeConflictData{
					ExistingHash: existingHash,
					IncomingHash: incomingHash,
					Resolution:   "kept-existing",
				}
			default: // no-overwrite
				skipped++
				conflicts[targetPath] = types.MergeConflictData{
					ExistingHash: existingHash,
					IncomingHash: incomingHash,
					Resolution:   "unresolved",
				}
			}
		}
	}

	result := types.MergeResultData{
		Applied:   applied,
		Skipped:   skipped,
		Conflicts: conflicts,
		Strategy:  strategy,
	}
	resultEntity, err := result.ToEntity()
	if err != nil {
		return nil, err
	}
	if len(cascadeIncomplete) > 0 {
		return cascadeToPartialResponse(cascadeIncomplete[0], resultEntity)
	}
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

func (h *Handler) handleExtract(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	var extractReq types.ExtractRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &extractReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode extract-request params")
		}
	}

	// Prefix from resource target first, fallback to params.
	prefix := extractReq.Prefix
	if hctx.Resource != nil && len(hctx.Resource.Targets) > 0 {
		prefix = hctx.Resource.Targets[0]
	}

	if !validatePrefix(prefix) {
		return handler.NewErrorResponse(400, "invalid_prefix", "non-empty prefix must end with /")
	}

	// Level 2 capability check.
	if !checkPathPerm(hctx, "get", prefix) {
		return handler.NewErrorResponse(403, "capability_denied", "insufficient capability for extract prefix: "+prefix)
	}

	// Since-mode (PROPOSAL-TREE-EXTRACT-SINCE.md): incremental closure
	// transport. When `Since` is set, the envelope bundles only the
	// content-addressed nodes that DIFFER from the receiver's snapshot
	// — every trie node entity reachable from the current root whose
	// hash is not in the since-tree's reachable set, plus its leaf
	// binding entities. The receiver merges this with what it already
	// has at `since`. Wire-format-identical to paths-mode; only the
	// inclusion rule differs.
	if !extractReq.Since.IsZero() {
		// Mutual exclusivity (§2.2): paths and since cannot coexist.
		if len(extractReq.Paths) > 0 {
			return handler.NewErrorResponse(400, "conflicting_filters",
				"paths and since are mutually exclusive on tree:extract")
		}
		return h.handleExtractSince(hctx, prefix, extractReq.Since)
	}

	// Collect bindings.
	var trieBindings []Binding
	if len(extractReq.Paths) > 0 {
		// Filtered: read specific paths directly.
		for _, relPath := range extractReq.Paths {
			fullPath := prefix + relPath
			if h, ok := hctx.LocationIndex.Get(fullPath); ok {
				trieBindings = append(trieBindings, Binding{Path: relPath, Hash: h})
			}
		}
	} else {
		// Full prefix: all bindings under prefix.
		// List returns qualified paths; trim the full qualified prefix to get relative keys.
		qp := store.QualifyPath(string(hctx.LocalPeerID), prefix)
		entries := hctx.LocationIndex.List(prefix)
		for _, e := range entries {
			rel := strings.TrimPrefix(e.Path, qp)
			if rel != "" {
				trieBindings = append(trieBindings, Binding{Path: rel, Hash: e.Hash})
			}
		}
	}

	// Build trie and snapshot entity.
	root, err := BuildTrie(hctx.Store, trieBindings)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "failed to build trie: "+err.Error())
	}

	snap := types.SnapshotData{
		Root: root,
	}
	snapEntity, err := snap.ToEntity()
	if err != nil {
		return nil, err
	}

	// Bundle trie node entities (per TREE §6.2 — MUST include all reachable nodes).
	included := make(map[hash.Hash]entity.Entity)
	collectTrieEntities(hctx.Store, root, included)

	// Bundle data entities from bindings.
	for _, b := range trieBindings {
		if ent, ok := hctx.Store.Get(b.Hash); ok {
			included[b.Hash] = ent
		}
	}

	// Encode envelope as entity data.
	env := entity.Envelope{
		Root:     snapEntity,
		Included: included,
	}
	envEntity, err := env.ToEntity()
	if err != nil {
		return nil, err
	}

	return &handler.Response{Status: 200, Result: envEntity}, nil
}

// handleExtractSince bundles the incremental closure from `since` to the
// current trie root for `prefix`. Implements EXTENSION-TREE v3.14 §6.2a
// algorithm: resolve current_root_hash via the canonical revision head
// path for revision-tracked prefixes (load-bearing for server-side scale —
// avoids rebuilding the trie from live bindings on every request), fall
// back to materialization for non-revision-tracked prefixes. Validates
// scope per §6.2b. Walks compute_trie_diff with content-addressed
// subtree skipping. Error codes:
//
//   - 404 no_local_state    — no tree state at prefix
//   - 404 since_not_found   — since hash isn't resolvable locally
//   - 400 scope_mismatch    — since came from a different prefix's tree
//   - 200                   — envelope wrapped (snapshot root + diff closure)
func (h *Handler) handleExtractSince(hctx *handler.HandlerContext, prefix string, sinceRoot hash.Hash) (*handler.Response, error) {
	// §6.2a: resolve current trie root via the canonical path for
	// revision-tracked prefixes (O(1) lookup), or fall back to
	// materializing from live bindings (the documented MAY-fallback;
	// non-revision-tracked callers should expect suboptimal performance
	// at scale per §6.2a's discussion).
	currentRoot, hasCanonicalRoot, err := resolveCurrentTrieRoot(hctx, prefix)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"failed to resolve current trie root: "+err.Error())
	}
	if currentRoot.IsZero() {
		return handler.NewErrorResponse(404, "no_local_state",
			"no tree state at prefix: "+prefix)
	}

	// §6.2a: validate `since` is resolvable in the local content store.
	if _, ok := hctx.Store.Get(sinceRoot); !ok {
		return handler.NewErrorResponse(404, "since_not_found",
			"server does not have the specified trie root; caller may retry with `since` unset (full closure)")
	}

	// §6.2b: scope validation. For revision-tracked prefixes, walk the
	// version DAG back from head and check `since` matches a known
	// version's Root. For non-revision-tracked prefixes, the spec's
	// "implementation-defined" leeway lets us accept on weaker
	// evidence (since-hash decodes as a trie node entity) — we cannot
	// validate scope without DAG metadata.
	if hasCanonicalRoot {
		if !revisionDAGContainsRoot(hctx, prefix, sinceRoot, currentRoot) {
			return handler.NewErrorResponse(400, "scope_mismatch",
				"since root's scope does not match extract prefix")
		}
	}

	// Walk `since` to collect the set of trie-node + binding hashes the
	// receiver already has. Content addressing means anything with the
	// same hash is identical, so we skip those when collecting from
	// current.
	skip := make(map[hash.Hash]bool)
	CollectReachableHashes(hctx.Store, sinceRoot, skip)

	// Walk `current`, collecting only entities the receiver doesn't
	// already have. The snapshot root entity (system/tree/snapshot
	// wrapping the trie root) is always bundled so the receiver knows
	// what root to merge against — its hash is the snapshot envelope's
	// Root.
	included := make(map[hash.Hash]entity.Entity)
	CollectTrieEntitiesExcept(hctx.Store, currentRoot, skip, included)

	snap := types.SnapshotData{Root: currentRoot}
	snapEntity, sErr := snap.ToEntity()
	if sErr != nil {
		return nil, sErr
	}

	env := entity.Envelope{Root: snapEntity, Included: included}
	envEntity, eErr := env.ToEntity()
	if eErr != nil {
		return nil, eErr
	}
	return &handler.Response{Status: 200, Result: envEntity}, nil
}

// resolveCurrentTrieRoot implements §6.2a's canonical resolution. For
// revision-tracked prefixes (the canonical use case for since-mode),
// reads system/revision/{prefix_hash}/head, loads the version entry,
// and returns its Root — O(1) lookup. Returns (root, true, nil) on the
// canonical path. If no revision head is bound for the prefix, falls
// back to materializing from live bindings (the MAY path); returns
// (root, false, nil) with hasCanonical=false so the caller knows scope
// validation has weaker guarantees.
//
// The prefix is resolved to its absolute, peer-id-namespaced form
// before hashing so the canonical head path matches what
// ext/revision wrote on commit (ext/revision/handler.go::resolvePrefix
// + PrefixHash convention).
func resolveCurrentTrieRoot(hctx *handler.HandlerContext, prefix string) (hash.Hash, bool, error) {
	absPrefix := resolveAbsolutePrefix(prefix, string(hctx.LocalPeerID))
	headPath := revisionHeadPath(absPrefix)
	if headHash, ok := hctx.LocationIndex.Get(headPath); ok {
		ent, ok := hctx.Store.Get(headHash)
		if ok {
			if rev, err := types.RevisionEntryDataFromEntity(ent); err == nil {
				return rev.Root, true, nil
			}
		}
		// Head pointer exists but version entry isn't loadable — store
		// integrity error; surface explicitly rather than silently
		// falling back.
		return hash.Hash{}, false, fmt.Errorf("revision head version entry missing or undecodable")
	}
	// Non-revision-tracked: materialize from live bindings. Per §6.2a,
	// impls MAY do this OR reject with 400 not_supported; workbench
	// chose materialize to keep the no-config use case working.
	qp := store.QualifyPath(string(hctx.LocalPeerID), prefix)
	entries := hctx.LocationIndex.List(prefix)
	var trieBindings []Binding
	for _, e := range entries {
		rel := strings.TrimPrefix(e.Path, qp)
		if rel != "" {
			trieBindings = append(trieBindings, Binding{Path: rel, Hash: e.Hash})
		}
	}
	if len(trieBindings) == 0 {
		return hash.Hash{}, false, nil
	}
	root, err := BuildTrie(hctx.Store, trieBindings)
	if err != nil {
		return hash.Hash{}, false, fmt.Errorf("materialize trie: %w", err)
	}
	return root, false, nil
}

// revisionHeadPath computes the LI path where the revision handler binds
// a prefix's head pointer. The prefix MUST be absolute (peer-id-namespaced
// per V7 §1.5); callers use resolveAbsolutePrefix to normalize. Mirrors
// ext/revision/handler.go::PrefixHash + headPath but lives in core/tree
// to avoid a reverse module dependency — core/tree cannot import
// ext/revision. The string layout is part of EXTENSION-REVISION v3.0
// §3.1 and stable.
func revisionHeadPath(absPrefix string) string {
	data, _ := ecf.Encode(absPrefix)
	h, _ := hash.Compute("system/tree/path", cbor.RawMessage(data))
	return "system/revision/" + hex.EncodeToString(h.Bytes()) + "/head"
}

// resolveAbsolutePrefix normalizes a prefix to its absolute, peer-id-
// namespaced form (per V7 §1.5). If prefix is already absolute it
// passes through; otherwise the local peer's namespace is prepended.
// Matches ext/revision/handler.go::resolvePrefix so canonical head
// paths computed in either layer hash identically.
func resolveAbsolutePrefix(prefix, localPeerID string) string {
	if strings.HasPrefix(prefix, "/") {
		return prefix
	}
	return "/" + localPeerID + "/" + prefix
}

// revisionDAGContainsRoot is §6.2b's scope-validation mechanism for
// revision-tracked prefixes. BFS-walks the version DAG back from
// `currentRoot`'s owning head until either: (a) it finds a version
// whose Root equals `since` — scope matches; or (b) it exhausts the
// bounded walk — scope_mismatch. The bound keeps the validation
// O(history_depth ∧ maxDepth) regardless of how deep the DAG is.
//
// since == current is the trivial accept (the caller is up-to-date).
// Other accepts require `since` to appear as a known version's Root
// within the bound. This catches the canonical cross-prefix
// mistake (since=foo's_root passed to extract on bar/) without
// requiring per-trie scope metadata.
func revisionDAGContainsRoot(hctx *handler.HandlerContext, prefix string, since, currentRoot hash.Hash) bool {
	if since == currentRoot {
		return true
	}
	absPrefix := resolveAbsolutePrefix(prefix, string(hctx.LocalPeerID))
	headHash, ok := hctx.LocationIndex.Get(revisionHeadPath(absPrefix))
	if !ok {
		return false
	}
	const maxDepth = 1000 // bounded BFS; typical follower since-lag is 1–2
	visited := make(map[hash.Hash]bool)
	queue := []hash.Hash{headHash}
	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		next := make([]hash.Hash, 0)
		for _, vh := range queue {
			if visited[vh] {
				continue
			}
			visited[vh] = true
			ent, ok := hctx.Store.Get(vh)
			if !ok {
				continue
			}
			rev, err := types.RevisionEntryDataFromEntity(ent)
			if err != nil {
				continue
			}
			if rev.Root == since {
				return true
			}
			next = append(next, rev.Parents...)
		}
		queue = next
	}
	return false
}

// CollectReachableHashes records every trie-node hash AND its leaf
// binding hash reachable from root into `collected`. Used by since-mode
// to compute the "receiver already has" set.
//
// Under v4.0 HAMT shape each node's Data array holds either bucket entries
// (whose tuples carry value_hashes — the leaf binding hashes) or link
// entries (sub-node hashes — recurse).
func CollectReachableHashes(cs store.ContentStore, nodeHash hash.Hash, collected map[hash.Hash]bool) {
	if collected[nodeHash] {
		return
	}
	collected[nodeHash] = true
	ent, ok := cs.Get(nodeHash)
	if !ok {
		return
	}
	node, err := types.SnapshotNodeDataFromEntity(ent)
	if err != nil {
		return
	}
	for _, entry := range node.Data {
		if entry.IsBucket() {
			for _, t := range entry.Bucket {
				collected[t.ValueHash] = true
			}
		} else {
			CollectReachableHashes(cs, *entry.Link, collected)
		}
	}
}

// CollectTrieEntitiesExcept walks the current trie collecting every
// node + binding entity whose hash is NOT in `skip`. Content-addressed
// equality means a subtree whose root hash matches the receiver's is
// shared verbatim and need not be transmitted; same for any leaf data
// entity already in the receiver's `since` closure.
func CollectTrieEntitiesExcept(cs store.ContentStore, nodeHash hash.Hash, skip map[hash.Hash]bool, collected map[hash.Hash]entity.Entity) {
	if skip[nodeHash] {
		return
	}
	if _, already := collected[nodeHash]; already {
		return
	}
	ent, ok := cs.Get(nodeHash)
	if !ok {
		return
	}
	collected[nodeHash] = ent
	node, err := types.SnapshotNodeDataFromEntity(ent)
	if err != nil {
		return
	}
	for _, entry := range node.Data {
		if entry.IsBucket() {
			for _, t := range entry.Bucket {
				if skip[t.ValueHash] {
					continue
				}
				if bindEnt, ok := cs.Get(t.ValueHash); ok {
					collected[t.ValueHash] = bindEnt
				}
			}
		} else {
			CollectTrieEntitiesExcept(cs, *entry.Link, skip, collected)
		}
	}
}

// collectTrieEntities recursively collects all trie node entities reachable from nodeHash.
func collectTrieEntities(cs store.ContentStore, nodeHash hash.Hash, collected map[hash.Hash]entity.Entity) {
	ent, ok := cs.Get(nodeHash)
	if !ok {
		return
	}
	collected[nodeHash] = ent
	node, err := types.SnapshotNodeDataFromEntity(ent)
	if err != nil {
		return
	}
	for _, entry := range node.Data {
		if entry.IsLink() {
			collectTrieEntities(cs, *entry.Link, collected)
		}
	}
}
