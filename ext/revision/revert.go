package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleRevert implements the revert operation per EXTENSION-REVISION v2.1.
func (h *Handler) handleRevert(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionRevertParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode revert params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}
	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if params.Version.IsZero() {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "version is required")
		return resp, nil
	}

	if resp := hctx.CheckPathCapability("revert", params.Prefix); resp != nil {
		return resp, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Load the version to revert.
	revertVer, ok := loadVersion(hctx, params.Version)
	if !ok {
		resp, _ := handler.NewErrorResponse(404, "not_found", "version not found")
		return resp, nil
	}

	// Need current head.
	localHead, hasHead := hctx.LocationIndex.Get(headPath(ph))
	if !hasHead {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "no head version exists")
		return resp, nil
	}

	// Determine parent for three-way merge per REVISION v2.8 §4.4.16 (R1).
	if len(revertVer.Parents) == 0 {
		resp, _ := handler.NewErrorResponse(400, "no_parent", "cannot revert an initial version")
		return resp, nil
	}

	var parentHash hash.Hash
	if !params.Parent.IsZero() {
		found := false
		for _, p := range revertVer.Parents {
			if p == params.Parent {
				found = true
				break
			}
		}
		if !found {
			resp, _ := handler.NewErrorResponse(400, "invalid_parent", "specified parent is not in version's parent list")
			return resp, nil
		}
		parentHash = params.Parent
	} else if len(revertVer.Parents) > 1 {
		resp, _ := handler.NewErrorResponse(400, "ambiguous_parent", "merge version has multiple parents — specify which parent to diff against")
		return resp, nil
	} else {
		parentHash = revertVer.Parents[0]
	}

	var parentRoot hash.Hash
	if parentVer, ok := loadVersion(hctx, parentHash); ok {
		parentRoot = parentVer.Root
	} else {
		resp, _ := handler.NewErrorResponse(404, "parent_not_found", "parent version not available locally")
		return resp, nil
	}

	localVer, ok := loadVersion(hctx, localHead)
	if !ok {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to load local version")
		return resp, nil
	}

	// Augment the parent's trie with explicit deletion markers at paths
	// V_target added. Under PROPOSAL-DELETION-MARKERS A.8 absence-is-preserve
	// semantics, the standard merge would interpret "parent is absent at P"
	// as "parent hasn't seen P" and preserve V_target's binding — defeating
	// revert's intent. By injecting markers at "added by V_target" paths in
	// the parent's view, the merge sees "parent has marker at P" (intentional
	// deletion signal) and correctly routes the path to deletion.
	augmentedParentRoot, err := augmentTrieWithDeletionMarkers(hctx.Store, parentRoot, revertVer.Root)
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to augment parent trie")
		return resp, nil
	}

	// Recursive three-way merge: ancestor=version's root, local=current,
	// remote=augmented parent (parent with markers at V_target's additions).
	mergedBindings, deletions, conflicts := trieMergeBindings(
		hctx.Store, hctx, params.Prefix, "",
		revertVer.Root, localVer.Root, augmentedParentRoot,
		localHead, params.Version,
	)

	// Build trie from projected merged state BEFORE applying per §6A.
	projectedBindings := make([]tree.Binding, 0, len(mergedBindings))
	for relPath, h := range mergedBindings {
		projectedBindings = append(projectedBindings, tree.Binding{Path: relPath, Hash: h})
	}
	trieRoot, err := tree.BuildTrie(hctx.Store, projectedBindings)
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to build revert trie")
		return resp, nil
	}

	// Create revert version with single parent (current head).
	rvVersion := types.RevisionEntryData{
		Root:    trieRoot,
		Parents: tree.SortedParents([]hash.Hash{localHead}),
	}
	versionEntity, _ := rvVersion.ToEntity()
	versionHash, _ := hctx.Store.Put(versionEntity)

	var cascadeWarnings []types.RevisionCascadeWarningData

	// Advance head and active-branch BEFORE applying bindings per §6A.
	// Partial-application semantics identical to merge (§6A.1).
	//
	// Phantom-marker race fix (F10 part 7): hold AV's per-prefix mutex
	// from pre-head-write through post-apply. See merge::performMerge for
	// the detailed rationale.
	unlockAV := h.lockPrefixForApply(params.Prefix)
	defer func() {
		if unlockAV != nil {
			unlockAV()
		}
	}()

	cr, resp := bind(hctx, headPath(ph), versionHash, "revert")
	if resp != nil {
		return resp, nil
	}
	collectCascadeWarning(cr, headPath(ph), &cascadeWarnings)
	if branch, onBranch := readStringEntity(hctx, activeBranchPath(ph)); onBranch && branch != "" {
		cr, resp = bind(hctx, branchPath(ph, branch), versionHash, "revert")
		if resp != nil {
			return resp, nil
		}
		collectCascadeWarning(cr, branchPath(ph, branch), &cascadeWarnings)
	}

	// Apply merged bindings via the marker-aware helper per
	// PROPOSAL-DELETION-MARKERS Amendment 3 — markers translate to
	// TreeRemove on the live tree.
	for relPath, h := range mergedBindings {
		cr, resp = bindMerged(hctx, params.Prefix+relPath, h, "revert")
		if resp != nil {
			return resp, nil
		}
		collectCascadeWarning(cr, params.Prefix+relPath, &cascadeWarnings)
	}
	for _, relPath := range deletions {
		_, _, cr = hctx.TreeRemove(params.Prefix+relPath, "revert")
		collectCascadeWarning(cr, params.Prefix+relPath, &cascadeWarnings)
	}

	// Store conflicts.
	for _, conflict := range conflicts {
		conflictEntity, err := conflict.ToEntity()
		if err != nil {
			continue
		}
		conflictHash, err := hctx.Store.Put(conflictEntity)
		if err != nil {
			continue
		}
		cPath := conflictPath(ph, conflict.Path)
		cr, resp = bind(hctx, cPath, conflictHash, "revert")
		if resp != nil {
			return resp, nil
		}
		collectCascadeWarning(cr, cPath, &cascadeWarnings)
	}

	status := "reverted"
	if len(conflicts) > 0 {
		status = "reverted_with_conflicts"
	}
	var conflictPaths []string
	for _, c := range conflicts {
		conflictPaths = append(conflictPaths, c.Path)
	}

	result := types.RevisionRevertResultData{
		Status:          status,
		Version:         versionHash,
		Reverted:        params.Version,
		Conflicts:       conflictPaths,
		CascadeWarnings: cascadeWarnings,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}
