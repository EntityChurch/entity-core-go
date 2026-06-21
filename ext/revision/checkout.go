package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleCheckout implements the checkout operation per EXTENSION-REVISION v2.1.
func (h *Handler) handleCheckout(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionCheckoutParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode checkout params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}
	if params.Branch == "" && params.Version.IsZero() {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "branch or version is required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("checkout", params.Prefix); resp != nil {
		return resp, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var targetVersion hash.Hash
	var branchName string

	if params.Branch != "" {
		bp := branchPath(ph, params.Branch)
		bv, ok := hctx.LocationIndex.Get(bp)
		if !ok {
			resp, _ := handler.NewErrorResponse(404, "not_found", "branch not found: "+params.Branch)
			return resp, nil
		}
		targetVersion = bv
		branchName = params.Branch
	} else {
		targetVersion = params.Version
		if !hctx.Store.Has(targetVersion) {
			resp, _ := handler.NewErrorResponse(404, "not_found", "version not found")
			return resp, nil
		}
	}

	// Load version entry.
	ver, ok := loadVersion(hctx, targetVersion)
	if !ok {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to load target version")
		return resp, nil
	}

	// Capture the committed source head BEFORE we advance head to target.
	// The diff baseline below must be the SOURCE version's trie root (the
	// version we're checking out FROM) — not the live tree, and not the
	// post-advance head. Without this capture, the head-advance below
	// destroys our view of "what the local revision said before checkout"
	// and we'd be forced to fall back to live-tree probing, which would
	// wipe in-flight writes the same way the pre-A.3 merge code did.
	sourceHead, hasSourceHead := hctx.LocationIndex.Get(headPath(ph))

	var cascadeWarnings []types.RevisionCascadeWarningData

	// Advance head BEFORE applying bindings per EXTENSION-REVISION §6A:
	// under auto-version ON, per-write consumers fire on each binding
	// application and create versions chained from the current head.
	// Advancing head first ensures any intermediates descend from
	// target_version rather than being orphaned by a trailing head write.
	//
	// CAS against sourceHead so a concurrent AutoVersioner emit cannot be
	// silently overwritten. F10 part 5 — same head-write atomicity invariant
	// that performMerge / fastForward use. When sourceHead is absent
	// (first checkout in a fresh prefix), fall back to plain TreeSet —
	// CompareAndSwap has no expected value to match against an empty path.
	//
	// Phantom-marker race fix (F10 part 7): hold AV's per-prefix mutex
	// from pre-head-write through post-apply. See merge::performMerge for
	// the detailed rationale.
	unlockAV := h.lockPrefixForApply(params.Prefix)
	releaseLockOnce := func() {
		if unlockAV != nil {
			unlockAV()
			unlockAV = nil
		}
	}
	defer releaseLockOnce()

	if hasSourceHead {
		if err := hctx.LocationIndex.CompareAndSwap(headPath(ph), sourceHead, targetVersion); err != nil {
			releaseLockOnce()
			result := types.RevisionCheckoutResultData{Status: "stale_local_head_retry"}
			resultEntity, _ := result.ToEntity()
			return &handler.Response{Status: 200, Result: resultEntity}, nil
		}
	} else {
		cr, resp := bind(hctx, headPath(ph), targetVersion, "checkout")
		if resp != nil {
			return resp, nil
		}
		collectCascadeWarning(cr, headPath(ph), &cascadeWarnings)
	}

	if branchName != "" {
		nameHash, err := storeStringEntity(hctx, branchName)
		if err == nil {
			cr, resp := bind(hctx, activeBranchPath(ph), nameHash, "checkout")
			if resp != nil {
				return resp, nil
			}
			collectCascadeWarning(cr, activeBranchPath(ph), &cascadeWarnings)
		}
	} else {
		_, _, cr := hctx.TreeRemove(activeBranchPath(ph), "checkout")
		collectCascadeWarning(cr, activeBranchPath(ph), &cascadeWarnings)
	}

	// Diff the SOURCE version's trie (the committed head we captured pre-advance)
	// against the TARGET version's trie. Per EXTENSION-REVISION A.3
	// (version-transcription invariant): a transcription operation may only
	// remove paths the version DAG has an opinion about — paths present in the
	// source-version's trie but absent from the target-version's trie. Live-tree
	// paths not present in either version are in-flight writes pending
	// auto-version capture; they MUST be preserved.
	//
	// The previous implementation diffed the live tree, which classified any
	// in-flight write as "removed" and wiped it via TreeRemove. Sibling bug to
	// the fast-forward path identified in the confirmed F10 diagnosis.
	//
	// Empty-trie fallback: when there is no committed source head (first checkout
	// in a fresh prefix), the source trie is, by definition, empty. Nothing can
	// be "removed"; everything in target is "added". Mirrors performMerge's
	// no-common-ancestor handling.
	var sourceRoot hash.Hash
	if hasSourceHead {
		if sourceVer, ok := loadVersion(hctx, sourceHead); ok {
			sourceRoot = sourceVer.Root
		}
	}
	if sourceRoot.IsZero() {
		emptyRoot, err := tree.BuildTrie(hctx.Store, nil)
		if err != nil {
			resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create empty trie root")
			return resp, nil
		}
		sourceRoot = emptyRoot
	}

	added, removed, changed, _ := tree.TrieDiff(hctx.Store, sourceRoot, ver.Root)

	var cr *store.CascadeResult
	var resp *handler.Response
	// Apply via marker-aware helper per PROPOSAL-DELETION-MARKERS Amendment 3.
	for path, h := range added {
		cr, resp = bindMerged(hctx, params.Prefix+path, h, "checkout")
		if resp != nil {
			return resp, nil
		}
		collectCascadeWarning(cr, params.Prefix+path, &cascadeWarnings)
	}
	// `removed` = paths in sourceRoot but absent from targetRoot. Unlike
	// three-way merge (where absence is preserve under Amendment 3),
	// checkout is a force-state operation: the user explicitly chose
	// targetVersion's state and absence on the target side means "this
	// path doesn't exist in the state I want." Remove from live tree.
	//
	// (Compare with `fastForward` in merge.go, which preserves on absence
	// because it's an auto-converge operation, not a force-state one.
	// And `revert`, which augments parent's trie with explicit markers so
	// that "added by V_target" paths route through the standard marker
	// translation rather than through this loop.)
	for path := range removed {
		_, _, cr = hctx.TreeRemove(params.Prefix+path, "checkout")
		collectCascadeWarning(cr, params.Prefix+path, &cascadeWarnings)
	}
	for path, ch := range changed {
		cr, resp = bindMerged(hctx, params.Prefix+path, ch.TargetHash, "checkout")
		if resp != nil {
			return resp, nil
		}
		collectCascadeWarning(cr, params.Prefix+path, &cascadeWarnings)
	}

	result := types.RevisionCheckoutResultData{
		Status:          "checked_out",
		Version:         targetVersion,
		Branch:          branchName,
		CascadeWarnings: cascadeWarnings,
	}
	resultEntity, err := result.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create result entity")
		return resp, nil
	}

	return &handler.Response{
		Status: 200,
		Result: resultEntity,
	}, nil
}
