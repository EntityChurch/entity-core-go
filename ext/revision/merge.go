package revision

import (
	"context"
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleMerge implements the merge operation per EXTENSION-REVISION v2.1 §4.4.4.
func (h *Handler) handleMerge(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionMergeParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode merge params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}

	// Chain-composition path: if SourceEnvelope is provided, ingest
	// its included entities into the local content store and derive
	// RemoteVersion from the envelope's root (a fetch-result entity
	// carrying .head). Mirrors tree/merge's source_envelope handling
	// at core/tree/operations.go:213-244 — supports the 2-step
	// continuation chain `fetch → merge` for cross-peer revision sync.
	if len(params.SourceEnvelope) > 0 {
		var env entity.Envelope
		var ent entity.Entity
		if err := ecf.Decode(params.SourceEnvelope, &ent); err == nil && ent.Type != "" {
			if err2 := ecf.Decode(ent.Data, &env); err2 != nil {
				resp, _ := handler.NewErrorResponse(400, "invalid_params",
					"could not decode source_envelope entity data as envelope: "+err2.Error())
				return resp, nil
			}
		} else if err := ecf.Decode(params.SourceEnvelope, &env); err != nil || env.Root.Type == "" {
			resp, _ := handler.NewErrorResponse(400, "invalid_params",
				"could not decode source_envelope as entity or envelope")
			return resp, nil
		}
		for _, ie := range env.Included {
			if _, err := hctx.Store.Put(ie); err != nil {
				resp, _ := handler.NewErrorResponse(500, "internal_error",
					"failed to ingest source_envelope included entity")
				return resp, nil
			}
		}
		if _, err := hctx.Store.Put(env.Root); err != nil {
			resp, _ := handler.NewErrorResponse(500, "internal_error",
				"failed to store source_envelope root")
			return resp, nil
		}
		fetchResult, ferr := types.RevisionFetchResultDataFromEntity(env.Root)
		if ferr != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params",
				"source_envelope root is not a RevisionFetchResultData: "+ferr.Error())
			return resp, nil
		}
		if fetchResult.Head.IsZero() {
			resp, _ := handler.NewErrorResponse(400, "invalid_params",
				"source_envelope's fetch result has zero head")
			return resp, nil
		}
		params.RemoteVersion = fetchResult.Head
	}

	if params.RemoteVersion.IsZero() {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "remote_version or source_envelope is required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("merge", params.Prefix); resp != nil {
		return resp, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Get local head.
	localHead, hasLocalHead := hctx.LocationIndex.Get(headPath(ph))

	// Validate remote version exists.
	_, ok := loadVersion(hctx, params.RemoteVersion)
	if !ok {
		resp, _ := handler.NewErrorResponse(404, "not_found", "remote version not found")
		return resp, nil
	}

	if !hasLocalHead {
		return h.fastForward(hctx, params, hash.Hash{}, params.RemoteVersion)
	}

	relationship := checkRelationship(hctx.Store, localHead, params.RemoteVersion)

	switch relationship {
	case "in_sync":
		result := types.RevisionMergeResultData{Status: "already_in_sync"}
		resultEntity, _ := result.ToEntity()
		return &handler.Response{Status: 200, Result: resultEntity}, nil

	case "ahead":
		result := types.RevisionMergeResultData{Status: "already_ahead"}
		resultEntity, _ := result.ToEntity()
		return &handler.Response{Status: 200, Result: resultEntity}, nil

	case "behind":
		return h.fastForward(hctx, params, localHead, params.RemoteVersion)

	case "diverged":
		return h.performMerge(ctx, hctx, params, localHead, params.RemoteVersion)

	default:
		resp, _ := handler.NewErrorResponse(500, "internal_error", "unexpected relationship: "+relationship)
		return resp, nil
	}
}

// fastForward applies a fast-forward merge.
//
// localHead is the prior committed head (zero when there is no prior head —
// first-ever sync). It is passed explicitly rather than re-read here so the
// data flow is visible at the call site, matching performMerge's signature.
func (h *Handler) fastForward(hctx *handler.HandlerContext, params types.RevisionMergeParamsData, localHead, remoteVersion hash.Hash) (*handler.Response, error) {
	ph := PrefixHash(params.Prefix)

	remoteVer, ok := loadVersion(hctx, remoteVersion)
	if !ok {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to load remote version")
		return resp, nil
	}

	var cascadeWarnings []types.RevisionCascadeWarningData

	dryRun := params.DryRun != nil && *params.DryRun
	if !dryRun {
		// Advance head via CAS when there's a prior head, per the same
		// head-write atomicity invariant as performMerge. When there is
		// no prior head (localHead.IsZero(), first-ever sync into this
		// prefix) we fall back to plain TreeSet — CompareAndSwap has no
		// expected value to match against an empty path. There is a tiny
		// residual race here vs. a concurrent AutoVersioner first-emit,
		// but it can only fire once per prefix per peer lifetime and
		// requires AV to fire between the no-head check and this write.
		//
		// Phantom-marker race fix (F10 part 7): hold AV's per-prefix mutex
		// from pre-head-write through post-apply. See performMerge for the
		// detailed rationale.
		unlockAV := h.lockPrefixForApply(params.Prefix)
		releaseLockOnce := func() {
			if unlockAV != nil {
				unlockAV()
				unlockAV = nil
			}
		}
		defer releaseLockOnce()

		if !localHead.IsZero() {
			if err := hctx.LocationIndex.CompareAndSwap(headPath(ph), localHead, remoteVersion); err != nil {
				releaseLockOnce()
				result := types.RevisionMergeResultData{Status: "stale_local_head_retry"}
				resultEntity, _ := result.ToEntity()
				return &handler.Response{Status: 200, Result: resultEntity}, nil
			}
		} else {
			cr, resp := bind(hctx, headPath(ph), remoteVersion, "merge")
			if resp != nil {
				return resp, nil
			}
			collectCascadeWarning(cr, headPath(ph), &cascadeWarnings)
		}
		if branch, onBranch := readStringEntity(hctx, activeBranchPath(ph)); onBranch && branch != "" {
			cr, resp := bind(hctx, branchPath(ph, branch), remoteVersion, "merge")
			if resp != nil {
				return resp, nil
			}
			collectCascadeWarning(cr, branchPath(ph, branch), &cascadeWarnings)
		}

		// Diff the COMMITTED LOCAL HEAD's trie against the remote version's trie
		// — never the live tree. Per EXTENSION-REVISION A.3 (version-transcription
		// invariant): a transcription operation may only remove paths the version
		// DAG has an opinion about (paths present in local-head's trie but absent
		// from remote's trie). Live-tree paths not present in either version are
		// in-flight writes pending auto-version capture; they MUST be preserved.
		//
		// The previous implementation read from the live tree via computeTrieRoot,
		// which classified any in-flight write as "removed" and physically wiped
		// it via TreeRemove. Under burst writes this caused asymmetric data loss
		// (the slower committer's writes vanished). See the
		// confirmed F10 diagnosis.
		//
		// Empty-trie fallback: when localHead is zero (no prior head — first-ever
		// sync) the local trie is, by definition, empty. An empty trie root is
		// not "missing data"; it's the correct semantic baseline. Mirrors
		// performMerge:199-204's no-common-ancestor handling.
		var localRoot hash.Hash
		if !localHead.IsZero() {
			if localVer, ok := loadVersion(hctx, localHead); ok {
				localRoot = localVer.Root
			}
		}
		if localRoot.IsZero() {
			emptyRoot, err := tree.BuildTrie(hctx.Store, nil)
			if err != nil {
				resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create empty trie root")
				return resp, nil
			}
			localRoot = emptyRoot
		}

		added, removed, changed, _ := tree.TrieDiff(hctx.Store, localRoot, remoteVer.Root)
		var cr *store.CascadeResult
		var resp *handler.Response
		// Apply added/changed via the marker-aware helper — markers in remote
		// translate to live-tree unbinds (Amendment 3).
		for path, h := range added {
			cr, resp = bindMerged(hctx, params.Prefix+path, h, "merge")
			if resp != nil {
				return resp, nil
			}
			collectCascadeWarning(cr, params.Prefix+path, &cascadeWarnings)
		}
		// `removed` here is paths present in localHead's trie but absent from
		// remote's — under Amendment 3 these are NOT deletions (absence is
		// preserve, not delete). Unconditionally calling TreeRemove for them
		// would re-introduce the F10 bug class. We skip the loop. If remote
		// intended to delete a path, it bound the canonical marker; that
		// would appear in `changed` or `added`, not `removed`.
		_ = removed
		for path, ch := range changed {
			cr, resp = bindMerged(hctx, params.Prefix+path, ch.TargetHash, "merge")
			if resp != nil {
				return resp, nil
			}
			collectCascadeWarning(cr, params.Prefix+path, &cascadeWarnings)
		}
	}

	result := types.RevisionMergeResultData{
		Status:          "fast_forward",
		Version:         remoteVersion,
		CascadeWarnings: cascadeWarnings,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// performMerge does a full three-way merge for diverged branches.
func (h *Handler) performMerge(ctx context.Context, hctx *handler.HandlerContext, params types.RevisionMergeParamsData, localHead, remoteVersion hash.Hash) (*handler.Response, error) {
	ph := PrefixHash(params.Prefix)

	// Find common ancestor. If none exists, merge with empty base.
	ancestor, found := findCommonAncestor(hctx.Store, localHead, remoteVersion)

	// Load all three versions' trie roots.
	localVer, _ := loadVersion(hctx, localHead)
	remoteVer, _ := loadVersion(hctx, remoteVersion)

	var ancestorVer types.RevisionEntryData
	if found {
		ancestorVer, _ = loadVersion(hctx, ancestor)
	} else {
		// No common ancestor: use empty trie root as base.
		// Everything in both sides is "added" — overlapping paths are conflicts.
		emptyRoot, err := tree.BuildTrie(hctx.Store, nil)
		if err != nil {
			resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create empty trie root")
			return resp, nil
		}
		ancestorVer = types.RevisionEntryData{Root: emptyRoot}
	}

	// Determine merge ordering.
	cfg, hasCfg := loadConfig(hctx, ph)
	mergeOrder := "deterministic"
	if hasCfg && cfg.MergeOrder != "" {
		mergeOrder = cfg.MergeOrder
	}

	// Normalize merge sides for deterministic ordering.
	mergeLocalRoot, mergeRemoteRoot := localVer.Root, remoteVer.Root
	mergeLocalHead, mergeRemoteVersion := localHead, remoteVersion
	if mergeOrder == "deterministic" {
		mergeLocalHead, mergeRemoteVersion = normalizeMergeSides(localHead, remoteVersion)
		if mergeLocalHead != localHead {
			mergeLocalRoot, mergeRemoteRoot = remoteVer.Root, localVer.Root
		}
	}

	// Recursive three-way merge — skips unchanged subtrees via hash comparison.
	mergedBindings, deletions, conflicts := trieMergeBindings(
		hctx.Store, hctx, params.Prefix, params.Strategy,
		ancestorVer.Root, mergeLocalRoot, mergeRemoteRoot,
		mergeLocalHead, mergeRemoteVersion,
	)

	dryRun := params.DryRun != nil && *params.DryRun

	var cascadeWarnings []types.RevisionCascadeWarningData

	if !dryRun {
		// Build trie from projected merged state BEFORE applying, so we can
		// advance head before bindings per EXTENSION-REVISION §6A. mergedBindings
		// already represents the full resulting versioned state.
		projectedBindings := make([]tree.Binding, 0, len(mergedBindings))
		for relPath, h := range mergedBindings {
			projectedBindings = append(projectedBindings, tree.Binding{Path: relPath, Hash: h})
		}
		mergeTrieRoot, err := tree.BuildTrie(hctx.Store, projectedBindings)
		if err != nil {
			resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to build merge trie")
			return resp, nil
		}

		// Check oscillation. detectOscillation compares full candidate-version
		// identity (root + sorted parents) against ancestors, not just root —
		// see dag.go::detectOscillation. The proposed parents are
		// [localHead, remoteVersion] in the same shape the merge handler will
		// persist below, so byte-identical match is required to flag.
		oscillationDepth := 4
		if hasCfg && cfg.OscillationDepth != nil {
			oscillationDepth = int(*cfg.OscillationDepth)
		}
		if detectOscillation(hctx.Store, mergeTrieRoot, []hash.Hash{localHead, remoteVersion}, localHead, oscillationDepth) {
			result := types.RevisionMergeResultData{Status: "oscillation_detected"}
			resultEntity, _ := result.ToEntity()
			return &handler.Response{Status: 200, Result: resultEntity}, nil
		}

		// Create merge version with sorted parents.
		mergeVersion := types.RevisionEntryData{
			Root:    mergeTrieRoot,
			Parents: tree.SortedParents([]hash.Hash{localHead, remoteVersion}),
		}
		versionEntity, _ := mergeVersion.ToEntity()
		versionHash, _ := hctx.Store.Put(versionEntity)

		// Phantom-deletion-marker race fix (F10 part 7). Acquire AV's
		// per-prefix mutex BEFORE the head CAS, hold through the
		// binding-apply phase. Without this, a concurrent Put between the
		// head CAS and binding-apply would fire AV.fire() observing a
		// "head moved to V_merge but live tree pre-apply" state, then
		// emitDeletionMarkers(V_merge.Root, liveRoot_pre_apply) would
		// classify every path V_merge is about to apply as `removed` and
		// emit phantom markers for ALL of them. Cascading data loss via
		// deletion-wins.
		//
		// Lock window: pre-CAS through post-apply. Released by defer below
		// once apply finishes. Sibling release in the stale-localHead path
		// inside this block runs before the early return so the lock isn't
		// held across the retry.
		//
		// See the workbench's deletion-markers phase-2 validation.
		unlockAV := h.lockPrefixForApply(params.Prefix)
		releaseLockOnce := func() {
			if unlockAV != nil {
				unlockAV()
				unlockAV = nil
			}
		}
		defer releaseLockOnce()

		// Advance head via CAS so a concurrent auto-version emit cannot be
		// silently overwritten. The expected value is localHead — what we
		// read at the start of handleMerge. If AV (or any other writer)
		// advanced head between then and now, our CAS fails and we abort
		// this merge BEFORE applying bindings: the bindings reflect a stale
		// trie diff that would be wrong against the new head.
		//
		// V_merge is already in the content store (idempotent put: re-running
		// merge would re-emit the same hash, no leak). The converge handler
		// retries naturally on the next remote-head notification.
		//
		// Mirrors AutoVersioner.fire's CAS pattern (F10 part 4). The
		// symmetric race — where merge's plain TreeSet overwrites AV's
		// CAS-validated emit — was the residual after part 4. See
		// the F10 postmortem and the workbench's F10 part-4 results.
		if err := hctx.LocationIndex.CompareAndSwap(headPath(ph), localHead, versionHash); err != nil {
			// Release the AV lock before returning — the retry path
			// doesn't hold it; the caller may issue another merge that
			// re-acquires fresh.
			releaseLockOnce()
			result := types.RevisionMergeResultData{Status: "stale_local_head_retry"}
			resultEntity, _ := result.ToEntity()
			return &handler.Response{Status: 200, Result: resultEntity}, nil
		}
		// Branch advance: only after head CAS succeeds. Plain TreeSet here is
		// acceptable because the branch pointer's writers (merge / checkout /
		// fastForward / explicit branch set) all hold the revision handler
		// mutex (h.mu). AV doesn't write branch pointers.
		if branch, onBranch := readStringEntity(hctx, activeBranchPath(ph)); onBranch && branch != "" {
			cr, resp := bind(hctx, branchPath(ph, branch), versionHash, "merge")
			if resp != nil {
				return resp, nil
			}
			collectCascadeWarning(cr, branchPath(ph, branch), &cascadeWarnings)
		}

		// Apply merged bindings to tree. Iterate in deterministic lexical
		// order so write-event order is reproducible across runs and across
		// impls — Go's map iteration is randomized, so without an explicit
		// sort, two peers (or the same peer across runs) emit binding writes
		// in different orders. The merge result is identical either way
		// (V_merge captures the final state and is deterministic), but
		// downstream consumers that observe individual writes (subscriptions,
		// auto-version sync hooks if not suppressed for "merge" ops) would
		// see peer-specific event sequences. Pure defensive coding: makes
		// the spec's observable behavior independent of map iteration order.
		mergedPaths := make([]string, 0, len(mergedBindings))
		for relPath := range mergedBindings {
			mergedPaths = append(mergedPaths, relPath)
		}
		sort.Strings(mergedPaths)
		var cr *store.CascadeResult
		var resp *handler.Response
		for _, relPath := range mergedPaths {
			// Translate deletion-marker bindings to live-tree unbinds per
			// PROPOSAL-DELETION-MARKERS Amendment 3 §"Deletion marker
			// translation at apply." Markers live only in version tries,
			// never in the live location index.
			cr, resp = bindMerged(hctx, params.Prefix+relPath, mergedBindings[relPath], "merge")
			if resp != nil {
				return resp, nil
			}
			collectCascadeWarning(cr, params.Prefix+relPath, &cascadeWarnings)
		}
		// Deletions slice is already deterministic if trieMergeBindings
		// produces it in a deterministic order; sort here as a belt-and-
		// suspenders measure since it costs nothing.
		sortedDeletions := append([]string(nil), deletions...)
		sort.Strings(sortedDeletions)
		for _, relPath := range sortedDeletions {
			_, _, cr = hctx.TreeRemove(params.Prefix+relPath, "merge")
			collectCascadeWarning(cr, params.Prefix+relPath, &cascadeWarnings)
		}

		// Store conflict entities (excluded from versioned trie; §6.1 reentrancy).
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
			if existingHash, exists := hctx.LocationIndex.Get(cPath); exists {
				conflict.Supersedes = existingHash
				conflictEntity, _ = conflict.ToEntity()
				conflictHash, _ = hctx.Store.Put(conflictEntity)
			}
			cr, resp = bind(hctx, cPath, conflictHash, "merge")
			if resp != nil {
				return resp, nil
			}
			collectCascadeWarning(cr, cPath, &cascadeWarnings)
		}

		mergedCount := uint64(len(mergedBindings))
		deletedCount := uint64(len(deletions))

		status := "merged"
		if len(conflicts) > 0 {
			status = "merged_with_conflicts"
		}

		var conflictPaths []string
		for _, c := range conflicts {
			conflictPaths = append(conflictPaths, c.Path)
		}

		result := types.RevisionMergeResultData{
			Status:          status,
			Version:         versionHash,
			Conflicts:       conflictPaths,
			MergedCount:     &mergedCount,
			DeletedCount:    &deletedCount,
			CascadeWarnings: cascadeWarnings,
		}
		resultEntity, _ := result.ToEntity()
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	// Dry run.
	mergedCount := uint64(len(mergedBindings))
	deletedCount := uint64(len(deletions))
	status := "would_merge"
	if len(conflicts) > 0 {
		status = "would_conflict"
	}
	var conflictPaths []string
	for _, c := range conflicts {
		conflictPaths = append(conflictPaths, c.Path)
	}
	result := types.RevisionMergeResultData{
		Status:       status,
		Conflicts:    conflictPaths,
		MergedCount:  &mergedCount,
		DeletedCount: &deletedCount,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// normalizeMergeSides returns heads in deterministic order (lower hash first).
func normalizeMergeSides(headA, headB hash.Hash) (hash.Hash, hash.Hash) {
	ab := headA.Bytes()
	bb := headB.Bytes()
	for i := 0; i < len(ab) && i < len(bb); i++ {
		if ab[i] < bb[i] {
			return headA, headB
		}
		if ab[i] > bb[i] {
			return headB, headA
		}
	}
	return headA, headB
}

// applyBindings replaces the tree under prefix with the given bindings.
// Returns the first storage error encountered, if any.
func applyBindings(hctx *handler.HandlerContext, prefix string, bindings map[string]hash.Hash, warnings *[]types.RevisionCascadeWarningData) error {
	// Remove current bindings under prefix (except system/revision/ metadata).
	currentEntries := hctx.LocationIndex.List(prefix)
	for _, entry := range currentEntries {
		relPath := trimPrefix(entry.Path, prefix, hctx.LocalPeerID)
		if relPath != "" {
			_, _, cr := hctx.TreeRemove(entry.Path, "merge")
			collectCascadeWarning(cr, entry.Path, warnings)
		}
	}

	// Set new bindings.
	for relPath, h := range bindings {
		cr, err := hctx.TreeSet(prefix+relPath, h, "merge")
		if err != nil {
			return err
		}
		collectCascadeWarning(cr, prefix+relPath, warnings)
	}
	return nil
}
