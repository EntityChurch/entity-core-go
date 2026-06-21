package revision

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// augmentTrieWithDeletionMarkers builds a new trie that's `target`'s bindings
// PLUS canonical deletion-marker entries at paths present in `addedRelativeTo`
// but absent from `target`. Used by operations like `revert` that want to
// turn an additive-set difference into an explicit deletion — by injecting
// markers, the standard three-way merge correctly routes those paths to
// deletion via the deletion-marker semantics.
//
// Concrete use: revert(V_target) builds an augmented parent trie by injecting
// markers at paths V_target added (i.e., paths present in V_target's trie but
// absent from V_target's parent's trie). The merge then sees "parent has a
// marker at P" (intentional deletion signal) rather than "parent is absent
// at P" (preserve under absence-is-preserve), so the merge correctly undoes
// the addition.
//
// If `target` already has every path `addedRelativeTo` has (no augmentation
// needed), returns `target` unchanged.
func augmentTrieWithDeletionMarkers(cs store.ContentStore, target, addedRelativeTo hash.Hash) (hash.Hash, error) {
	// We want paths present in `addedRelativeTo` but not in `target` — these
	// are the augmentation candidates. TrieDiff(target, addedRelativeTo) returns
	// `added` = paths in addedRelativeTo not in target. Exactly what we want.
	addedSet, _, _, _ := tree.TrieDiff(cs, target, addedRelativeTo)
	if len(addedSet) == 0 {
		return target, nil
	}

	// Ensure the canonical marker entity is in the store. Idempotent — same
	// canonical hash every time; the store dedups.
	if _, err := cs.Put(types.CanonicalDeletionMarker()); err != nil {
		return hash.Hash{}, err
	}
	markerHash := types.CanonicalDeletionMarkerHash()

	targetBindings := tree.CollectAllBindings(cs, target, "")
	out := make([]tree.Binding, 0, len(targetBindings)+len(addedSet))
	for path, h := range targetBindings {
		out = append(out, tree.Binding{Path: path, Hash: h})
	}
	for path := range addedSet {
		out = append(out, tree.Binding{Path: path, Hash: markerHash})
	}
	return tree.BuildTrie(cs, out)
}

// applyMergedBindingToTree applies one (path, hash) entry from a merged trie
// to the live tree. Per PROPOSAL-DELETION-MARKERS.md Amendment 3 §"Deletion
// marker translation at apply":
//
//   - If the hash is the canonical deletion marker, the path is unbound via
//     TreeRemove (live tree never holds marker bindings).
//   - Otherwise the path is set to the entity hash via TreeSet.
//
// op is the mutation operation tag (e.g., "merge", "checkout", "cherry-pick",
// "revert") — flows into the emitted TreeChangeEvent's MutationContext.
//
// Used by every version-transcription operation that applies merged trie
// bindings to the live tree: performMerge, fastForward, checkout, push
// recipient apply (merge with SourceEnvelope), cherry-pick, revert.
func applyMergedBindingToTree(hctx *handler.HandlerContext, path string, h hash.Hash, op string) (*store.CascadeResult, error) {
	if types.IsDeletionMarker(h) {
		_, _, cr := hctx.TreeRemove(path, op)
		return cr, nil
	}
	return hctx.TreeSet(path, h, op)
}

// emitDeletionMarkers computes the trie root for a version that captures the
// current live tree state PLUS canonical deletion markers at paths bound in
// parent's trie but unbound in live state. Per PROPOSAL-DELETION-MARKERS.md
// (A.8) Amendment 2.
//
// The semantics:
//   - For paths in live's trie: carry forward the live binding (live's hash).
//   - For paths in parent's trie but NOT in live's: bind the canonical
//     deletion marker hash. This is the explicit "deleted" signal — replaces
//     the prior absence-as-deletion inference that caused F10's cascading
//     data loss.
//   - For paths already bound to the canonical marker in parent and still
//     absent in live: carry-forward via Merkle sharing — the new trie node
//     for that path is identical to parent's, so no new entities are emitted.
//   - For paths in live but NOT in parent (added or unbound-then-rebound
//     before commit): live binding wins. No marker.
//
// The diff primitive (tree.TrieDiff) is used for efficiency per Amendment 2
// — O(changes × depth), not O(total paths).
//
// Returns the marker-augmented trie root. If parent's trie is empty (no
// markers to emit, no diff to compute), returns liveRoot unchanged.
//
// `li` + `prefix` are used to confirm candidate deletions against the live
// location index before emitting a marker. This guards against RootTracker
// eventual-consistency: under concurrent writes the tracked root (passed as
// liveRoot) can lag the live index — e.g. a merge applies merge-target paths
// to the index, but the tracker's per-prefix update for some of them is still
// queued (RootTracker.applyEventWithDepth spawns async on lock contention to
// avoid same-goroutine reentrancy deadlock). The stale tracker root then makes
// those still-present paths look "removed", so a naive diff would emit phantom
// deletion markers for live data. Confirming against the index — the authority
// on current existence — keeps marker emission to *genuine* deletions
// (absent from both tracker root and index), per the "absence = preserve,
// marker = delete" model. li may be nil (callers without an index); the guard
// is simply skipped, preserving the prior diff-only behavior.
func emitDeletionMarkers(cs store.ContentStore, parentRoot, liveRoot hash.Hash, li store.LocationIndex, prefix string) (hash.Hash, error) {
	// Edge case: empty parent root (rare — parent was an empty-trie version).
	// No deletions can be inferred; liveRoot is already correct.
	if parentRoot.IsZero() {
		return liveRoot, nil
	}

	// Fast path: parent's trie and live's trie are identical → no diff →
	// no markers to emit. Common case after a no-op commit cycle.
	if parentRoot == liveRoot {
		return liveRoot, nil
	}

	// Compute diff. `removed` = paths in parent but absent in live —
	// exactly the deletion-marker emission set.
	_, removed, _, _ := tree.TrieDiff(cs, parentRoot, liveRoot)

	// No deletions to mark — return live root unchanged. Common when the
	// commit cycle only added or changed paths.
	if len(removed) == 0 {
		return liveRoot, nil
	}

	// Ensure the canonical marker entity is in the content store. Idempotent
	// — same canonical hash every time; store dedups.
	markerEntity := types.CanonicalDeletionMarker()
	if _, err := cs.Put(markerEntity); err != nil {
		return hash.Hash{}, err
	}
	markerHash := types.CanonicalDeletionMarkerHash()

	// Collect live's bindings as the base of the new trie.
	liveBindings := tree.CollectAllBindings(cs, liveRoot, "")
	newBindings := make([]tree.Binding, 0, len(liveBindings)+len(removed))
	for path, h := range liveBindings {
		newBindings = append(newBindings, tree.Binding{Path: path, Hash: h})
	}

	// Add canonical marker bindings for each removed path — but only for paths
	// that are genuinely gone from the live index. A path that diffs as
	// "removed" yet is still bound in the index is a tracker-staleness false
	// positive (see the doc comment): carry its live binding forward instead of
	// emitting a phantom marker, so the emitted version reflects the real tree.
	for path := range removed {
		if li != nil {
			if liveHash, ok := li.Get(prefix + path); ok && !types.IsDeletionMarker(liveHash) {
				newBindings = append(newBindings, tree.Binding{Path: path, Hash: liveHash})
				continue
			}
		}
		newBindings = append(newBindings, tree.Binding{Path: path, Hash: markerHash})
	}

	return tree.BuildTrie(cs, newBindings)
}

// deletionStrategy enumerates the deletion-vs-entity conflict resolution
// policies per PROPOSAL-DELETION-MARKERS.md Amendment 4 (ratified).
// The values are the strings stored in RevisionMergeConfigData.DeletionResolution.
//
// Honest framing per the ratified amendment: neither named-default strategy is
// "lossless" — `preserve-on-conflict` silently drops the DELETE signal;
// `deletion-wins` silently drops the EDIT signal. The choice trades operational
// simplicity (no conflict-entity accumulation) for explicit-conflict signal.
// `three-way-fallthrough` is the explicit-signal opt-in.
//
// `lww` and `keep-both` are NOT valid here per §193. They are rejected at
// config-write time with `invalid_strategy` (see revision config handler).
// `deterministic` remains available but is operationally arbitrary with
// canonical markers (depends on byte-ordering of marker hash vs entity hash).
type deletionStrategy string

const (
	deletionStrategyPreserveOnConflict  deletionStrategy = "preserve-on-conflict"  // default — entity supersedes marker (delete signal silently dropped)
	deletionStrategyDeletionWins        deletionStrategy = "deletion-wins"         // marker supersedes entity (edit signal silently dropped)
	deletionStrategyThreeWayFallthrough deletionStrategy = "three-way-fallthrough" // fall through to entity-vs-entity merge → conflict entity per §193
	deletionStrategyDeterministic       deletionStrategy = "deterministic"         // byte-order hash comparison; arbitrary with canonical markers

	defaultDeletionStrategy = deletionStrategyPreserveOnConflict
)

// invalidDeletionStrategies enumerates strategy strings that MUST be rejected
// at config-write time with `invalid_strategy`. Per Amendment 4 §"keep-both"
// rejection and §"lww removed."
var invalidDeletionStrategies = map[string]string{
	"keep-both": "keep-both is not valid for deletion_resolution — KeepBoth only applies to edit-vs-edit conflicts per §193; use three-way-fallthrough for explicit conflict-entity surfacing on delete-vs-edit",
	"lww":       "lww is not supported for deletion_resolution — canonical markers carry no timestamp; use deletion-wins, preserve-on-conflict, or three-way-fallthrough",
}

// deletionResolutionResult conveys the outcome of resolveDeletionVsEntity.
//
// HasConflict indicates whether the input was actually a deletion-vs-entity
// divergent case. If false, caller falls through to the standard
// entity-vs-entity merge strategy.
//
// ResolvedHash is the value the caller should bind at the primary path.
//
// SidecarBindings is non-empty only for the `keep-both` strategy: each entry
// is an additional (path, hash) the caller MUST also bind in the merged
// trie. The primary path receives the marker (for delete-stickiness audit);
// each sidecar path receives the conflicting entity at `<basename>.keep-both-<hash-prefix>`.
type deletionResolutionResult struct {
	HasConflict     bool
	ResolvedHash    hash.Hash
	SidecarBindings []tree.Binding
}

// resolveDeletionVsEntity classifies a (local, remote) pair as a
// deletion-vs-entity divergent merge case and applies the configured
// strategy per PROPOSAL-DELETION-MARKERS.md Amendment 4 (ratified).
//
// Strategy semantics:
//
//   - `preserve-on-conflict` (default): the entity supersedes the canonical
//     marker. Delete signal silently dropped. Recommended for collaborative-
//     edit workflows where edit preservation is the priority.
//
//   - `deletion-wins`: the canonical marker supersedes the entity. Edit
//     signal silently dropped. Sticky delete; appropriate for security-
//     sensitive workflows (revocation, access removal) where delete must
//     stick.
//
//   - `three-way-fallthrough`: activates the §193 dormant code path —
//     returns HasConflict=false so the caller falls through to
//     `applyMergeStrategy(three-way)` which writes a conflict entity at
//     `system/revision/{H}/conflicts/{path}`. For workflows with human-in-
//     the-loop conflict resolution.
//
//   - `deterministic`: byte-order the two hashes; lower hash wins. Stable
//     but operationally arbitrary with canonical markers — the marker hash
//     is fixed; whether marker or entity wins depends on the entity hash's
//     collation against `CANONICAL_DELETION_MARKER_HASH`. Tie-break for
//     operators who care that the choice is reproducible but not that it
//     means anything.
//
// `keep-both` and `lww` are NOT valid here per §193. They are rejected at
// config-write time with `invalid_strategy` before this function is reached.
//
// Tombstone-vs-tombstone is NOT a divergent case (canonical markers are
// byte-identical → "same on both sides," handled by the caller before this
// is invoked). Defensive: if it does land here, we return the marker.
//
// `path` is the trie-relative path being resolved; included in the signature
// for future strategies that may need it. `localVer`/`remoteVer` are the
// enclosing version hashes; reserved for future strategies (e.g., if a
// `committed_at` field is added to RevisionEntryData for real LWW).
func resolveDeletionVsEntity(
	cs store.ContentStore,
	strategy deletionStrategy,
	path string,
	local, remote hash.Hash,
	localVer, remoteVer hash.Hash,
) deletionResolutionResult {
	localIsMarker := types.IsDeletionMarker(local)
	remoteIsMarker := types.IsDeletionMarker(remote)

	// Not a deletion-vs-entity case — caller falls through.
	if !localIsMarker && !remoteIsMarker {
		return deletionResolutionResult{HasConflict: false}
	}
	// Both markers (defensive — caller's same-hash check usually catches this).
	if localIsMarker && remoteIsMarker {
		return deletionResolutionResult{HasConflict: true, ResolvedHash: local}
	}

	// Identify which side is the entity (the non-marker side).
	var entityHash hash.Hash
	if localIsMarker {
		entityHash = remote
	} else {
		entityHash = local
	}

	// Default empty strategy → spec default (preserve-on-conflict per
	// Amendment 4 §"Honest framing").
	if strategy == "" {
		strategy = defaultDeletionStrategy
	}

	switch strategy {
	case deletionStrategyPreserveOnConflict:
		// Entity supersedes marker; delete signal silently dropped.
		return deletionResolutionResult{HasConflict: true, ResolvedHash: entityHash}

	case deletionStrategyDeletionWins:
		// Marker supersedes entity; edit signal silently dropped.
		return deletionResolutionResult{HasConflict: true, ResolvedHash: types.CanonicalDeletionMarkerHash()}

	case deletionStrategyThreeWayFallthrough:
		// Activate §193 dormant path. Returning HasConflict=false causes the
		// caller to fall through to applyMergeStrategy(three-way), which
		// classifies marker-vs-entity as unresolvable → writes a conflict
		// entity at system/revision/{H}/conflicts/{path}.
		return deletionResolutionResult{HasConflict: false}

	case deletionStrategyDeterministic:
		// Byte-order the two hashes; lower wins. Operationally arbitrary
		// with canonical markers since the marker hash is fixed.
		markerHash := types.CanonicalDeletionMarkerHash()
		mb := markerHash.Bytes()
		eb := entityHash.Bytes()
		for i := 0; i < len(mb) && i < len(eb); i++ {
			if mb[i] < eb[i] {
				return deletionResolutionResult{HasConflict: true, ResolvedHash: markerHash}
			}
			if mb[i] > eb[i] {
				return deletionResolutionResult{HasConflict: true, ResolvedHash: entityHash}
			}
		}
		// Tie (vanishingly unlikely with 32-byte hashes) — fall back to marker.
		return deletionResolutionResult{HasConflict: true, ResolvedHash: markerHash}
	}

	// Unknown strategy string. The config-write rejection layer should have
	// caught this before reaching here. Defensive: fall through to spec
	// default (preserve-on-conflict).
	return deletionResolutionResult{HasConflict: true, ResolvedHash: entityHash}
}

// ValidateDeletionResolution checks whether the given strategy string is
// acceptable for `RevisionMergeConfigData.DeletionResolution` per Amendment 4.
// Returns nil for valid values (`preserve-on-conflict`, `deletion-wins`,
// `three-way-fallthrough`, `deterministic`, or empty for default). Returns
// an error with code `invalid_strategy` for explicitly-rejected values
// (`keep-both`, `lww`) and for unknown strings.
//
// Spec mandates rejection at config-write time per Amendment 4 §"keep-both
// rejection" and §"lww removed." Callers writing `system/revision/merge-config`
// entities SHOULD invoke this before persisting. Implementations of the
// revision extension MAY wire a sync hook that calls this on writes to
// `system/revision/config/merge/path/*` and halts the cascade with
// `invalid_strategy` on failure — this is the spec-mandated rejection path.
//
// The resolver also skips invalid values defensively at read time
// (resolveDeletionStrategy below) so a misconfigured entry that escaped
// validation doesn't take effect; the default applies instead.
func ValidateDeletionResolution(s string) error {
	if s == "" {
		return nil // empty → spec default; valid
	}
	if reason, rejected := invalidDeletionStrategies[s]; rejected {
		return fmt.Errorf("invalid_strategy: %s", reason)
	}
	switch deletionStrategy(s) {
	case deletionStrategyPreserveOnConflict,
		deletionStrategyDeletionWins,
		deletionStrategyThreeWayFallthrough,
		deletionStrategyDeterministic:
		return nil
	}
	return fmt.Errorf("invalid_strategy: %q is not a valid deletion_resolution value (accepted: preserve-on-conflict, deletion-wins, three-way-fallthrough, deterministic)", s)
}

// resolveDeletionStrategy looks up the per-prefix deletion_resolution config
// and returns the chosen strategy. Lookup mirrors findMergeStrategy: pattern
// match against the trie-relative path; longest-match wins; fall back to
// spec default if no config matches.
//
// Invalid configured values (`lww`, `keep-both`, unknown) are skipped at
// read time as a defensive measure — spec mandates these be rejected at
// config-write time (see ValidateDeletionResolution), but read-time skip
// ensures a misconfigured entry that escaped validation doesn't take effect.
func resolveDeletionStrategy(hctx *handler.HandlerContext, configPrefix, relPath string) deletionStrategy {
	if hctx == nil || hctx.LocationIndex == nil {
		return defaultDeletionStrategy
	}
	configEntries := hctx.LocationIndex.List("system/revision/config/merge/path/")
	var bestMatch deletionStrategy
	bestSpecificity := -1
	for _, entry := range configEntries {
		ent, ok := hctx.Store.Get(entry.Hash)
		if !ok {
			continue
		}
		cfg, err := types.RevisionMergeConfigDataFromEntity(ent)
		if err != nil {
			continue
		}
		if cfg.DeletionResolution == "" {
			continue
		}
		// Skip invalid strategy values defensively. Spec mandates these be
		// rejected at config-write time via ValidateDeletionResolution.
		if ValidateDeletionResolution(cfg.DeletionResolution) != nil {
			continue
		}
		if globMatch(cfg.Pattern, relPath) {
			specificity := patternSpecificity(cfg.Pattern)
			if specificity > bestSpecificity {
				bestMatch = deletionStrategy(cfg.DeletionResolution)
				bestSpecificity = specificity
			}
		}
	}
	if bestSpecificity >= 0 {
		return bestMatch
	}
	return defaultDeletionStrategy
}
