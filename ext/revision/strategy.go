package revision

import (
	"encoding/hex"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// mergeStrategy identifies a merge strategy.
type mergeStrategy string

const (
	strategyThreeWay   mergeStrategy = "three-way"
	strategySourceWins mergeStrategy = "source-wins"
	strategyTargetWins mergeStrategy = "target-wins"
	strategyKeepBoth   mergeStrategy = "keep-both"
	strategyManual     mergeStrategy = "manual"
)

// additionalBinding is a path→hash pair produced by strategies like keep-both.
type additionalBinding struct {
	Path string
	Hash hash.Hash
}

// mergeStrategyResult is the outcome of applying a merge strategy to a conflict.
type mergeStrategyResult struct {
	resolved           bool
	hash               hash.Hash
	additionalBindings []additionalBinding
}

// findMergeStrategy determines the merge strategy for a given path.
// Cascade per §5.1: override → per-type config → per-path config → default three-way.
func findMergeStrategy(hctx *handler.HandlerContext, prefix, relPath string, override string) mergeStrategy {
	if override != "" {
		return mergeStrategy(override)
	}

	// Step 2 (§5.1): Per-path merge config.
	// Configs stored at system/revision/config/merge/path/{name} (global, not prefix-scoped).
	// Pattern matched against trie-relative path within the merge prefix.
	configEntries := hctx.LocationIndex.List("system/revision/config/merge/path/")
	var bestMatch mergeStrategy
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
		if globMatch(cfg.Pattern, relPath) {
			specificity := patternSpecificity(cfg.Pattern)
			if specificity > bestSpecificity {
				bestMatch = mergeStrategy(cfg.Strategy)
				bestSpecificity = specificity
			}
		}
	}
	if bestSpecificity >= 0 {
		return bestMatch
	}

	return strategyThreeWay
}

// patternSpecificity returns a score for how specific a glob pattern is.
// More literal characters = more specific. "*" alone scores 0.
func patternSpecificity(pattern string) int {
	specificity := 0
	for _, c := range pattern {
		if c != '*' && c != '?' {
			specificity++
		}
	}
	return specificity
}

// applyMergeStrategy applies the given strategy to resolve a conflict.
// path is the trie-relative path being merged (needed by keep-both for additional binding paths).
func applyMergeStrategy(cs store.ContentStore, strategy mergeStrategy, path string, base, local, remote hash.Hash) mergeStrategyResult {
	switch strategy {
	case strategySourceWins:
		return mergeStrategyResult{resolved: true, hash: remote}

	case strategyTargetWins:
		return mergeStrategyResult{resolved: true, hash: local}

	case strategyKeepBoth:
		if local.IsZero() || remote.IsZero() {
			return mergeStrategyResult{resolved: false}
		}
		hashPrefix := hex.EncodeToString(remote.Digest[:4])
		return mergeStrategyResult{
			resolved: true,
			hash:     local,
			additionalBindings: []additionalBinding{
				{Path: path + ".keep-both-" + hashPrefix, Hash: remote},
			},
		}

	case strategyManual:
		return mergeStrategyResult{resolved: false}

	case strategyThreeWay:
		return applyThreeWayMerge(cs, base, local, remote)

	default:
		return mergeStrategyResult{resolved: false}
	}
}

// applyThreeWayMerge implements field-by-field three-way merge for structured entities.
func applyThreeWayMerge(cs store.ContentStore, base, local, remote hash.Hash) mergeStrategyResult {
	if base.IsZero() || local.IsZero() || remote.IsZero() {
		return mergeStrategyResult{resolved: false}
	}

	baseEnt, ok := cs.Get(base)
	if !ok {
		return mergeStrategyResult{resolved: false}
	}
	localEnt, ok := cs.Get(local)
	if !ok {
		return mergeStrategyResult{resolved: false}
	}
	remoteEnt, ok := cs.Get(remote)
	if !ok {
		return mergeStrategyResult{resolved: false}
	}

	if baseEnt.Type != localEnt.Type || baseEnt.Type != remoteEnt.Type {
		return mergeStrategyResult{resolved: false}
	}

	var baseMap, localMap, remoteMap map[string]interface{}
	if err := ecf.Decode(baseEnt.Data, &baseMap); err != nil {
		return mergeStrategyResult{resolved: false}
	}
	if err := ecf.Decode(localEnt.Data, &localMap); err != nil {
		return mergeStrategyResult{resolved: false}
	}
	if err := ecf.Decode(remoteEnt.Data, &remoteMap); err != nil {
		return mergeStrategyResult{resolved: false}
	}

	allKeys := make(map[string]bool)
	for k := range baseMap {
		allKeys[k] = true
	}
	for k := range localMap {
		allKeys[k] = true
	}
	for k := range remoteMap {
		allKeys[k] = true
	}

	merged := make(map[string]interface{})
	for key := range allKeys {
		baseVal := baseMap[key]
		localVal := localMap[key]
		remoteVal := remoteMap[key]

		baseBytes, _ := ecf.Encode(baseVal)
		localBytes, _ := ecf.Encode(localVal)
		remoteBytes, _ := ecf.Encode(remoteVal)

		localChanged := string(localBytes) != string(baseBytes)
		remoteChanged := string(remoteBytes) != string(baseBytes)

		switch {
		case !localChanged && !remoteChanged:
			merged[key] = baseVal
		case localChanged && !remoteChanged:
			merged[key] = localVal
		case !localChanged && remoteChanged:
			merged[key] = remoteVal
		case string(localBytes) == string(remoteBytes):
			merged[key] = localVal
		default:
			return mergeStrategyResult{resolved: false}
		}
	}

	mergedRaw, err := ecf.Encode(merged)
	if err != nil {
		return mergeStrategyResult{resolved: false}
	}
	mergedEnt, err := entity.NewEntity(baseEnt.Type, cbor.RawMessage(mergedRaw))
	if err != nil {
		return mergeStrategyResult{resolved: false}
	}
	mergedHash, err := cs.Put(mergedEnt)
	if err != nil {
		return mergeStrategyResult{resolved: false}
	}

	return mergeStrategyResult{resolved: true, hash: mergedHash}
}

// mergeSnapshots performs path-by-path merge of three binding maps.
func mergeSnapshots(
	hctx *handler.HandlerContext,
	prefix, strategyOverride string,
	ancestor, local, remote map[string]hash.Hash,
	localVersion, remoteVersion hash.Hash,
) (merged map[string]hash.Hash, deletions []string, conflicts []types.RevisionConflictData) {
	merged = make(map[string]hash.Hash)

	allPaths := make(map[string]bool)
	for p := range ancestor {
		allPaths[p] = true
	}
	for p := range local {
		allPaths[p] = true
	}
	for p := range remote {
		allPaths[p] = true
	}

	for relPath := range allPaths {
		baseHash := ancestor[relPath]
		localHash := local[relPath]
		remoteHash := remote[relPath]

		inLocal := !localHash.IsZero()
		inRemote := !remoteHash.IsZero()

		localChanged := localHash != baseHash
		remoteChanged := remoteHash != baseHash

		switch {
		case !localChanged && !remoteChanged:
			if !baseHash.IsZero() {
				merged[relPath] = baseHash
			}

		case !localChanged && remoteChanged:
			if inRemote {
				// Remote modified or set a marker — take remote's value.
				// (Marker hashes go through this branch like any other entity
				// hash; the apply phase will translate them to TreeRemove.)
				merged[relPath] = remoteHash
			} else {
				// Remote's trie lacks this path that ancestor (and unchanged
				// local) has. Under PROPOSAL-DELETION-MARKERS.md A.8, absence
				// is preserved — deletion requires an explicit marker binding.
				// Mirrors mergeBindingAtNode's preserve-on-absence (the
				// recursive path; this is the flat-merge analogue). Aligning
				// the two paths closes TestTrieMerge_MatchesFlatMerge.
				merged[relPath] = baseHash
			}

		case localChanged && !remoteChanged:
			if inLocal {
				merged[relPath] = localHash
			} else {
				// Local removed it but ancestor has it. Same as above,
				// mirrored: preserve base. Without an explicit marker we
				// can't distinguish "local hasn't seen yet" from "local
				// intentionally deleted." Conservative: preserve.
				merged[relPath] = baseHash
			}

		default:
			if localHash == remoteHash {
				merged[relPath] = localHash
				continue
			}

			// One side absent (zero hash), other side has a non-zero hash
			// (entity or marker). Under PROPOSAL-DELETION-MARKERS A.8
			// absence-is-preserve semantics, the absent side has no opinion
			// — the non-absent side's value wins. Mirrors the equivalent
			// path-level handling in trieMergeBindings::mergeDeleteVsModify.
			// Without this, both-changed+one-absent falls through to the
			// entity-vs-entity strategy and surfaces a phantom conflict.
			if localHash.IsZero() {
				merged[relPath] = remoteHash
				continue
			}
			if remoteHash.IsZero() {
				merged[relPath] = localHash
				continue
			}

			// Deletion-vs-entity conflict per Amendment 4. Mirrors the
			// equivalent branch in trieMergeBindings::mergeBindingAtNode.
			if result := resolveDeletionVsEntity(
				hctx.Store,
				resolveDeletionStrategy(hctx, prefix, relPath),
				relPath, localHash, remoteHash, localVersion, remoteVersion,
			); result.HasConflict {
				merged[relPath] = result.ResolvedHash
				for _, sb := range result.SidecarBindings {
					merged[sb.Path] = sb.Hash
				}
				continue
			}

			strategy := findMergeStrategy(hctx, prefix, relPath, strategyOverride)
			result := applyMergeStrategy(hctx.Store, strategy, relPath, baseHash, localHash, remoteHash)

			if result.resolved {
				merged[relPath] = result.hash
				for _, ab := range result.additionalBindings {
					merged[ab.Path] = ab.Hash
				}
			} else {
				conflict := types.RevisionConflictData{
					Path:          relPath,
					Strategy:      string(strategy),
					VersionLocal:  localVersion,
					VersionRemote: remoteVersion,
				}
				if !baseHash.IsZero() {
					conflict.Base = baseHash
				}
				if inLocal {
					conflict.Local = localHash
				}
				if inRemote {
					conflict.Remote = remoteHash
				}
				conflicts = append(conflicts, conflict)

				if inLocal {
					merged[relPath] = localHash
				}
			}
		}
	}

	return merged, deletions, conflicts
}
