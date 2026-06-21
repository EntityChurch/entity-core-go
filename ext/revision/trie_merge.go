package revision

import (
	"sort"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// trieMergeBindings performs a three-way merge over three HAMT roots and
// returns flat merged bindings (relative paths, no prefix), deletions,
// and conflicts. Same external contract as before — only the internal
// algorithm shifts to bit-position-aligned bucket walk per EXTENSION-TREE
// v4.0.
//
// Strategy: walk the three tries by combined bitmap position, hash-equality
// early-exit at every (position, all-three-link) site, and at every leaf
// bucket apply the existing per-key three-way merge logic
// (mergeBindingAtPath) which encodes the deletion-vs-modify, deletion-
// marker, and merge-strategy rules.
//
// configPrefix is used only for merge strategy lookup, not for output paths.
func trieMergeBindings(
	cs store.ContentStore,
	hctx *handler.HandlerContext,
	configPrefix, strategyOverride string,
	baseRoot, localRoot, remoteRoot hash.Hash,
	localVersion, remoteVersion hash.Hash,
) (merged map[string]hash.Hash, deletions []string, conflicts []types.RevisionConflictData) {
	merged = make(map[string]hash.Hash)

	// All three roots equal — entire tree unchanged.
	if baseRoot == localRoot && baseRoot == remoteRoot {
		merged = tree.CollectAllBindings(cs, baseRoot, "")
		return
	}

	nodeBase := loadOrEmpty(cs, baseRoot)
	nodeLocal := loadOrEmpty(cs, localRoot)
	nodeRemote := loadOrEmpty(cs, remoteRoot)

	mergeNodes(
		cs, hctx, configPrefix, strategyOverride,
		nodeBase, nodeLocal, nodeRemote,
		localVersion, remoteVersion,
		merged, &deletions, &conflicts,
	)
	return
}

// loadOrEmpty loads a HAMT node from cs, or returns the canonical empty
// node when the hash is zero or missing. Mirrors tree.loadOrEmpty (kept
// package-local because the tree variant is unexported).
func loadOrEmpty(cs store.ContentStore, h hash.Hash) types.SnapshotNodeData {
	if h.IsZero() {
		return tree.EmptyNode()
	}
	node, ok := tree.LoadTrieNode(cs, h)
	if !ok {
		return tree.EmptyNode()
	}
	return node
}

// mergeNodes recursively merges three HAMT nodes. The bit-position walk
// preserves the early-exit-on-hash-equality property at every recursion
// site and lifts leaf-bucket tuples up into the merged map per the
// per-key merge logic.
func mergeNodes(
	cs store.ContentStore,
	hctx *handler.HandlerContext,
	configPrefix, strategyOverride string,
	base, local, remote types.SnapshotNodeData,
	localVersion, remoteVersion hash.Hash,
	merged map[string]hash.Hash,
	deletions *[]string,
	conflicts *[]types.RevisionConflictData,
) {
	combined := tree.BitmapU32(base.Map) | tree.BitmapU32(local.Map) | tree.BitmapU32(remote.Map)
	for combined != 0 {
		p := trailingZeros32(combined)
		combined &^= 1 << uint(p)

		eB, hB := entryAt(base, p)
		eL, hL := entryAt(local, p)
		eR, hR := entryAt(remote, p)

		// Three-way link hash-equality: if every present side is a link
		// and the link hashes match, the whole subtree is identical.
		if eB != nil && eL != nil && eR != nil &&
			eB.IsLink() && eL.IsLink() && eR.IsLink() &&
			*eB.Link == *eL.Link && *eB.Link == *eR.Link {
			for k, v := range tree.CollectAllBindings(cs, *eB.Link, "") {
				merged[k] = v
			}
			continue
		}

		// Mixed shapes or differing links → flatten each side's subtree
		// at this bitmap position into a per-key map; merge per key.
		_, _, _ = hB, hL, hR
		mergeEntries(
			cs, hctx, configPrefix, strategyOverride,
			eB, eL, eR,
			localVersion, remoteVersion,
			merged, deletions, conflicts,
		)
	}
}

// entryAt returns (entry pointer, hash) for position p in node, or (nil,
// zero) when the bit is clear. The hash is the link target hash for link
// entries; for bucket entries it is zero.
func entryAt(node types.SnapshotNodeData, p int) (*types.NodeEntry, hash.Hash) {
	if !tree.BitmapGet(node.Map, p) {
		return nil, hash.Hash{}
	}
	idx := tree.PopcountBelow(node.Map, p)
	e := node.Data[idx]
	if e.IsLink() {
		return &e, *e.Link
	}
	return &e, hash.Hash{}
}

// mergeEntries pairs up three entries at the same bitmap position and
// applies per-key three-way merge to every key reachable from any side.
//
// When all three present entries are links with matching hashes the
// caller short-circuits before reaching here. When two of three links
// match, we still walk per-key because the third may differ.
func mergeEntries(
	cs store.ContentStore,
	hctx *handler.HandlerContext,
	configPrefix, strategyOverride string,
	eB, eL, eR *types.NodeEntry,
	localVersion, remoteVersion hash.Hash,
	merged map[string]hash.Hash,
	deletions *[]string,
	conflicts *[]types.RevisionConflictData,
) {
	tuplesB := flattenEntry(cs, eB)
	tuplesL := flattenEntry(cs, eL)
	tuplesR := flattenEntry(cs, eR)

	allKeys := make(map[string]struct{})
	for k := range tuplesB {
		allKeys[k] = struct{}{}
	}
	for k := range tuplesL {
		allKeys[k] = struct{}{}
	}
	for k := range tuplesR {
		allKeys[k] = struct{}{}
	}

	// Stable per-key iteration (lex) so conflict-list / deletion-list
	// ordering is deterministic across runs.
	keys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		bp := ptrIfPresent(tuplesB, k)
		lp := ptrIfPresent(tuplesL, k)
		rp := ptrIfPresent(tuplesR, k)
		mergeBindingAtPath(
			cs, hctx, k, configPrefix, strategyOverride,
			bp, lp, rp,
			localVersion, remoteVersion,
			merged, deletions, conflicts,
		)
	}
}

// flattenEntry returns every (relative_key → value_hash) tuple reachable
// from entry, keyed by relative_key. Nil entry → empty map.
func flattenEntry(cs store.ContentStore, entry *types.NodeEntry) map[string]hash.Hash {
	out := make(map[string]hash.Hash)
	if entry == nil {
		return out
	}
	if entry.IsBucket() {
		for _, t := range entry.Bucket {
			out[t.Key] = t.ValueHash
		}
		return out
	}
	child, ok := tree.LoadTrieNode(cs, *entry.Link)
	if !ok {
		return out
	}
	for _, t := range tree.CollectSubtreeTuples(cs, child) {
		out[t.Key] = t.ValueHash
	}
	return out
}

// ptrIfPresent returns a pointer to m[k] if present, else nil.
func ptrIfPresent(m map[string]hash.Hash, k string) *hash.Hash {
	h, ok := m[k]
	if !ok {
		return nil
	}
	return &h
}

// trailingZeros32 returns the lowest set bit index. Caller guarantees u != 0.
func trailingZeros32(u uint32) int {
	for i := 0; i < 32; i++ {
		if u&(1<<uint(i)) != 0 {
			return i
		}
	}
	return 32
}

// mergeBindingAtPath performs the three-way per-key merge that
// previously lived in mergeBindingAtNode (keyed by triePath). Under v4.0
// the relative_key is the full bucket key; there is no per-node path
// accumulation. Semantics are identical to the prior implementation: a
// nil side means "absent" (which today's deletion-vs-modify rules treat
// as "haven't seen yet", not "intentional delete").
func mergeBindingAtPath(
	cs store.ContentStore,
	hctx *handler.HandlerContext,
	relativeKey, configPrefix, strategyOverride string,
	bindBase, bindLocal, bindRemote *hash.Hash,
	localVersion, remoteVersion hash.Hash,
	merged map[string]hash.Hash,
	deletions *[]string,
	conflicts *[]types.RevisionConflictData,
) {
	_ = deletions // preserved for signature compatibility with prior callers

	hashBase := hashFromPtr(bindBase)
	hashLocal := hashFromPtr(bindLocal)
	hashRemote := hashFromPtr(bindRemote)

	localChanged := hashLocal != hashBase
	remoteChanged := hashRemote != hashBase

	switch {
	case !localChanged && !remoteChanged:
		if !hashBase.IsZero() {
			merged[relativeKey] = hashBase
		}

	case !localChanged && remoteChanged:
		if bindRemote != nil {
			merged[relativeKey] = hashRemote
		} else {
			// Remote absent for an entry local+base share. Under write-only
			// semantics this is "remote hasn't received yet," not "delete."
			// Preserve. See the F10 part-6 diagnosis.
			merged[relativeKey] = hashBase
		}

	case localChanged && !remoteChanged:
		if bindLocal != nil {
			merged[relativeKey] = hashLocal
		} else if !hashBase.IsZero() {
			// Local absent for an entry remote+base share. Mirror the
			// preserve-base policy above.
			merged[relativeKey] = hashBase
		}

	default:
		// Both changed.
		if hashLocal == hashRemote {
			merged[relativeKey] = hashLocal
			return
		}

		// Deletion-vs-entity conflict per PROPOSAL-DELETION-MARKERS A.8
		// Amendment 4: if exactly one side is the canonical deletion marker,
		// apply the configured deletion_resolution strategy.
		if result := resolveDeletionVsEntity(
			cs,
			resolveDeletionStrategy(hctx, configPrefix, relativeKey),
			relativeKey, hashLocal, hashRemote, localVersion, remoteVersion,
		); result.HasConflict {
			merged[relativeKey] = result.ResolvedHash
			for _, sb := range result.SidecarBindings {
				merged[sb.Path] = sb.Hash
			}
			return
		}

		strategy := findMergeStrategy(hctx, configPrefix, relativeKey, strategyOverride)
		result := applyMergeStrategy(cs, strategy, relativeKey, hashBase, hashLocal, hashRemote)

		if result.resolved {
			merged[relativeKey] = result.hash
			for _, ab := range result.additionalBindings {
				merged[ab.Path] = ab.Hash
			}
		} else {
			conflict := types.RevisionConflictData{
				Path:          relativeKey,
				Strategy:      string(strategy),
				VersionLocal:  localVersion,
				VersionRemote: remoteVersion,
			}
			if !hashBase.IsZero() {
				conflict.Base = hashBase
			}
			if bindLocal != nil {
				conflict.Local = hashLocal
			}
			if bindRemote != nil {
				conflict.Remote = hashRemote
			}
			*conflicts = append(*conflicts, conflict)

			if bindLocal != nil {
				merged[relativeKey] = hashLocal
			}
		}
	}
}

// hashFromPtr returns the hash value from a pointer, or zero hash if nil.
func hashFromPtr(p *hash.Hash) hash.Hash {
	if p == nil {
		return hash.Hash{}
	}
	return *p
}
