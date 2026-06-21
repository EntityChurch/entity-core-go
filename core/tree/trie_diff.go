package tree

import (
	"math/bits"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TrieDiff computes the diff between two HAMT roots per EXTENSION-TREE
// v4.0 §4.3. Walks both tries in parallel by bitmap position, hash-
// equality early-exits at every node (entire subtree identical), and
// emits (added, removed, changed) per leaf-bucket tuple.
//
// Returns:
//   - added:     keys in B but not A, mapped to B's value_hash
//   - removed:   keys in A but not B, mapped to A's value_hash
//   - changed:   keys in both with different value_hash
//   - unchanged: count of identical-hash bindings
//
// Cost: O(changes) — the hash-equality early-exit at every node skips
// entire unchanged subtrees. For a single binding change in an N-binding
// tree, the diff visits ~log_32(N) positions.
func TrieDiff(cs store.ContentStore, rootA, rootB hash.Hash) (
	added map[string]hash.Hash,
	removed map[string]hash.Hash,
	changed map[string]types.DiffChangeData,
	unchanged uint64,
) {
	added = make(map[string]hash.Hash)
	removed = make(map[string]hash.Hash)
	changed = make(map[string]types.DiffChangeData)

	// Root-level hash equality short-circuit: identical tries.
	if rootA == rootB {
		unchanged = countAllBindings(cs, rootA)
		return
	}

	nodeA, okA := LoadTrieNode(cs, rootA)
	nodeB, okB := LoadTrieNode(cs, rootB)

	switch {
	case !okA && !okB:
		return
	case !okA:
		// Treat A as empty — every binding in B is added.
		for k, v := range CollectAllBindings(cs, rootB, "") {
			added[k] = v
		}
		return
	case !okB:
		// Treat B as empty — every binding in A is removed.
		for k, v := range CollectAllBindings(cs, rootA, "") {
			removed[k] = v
		}
		return
	}

	diffNodes(cs, nodeA, nodeB, added, removed, changed, &unchanged)
	return
}

// diffNodes walks two HAMT nodes in parallel by combined bitmap position.
// Per spec §4.3:
//
//   - position only in A → emit removed for all tuples reachable from A's entry
//   - position only in B → emit added for all tuples reachable from B's entry
//   - both buckets → merge-walk by key
//   - both links → hash-equality short-circuit; otherwise recurse
//   - bucket vs link → flatten the link side and merge against the bucket
func diffNodes(
	cs store.ContentStore,
	a, b types.SnapshotNodeData,
	added map[string]hash.Hash,
	removed map[string]hash.Hash,
	changed map[string]types.DiffChangeData,
	unchanged *uint64,
) {
	combined := BitmapU32(a.Map) | BitmapU32(b.Map)
	for combined != 0 {
		p := bits.TrailingZeros32(combined)
		combined &^= 1 << uint(p)

		hasA := BitmapGet(a.Map, p)
		hasB := BitmapGet(b.Map, p)

		switch {
		case hasA && !hasB:
			collectEntryAs(cs, a.Data[PopcountBelow(a.Map, p)], removed)
		case !hasA && hasB:
			collectEntryAs(cs, b.Data[PopcountBelow(b.Map, p)], added)
		default:
			entryA := a.Data[PopcountBelow(a.Map, p)]
			entryB := b.Data[PopcountBelow(b.Map, p)]
			diffEntries(cs, entryA, entryB, added, removed, changed, unchanged)
		}
	}
}

// diffEntries compares two entries at the same bitmap position. The four
// shape combinations (bucket/bucket, link/link, bucket/link, link/bucket)
// are all covered.
func diffEntries(
	cs store.ContentStore,
	entryA, entryB types.NodeEntry,
	added map[string]hash.Hash,
	removed map[string]hash.Hash,
	changed map[string]types.DiffChangeData,
	unchanged *uint64,
) {
	switch {
	case entryA.IsBucket() && entryB.IsBucket():
		diffBuckets(entryA.Bucket, entryB.Bucket, added, removed, changed, unchanged)

	case entryA.IsLink() && entryB.IsLink():
		// Hash equality → entire subtree identical, count and skip.
		if *entryA.Link == *entryB.Link {
			*unchanged += countAllBindings(cs, *entryA.Link)
			return
		}
		childA, okA := LoadTrieNode(cs, *entryA.Link)
		childB, okB := LoadTrieNode(cs, *entryB.Link)
		if !okA || !okB {
			return
		}
		diffNodes(cs, childA, childB, added, removed, changed, unchanged)

	case entryA.IsBucket() && entryB.IsLink():
		// Flatten the link side's subtree into a virtual bucket and merge.
		child, ok := LoadTrieNode(cs, *entryB.Link)
		if !ok {
			return
		}
		bindingsB := CollectSubtreeTuples(cs, child)
		diffBuckets(entryA.Bucket, bindingsB, added, removed, changed, unchanged)

	case entryA.IsLink() && entryB.IsBucket():
		child, ok := LoadTrieNode(cs, *entryA.Link)
		if !ok {
			return
		}
		bindingsA := CollectSubtreeTuples(cs, child)
		diffBuckets(bindingsA, entryB.Bucket, added, removed, changed, unchanged)
	}
}

// diffBuckets merge-walks two lex-sorted bucket slices.
func diffBuckets(
	bucketA, bucketB []types.BucketTuple,
	added map[string]hash.Hash,
	removed map[string]hash.Hash,
	changed map[string]types.DiffChangeData,
	unchanged *uint64,
) {
	i, j := 0, 0
	for i < len(bucketA) && j < len(bucketB) {
		switch {
		case bucketA[i].Key < bucketB[j].Key:
			removed[bucketA[i].Key] = bucketA[i].ValueHash
			i++
		case bucketA[i].Key > bucketB[j].Key:
			added[bucketB[j].Key] = bucketB[j].ValueHash
			j++
		default:
			if bucketA[i].ValueHash == bucketB[j].ValueHash {
				*unchanged++
			} else {
				changed[bucketA[i].Key] = types.DiffChangeData{
					BaseHash:   bucketA[i].ValueHash,
					TargetHash: bucketB[j].ValueHash,
				}
			}
			i++
			j++
		}
	}
	for ; i < len(bucketA); i++ {
		removed[bucketA[i].Key] = bucketA[i].ValueHash
	}
	for ; j < len(bucketB); j++ {
		added[bucketB[j].Key] = bucketB[j].ValueHash
	}
}

// collectEntryAs flattens every (key, value_hash) reachable from entry
// into out (keyed by relative_key). Used when a bitmap position is
// present in only one side of a diff: the whole subtree is added or
// removed.
func collectEntryAs(cs store.ContentStore, entry types.NodeEntry, out map[string]hash.Hash) {
	if entry.IsBucket() {
		for _, t := range entry.Bucket {
			out[t.Key] = t.ValueHash
		}
		return
	}
	child, ok := LoadTrieNode(cs, *entry.Link)
	if !ok {
		return
	}
	for _, t := range CollectSubtreeTuples(cs, child) {
		out[t.Key] = t.ValueHash
	}
}

// countAllBindings returns the total binding count under nodeHash. Used
// by the unchanged-count accumulator on hash-equality early-exit.
func countAllBindings(cs store.ContentStore, nodeHash hash.Hash) uint64 {
	node, ok := LoadTrieNode(cs, nodeHash)
	if !ok {
		return 0
	}
	return uint64(BranchSize(cs, node))
}

