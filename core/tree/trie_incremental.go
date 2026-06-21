package tree

import (
	"crypto/sha256"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TriePut inserts or replaces a single (relativeKey → value) binding in
// the HAMT rooted at currentRoot and returns the new root hash. Per
// EXTENSION-TREE v4.0 §3.4.2. The result is byte-identical to
// BuildTrie(cs, full_updated_bindings) — that invariant is the cross-impl
// convergence guarantee and is exercised by the fuzzer.
//
// Algorithm (bit-slice descent with bucket promotion on overflow):
//
//  1. Compute h = SHA-256(UTF-8(relativeKey)).
//  2. At each level L, compute position p = 5 bits of h starting at bit
//     offset 5*L (MSB-first per spec §3.4.2). Inspect node.Map at bit p:
//     - clear: set bit p; insert a single-tuple bucket at popcount index
//       in node.Data; done.
//     - set: consult the entry at popcount index:
//     - bucket and key present: replace value_hash.
//     - bucket with len < BucketSize: insert tuple sorted lex.
//     - bucket with len == BucketSize: promote — build a sub-node at
//       level L+1 by routing all BucketSize+1 tuples by their next 5
//       bits; replace this entry with a Link to the sub-node.
//     - link: descend into the sub-node and recurse at level L+1.
//  3. On ascent, every modified node is re-stored to the content store
//     and the new hash is propagated up.
//
// Cost: O(depth) per call — one Put per ancestor on the modified path.
func TriePut(cs store.ContentStore, currentRoot hash.Hash, relativeKey string, value hash.Hash) (hash.Hash, error) {
	root := loadOrEmpty(cs, currentRoot)
	h := HashKey(relativeKey)
	newRoot, err := putAtNode(cs, root, h, 0, relativeKey, value)
	if err != nil {
		return hash.Hash{}, err
	}
	return StoreTrieNode(cs, newRoot)
}

// TrieRemove unbinds relativeKey from the HAMT rooted at currentRoot and
// returns the new root hash. Returns currentRoot unchanged when the key
// is not present. On ascent the CHAMP-on-delete canonical form is
// enforced: every non-root node MUST have branchSize ≥ BucketSize+1 = 4
// reachable tuples; a violator is collapsed into the parent's bucket at
// the position that linked to it (preserving lex sort).
//
// The root node is exempt from the canonical-form lower bound (per
// EXTENSION-TREE §3.1).
func TrieRemove(cs store.ContentStore, currentRoot hash.Hash, relativeKey string) (hash.Hash, error) {
	if currentRoot.IsZero() {
		return currentRoot, nil
	}
	root, ok := LoadTrieNode(cs, currentRoot)
	if !ok {
		return currentRoot, nil
	}
	h := HashKey(relativeKey)
	newRoot, removed, err := removeAtNode(cs, root, h, 0, relativeKey, true /* isRoot */)
	if err != nil {
		return hash.Hash{}, err
	}
	if !removed {
		return currentRoot, nil
	}
	return StoreTrieNode(cs, newRoot)
}

// putAtNode applies put(relativeKey → value) within node at the given
// descent level. Returns the modified node (caller stores it).
func putAtNode(
	cs store.ContentStore,
	node types.SnapshotNodeData,
	h [sha256.Size]byte,
	level int,
	relativeKey string,
	value hash.Hash,
) (types.SnapshotNodeData, error) {
	if level >= MaxLevel {
		return node, fmt.Errorf("trie put: descended past MaxLevel=%d (hash collision)", MaxLevel)
	}

	p := HashSlice(h, level)
	idx := PopcountBelow(node.Map, p)

	// Bit clear → fresh insert at popcount index.
	if !BitmapGet(node.Map, p) {
		newMap := cloneBytes(node.Map)
		BitmapSet(newMap, p)
		bucket := []types.BucketTuple{{Key: relativeKey, ValueHash: value}}
		newData := insertEntry(node.Data, idx, BucketEntry(bucket))
		return types.SnapshotNodeData{Map: newMap, Data: newData}, nil
	}

	entry := node.Data[idx]

	if entry.IsBucket() {
		bucket := entry.Bucket
		if _, present := BucketFind(bucket, relativeKey); present {
			// Replace in-place — key already present at this bucket.
			newBucket := BucketInsert(bucket, relativeKey, value)
			newData := replaceEntry(node.Data, idx, BucketEntry(newBucket))
			return types.SnapshotNodeData{Map: cloneBytes(node.Map), Data: newData}, nil
		}
		if len(bucket) < BucketSize {
			newBucket := BucketInsert(bucket, relativeKey, value)
			newData := replaceEntry(node.Data, idx, BucketEntry(newBucket))
			return types.SnapshotNodeData{Map: cloneBytes(node.Map), Data: newData}, nil
		}
		// Bucket full → promote at next level.
		subNode, err := promoteBucket(cs, bucket, relativeKey, value, level+1)
		if err != nil {
			return types.SnapshotNodeData{}, err
		}
		subHash, err := StoreTrieNode(cs, subNode)
		if err != nil {
			return types.SnapshotNodeData{}, err
		}
		newData := replaceEntry(node.Data, idx, LinkEntry(subHash))
		return types.SnapshotNodeData{Map: cloneBytes(node.Map), Data: newData}, nil
	}

	// Link → descend.
	child, ok := LoadTrieNode(cs, *entry.Link)
	if !ok {
		return types.SnapshotNodeData{}, fmt.Errorf("trie put: child node missing: %s", entry.Link)
	}
	newChild, err := putAtNode(cs, child, h, level+1, relativeKey, value)
	if err != nil {
		return types.SnapshotNodeData{}, err
	}
	newChildHash, err := StoreTrieNode(cs, newChild)
	if err != nil {
		return types.SnapshotNodeData{}, err
	}
	newData := replaceEntry(node.Data, idx, LinkEntry(newChildHash))
	return types.SnapshotNodeData{Map: cloneBytes(node.Map), Data: newData}, nil
}

// promoteBucket builds a sub-node that holds bucket's BucketSize tuples
// plus the new (relativeKey → value) tuple, distributed by their next-
// level hash bits. The resulting sub-node is canonical (it has
// BucketSize+1 reachable tuples — the invariant lower bound).
func promoteBucket(
	cs store.ContentStore,
	bucket []types.BucketTuple,
	newKey string,
	newValue hash.Hash,
	level int,
) (types.SnapshotNodeData, error) {
	sub := EmptyNode()
	// Insert each existing tuple, then the new one. The order doesn't
	// affect the final canonical form (CHAMP invariant).
	for _, t := range bucket {
		h := HashKey(t.Key)
		next, err := putAtNode(cs, sub, h, level, t.Key, t.ValueHash)
		if err != nil {
			return types.SnapshotNodeData{}, err
		}
		sub = next
	}
	h := HashKey(newKey)
	return putAtNode(cs, sub, h, level, newKey, newValue)
}

// removeAtNode applies remove(relativeKey) within node at the given
// descent level. Returns (newNode, true) when the key was present and
// removed, (node, false) otherwise. CHAMP-on-delete collapse is
// performed by the parent — see collapsedChild.
//
// isRoot indicates whether this node is the root (exempt from the
// canonical-form lower bound).
func removeAtNode(
	cs store.ContentStore,
	node types.SnapshotNodeData,
	h [sha256.Size]byte,
	level int,
	relativeKey string,
	isRoot bool,
) (types.SnapshotNodeData, bool, error) {
	p := HashSlice(h, level)
	if !BitmapGet(node.Map, p) {
		return node, false, nil
	}
	idx := PopcountBelow(node.Map, p)
	entry := node.Data[idx]

	if entry.IsBucket() {
		newBucket, ok := BucketRemove(entry.Bucket, relativeKey)
		if !ok {
			return node, false, nil
		}
		if len(newBucket) == 0 {
			// Bucket emptied: drop entry and clear bitmap bit.
			newMap := cloneBytes(node.Map)
			BitmapClear(newMap, p)
			newData := removeEntryAt(node.Data, idx)
			return types.SnapshotNodeData{Map: newMap, Data: newData}, true, nil
		}
		newData := replaceEntry(node.Data, idx, BucketEntry(newBucket))
		return types.SnapshotNodeData{Map: cloneBytes(node.Map), Data: newData}, true, nil
	}

	// Link → descend, then on return apply CHAMP collapse if the child
	// drops below the canonical-form threshold.
	child, ok := LoadTrieNode(cs, *entry.Link)
	if !ok {
		return node, false, fmt.Errorf("trie remove: child node missing: %s", entry.Link)
	}
	newChild, removed, err := removeAtNode(cs, child, h, level+1, relativeKey, false /* isRoot */)
	if err != nil {
		return types.SnapshotNodeData{}, false, err
	}
	if !removed {
		return node, false, nil
	}

	// Decide between collapsing the sub-node into a bucket at this
	// position or re-storing it as a Link.
	collapsedTuples, doCollapse := collapsedChild(cs, newChild)
	if doCollapse {
		if len(collapsedTuples) == 0 {
			// Sub-node became empty — drop entry, clear bit.
			newMap := cloneBytes(node.Map)
			BitmapClear(newMap, p)
			newData := removeEntryAt(node.Data, idx)
			return types.SnapshotNodeData{Map: newMap, Data: newData}, true, nil
		}
		newData := replaceEntry(node.Data, idx, BucketEntry(collapsedTuples))
		return types.SnapshotNodeData{Map: cloneBytes(node.Map), Data: newData}, true, nil
	}

	// Sub-node remains a proper non-root node — store and update link.
	newChildHash, err := StoreTrieNode(cs, newChild)
	if err != nil {
		return types.SnapshotNodeData{}, false, err
	}
	newData := replaceEntry(node.Data, idx, LinkEntry(newChildHash))
	_ = isRoot // current node's exemption is enforced by the caller via the wrapper
	return types.SnapshotNodeData{Map: cloneBytes(node.Map), Data: newData}, true, nil
}

// collapsedChild inspects a freshly-modified non-root sub-node. If its
// branchSize has dropped below BucketSize+1 = 4, it returns (tuples, true)
// where tuples is the lex-sorted flattening of every reachable
// (key, value_hash) — the parent inlines these as a bucket at the position
// that linked here. Otherwise returns (nil, false) and the sub-node is
// stored normally.
func collapsedChild(cs store.ContentStore, child types.SnapshotNodeData) ([]types.BucketTuple, bool) {
	bs := BranchSize(cs, child)
	if bs >= BucketSize+1 {
		return nil, false
	}
	return CollectSubtreeTuples(cs, child), true
}

// loadOrEmpty returns the node at h, or the canonical EmptyNode when h is
// zero or absent. Treating a zero/missing root as empty lets TriePut be
// the initial-build path too.
func loadOrEmpty(cs store.ContentStore, h hash.Hash) types.SnapshotNodeData {
	if h.IsZero() {
		return EmptyNode()
	}
	node, ok := LoadTrieNode(cs, h)
	if !ok {
		return EmptyNode()
	}
	// Defensive: ensure Map is exactly BitmapBytes so callers don't have
	// to guard against a malformed on-disk node.
	if len(node.Map) != BitmapBytes {
		fixed := make([]byte, BitmapBytes)
		copy(fixed, node.Map)
		node.Map = fixed
	}
	if node.Data == nil {
		node.Data = []types.NodeEntry{}
	}
	return node
}

// cloneBytes returns a fresh copy of bm (length BitmapBytes assumed).
func cloneBytes(bm []byte) []byte {
	out := make([]byte, len(bm))
	copy(out, bm)
	return out
}

// insertEntry inserts entry at index idx, shifting the rest right.
func insertEntry(data []types.NodeEntry, idx int, entry types.NodeEntry) []types.NodeEntry {
	out := make([]types.NodeEntry, 0, len(data)+1)
	out = append(out, data[:idx]...)
	out = append(out, entry)
	out = append(out, data[idx:]...)
	return out
}

// replaceEntry returns a copy of data with element idx replaced by entry.
func replaceEntry(data []types.NodeEntry, idx int, entry types.NodeEntry) []types.NodeEntry {
	out := make([]types.NodeEntry, len(data))
	copy(out, data)
	out[idx] = entry
	return out
}

// removeEntryAt returns a copy of data with element idx removed.
func removeEntryAt(data []types.NodeEntry, idx int) []types.NodeEntry {
	out := make([]types.NodeEntry, 0, len(data)-1)
	out = append(out, data[:idx]...)
	out = append(out, data[idx+1:]...)
	return out
}
