package tree

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// HAMT parameters per EXTENSION-TREE v4.0 §3.1.
const (
	// BitWidth is the number of hash bits consumed per level. K = 32 buckets per node.
	BitWidth = 5
	// K is the fanout: number of bitmap positions per node.
	K = 1 << BitWidth
	// BucketSize is the maximum tuples per bucket before promoting to a sub-node.
	BucketSize = 3
	// BitmapBytes is the byte length of the bitmap (K / 8).
	BitmapBytes = K / 8 // 4 for K=32
	// MaxLevel is the maximum descent depth before bits exhaust (256 bits / 5 bits per level).
	MaxLevel = 256 / BitWidth // 51 full levels; the 52nd level has only 1 bit so cannot be used
)

// EmptyNode returns a canonical empty HAMT node: zero bitmap and an empty
// entries array. Used as the initial root for BuildTrie([]) and as the
// fallback for trie operations on a missing root.
func EmptyNode() types.SnapshotNodeData {
	return types.SnapshotNodeData{
		Map:  make([]byte, BitmapBytes),
		Data: []types.NodeEntry{},
	}
}

// StoreTrieNode encodes node via ECF, wraps it as a system/tree/snapshot/node
// entity, and stores it in the content store. Returns the content hash.
func StoreTrieNode(cs store.ContentStore, node types.SnapshotNodeData) (hash.Hash, error) {
	raw, err := ecf.Encode(node)
	if err != nil {
		return hash.Hash{}, err
	}
	ent, err := entity.NewEntity(types.TypeTreeSnapshotNode, cbor.RawMessage(raw))
	if err != nil {
		return hash.Hash{}, err
	}
	return cs.Put(ent)
}

// LoadTrieNode loads a trie node from the content store. Returns (node,
// true) on success; (zero, false) when the hash is unknown or the entity
// fails to decode.
func LoadTrieNode(cs store.ContentStore, h hash.Hash) (types.SnapshotNodeData, bool) {
	ent, ok := cs.Get(h)
	if !ok {
		return types.SnapshotNodeData{}, false
	}
	node, err := types.SnapshotNodeDataFromEntity(ent)
	if err != nil {
		return types.SnapshotNodeData{}, false
	}
	return node, true
}

// HashKey returns SHA-256(UTF-8(relativeKey)) — the routing hash per §3.3.
// Canonical-normalize of relative_key here is the identity (existing path
// canonicalization already happens upstream when paths are normalized into
// the location index).
func HashKey(relativeKey string) [sha256.Size]byte {
	return sha256.Sum256([]byte(relativeKey))
}

// HashSlice extracts the 5-bit position at the given level from a SHA-256
// hash, MSB-first per spec §3.4.2. Level 0 = bits 0-4 of byte 0; level 1
// = bits 5-9 spanning bytes 0-1; etc.
func HashSlice(hashBytes [sha256.Size]byte, level int) int {
	if level < 0 || level >= MaxLevel {
		// Out of range — caller should not descend past MaxLevel.
		// In practice unreachable for typical N (depth ~ log_32(N)).
		return 0
	}
	bitOffset := level * BitWidth
	byteOffset := bitOffset / 8
	bitInByte := bitOffset % 8
	// Build a 16-bit big-endian word spanning [byte, byte+1] so the 5-bit
	// slice always fits within a single word read (we only ever need 8+5=13
	// bits in the worst case).
	var v uint16 = uint16(hashBytes[byteOffset]) << 8
	if byteOffset+1 < len(hashBytes) {
		v |= uint16(hashBytes[byteOffset+1])
	}
	shift := 16 - bitInByte - BitWidth
	return int((v >> uint(shift)) & ((1 << BitWidth) - 1))
}

// BitmapSet sets bit p in a K-bit bitmap encoded as BitmapBytes bytes big-
// endian (MSB byte first). Position 0 → 0x00000001; position 28 →
// 0x10000000. Caller MUST ensure bm has length BitmapBytes.
func BitmapSet(bm []byte, p int) {
	byteIdx := BitmapBytes - 1 - (p / 8)
	bitIdx := p % 8
	bm[byteIdx] |= 1 << uint(bitIdx)
}

// BitmapClear clears bit p in a K-bit bitmap (see BitmapSet).
func BitmapClear(bm []byte, p int) {
	byteIdx := BitmapBytes - 1 - (p / 8)
	bitIdx := p % 8
	bm[byteIdx] &^= 1 << uint(bitIdx)
}

// BitmapGet reports whether bit p is set in the bitmap.
func BitmapGet(bm []byte, p int) bool {
	byteIdx := BitmapBytes - 1 - (p / 8)
	bitIdx := p % 8
	return bm[byteIdx]&(1<<uint(bitIdx)) != 0
}

// BitmapU32 reads the bitmap as a uint32 (big-endian).
func BitmapU32(bm []byte) uint32 {
	return uint32(bm[0])<<24 | uint32(bm[1])<<16 | uint32(bm[2])<<8 | uint32(bm[3])
}

// PopcountBelow returns the number of set bits strictly below position p.
// This is the dense-array index for the entry at position p (when bit p
// is set in the bitmap).
func PopcountBelow(bm []byte, p int) int {
	u := BitmapU32(bm)
	mask := uint32(1)<<uint(p) - 1
	return bits.OnesCount32(u & mask)
}

// Popcount returns the total number of set bits in the bitmap (= len(Data)).
func Popcount(bm []byte) int {
	return bits.OnesCount32(BitmapU32(bm))
}

// IterateSetBits returns the bit positions (in ascending order) set in the
// bitmap. Allocates a slice of length Popcount(bm).
func IterateSetBits(bm []byte) []int {
	u := BitmapU32(bm)
	out := make([]int, 0, bits.OnesCount32(u))
	for u != 0 {
		p := bits.TrailingZeros32(u)
		out = append(out, p)
		u &= u - 1
	}
	return out
}

// BucketInsert returns a new bucket with (key, valueHash) inserted lex-
// sorted by key. If key already exists the value_hash is replaced. The
// input bucket is not mutated.
func BucketInsert(bucket []types.BucketTuple, key string, valueHash hash.Hash) []types.BucketTuple {
	idx := sort.Search(len(bucket), func(i int) bool { return bucket[i].Key >= key })
	if idx < len(bucket) && bucket[idx].Key == key {
		out := make([]types.BucketTuple, len(bucket))
		copy(out, bucket)
		out[idx].ValueHash = valueHash
		return out
	}
	out := make([]types.BucketTuple, 0, len(bucket)+1)
	out = append(out, bucket[:idx]...)
	out = append(out, types.BucketTuple{Key: key, ValueHash: valueHash})
	out = append(out, bucket[idx:]...)
	return out
}

// BucketRemove returns (bucket-without-key, true) if key existed; otherwise
// (bucket, false). The input bucket is not mutated.
func BucketRemove(bucket []types.BucketTuple, key string) ([]types.BucketTuple, bool) {
	idx := sort.Search(len(bucket), func(i int) bool { return bucket[i].Key >= key })
	if idx >= len(bucket) || bucket[idx].Key != key {
		return bucket, false
	}
	out := make([]types.BucketTuple, 0, len(bucket)-1)
	out = append(out, bucket[:idx]...)
	out = append(out, bucket[idx+1:]...)
	return out, true
}

// BucketFind returns the value_hash for key, or (zero, false) if absent.
func BucketFind(bucket []types.BucketTuple, key string) (hash.Hash, bool) {
	idx := sort.Search(len(bucket), func(i int) bool { return bucket[i].Key >= key })
	if idx >= len(bucket) || bucket[idx].Key != key {
		return hash.Hash{}, false
	}
	return bucket[idx].ValueHash, true
}

// BranchSize returns the total count of reachable (key, value_hash) tuples
// in the subtree rooted at node. Used by the CHAMP collapse check on
// delete (canonical form: every non-root node MUST have branchSize ≥
// BucketSize+1 = 4).
func BranchSize(cs store.ContentStore, node types.SnapshotNodeData) int {
	count := 0
	for _, entry := range node.Data {
		if entry.IsBucket() {
			count += len(entry.Bucket)
		} else {
			child, ok := LoadTrieNode(cs, *entry.Link)
			if !ok {
				// Missing sub-node — defensive: skip silently (treat as 0).
				continue
			}
			count += BranchSize(cs, child)
		}
	}
	return count
}

// CollectSubtreeTuples returns every (key, value_hash) tuple reachable
// from node. Used by CHAMP collapse to inline a sub-node's contents into
// the parent's bucket position. Output is lex-sorted by key so the caller
// can install it as a canonical bucket directly.
func CollectSubtreeTuples(cs store.ContentStore, node types.SnapshotNodeData) []types.BucketTuple {
	var out []types.BucketTuple
	collectSubtreeTuples(cs, node, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func collectSubtreeTuples(cs store.ContentStore, node types.SnapshotNodeData, out *[]types.BucketTuple) {
	for _, entry := range node.Data {
		if entry.IsBucket() {
			*out = append(*out, entry.Bucket...)
		} else {
			child, ok := LoadTrieNode(cs, *entry.Link)
			if !ok {
				continue
			}
			collectSubtreeTuples(cs, child, out)
		}
	}
}

// LinkEntry wraps a hash as a link NodeEntry.
func LinkEntry(h hash.Hash) types.NodeEntry {
	return types.NodeEntry{Link: &h}
}

// CollectNodeClosure returns the transitive set of hashes reachable from
// rootHash: rootHash itself, every interior sub-node it links to, and every
// leaf-bucket value hash. Per EXTENSION-NETWORK §6.5.6 Amendment 10 this is
// the served set a publisher of `signed_pointer` MUST cover so a consumer's
// hash-chain walk from a signed root does not 404 on an interior CHAMP node
// (interior nodes are hash-linked, not path-bound, so NamespaceScope alone
// fails them). Missing nodes are skipped — the walk is best-effort, callers
// that need strict closure should ensure the trie is locally complete.
func CollectNodeClosure(cs store.ContentStore, rootHash hash.Hash) map[hash.Hash]struct{} {
	out := make(map[hash.Hash]struct{})
	collectNodeClosure(cs, rootHash, out)
	return out
}

func collectNodeClosure(cs store.ContentStore, nodeHash hash.Hash, out map[hash.Hash]struct{}) {
	if nodeHash.IsZero() {
		return
	}
	if _, seen := out[nodeHash]; seen {
		return
	}
	out[nodeHash] = struct{}{}
	node, ok := LoadTrieNode(cs, nodeHash)
	if !ok {
		return
	}
	for _, entry := range node.Data {
		if entry.IsLink() {
			collectNodeClosure(cs, *entry.Link, out)
			continue
		}
		for _, tuple := range entry.Bucket {
			out[tuple.ValueHash] = struct{}{}
		}
	}
}

// BucketEntry wraps a sorted tuple slice as a bucket NodeEntry. The caller
// owns the slice (no copy is made).
func BucketEntry(b []types.BucketTuple) types.NodeEntry {
	return types.NodeEntry{Bucket: b}
}

// EnsureValid returns an error if the node has internally inconsistent
// shape (bitmap popcount != data length, malformed bucket sort, etc.).
// Used by tests; not called on the hot path.
func EnsureValid(node types.SnapshotNodeData) error {
	if len(node.Map) != BitmapBytes {
		return fmt.Errorf("node: bitmap length %d, expected %d", len(node.Map), BitmapBytes)
	}
	if pc := Popcount(node.Map); pc != len(node.Data) {
		return fmt.Errorf("node: popcount %d != len(data) %d", pc, len(node.Data))
	}
	for i, entry := range node.Data {
		if entry.IsBucket() {
			if len(entry.Bucket) == 0 || len(entry.Bucket) > BucketSize {
				return fmt.Errorf("node[%d]: bucket size %d out of [1, %d]", i, len(entry.Bucket), BucketSize)
			}
			for j := 1; j < len(entry.Bucket); j++ {
				if entry.Bucket[j-1].Key >= entry.Bucket[j].Key {
					return fmt.Errorf("node[%d]: bucket not sorted at %d", i, j)
				}
			}
		} else if entry.Link == nil {
			return fmt.Errorf("node[%d]: empty entry (no bucket and no link)", i)
		}
	}
	return nil
}
