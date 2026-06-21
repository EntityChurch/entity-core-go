package tree

import (
	"sort"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Binding represents a (relative_key → value_hash) pair used during trie
// construction.
type Binding struct {
	Path string
	Hash hash.Hash
}

// BuildTrie builds a content-addressed IPLD HashMap (HAMT + CHAMP) from a
// set of bindings per EXTENSION-TREE v4.0 §3.3. Returns the root node hash
// and stores all trie nodes in the content store. Empty bindings → canonical
// empty-root node.
//
// Algorithm: start from EmptyNode and incrementally TriePut each binding.
// CHAMP canonical-form is maintained after every put, so the resulting
// trie is byte-identical to any other peer's BuildTrie over the same
// binding set — this is the cross-impl convergence guarantee.
//
// Iteration order over the input is irrelevant for the output hash because
// CHAMP-canonical insert produces a permutation-invariant structure.
func BuildTrie(cs store.ContentStore, bindings []Binding) (hash.Hash, error) {
	if len(bindings) == 0 {
		return StoreTrieNode(cs, EmptyNode())
	}
	rootHash, err := StoreTrieNode(cs, EmptyNode())
	if err != nil {
		return hash.Hash{}, err
	}
	for _, b := range bindings {
		rootHash, err = TriePut(cs, rootHash, b.Path, b.Hash)
		if err != nil {
			return hash.Hash{}, err
		}
	}
	return rootHash, nil
}

// CollectAllBindings walks the HAMT rooted at nodeHash and returns every
// (relative_key → value_hash) binding. If prefix is non-empty, it is
// prepended to each key (joined with "/" when both are non-empty).
//
// Under v4.0 hash-keyed routing the relative_key is stored in full inside
// leaf buckets — there is no per-node path accumulation. The function
// reads keys directly from buckets; the hash-bit traversal order is
// discarded.
func CollectAllBindings(cs store.ContentStore, nodeHash hash.Hash, prefix string) map[string]hash.Hash {
	result := make(map[string]hash.Hash)
	node, ok := LoadTrieNode(cs, nodeHash)
	if !ok {
		return result
	}
	collectBindings(cs, node, prefix, result)
	return result
}

func collectBindings(cs store.ContentStore, node types.SnapshotNodeData, prefix string, out map[string]hash.Hash) {
	for _, entry := range node.Data {
		if entry.IsBucket() {
			for _, t := range entry.Bucket {
				out[joinKey(prefix, t.Key)] = t.ValueHash
			}
		} else {
			child, ok := LoadTrieNode(cs, *entry.Link)
			if !ok {
				continue
			}
			collectBindings(cs, child, prefix, out)
		}
	}
}

// joinKey combines a caller-supplied prefix with a bucket-stored relative
// key. Empty prefix is the common case (every caller in this repo today
// passes "") and the bucket key is returned verbatim.
func joinKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	if key == "" {
		return prefix
	}
	return prefix + "/" + key
}

// SortedParents returns parents sorted by lexicographic binary comparison.
// This ensures deterministic version entry hashing.
//
// Normalizes nil to an empty slice so CBOR encodes as array-of-length-0 (0x80)
// rather than null (0xf6). Per EXTENSION-REVISION §6.1 the entry shape is
// `{root, parents}` with `parents: []` when no current head; null here
// diverges from Rust/Python on the content hash and breaks cross-impl
// convergence (P4).
func SortedParents(parents []hash.Hash) []hash.Hash {
	if parents == nil {
		return []hash.Hash{}
	}
	if len(parents) <= 1 {
		return parents
	}
	sorted := make([]hash.Hash, len(parents))
	copy(sorted, parents)
	sort.Slice(sorted, func(i, j int) bool {
		ib := sorted[i].Bytes()
		jb := sorted[j].Bytes()
		for k := 0; k < len(ib) && k < len(jb); k++ {
			if ib[k] != jb[k] {
				return ib[k] < jb[k]
			}
		}
		return len(ib) < len(jb)
	})
	return sorted
}
