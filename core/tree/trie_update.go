package tree

import (
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
)

// BuildTrieForPrefix collects all bindings under prefix from the location index
// and builds a content-addressed trie rooted at the returned hash.
//
// Per EXTENSION-TREE v3.8 §3.4 this is the root of an incremental maintenance
// structure. Today the implementation is a full O(N) rebuild over all bindings
// under the prefix. Because it dispatches to BuildTrie the output hash is
// identical to any other path that builds a trie from the same binding set,
// which preserves the invariant required for interop with Rust/Python and for
// future incremental optimizations that replace this function.
func BuildTrieForPrefix(cs store.ContentStore, li store.LocationIndex, localPeerID crypto.PeerID, prefix string) (hash.Hash, error) {
	var qualifiedPrefix string
	if strings.HasPrefix(prefix, "/") {
		qualifiedPrefix = prefix
	} else {
		qualifiedPrefix = store.QualifyPath(string(localPeerID), prefix)
	}
	entries := li.List(prefix)

	var bindings []Binding
	for _, e := range entries {
		rel := strings.TrimPrefix(e.Path, qualifiedPrefix)
		if rel == "" {
			continue
		}
		bindings = append(bindings, Binding{Path: rel, Hash: e.Hash})
	}
	return BuildTrie(cs, bindings)
}
