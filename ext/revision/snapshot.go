package revision

import (
	"path"
	"strings"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// computeBindings collects path→hash bindings from the location index under prefix.
// Skips system/revision/ metadata paths.
func computeBindings(hctx *handler.HandlerContext, prefix string) []tree.Binding {
	entries := hctx.LocationIndex.List(prefix)
	var result []tree.Binding
	for _, entry := range entries {
		relPath := trimPrefix(entry.Path, prefix, hctx.LocalPeerID)
		if relPath == "" || strings.HasPrefix(relPath, "system/revision/") {
			continue
		}
		result = append(result, tree.Binding{Path: relPath, Hash: entry.Hash})
	}
	return result
}

// computeVersionedBindings collects bindings with config-based exclusions.
func computeVersionedBindings(hctx *handler.HandlerContext, prefix string, config *types.RevisionConfigData) []tree.Binding {
	entries := hctx.LocationIndex.List(prefix)
	var result []tree.Binding
	for _, entry := range entries {
		relPath := trimPrefix(entry.Path, prefix, hctx.LocalPeerID)
		if relPath == "" {
			continue
		}

		if config != nil {
			if matchesAnyPattern(relPath, config.Exclude) {
				continue
			}
			if len(config.ExcludeTypes) > 0 {
				ent, ok := hctx.Store.Get(entry.Hash)
				if ok && matchesAnyExact(ent.Type, config.ExcludeTypes) {
					continue
				}
			}
		}

		result = append(result, tree.Binding{Path: relPath, Hash: entry.Hash})
	}
	return result
}

// computeTrieRoot builds a trie from the current tree state and returns the root hash.
func computeTrieRoot(hctx *handler.HandlerContext, prefix string, config *types.RevisionConfigData) (hash.Hash, error) {
	var bindings []tree.Binding
	if config != nil {
		bindings = computeVersionedBindings(hctx, prefix, config)
	} else {
		bindings = computeBindings(hctx, prefix)
	}
	return tree.BuildTrie(hctx.Store, bindings)
}

// computeBindingsMap computes a flat path→hash map from the tree (for status pending count).
func computeBindingsMap(hctx *handler.HandlerContext, prefix string) map[string]hash.Hash {
	entries := hctx.LocationIndex.List(prefix)
	bindings := make(map[string]hash.Hash)
	for _, entry := range entries {
		relPath := trimPrefix(entry.Path, prefix, hctx.LocalPeerID)
		if relPath == "" || strings.HasPrefix(relPath, "system/revision/") {
			continue
		}
		bindings[relPath] = entry.Hash
	}
	return bindings
}

// trieToBindings extracts all bindings from a trie root for tree application.
func trieToBindings(cs store.ContentStore, rootHash hash.Hash) map[string]hash.Hash {
	return tree.CollectAllBindings(cs, rootHash, "")
}

// matchesAnyPattern checks if path matches any glob pattern in the list.
func matchesAnyPattern(p string, patterns []string) bool {
	for _, pattern := range patterns {
		if globMatch(pattern, p) {
			return true
		}
	}
	return false
}

// matchesAnyExact checks if value matches any string in the list.
func matchesAnyExact(value string, list []string) bool {
	for _, item := range list {
		if value == item {
			return true
		}
	}
	return false
}

// globMatch implements simple glob matching (*, **).
func globMatch(pattern, name string) bool {
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := parts[1]
		if !strings.HasPrefix(name, prefix) {
			return false
		}
		if suffix == "" || suffix == "/" {
			return true
		}
		rest := name[len(prefix):]
		for i := 0; i <= len(rest); i++ {
			if i == 0 || (i > 0 && rest[i-1] == '/') {
				matched, _ := path.Match(strings.TrimPrefix(suffix, "/"), rest[i:])
				if matched {
					return true
				}
			}
		}
		return false
	}
	matched, _ := path.Match(pattern, name)
	return matched
}
