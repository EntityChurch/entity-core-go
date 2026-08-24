package revision

import (
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
				// REV-GLOB-TYPES-1: the same four forms apply to the type-name
				// subject — `app/*` (subtree) and `*-draft` (suffix) both match
				// here, not just exact type names.
				if ok && matchesAnyPattern(ent.Type, config.ExcludeTypes) {
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

// globMatch implements EXTENSION-REVISION §2.4's exclude / exclude_types matcher:
// exactly FOUR forms, no `**` and no segment-scoped `*`. `subject` is the
// prefix-relative path (for `exclude`) or the entity type name (for
// `exclude_types`). Forms are tested in the spec's order:
//
//  1. "*"        — match all.
//  2. "<lit>/*"  — SUBTREE PREFIX, identical to ENTITY-CORE-PROTOCOL §5.4
//     `matches_pattern`: the `*` crosses `/` at ANY depth. The
//     trailing `*` is dropped and the `/` is RETAINED, so
//     "system/revision/*" matches "system/revision/head/{H}/deep"
//     yet not the sibling "system/revisionary". This is why §6.1's
//     Reentrancy exclusion needs no second wildcard.
//  3. "*<lit>"   — TRAILING LITERAL, a byte-suffix over the WHOLE subject; `/`
//     is NOT special. "*.cache" matches "a/b/foo.cache" and
//     ".cache", not "a/cache/b" or "foo.cache.tmp". The one form
//     beyond §5.4's vocabulary (the operator's addition).
//  4. "<lit>"    — EXACT.
//
// There is deliberately NO stdlib fallback. A matcher that merely dropped `**`
// but still called path.Match would give `*` segment-scoped semantics that
// CONTRADICT §5.4 — the exact hash-determining divergence §2.4 pins against
// (capability/subscription §5.4 `*` crosses `/`; path.Match's does not). Any
// pattern outside the four forms is rejected at config write by
// validExcludePattern (§4.4.17 V6) before it can reach here.
func globMatch(pattern, subject string) bool {
	switch {
	case pattern == "*": // form 1
		return true
	case strings.HasSuffix(pattern, "/*"): // form 2 — drop "*", retain "/"
		return strings.HasPrefix(subject, pattern[:len(pattern)-1])
	case strings.HasPrefix(pattern, "*"): // form 3 — drop leading "*"
		return strings.HasSuffix(subject, pattern[1:])
	default: // form 4
		return subject == pattern
	}
}

// validExcludePattern enforces EXTENSION-REVISION §4.4.17 V6: an `exclude` /
// `exclude_types` pattern MUST be one of globMatch's four forms and nothing
// else. A valid pattern contains AT MOST ONE `*`, and that `*` is either the
// whole pattern, the final character preceded by `/`, or the first character.
// `**`, `a/**/b`, `a*b`, `*a*` are all rejected. This is what makes the matcher
// deterministic rather than merely specified — the load-bearing check is that a
// peer refuses `**` at write rather than silently omitting it from its matcher.
func validExcludePattern(pattern string) bool {
	switch strings.Count(pattern, "*") {
	case 0: // form 4 — exact
		return true
	case 1:
		return pattern == "*" || // form 1
			strings.HasSuffix(pattern, "/*") || // form 2 — final char, preceded by "/"
			strings.HasPrefix(pattern, "*") // form 3 — first char
	default: // two or more `*`
		return false
	}
}
