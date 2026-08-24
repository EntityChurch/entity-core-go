package history

import (
	"sort"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// configPrefix is the tree path prefix where history configs are stored.
const configPrefix = "system/history/config/"

// configEntry is a cached history config with its canonicalized pattern and
// the two specificity keys (§6.2 v1.7). Key 3 — lexicographic byte order on the
// canonicalized pattern — is read off canonicalizedPat directly at compare time.
type configEntry struct {
	config           types.HistoryConfigData
	canonicalizedPat string
	literalSegs      int // key 1 — literal (non-"*") segment count; higher wins
	totalDepth       int // key 2 — total segment depth; higher wins
}

// configCache maintains an in-memory cache of history configurations,
// sorted by specificity (most specific first). Thread-safe.
type configCache struct {
	mu          sync.RWMutex
	entries     []configEntry
	localPeerID string
}

func newConfigCache(localPeerID string) *configCache {
	return &configCache{localPeerID: localPeerID}
}

// load scans the location index for all history configs and rebuilds the cache.
func (c *configCache) load(li store.LocationIndex, cs store.ContentStore) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = nil

	qualifiedPrefix := store.QualifyPath(c.localPeerID, configPrefix)
	entries := li.List(qualifiedPrefix)
	for _, e := range entries {
		ent, ok := cs.Get(e.Hash)
		if !ok {
			continue
		}
		if ent.Type != types.TypeHistoryConfig {
			continue
		}
		var cfg types.HistoryConfigData
		if err := ecf.Decode(ent.Data, &cfg); err != nil {
			continue
		}
		canon := canonicalizePattern(cfg.Pattern, c.localPeerID)
		lit, depth := patternSpecificity(canon)
		c.entries = append(c.entries, configEntry{
			config:           cfg,
			canonicalizedPat: canon,
			literalSegs:      lit,
			totalDepth:       depth,
		})
	}

	// Sort most-specific-first by the §6.2 three-key tuple. The comparator is a
	// TOTAL order (key 3 breaks every key-1/key-2 tie), so the selected config
	// does not depend on enumeration order — the v1.7 [MUST]. sort.Slice need not
	// be stable because no two distinct patterns can compare equal.
	sort.Slice(c.entries, func(i, j int) bool {
		return moreSpecific(c.entries[i], c.entries[j])
	})
}

// moreSpecific reports whether a outranks b under §6.2's ordered tuple:
// (1) literal segments — higher wins; (2) total depth — higher wins;
// (3) lexicographic byte order on the canonicalized pattern — LOWER wins.
// Key 3 makes the order total and peer-independent, so every conformant peer
// selects the same config regardless of the store's listing order.
func moreSpecific(a, b configEntry) bool {
	if a.literalSegs != b.literalSegs {
		return a.literalSegs > b.literalSegs
	}
	if a.totalDepth != b.totalDepth {
		return a.totalDepth > b.totalDepth
	}
	return a.canonicalizedPat < b.canonicalizedPat
}

// onTreeChange handles a config path change by reloading affected entry.
// Returns true if the path is a config path (caller can skip further processing).
func (c *configCache) isConfigPath(path string) bool {
	_, bare := store.SplitNamespace(path)
	return strings.HasPrefix(bare, configPrefix)
}

// find returns the most specific enabled config matching the given absolute path,
// or nil if no config matches or history is not enabled.
func (c *configCache) find(path string) *types.HistoryConfigData {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := range c.entries {
		e := &c.entries[i]
		if matchHistoryPattern(e.canonicalizedPat, path) {
			if e.config.Enabled {
				return &e.config
			}
			return nil // most specific match wins, but disabled
		}
	}
	return nil
}

// canonicalizePattern converts a config pattern to canonical form per §6.2.
// Short-form patterns get the local peer prefix. Already-absolute and
// peer-wildcard patterns pass through unchanged.
func canonicalizePattern(pattern, localPeerID string) string {
	if strings.HasPrefix(pattern, "/") {
		return pattern // already absolute
	}
	first := pattern
	if idx := strings.IndexByte(pattern, '/'); idx >= 0 {
		first = pattern[:idx]
	}
	if first == "*" {
		return pattern // peer wildcard
	}
	return "/" + localPeerID + "/" + pattern
}

// matchHistoryPattern checks if an absolute path matches a canonicalized pattern.
// Supports exact match, subtree wildcard (suffix /*), peer wildcard (*/), and full wildcard (*).
func matchHistoryPattern(pattern, path string) bool {
	if pattern == "*" || pattern == "/*/*" {
		return true
	}
	if pattern == path {
		return true
	}
	// Peer wildcard: */rest or */rest/* — must check before subtree wildcard
	// because patterns like "*/project/*" match both prefix checks.
	if strings.HasPrefix(pattern, "*/") {
		rest := pattern[2:]
		_, barePath := store.SplitNamespace(path)
		if rest == barePath {
			return true
		}
		if strings.HasSuffix(rest, "/*") {
			restPrefix := strings.TrimSuffix(rest, "*")
			return strings.HasPrefix(barePath, restPrefix)
		}
		return false
	}
	// Subtree wildcard: prefix/*
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return false
}

// patternSpecificity returns the two ordered specificity keys of a canonicalized
// pattern per §6.2 (v1.7): the count of literal (non-"*") segments and the total
// segment depth. §2.2's "explicit peer ID > wildcard peer" needs no separate key
// — an explicit peer segment is literal and a "*" peer segment is not, so key 1
// already ranks /{peerA}/project/* above */project/*.
//
// This deliberately does NOT collapse the two keys into one scalar: a scalar
// (e.g. "2 per literal, 1 per wildcard") manufactures ties §2.2 does not have —
// a/b/c/d (4 literal, depth 4) and a/*/c/*/e (3 literal, depth 5) both score 8 —
// and then resolves them by whatever the store yielded. Key 1 must decide that
// pair for the a/b/c/d config; the tuple comparison in moreSpecific does so.
func patternSpecificity(pattern string) (literal, depth int) {
	trimmed := strings.Trim(pattern, "/")
	if trimmed == "" {
		return 0, 0
	}
	for _, seg := range strings.Split(trimmed, "/") {
		depth++
		if seg != "*" {
			literal++
		}
	}
	return literal, depth
}
