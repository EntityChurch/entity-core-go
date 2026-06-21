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

// configEntry is a cached history config with its canonicalized pattern.
type configEntry struct {
	config           types.HistoryConfigData
	canonicalizedPat string
	specificity      int
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
		c.entries = append(c.entries, configEntry{
			config:           cfg,
			canonicalizedPat: canon,
			specificity:      patternSpecificity(canon),
		})
	}

	// Sort by specificity descending (most specific first).
	sort.Slice(c.entries, func(i, j int) bool {
		return c.entries[i].specificity > c.entries[j].specificity
	})
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

// patternSpecificity calculates specificity for pattern priority.
// More literal segments = higher specificity. Explicit peer ID > wildcard peer.
func patternSpecificity(pattern string) int {
	if pattern == "*" {
		return 0
	}
	segments := strings.Split(strings.Trim(pattern, "/"), "/")
	score := 0
	for _, seg := range segments {
		if seg != "*" {
			score += 2 // literal segment
		} else {
			score += 1 // wildcard segment (less specific)
		}
	}
	return score
}
