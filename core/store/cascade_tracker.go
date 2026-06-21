package store

import (
	"sync"
	"time"
)

// CascadeTracker maintains a map of chain_id → highest cascade depth seen.
// Used for cross-peer cascade depth enforcement: when a notification arrives
// with a chain_id, check the tracker to use max(incoming_depth, tracked_depth).
// Without this, chains crossing N peers allow N×DefaultMaxCascadeDepth total
// depth because each peer only sees its local portion.
type CascadeTracker struct {
	mu      sync.RWMutex
	entries map[string]cascadeEntry
	ttl     time.Duration
}

type cascadeEntry struct {
	MaxDepth uint64
	LastSeen time.Time
}

// NewCascadeTracker creates a tracker with the given TTL for entry expiration.
// Entries older than ttl are eligible for removal when Prune is called.
func NewCascadeTracker(ttl time.Duration) *CascadeTracker {
	return &CascadeTracker{
		entries: make(map[string]cascadeEntry),
		ttl:     ttl,
	}
}

// Update records or updates the cascade depth for a chain_id.
// Returns the effective depth (max of incoming and previously tracked).
func (ct *CascadeTracker) Update(chainID string, depth uint64) uint64 {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if entry, ok := ct.entries[chainID]; ok && entry.MaxDepth > depth {
		ct.entries[chainID] = cascadeEntry{MaxDepth: entry.MaxDepth, LastSeen: time.Now()}
		return entry.MaxDepth
	}
	ct.entries[chainID] = cascadeEntry{MaxDepth: depth, LastSeen: time.Now()}
	return depth
}

// Depth returns the tracked depth for a chain_id, or 0 if not tracked.
func (ct *CascadeTracker) Depth(chainID string) uint64 {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	if entry, ok := ct.entries[chainID]; ok {
		return entry.MaxDepth
	}
	return 0
}

// Prune removes entries older than the TTL. Call periodically.
func (ct *CascadeTracker) Prune() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	cutoff := time.Now().Add(-ct.ttl)
	for id, entry := range ct.entries {
		if entry.LastSeen.Before(cutoff) {
			delete(ct.entries, id)
		}
	}
}
