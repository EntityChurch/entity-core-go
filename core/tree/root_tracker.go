package tree

import (
	"log"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// trackingConfigPrefix is where tracking-config entities live.
const trackingConfigPrefix = "system/tree/tracking-config/"

// rootStoragePrefix is where the current tracked root is written per prefix.
// Per EXTENSION-TREE v3.8 §3.4.1 the root is stored at system/tree/root/{prefix}.
const rootStoragePrefix = "system/tree/root/"

// RootTracker is a position-6 emit consumer (SYSTEM-COMPOSITION §2.2 /
// EXTENSION-TREE v3.8 §3.4.1a) that maintains an incremental trie root at
// system/tree/root/{prefix} for each enabled tracking-config.
//
// Register via peer.WithNamedSyncHook("tree/root-tracker", tracker.OnTreeChange)
// after history and before subscription. Call Load() after peer construction
// to initialize the config cache and perform the initial build for each
// enabled prefix.
type RootTracker struct {
	cs          store.ContentStore
	li          store.LocationIndex
	localPeerID string
	debugLog    *log.Logger

	mu       sync.RWMutex
	tracked  map[string]bool // prefix -> enabled
	bgCtx    *store.MutationContext
	identity hash.Hash

	// rebuildMu serializes rebuilds per-prefix. Without this, concurrent
	// rebuilds for the same prefix can race: each lists the live tree
	// independently and writes its trie root via li.Set without
	// coordination. The slower rebuild can land its trie LAST, overwriting
	// the faster (newer) rebuild's trie. Result: tracker.Root reflects a
	// stale snapshot of the live tree. AutoVersioner then emits a version
	// with that stale root. When that version becomes a "remote" in a
	// downstream 3-way merge, the missing paths get classified as "remote
	// deleted them" and trieMergeBindings adds them to the deletions list
	// — cascading data loss.
	// See the workbench F10 part-5 residual review.
	rebuildMu   sync.Mutex
	prefixLocks map[string]*sync.Mutex
}

// NewRootTracker creates a tracker that will read/write through the given
// content store. The LocationIndex must be set via SetLocationIndex after peer
// construction (same pattern as the history recorder).
func NewRootTracker(cs store.ContentStore, localPeerID string, debugLog *log.Logger) *RootTracker {
	return &RootTracker{
		cs:          cs,
		localPeerID: localPeerID,
		debugLog:    debugLog,
		tracked:     make(map[string]bool),
		prefixLocks: make(map[string]*sync.Mutex),
	}
}

// lockForPrefix returns a mutex unique to the given prefix, allocating on
// demand. Rebuilds serialize on this mutex so a rebuild's list-then-write
// is atomic relative to other rebuilds for the same prefix.
func (t *RootTracker) lockForPrefix(prefix string) *sync.Mutex {
	t.rebuildMu.Lock()
	defer t.rebuildMu.Unlock()
	mu, ok := t.prefixLocks[prefix]
	if !ok {
		mu = &sync.Mutex{}
		t.prefixLocks[prefix] = mu
	}
	return mu
}

// SetLocalPeerID updates the local peer ID and identity hash used for
// MutationContext on root writes. Must be called before Load().
func (t *RootTracker) SetLocalPeerID(id string, identityHash hash.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.localPeerID = id
	t.identity = identityHash
}

// SetLocationIndex sets the location index used for reads and root writes.
// Must be called after peer construction so the tracker uses the same
// NamespacedIndex that emits events.
func (t *RootTracker) SetLocationIndex(li store.LocationIndex) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.li = li
}

// Load scans existing tracking-config entities and performs an initial root
// build for every enabled prefix. Call after SetLocationIndex.
func (t *RootTracker) Load() {
	t.mu.Lock()
	if t.li == nil {
		t.mu.Unlock()
		return
	}

	t.tracked = make(map[string]bool)
	t.reloadConfigsLocked()

	// Cache a MutationContext for our own writes.
	var capHash hash.Hash
	if gh, ok := t.li.Get("system/capability/grants/system/tree"); ok {
		capHash = gh
	}
	t.bgCtx = &store.MutationContext{
		AuthorHash:     t.identity,
		CapabilityHash: capHash,
		HandlerPattern: "system/tree",
		Operation:      "track",
	}

	prefixes := make([]string, 0, len(t.tracked))
	for p, enabled := range t.tracked {
		if enabled {
			prefixes = append(prefixes, p)
		}
	}
	t.mu.Unlock()

	for _, p := range prefixes {
		t.rebuild(p)
	}
	t.debugf("loaded %d tracking configs", len(prefixes))
}

// OnTreeChange is the sync-hook entry point. Returns nil (success) — root
// tracking never intentionally halts the cascade.
func (t *RootTracker) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	if t.isSelfPath(evt.Path) {
		return nil
	}

	// Break feedback loops from sync-hook consumers that write inside our
	// tracked prefix. The published-root publisher binds its manifest at
	// system/peer/published-root/{peer_id} and its signature at
	// system/signature/{hex} — both under "system/" — so without this filter
	// the publisher's own write advances the trie root, which fires the
	// publisher again. Consumers self-tag via MutationContext.HandlerPattern;
	// see ext/publishedroot.PublisherHandlerPattern.
	if evt.Context != nil && isFeedbackLoopHandler(evt.Context.HandlerPattern) {
		return nil
	}

	if t.isConfigPath(evt.Path) {
		t.handleConfigChange()
		return nil
	}

	// Find tracked prefixes that contain this path, rebuild each.
	t.mu.RLock()
	var affected []string
	for prefix, enabled := range t.tracked {
		if !enabled {
			continue
		}
		if t.pathUnderPrefix(evt.Path, prefix) {
			affected = append(affected, prefix)
		}
	}
	t.mu.RUnlock()

	var parentDepth uint64
	if evt.Context != nil && evt.Context.CascadeDepth != nil {
		parentDepth = *evt.Context.CascadeDepth
	}
	for _, prefix := range affected {
		t.applyEventWithDepth(prefix, evt, parentDepth)
	}
	return nil
}

// handleConfigChange reloads the config cache and triggers initial builds for
// any newly-enabled prefixes.
func (t *RootTracker) handleConfigChange() {
	t.mu.Lock()
	prev := t.tracked
	t.tracked = make(map[string]bool)
	t.reloadConfigsLocked()
	// Determine which prefixes went from disabled/absent to enabled — those
	// need an initial O(N) build. Disabled prefixes retain a stale root; the
	// spec says the root SHOULD be removed. We do so by writing a tombstone
	// (empty trie) and then removing the binding.
	toBuild := make([]string, 0)
	toClear := make([]string, 0)
	for p, enabled := range t.tracked {
		if enabled && !prev[p] {
			toBuild = append(toBuild, p)
		}
	}
	for p, wasEnabled := range prev {
		if wasEnabled && !t.tracked[p] {
			toClear = append(toClear, p)
		}
	}
	t.mu.Unlock()

	for _, p := range toBuild {
		t.rebuild(p)
	}
	for _, p := range toClear {
		t.clear(p)
	}
}

// reloadConfigsLocked rescans tracking-config entities. Caller must hold t.mu.
func (t *RootTracker) reloadConfigsLocked() {
	if t.li == nil {
		return
	}
	qualifiedPrefix := store.QualifyPath(t.localPeerID, trackingConfigPrefix)
	entries := t.li.List(qualifiedPrefix)
	for _, e := range entries {
		ent, ok := t.cs.Get(e.Hash)
		if !ok {
			continue
		}
		if ent.Type != types.TypeTreeTrackingConfig {
			continue
		}
		var cfg types.TrackingConfigData
		if err := ecf.Decode(ent.Data, &cfg); err != nil {
			continue
		}
		if cfg.Prefix == "" {
			continue
		}
		t.tracked[cfg.Prefix] = cfg.Enabled
	}
}

// rebuild recomputes the trie root for a prefix and writes it to
// system/tree/root/{prefix}. Uses the background mutation context.
func (t *RootTracker) rebuild(prefix string) {
	t.rebuildWithDepth(prefix, 0)
}

// applyEventWithDepth applies a single tree-change event incrementally to
// the tracked root for prefix (EXTENSION-TREE v3.15 §3.4.2). When no
// current root exists yet (first event for a freshly-enabled prefix), or
// when the relative path can't be derived, falls back to a full
// O(N) rebuild — that's the spec-compliant slow path, used only when the
// fast path can't be taken.
//
// OP-1 hot-path. Replaces the prior unconditional O(N) BuildTrieForPrefix
// on every event, which was the 109× cliff workbench-go pinned in Stage 6.
func (t *RootTracker) applyEventWithDepth(prefix string, evt store.TreeChangeEvent, parentDepth uint64) {
	prefixMu := t.lockForPrefix(prefix)
	// TryLock + async-on-contention. The synchronous cascade path can re-enter
	// the same prefix's tracker from the same goroutine: a tracked tree-root
	// write fans out to downstream sync hooks (history.Recorder is the canonical
	// case), one of those hooks issues its own li.Set inside the same cascade,
	// the new write lands under our tracked prefix, and runCascade routes the
	// event back here while the outer rebuildWithDepth still holds prefixMu.
	// Same-goroutine reentry on a sync.Mutex deadlocks; the publisher already
	// uses async-spawn for the same reason (663169c). Other-goroutine contention
	// also routes through this path — the spawn queues behind the holder and
	// runs once it releases, preserving per-prefix serialization. Common (no
	// contention) path stays synchronous.
	if !prefixMu.TryLock() {
		go t.applyEventLocked(prefix, evt, parentDepth, prefixMu)
		return
	}
	defer prefixMu.Unlock()
	t.applyEventBody(prefix, evt, parentDepth)
}

// applyEventLocked is the async path used when the prefix mutex is contended.
// It acquires the mutex (queueing behind the current holder) then runs the
// event body, same shape as the synchronous path.
func (t *RootTracker) applyEventLocked(prefix string, evt store.TreeChangeEvent, parentDepth uint64, prefixMu sync.Locker) {
	prefixMu.Lock()
	defer prefixMu.Unlock()
	t.applyEventBody(prefix, evt, parentDepth)
}

// applyEventBody is the event-application body. Caller must hold prefixMu.
func (t *RootTracker) applyEventBody(prefix string, evt store.TreeChangeEvent, parentDepth uint64) {
	t.mu.RLock()
	li := t.li
	pid := t.localPeerID
	ctx := t.bgCtx
	t.mu.RUnlock()
	if li == nil {
		return
	}

	// Resolve qualified prefix for relative-path computation. Same shape
	// as BuildTrieForPrefix so absolute vs peer-relative configs land in
	// the same coordinate space.
	var qualifiedPrefix string
	if strings.HasPrefix(prefix, "/") {
		qualifiedPrefix = prefix
	} else {
		qualifiedPrefix = store.QualifyPath(pid, prefix)
	}

	rootPath := store.CleanPath(rootStoragePrefix + prefix)
	currentRoot, hasRoot := li.Get(rootPath)

	if !hasRoot {
		// First event for this prefix — no root to update incrementally.
		// Fall through to a full build so the root gets established;
		// subsequent events go through the fast path.
		t.rebuildLocked(prefix, parentDepth, li, ctx)
		return
	}

	if !strings.HasPrefix(evt.Path, qualifiedPrefix) {
		// Defensive: pathUnderPrefix already screened this, but if a
		// caller routes an off-prefix event here we don't want to
		// produce a garbage incremental root. Drop with a debug log.
		t.debugf("applyEvent %s: off-prefix path %q (qualified %q) — skipping",
			prefix, evt.Path, qualifiedPrefix)
		return
	}
	relPath := strings.TrimPrefix(evt.Path, qualifiedPrefix)

	var (
		newRoot hash.Hash
		err     error
	)
	switch evt.ChangeType {
	case store.ChangeDeleted:
		newRoot, err = TrieRemove(t.cs, currentRoot, relPath)
	default:
		// Created / Modified both bind relPath → evt.Hash.
		newRoot, err = TriePut(t.cs, currentRoot, relPath, evt.Hash)
	}
	if err != nil {
		// Incremental update failed — fall back to a full rebuild so
		// the tracked root stays consistent with the live tree.
		t.debugf("applyEvent %s: incremental failed (%v); falling back to full rebuild", prefix, err)
		t.rebuildLocked(prefix, parentDepth, li, ctx)
		return
	}

	// No-op (TrieRemove on absent path, TriePut with same value): skip
	// the write so we don't burn an emit on an idempotent root update.
	if newRoot == currentRoot {
		return
	}

	t.writeRoot(li, ctx, rootPath, newRoot, parentDepth, prefix)
}

// rebuildLocked is rebuildWithDepth's body once the per-prefix lock + the
// (li, ctx) snapshot are held by the caller. Extracted so applyEventWithDepth
// can chain into a full rebuild without double-locking the per-prefix mutex.
func (t *RootTracker) rebuildLocked(prefix string, parentDepth uint64, li store.LocationIndex, ctx *store.MutationContext) {
	root, err := BuildTrieForPrefix(t.cs, li, crypto.PeerID(t.localPeerID), prefix)
	if err != nil {
		t.debugf("rebuild %s: %v", prefix, err)
		return
	}
	rootPath := store.CleanPath(rootStoragePrefix + prefix)
	t.writeRoot(li, ctx, rootPath, root, parentDepth, prefix)
}

// writeRoot persists the new tracked root with the appropriate mutation
// context (cascade-depth incremented from parentDepth).
func (t *RootTracker) writeRoot(li store.LocationIndex, ctx *store.MutationContext, rootPath string, root hash.Hash, parentDepth uint64, prefix string) {
	var setErr error
	if cw, ok := li.(store.ContextualWriter); ok && ctx != nil {
		nestedDepth := parentDepth + 1
		nestedCtx := *ctx
		nestedCtx.CascadeDepth = &nestedDepth
		_, setErr = cw.SetWithContext(rootPath, root, &nestedCtx)
	} else {
		setErr = li.Set(rootPath, root)
	}
	if setErr != nil {
		// Background trie-root maintenance can't fail an in-flight
		// operation — but we must not swallow the error. Log loudly so
		// the operator sees that tracked-root state is now inconsistent
		// with the live tree.
		t.debugf("tracked root %s write failed: %v", prefix, setErr)
		return
	}
	t.debugf("tracked root %s = %s", prefix, root.String())
}

// rebuildWithDepth recomputes the trie root, incrementing cascade depth for
// the nested write so depth enforcement works end-to-end.
//
// Serialized per-prefix via lockForPrefix(prefix). Without serialization,
// concurrent rebuilds for the same prefix race: each does an independent
// list+build+Set, and the slower rebuild's stale trie can land last,
// overwriting a newer rebuild's trie. AutoVersioner then reads that stale
// tracker.Root and emits versions whose tries are behind the live tree.
//
// Used by Load() (startup) and handleConfigChange() (newly-enabled
// prefix). Steady-state event updates take applyEventWithDepth (OP-1).
func (t *RootTracker) rebuildWithDepth(prefix string, parentDepth uint64) {
	prefixMu := t.lockForPrefix(prefix)
	prefixMu.Lock()
	defer prefixMu.Unlock()

	t.mu.RLock()
	li := t.li
	ctx := t.bgCtx
	t.mu.RUnlock()
	if li == nil {
		return
	}
	t.rebuildLocked(prefix, parentDepth, li, ctx)
}

// clear removes the tracked-root binding for a prefix.
func (t *RootTracker) clear(prefix string) {
	t.mu.RLock()
	li := t.li
	t.mu.RUnlock()
	if li == nil {
		return
	}
	rootPath := store.CleanPath(rootStoragePrefix + prefix)
	li.Remove(rootPath)
}

// Root returns the current tracked trie root for a prefix, if enabled and
// built. Consumers (e.g., the snapshot op) use this for O(1) lookup.
func (t *RootTracker) Root(prefix string) (hash.Hash, bool) {
	t.mu.RLock()
	li := t.li
	enabled := t.tracked[prefix]
	t.mu.RUnlock()
	if li == nil || !enabled {
		return hash.Hash{}, false
	}
	rootPath := store.CleanPath(rootStoragePrefix + prefix)
	return li.Get(rootPath)
}

// isSelfPath guards against recursion: we never react to writes of our own
// root output (system/tree/root/*).
func (t *RootTracker) isSelfPath(path string) bool {
	_, bare := store.SplitNamespace(path)
	return strings.HasPrefix(bare, rootStoragePrefix)
}

// isFeedbackLoopHandler reports whether a handler pattern names a sync-hook
// consumer whose writes inside the tracked prefix would otherwise loop the
// trie-root → consumer → trie-root cycle. The set is intentionally narrow:
// only consumers whose outputs DESCRIBE trie state (history transitions /
// head pointers, auto-version heads, published-root manifests + signatures,
// clock state) rather than CONTRIBUTE user content belong here. For the
// published-root.root_hash to be stable across publishes, none of these
// metadata writes may move the trie root.
//
// Defined as a function rather than a string match so the publisher's tag
// constant can move without re-coordinating both packages, and so additional
// position-7 consumers can extend the list locally.
//
// Concretely observed feedback chains broken by this filter:
//   - publisher writes published-root → history records it → trie root advances
//     → publisher fires again (cycle 1).
//   - root-tracker writes tracked root → history records it → trie root advances
//     → history records it … (cycle 2, runs even without a publisher).
//   - auto-versioner writes head/version → tracker rebuilds → history records →
//     tracker rebuilds again … (cycle 3, only with auto_version configs but the
//     filter is cheap so we cover it preemptively).
func isFeedbackLoopHandler(pattern string) bool {
	switch pattern {
	case "publishedroot/publisher",
		"system/history":
		return true
	}
	return false
}

func (t *RootTracker) isConfigPath(path string) bool {
	_, bare := store.SplitNamespace(path)
	return strings.HasPrefix(bare, trackingConfigPrefix)
}

// pathUnderPrefix checks whether a tree change event path falls under a
// tracked prefix. Handles both absolute prefixes (/{peerID}/data/) and
// peer-relative prefixes (data/) by comparing in the same space.
func (t *RootTracker) pathUnderPrefix(path, prefix string) bool {
	if strings.HasPrefix(prefix, "/") {
		// Absolute prefix: compare directly against the absolute event path.
		return strings.HasPrefix(path, prefix)
	}
	// Peer-relative prefix: strip namespace from path and compare.
	_, bare := store.SplitNamespace(path)
	return strings.HasPrefix(bare, prefix)
}

func (t *RootTracker) debugf(format string, args ...interface{}) {
	if t.debugLog != nil {
		t.debugLog.Printf("[root-tracker] "+format, args...)
	}
}
