package revision

import (
	"log"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// AutoVersioner is the position-7 emit consumer (SYSTEM-COMPOSITION §2.2,
// EXTENSION-REVISION §6.1) that creates per-write version entries on tree
// writes matching a prefix configured with auto_version: true.
//
// Register via peer.WithNamedSyncHook("revision/auto-version", av.OnTreeChange)
// AFTER the RootTracker hook (so the tracked root is settled before we read
// it) and strictly before any TreeEventSink consumers (position 8, subscription).
type AutoVersioner struct {
	cs       store.ContentStore
	tracker  *tree.RootTracker
	debugLog *log.Logger

	mu          sync.RWMutex
	li          store.LocationIndex
	localPeerID string
	identity    hash.Hash
	grantHash   hash.Hash
	configs     map[string]types.RevisionConfigData
	prefixMu    map[string]*sync.Mutex
}

// NewAutoVersioner creates a versioner. Call SetLocationIndex,
// SetLocalPeerID, and Load after peer construction.
func NewAutoVersioner(cs store.ContentStore, tracker *tree.RootTracker, debugLog *log.Logger) *AutoVersioner {
	return &AutoVersioner{
		cs:       cs,
		tracker:  tracker,
		debugLog: debugLog,
		configs:  make(map[string]types.RevisionConfigData),
		prefixMu: make(map[string]*sync.Mutex),
	}
}

// SetLocationIndex must be called after peer construction with the peer's
// NamespacedIndex (same instance that emits events).
func (a *AutoVersioner) SetLocationIndex(li store.LocationIndex) {
	a.mu.Lock()
	a.li = li
	a.mu.Unlock()
}

// SetLocalPeerID sets the peer ID and identity hash used for MutationContext
// on head writes. Call before Load.
func (a *AutoVersioner) SetLocalPeerID(id string, identityHash hash.Hash) {
	a.mu.Lock()
	a.localPeerID = id
	a.identity = identityHash
	a.mu.Unlock()
}

// Load scans existing system/revision/config/** entries and caches them.
// Call after SetLocationIndex and SetLocalPeerID.
func (a *AutoVersioner) Load() {
	a.reloadConfigs()
	a.mu.Lock()
	if a.li != nil {
		if gh, ok := a.li.Get("system/capability/grants/system/revision"); ok {
			a.grantHash = gh
		}
	}
	a.mu.Unlock()
}

// OnTreeChange is the sync-hook entry point, invoked inline on each write.
// Returns nil on success. May return a halt result if auto-version encounters
// a configuration error (e.g., missing required excludes).
func (a *AutoVersioner) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	_, bare := store.SplitNamespace(evt.Path)

	// Hot-reload config cache on any revision-config write per §2.4.
	// Config lives at system/revision/{prefix_hash}/config (v3.0).
	if isRevisionConfigPath(bare) {
		a.reloadConfigs()
		return nil
	}

	// Reentrancy guard: skip revision metadata and tree-root paths (§6.1).
	if isSelfManagedPath(bare) {
		return nil
	}

	// Version-transcription guard: skip auto-version intermediates for writes
	// carried under a "merge" or "checkout" mutation context. Those operations
	// each write their own version entity (`V_merge` / `V_checkout`) that
	// captures the post-operation tree state. Auto-version intermediates fired
	// during their binding-application loops would be:
	//
	//   1. Redundant — the operation's own version entity already records the
	//      final state. Intermediates are partial snapshots no consumer needs.
	//   2. Cross-peer divergent — Go's map iteration order is non-deterministic
	//      (mergedBindings is a map[string]hash.Hash). Different peers applying
	//      the same logical bindings emit different intermediate version chains
	//      from identical inputs, so heads never converge and the merge loop
	//      never reaches the "in_sync" / "ahead" fixed point.
	//
	// See the workbench F10 part-2 diagnosis. The version-transcription invariant in
	// PROPOSAL-PRODUCTION-READINESS-AMENDMENTS A.3 motivates this — a
	// transcription op produces exactly one version capturing the final state.
	if evt.Context != nil {
		switch evt.Context.Operation {
		case "merge", "checkout":
			return nil
		}
	}

	a.mu.RLock()
	matches := make([]types.RevisionConfigData, 0, 1)
	for _, cfg := range a.configs {
		if cfg.AutoVersion == nil || !*cfg.AutoVersion {
			continue
		}
		prefix := cfg.Prefix
		// Match using full absolute event path when prefix is absolute,
		// otherwise use bare (peer-relative) path.
		var matchPath string
		if strings.HasPrefix(prefix, "/") {
			matchPath = evt.Path
		} else {
			matchPath = bare
		}
		if !strings.HasPrefix(matchPath, prefix) {
			continue
		}
		rel := strings.TrimPrefix(matchPath, prefix)
		if matchesAnyPattern(rel, cfg.Exclude) {
			continue
		}
		matches = append(matches, cfg)
	}
	a.mu.RUnlock()

	var parentDepth uint64
	if evt.Context != nil && evt.Context.CascadeDepth != nil {
		parentDepth = *evt.Context.CascadeDepth
	}
	for _, cfg := range matches {
		a.fire(cfg, parentDepth)
	}
	return nil
}

// fire creates a version entry for the given config's prefix and advances head.
// Serialized per-prefix per §6.1 "Single-writer serialization" tactic.
// parentDepth is the cascade depth of the triggering event; nested writes use
// parentDepth+1 so cascade depth enforcement works end-to-end.
func (a *AutoVersioner) fire(cfg types.RevisionConfigData, parentDepth uint64) {
	prefix := cfg.Prefix
	ph := PrefixHash(prefix)
	muPrefix := a.lockFor(prefix)
	muPrefix.Lock()
	defer muPrefix.Unlock()

	a.mu.RLock()
	li := a.li
	nestedDepth := parentDepth + 1
	ctx := &store.MutationContext{
		AuthorHash:     a.identity,
		CapabilityHash: a.grantHash,
		HandlerPattern: "system/revision",
		Operation:      "auto-version",
		CascadeDepth:   &nestedDepth,
	}
	a.mu.RUnlock()
	if li == nil {
		return
	}

	headP := headPath(ph)

	// CAS-retry loop for the head write.
	//
	// muPrefix serializes auto-version emits FOR THIS PREFIX against each
	// other, but it does NOT serialize against merge/checkout/fast-forward
	// writes to the same head path (those handlers hold their own h.mu —
	// a different lock). Under concurrent burst, the AutoVersioner's head
	// write can race with merge's head advance: both writers Get(headP)
	// independently, build a version chained from their respective view of
	// the head, and Set(headP) without coordination. Whichever Set lands
	// last wins; the loser's emitted version is orphaned in the content
	// store (live tree still has its bindings, but no head pointer
	// references the orphaned version).
	//
	// The observable failure was the "symmetric last-burst-write loss"
	// pattern — each peer's last burst write captured in an orphaned
	// version, missing from the converged head's trie. Diagnosed by
	// the workbench in the F10 part-3 results.
	//
	// Fix: read currentHead, build candidate, then CompareAndSwap. On CAS
	// failure (head moved underneath us — typically because merge advanced
	// it), retry: re-read head, rebuild candidate chaining from the new
	// head, re-emit. Bounded retries (maxFireRetries = 8) bound any
	// pathological livelock; under realistic contention 1-2 attempts
	// suffice and the system is self-healing on subsequent events anyway.
	//
	// First-emit case (no prior head): plain Set. CAS cannot create from
	// "no value" — `MemoryLocationIndex.CompareAndSwap` returns CasError{
	// NotFound: true} if the path isn't bound. The first head emit happens
	// before any merge can run on this prefix (merge requires a remote
	// version, which requires prior pull, which requires prior head), so
	// there's no concurrent writer to race against.
	const maxFireRetries = 8
	for attempt := 0; attempt < maxFireRetries; attempt++ {
		// Re-read tracker.Root INSIDE the retry loop. The live tree may have
		// advanced (concurrent merge applied bindings, concurrent Put) since
		// the previous attempt; building a candidate version with a stale
		// root would emit a version whose trie is BEHIND the live tree. That
		// stale-root version, when later compared as a 3-way merge "remote"
		// against an ancestor that captured the newer state, gets flagged as
		// "remote deleted these paths" by trieMergeBindings (the inference is
		// correct for systems with explicit deletes; wrong for a write-only
		// workload where absence means "not received yet"). Result: cascading
		// data loss via merge.go deletions.
		// See the workbench F10 part-5 residual analysis.
		liveRoot, ok := a.tracker.Root(prefix)
		if !ok {
			a.debugf("fire %s: no tracked root (tracking-config missing or disabled)", prefix)
			return
		}

		currentHead, hasHead := li.Get(headP)

		// Build the version's trie root. For the first emit (no parent), the
		// version's root IS the live root — there's no parent trie to diff
		// against, no deletions to mark. For subsequent emits, the version's
		// root is the live root AUGMENTED with deletion markers at paths
		// present in parent's trie but absent in live state.
		//
		// Per PROPOSAL-DELETION-MARKERS.md (A.8) Amendment 2:
		//   - The new version's trie MUST include explicit entries for every
		//     path bound in parent's trie. For paths bound in parent but
		//     unbound in live, the entry binds the canonical deletion marker.
		//   - Carry-forward is automatic via canonical hashing — paths already
		//     bound to the marker in parent are still bound to the same hash
		//     in the new trie (Merkle sharing).
		//   - Re-add (parent has marker, live has entity) is classified as a
		//     `changed` path by TrieDiff and resolves correctly: the new trie
		//     binds the live entity, superseding the marker.
		//
		// First-emit: liveRoot is the new root directly. No parent to diff;
		// `removed` set is empty by definition.
		versionRoot := liveRoot
		if hasHead {
			parentVer, parentOK := loadVersionFromStore(a.cs, currentHead)
			if parentOK {
				augmented, err := emitDeletionMarkers(a.cs, parentVer.Root, liveRoot, li, prefix)
				if err != nil {
					a.debugf("fire %s: emit markers: %v (falling back to liveRoot)", prefix, err)
				} else {
					versionRoot = augmented
				}
			}
		}

		// Dedup per §6.1: if current head already has the same trie root, no-op.
		// Re-check each iteration — a concurrent writer may have advanced
		// head to a version whose root matches ours, making our emit
		// redundant. Compare against versionRoot (marker-augmented), not
		// liveRoot — a peer that's already at the marker-augmented state
		// shouldn't re-emit.
		if hasHead {
			if ent, exists := a.cs.Get(currentHead); exists {
				if curVer, err := types.RevisionEntryDataFromEntity(ent); err == nil {
					if curVer.Root == versionRoot {
						return
					}
				}
			}
		}

		var parents []hash.Hash
		if hasHead {
			parents = []hash.Hash{currentHead}
		}
		ver := types.RevisionEntryData{
			Root:    versionRoot,
			Parents: tree.SortedParents(parents),
		}
		verEnt, err := ver.ToEntity()
		if err != nil {
			a.debugf("fire %s: build entity: %v", prefix, err)
			return
		}
		verHash, err := a.cs.Put(verEnt)
		if err != nil {
			a.debugf("fire %s: store put: %v", prefix, err)
			return
		}

		// Commit head. First-emit path uses plain Set (no prior value to
		// CAS against). Established-head path uses CompareAndSwap so a
		// concurrent merge can't silently overwrite our emit.
		if !hasHead {
			if err := writeWithContext(li, headP, verHash, ctx); err != nil {
				a.debugf("fire %s: head bind failed: %v", prefix, err)
				return
			}
		} else {
			if err := li.CompareAndSwap(headP, currentHead, verHash); err != nil {
				// CAS failed — head advanced between Get and CompareAndSwap.
				// Loop will re-read and rebuild against the new head.
				a.debugf("fire %s: CAS retry %d/%d (head advanced concurrently: %v)",
					prefix, attempt+1, maxFireRetries, err)
				continue
			}
		}

		// Branch advance: only after head commit succeeds. Same race exists
		// in principle between branch writes, but a merge that advances the
		// branch only does so after its head write — so if we won the head
		// CAS, the branch write should land cleanly. Worst case downstream
		// is a stale branch pointer that the next fire() will catch up.
		if branchNameHash, ok := li.Get(activeBranchPath(ph)); ok {
			if bent, ok := a.cs.Get(branchNameHash); ok {
				var branchName string
				if err := ecf.Decode(bent.Data, &branchName); err == nil && branchName != "" {
					if err := writeWithContext(li, branchPath(ph, branchName), verHash, ctx); err != nil {
						a.debugf("fire %s: branch bind failed: %v", prefix, err)
					}
				}
			}
		}

		if attempt > 0 {
			a.debugf("fire %s: head -> %s (root %s) [succeeded after %d retries]",
				prefix, verHash.String(), versionRoot.String(), attempt)
		} else {
			a.debugf("fire %s: head -> %s (root %s)", prefix, verHash.String(), versionRoot.String())
		}
		return
	}

	// Retry budget exhausted. The candidate version is in the content store
	// (cs.Put is idempotent) but unreferenced. The next sync-hook event for
	// this prefix will fire() again and have another shot at capturing the
	// live tree state. Loud log so operational observers can tell this is
	// happening if it ever does in practice.
	a.debugf("fire %s: exhausted %d CAS retries — emit abandoned; next event will retry",
		prefix, maxFireRetries)
}

func (a *AutoVersioner) lockFor(prefix string) *sync.Mutex {
	a.mu.Lock()
	defer a.mu.Unlock()
	mu, ok := a.prefixMu[prefix]
	if !ok {
		mu = &sync.Mutex{}
		a.prefixMu[prefix] = mu
	}
	return mu
}

// LockPrefix acquires the per-prefix mutex that AV.fire() uses for emit
// serialization, returning an unlock callback. Used by version-transcription
// operations (merge, fast-forward, checkout, cherry-pick, revert) to
// serialize their binding-apply phases with AV's emit phase on the same
// prefix.
//
// Without this coordination, a concurrent Put during a mid-apply merge can
// trigger AV.fire() to read `tracker.Root` reflecting partial-merge state.
// `emitDeletionMarkers` then computes paths "missing from live" against
// the parent's full state and emits phantom markers for paths the merge
// is about to apply. Under `deletion-wins` resolution, the phantom markers
// propagate cross-peer as intentional deletes — silent data loss for paths
// the user never deleted. See the workbench's deletion-markers
// phase-2 validation §4.
//
// Same conceptual race class as F10 parts 4/5 — different writers (merge,
// AV) on shared state (live tree contents reflected by tracker.Root)
// without holding a common mutex. The CAS coordination of parts 4/5
// protected the head pointer; this protects the live tree state that AV
// reads when emitting.
func (a *AutoVersioner) LockPrefix(prefix string) func() {
	mu := a.lockFor(prefix)
	mu.Lock()
	return mu.Unlock
}

// reloadConfigs rescans system/revision/config/** and rebuilds the cache.
// Coordinates tracking-config writes per §6.1: on auto_version: true we
// ensure a matching tracking-config exists (enabled); on transition to
// false we disable it. Rejects (skips with loud log) universal-tree configs
// missing required excludes per §6D.4.
func (a *AutoVersioner) reloadConfigs() {
	a.mu.RLock()
	li := a.li
	pid := a.localPeerID
	prev := a.configs
	a.mu.RUnlock()
	if li == nil {
		return
	}

	// Scan system/revision/{hash}/config entries (v3.0 layout).
	qualifiedPrefix := store.QualifyPath(pid, "system/revision/")
	allEntries := li.List(qualifiedPrefix)
	configs := make(map[string]types.RevisionConfigData, 8)
	for _, e := range allEntries {
		_, bare := store.SplitNamespace(e.Path)
		if !isRevisionConfigPath(bare) {
			continue
		}
		ent, ok := a.cs.Get(e.Hash)
		if !ok || ent.Type != types.TypeRevisionConfig {
			continue
		}
		cfg, err := types.RevisionConfigDataFromEntity(ent)
		if err != nil || cfg.Prefix == "" {
			continue
		}
		if cfg.AutoVersion != nil && *cfg.AutoVersion {
			if missing := missingRequiredExcludes(cfg); len(missing) > 0 {
				a.debugf("REJECT config %s: auto_version: true missing required excludes %v",
					cfg.Prefix, missing)
				continue
			}
		}
		configs[cfg.Prefix] = cfg
	}

	a.mu.Lock()
	a.configs = configs
	a.mu.Unlock()

	// Coordinate tracking-config writes for transitions (§6.1).
	a.coordinateTrackingConfigs(prev, configs)

	a.debugf("reloaded %d revision configs", len(configs))
}

// coordinateTrackingConfigs ensures tracking-configs track the auto_version
// state per §6.1. Enabled for prefixes gaining auto_version: true; disabled
// for prefixes losing it.
func (a *AutoVersioner) coordinateTrackingConfigs(prev, curr map[string]types.RevisionConfigData) {
	a.mu.RLock()
	li := a.li
	ctx := &store.MutationContext{
		AuthorHash:     a.identity,
		CapabilityHash: a.grantHash,
		HandlerPattern: "system/revision",
		Operation:      "auto-version-coordinate",
	}
	a.mu.RUnlock()
	if li == nil {
		return
	}

	prevEnabled := func(p string) bool {
		c, ok := prev[p]
		return ok && c.AutoVersion != nil && *c.AutoVersion
	}
	currEnabled := func(p string) bool {
		c, ok := curr[p]
		return ok && c.AutoVersion != nil && *c.AutoVersion
	}

	for prefix := range curr {
		if currEnabled(prefix) && !prevEnabled(prefix) {
			a.ensureTrackingConfig(li, ctx, prefix, true)
		}
	}
	for prefix := range prev {
		if prevEnabled(prefix) && !currEnabled(prefix) {
			a.ensureTrackingConfig(li, ctx, prefix, false)
		}
	}
}

// ensureTrackingConfig writes a tracking-config entity for the prefix at
// system/tree/tracking-config/{key} with the given enabled state. key is the
// prefix with trailing slash stripped and slashes replaced by `-` for flat
// storage. Idempotent: writes the same hash on repeat calls.
func (a *AutoVersioner) ensureTrackingConfig(li store.LocationIndex, ctx *store.MutationContext, prefix string, enabled bool) {
	cfg := types.TrackingConfigData{Prefix: prefix, Enabled: enabled}
	ent, err := cfg.ToEntity()
	if err != nil {
		a.debugf("coordinate %s: build tracking-config: %v", prefix, err)
		return
	}
	h, err := a.cs.Put(ent)
	if err != nil {
		a.debugf("coordinate %s: store tracking-config: %v", prefix, err)
		return
	}
	key := trackingConfigKey(prefix)
	if err := writeWithContext(li, "system/tree/tracking-config/"+key, h, ctx); err != nil {
		a.debugf("coordinate %s: tracking-config bind failed: %v", prefix, err)
		return
	}
	a.debugf("coordinate %s: tracking-config enabled=%v", prefix, enabled)
}

// trackingConfigKey computes the tracking-config binding key from an absolute prefix.
func trackingConfigKey(prefix string) string {
	return PrefixHash(prefix)
}

// missingRequiredExcludes checks a universal-or-system-encompassing prefix
// against the §6.1 required-exclude list. Returns patterns that are NOT
// covered. Non-system-encompassing prefixes (the common case) pass trivially.
func missingRequiredExcludes(cfg types.RevisionConfigData) []string {
	p := strings.TrimSuffix(strings.TrimPrefix(cfg.Prefix, "/"), "/")

	// The prefix encompasses required system paths iff it is a strict prefix
	// of ANY protected path ("" == universal covers all).
	protected := []string{
		"system/revision/",
		"system/tree/root/",
		"system/tree/tracking-config/",
		"system/history/",
		"system/clock/",
	}
	encompassesProtected := false
	for _, prot := range protected {
		if p == "" || strings.HasPrefix(prot, p+"/") || prot == p+"/" {
			encompassesProtected = true
			break
		}
	}
	if !encompassesProtected {
		return nil
	}

	required := []string{
		"system/revision/**",
		"system/tree/root/**",
		"system/tree/tracking-config/**",
		"system/history/**",
		"system/clock/**",
	}
	coveredBy := func(pattern string) bool {
		// Treat "system/**" as the shorthand that covers everything.
		for _, e := range cfg.Exclude {
			if e == "system/**" || e == pattern {
				return true
			}
		}
		return false
	}
	var missing []string
	for _, r := range required {
		if !coveredBy(r) {
			missing = append(missing, r)
		}
	}
	return missing
}

func (a *AutoVersioner) debugf(format string, args ...interface{}) {
	if a.debugLog != nil {
		a.debugLog.Printf("[auto-version] "+format, args...)
	}
}

// isSelfManagedPath returns true for paths that auto-version MUST NOT react
// to. Revision metadata paths, tree-root outputs, and tracking-config all
// qualify (§6.1 Reentrancy).
func isSelfManagedPath(bare string) bool {
	switch {
	case strings.HasPrefix(bare, "system/revision/"):
		return true
	case strings.HasPrefix(bare, "system/tree/root/"):
		return true
	case strings.HasPrefix(bare, "system/tree/tracking-config/"):
		return true
	}
	return false
}

// writeWithContext writes via ContextualWriter when available so downstream
// consumers (subscription, history) see the authoring MutationContext.
// Returns the underlying storage error so callers can surface partial-apply
// state per V7 §2688.
func writeWithContext(li store.LocationIndex, p string, h hash.Hash, ctx *store.MutationContext) error {
	if cw, ok := li.(store.ContextualWriter); ok {
		_, err := cw.SetWithContext(p, h, ctx)
		return err
	}
	return li.Set(p, h)
}

// Uses matchesAnyPattern from snapshot.go for glob matching.
