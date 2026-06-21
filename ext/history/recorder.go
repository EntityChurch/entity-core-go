package history

import (
	"log"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// headPrefix is the tree path prefix for history head pointers.
const headPrefix = "system/history/head/"

// Recorder records history transitions in response to tree mutations.
// Register as a sync hook via peer.WithNamedSyncHook("history/recorder", recorder.OnTreeChange).
// After peer construction, call Load() to initialize the config cache.
type Recorder struct {
	cs               store.ContentStore
	li               store.LocationIndex // set after peer construction
	cache            *configCache
	localPeerID      string
	peerIdentityHash hash.Hash
	debugLog         *log.Logger
	bgCtx            *store.MutationContext // background context for head pointer writes
}

// NewRecorder creates a history recorder. The LocationIndex must be set
// after peer construction via SetLocationIndex before the recorder processes
// any events.
func NewRecorder(cs store.ContentStore, localPeerID string, debugLog *log.Logger) *Recorder {
	return &Recorder{
		cs:          cs,
		cache:       newConfigCache(localPeerID),
		localPeerID: localPeerID,
		debugLog:    debugLog,
	}
}

// SetLocalPeerID sets the local peer ID and identity hash. Must be called
// before Load() and before any events are processed. This allows creating
// the recorder before the peer ID is known (e.g., before peer construction).
func (r *Recorder) SetLocalPeerID(id string, identityHash hash.Hash) {
	r.localPeerID = id
	r.cache.localPeerID = id
	r.peerIdentityHash = identityHash
}

// SetLocationIndex sets the location index used for head pointer reads/writes.
// Must be called after peer construction (to get the NamespacedIndex that fires events).
func (r *Recorder) SetLocationIndex(li store.LocationIndex) {
	r.li = li
}

// Load initializes the config cache from the current tree state.
// Call after peer construction and SetLocationIndex.
func (r *Recorder) Load() {
	r.cache.load(r.li, r.cs)
	r.debugf("loaded %d history configs", len(r.cache.entries))

	// Build background context for head pointer writes.
	var capHash hash.Hash
	if gh, ok := r.li.Get("system/capability/grants/system/history"); ok {
		capHash = gh
	}
	r.bgCtx = &store.MutationContext{
		AuthorHash:     r.peerIdentityHash,
		CapabilityHash: capHash,
		HandlerPattern: "system/history",
		Operation:      "record",
	}
}

// OnTreeChange processes a tree mutation event, recording a history transition
// if the path is configured for history. Also reloads config cache when
// config entities change. Returns nil (success) — history recording never
// intentionally halts the cascade.
func (r *Recorder) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	// Config hot-reload: if a config path changed, reload the cache.
	if r.cache.isConfigPath(evt.Path) {
		r.cache.load(r.li, r.cs)
		r.debugf("reloaded history configs (%d entries)", len(r.cache.entries))
		return nil
	}

	// Recursion prevention: never record history for local system/history/ paths.
	if r.isLocalHistoryPath(evt.Path) {
		return nil
	}

	// Look up config for this path.
	cfg := r.cache.find(evt.Path)
	if cfg == nil {
		return nil
	}

	// Determine event type.
	eventType := changeTypeToEvent(evt.ChangeType)
	if eventType == "" {
		return nil
	}

	// Check if this event type is configured.
	events := cfg.Events
	if len(events) == 0 {
		events = []string{"created", "updated", "deleted"}
	}
	if !containsString(events, eventType) {
		return nil
	}

	r.recordTransition(evt, eventType, cfg)
	return nil
}

// recordTransition builds and stores a transition entity, then updates the head pointer.
func (r *Recorder) recordTransition(evt store.TreeChangeEvent, eventType string, cfg *types.HistoryConfigData) {
	if r.li == nil {
		return
	}

	// Read current head pointer for this path.
	headPath := headPointerPath(evt.Path)
	previousTransitionHash, _ := r.li.Get(headPath)

	// Build transition data.
	td := types.TransitionData{
		Path:      evt.Path,
		Event:     eventType,
		Timestamp: uint64(time.Now().UnixMilli()),
	}

	if !evt.Hash.IsZero() {
		td.Hash = evt.Hash
	}
	if !evt.PreviousHash.IsZero() {
		td.PreviousHash = evt.PreviousHash
	}
	if !previousTransitionHash.IsZero() {
		td.Previous = previousTransitionHash
	}

	// Fill execution context from MutationContext if available.
	if evt.Context != nil {
		td.Author = evt.Context.AuthorHash
		td.Capability = evt.Context.CapabilityHash
		if !evt.Context.CallerCapabilityHash.IsZero() {
			td.CallerCapability = evt.Context.CallerCapabilityHash
		}
		td.Handler = evt.Context.HandlerPattern
		td.Operation = evt.Context.Operation
		td.ChainID = evt.Context.ChainID
		td.ParentChainID = evt.Context.ParentChainID
	}

	// Read structured clock state from the execution context (F6/F7, HISTORY v1.5).
	// The clock sync hook at position 2 populates Context.Clock before history
	// fires at position 4. Falls back to building a minimal ClockStateData from
	// the logical counter in the tree when the context lacks the structured value.
	if evt.Context != nil && len(evt.Context.Clock) > 0 {
		td.Clock = evt.Context.Clock
	} else if counter := r.readLogicalClock(); counter != nil {
		fallback := types.ClockStateData{
			Mode:    "logical",
			Logical: &types.ClockLogicalData{Counter: *counter},
		}
		if raw, err := ecf.Encode(fallback); err == nil {
			td.Clock = raw
		}
	}

	// Store the transition entity.
	transitionEntity, err := td.ToEntity()
	if err != nil {
		r.debugf("history: failed to create transition entity: %v", err)
		return
	}
	transitionHash, err := r.cs.Put(transitionEntity)
	if err != nil {
		r.debugf("history: failed to store transition entity: %v", err)
		return
	}

	// Update head pointer — with execution context (the recorder is the peer
	// acting under the history handler's grant). Increment cascade depth for
	// the nested write.
	var setErr error
	if cw, ok := r.li.(store.ContextualWriter); ok && r.bgCtx != nil {
		nestedCtx := *r.bgCtx
		var parentDepth uint64
		if evt.Context != nil && evt.Context.CascadeDepth != nil {
			parentDepth = *evt.Context.CascadeDepth
		}
		nestedDepth := parentDepth + 1
		nestedCtx.CascadeDepth = &nestedDepth
		_, setErr = cw.SetWithContext(headPath, transitionHash, &nestedCtx)
	} else {
		setErr = r.li.Set(headPath, transitionHash)
	}
	if setErr != nil {
		// Background recorder — log and bail; history-head pointer is now
		// stale relative to the live tree. Operator must see this.
		r.debugf("history: head bind failed for %s: %v", headPath, setErr)
		return
	}

	r.debugf("history: recorded %s for %s (hash=%s)", eventType, evt.Path, transitionHash)

	// Prune if max_depth is configured.
	if cfg.MaxDepth != nil {
		r.prune(evt.Path, *cfg.MaxDepth)
	}
}

// prune truncates the history chain to max_depth transitions.
// Older transitions become unreachable from the head and are eligible for GC.
func (r *Recorder) prune(path string, maxDepth uint64) {
	headPath := headPointerPath(path)
	headHash, ok := r.li.Get(headPath)
	if !ok {
		return
	}

	current := headHash
	count := uint64(1)
	for count < maxDepth {
		ent, ok := r.cs.Get(current)
		if !ok {
			return
		}
		td, err := types.TransitionDataFromEntity(ent)
		if err != nil {
			return
		}
		if td.Previous.IsZero() {
			return // chain shorter than max_depth
		}
		current = td.Previous
		count++
	}
	// current is now the last transition to keep.
	// Its previous field still points to the old chain in the content store
	// (immutable), but it's no longer reachable from the head. GC handles cleanup.
}

// readLogicalClock reads the current logical clock counter from the tree.
// Returns nil if the clock extension is not present or the value cannot be read.
func (r *Recorder) readLogicalClock() *uint64 {
	h, ok := r.li.Get("system/clock/logical")
	if !ok {
		return nil
	}
	ent, ok := r.cs.Get(h)
	if !ok {
		return nil
	}
	d, err := types.ClockLogicalDataFromEntity(ent)
	if err != nil {
		return nil
	}
	return &d.Counter
}

// isLocalHistoryPath checks if a path is a history engine output path (head pointers).
// Per SYSTEM-COMPOSITION §6.1: guard only engine output paths (system/history/head*),
// not configuration paths (system/history/config/*) which SHOULD be tracked.
func (r *Recorder) isLocalHistoryPath(path string) bool {
	prefix := "/" + r.localPeerID + "/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	suffix := path[len(prefix):]
	return strings.HasPrefix(suffix, "system/history/head")
}

// headPointerPath builds the head pointer path for a tracked path.
// The tracked path is absolute (e.g., "/{peerA}/docs/report"), so we
// strip the leading "/" to avoid double-slash in the head pointer path.
func headPointerPath(trackedPath string) string {
	return headPrefix + strings.TrimPrefix(trackedPath, "/")
}

// changeTypeToEvent maps a ChangeType to a history event string.
func changeTypeToEvent(ct store.ChangeType) string {
	switch ct {
	case store.ChangeCreated:
		return "created"
	case store.ChangeModified:
		return "updated"
	case store.ChangeDeleted:
		return "deleted"
	default:
		return ""
	}
}

// containsString checks if a slice contains a string.
func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// HeadPointerPath is exported for use by the handler to look up heads.
func HeadPointerPath(trackedPath string) string {
	return headPointerPath(trackedPath)
}

func (r *Recorder) debugf(format string, args ...any) {
	if r.debugLog != nil {
		r.debugLog.Printf(format, args...)
	}
}

// IsInHistory walks the transition chain for a path and checks if
// targetHash appears as a hash or previous_hash in any transition.
func IsInHistory(cs store.ContentStore, li store.LocationIndex, path string, targetHash hash.Hash) bool {
	headPath := headPointerPath(path)
	headHash, ok := li.Get(headPath)
	if !ok {
		return false
	}
	current := headHash
	for !current.IsZero() {
		ent, ok := cs.Get(current)
		if !ok {
			return false
		}
		td, err := types.TransitionDataFromEntity(ent)
		if err != nil {
			return false
		}
		if td.Hash == targetHash || td.PreviousHash == targetHash {
			return true
		}
		current = td.Previous
	}
	return false
}
