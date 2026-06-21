package store

import (
	"errors"
	"log"
	"sync/atomic"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// ErrEventBufferFull is returned by Set/SetWithContext when the tree-event
// channel is full and the binding cannot be emitted without dropping it.
//
// Design principle (errors-at-saturation-boundaries, see the
// event-delivery-backpressure review and
// V7 §2688): saturation of an internal SDK channel is a transient I/O
// failure of the event-delivery path. Per the same rule the storage
// boundary follows (`tree.put → 500 on transient I/O`), the SDK surfaces
// the saturation to the caller rather than dropping silently OR blocking
// the writer goroutine indefinitely. The caller — handler, watcher,
// continuation, background goroutine — has the operational context to
// decide whether to retry with backoff, abort, log+continue, or
// propagate as a 500 storage_error.
//
// IMPORTANT: when emit returns this error, the storage binding HAS
// committed. The location index reflects the new state. Only the
// downstream event delivery was lost. Per V7 §2870 ("tree.put is atomic
// at the binding level only"), this is permitted state — downstream
// consumers reconcile via state reads, gap-detection on previous_hash
// chains, or operator intervention.
var ErrEventBufferFull = errors.New("tree event buffer full: consumer not keeping up")

// ErrShuttingDown is returned by emit when the peer is shutting down
// (done channel closed). The binding has committed; the event is not
// emitted because the consumer pipeline is being torn down. Callers
// MAY ignore this; it's not an error condition operationally — just a
// signal that the write happened during shutdown.
var ErrShuttingDown = errors.New("peer shutting down: event not emitted")

// NotifyingLocationIndex wraps a LocationIndex and emits TreeChangeEvent on
// mutations (Set and Remove). Read operations pass through unchanged.
//
// Named sync hooks run inline during the write, before the async channel emit.
// Each hook can return a *ConsumerResult to halt the cascade (non-200 status)
// or nil for success. Use AddNamedSyncHook for infrastructure that must be
// consistent with writes (e.g., query indexes, auto-version).
//
// The async channel is best-effort — events may be dropped if the channel is
// full.
//
// The done channel prevents panics from sending to a closed events channel
// during shutdown.
type NotifyingLocationIndex struct {
	inner           LocationIndex
	events          chan<- TreeChangeEvent
	done            <-chan struct{}
	namedHooks      []NamedSyncHook
	maxCascadeDepth uint64
	debugLog        *log.Logger
	droppedEvents   atomic.Uint64

	// suppressEmit, when set, makes emit a no-op (no send to events channel,
	// no saturation counter increment). Used during peer construction's
	// seed phase to avoid event-channel fill before any consumer is wired.
	// Toggled via SetEmitSuppressed.
	suppressEmit atomic.Bool
}

// NewNotifyingLocationIndex wraps inner and sends mutation events to events.
// The caller owns both channels. Close done before closing events to prevent
// send-to-closed-channel panics.
func NewNotifyingLocationIndex(inner LocationIndex, events chan<- TreeChangeEvent, done <-chan struct{}) *NotifyingLocationIndex {
	return &NotifyingLocationIndex{
		inner:           inner,
		events:          events,
		done:            done,
		maxCascadeDepth: DefaultMaxCascadeDepth,
	}
}

// SetDebugLog enables debug logging for dropped events and other diagnostics.
func (n *NotifyingLocationIndex) SetDebugLog(l *log.Logger) {
	n.debugLog = l
}

// DroppedEvents returns 0 unconditionally — emit no longer drops events on
// a full channel; it applies backpressure to writers instead. Retained for
// API compatibility with callers that polled this for diagnostics; the
// counter is no longer meaningful and the method will be removed in a future
// version.
//
// Deprecated: emit is backpressure, not drop. Watch channel-fill-ratio
// metrics on the events sink instead.
func (n *NotifyingLocationIndex) DroppedEvents() uint64 {
	return n.droppedEvents.Load()
}

// AddNamedSyncHook registers a named synchronous callback that runs inline
// during each write (Set/Remove), before the async channel emit. Hooks are
// called in registration order. A non-200 return halts the cascade — remaining
// hooks are skipped.
//
// Hooks must be registered before the peer starts serving — not safe to call
// concurrently with Set/Remove.
func (n *NotifyingLocationIndex) AddNamedSyncHook(name string, fn func(TreeChangeEvent) *ConsumerResult) {
	n.namedHooks = append(n.namedHooks, NamedSyncHook{Name: name, Fn: fn})
}

// AddNamedSyncHookWithPattern is the pattern-filtered variant: the hook only
// fires when the event path matches pattern (NamedSyncHook.Pattern grammar —
// `*` for all, `prefix/*` for prefix match, or exact path). Non-matching
// events skip the hook entirely — it does not appear in CascadeResult.
//
// Same lifecycle constraints as AddNamedSyncHook.
func (n *NotifyingLocationIndex) AddNamedSyncHookWithPattern(name, pattern string, fn func(TreeChangeEvent) *ConsumerResult) {
	n.namedHooks = append(n.namedHooks, NamedSyncHook{Name: name, Pattern: pattern, Fn: fn})
}

// SetMaxCascadeDepth configures the system refusal threshold. Writes whose
// MutationContext.CascadeDepth >= this value are refused (binding does NOT
// commit). Default is DefaultMaxCascadeDepth (32).
func (n *NotifyingLocationIndex) SetMaxCascadeDepth(depth uint64) {
	n.maxCascadeDepth = depth
}

// SetEmitSuppressed toggles event emission. When suppressed, emit is a no-op:
// no event is pushed to the events channel, no saturation counter is
// incremented. Sync hooks still run (they're not part of emit).
//
// The peer constructor uses this during the seed phase: hundreds of type/
// handler/grant entities are bound before any consumer of the events channel
// is wired, so emitting them would either fill the channel (no consumer) or
// return ErrEventBufferFull (saturating during construction). Both are
// wrong — seed writes are not application events. Suppression is cleaner
// than running an internal drainer goroutine because there's no race
// between the drainer and the constructor.
//
// Toggling this during normal operation is also legal (e.g., to perform a
// bulk-rebuild without firing events), but callers must understand the
// downstream consequences: history won't record, subscriptions won't fire,
// query indexes won't update.
func (n *NotifyingLocationIndex) SetEmitSuppressed(suppressed bool) {
	n.suppressEmit.Store(suppressed)
}

func (n *NotifyingLocationIndex) Set(path string, h hash.Hash) error {
	_, err := n.setInternal(path, h, nil)
	return err
}

// SetWithContext stores a hash at the given path, runs the sync-phase cascade,
// and returns the cascade result. The binding commits before any consumer runs
// (per PROPOSAL-CASCADE-SEMANTICS §3.1). If CascadeDepth exceeds the system
// refusal threshold, the binding does NOT commit and all consumers are skipped.
// Returns a non-nil error if the underlying storage Set fails; on storage
// error the cascade is not run and no event is emitted.
func (n *NotifyingLocationIndex) SetWithContext(path string, h hash.Hash, ctx *MutationContext) (*CascadeResult, error) {
	return n.setInternal(path, h, ctx)
}

func (n *NotifyingLocationIndex) setInternal(path string, h hash.Hash, ctx *MutationContext) (*CascadeResult, error) {
	// Check cascade depth BEFORE committing the binding.
	if ctx != nil && ctx.CascadeDepth != nil && *ctx.CascadeDepth >= n.maxCascadeDepth {
		names := make([]string, len(n.namedHooks))
		for i, hook := range n.namedHooks {
			names[i] = hook.Name
		}
		return &CascadeResult{
			BindingCommitted: false,
			Skipped:          names,
			CascadeDepth:     *ctx.CascadeDepth,
		}, nil
	}

	prev, existed := n.inner.Get(path)

	// No-op suppression: if the binding already points to this hash, skip
	// the cascade and emit entirely (SYSTEM-COMPOSITION §1.1).
	if existed && prev == h {
		return nil, nil
	}

	if err := n.inner.Set(path, h); err != nil {
		return nil, err
	}

	var evt TreeChangeEvent
	if existed {
		evt = TreeChangeEvent{
			Path:         path,
			Hash:         h,
			PreviousHash: prev,
			ChangeType:   ChangeModified,
			Context:      ctx,
		}
	} else {
		evt = TreeChangeEvent{
			Path:       path,
			Hash:       h,
			ChangeType: ChangeCreated,
			Context:    ctx,
		}
	}

	cr := n.runCascade(evt, ctx)
	// Emit AFTER sync hooks run (the cascade contract: hooks see the event
	// before async consumers do). If emit returns ErrEventBufferFull, the
	// binding has committed and sync hooks have run; only the async event
	// delivery failed. Surface to caller — they decide whether this is
	// fatal (500 storage_error) or recoverable (log + continue).
	//
	// ErrShuttingDown is normal-during-teardown; surfacing it lets the
	// caller distinguish "lost event" from "shutting down" if they care.
	if err := n.emit(evt); err != nil {
		return cr, err
	}
	return cr, nil
}

func (n *NotifyingLocationIndex) Get(path string) (hash.Hash, bool) {
	return n.inner.Get(path)
}

func (n *NotifyingLocationIndex) Has(path string) bool {
	return n.inner.Has(path)
}

func (n *NotifyingLocationIndex) Remove(path string) (hash.Hash, bool) {
	h, ok, _ := n.removeInternal(path, nil)
	return h, ok
}

// RemoveWithContext removes a path, runs the sync-phase cascade, and returns
// the cascade result alongside the removed hash.
func (n *NotifyingLocationIndex) RemoveWithContext(path string, ctx *MutationContext) (hash.Hash, bool, *CascadeResult) {
	return n.removeInternal(path, ctx)
}

func (n *NotifyingLocationIndex) removeInternal(path string, ctx *MutationContext) (hash.Hash, bool, *CascadeResult) {
	h, ok := n.inner.Remove(path)
	if !ok {
		return h, false, nil
	}

	evt := TreeChangeEvent{
		Path:         path,
		PreviousHash: h,
		ChangeType:   ChangeDeleted,
		Context:      ctx,
	}

	cr := n.runCascade(evt, ctx)
	n.emit(evt)
	return h, true, cr
}

// runCascade iterates named sync hooks in order. On the first non-200 return,
// remaining hooks are skipped (halt semantics per §4.2).
func (n *NotifyingLocationIndex) runCascade(evt TreeChangeEvent, ctx *MutationContext) *CascadeResult {
	if len(n.namedHooks) == 0 {
		return nil
	}

	var depth uint64
	if ctx != nil && ctx.CascadeDepth != nil {
		depth = *ctx.CascadeDepth
	}

	cr := &CascadeResult{
		BindingCommitted: true,
		CascadeDepth:     depth,
	}

	halted := false
	for _, hook := range n.namedHooks {
		if halted {
			cr.Skipped = append(cr.Skipped, hook.Name)
			continue
		}
		// Pattern filter: hooks that don't match the event path are skipped
		// silently — they didn't participate, so they don't appear in any
		// CascadeResult bucket. Empty pattern matches everything (preserves
		// legacy AddNamedSyncHook behavior).
		if !pathMatchesPattern(hook.Pattern, evt.Path) {
			continue
		}
		result := hook.Fn(evt)
		if result == nil || result.Status == 0 || result.Status == 200 {
			cr.Completed = append(cr.Completed, hook.Name)
		} else {
			cr.Halted = append(cr.Halted, CascadeHaltEntry{
				Name:  hook.Name,
				Error: *result,
			})
			halted = true
		}
	}

	return cr
}

func (n *NotifyingLocationIndex) List(prefix string) []LocationEntry {
	return n.inner.List(prefix)
}

func (n *NotifyingLocationIndex) LenPrefix(prefix string) int {
	return n.inner.LenPrefix(prefix)
}

// CompareAndSwap forwards to the inner index. On success it emits an Updated
// event and runs the sync-phase cascade so observers stay coherent with
// regular Set traffic. On CAS failure no event is emitted.
func (n *NotifyingLocationIndex) CompareAndSwap(path string, expected, new hash.Hash) error {
	if err := n.inner.CompareAndSwap(path, expected, new); err != nil {
		return err
	}
	evt := TreeChangeEvent{
		Path:         path,
		Hash:         new,
		PreviousHash: expected,
		ChangeType:   ChangeModified,
	}
	n.runCascade(evt, nil)
	n.emit(evt)
	return nil
}

// CompareAndRemove forwards to the inner index. On success it emits a Deleted
// event and runs the sync-phase cascade. On CAS failure no event is emitted.
func (n *NotifyingLocationIndex) CompareAndRemove(path string, expected hash.Hash) error {
	if err := n.inner.CompareAndRemove(path, expected); err != nil {
		return err
	}
	evt := TreeChangeEvent{
		Path:         path,
		PreviousHash: expected,
		ChangeType:   ChangeDeleted,
	}
	n.runCascade(evt, nil)
	n.emit(evt)
	return nil
}

// emit tries to send an event to the async channel. Returns:
//   - nil on successful send.
//   - ErrShuttingDown if the peer is shutting down (done closed) — the
//     event is not delivered but this is not an error condition for the
//     caller; it just signals the write happened during teardown.
//   - ErrEventBufferFull if the channel is full and would block. The
//     binding has already committed at the storage layer (per V7 §2870);
//     only the event was not delivered. Caller decides whether to retry,
//     surface as a 500 storage_error, log + continue, or treat as fatal.
//
// Design rationale: see ErrEventBufferFull doc above. Briefly: silently
// dropping the event corrupts the cascade contract (downstream consumers
// believe they've seen every transition when they haven't); blocking the
// caller until consumed gives one slow / un-drained sink the power to
// halt the entire peer's write path. Both are wrong. Returning an error
// pushes the decision to the caller, whose code has the context to make
// it correctly. This mirrors §2688's contract for storage-layer
// transient I/O failures.
func (n *NotifyingLocationIndex) emit(evt TreeChangeEvent) error {
	// Suppression path: no-op for events fired during construction's seed
	// phase or any explicit bulk-rebuild. Sync hooks have already run; the
	// async event delivery is what's suppressed.
	if n.suppressEmit.Load() {
		return nil
	}
	// Fast-path done check. Go's select picks at random when multiple cases
	// are ready; bias toward done first so we don't push events into a
	// channel about to be torn down.
	select {
	case <-n.done:
		return ErrShuttingDown
	default:
	}
	select {
	case <-n.done:
		return ErrShuttingDown
	case n.events <- evt:
		return nil
	default:
		// Saturation. Increment counter for observability and surface as
		// error to caller. Operators should monitor this counter — sustained
		// growth means the consumer pipeline is undersized for the workload.
		count := n.droppedEvents.Add(1)
		if n.debugLog != nil {
			n.debugLog.Printf("tree event buffer full (saturation count: %d): path=%s — caller should retry or surface as storage_error", count, evt.Path)
		}
		return ErrEventBufferFull
	}
}
