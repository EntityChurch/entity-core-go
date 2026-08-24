package clock

// Periodic tick emission — EXTENSION-CLOCK §2.5 (`tick_interval`), §2.8 (the
// tick entity), §3.4 (the `tick` subscription convenience op).
//
// Until this existed, Go carried the whole tick SURFACE and none of the
// behavior: `TickInterval` and `DefaultTickIntervalMs` were declared in
// core/types and read nowhere, and `tick` delegated a subscription to
// `system/clock/tick/latest` — a path nothing ever wrote. A tick subscription
// therefore never fired. That was conformant (§10.3 lists the tick operation
// under MAY Implement) but useless, and it is the substrate every timed
// behavior wants underneath it.
//
// The shape, which is the spec's own: the clock OWNS the timer and writes the
// tick into the tree; consumers subscribe to the path. Nothing else needs a
// timer, because a tree write already fans out through the subscription engine
// — the tick is just another emission, and "timed execution" (§1.1) becomes an
// ordinary subscription to an ordinary path.
//
// What this deliberately does NOT do: schedule. There is no "wake me at tick N",
// no one-shot, and no per-waiter interval — `tick_interval` is peer-global and
// the tick lands on one overwritten path, so every watcher wakes on every tick
// and filters for itself. That is the spec as it stands; the gap and a proposed
// shape (addressable ticks, so a subscription on a path that names a future
// fires exactly once) were routed to arch 2026-07-22 as "clock has no
// scheduler".

import (
	"context"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// TickPath is where the periodic tick lands (§2.8). One path, overwritten each
// interval — subscribers watch it via `system/clock/tick/*`.
const TickPath = "system/clock/tick/latest"

// MinTickIntervalMs floors a configured interval.
//
// Not in the spec, and it overrides operator config, so it logs when it bites
// rather than applying silently. The reason it exists: every tick is a real
// tree write that runs the whole emit pipeline (advancement, history,
// subscription fan-out), so a 1ms interval is not a fast clock, it is a
// self-inflicted write storm that starves the work the ticks were meant to
// pace. An operator who wants sub-10ms timing wants a different mechanism than
// a tree write, and should say so upstream rather than discover it here.
const MinTickIntervalMs uint64 = 10

// StartTicking begins periodic tick emission, running until ctx is cancelled.
//
// No-ops when the peer has no `tick_interval` configured: §2.5 is explicit that
// absent means "no periodic ticks". That is the conservative reading and the
// right default — a background goroutine writing to every peer's tree once a
// second is not something to switch on by omission. (§8's
// `DEFAULT_TICK_INTERVAL_MS = 1000` reads as the value to use when ticking is
// enabled but unspecified, not as a reason to tick unasked; the tension is
// noted in the routed spec issue.)
//
// This is the first periodic timer in ext/ — ext/network's retry backoff
// (`time.AfterFunc`) is the only other one, and the marker sweep in
// ext/continuation deliberately avoided owning a lifecycle at all. So the
// lifecycle is kept to exactly one shape: one goroutine, owned by the caller's
// context, no stop channel, no shutdown handshake. It dies with the context
// that started it, which is the same contract subscription's StartDelivery has.
//
// Safe to call before or after SetupAdvancement; a tick fired before the store
// is wired is skipped rather than panicking.
func (h *Handler) StartTicking(ctx context.Context) {
	interval, ok := h.tickInterval()
	if !ok {
		h.logf("clock: no tick_interval configured — periodic ticks disabled (EXTENSION-CLOCK §2.5)")
		return
	}
	h.resumeTickSequence()
	h.logf("clock: emitting periodic ticks every %v at %s", interval, TickPath)
	go h.tickLoop(ctx, interval)
}

// tickLoop emits one tick per interval, re-reading the configured interval each
// time so `system/clock/config` can be retuned on a live peer instead of
// requiring a restart. A config change that disables ticking stops the loop.
func (h *Handler) tickLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.emitTick(); err != nil {
				// Best-effort, like every other clock write: a failed tick
				// must not kill the loop, or one transient store error
				// silently ends timed execution for the peer's lifetime.
				h.logf("clock: tick emission failed: %v", err)
			}
			next, ok := h.tickInterval()
			if !ok {
				h.logf("clock: tick_interval removed from config — stopping periodic ticks")
				return
			}
			if next != interval {
				h.logf("clock: tick_interval changed %v -> %v", interval, next)
				interval = next
				ticker.Reset(interval)
			}
		}
	}
}

// tickInterval reads the configured interval, applying the floor. Returns
// false when ticking is not configured.
func (h *Handler) tickInterval() (time.Duration, bool) {
	h.mu.Lock()
	cs, li := h.cs, h.li
	h.mu.Unlock()
	if cs == nil || li == nil {
		return 0, false
	}
	config := loadConfig(cs, li)
	if config.TickInterval == nil || *config.TickInterval == 0 {
		return 0, false
	}
	ms := *config.TickInterval
	if ms < MinTickIntervalMs {
		h.logf("clock: tick_interval %dms is below the %dms floor — clamping (every tick is a tree write through the full emit pipeline)",
			ms, MinTickIntervalMs)
		ms = MinTickIntervalMs
	}
	return time.Duration(ms) * time.Millisecond, true
}

// emitTick writes one `system/clock/tick` entity to TickPath (§2.8).
//
// The store handles are snapshotted under the lock and the write happens
// OUTSIDE it. advanceClock holds the mutex across its writes, but it is called
// from the emit pipeline where that is already the ambient shape; a background
// goroutine holding the handler lock while a tree write runs the entire emit
// pipeline (advancement, history, subscription fan-out) is a deadlock waiting
// for the first consumer that calls back into the clock. Snapshot, release,
// write.
func (h *Handler) emitTick() error {
	h.mu.Lock()
	cs, li, bg := h.cs, h.li, h.bgCtx
	h.tickSeq++
	seq := h.tickSeq
	h.mu.Unlock()

	if cs == nil || li == nil {
		return nil // not wired yet; skip rather than fail
	}

	config := loadConfig(cs, li)
	tick := types.ClockTickData{
		Sequence: seq,
		State:    readClockState(config, cs, li),
	}
	raw, err := ecf.Encode(tick)
	if err != nil {
		return err
	}
	ent, err := entity.NewEntity(types.TypeClockTick, cbor.RawMessage(raw))
	if err != nil {
		return err
	}
	eh, err := cs.Put(ent)
	if err != nil {
		return err
	}
	if cw, ok := li.(store.ContextualWriter); ok && bg != nil {
		// §9: clock writes are authorized by the clock handler's own grant with
		// the local peer identity as author — the same background context
		// advancement already uses.
		_, err = cw.SetWithContext(TickPath, eh, bg)
	} else {
		err = li.Set(TickPath, eh)
	}
	return err
}

// resumeTickSequence recovers the sequence counter from the last tick left in
// the tree, so `sequence` stays monotonic across a restart (§2.8 calls it a
// "monotonically increasing tick counter"; persistence across restarts is
// implementation-defined per §10.4).
//
// Restarting at 0 would be the other legal reading and is worse in the way that
// matters: a subscriber that has seen tick 500 and then sees tick 1 has no way
// to tell a restart from a wrap or a spoof, and any consumer using the sequence
// as an ordering coordinate silently goes backwards.
func (h *Handler) resumeTickSequence() {
	h.mu.Lock()
	cs, li := h.cs, h.li
	h.mu.Unlock()
	if cs == nil || li == nil {
		return
	}
	tickHash, ok := li.Get(TickPath)
	if !ok {
		return
	}
	ent, ok := cs.Get(tickHash)
	if !ok || ent.Type != types.TypeClockTick {
		return
	}
	var last types.ClockTickData
	if err := ecf.Decode(ent.Data, &last); err != nil {
		return
	}
	h.mu.Lock()
	if last.Sequence > h.tickSeq {
		h.tickSeq = last.Sequence
	}
	h.mu.Unlock()
}
