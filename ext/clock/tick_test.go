package clock

// EXTENSION-CLOCK §2.5/§2.8 periodic tick emission.
//
// These drive emitTick / tickInterval directly rather than sleeping through
// real intervals: the loop is a time.Ticker around emitTick, so testing the
// emission and the config resolution covers the behavior without putting wall
// time in the suite. The one thing that genuinely needs the loop — that it
// stops when its context is cancelled — is tested with a short interval.

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func newTickHandler(t *testing.T, tickIntervalMs *uint64) *Handler {
	t.Helper()
	h := NewHandler()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	h.SetupAdvancement(cs, li, "peer-1", hash.Hash{}, nil)

	if tickIntervalMs != nil {
		config := types.ClockConfigData{Mode: "wall", TickInterval: tickIntervalMs}
		ent, err := config.ToEntity()
		if err != nil {
			t.Fatal(err)
		}
		ch, err := cs.Put(ent)
		if err != nil {
			t.Fatal(err)
		}
		if err := li.Set("system/clock/config", ch); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func readTick(t *testing.T, h *Handler) (types.ClockTickData, bool) {
	t.Helper()
	tickHash, ok := h.li.Get(TickPath)
	if !ok {
		return types.ClockTickData{}, false
	}
	ent, ok := h.cs.Get(tickHash)
	if !ok {
		t.Fatalf("tick bound at %s but not in the content store", TickPath)
	}
	if ent.Type != types.TypeClockTick {
		t.Fatalf("entity at %s has type %q, want %q", TickPath, ent.Type, types.TypeClockTick)
	}
	var d types.ClockTickData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		t.Fatalf("decode tick: %v", err)
	}
	return d, true
}

// TestTickDisabledWithoutInterval pins §2.5's "Absent = no periodic ticks".
// The conservative default matters: a background goroutine writing to every
// peer's tree once a second must not be something you get by omission.
func TestTickDisabledWithoutInterval(t *testing.T) {
	h := newTickHandler(t, nil)
	if _, ok := h.tickInterval(); ok {
		t.Fatal("tick interval resolved with no config — ticking would start unasked")
	}

	// StartTicking must be a no-op, not a goroutine spinning on a zero ticker.
	h.StartTicking(context.Background())
	time.Sleep(30 * time.Millisecond)
	if _, emitted := readTick(t, h); emitted {
		t.Error("a tick was emitted with no tick_interval configured")
	}
}

func TestTickIntervalFloorIsApplied(t *testing.T) {
	tiny := uint64(1)
	h := newTickHandler(t, &tiny)
	got, ok := h.tickInterval()
	if !ok {
		t.Fatal("interval did not resolve")
	}
	if want := time.Duration(MinTickIntervalMs) * time.Millisecond; got != want {
		t.Errorf("interval = %v, want the %v floor — every tick runs the full emit pipeline", got, want)
	}
}

// TestEmitTickWritesMonotonicSequence covers §2.8: the tick entity carries a
// monotonically increasing counter and lands at the subscribed path.
func TestEmitTickWritesMonotonicSequence(t *testing.T) {
	interval := uint64(50)
	h := newTickHandler(t, &interval)

	for want := uint64(1); want <= 3; want++ {
		if err := h.emitTick(); err != nil {
			t.Fatalf("emitTick: %v", err)
		}
		tick, ok := readTick(t, h)
		if !ok {
			t.Fatalf("no tick bound at %s", TickPath)
		}
		if tick.Sequence != want {
			t.Fatalf("sequence = %d, want %d", tick.Sequence, want)
		}
	}
}

// TestTickPathIsExcludedFromAdvancement is the §4.3 guard. If a tick advanced
// the clock, an IDLE peer's logical counter would climb at wall-clock rate —
// a logical clock counting seconds instead of causal events.
func TestTickPathIsExcludedFromAdvancement(t *testing.T) {
	if !isClockEnginePath(TickPath) {
		t.Fatalf("%s is not treated as clock engine output — every tick would advance the clock", TickPath)
	}
	// The §4.3 enumeration is exact, not a prefix match: config MUST still
	// advance like any other tree mutation.
	if isClockEnginePath("system/clock/config") {
		t.Error("config was excluded from advancement — §4.3 says it SHOULD advance like any other write")
	}
	if isClockEnginePath("app/anything") {
		t.Error("a non-clock path was excluded from advancement")
	}
}

// TestResumeTickSequenceSurvivesRestart: a subscriber that has seen tick 500
// must not then see tick 1. Restarting at 0 is the other legal reading of
// §10.4 and is worse — any consumer using sequence as an ordering coordinate
// would silently go backwards.
func TestResumeTickSequenceSurvivesRestart(t *testing.T) {
	interval := uint64(50)
	h := newTickHandler(t, &interval)
	for i := 0; i < 5; i++ {
		if err := h.emitTick(); err != nil {
			t.Fatal(err)
		}
	}

	// A "restart": a fresh handler over the same store and index.
	restarted := NewHandler()
	restarted.SetupAdvancement(h.cs, h.li, "peer-1", hash.Hash{}, nil)
	restarted.resumeTickSequence()
	if err := restarted.emitTick(); err != nil {
		t.Fatal(err)
	}
	tick, ok := readTick(t, restarted)
	if !ok {
		t.Fatal("no tick after restart")
	}
	if tick.Sequence != 6 {
		t.Errorf("sequence after restart = %d, want 6 — the counter went backwards", tick.Sequence)
	}
}

// TestResumeIgnoresForeignEntityAtTickPath: recovery reads a value the tree
// could have had put there by something else. It must not adopt a sequence
// from an entity that is not a tick.
func TestResumeIgnoresForeignEntityAtTickPath(t *testing.T) {
	interval := uint64(50)
	h := newTickHandler(t, &interval)

	raw, _ := ecf.Encode(map[string]interface{}{"sequence": 9999})
	foreign, _ := entity.NewEntity("app/not-a-tick", cbor.RawMessage(raw))
	fh, err := h.cs.Put(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.li.Set(TickPath, fh); err != nil {
		t.Fatal(err)
	}

	h.resumeTickSequence()
	if err := h.emitTick(); err != nil {
		t.Fatal(err)
	}
	tick, _ := readTick(t, h)
	if tick.Sequence != 1 {
		t.Errorf("sequence = %d, want 1 — a foreign entity's field was adopted as the tick counter", tick.Sequence)
	}
}

// TestTickLoopStopsOnContextCancel: the loop's whole lifecycle contract is
// "dies with the context that started it" — no stop channel, no handshake.
func TestTickLoopStopsOnContextCancel(t *testing.T) {
	interval := uint64(10)
	h := newTickHandler(t, &interval)

	ctx, cancel := context.WithCancel(context.Background())
	h.StartTicking(ctx)
	time.Sleep(60 * time.Millisecond)

	h.mu.Lock()
	during := h.tickSeq
	h.mu.Unlock()
	if during == 0 {
		t.Fatal("no ticks emitted while the loop was running")
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
	h.mu.Lock()
	afterCancel := h.tickSeq
	h.mu.Unlock()
	time.Sleep(60 * time.Millisecond)
	h.mu.Lock()
	settled := h.tickSeq
	h.mu.Unlock()

	if settled != afterCancel {
		t.Errorf("ticks kept coming after cancel (%d -> %d) — the goroutine outlived its context", afterCancel, settled)
	}
}
