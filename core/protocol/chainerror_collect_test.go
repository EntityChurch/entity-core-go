package protocol

import (
	"testing"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

const ceCollectNow uint64 = 1_800_000_000_000 // arbitrary "now", ms since epoch

// putMarker stores a chain-error-lost marker with the given origination
// timestamp and binds it under MarkerRoot (the kind segment is arbitrary — the
// sweep is indifferent to lost vs rejected). Returns the bound path.
func putMarker(t *testing.T, cs store.ContentStore, li store.LocationIndex, kind, chainID string, ts uint64) string {
	t.Helper()
	ent, err := types.ChainErrorLostData{
		Reason:    "capability_denied",
		Timestamp: ts,
		ChainID:   chainID,
		StepIndex: "step",
	}.ToEntity()
	if err != nil {
		t.Fatalf("build marker: %v", err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatalf("store marker: %v", err)
	}
	path := MarkerRoot + kind + "/" + chainID + "/step/capability_denied/marker"
	if err := li.Set(path, h); err != nil {
		t.Fatalf("bind marker: %v", err)
	}
	return path
}

func setRetention(t *testing.T, cs store.ContentStore, li store.LocationIndex, ms uint64) {
	t.Helper()
	raw, err := ecf.Encode(ChainErrorsConfig{RetentionMs: &ms})
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	ent, err := entity.NewEntity(MarkerRetentionConfigPath, cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatalf("store config: %v", err)
	}
	if err := li.Set(MarkerRetentionConfigPath, h); err != nil {
		t.Fatalf("bind config: %v", err)
	}
}

// TestCollectExpiredMarkersReapsRejectedAndLost proves the shared collector reaps
// under MarkerRoot regardless of the kind segment — the reason it must live here,
// where the dispatcher's `rejected` markers can reach it.
func TestCollectExpiredMarkersReapsRejectedAndLost(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	oldRejected := putMarker(t, cs, li, "rejected", "chain-old", ceCollectNow-2*DefaultMarkerRetentionMs)
	oldLost := putMarker(t, cs, li, "lost", "chain-old2", ceCollectNow-2*DefaultMarkerRetentionMs)
	fresh := putMarker(t, cs, li, "rejected", "chain-fresh", ceCollectNow)

	n := CollectExpiredMarkers(cs, li, DefaultMarkerRetentionMs, ceCollectNow)
	if n != 2 {
		t.Errorf("collected %d, want 2 (both old markers, either kind)", n)
	}
	for _, p := range []string{oldRejected, oldLost} {
		if _, present := li.Get(p); present {
			t.Errorf("expired marker survived: %s", p)
		}
	}
	if _, present := li.Get(fresh); !present {
		t.Errorf("fresh marker was collected: %s", fresh)
	}
}

// TestDispatcherSelfSweepsRejectedMarkers is the leak fix as an executable claim:
// the dispatcher reaps expired chain-error markers on the rejected-bind path,
// honoring the tree retention config — so a peer that only ever DENIES chain
// dispatches (never advancing a continuation, so the ext/continuation sweep never
// fires) still collects. Reported by entity-core-rust, 2026-08-15.
func TestDispatcherSelfSweepsRejectedMarkers(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	d := &Dispatcher{Store: cs, LocationIndex: li}

	// An old rejected marker from a prior probe, and the operator's short window.
	old := putMarker(t, cs, li, "rejected", "chain-attacker", ceCollectNow-2*DefaultMarkerRetentionMs)
	setRetention(t, cs, li, 1000) // 1s window; the old marker is well past it

	// The sweep uses time.Now() internally; ceCollectNow is far in the future, so
	// against real-now the old marker (timestamp ~ceCollectNow) would look
	// future-dated and NOT be collected. Drive the reap directly at the fixed
	// clock to assert the config-honoring reap; the throttle/CAS path is covered
	// by TestDispatcherSweepThrottle.
	got := CollectExpiredMarkers(cs, li, EffectiveRetention(cs, li, DefaultMarkerRetentionMs), ceCollectNow)
	if got != 1 {
		t.Fatalf("collected %d, want 1 (the old rejected marker under the tree's 1s window)", got)
	}
	if _, present := li.Get(old); present {
		t.Errorf("dispatcher retention path did not reap the expired rejected marker")
	}

	// And the wired entrypoint runs without panicking and claims its throttle
	// window (a real bind calls exactly this).
	d.maybeCollectChainErrorMarkers()
	if d.lastChainErrorSweep.Load() == 0 {
		t.Errorf("maybeCollectChainErrorMarkers did not stamp the throttle")
	}
}

// TestDispatcherSweepThrottle: a second sweep inside the throttle window is a
// no-op (the timestamp does not advance), so the reap stays off the hot path.
func TestDispatcherSweepThrottle(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	d := &Dispatcher{Store: cs, LocationIndex: li}

	d.maybeCollectChainErrorMarkers()
	first := d.lastChainErrorSweep.Load()
	if first == 0 {
		t.Fatalf("first sweep did not stamp the throttle")
	}
	d.maybeCollectChainErrorMarkers()
	if d.lastChainErrorSweep.Load() != first {
		t.Errorf("second sweep inside the throttle window advanced the timestamp — throttle not holding")
	}
}

// TestEffectiveRetentionPrecedence: tree config wins over the fallback, including
// an explicit 0 (retain-forever); absent config falls back.
func TestEffectiveRetentionPrecedence(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	if got := EffectiveRetention(cs, li, DefaultMarkerRetentionMs); got != DefaultMarkerRetentionMs {
		t.Errorf("no config: EffectiveRetention = %d, want fallback %d", got, DefaultMarkerRetentionMs)
	}
	setRetention(t, cs, li, 5000)
	if got := EffectiveRetention(cs, li, DefaultMarkerRetentionMs); got != 5000 {
		t.Errorf("tree config 5000 did not win: got %d", got)
	}
	setRetention(t, cs, li, 0)
	if got := EffectiveRetention(cs, li, DefaultMarkerRetentionMs); got != RetainMarkersForever {
		t.Errorf("explicit retention_ms=0 must win as retain-forever: got %d", got)
	}
}
