package continuation

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

const collectNow uint64 = 1_800_000_000_000 // arbitrary "now", ms since epoch

// bindMarker puts a marker with the given origination timestamp at a path
// shaped like the §3.10.6 scheme, and returns the path.
func bindMarker(t *testing.T, cs store.ContentStore, li store.LocationIndex, chainID string, ts uint64) string {
	t.Helper()
	ent, err := types.ChainErrorLostData{
		Reason:    "unavailable",
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
	path := markerRoot + "lost/" + chainID + "/step/unavailable/marker"
	if err := li.Set(path, h); err != nil {
		t.Fatalf("bind marker: %v", err)
	}
	return path
}

func TestCollectExpiredMarkers(t *testing.T) {
	day := DefaultMarkerRetentionMs

	tests := []struct {
		name      string
		age       uint64 // how long before collectNow the marker originated
		retention uint64
		wantGone  bool
	}{
		{"fresh marker survives", 0, day, false},
		{"1h old survives a 24h window", 60 * 60 * 1000, day, false},
		{"23h59m old survives", day - 60_000, day, false},
		{"exactly at the window is collected", day, day, true},
		{"a week old is collected", 7 * day, day, true},
		// The operator who wants their history keeps ALL of it.
		{"retain-forever keeps a year-old marker", 365 * day, RetainMarkersForever, false},
		{"a short window collects aggressively", 2000, 1000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := store.NewMemoryContentStore()
			li := store.NewMemoryLocationIndex()
			path := bindMarker(t, cs, li, "chain-x", collectNow-tt.age)

			CollectExpiredMarkers(cs, li, tt.retention, collectNow)

			_, present := li.Get(path)
			if tt.wantGone && present {
				t.Errorf("marker aged %dms survived a %dms retention window", tt.age, tt.retention)
			}
			if !tt.wantGone && !present {
				t.Errorf("marker aged %dms was collected under a %dms retention window", tt.age, tt.retention)
			}
		})
	}
}

// The sweep must collect only what it can positively identify as an expired
// marker. Anything else in the tree — a foreign entity, an undecodable body, a
// marker with no timestamp — stays. A reaper that deletes what it did not
// understand is a data-loss bug, and this tree is an event log.
func TestCollectExpiredMarkersLeavesWhatItCannotIdentify(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	ancient := collectNow - 365*DefaultMarkerRetentionMs

	// A foreign entity parked under the marker root.
	foreign, err := types.ContinuationData{Target: "system/tree", Operation: "put"}.ToEntity()
	if err != nil {
		t.Fatalf("build foreign entity: %v", err)
	}
	fh, _ := cs.Put(foreign)
	foreignPath := markerRoot + "lost/chain-f/step/reason/not-a-marker"
	if err := li.Set(foreignPath, fh); err != nil {
		t.Fatalf("bind foreign: %v", err)
	}

	// A marker with NO timestamp: unknown age, not evidence of old age.
	noTS, err := types.ChainErrorLostData{Reason: "unavailable", ChainID: "chain-n", StepIndex: "step"}.ToEntity()
	if err != nil {
		t.Fatalf("build untimestamped marker: %v", err)
	}
	nh, _ := cs.Put(noTS)
	noTSPath := markerRoot + "lost/chain-n/step/unavailable/marker"
	if err := li.Set(noTSPath, nh); err != nil {
		t.Fatalf("bind untimestamped: %v", err)
	}

	// And one genuinely expired marker, so the sweep is doing something.
	expired := bindMarker(t, cs, li, "chain-e", ancient)

	got := CollectExpiredMarkers(cs, li, DefaultMarkerRetentionMs, collectNow)
	if got != 1 {
		t.Fatalf("collected %d markers, want exactly 1 (only the identified expired one)", got)
	}
	if _, present := li.Get(expired); present {
		t.Errorf("the expired marker survived")
	}
	if _, present := li.Get(foreignPath); !present {
		t.Errorf("the sweep deleted a non-marker entity it did not identify")
	}
	if _, present := li.Get(noTSPath); !present {
		t.Errorf("the sweep deleted a marker with no timestamp — unknown age is not old age")
	}
}

// Collection must never be able to affect a chain: it removes observations,
// not behaviour. A nil store/index is a manually-built context, not a crash.
func TestCollectExpiredMarkersIsSafeOnEmptyInputs(t *testing.T) {
	if n := CollectExpiredMarkers(nil, nil, DefaultMarkerRetentionMs, collectNow); n != 0 {
		t.Errorf("collected %d from nil inputs", n)
	}
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	if n := CollectExpiredMarkers(cs, li, DefaultMarkerRetentionMs, collectNow); n != 0 {
		t.Errorf("collected %d from an empty tree", n)
	}
	// A clock earlier than the window cannot expire anything, and must not
	// underflow into collecting everything.
	bindMarker(t, cs, li, "chain-z", 1)
	if n := CollectExpiredMarkers(cs, li, DefaultMarkerRetentionMs, 1000); n != 0 {
		t.Errorf("collected %d with now < retention — underflowed the cutoff", n)
	}
}

// The default is bounded: doing nothing must not get you unbounded growth,
// which is the entire reason collection is a MUST.
func TestHandlerDefaultsToBoundedRetention(t *testing.T) {
	if got := NewHandler().markerRetention(); got != DefaultMarkerRetentionMs {
		t.Errorf("default retention = %d, want %d (24h)", got, DefaultMarkerRetentionMs)
	}
	if got := NewHandler(WithMarkerRetention(RetainMarkersForever)).markerRetention(); got != RetainMarkersForever {
		t.Errorf("WithMarkerRetention(RetainMarkersForever) = %d, want 0 — the operator opt-out is not wired", got)
	}
	if got := NewHandler(WithMarkerRetention(5000)).markerRetention(); got != 5000 {
		t.Errorf("WithMarkerRetention(5000) = %d", got)
	}
}
