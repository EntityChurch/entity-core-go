package tree

import (
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// trackerSetup creates a content store and a NotifyingLocationIndex wired to a
// RootTracker. Returns all the pieces a test needs to drive writes and inspect
// the tracked root path.
func trackerSetup(t *testing.T) (*RootTracker, store.ContentStore, store.LocationIndex, crypto.PeerID) {
	t.Helper()
	cs := store.NewMemoryContentStore()
	rawLI := store.NewMemoryLocationIndex()
	events := make(chan store.TreeChangeEvent, 64)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	notifying := store.NewNotifyingLocationIndex(rawLI, events, done)
	kp, _ := crypto.Generate()
	li := store.NewNamespacedIndex(notifying, string(kp.PeerID()))

	tracker := NewRootTracker(cs, string(kp.PeerID()), nil)
	tracker.SetLocationIndex(li)
	// We need the tracker to be a sync hook so root writes don't race with
	// our assertions.
	notifying.AddNamedSyncHook("root-tracker", tracker.OnTreeChange)
	return tracker, cs, li, kp.PeerID()
}

func writeTrackingConfig(t *testing.T, cs store.ContentStore, li store.LocationIndex, name, prefix string, enabled bool) {
	t.Helper()
	cfg := types.TrackingConfigData{Prefix: prefix, Enabled: enabled}
	ent, err := cfg.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(ent); err != nil {
		t.Fatal(err)
	}
	li.Set(trackingConfigPrefix+name, ent.ContentHash)
}

func rootPathFor(prefix string) string {
	// Mirrors RootTracker.rebuild.
	p := prefix
	for len(p) > 0 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return rootStoragePrefix + p
}

func TestRootTracker_BuildsOnConfigCreation(t *testing.T) {
	tracker, cs, li, pid := trackerSetup(t)

	// Seed some entities under the prefix before the config is enabled — the
	// initial Load() after config creation must build from these.
	e1 := makeEntity(t, "test/b", "v1")
	cs.Put(e1)
	li.Set("project/src/a.go", e1.ContentHash)

	writeTrackingConfig(t, cs, li, "project", "project/", true)

	// The config write path is what triggers tracker.handleConfigChange, which
	// rebuilds. After the sync hook returns, the tracked root should exist.
	got, ok := li.Get(rootPathFor("project/"))
	if !ok {
		t.Fatal("tracked root should be set after enabling config")
	}

	// Compare against a freshly-built trie over the same bindings.
	want, err := BuildTrieForPrefix(cs, li, pid, "project/")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("tracked root %s != expected %s", got.String(), want.String())
	}

	// Sanity that tracker cache picked up the config.
	if r, ok := tracker.Root("project/"); !ok || r != want {
		t.Fatalf("tracker.Root returned (%s, %v), want (%s, true)", r.String(), ok, want.String())
	}
}

func TestRootTracker_UpdatesOnWritesUnderPrefix(t *testing.T) {
	_, cs, li, pid := trackerSetup(t)
	writeTrackingConfig(t, cs, li, "project", "project/", true)

	first, _ := li.Get(rootPathFor("project/"))

	e := makeEntity(t, "test/b", "v1")
	cs.Put(e)
	li.Set("project/src/x.go", e.ContentHash)

	second, ok := li.Get(rootPathFor("project/"))
	if !ok {
		t.Fatal("tracked root missing after write")
	}
	if second == first {
		t.Fatal("tracked root did not change after write under prefix")
	}

	want, err := BuildTrieForPrefix(cs, li, pid, "project/")
	if err != nil {
		t.Fatal(err)
	}
	if second != want {
		t.Fatalf("tracked root %s != rebuild %s", second.String(), want.String())
	}
}

func TestRootTracker_IgnoresWritesOutsidePrefix(t *testing.T) {
	_, cs, li, _ := trackerSetup(t)
	writeTrackingConfig(t, cs, li, "project", "project/", true)
	before, _ := li.Get(rootPathFor("project/"))

	e := makeEntity(t, "test/b", "v1")
	cs.Put(e)
	li.Set("other/stuff.txt", e.ContentHash)

	after, _ := li.Get(rootPathFor("project/"))
	if before != after {
		t.Fatalf("tracked root changed for unrelated write: %s → %s",
			before.String(), after.String())
	}
}

func TestRootTracker_SelfGuardPreventsLoop(t *testing.T) {
	_, cs, li, _ := trackerSetup(t)
	writeTrackingConfig(t, cs, li, "project", "project/", true)

	// Write directly under system/tree/root/ — tracker must ignore it. If the
	// self-guard failed, the tracker would rebuild and overwrite the value.
	var bogus hash.Hash
	bogus.Algorithm = hash.AlgorithmSHA256
	for i := 0; i < hash.SHA256DigestSize; i++ {
		bogus.Digest[i] = 0xAB
	}
	li.Set(rootStoragePrefix+"other", bogus)

	got, ok := li.Get(rootStoragePrefix + "other")
	if !ok || got != bogus {
		t.Fatalf("self-guard write was overwritten: ok=%v got=%s", ok, got.String())
	}
}

func TestSnapshotShortCircuitMatchesRebuild(t *testing.T) {
	// With a RootTracker attached, snapshot must return the tracked root, and
	// that root must equal a full rebuild over the same bindings.
	tracker, cs, li, pid := trackerSetup(t)
	writeTrackingConfig(t, cs, li, "project", "project/", true)

	// Populate.
	for _, k := range []string{"src/a.go", "src/b.go", "src/d/e.go", "README.md"} {
		e := makeEntity(t, "test/b", k)
		cs.Put(e)
		li.Set("project/"+k, e.ContentHash)
	}

	// Handler with tracker attached.
	h := NewHandler()
	h.SetRootTracker(tracker)

	snapReq := types.SnapshotRequestData{}
	snapEntity, _ := snapReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "snapshot", snapEntity,
		&types.ResourceTarget{Targets: []string{"project/"}})
	resp, err := h.handleSnapshot(nil, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("snapshot status: %d", resp.Status)
	}
	snapData, err := types.SnapshotDataFromEntity(resp.Result)
	if err != nil {
		t.Fatal(err)
	}

	want, err := BuildTrieForPrefix(cs, li, pid, "project/")
	if err != nil {
		t.Fatal(err)
	}
	if snapData.Root != want {
		t.Fatalf("snapshot root %s != rebuild %s", snapData.Root.String(), want.String())
	}
	if got, _ := tracker.Root("project/"); got != want {
		t.Fatalf("tracker.Root %s != rebuild %s", got.String(), want.String())
	}
}

// TestRootTracker_CurrentRootReflectsPendingAsyncApply pins the fix for the
// symmetric last-burst-write loss (workbench CORE-GO-LAST-BURST-WRITE-LOSS,
// 2026-08-20). Under a concurrent burst the tracker defers a write's
// incremental apply to a goroutine (applyEventWithDepth's contention path) and
// returns before it lands, so a plain Root() read lags the live index by the
// very write being applied. The AutoVersioner reads through CurrentRoot, which
// must recompute from the live index while an apply is pending — otherwise it
// builds a version from the lagging root, fails to capture the write, and the
// loss is terminal for the last write of a burst (no next event re-fires).
//
// This test forces the async-defer deterministically by holding the prefix
// mutex, so the assertion is not load-dependent. Teeth: point CurrentRoot back
// at Root() and the CurrentRoot assertion goes RED (it would return `settled`,
// the lagging root, not `want`).
func TestRootTracker_CurrentRootReflectsPendingAsyncApply(t *testing.T) {
	tracker, cs, li, pid := trackerSetup(t)
	writeTrackingConfig(t, cs, li, "project", "project/", true)

	// Baseline entry → settled tracked root.
	e1 := makeEntity(t, "test/b", "v1")
	cs.Put(e1)
	li.Set("project/a.go", e1.ContentHash)
	settled, ok := tracker.Root("project/")
	if !ok {
		t.Fatal("precondition: baseline tracked root must exist")
	}

	// Hold the per-prefix mutex so the next write's apply is forced down the
	// async (contended) path and blocks on us — reproducing the burst window.
	mu := tracker.lockForPrefix("project/")
	mu.Lock()

	// New write: its OnTreeChange async-spawns (pending++) and returns; the
	// apply goroutine blocks on mu. The binding is in the live index now.
	e2 := makeEntity(t, "test/b", "v2")
	cs.Put(e2)
	li.Set("project/b.go", e2.ContentHash)

	// The cached root still lags — the apply is blocked on our lock.
	if lag, _ := tracker.Root("project/"); lag != settled {
		mu.Unlock()
		t.Fatalf("precondition: cached root should still lag at %s, got %s", settled.String(), lag.String())
	}

	// The authoritative root over the live index includes the pending write.
	want, err := BuildTrieForPrefix(cs, li, pid, "project/")
	if err != nil {
		mu.Unlock()
		t.Fatal(err)
	}
	if want == settled {
		mu.Unlock()
		t.Fatal("test bug: the new write did not change the authoritative root")
	}

	// CurrentRoot must reflect the pending write — this is the fix.
	got, ok := tracker.CurrentRoot("project/")
	if !ok || got != want {
		mu.Unlock()
		t.Fatalf("CurrentRoot while apply pending = (%s, %v), want (%s, true); the lagging cached root %s is the pre-fix answer",
			got.String(), ok, want.String(), settled.String())
	}

	// Release; the deferred apply lands and the cached root catches up.
	mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		tracker.rebuildMu.Lock()
		p := tracker.pending["project/"]
		tracker.rebuildMu.Unlock()
		if p == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deferred apply never drained")
		}
		time.Sleep(time.Millisecond)
	}
	if final, _ := tracker.Root("project/"); final != want {
		t.Fatalf("after deferred apply, cached root = %s, want %s", final.String(), want.String())
	}
}

func TestRootTracker_DisableClearsRoot(t *testing.T) {
	_, cs, li, _ := trackerSetup(t)
	writeTrackingConfig(t, cs, li, "project", "project/", true)

	if _, ok := li.Get(rootPathFor("project/")); !ok {
		t.Fatal("precondition: tracked root must exist")
	}

	writeTrackingConfig(t, cs, li, "project", "project/", false)

	if _, ok := li.Get(rootPathFor("project/")); ok {
		t.Fatal("tracked root must be cleared when config disabled")
	}
}
