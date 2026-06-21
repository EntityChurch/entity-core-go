package tree

import (
	"testing"

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
