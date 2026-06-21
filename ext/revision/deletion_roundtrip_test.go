package revision

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestDeletionRoundtrip_SinglePeer is the A.8 Phase 2 in-process integration
// test. Exercises the full commit → emit-marker → re-add cycle within a
// single peer:
//
//  1. Bind a path → AV fires → version trie binds the entity.
//  2. Unbind the path via tree:put(path, null) → AV fires → version trie
//     carries a deletion marker at the path.
//  3. Live tree should not show the path (markers never appear in live).
//  4. Re-bind to a new entity → AV fires → version trie binds the new
//     entity (marker is overridden by the re-add).
//  5. Live tree shows the new entity.
//
// This is the canonical "delete propagates correctly" semantic that all
// version-transcription operations rely on.
func TestDeletionRoundtrip_SinglePeer(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	// Step 1: bind data/foo → entity_X.
	hX := f.putEntity(t, "data/foo", "app/doc", map[string]string{"v": "X"})
	headAfterBind, ok := f.head("data/")
	if !ok {
		t.Fatal("no head after first bind")
	}
	v1 := f.loadVersion(t, headAfterBind)
	v1Bindings := tree.CollectAllBindings(f.cs, v1.Root, "")
	if got := v1Bindings["foo"]; got != hX {
		t.Fatalf("V1.trie[data/foo] = %s, want entity_X %s", got, hX)
	}

	// Step 2: unbind data/foo → AV emits V2 with canonical marker at foo.
	if _, ok := f.li.Remove("data/foo"); !ok {
		t.Fatal("setup: removing data/foo from li should succeed")
	}
	headAfterDelete, ok := f.head("data/")
	if !ok {
		t.Fatal("no head after delete")
	}
	if headAfterDelete == headAfterBind {
		t.Fatal("head should advance after delete (new version with marker)")
	}
	v2 := f.loadVersion(t, headAfterDelete)
	v2Bindings := tree.CollectAllBindings(f.cs, v2.Root, "")
	markerHash := types.CanonicalDeletionMarkerHash()
	if got := v2Bindings["foo"]; got != markerHash {
		t.Fatalf("V2.trie[data/foo] = %s, want canonical marker %s", got, markerHash)
	}

	// Step 3: live tree should not show data/foo.
	if _, present := f.li.Get("data/foo"); present {
		t.Fatal("data/foo should be unbound in live tree after delete")
	}

	// Step 4: re-bind data/foo → entity_Z.
	hZ := f.putEntity(t, "data/foo", "app/doc", map[string]string{"v": "Z"})
	headAfterRebind, ok := f.head("data/")
	if !ok {
		t.Fatal("no head after re-bind")
	}
	if headAfterRebind == headAfterDelete {
		t.Fatal("head should advance after re-bind")
	}
	v3 := f.loadVersion(t, headAfterRebind)
	v3Bindings := tree.CollectAllBindings(f.cs, v3.Root, "")
	if got := v3Bindings["foo"]; got != hZ {
		t.Fatalf("V3.trie[data/foo] = %s, want entity_Z %s", got, hZ)
	}

	// Step 5: live tree shows entity_Z.
	if got, _ := f.li.Get("data/foo"); got != hZ {
		t.Fatalf("live tree[data/foo] = %s, want entity_Z %s", got, hZ)
	}
}

// TestDeletionRoundtrip_MarkerCarryForward — successive commits after a
// delete carry the marker forward via canonical hash. No new marker entity
// is emitted per commit; content-store dedup means storage is bounded by
// delete events, not delete-times-commits.
func TestDeletionRoundtrip_MarkerCarryForward(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	// Bind, then delete.
	f.putEntity(t, "data/foo", "app/doc", map[string]string{"v": "X"})
	f.li.Remove("data/foo")
	head1, _ := f.head("data/")
	v1 := f.loadVersion(t, head1)

	// Trigger another commit by writing a different path.
	f.putEntity(t, "data/bar", "app/doc", map[string]string{"v": "Y"})
	head2, _ := f.head("data/")
	if head2 == head1 {
		t.Fatal("head should advance after second commit")
	}
	v2 := f.loadVersion(t, head2)

	v1Bindings := tree.CollectAllBindings(f.cs, v1.Root, "")
	v2Bindings := tree.CollectAllBindings(f.cs, v2.Root, "")
	markerHash := types.CanonicalDeletionMarkerHash()

	if got := v2Bindings["foo"]; got != markerHash {
		t.Fatalf("V2 should carry forward marker at data/foo, got %s", got)
	}
	if v1Bindings["foo"] != v2Bindings["foo"] {
		t.Fatalf("marker should carry forward by identical hash; V1=%s V2=%s",
			v1Bindings["foo"], v2Bindings["foo"])
	}
}

// TestDeletionRoundtrip_MergeAppliesMarkerAsUnbind — the apply-phase
// translation across version-transcription. Construct a remote version with
// a marker at a path, invoke the merge handler, verify the live tree path
// is UNBOUND (translated correctly, not bound to the marker hash). This is
// the cross-peer propagation semantic in miniature.
func TestDeletionRoundtrip_MergeAppliesMarkerAsUnbind(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Step 1: live tree has data/foo → entity_X. Commit V_base.
	hX := storeEntity(t, hctx, "data/foo", "app/doc", map[string]string{"v": "X"})
	commitReq := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	commitResp, err := h.Handle(context.Background(), commitReq)
	if err != nil {
		t.Fatalf("commit V_base: %v", err)
	}
	commitResult, err := types.RevisionCommitResultDataFromEntity(commitResp.Result)
	if err != nil {
		t.Fatalf("decode commit result: %v", err)
	}
	vBase := commitResult.Version

	// Step 2: build V_delete with a marker at the path. Simulates a peer
	// that intentionally deleted foo and committed a version.
	if _, err := hctx.Store.Put(types.CanonicalDeletionMarker()); err != nil {
		t.Fatalf("put canonical marker: %v", err)
	}
	markerHash := types.CanonicalDeletionMarkerHash()
	vDeleteRoot, err := tree.BuildTrie(hctx.Store, []tree.Binding{
		{Path: "foo", Hash: markerHash},
	})
	if err != nil {
		t.Fatalf("build V_delete trie: %v", err)
	}
	vDelete := types.RevisionEntryData{
		Root:    vDeleteRoot,
		Parents: tree.SortedParents([]hash.Hash{vBase}),
	}
	vDeleteEnt, _ := vDelete.ToEntity()
	vDeleteHash, _ := hctx.Store.Put(vDeleteEnt)

	// Sanity: data/foo is bound before merge.
	if got, _ := hctx.LocationIndex.Get("data/foo"); got != hX {
		t.Fatalf("setup: live tree[data/foo] = %s, want hX %s", got, hX)
	}

	// Step 3: merge V_delete into local.
	mergeReq := makeRequest(t, hctx, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: vDeleteHash,
	})
	mergeResp, err := h.Handle(context.Background(), mergeReq)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if mergeResp.Status != 200 {
		t.Fatalf("merge status %d", mergeResp.Status)
	}

	// Step 4: live tree should no longer have data/foo (marker → TreeRemove).
	if got, present := hctx.LocationIndex.Get("data/foo"); present {
		t.Fatalf("data/foo should be unbound after marker-bearing merge, live has %s", got)
	}
}

// TestDeletionRoundtrip_NoPhantomMarkersUnderConcurrentPut is the F10 part-7
// regression test. The phantom-marker race fires when a concurrent Put
// triggers AV.fire() while a merge handler is mid-binding-apply. AV reads
// tracker.Root reflecting partial-merge state; emitDeletionMarkers diffs
// against the parent (V_merge with full state) and classifies "still-pending
// merge bindings" as `removed` → phantom markers for paths the merge is
// about to apply.
//
// This test simulates the race directly. With the fix in place (merge
// acquires AV's per-prefix mutex during binding-apply), AV.fire blocks
// until merge completes. By the time AV runs, the live tree is in its
// post-merge full state; the diff produces no phantoms.
//
// Without the fix, this test would intermittently fail with phantom marker
// entries in V_post_merge or in the live tree's location index.
func TestDeletionRoundtrip_NoPhantomMarkersUnderConcurrentPut(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	// Establish baseline: commit a version with one binding so merges have
	// a localHead to chain from.
	f.putEntity(t, "data/seed", "app/doc", map[string]string{"v": "seed"})
	seedHead, ok := f.head("data/")
	if !ok {
		t.Fatal("setup: no head after seed")
	}
	seedVer := f.loadVersion(t, seedHead)

	// Build a "remote" version with paths the merge will apply. This is
	// the V_merge equivalent — represents a peer's view with several new
	// bindings.
	var bindings []tree.Binding
	// Carry forward the seed binding (otherwise merge sees seed as removed).
	seedBindings := tree.CollectAllBindings(f.cs, seedVer.Root, "")
	for path, h := range seedBindings {
		bindings = append(bindings, tree.Binding{Path: path, Hash: h})
	}
	for i := 0; i < 5; i++ {
		h := f.putEntity(t, "", "app/doc", map[string]int{"i": i})
		bindings = append(bindings, tree.Binding{Path: "merge-target-" + string(rune('a'+i)), Hash: h})
	}
	remoteRoot, err := tree.BuildTrie(f.cs, bindings)
	if err != nil {
		t.Fatalf("build remote root: %v", err)
	}
	remoteVer := types.RevisionEntryData{
		Root:    remoteRoot,
		Parents: tree.SortedParents([]hash.Hash{seedHead}),
	}
	remoteEnt, _ := remoteVer.ToEntity()
	remoteHash, _ := f.cs.Put(remoteEnt)

	// Wire a handler with the AV reference (this is what the fix enables).
	mergeH := NewHandler()
	mergeH.SetAutoVersioner(f.av)

	// Build a HandlerContext that uses the fixture's li/cs so the merge
	// writes through the same sync-hook pipeline.
	mergeHctx := newTestContextWithFixture(f)

	// Concurrently fire many Puts during the merge. If the race exists,
	// some AV.fire() call would observe partial state and emit phantoms.
	concurrentDone := make(chan struct{})
	go func() {
		defer close(concurrentDone)
		for i := 0; i < 50; i++ {
			f.putEntity(t, "data/concurrent-"+string(rune('a'+i%26)), "app/doc",
				map[string]int{"i": i})
		}
	}()

	mergeReq := makeRequest(t, mergeHctx, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: remoteHash,
	})
	mergeResp, err := mergeH.Handle(context.Background(), mergeReq)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if mergeResp.Status != 200 {
		t.Fatalf("merge status %d", mergeResp.Status)
	}

	<-concurrentDone

	// Verify no phantom markers in the final head's trie. Walk the head's
	// version trie; assert every entry that's NOT a marker corresponds to a
	// real binding we made, and no marker entries exist for merge-target
	// paths (which were never deleted — just merged in).
	finalHead, _ := f.head("data/")
	markerHash := types.CanonicalDeletionMarkerHash()
	// Walk the version DAG from head; check every version's trie has no
	// merge-target paths bound to the marker.
	visited := make(map[hash.Hash]bool)
	queue := []hash.Hash{finalHead}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur] {
			continue
		}
		visited[cur] = true
		v, ok := loadVersionFromStore(f.cs, cur)
		if !ok {
			continue
		}
		trie := tree.CollectAllBindings(f.cs, v.Root, "")
		for i := 0; i < 5; i++ {
			path := "merge-target-" + string(rune('a'+i))
			if got, ok := trie[path]; ok && got == markerHash {
				t.Fatalf("phantom marker at %s in version %s — race fix failed", path, cur)
			}
		}
		queue = append(queue, v.Parents...)
	}
}

// newTestContextWithFixture builds a HandlerContext sharing the fixture's
// store + location index. Allows merge handler invocations to write through
// the same sync-hook pipeline AV is wired into.
func newTestContextWithFixture(f *autoVersionFixture) *handler.HandlerContext {
	return &handler.HandlerContext{
		Store:          f.cs,
		LocationIndex:  f.li,
		LocalPeerID:    crypto.PeerID(f.nsID),
		HandlerPattern: "system/revision",
		Included:       make(map[hash.Hash]entity.Entity),
	}
}

// TestDeletionRoundtrip_AlreadyUnboundIsNoOp — idempotency: tree:put(P, null)
// when P is already unbound emits no events, no version, no marker. Verifies
// the diff-based emission logic doesn't classify "absent in parent AND
// absent in live" as a deletion.
func TestDeletionRoundtrip_AlreadyUnboundIsNoOp(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	// Establish a baseline commit so we have a parent to compare against.
	f.putEntity(t, "data/foo", "app/doc", map[string]string{"v": "X"})
	headBefore, _ := f.head("data/")

	// Try to "remove" a path that was never bound. Should be a no-op:
	// no version advance, no marker emission.
	if _, ok := f.li.Remove("data/nonexistent"); ok {
		t.Fatal("setup: data/nonexistent shouldn't have been bound")
	}

	headAfter, _ := f.head("data/")
	if headBefore != headAfter {
		t.Fatalf("head shouldn't advance for removing an unbound path; before=%s after=%s",
			headBefore, headAfter)
	}
}
