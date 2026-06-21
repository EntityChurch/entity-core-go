package tree

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// --- Snapshot Tests ---

func TestSnapshotEmptyTree(t *testing.T) {
	h, cs, li, pid := setup(t)
	req := makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{""}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	snap, err := types.SnapshotDataFromEntity(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	// Empty tree still has a root (empty trie node), but no bindings.
	bindings := CollectAllBindings(cs, snap.Root, "")
	if len(bindings) != 0 {
		t.Fatalf("expected 0 bindings, got %d", len(bindings))
	}
}

func TestSnapshotFullTree(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("local/files/a.txt", e1.ContentHash)
	li.Set("local/files/b.txt", e2.ContentHash)

	req := makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{""}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	snap, err := types.SnapshotDataFromEntity(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	bindings := CollectAllBindings(cs, snap.Root, "")
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(bindings))
	}
	if bindings["local/files/a.txt"] != e1.ContentHash {
		t.Fatal("binding a.txt hash mismatch")
	}
	if bindings["local/files/b.txt"] != e2.ContentHash {
		t.Fatal("binding b.txt hash mismatch")
	}
}

func TestSnapshotPrefixFiltering(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("local/files/a.txt", e1.ContentHash)
	li.Set("other/b.txt", e2.ContentHash)

	req := makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{"local/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := types.SnapshotDataFromEntity(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	bindings := CollectAllBindings(cs, snap.Root, "")
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if _, ok := bindings["files/a.txt"]; !ok {
		t.Fatal("expected relative path files/a.txt in bindings")
	}
}

func TestSnapshotInvalidPrefix(t *testing.T) {
	h, cs, li, pid := setup(t)
	req := makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{"no-trailing-slash"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
}

func TestSnapshotDeterminism(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("local/a", e1.ContentHash)
	li.Set("local/b", e2.ContentHash)

	req := makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{""}})
	resp1, _ := h.Handle(context.Background(), req)
	resp2, _ := h.Handle(context.Background(), req)

	if resp1.Result.ContentHash != resp2.Result.ContentHash {
		t.Fatal("same bindings should produce the same snapshot hash")
	}
}

func TestSnapshotCapabilityDenied(t *testing.T) {
	h, cs, li, _ := setup(t)
	kp, _ := crypto.Generate()
	identity, _ := kp.IdentityEntity()

	// Capability that only grants get on "other/*".
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"other/*"}},
			Operations: types.CapabilityScope{Include: []string{"snapshot"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	req := &handler.Request{
		Path:      "system/tree",
		Operation: "snapshot",
		Params:    entity.Entity{},
		Context: &handler.HandlerContext{
			LocalPeerID:      kp.PeerID(),
			Store:            cs,
			LocationIndex:    li,
			HandlerPattern:   "system/tree",
			CallerCapability: capEntity,
			Resource:         &types.ResourceTarget{Targets: []string{"local/files/"}},
		},
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403, got %d", resp.Status)
	}
}

// --- Diff Tests ---

func TestDiffIdenticalSnapshots(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	cs.Put(e1)
	li.Set("local/a", e1.ContentHash)

	// Take snapshot and store it.
	req := makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{""}})
	resp, _ := h.Handle(context.Background(), req)
	snapHash, _ := cs.Put(resp.Result)

	// Diff same snapshot against itself.
	diffReq := types.DiffRequestData{Base: snapHash, Target: snapHash}
	diffEntity, _ := diffReq.ToEntity()
	req = makeRequest(cs, li, pid, "system/tree", "diff", diffEntity, nil)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	diff, err := types.DiffDataFromEntity(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Changed) != 0 {
		t.Fatal("identical snapshots should have no differences")
	}
	if diff.Unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", diff.Unchanged)
	}
}

func TestDiffAddedRemovedChanged(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("local/a", e1.ContentHash)
	li.Set("local/b", e2.ContentHash)

	// Base snapshot.
	req := makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{""}})
	resp, _ := h.Handle(context.Background(), req)
	baseHash, _ := cs.Put(resp.Result)

	// Modify tree: remove a, change b, add c.
	li.Remove("local/a")
	e3 := makeEntity(t, "test/b2", "beta-v2")
	cs.Put(e3)
	li.Set("local/b", e3.ContentHash)
	e4 := makeEntity(t, "test/c", "gamma")
	cs.Put(e4)
	li.Set("local/c", e4.ContentHash)

	// Target snapshot.
	req = makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{""}})
	resp, _ = h.Handle(context.Background(), req)
	targetHash, _ := cs.Put(resp.Result)

	// Diff.
	diffReq := types.DiffRequestData{Base: baseHash, Target: targetHash}
	diffEntity, _ := diffReq.ToEntity()
	req = makeRequest(cs, li, pid, "system/tree", "diff", diffEntity, nil)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	diff, _ := types.DiffDataFromEntity(resp.Result)

	if len(diff.Added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(diff.Added))
	}
	if _, ok := diff.Added["local/c"]; !ok {
		t.Fatal("expected local/c in added")
	}
	if len(diff.Removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(diff.Removed))
	}
	if _, ok := diff.Removed["local/a"]; !ok {
		t.Fatal("expected local/a in removed")
	}
	if len(diff.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(diff.Changed))
	}
	ch, ok := diff.Changed["local/b"]
	if !ok {
		t.Fatal("expected local/b in changed")
	}
	if ch.BaseHash != e2.ContentHash || ch.TargetHash != e3.ContentHash {
		t.Fatal("changed hashes mismatch")
	}
}

func TestDiffSnapshotNotFound(t *testing.T) {
	h, cs, li, pid := setup(t)

	fakeHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	fakeHash.Digest[0] = 0xFF

	diffReq := types.DiffRequestData{Base: fakeHash, Target: fakeHash}
	diffEntity, _ := diffReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "diff", diffEntity, nil)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404, got %d", resp.Status)
	}
}

func TestDiffResolvesFromIncluded(t *testing.T) {
	h, cs, li, pid := setup(t)

	// Create two snapshots without storing them in content store.
	// Build trie roots using BuildTrie so the snapshot Root is correct.
	emptyRoot, _ := BuildTrie(cs, nil)
	snap1 := types.SnapshotData{Root: emptyRoot}
	snap1Entity, _ := snap1.ToEntity()

	e1 := makeEntity(t, "test/a", "alpha")
	oneRoot, _ := BuildTrie(cs, []Binding{{Path: "local/a", Hash: e1.ContentHash}})
	snap2 := types.SnapshotData{Root: oneRoot}
	snap2Entity, _ := snap2.ToEntity()

	// Pass snapshots via included.
	included := map[hash.Hash]entity.Entity{
		snap1Entity.ContentHash: snap1Entity,
		snap2Entity.ContentHash: snap2Entity,
	}

	diffReq := types.DiffRequestData{Base: snap1Entity.ContentHash, Target: snap2Entity.ContentHash}
	diffEntity, _ := diffReq.ToEntity()
	req := &handler.Request{
		Path:      "system/tree",
		Operation: "diff",
		Params:    diffEntity,
		Context: &handler.HandlerContext{
			LocalPeerID:    pid,
			Store:          cs,
			LocationIndex:  li,
			HandlerPattern: "system/tree",
			Included:       included,
		},
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	diff, _ := types.DiffDataFromEntity(resp.Result)
	if len(diff.Added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(diff.Added))
	}
}

// --- Merge Tests ---

func TestMergeNewPathsIntoEmptyTree(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)

	// Create snapshot with bindings via trie.
	root, _ := BuildTrie(cs, []Binding{
		{Path: "local/a", Hash: e1.ContentHash},
		{Path: "local/b", Hash: e2.ContentHash},
	})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	mergeReq := types.MergeRequestData{Source: snapHash}
	mergeEntity, _ := mergeReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	result, _ := types.MergeResultDataFromEntity(resp.Result)
	if result.Applied != 2 {
		t.Fatalf("expected 2 applied, got %d", result.Applied)
	}
	if result.Skipped != 0 {
		t.Fatalf("expected 0 skipped, got %d", result.Skipped)
	}
	if len(result.Conflicts) != 0 {
		t.Fatalf("expected 0 conflicts, got %d", len(result.Conflicts))
	}

	// Verify bindings were applied.
	if h1, ok := li.Get("local/a"); !ok || h1 != e1.ContentHash {
		t.Fatal("local/a not bound correctly")
	}
	if h2, ok := li.Get("local/b"); !ok || h2 != e2.ContentHash {
		t.Fatal("local/b not bound correctly")
	}
}

func TestMergeNoOverwriteConflict(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/a2", "alpha-v2")
	cs.Put(e1)
	cs.Put(e2)

	// Pre-populate with e1.
	li.Set("local/a", e1.ContentHash)

	// Snapshot with different hash for same path.
	root, _ := BuildTrie(cs, []Binding{{Path: "local/a", Hash: e2.ContentHash}})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	mergeReq := types.MergeRequestData{Source: snapHash}
	mergeEntity, _ := mergeReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.MergeResultDataFromEntity(resp.Result)

	if result.Applied != 0 {
		t.Fatalf("expected 0 applied, got %d", result.Applied)
	}
	if result.Skipped != 1 {
		t.Fatalf("expected 1 skipped, got %d", result.Skipped)
	}
	if len(result.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(result.Conflicts))
	}
	c := result.Conflicts["local/a"]
	if c.Resolution != "unresolved" {
		t.Fatalf("expected unresolved, got %s", c.Resolution)
	}

	// Original binding should be unchanged.
	if h1, ok := li.Get("local/a"); !ok || h1 != e1.ContentHash {
		t.Fatal("local/a should still have original hash")
	}
}

func TestMergeSourceWins(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/a2", "alpha-v2")
	cs.Put(e1)
	cs.Put(e2)

	li.Set("local/a", e1.ContentHash)

	root, _ := BuildTrie(cs, []Binding{{Path: "local/a", Hash: e2.ContentHash}})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	boolTrue := true
	mergeReq := types.MergeRequestData{Source: snapHash, Strategy: "source-wins", DryRun: &boolTrue}
	mergeEntity, _ := mergeReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)

	// First with dry_run=true.
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.MergeResultDataFromEntity(resp.Result)
	if result.Applied != 1 {
		t.Fatalf("dry_run: expected 1 applied, got %d", result.Applied)
	}
	if result.Conflicts["local/a"].Resolution != "used-incoming" {
		t.Fatal("dry_run: expected used-incoming resolution")
	}
	// Binding should be unchanged (dry run).
	if h1, _ := li.Get("local/a"); h1 != e1.ContentHash {
		t.Fatal("dry_run should not modify bindings")
	}

	// Now for real.
	boolFalse := false
	mergeReq.DryRun = &boolFalse
	mergeEntity, _ = mergeReq.ToEntity()
	req = makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, _ = h.Handle(context.Background(), req)
	result, _ = types.MergeResultDataFromEntity(resp.Result)
	if result.Applied != 1 {
		t.Fatalf("expected 1 applied, got %d", result.Applied)
	}
	if h1, _ := li.Get("local/a"); h1 != e2.ContentHash {
		t.Fatal("source-wins should overwrite binding")
	}
}

func TestMergeTargetWins(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/a2", "alpha-v2")
	cs.Put(e1)
	cs.Put(e2)

	li.Set("local/a", e1.ContentHash)

	root, _ := BuildTrie(cs, []Binding{{Path: "local/a", Hash: e2.ContentHash}})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	mergeReq := types.MergeRequestData{Source: snapHash, Strategy: "target-wins"}
	mergeEntity, _ := mergeReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.MergeResultDataFromEntity(resp.Result)

	if result.Skipped != 1 {
		t.Fatalf("expected 1 skipped, got %d", result.Skipped)
	}
	c := result.Conflicts["local/a"]
	if c.Resolution != "kept-existing" {
		t.Fatalf("expected kept-existing, got %s", c.Resolution)
	}
	if h1, _ := li.Get("local/a"); h1 != e1.ContentHash {
		t.Fatal("target-wins should keep original binding")
	}
}

func TestMergeIdenticalPathsSkipped(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	cs.Put(e1)
	li.Set("local/a", e1.ContentHash)

	root, _ := BuildTrie(cs, []Binding{{Path: "local/a", Hash: e1.ContentHash}})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	mergeReq := types.MergeRequestData{Source: snapHash}
	mergeEntity, _ := mergeReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.MergeResultDataFromEntity(resp.Result)

	if result.Applied != 0 {
		t.Fatalf("expected 0 applied, got %d", result.Applied)
	}
	if result.Skipped != 1 {
		t.Fatalf("expected 1 skipped, got %d", result.Skipped)
	}
	if len(result.Conflicts) != 0 {
		t.Fatalf("expected 0 conflicts, got %d", len(result.Conflicts))
	}
}

func TestMergePrefixRemap(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	cs.Put(e1)

	root, _ := BuildTrie(cs, []Binding{{Path: "readme.md", Hash: e1.ContentHash}})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	mergeReq := types.MergeRequestData{
		Source:       snapHash,
		SourcePrefix: "alice/files/",
		TargetPrefix: "bob/files/",
	}
	mergeEntity, _ := mergeReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.MergeResultDataFromEntity(resp.Result)

	if result.Applied != 1 {
		t.Fatalf("expected 1 applied, got %d", result.Applied)
	}

	// Verify remapped path.
	if _, ok := li.Get("bob/files/readme.md"); !ok {
		t.Fatal("expected binding at bob/files/readme.md after remap")
	}
}

func TestMergeInvalidStrategy(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	cs.Put(e1)

	root, _ := BuildTrie(cs, []Binding{{Path: "a", Hash: e1.ContentHash}})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	mergeReq := types.MergeRequestData{Source: snapHash, Strategy: "invalid"}
	mergeEntity, _ := mergeReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
}

func TestMergeCapabilityDeniedAtomic(t *testing.T) {
	h, cs, li, _ := setup(t)
	kp, _ := crypto.Generate()
	identity, _ := kp.IdentityEntity()

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)

	// Cap that only allows put on "allowed/*".
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"allowed/*"}},
			Operations: types.CapabilityScope{Include: []string{"merge"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	root, _ := BuildTrie(cs, []Binding{
		{Path: "allowed/a", Hash: e1.ContentHash},
		{Path: "forbidden/b", Hash: e2.ContentHash},
	})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	mergeReq := types.MergeRequestData{Source: snapHash}
	mergeEntity, _ := mergeReq.ToEntity()
	req := &handler.Request{
		Path:      "system/tree",
		Operation: "merge",
		Params:    mergeEntity,
		Context: &handler.HandlerContext{
			LocalPeerID:      kp.PeerID(),
			Store:            cs,
			LocationIndex:    li,
			HandlerPattern:   "system/tree",
			CallerCapability: capEntity,
		},
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403, got %d", resp.Status)
	}
	// No bindings should have been applied (atomic failure).
	if li.Has("allowed/a") {
		t.Fatal("no bindings should be applied on atomic denial")
	}
}

func TestMergeDryRun(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	cs.Put(e1)

	root, _ := BuildTrie(cs, []Binding{{Path: "local/a", Hash: e1.ContentHash}})
	snap := types.SnapshotData{Root: root}
	snapEntity, _ := snap.ToEntity()
	snapHash, _ := cs.Put(snapEntity)

	boolTrue := true
	mergeReq := types.MergeRequestData{Source: snapHash, DryRun: &boolTrue}
	mergeEntity, _ := mergeReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.MergeResultDataFromEntity(resp.Result)

	if result.Applied != 1 {
		t.Fatalf("expected 1 applied, got %d", result.Applied)
	}
	// Binding should NOT be present.
	if li.Has("local/a") {
		t.Fatal("dry_run should not modify bindings")
	}
}

// --- Extract Tests ---

func TestExtractFullPrefix(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("local/files/a.txt", e1.ContentHash)
	li.Set("local/files/b.txt", e2.ContentHash)

	req := makeRequest(cs, li, pid, "system/tree", "extract", entity.Entity{}, &types.ResourceTarget{Targets: []string{"local/files/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	if resp.Result.Type != types.TypeEnvelope {
		t.Fatalf("expected %s, got %s", types.TypeEnvelope, resp.Result.Type)
	}

	// Decode envelope.
	var env entity.Envelope
	if err := ecf.Decode(resp.Result.Data, &env); err != nil {
		t.Fatal(err)
	}
	if env.Root.Type != types.TypeTreeSnapshot {
		t.Fatalf("expected snapshot root, got %s", env.Root.Type)
	}
	snap, _ := types.SnapshotDataFromEntity(env.Root)
	bindings := CollectAllBindings(cs, snap.Root, "")
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(bindings))
	}
	// Included should contain 2 data entities + trie nodes.
	if len(env.Included) < 2 {
		t.Fatalf("expected at least 2 included entities (data + trie nodes), got %d", len(env.Included))
	}
}

func TestExtractPathsFilter(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("local/files/a.txt", e1.ContentHash)
	li.Set("local/files/b.txt", e2.ContentHash)

	extractReq := types.ExtractRequestData{
		Prefix: "local/files/",
		Paths:  []string{"a.txt"},
	}
	extractEntity, _ := extractReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "extract", extractEntity, &types.ResourceTarget{Targets: []string{"local/files/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	var env entity.Envelope
	if err := ecf.Decode(resp.Result.Data, &env); err != nil {
		t.Fatal(err)
	}
	snap, _ := types.SnapshotDataFromEntity(env.Root)
	bindings := CollectAllBindings(cs, snap.Root, "")
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding (filtered), got %d", len(bindings))
	}
	if _, ok := bindings["a.txt"]; !ok {
		t.Fatal("expected a.txt in filtered bindings")
	}
	// Included should contain 1 data entity + trie nodes.
	if len(env.Included) < 1 {
		t.Fatalf("expected at least 1 included entity (data + trie nodes), got %d", len(env.Included))
	}
}

func TestExtractMissingEntities(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	storedHash, _ := cs.Put(e1)
	li.Set("local/a", storedHash)

	// Remove entity from content store but keep binding.
	cs.Remove(storedHash)

	req := makeRequest(cs, li, pid, "system/tree", "extract", entity.Entity{}, &types.ResourceTarget{Targets: []string{"local/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	var env entity.Envelope
	if err := ecf.Decode(resp.Result.Data, &env); err != nil {
		t.Fatal(err)
	}
	snap, _ := types.SnapshotDataFromEntity(env.Root)
	bindings := CollectAllBindings(cs, snap.Root, "")
	if len(bindings) != 1 {
		t.Fatalf("binding should still be present, got %d", len(bindings))
	}
	// Data entity was removed, but trie nodes are still present from BuildTrie.
	// The data entity itself should NOT be in included (it was removed from store).
	if _, hasData := env.Included[storedHash]; hasData {
		t.Fatal("removed data entity should not be in included")
	}
}

func TestExtractInvalidPrefix(t *testing.T) {
	h, cs, li, pid := setup(t)
	req := makeRequest(cs, li, pid, "system/tree", "extract", entity.Entity{}, &types.ResourceTarget{Targets: []string{"no-trailing-slash"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
}

func TestExtractCapabilityDenied(t *testing.T) {
	h, cs, li, _ := setup(t)
	kp, _ := crypto.Generate()
	identity, _ := kp.IdentityEntity()

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"other/*"}},
			Operations: types.CapabilityScope{Include: []string{"extract"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	req := &handler.Request{
		Path:      "system/tree",
		Operation: "extract",
		Params:    entity.Entity{},
		Context: &handler.HandlerContext{
			LocalPeerID:      kp.PeerID(),
			Store:            cs,
			LocationIndex:    li,
			HandlerPattern:   "system/tree",
			CallerCapability: capEntity,
			Resource:         &types.ResourceTarget{Targets: []string{"local/files/"}},
		},
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403, got %d", resp.Status)
	}
}

// --- Round-trip Tests ---

func TestSnapshotDiffRoundTrip(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "alpha")
	cs.Put(e1)
	li.Set("local/a", e1.ContentHash)

	// Snapshot 1.
	req := makeRequest(cs, li, pid, "system/tree", "snapshot", entity.Entity{}, &types.ResourceTarget{Targets: []string{""}})
	resp1, _ := h.Handle(context.Background(), req)
	snap1Hash, _ := cs.Put(resp1.Result)

	// Modify.
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e2)
	li.Set("local/b", e2.ContentHash)

	// Snapshot 2.
	resp2, _ := h.Handle(context.Background(), req)
	snap2Hash, _ := cs.Put(resp2.Result)

	// Diff detects the addition.
	diffReq := types.DiffRequestData{Base: snap1Hash, Target: snap2Hash}
	diffEntity, _ := diffReq.ToEntity()
	req = makeRequest(cs, li, pid, "system/tree", "diff", diffEntity, nil)
	resp, _ := h.Handle(context.Background(), req)
	diff, _ := types.DiffDataFromEntity(resp.Result)

	if len(diff.Added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(diff.Added))
	}
	if diff.Unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", diff.Unchanged)
	}
}

func TestExtractMergeRoundTrip(t *testing.T) {
	h, cs, li, pid := setup(t)

	// Populate source tree.
	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("alice/files/a.txt", e1.ContentHash)
	li.Set("alice/files/b.txt", e2.ContentHash)

	// Extract.
	req := makeRequest(cs, li, pid, "system/tree", "extract", entity.Entity{}, &types.ResourceTarget{Targets: []string{"alice/files/"}})
	resp, _ := h.Handle(context.Background(), req)
	if resp.Status != 200 {
		t.Fatalf("extract: expected 200, got %d", resp.Status)
	}

	// Decode envelope, store snapshot.
	var env entity.Envelope
	ecf.Decode(resp.Result.Data, &env)
	snapHash, _ := cs.Put(env.Root)

	// Clear the tree and merge snapshot into a different prefix.
	li.Remove("alice/files/a.txt")
	li.Remove("alice/files/b.txt")

	mergeReq := types.MergeRequestData{
		Source:       snapHash,
		SourcePrefix: "alice/files/",
		TargetPrefix: "bob/files/",
	}
	mergeEntity, _ := mergeReq.ToEntity()
	req = makeRequest(cs, li, pid, "system/tree", "merge", mergeEntity, nil)
	resp, _ = h.Handle(context.Background(), req)
	result, _ := types.MergeResultDataFromEntity(resp.Result)

	if result.Applied != 2 {
		t.Fatalf("expected 2 applied, got %d", result.Applied)
	}

	// Verify remapped bindings.
	if h1, ok := li.Get("bob/files/a.txt"); !ok || h1 != e1.ContentHash {
		t.Fatal("expected bob/files/a.txt with correct hash")
	}
	if h2, ok := li.Get("bob/files/b.txt"); !ok || h2 != e2.ContentHash {
		t.Fatal("expected bob/files/b.txt with correct hash")
	}
}

// --- Helper Tests ---

func TestValidatePrefix(t *testing.T) {
	tests := []struct {
		prefix string
		valid  bool
	}{
		{"", true},
		{"local/", true},
		{"local/files/", true},
		{"no-slash", false},
		{"/", true},
	}
	for _, tt := range tests {
		if got := validatePrefix(tt.prefix); got != tt.valid {
			t.Errorf("validatePrefix(%q) = %v, want %v", tt.prefix, got, tt.valid)
		}
	}
}

func TestRemap(t *testing.T) {
	tests := []struct {
		fullPath, srcPrefix, tgtPrefix, want string
	}{
		{"alice/files/readme.md", "alice/files/", "bob/files/", "bob/files/readme.md"},
		{"alice/files/readme.md", "", "", "alice/files/readme.md"},
		{"other/path", "alice/files/", "bob/files/", "other/path"},
		{"alice/files/readme.md", "alice/files/", "", "alice/files/readme.md"},
	}
	for _, tt := range tests {
		got := remap(tt.fullPath, tt.srcPrefix, tt.tgtPrefix)
		if got != tt.want {
			t.Errorf("remap(%q, %q, %q) = %q, want %q", tt.fullPath, tt.srcPrefix, tt.tgtPrefix, got, tt.want)
		}
	}
}

// newMemoryStore creates a fresh pair for tests that need isolated stores.
func newMemoryStore() (store.ContentStore, store.LocationIndex) {
	return store.NewMemoryContentStore(), store.NewMemoryLocationIndex()
}

// --- §6.2 since-mode tests ---

// installRevisionHead helps since-mode tests set up a revision-tracked
// prefix without depending on ext/revision. Writes a RevisionEntryData
// with the given trie root + parents, stores it, and binds the LI head
// pointer at the canonical path. Returns the version hash so tests can
// build a DAG of multiple versions.
func installRevisionHead(t *testing.T, cs store.ContentStore, li store.LocationIndex, prefix string, root hash.Hash, parents []hash.Hash) hash.Hash {
	t.Helper()
	rev := types.RevisionEntryData{Root: root, Parents: parents}
	ent, err := rev.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	versionHash, err := cs.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	if err := li.Set(revisionHeadPath(prefix), versionHash); err != nil {
		t.Fatal(err)
	}
	return versionHash
}

// TestExtractSince_ConflictingFilters — §6.1 mutual exclusivity: paths
// and since cannot both be set.
func TestExtractSince_ConflictingFilters(t *testing.T) {
	h, cs, li, pid := setup(t)
	e := makeEntity(t, "test/x", "data")
	cs.Put(e)
	li.Set("files/x.txt", e.ContentHash)

	bogusSince := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	bogusSince.Digest[0] = 0xab

	extractReq := types.ExtractRequestData{
		Prefix: "files/",
		Paths:  []string{"x.txt"},
		Since:  bogusSince,
	}
	extractEntity, _ := extractReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "extract", extractEntity,
		&types.ResourceTarget{Targets: []string{"files/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "conflicting_filters" {
		t.Fatalf("expected conflicting_filters, got %q", errData.Code)
	}
}

// TestExtractSince_NotFound — §6.2a: since hash isn't resolvable in the
// content store.
func TestExtractSince_NotFound(t *testing.T) {
	h, cs, li, pid := setup(t)
	e := makeEntity(t, "test/x", "data")
	cs.Put(e)
	li.Set("files/x.txt", e.ContentHash)

	// Install a revision head so resolveCurrentTrieRoot finds the
	// canonical root; otherwise the materialize fallback would still
	// work but the since-not-found check fires later regardless.
	trieRoot, _ := BuildTrie(cs, []Binding{{Path: "x.txt", Hash: e.ContentHash}})
	installRevisionHead(t, cs, li, "/"+string(pid)+"/files/", trieRoot, nil)

	bogusSince := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	bogusSince.Digest[0] = 0xab

	extractReq := types.ExtractRequestData{Prefix: "files/", Since: bogusSince}
	extractEntity, _ := extractReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "extract", extractEntity,
		&types.ResourceTarget{Targets: []string{"files/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "since_not_found" {
		t.Fatalf("expected since_not_found, got %q", errData.Code)
	}
}

// TestExtractSince_ScopeMismatch — §6.2b MUST clause: since's scope
// must match the extract prefix. A trie root from a foreign prefix's
// DAG is rejected with 400 scope_mismatch.
func TestExtractSince_ScopeMismatch(t *testing.T) {
	h, cs, li, pid := setup(t)

	// Two distinct prefixes with distinct revision DAGs.
	eA := makeEntity(t, "test/a", "alpha")
	eB := makeEntity(t, "test/b", "beta")
	cs.Put(eA)
	cs.Put(eB)
	li.Set("foo/a.txt", eA.ContentHash)
	li.Set("bar/b.txt", eB.ContentHash)

	rootFoo, _ := BuildTrie(cs, []Binding{{Path: "a.txt", Hash: eA.ContentHash}})
	rootBar, _ := BuildTrie(cs, []Binding{{Path: "b.txt", Hash: eB.ContentHash}})

	// Make `foo/` revision-tracked. Don't track `bar/`.
	installRevisionHead(t, cs, li, "/"+string(pid)+"/foo/", rootFoo, nil)

	// Caller passes bar's root as `since` on an extract of `foo/`. Bar's
	// root is in the content store (legitimately — its bindings live
	// here) so the since_not_found check passes; the scope_matches walk
	// finds rootBar nowhere in foo's DAG → scope_mismatch.
	extractReq := types.ExtractRequestData{Prefix: "foo/", Since: rootBar}
	extractEntity, _ := extractReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "extract", extractEntity,
		&types.ResourceTarget{Targets: []string{"foo/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d, msg=%s", resp.Status, string(resp.Result.Data))
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "scope_mismatch" {
		t.Fatalf("expected scope_mismatch, got %q", errData.Code)
	}
}

// TestExtractSince_RevisionTrackedFastPath — §6.2a canonical resolution:
// when prefix has a revision head, the impl reads the committed root
// O(1) and the since-mode envelope bundles only the changed closure
// without rebuilding the trie from live bindings. Validates correctness
// of the canonical path (the scale claim is a property of the impl
// shape, not directly measurable here).
func TestExtractSince_RevisionTrackedFastPath(t *testing.T) {
	h, cs, li, pid := setup(t)

	// Build V1: two leaves under proj/.
	e1 := makeEntity(t, "test/n", "v1 a")
	e2 := makeEntity(t, "test/n", "v1 b")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("proj/a.txt", e1.ContentHash)
	li.Set("proj/b.txt", e2.ContentHash)
	rootV1, _ := BuildTrie(cs, []Binding{
		{Path: "a.txt", Hash: e1.ContentHash},
		{Path: "b.txt", Hash: e2.ContentHash},
	})
	v1Hash := installRevisionHead(t, cs, li, "/"+string(pid)+"/proj/", rootV1, nil)

	// Advance to V2: a.txt updated, b.txt unchanged.
	e1new := makeEntity(t, "test/n", "v2 a")
	cs.Put(e1new)
	li.Set("proj/a.txt", e1new.ContentHash)
	rootV2, _ := BuildTrie(cs, []Binding{
		{Path: "a.txt", Hash: e1new.ContentHash},
		{Path: "b.txt", Hash: e2.ContentHash},
	})
	installRevisionHead(t, cs, li, "/"+string(pid)+"/proj/", rootV2, []hash.Hash{v1Hash})

	// extract(since=rootV1) — the §6.2a fast path. Should resolve the
	// current root via the head pointer (now V2), validate scope
	// (rootV1 is in V2's parent DAG), and bundle only the V1→V2 delta.
	extractReq := types.ExtractRequestData{Prefix: "proj/", Since: rootV1}
	extractEntity, _ := extractReq.ToEntity()
	req := makeRequest(cs, li, pid, "system/tree", "extract", extractEntity,
		&types.ResourceTarget{Targets: []string{"proj/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		errData, _ := types.ErrorDataFromEntity(resp.Result)
		t.Fatalf("expected 200, got %d (%q)", resp.Status, errData.Code)
	}

	var env entity.Envelope
	if err := ecf.Decode(resp.Result.Data, &env); err != nil {
		t.Fatal(err)
	}
	if env.Root.Type != types.TypeTreeSnapshot {
		t.Fatalf("expected snapshot root, got %s", env.Root.Type)
	}
	snap, _ := types.SnapshotDataFromEntity(env.Root)
	if snap.Root != rootV2 {
		t.Fatalf("envelope snapshot Root = %s, want V2 root %s", snap.Root, rootV2)
	}
	// The since-mode envelope should be SMALLER than a full extract
	// (only changed-branch closure). For this 2-leaf workspace with
	// one changed leaf, the unchanged b-leaf's trie node + data
	// entity share content-addressed hashes with V1 and are skipped;
	// included = V2 root node + V2's a-leaf trie node + a-leaf data
	// entity. A full extract would bundle all 5.
	if len(env.Included) >= 5 {
		t.Fatalf("since-mode envelope included %d entities; expected fewer than the 5 a full extract would bundle", len(env.Included))
	}
	if _, ok := env.Included[e1new.ContentHash]; !ok {
		t.Errorf("since-mode envelope missing the changed leaf's data entity")
	}
	if _, ok := env.Included[e2.ContentHash]; ok {
		t.Errorf("since-mode envelope contains b-leaf's data entity (should be skipped — unchanged)")
	}
}
