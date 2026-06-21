package revision

import (
	"context"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// unwrapEnvelope decodes a system/envelope entity response, returning the inner
// root entity and included map. Used by tests to adapt to the envelope result pattern.
func unwrapEnvelope(t *testing.T, resp *handler.Response) (entity.Entity, map[hash.Hash]entity.Entity) {
	t.Helper()
	if resp.Result.Type != "system/envelope" {
		t.Fatalf("expected system/envelope result, got %s", resp.Result.Type)
	}
	var env entity.Envelope
	if err := ecf.Decode(resp.Result.Data, &env); err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}
	return env.Root, env.Included
}

func newTestContext() *handler.HandlerContext {
	kp, _ := crypto.Generate()
	rawLI := store.NewMemoryLocationIndex()
	nsLI := store.NewNamespacedIndex(rawLI, string(kp.PeerID()))
	return &handler.HandlerContext{
		Store:          store.NewMemoryContentStore(),
		LocationIndex:  nsLI,
		LocalPeerID:    kp.PeerID(),
		HandlerPattern: "system/revision",
		Included:       make(map[hash.Hash]entity.Entity),
	}
}

// testPH computes the prefix hash for a peer-relative prefix in a test context.
func testPH(hctx *handler.HandlerContext, prefix string) string {
	return PrefixHash(resolvePrefix(prefix, string(hctx.LocalPeerID)))
}

// storeEntity stores an entity at a path, returning its hash.
func storeEntity(t *testing.T, hctx *handler.HandlerContext, path, typeName string, data interface{}) hash.Hash {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	ent, err := entity.NewEntity(typeName, cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	h, err := hctx.Store.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		hctx.LocationIndex.Set(path, h)
	}
	return h
}

func makeRequest(t *testing.T, hctx *handler.HandlerContext, operation string, params interface{}) *handler.Request {
	t.Helper()
	raw, err := ecf.Encode(params)
	if err != nil {
		t.Fatal(err)
	}
	paramsEntity, err := entity.NewEntity("system/revision/"+operation+"-params", cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return &handler.Request{
		Operation: operation,
		Params:    paramsEntity,
		Context:   hctx,
	}
}

// --- Phase 1 Tests ---

func TestCommit_Initial(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Put some data in the tree.
	storeEntity(t, hctx, "data/file1", "test/document", map[string]string{"content": "hello"})
	storeEntity(t, hctx, "data/file2", "test/document", map[string]string{"content": "world"})

	// Commit.
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{
		Prefix: "data/",
	})

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	// Decode result.
	result, err := types.RevisionCommitResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatal(err)
	}

	if result.Version.IsZero() {
		t.Fatal("version hash is zero")
	}
	if result.Root.IsZero() {
		t.Fatal("root hash is zero")
	}

	// Verify head was set.
	headHash, ok := hctx.LocationIndex.Get(headPath(testPH(hctx, "data/")))
	if !ok {
		t.Fatal("head not set")
	}
	if headHash != result.Version {
		t.Fatal("head doesn't match version")
	}

	// Verify version entity.
	ver, ok := loadVersion(hctx, result.Version)
	if !ok {
		t.Fatal("version entity not in store")
	}
	if ver.Root.IsZero() {
		t.Fatal("version root hash is zero")
	}
	if len(ver.Parents) != 0 {
		t.Fatalf("initial commit should have 0 parents, got %d", len(ver.Parents))
	}

	// Verify tree contents via location index: both files should still be present.
	if _, ok := hctx.LocationIndex.Get("data/file1"); !ok {
		t.Fatal("file1 should still be in the tree")
	}
	if _, ok := hctx.LocationIndex.Get("data/file2"); !ok {
		t.Fatal("file2 should still be in the tree")
	}
}

func TestCommit_Sequential(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	storeEntity(t, hctx, "data/file1", "test/document", map[string]string{"content": "v1"})

	// First commit.
	req1 := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp1, err := h.Handle(context.Background(), req1)
	if err != nil {
		t.Fatal(err)
	}
	result1, _ := types.RevisionCommitResultDataFromEntity(resp1.Result)

	// Modify and second commit.
	storeEntity(t, hctx, "data/file1", "test/document", map[string]string{"content": "v2"})
	req2 := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp2, err := h.Handle(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	result2, _ := types.RevisionCommitResultDataFromEntity(resp2.Result)

	// Second commit should have first as parent.
	ver2, _ := loadVersion(hctx, result2.Version)
	if len(ver2.Parents) != 1 {
		t.Fatalf("expected 1 parent, got %d", len(ver2.Parents))
	}
	if ver2.Parents[0] != result1.Version {
		t.Fatal("parent should be first version")
	}
}

func TestLog_Empty(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	req := makeRequest(t, hctx, "log", types.RevisionLogParamsData{Prefix: "data/"})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	root, _ := unwrapEnvelope(t, resp)
	result, _ := types.RevisionLogResultDataFromEntity(root)
	if len(result.Versions) != 0 {
		t.Fatalf("expected 0 versions, got %d", len(result.Versions))
	}
	if result.HasMore {
		t.Fatal("should not have more")
	}
}

func TestLog_ReturnsVersions(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create 3 sequential commits.
	var versionHashes []hash.Hash
	for i := 0; i < 3; i++ {
		storeEntity(t, hctx, "data/file", "test/document", map[string]interface{}{"v": i})
		req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
		resp, _ := h.Handle(context.Background(), req)
		result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)
		versionHashes = append(versionHashes, result.Version)
	}

	// Log should return all 3, newest first (BFS from head).
	req := makeRequest(t, hctx, "log", types.RevisionLogParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)

	root, included := unwrapEnvelope(t, resp)
	result, _ := types.RevisionLogResultDataFromEntity(root)
	if len(result.Versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(result.Versions))
	}
	// First should be most recent.
	if result.Versions[0] != versionHashes[2] {
		t.Fatal("first version should be most recent")
	}

	// Included should contain version entities.
	if len(included) != 3 {
		t.Fatalf("expected 3 included entities, got %d", len(included))
	}
}

func TestLog_Limit(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	for i := 0; i < 5; i++ {
		storeEntity(t, hctx, "data/file", "test/document", map[string]interface{}{"v": i})
		req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
		h.Handle(context.Background(), req)
	}

	limit := uint64(2)
	req := makeRequest(t, hctx, "log", types.RevisionLogParamsData{Prefix: "data/", Limit: &limit})
	resp, _ := h.Handle(context.Background(), req)

	root, _ := unwrapEnvelope(t, resp)
	result, _ := types.RevisionLogResultDataFromEntity(root)
	if len(result.Versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(result.Versions))
	}
	if !result.HasMore {
		t.Fatal("should have more")
	}
}

func TestStatus(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Status before any commits.
	req := makeRequest(t, hctx, "status", types.RevisionStatusParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)

	status, _ := types.RevisionStatusDataFromEntity(resp.Result)
	if !status.Head.IsZero() {
		t.Fatal("head should be zero before first commit")
	}
	if status.Conflicts != 0 {
		t.Fatalf("expected 0 conflicts, got %d", status.Conflicts)
	}

	// Commit and check status.
	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"content": "v1"})
	commitReq := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	commitResp, _ := h.Handle(context.Background(), commitReq)
	commitResult, _ := types.RevisionCommitResultDataFromEntity(commitResp.Result)

	req = makeRequest(t, hctx, "status", types.RevisionStatusParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	status, _ = types.RevisionStatusDataFromEntity(resp.Result)

	if status.Head != commitResult.Version {
		t.Fatal("head should match committed version")
	}
}

func TestFindAncestor_Linear(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create linear chain: v1 -> v2 -> v3.
	var versions []hash.Hash
	for i := 0; i < 3; i++ {
		storeEntity(t, hctx, "data/file", "test/document", map[string]interface{}{"v": i})
		req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
		resp, _ := h.Handle(context.Background(), req)
		result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)
		versions = append(versions, result.Version)
	}

	// Ancestor of v2 and v3 should be v2.
	req := makeRequest(t, hctx, "find-ancestor", types.RevisionAncestorParamsData{
		VersionA: versions[1],
		VersionB: versions[2],
	})
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.RevisionAncestorResultDataFromEntity(resp.Result)

	if result.Ancestor != versions[1] {
		t.Fatal("ancestor should be v2")
	}

	// Ancestor of v1 and v3 should be v1.
	req = makeRequest(t, hctx, "find-ancestor", types.RevisionAncestorParamsData{
		VersionA: versions[0],
		VersionB: versions[2],
	})
	resp, _ = h.Handle(context.Background(), req)
	result, _ = types.RevisionAncestorResultDataFromEntity(resp.Result)

	if result.Ancestor != versions[0] {
		t.Fatal("ancestor should be v1")
	}
}

func TestFindAncestor_Same(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"x": "y"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Ancestor of same version is itself.
	req = makeRequest(t, hctx, "find-ancestor", types.RevisionAncestorParamsData{
		VersionA: result.Version,
		VersionB: result.Version,
	})
	resp, _ = h.Handle(context.Background(), req)
	ancestorResult, _ := types.RevisionAncestorResultDataFromEntity(resp.Result)

	if ancestorResult.Ancestor != result.Version {
		t.Fatal("ancestor of same version should be itself")
	}
}

// --- Phase 2 Tests ---

func TestMerge_AlreadyInSync(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"x": "y"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Merge with itself.
	req = makeRequest(t, hctx, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: result.Version,
	})
	resp, _ = h.Handle(context.Background(), req)
	mergeResult, _ := types.RevisionMergeResultDataFromEntity(resp.Result)

	if mergeResult.Status != "already_in_sync" {
		t.Fatalf("expected already_in_sync, got %s", mergeResult.Status)
	}
}

func TestMerge_FastForward(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create v1.
	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"content": "v1"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	v1Result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Create v2 (builds on v1).
	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"content": "v2"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	v2Result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Reset head to v1.
	hctx.LocationIndex.Set(headPath(testPH(hctx, "data/")), v1Result.Version)

	// Merge with v2 should fast-forward.
	req = makeRequest(t, hctx, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: v2Result.Version,
	})
	resp, _ = h.Handle(context.Background(), req)
	mergeResult, _ := types.RevisionMergeResultDataFromEntity(resp.Result)

	if mergeResult.Status != "fast_forward" {
		t.Fatalf("expected fast_forward, got %s", mergeResult.Status)
	}
	if mergeResult.Version != v2Result.Version {
		t.Fatal("version should match remote version")
	}
}

// TestMerge_FastForward_StaleLocalHead_ReturnsRetry is the F10 part-5
// regression test for fastForward's CAS on head. If localHead was advanced
// concurrently (typical: AutoVersioner CAS'd a fresh emit between the merge
// handler's localHead read and its head write), fastForward must NOT
// silently overwrite that emit — it must detect the stale localHead and
// return a retry status. The converge handler picks up on the next
// notification with the new head.
//
// Without this guard, AV's emit would be orphaned and the in-flight write
// captured by that emit would be lost from the version DAG (F10 part-4's
// AV-side fix had a symmetric residual on the merge side). See
// the F10 postmortem.
func TestMerge_FastForward_StaleLocalHead_ReturnsRetry(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Commit V1 (the version we'll pretend was "our localHead at merge start").
	storeEntity(t, hctx, "data/base", "test/document", map[string]string{"v": "base"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	v1Result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)
	v1Hash := v1Result.Version

	// Commit V2 (will be the merge target — fast-forward case).
	storeEntity(t, hctx, "data/extra", "test/document", map[string]string{"v": "extra"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	v2Result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Simulate the race: between the merge handler's read of localHead=V1
	// and its head CAS, "AutoVersioner" (modeled here by directly running
	// CAS) advances head to V_external. The next merge attempt will see
	// head=V_external and its localHead=V1 will be stale.
	externalRoot, _ := tree.BuildTrie(hctx.Store, []tree.Binding{
		{Path: "spurious", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0x77})}},
	})
	externalVer := types.RevisionEntryData{
		Root:    externalRoot,
		Parents: tree.SortedParents([]hash.Hash{v1Hash}),
	}
	externalEnt, _ := externalVer.ToEntity()
	externalHash, _ := hctx.Store.Put(externalEnt)
	if err := hctx.LocationIndex.CompareAndSwap(headPath(testPH(hctx, "data/")), v2Result.Version, externalHash); err != nil {
		// Head wasn't at V2; that's because TestCommit_Sequential's auto-version
		// behavior in newTestContext doesn't apply. Find the actual current head.
		t.Fatalf("setup CAS failed: %v", err)
	}

	// Issue a merge with remote=V2 — fastForward should see localHead has
	// already been advanced to externalHash and refuse to overwrite, returning
	// stale_local_head_retry.
	//
	// Force the merge handler to read localHead from the index. We can't
	// inject a stale localHead value into handleMerge; instead we rely on
	// the fact that V_external is the current head, so fastForward against
	// V2 will succeed normally (V2 is an ancestor of V_external or unrelated).
	//
	// The test we CAN exercise directly: call fastForward with an explicitly
	// stale localHead, and assert it returns the retry status.
	revHandler := h
	revHandler.mu.Lock()
	defer revHandler.mu.Unlock()
	resp, _ = revHandler.fastForward(hctx, types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: v2Result.Version,
	}, v1Hash, v2Result.Version) // explicitly pass stale localHead=v1Hash

	mergeResult, _ := types.RevisionMergeResultDataFromEntity(resp.Result)
	if mergeResult.Status != "stale_local_head_retry" {
		t.Fatalf("expected stale_local_head_retry, got %q (head was concurrently advanced to externalHash)",
			mergeResult.Status)
	}

	// Head was NOT overwritten by fastForward — externalHash survives.
	currentHead, _ := hctx.LocationIndex.Get(headPath(testPH(hctx, "data/")))
	if currentHead != externalHash {
		t.Fatalf("fastForward overwrote the externally-advanced head despite stale localHead; got %s, want %s",
			currentHead, externalHash)
	}
}

// TestMerge_FastForward_PreservesInFlightWrites is the F10 regression test.
// Reproduces the bidirectional-burst data-loss mechanism in a single-peer,
// in-process fixture per the workbench team's F10 follow-up suggestion.
//
// Setup: a committed version V_remote that does NOT include the path
// "data/in-flight" — analogue of the remote peer's revision before alice's
// burst write landed. Then bind "data/in-flight" in the LIVE tree to
// represent an in-flight write that auto-version hasn't captured yet.
//
// Expected: fast-forward merge advances head to V_remote and preserves the
// in-flight binding. Previously fastForward computed `currentRoot` from the
// live tree, classified "data/in-flight" as `removed` in TrieDiff, and
// physically wiped it via TreeRemove. The version-transcription invariant
// (PROPOSAL-PRODUCTION-READINESS-AMENDMENTS A.3) forbids that wipe.
func TestMerge_FastForward_PreservesInFlightWrites(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Commit V_base with one file. Tree state matches V_base after commit.
	storeEntity(t, hctx, "data/base", "test/document", map[string]string{"content": "base"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	baseResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Commit V_remote (adds data/remote). Tree state matches V_remote.
	storeEntity(t, hctx, "data/remote", "test/document", map[string]string{"content": "remote"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	remoteResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Rewind head to V_base — this is the simulated "alice was here, then
	// pulled bob's V_remote" state. data/remote was committed so still in
	// the live tree, but head is back at V_base; relationship to V_remote
	// will be "behind" → fastForward will run.
	ph := testPH(hctx, "data/")
	hctx.LocationIndex.Set(headPath(ph), baseResult.Version)

	// Drop data/remote from the live tree — that's a remote write we don't
	// have locally yet (we're behind). data/remote is in V_remote's trie
	// but not in V_base's trie nor in our current live tree.
	hctx.LocationIndex.Remove("data/remote")

	// Land an IN-FLIGHT write into the live tree at "data/in-flight". This
	// represents alice's localfiles watcher binding a path before
	// auto-version emits a version for it. The binding exists in the
	// location index but is in NEITHER V_base's trie NOR V_remote's trie.
	inFlightHash := storeEntity(t, hctx, "data/in-flight", "test/document",
		map[string]string{"content": "in-flight write"})

	// Sanity: in-flight binding is present pre-merge.
	if got, ok := hctx.LocationIndex.Get("data/in-flight"); !ok || got != inFlightHash {
		t.Fatalf("setup broken: in-flight binding not present pre-merge")
	}

	// Merge V_remote. Relationship "behind" → fastForward.
	req = makeRequest(t, hctx, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: remoteResult.Version,
	})
	resp, _ = h.Handle(context.Background(), req)
	mergeResult, _ := types.RevisionMergeResultDataFromEntity(resp.Result)

	if mergeResult.Status != "fast_forward" {
		t.Fatalf("expected fast_forward, got %s", mergeResult.Status)
	}

	// V_remote's contents propagated.
	if _, ok := hctx.LocationIndex.Get("data/remote"); !ok {
		t.Fatalf("V_remote's data/remote not propagated by fast-forward")
	}

	// THE REGRESSION ASSERTION: in-flight write survived.
	if got, ok := hctx.LocationIndex.Get("data/in-flight"); !ok {
		t.Fatalf("in-flight write at data/in-flight was wiped by fast-forward — F10 regression")
	} else if got != inFlightHash {
		t.Fatalf("in-flight binding hash changed: got %s, want %s", got, inFlightHash)
	}
}

// TestMerge_FastForward_NoLocalHead_PreservesLiveTree exercises the empty-trie
// fallback path: first-ever merge into a prefix with no prior local head must
// also preserve live-tree paths not present in the remote version. Without
// the empty-trie fallback, this would either panic or fall back to live-tree
// diffing — both wrong per the version-transcription invariant.
func TestMerge_FastForward_NoLocalHead_PreservesLiveTree(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Build a remote version in a parallel "remote" prefix.
	storeEntity(t, hctx, "remote-data/file", "test/document", map[string]string{"content": "remote"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "remote-data/"})
	resp, _ := h.Handle(context.Background(), req)
	remoteResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Pre-bind a live-tree path under the merge target prefix BEFORE any
	// merge has run. No local head exists for the target prefix.
	inFlightHash := storeEntity(t, hctx, "data/in-flight", "test/document",
		map[string]string{"content": "pre-existing live-tree binding"})

	// Merge V_remote into the target prefix (no prior head → fastForward via
	// the !hasLocalHead branch, empty-trie fallback path).
	req = makeRequest(t, hctx, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: remoteResult.Version,
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("merge returned status %d", resp.Status)
	}

	// In-flight path survives.
	if got, ok := hctx.LocationIndex.Get("data/in-flight"); !ok {
		t.Fatalf("live-tree path data/in-flight wiped by no-local-head fast-forward — F10 regression")
	} else if got != inFlightHash {
		t.Fatalf("in-flight binding hash changed: got %s, want %s", got, inFlightHash)
	}
}

// TestCheckout_PreservesInFlightWrites is the sibling-bug regression test for
// checkout (CORE-GO-F10-DIAGNOSIS-CONFIRMED §2). Same shape as the fast-forward
// case: in-flight live-tree bindings must survive a checkout to a version that
// doesn't include them.
func TestCheckout_PreservesInFlightWrites(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Commit V_a with file_a.
	storeEntity(t, hctx, "data/file_a", "test/document", map[string]string{"content": "a"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	aResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Commit V_b (replaces file_a with file_b).
	hctx.LocationIndex.Remove("data/file_a")
	storeEntity(t, hctx, "data/file_b", "test/document", map[string]string{"content": "b"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	bResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)
	_ = bResult

	// Land an in-flight write — not in V_a's trie, not in V_b's trie.
	inFlightHash := storeEntity(t, hctx, "data/in-flight", "test/document",
		map[string]string{"content": "in-flight"})

	// Checkout V_a. Without the fix, the live-tree diff would see
	// data/in-flight as "in live but not in V_a → remove" and wipe it.
	req = makeRequest(t, hctx, "checkout", types.RevisionCheckoutParamsData{
		Prefix:  "data/",
		Version: aResult.Version,
	})
	resp, _ = h.Handle(context.Background(), req)
	if resp.Status != 200 {
		t.Fatalf("checkout returned status %d", resp.Status)
	}

	// V_a's contents are present.
	if _, ok := hctx.LocationIndex.Get("data/file_a"); !ok {
		t.Fatalf("V_a's data/file_a not applied by checkout")
	}
	// V_b's file_b is gone (it was in source V_b's trie but not in target V_a's — legitimate remove).
	if _, ok := hctx.LocationIndex.Get("data/file_b"); ok {
		t.Fatalf("V_b's data/file_b should be removed by checkout to V_a")
	}

	// THE REGRESSION ASSERTION: in-flight write survived.
	if got, ok := hctx.LocationIndex.Get("data/in-flight"); !ok {
		t.Fatalf("in-flight write at data/in-flight was wiped by checkout — F10 sibling regression")
	} else if got != inFlightHash {
		t.Fatalf("in-flight binding hash changed: got %s, want %s", got, inFlightHash)
	}
}

func TestMerge_Diverged_Clean(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create base commit with shared file.
	storeEntity(t, hctx, "data/shared", "test/document", map[string]string{"content": "base"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	baseResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Create "local" branch: add local_file.
	storeEntity(t, hctx, "data/local_file", "test/document", map[string]string{"content": "local"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	localResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Create "remote" branch: reset to base and add remote_file.
	hctx.LocationIndex.Set(headPath(testPH(hctx, "data/")), baseResult.Version)
	hctx.LocationIndex.Remove("data/local_file")
	storeEntity(t, hctx, "data/remote_file", "test/document", map[string]string{"content": "remote"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	remoteResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Reset head to local and restore local tree state from trie.
	hctx.LocationIndex.Set(headPath(testPH(hctx, "data/")), localResult.Version)
	localVer, _ := loadVersion(hctx, localResult.Version)
	localBindings := trieToBindings(hctx.Store, localVer.Root)
	for p, bindHash := range localBindings {
		hctx.LocationIndex.Set("data/"+p, bindHash)
	}
	// Remove remote_file since we're on the local branch.
	hctx.LocationIndex.Remove("data/remote_file")

	// Merge remote into local.
	req = makeRequest(t, hctx, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: remoteResult.Version,
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	mergeResult, _ := types.RevisionMergeResultDataFromEntity(resp.Result)

	if mergeResult.Status != "merged" {
		t.Fatalf("expected merged, got %s", mergeResult.Status)
	}
	if len(mergeResult.Conflicts) != 0 {
		t.Fatalf("expected 0 conflicts, got %d", len(mergeResult.Conflicts))
	}

	// Verify merge version has two parents.
	mergeVer, _ := loadVersion(hctx, mergeResult.Version)
	if len(mergeVer.Parents) != 2 {
		t.Fatalf("merge version should have 2 parents, got %d", len(mergeVer.Parents))
	}
}

func TestResolve(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Manually create a conflict.
	conflict := types.RevisionConflictData{
		Path:     "file1",
		Strategy: "three-way",
	}
	conflictEntity, _ := conflict.ToEntity()
	conflictHash, _ := hctx.Store.Put(conflictEntity)
	hctx.LocationIndex.Set(conflictPath(testPH(hctx, "data/"), "file1"), conflictHash)

	// Create resolved entity.
	resolvedHash := storeEntity(t, hctx, "", "test/document", map[string]string{"content": "resolved"})

	req := makeRequest(t, hctx, "resolve", types.RevisionResolveParamsData{
		Prefix:   "data/",
		Path:     "file1",
		Resolved: &resolvedHash,
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	// Conflict should be removed.
	if _, ok := hctx.LocationIndex.Get(conflictPath(testPH(hctx, "data/"), "file1")); ok {
		t.Fatal("conflict should be removed")
	}

	// Resolved entity should be at original path.
	boundHash, ok := hctx.LocationIndex.Get("data/file1")
	if !ok {
		t.Fatal("resolved entity not bound")
	}
	if boundHash != resolvedHash {
		t.Fatal("bound hash doesn't match resolved hash")
	}
}

func TestMergeStrategy_SourceWins(t *testing.T) {
	cs := store.NewMemoryContentStore()
	localHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "local"})
	remoteHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "remote"})
	baseHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "base"})

	result := applyMergeStrategy(cs, strategySourceWins, "test/path", baseHash, localHash, remoteHash)
	if !result.resolved {
		t.Fatal("source-wins should resolve")
	}
	if result.hash != remoteHash {
		t.Fatal("source-wins should return remote hash")
	}
}

func TestMergeStrategy_TargetWins(t *testing.T) {
	cs := store.NewMemoryContentStore()
	localHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "local"})
	remoteHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "remote"})
	baseHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "base"})

	result := applyMergeStrategy(cs, strategyTargetWins, "test/path", baseHash, localHash, remoteHash)
	if !result.resolved {
		t.Fatal("target-wins should resolve")
	}
	if result.hash != localHash {
		t.Fatal("target-wins should return local hash")
	}
}

func TestMergeStrategy_KeepBoth(t *testing.T) {
	cs := store.NewMemoryContentStore()
	localHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "local"})
	remoteHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "remote"})
	baseHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "base"})

	result := applyMergeStrategy(cs, strategyKeepBoth, "docs/readme", baseHash, localHash, remoteHash)
	if !result.resolved {
		t.Fatal("keep-both should resolve for edit-vs-edit")
	}
	if result.hash != localHash {
		t.Fatal("keep-both should place local at original path")
	}
	if len(result.additionalBindings) != 1 {
		t.Fatalf("keep-both should produce 1 additional binding, got %d", len(result.additionalBindings))
	}
	ab := result.additionalBindings[0]
	if ab.Hash != remoteHash {
		t.Fatal("additional binding should reference remote hash")
	}
	if !strings.HasPrefix(ab.Path, "docs/readme.keep-both-") {
		t.Fatalf("additional binding path should have keep-both prefix, got %s", ab.Path)
	}
	if len(ab.Path) != len("docs/readme.keep-both-")+8 {
		t.Fatalf("additional binding path should have 8-char hex suffix, got %s", ab.Path)
	}
}

func TestMergeStrategy_KeepBoth_DeleteVsEdit(t *testing.T) {
	cs := store.NewMemoryContentStore()
	localHash := storeTestEntity(t, cs, "test/doc", map[string]string{"x": "local"})

	result := applyMergeStrategy(cs, strategyKeepBoth, "test/path", hash.Hash{}, localHash, hash.Hash{})
	if result.resolved {
		t.Fatal("keep-both should not resolve for delete-vs-edit")
	}
}

func TestMergeStrategy_ThreeWay_Clean(t *testing.T) {
	cs := store.NewMemoryContentStore()
	baseHash := storeTestEntity(t, cs, "test/doc", map[string]interface{}{"a": "base", "b": "base"})
	localHash := storeTestEntity(t, cs, "test/doc", map[string]interface{}{"a": "local", "b": "base"})
	remoteHash := storeTestEntity(t, cs, "test/doc", map[string]interface{}{"a": "base", "b": "remote"})

	result := applyMergeStrategy(cs, strategyThreeWay, "test/path", baseHash, localHash, remoteHash)
	if !result.resolved {
		t.Fatal("three-way should resolve when changes don't overlap")
	}

	// Verify merged entity has both changes.
	ent, ok := cs.Get(result.hash)
	if !ok {
		t.Fatal("merged entity not in store")
	}
	var merged map[string]interface{}
	ecf.Decode(ent.Data, &merged)
	if merged["a"] != "local" {
		t.Fatalf("expected a=local, got %v", merged["a"])
	}
	if merged["b"] != "remote" {
		t.Fatalf("expected b=remote, got %v", merged["b"])
	}
}

func TestMergeStrategy_ThreeWay_Conflict(t *testing.T) {
	cs := store.NewMemoryContentStore()
	baseHash := storeTestEntity(t, cs, "test/doc", map[string]interface{}{"a": "base"})
	localHash := storeTestEntity(t, cs, "test/doc", map[string]interface{}{"a": "local"})
	remoteHash := storeTestEntity(t, cs, "test/doc", map[string]interface{}{"a": "remote"})

	result := applyMergeStrategy(cs, strategyThreeWay, "test/path", baseHash, localHash, remoteHash)
	if result.resolved {
		t.Fatal("three-way should not resolve when same field changed to different values")
	}
}

func TestMergeStrategy_Manual(t *testing.T) {
	cs := store.NewMemoryContentStore()
	result := applyMergeStrategy(cs, strategyManual, "test/path", hash.Hash{}, hash.Hash{}, hash.Hash{})
	if result.resolved {
		t.Fatal("manual should never resolve")
	}
}

func TestPrefixHash(t *testing.T) {
	ph := PrefixHash("/testpeer/project/")
	if len(ph) != 66 {
		t.Fatalf("expected 66 chars, got %d: %s", len(ph), ph)
	}
	if !isHex(ph) {
		t.Fatalf("not hex: %s", ph)
	}
	// Deterministic
	if PrefixHash("/testpeer/project/") != ph {
		t.Fatal("PrefixHash not deterministic")
	}
	// Different prefix → different hash
	if PrefixHash("/testpeer/other/") == ph {
		t.Fatal("different prefixes produced same hash")
	}
}

func TestIsRevisionConfigPath(t *testing.T) {
	ph := PrefixHash("/testpeer/data/")
	if !isRevisionConfigPath("system/revision/" + ph + "/config") {
		t.Fatalf("should match: system/revision/%s/config", ph)
	}
	if isRevisionConfigPath("system/revision/config/merge/path/test") {
		t.Fatal("should not match global config path")
	}
	if isRevisionConfigPath("system/revision/head") {
		t.Fatal("should not match non-config metadata")
	}
}

func TestResolvePrefix(t *testing.T) {
	if got := resolvePrefix("project/", "peerA"); got != "/peerA/project/" {
		t.Fatalf("peer-relative: got %q", got)
	}
	if got := resolvePrefix("/peerB/project/", "peerA"); got != "/peerB/project/" {
		t.Fatalf("already-absolute: got %q", got)
	}
}

// --- Phase 3 Tests ---

func TestBranch_CreateListDelete(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create initial commit.
	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"x": "y"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	commitResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Create branch.
	req = makeRequest(t, hctx, "branch", types.RevisionBranchParamsData{
		Prefix: "data/",
		Action: "create",
		Name:   "feature",
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	branchResult, _ := types.RevisionBranchResultDataFromEntity(resp.Result)
	if branchResult.Status != "created" {
		t.Fatalf("expected created, got %s", branchResult.Status)
	}
	if branchResult.Version != commitResult.Version {
		t.Fatal("branch should point to current head")
	}

	// List branches.
	req = makeRequest(t, hctx, "branch", types.RevisionBranchParamsData{
		Prefix: "data/",
		Action: "list",
	})
	resp, _ = h.Handle(context.Background(), req)
	branchResult, _ = types.RevisionBranchResultDataFromEntity(resp.Result)
	if len(branchResult.Branches) != 1 {
		t.Fatalf("expected 1 branch, got %d", len(branchResult.Branches))
	}
	if _, ok := branchResult.Branches["feature"]; !ok {
		t.Fatal("feature branch not in list")
	}

	// Delete branch.
	req = makeRequest(t, hctx, "branch", types.RevisionBranchParamsData{
		Prefix: "data/",
		Action: "delete",
		Name:   "feature",
	})
	resp, _ = h.Handle(context.Background(), req)
	branchResult, _ = types.RevisionBranchResultDataFromEntity(resp.Result)
	if branchResult.Status != "deleted" {
		t.Fatalf("expected deleted, got %s", branchResult.Status)
	}

	// Verify branch is gone.
	if _, ok := hctx.LocationIndex.Get(branchPath(testPH(hctx, "data/"), "feature")); ok {
		t.Fatal("branch should be removed")
	}
}

func TestBranch_CannotDeleteActive(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"x": "y"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	h.Handle(context.Background(), req)

	// Create branch and checkout.
	req = makeRequest(t, hctx, "branch", types.RevisionBranchParamsData{
		Prefix: "data/",
		Action: "create",
		Name:   "main",
	})
	h.Handle(context.Background(), req)

	req = makeRequest(t, hctx, "checkout", types.RevisionCheckoutParamsData{
		Prefix: "data/",
		Branch: "main",
	})
	h.Handle(context.Background(), req)

	// Try to delete active branch.
	req = makeRequest(t, hctx, "branch", types.RevisionBranchParamsData{
		Prefix: "data/",
		Action: "delete",
		Name:   "main",
	})
	resp, _ := h.Handle(context.Background(), req)
	if resp.Status != 409 {
		t.Fatalf("expected 409, got %d", resp.Status)
	}
}

func TestCheckout(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create v1 with file1.
	storeEntity(t, hctx, "data/file1", "test/document", map[string]string{"content": "v1"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	v1, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Create v2 with file2 added.
	storeEntity(t, hctx, "data/file2", "test/document", map[string]string{"content": "new"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	h.Handle(context.Background(), req)

	// Checkout v1 — file2 should be removed.
	req = makeRequest(t, hctx, "checkout", types.RevisionCheckoutParamsData{
		Prefix:  "data/",
		Version: v1.Version,
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	checkoutResult, _ := types.RevisionCheckoutResultDataFromEntity(resp.Result)
	if checkoutResult.Status != "checked_out" {
		t.Fatalf("expected checked_out, got %s", checkoutResult.Status)
	}

	// file2 should be gone.
	if _, ok := hctx.LocationIndex.Get("data/file2"); ok {
		t.Fatal("file2 should be removed after checkout to v1")
	}
	// file1 should still exist.
	if _, ok := hctx.LocationIndex.Get("data/file1"); !ok {
		t.Fatal("file1 should still exist after checkout to v1")
	}
}

func TestTag_CreateListDelete(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"x": "y"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	commitResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Create tag.
	req = makeRequest(t, hctx, "tag", types.RevisionTagParamsData{
		Prefix: "data/",
		Action: "create",
		Name:   "v1.0",
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	tagResult, _ := types.RevisionTagResultDataFromEntity(resp.Result)
	if tagResult.Status != "created" {
		t.Fatalf("expected created, got %s", tagResult.Status)
	}
	if tagResult.Version != commitResult.Version {
		t.Fatal("tag should point to head version")
	}

	// Tag is immutable — cannot overwrite.
	req = makeRequest(t, hctx, "tag", types.RevisionTagParamsData{
		Prefix: "data/",
		Action: "create",
		Name:   "v1.0",
	})
	resp, _ = h.Handle(context.Background(), req)
	if resp.Status != 409 {
		t.Fatalf("expected 409 for duplicate tag, got %d", resp.Status)
	}

	// List tags.
	req = makeRequest(t, hctx, "tag", types.RevisionTagParamsData{
		Prefix: "data/",
		Action: "list",
	})
	resp, _ = h.Handle(context.Background(), req)
	tagResult, _ = types.RevisionTagResultDataFromEntity(resp.Result)
	if len(tagResult.Tags) != 1 {
		t.Fatalf("expected 1 tag, got %d", len(tagResult.Tags))
	}

	// Delete tag.
	req = makeRequest(t, hctx, "tag", types.RevisionTagParamsData{
		Prefix: "data/",
		Action: "delete",
		Name:   "v1.0",
	})
	resp, _ = h.Handle(context.Background(), req)
	tagResult, _ = types.RevisionTagResultDataFromEntity(resp.Result)
	if tagResult.Status != "deleted" {
		t.Fatalf("expected deleted, got %s", tagResult.Status)
	}
}

func TestDiff(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// v1: file1 only.
	storeEntity(t, hctx, "data/file1", "test/document", map[string]string{"content": "v1"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	v1, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// v2: file1 changed, file2 added.
	storeEntity(t, hctx, "data/file1", "test/document", map[string]string{"content": "v2"})
	storeEntity(t, hctx, "data/file2", "test/document", map[string]string{"content": "new"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	v2, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Diff v1 vs v2.
	req = makeRequest(t, hctx, "diff", types.RevisionDiffParamsData{
		Prefix: "data/",
		Base:   v1.Version,
		Target: v2.Version,
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	diff, err := types.DiffDataFromEntity(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(diff.Added))
	}
	if _, ok := diff.Added["file2"]; !ok {
		t.Fatal("file2 should be in added")
	}
	if len(diff.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(diff.Changed))
	}
	if _, ok := diff.Changed["file1"]; !ok {
		t.Fatal("file1 should be in changed")
	}
}

func TestCherryPick(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create base with file1.
	storeEntity(t, hctx, "data/file1", "test/document", map[string]string{"content": "base"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	baseResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Create a version that adds file2 (on a "feature" branch conceptually).
	storeEntity(t, hctx, "data/file2", "test/document", map[string]string{"content": "feature"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ = h.Handle(context.Background(), req)
	featureResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Reset head to base (simulate being on main branch).
	hctx.LocationIndex.Set(headPath(testPH(hctx, "data/")), baseResult.Version)
	// Remove file2 from tree to match base state.
	hctx.LocationIndex.Remove("data/file2")

	// Cherry-pick the feature commit onto base.
	req = makeRequest(t, hctx, "cherry-pick", types.RevisionCherryPickParamsData{
		Prefix:  "data/",
		Version: featureResult.Version,
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	cpResult, _ := types.RevisionCherryPickResultDataFromEntity(resp.Result)

	if cpResult.Status != "cherry_picked" {
		t.Fatalf("expected cherry_picked, got %s", cpResult.Status)
	}

	// file2 should now be in the tree.
	if _, ok := hctx.LocationIndex.Get("data/file2"); !ok {
		t.Fatal("file2 should be present after cherry-pick")
	}

	// New version should have single parent (base).
	cpVer, _ := loadVersion(hctx, cpResult.Version)
	if len(cpVer.Parents) != 1 {
		t.Fatalf("cherry-pick version should have 1 parent, got %d", len(cpVer.Parents))
	}
	if cpVer.Parents[0] != baseResult.Version {
		t.Fatal("cherry-pick parent should be base version")
	}
}

func TestRevert(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// v1: file1 only.
	storeEntity(t, hctx, "data/file1", "test/document", map[string]string{"content": "original"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	h.Handle(context.Background(), req)

	// v2: add file2.
	storeEntity(t, hctx, "data/file2", "test/document", map[string]string{"content": "added"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	v2Result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Revert v2 — should remove file2.
	req = makeRequest(t, hctx, "revert", types.RevisionRevertParamsData{
		Prefix:  "data/",
		Version: v2Result.Version,
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	revertResult, _ := types.RevisionRevertResultDataFromEntity(resp.Result)

	if revertResult.Status != "reverted" {
		t.Fatalf("expected reverted, got %s", revertResult.Status)
	}

	// file2 should be gone.
	if _, ok := hctx.LocationIndex.Get("data/file2"); ok {
		t.Fatal("file2 should be removed after revert")
	}
	// file1 should still exist.
	if _, ok := hctx.LocationIndex.Get("data/file1"); !ok {
		t.Fatal("file1 should still exist after revert")
	}
}

func TestManifest(t *testing.T) {
	h := NewHandler()
	manifest := h.Manifest()

	if manifest.Pattern != "system/revision" {
		t.Fatalf("expected pattern system/revision, got %s", manifest.Pattern)
	}

	expectedOps := []string{
		"commit", "log", "status", "merge", "resolve",
		"fetch", "fetch-entities", "fetch-diff", "pull", "push",
		"find-ancestor", "branch", "checkout", "tag", "diff",
		"cherry-pick", "revert", "config", "merge-config",
	}
	for _, op := range expectedOps {
		if _, ok := manifest.Operations[op]; !ok {
			t.Fatalf("missing operation: %s", op)
		}
	}
	if len(manifest.Operations) != 19 {
		t.Fatalf("expected 19 operations, got %d", len(manifest.Operations))
	}
}

func TestUnknownOperation(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	req := &handler.Request{
		Operation: "nonexistent",
		Context:   hctx,
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
}

func TestCommit_AdvancesBranch(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create initial commit.
	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"x": "y"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	h.Handle(context.Background(), req)

	// Create branch and checkout.
	req = makeRequest(t, hctx, "branch", types.RevisionBranchParamsData{
		Prefix: "data/",
		Action: "create",
		Name:   "feature",
	})
	h.Handle(context.Background(), req)

	req = makeRequest(t, hctx, "checkout", types.RevisionCheckoutParamsData{
		Prefix: "data/",
		Branch: "feature",
	})
	h.Handle(context.Background(), req)

	// Commit on branch — branch pointer should advance.
	storeEntity(t, hctx, "data/file", "test/document", map[string]string{"x": "updated"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	commitResult, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Branch pointer should match new commit.
	branchHash, ok := hctx.LocationIndex.Get(branchPath(testPH(hctx, "data/"), "feature"))
	if !ok {
		t.Fatal("branch pointer should exist")
	}
	if branchHash != commitResult.Version {
		t.Fatal("branch pointer should match new commit")
	}
}

// --- Helpers ---

func storeTestEntity(t *testing.T, cs store.ContentStore, typeName string, data interface{}) hash.Hash {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	ent, err := entity.NewEntity(typeName, cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
