package revision

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

func newNamespacedLI() (store.LocationIndex, crypto.PeerID) {
	kp, _ := crypto.Generate()
	rawLI := store.NewMemoryLocationIndex()
	return store.NewNamespacedIndex(rawLI, string(kp.PeerID())), kp.PeerID()
}

// --- M1: Concurrent Non-Conflicting Merge — CRDT Convergence ---

func TestCRDT_ConcurrentNonConflictingMerge(t *testing.T) {
	// Two independent handler instances merge the same diverged versions.
	// With structural entries: same inputs → same version entry hash.
	//
	// Setup:
	//   V1 (shared initial state: readme + config)
	//   V2a: A edits readme (parent: V1)
	//   V2b: B edits config (parent: V1)
	//
	// Both A and B merge V2a + V2b independently → must produce same version entry.

	// Shared content store (simulates same entities available to both peers).
	cs := store.NewMemoryContentStore()

	// Create shared entities.
	readmeBase := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "readme-base"})
	configBase := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "config-base"})
	readmeEdited := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "readme-edited-by-A"})
	configEdited := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "config-edited-by-B"})

	// Build V1 trie (shared base).
	v1Root, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "readme", Hash: readmeBase},
		{Path: "config", Hash: configBase},
	})
	v1 := types.RevisionEntryData{Root: v1Root, Parents: nil}
	v1Ent, _ := v1.ToEntity()
	v1Hash, _ := cs.Put(v1Ent)

	// Build V2a trie (A edited readme).
	v2aRoot, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "readme", Hash: readmeEdited},
		{Path: "config", Hash: configBase},
	})
	v2a := types.RevisionEntryData{Root: v2aRoot, Parents: tree.SortedParents([]hash.Hash{v1Hash})}
	v2aEnt, _ := v2a.ToEntity()
	v2aHash, _ := cs.Put(v2aEnt)

	// Build V2b trie (B edited config).
	v2bRoot, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "readme", Hash: readmeBase},
		{Path: "config", Hash: configEdited},
	})
	v2b := types.RevisionEntryData{Root: v2bRoot, Parents: tree.SortedParents([]hash.Hash{v1Hash})}
	v2bEnt, _ := v2b.ToEntity()
	v2bHash, _ := cs.Put(v2bEnt)

	// --- Peer A merges ---
	hA := NewHandler()
	liA, pidA := newNamespacedLI()
	hctxA := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  liA,
		LocalPeerID:    pidA,
		HandlerPattern: "system/revision",
		Included:       make(map[hash.Hash]entity.Entity),
	}

	// Set A's tree state to V2a.
	phA := PrefixHash(resolvePrefix("data/", string(pidA)))
	hctxA.LocationIndex.Set("data/readme", readmeEdited)
	hctxA.LocationIndex.Set("data/config", configBase)
	hctxA.LocationIndex.Set(headPath(phA), v2aHash)

	reqA := makeRequest(t, hctxA, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: v2bHash,
	})
	respA, err := hA.Handle(context.Background(), reqA)
	if err != nil {
		t.Fatal(err)
	}
	resultA, _ := types.RevisionMergeResultDataFromEntity(respA.Result)
	if resultA.Status != "merged" {
		t.Fatalf("A: expected merged, got %s", resultA.Status)
	}

	// --- Peer B merges ---
	hB := NewHandler()
	liB, pidB := newNamespacedLI()
	hctxB := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  liB,
		LocalPeerID:    pidB,
		HandlerPattern: "system/revision",
		Included:       make(map[hash.Hash]entity.Entity),
	}

	// Set B's tree state to V2b.
	phB := PrefixHash(resolvePrefix("data/", string(pidB)))
	hctxB.LocationIndex.Set("data/readme", readmeBase)
	hctxB.LocationIndex.Set("data/config", configEdited)
	hctxB.LocationIndex.Set(headPath(phB), v2bHash)

	reqB := makeRequest(t, hctxB, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: v2aHash,
	})
	respB, err := hB.Handle(context.Background(), reqB)
	if err != nil {
		t.Fatal(err)
	}
	resultB, _ := types.RevisionMergeResultDataFromEntity(respB.Result)
	if resultB.Status != "merged" {
		t.Fatalf("B: expected merged, got %s", resultB.Status)
	}

	// --- The CRDT assertion ---
	// Both merges should produce the same trie root (symmetric three-way merge).
	verA, ok := loadVersion(hctxA, resultA.Version)
	if !ok {
		t.Fatal("A's merge version not found")
	}
	verB, ok := loadVersion(hctxB, resultB.Version)
	if !ok {
		t.Fatal("B's merge version not found")
	}

	if verA.Root != verB.Root {
		t.Fatalf("CRDT FAILED: trie roots differ: A=%v B=%v", verA.Root, verB.Root)
	}

	// Same sorted parents: both should have sorted([V2a, V2b]).
	if len(verA.Parents) != 2 || len(verB.Parents) != 2 {
		t.Fatalf("expected 2 parents each, got A=%d B=%d", len(verA.Parents), len(verB.Parents))
	}
	for i := 0; i < 2; i++ {
		if verA.Parents[i] != verB.Parents[i] {
			t.Fatalf("parent mismatch at index %d: A=%v B=%v", i, verA.Parents[i], verB.Parents[i])
		}
	}

	// Same root + same sorted parents = same version entry hash.
	if resultA.Version != resultB.Version {
		t.Fatalf("CRDT FAILED: version hashes differ: A=%v B=%v", resultA.Version, resultB.Version)
	}

	// Verify merged tree content.
	bindingsA := trieToBindings(cs, verA.Root)
	if bindingsA["readme"] != readmeEdited {
		t.Fatal("merged tree should have A's readme edit")
	}
	if bindingsA["config"] != configEdited {
		t.Fatal("merged tree should have B's config edit")
	}
}

// --- M2: Concurrent Conflicting Merge — Forward Progress ---

func TestCRDT_ConcurrentConflictingMerge_ForwardProgress(t *testing.T) {
	// Both peers edit the same file. Merge should still create version entries
	// (DAG makes forward progress even with conflicts).
	//
	// We include an extra unchanged file so the merged trie root is novel
	// (has both the conflicted file and the stable file), avoiding oscillation
	// detection triggering on a root that matches a prior version.

	cs := store.NewMemoryContentStore()

	readmeBase := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "base"})
	readmeA := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "edited-by-A"})
	readmeB := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "edited-by-B"})
	configBase := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "config-base"})
	configNew := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "config-new"})

	// V1 (base): readme + config.
	v1Root, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "readme", Hash: readmeBase},
		{Path: "config", Hash: configBase},
	})
	v1 := types.RevisionEntryData{Root: v1Root}
	v1Ent, _ := v1.ToEntity()
	v1Hash, _ := cs.Put(v1Ent)

	// V2a (A edited readme only).
	v2aRoot, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "readme", Hash: readmeA},
		{Path: "config", Hash: configBase},
	})
	v2a := types.RevisionEntryData{Root: v2aRoot, Parents: []hash.Hash{v1Hash}}
	v2aEnt, _ := v2a.ToEntity()
	v2aHash, _ := cs.Put(v2aEnt)

	// V2b (B edited readme + config — conflict on readme, clean merge on config).
	v2bRoot, _ := tree.BuildTrie(cs, []tree.Binding{
		{Path: "readme", Hash: readmeB},
		{Path: "config", Hash: configNew},
	})
	v2b := types.RevisionEntryData{Root: v2bRoot, Parents: []hash.Hash{v1Hash}}
	v2bEnt, _ := v2b.ToEntity()
	v2bHash, _ := cs.Put(v2bEnt)

	// Peer A merges. readme conflicts, config cleanly takes B's change.
	// Merged trie: {readme=readmeA(local), config=configNew(remote)} — novel root.
	hA := NewHandler()
	liA2, pidA2 := newNamespacedLI()
	hctxA := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  liA2,
		LocalPeerID:    pidA2,
		HandlerPattern: "system/revision",
		Included:       make(map[hash.Hash]entity.Entity),
	}
	phA2 := PrefixHash(resolvePrefix("data/", string(pidA2)))
	hctxA.LocationIndex.Set("data/readme", readmeA)
	hctxA.LocationIndex.Set("data/config", configBase)
	hctxA.LocationIndex.Set(headPath(phA2), v2aHash)

	reqA := makeRequest(t, hctxA, "merge", types.RevisionMergeParamsData{
		Prefix:        "data/",
		RemoteVersion: v2bHash,
	})
	respA, err := hA.Handle(context.Background(), reqA)
	if err != nil {
		t.Fatal(err)
	}
	resultA, _ := types.RevisionMergeResultDataFromEntity(respA.Result)

	// Should be merged (with conflicts), not blocked.
	if resultA.Status != "merged_with_conflicts" {
		t.Fatalf("expected merged_with_conflicts, got %s", resultA.Status)
	}
	if len(resultA.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(resultA.Conflicts))
	}

	// Version entry was still created — DAG made forward progress.
	if resultA.Version.IsZero() {
		t.Fatal("version hash should not be zero — DAG should make forward progress")
	}
	verA, ok := loadVersion(hctxA, resultA.Version)
	if !ok {
		t.Fatal("merge version not found in store")
	}
	if len(verA.Parents) != 2 {
		t.Fatalf("merge version should have 2 parents, got %d", len(verA.Parents))
	}
}

// --- M3: Clone Across Different Mount Points ---

func TestLocationIndependentVersioning(t *testing.T) {
	// Version entries are prefix-independent: {root, parents} only.
	// Same content at different prefixes produces same version entries.

	cs := store.NewMemoryContentStore()
	hashR := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "readme"})
	hashM := storeTestEntity(t, cs, "app/doc", map[string]string{"content": "main"})

	// Peer A commits at prefix "A/data/project/"
	hA := NewHandler()
	liAL, pidAL := newNamespacedLI()
	hctxA := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  liAL,
		LocalPeerID:    pidAL,
		HandlerPattern: "system/revision",
		Included:       make(map[hash.Hash]entity.Entity),
	}
	hctxA.LocationIndex.Set("A/data/project/readme", hashR)
	hctxA.LocationIndex.Set("A/data/project/src/main", hashM)

	reqA := makeRequest(t, hctxA, "commit", types.RevisionCommitParamsData{Prefix: "A/data/project/"})
	respA, _ := hA.Handle(context.Background(), reqA)
	resultA, _ := types.RevisionCommitResultDataFromEntity(respA.Result)

	// Peer B commits at prefix "B/projects/myproject/" — same content, different mount.
	hB := NewHandler()
	liBL, pidBL := newNamespacedLI()
	hctxB := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  liBL,
		LocalPeerID:    pidBL,
		HandlerPattern: "system/revision",
		Included:       make(map[hash.Hash]entity.Entity),
	}
	hctxB.LocationIndex.Set("B/projects/myproject/readme", hashR)
	hctxB.LocationIndex.Set("B/projects/myproject/src/main", hashM)

	reqB := makeRequest(t, hctxB, "commit", types.RevisionCommitParamsData{Prefix: "B/projects/myproject/"})
	respB, _ := hB.Handle(context.Background(), reqB)
	resultB, _ := types.RevisionCommitResultDataFromEntity(respB.Result)

	// Trie roots should be identical (same relative bindings).
	if resultA.Root != resultB.Root {
		t.Fatalf("trie roots should be identical across mount points: A=%v B=%v", resultA.Root, resultB.Root)
	}

	// Both are initial commits (no parents) → version entry hashes should match.
	if resultA.Version != resultB.Version {
		t.Fatalf("version hashes should be identical (same root, both have no parents): A=%v B=%v", resultA.Version, resultB.Version)
	}

	// B can use A's version entity directly.
	verA, ok := loadVersion(hctxA, resultA.Version)
	if !ok {
		t.Fatal("A's version not found")
	}
	verB, ok := loadVersion(hctxB, resultB.Version)
	if !ok {
		t.Fatal("B's version not found")
	}

	// Verify the version entries have identical structure.
	if verA.Root != verB.Root {
		t.Fatal("version roots should match")
	}
	if len(verA.Parents) != len(verB.Parents) {
		t.Fatal("version parents should match")
	}
}

// --- M6: Oscillation Detection ---

// TestOscillationDetection — under the post-F10-part-3 semantics, oscillation
// fires only when the proposed merge's full identity (root + sorted parents)
// is byte-identical to an existing ancestor. Same root with different parents
// is a legitimate cross-link, not an oscillation.
func TestOscillationDetection(t *testing.T) {
	cs := store.NewMemoryContentStore()

	rootA, _ := tree.BuildTrie(cs, []tree.Binding{{Path: "file", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}}})
	rootB, _ := tree.BuildTrie(cs, []tree.Binding{{Path: "file", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0x02})}}})

	// V1{rootA, parents=[]}, V2{rootB, parents=[V1]}. Use SortedParents to
	// match the canonical wire shape (empty slice, not nil) that the merge
	// handler and auto-versioner both produce. nil-vs-empty-slice produces
	// different CBOR and therefore different content hashes.
	v1 := types.RevisionEntryData{Root: rootA, Parents: tree.SortedParents(nil)}
	v1Ent, _ := v1.ToEntity()
	v1Hash, _ := cs.Put(v1Ent)

	v2 := types.RevisionEntryData{Root: rootB, Parents: tree.SortedParents([]hash.Hash{v1Hash})}
	v2Ent, _ := v2.ToEntity()
	v2Hash, _ := cs.Put(v2Ent)

	// Proposing {rootA, no parents} from V2 → re-creates V1 exactly → oscillation.
	if !detectOscillation(cs, rootA, []hash.Hash{}, v2Hash, 4) {
		t.Fatal("should detect oscillation: candidate {rootA, []} matches V1 byte-for-byte")
	}

	// Proposing {rootB, parents=[V1]} from V2 → re-creates V2 exactly → oscillation.
	if !detectOscillation(cs, rootB, []hash.Hash{v1Hash}, v2Hash, 4) {
		t.Fatal("should detect oscillation: candidate {rootB, [V1]} matches V2 byte-for-byte")
	}

	// Proposing rootB with DIFFERENT parents → legitimate new version (a
	// cross-link recording new lineage with same content). NOT oscillation.
	// This is the F10-part-3 bug case: rejecting this leaves divergent terminals.
	if detectOscillation(cs, rootB, []hash.Hash{v2Hash}, v2Hash, 4) {
		t.Fatal("same root with different parents must NOT be flagged as oscillation (F10 part-3)")
	}

	// Proposing a novel root → no version match, not oscillation.
	rootC, _ := tree.BuildTrie(cs, []tree.Binding{{Path: "file", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0x03})}}})
	if detectOscillation(cs, rootC, []hash.Hash{}, v2Hash, 4) {
		t.Fatal("novel root should not trigger oscillation")
	}
}

// TestOscillationDetection_DepthLimit verifies the BFS depth limit is respected.
// Builds a chain V1..V6 and proposes a duplicate of V_k for varying depths.
func TestOscillationDetection_DepthLimit(t *testing.T) {
	cs := store.NewMemoryContentStore()

	roots := make([]hash.Hash, 6)
	for i := 0; i < 6; i++ {
		roots[i], _ = tree.BuildTrie(cs, []tree.Binding{{Path: "file", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{byte(i)})}}})
	}

	var prev hash.Hash
	hashes := make([]hash.Hash, 6)
	parents := make([][]hash.Hash, 6)
	for i := 0; i < 6; i++ {
		var ps []hash.Hash
		if !prev.IsZero() {
			ps = []hash.Hash{prev}
		}
		canonical := tree.SortedParents(ps)
		parents[i] = canonical
		v := types.RevisionEntryData{Root: roots[i], Parents: canonical}
		ent, _ := v.ToEntity()
		hashes[i], _ = cs.Put(ent)
		prev = hashes[i]
	}

	head := hashes[5] // V6 (root=roots[5], parents=[V5])

	// Proposing V5's exact identity (1 ancestor back) → detected with depth=2.
	if !detectOscillation(cs, roots[4], parents[4], head, 2) {
		t.Fatal("depth=2 should detect identical version 1 ancestor back")
	}

	// Proposing V4's exact identity (2 ancestors back) → NOT detected at depth=2.
	if detectOscillation(cs, roots[3], parents[3], head, 2) {
		t.Fatal("depth=2 should NOT detect version 2 ancestors back (limit too shallow)")
	}

	// Same proposal detected at depth=4.
	if !detectOscillation(cs, roots[3], parents[3], head, 4) {
		t.Fatal("depth=4 should detect version 2 ancestors back")
	}
}

func TestOscillationDetection_NoHistory(t *testing.T) {
	cs := store.NewMemoryContentStore()
	root, _ := tree.BuildTrie(cs, []tree.Binding{{Path: "file", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}}})

	// No history → no ancestors → no oscillation regardless of proposed identity.
	if detectOscillation(cs, root, []hash.Hash{}, hash.Hash{}, 4) {
		t.Fatal("zero head should never detect oscillation")
	}
}

// TestOscillationDetection_CrossLinkAllowed is the F10-part-3 regression test.
// After cross-peer content convergence, two peers may hold the same content
// state (same trie root) at different head versions. The next round of merges
// produces candidate versions with the same root as a recent ancestor but
// DIFFERENT parents (cross-linking the divergent terminals). Pre-fix, the
// oscillation detector matched on root alone and aborted those merges,
// stranding the DAG at divergent terminals forever.
//
// This test models the convergent-but-divergent-heads state and asserts that
// detectOscillation lets the cross-link merge through.
func TestOscillationDetection_CrossLinkAllowed(t *testing.T) {
	cs := store.NewMemoryContentStore()

	// Both peers' DAGs share a base V_base. Each diverges to a peer-specific
	// terminal V_aliceTerm / V_bobTerm whose ROOTS are equal (same content)
	// but identities differ (different parent histories).
	sharedRoot, _ := tree.BuildTrie(cs, []tree.Binding{{Path: "data/file", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0x10})}}})

	baseRoot, _ := tree.BuildTrie(cs, []tree.Binding{{Path: "data/file", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}}})
	base := types.RevisionEntryData{Root: baseRoot, Parents: tree.SortedParents(nil)}
	baseEnt, _ := base.ToEntity()
	baseHash, _ := cs.Put(baseEnt)

	// Alice's terminal: descends from base, reaches sharedRoot.
	aliceTerm := types.RevisionEntryData{Root: sharedRoot, Parents: tree.SortedParents([]hash.Hash{baseHash})}
	aliceEnt, _ := aliceTerm.ToEntity()
	aliceTermHash, _ := cs.Put(aliceEnt)

	// Bob's terminal: ALSO reaches sharedRoot but via an intermediate V_mid,
	// so its parent set differs from alice's terminal. Same content, distinct
	// version identity — exactly the post-convergence state P2P sync produces.
	midRoot, _ := tree.BuildTrie(cs, []tree.Binding{{Path: "data/file", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0x05})}}})
	mid := types.RevisionEntryData{Root: midRoot, Parents: tree.SortedParents([]hash.Hash{baseHash})}
	midEnt, _ := mid.ToEntity()
	midHash, _ := cs.Put(midEnt)

	bobTerm := types.RevisionEntryData{Root: sharedRoot, Parents: tree.SortedParents([]hash.Hash{midHash})}
	bobEnt, _ := bobTerm.ToEntity()
	bobTermHash, _ := cs.Put(bobEnt)

	// Sanity: aliceTermHash != bobTermHash (different parents) but same root.
	if aliceTermHash == bobTermHash {
		t.Fatal("test setup: alice and bob terminal hashes should differ (different parents)")
	}

	// Alice proposes the cross-link merge: parents=[aliceTerm, bobTerm], root
	// = sharedRoot (still). Pre-fix this would match aliceTerm's root and
	// abort. Post-fix it must succeed (candidate identity is novel — neither
	// aliceTerm nor bobTerm has parents=[aliceTerm, bobTerm]).
	proposedParents := []hash.Hash{aliceTermHash, bobTermHash}
	if detectOscillation(cs, sharedRoot, proposedParents, aliceTermHash, 4) {
		t.Fatal("cross-link merge falsely flagged as oscillation — F10 part-3 regression: " +
			"same root with novel parent set is a legitimate new version")
	}
}

// --- C6: Fetch + Fetch-Entities ---

func TestFetch_ReturnsVersionsAndTrieNodes(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create V1, V2, V3.
	for i := 0; i < 3; i++ {
		storeEntity(t, hctx, "data/file", "test/doc", map[string]interface{}{"v": i})
		req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
		h.Handle(context.Background(), req)
	}

	// Fetch all.
	req := makeRequest(t, hctx, "fetch", types.RevisionFetchParamsData{Prefix: "data/"})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	root, included := unwrapEnvelope(t, resp)
	result, err := types.RevisionFetchResultDataFromEntity(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Head.IsZero() {
		t.Fatal("fetch head should be non-zero")
	}
	if len(result.Versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(result.Versions))
	}

	// Included should contain version entities AND root trie nodes.
	if len(included) < 3 {
		t.Fatalf("expected at least 3 included entities (versions), got %d", len(included))
	}

	// Each version entity should be in included.
	for _, vh := range result.Versions {
		if _, ok := included[vh]; !ok {
			t.Fatalf("version %v not in included", vh)
		}
	}
}

func TestFetch_Since(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create V1, V2, V3.
	var versionHashes []hash.Hash
	for i := 0; i < 3; i++ {
		storeEntity(t, hctx, "data/file", "test/doc", map[string]interface{}{"v": i})
		req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
		resp, _ := h.Handle(context.Background(), req)
		result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)
		versionHashes = append(versionHashes, result.Version)
	}

	// Fetch since V1 → should return V2, V3 only.
	req := makeRequest(t, hctx, "fetch", types.RevisionFetchParamsData{
		Prefix: "data/",
		Since:  versionHashes[0],
	})
	resp, _ := h.Handle(context.Background(), req)
	root, _ := unwrapEnvelope(t, resp)
	result, _ := types.RevisionFetchResultDataFromEntity(root)

	if len(result.Versions) != 2 {
		t.Fatalf("expected 2 versions since V1, got %d", len(result.Versions))
	}
}

func TestFetchEntities_ValidatesHashes(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create a commit.
	fileHash := storeEntity(t, hctx, "data/file", "test/doc", map[string]string{"content": "hello"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)

	// Get the trie root from the version.
	ver, _ := loadVersion(hctx, result.Version)

	// Fetch entities using the trie root.
	req = makeRequest(t, hctx, "fetch-entities", types.RevisionFetchEntitiesParamsData{
		Prefix:   "data/",
		Snapshot: ver.Root,
		Hashes:   []hash.Hash{fileHash},
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	root, included := unwrapEnvelope(t, resp)
	feResult, _ := types.RevisionFetchEntitiesResultDataFromEntity(root)
	if len(feResult.Found) != 1 {
		t.Fatalf("expected 1 found, got %d", len(feResult.Found))
	}
	if feResult.Found[0] != fileHash {
		t.Fatal("found hash should match requested hash")
	}
	if len(feResult.Missing) != 0 {
		t.Fatalf("expected 0 missing, got %d", len(feResult.Missing))
	}

	// Included should contain the entity.
	if _, ok := included[fileHash]; !ok {
		t.Fatal("file entity should be in included")
	}
}

func TestFetchEntities_RejectsInvalidHash(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	storeEntity(t, hctx, "data/file", "test/doc", map[string]string{"content": "hello"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	resp, _ := h.Handle(context.Background(), req)
	result, _ := types.RevisionCommitResultDataFromEntity(resp.Result)
	ver, _ := loadVersion(hctx, result.Version)

	// Request a hash that's not in the trie (security check).
	fakeHash := hash.Hash{Digest: hash.ExtendDigest([32]byte{0xFF, 0xFE, 0xFD})}

	req = makeRequest(t, hctx, "fetch-entities", types.RevisionFetchEntitiesParamsData{
		Prefix:   "data/",
		Snapshot: ver.Root,
		Hashes:   []hash.Hash{fakeHash},
	})
	resp, _ = h.Handle(context.Background(), req)
	root, _ := unwrapEnvelope(t, resp)
	feResult, _ := types.RevisionFetchEntitiesResultDataFromEntity(root)

	if len(feResult.Found) != 0 {
		t.Fatal("should not return entities for hashes not in trie")
	}
	if len(feResult.Missing) != 1 {
		t.Fatalf("expected 1 missing, got %d", len(feResult.Missing))
	}
}

// --- Push ---

func TestPush_NothingToPush(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// No commits → nothing to push.
	req := makeRequest(t, hctx, "push", types.RevisionPushParamsData{
		Prefix: "data/",
		Remote: "origin",
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	pushResult, _ := types.RevisionPushResultDataFromEntity(resp.Result)
	if pushResult.Status != "nothing_to_push" {
		t.Fatalf("expected nothing_to_push, got %s", pushResult.Status)
	}
}

func TestPush_InitialPush(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Create V1, V2.
	storeEntity(t, hctx, "data/file", "test/doc", map[string]string{"v": "1"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	h.Handle(context.Background(), req)

	storeEntity(t, hctx, "data/file", "test/doc", map[string]string{"v": "2"})
	req = makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	h.Handle(context.Background(), req)

	// Push to origin.
	req = makeRequest(t, hctx, "push", types.RevisionPushParamsData{
		Prefix: "data/",
		Remote: "origin",
	})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	pushResult, _ := types.RevisionPushResultDataFromEntity(resp.Result)
	if pushResult.Status != "pushed" {
		t.Fatalf("expected pushed, got %s", pushResult.Status)
	}
	if pushResult.Versions == nil || *pushResult.Versions != 2 {
		t.Fatal("should report 2 versions pushed")
	}
}

func TestPush_UpToDate(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	storeEntity(t, hctx, "data/file", "test/doc", map[string]string{"v": "1"})
	req := makeRequest(t, hctx, "commit", types.RevisionCommitParamsData{Prefix: "data/"})
	h.Handle(context.Background(), req)

	// Push once.
	req = makeRequest(t, hctx, "push", types.RevisionPushParamsData{Prefix: "data/", Remote: "origin"})
	h.Handle(context.Background(), req)

	// Push again — should be up to date.
	req = makeRequest(t, hctx, "push", types.RevisionPushParamsData{Prefix: "data/", Remote: "origin"})
	resp, _ := h.Handle(context.Background(), req)
	pushResult, _ := types.RevisionPushResultDataFromEntity(resp.Result)

	if pushResult.Status != "up_to_date" {
		t.Fatalf("expected up_to_date, got %s", pushResult.Status)
	}
}
