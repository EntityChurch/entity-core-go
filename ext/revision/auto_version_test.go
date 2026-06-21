package revision

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// autoVersionFixture wires a minimal write pipeline matching the peer
// architecture: MemoryLI → NotifyingLI (sync hooks) → NamespacedIndex.
// Hooks registered: RootTracker at position 6, AutoVersioner at position 7.
type autoVersionFixture struct {
	cs      store.ContentStore
	li      store.LocationIndex // NamespacedIndex for writes (handler-facing)
	nsID    string
	tracker *tree.RootTracker
	av      *AutoVersioner
	events  chan store.TreeChangeEvent
	done    chan struct{}
}

func newAutoVersionFixture(t *testing.T) *autoVersionFixture {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pid := string(kp.PeerID())
	cs := store.NewMemoryContentStore()
	raw := store.NewMemoryLocationIndex()

	events := make(chan store.TreeChangeEvent, 512)
	done := make(chan struct{})
	notifying := store.NewNotifyingLocationIndex(raw, events, done)

	tracker := tree.NewRootTracker(cs, pid, nil)
	av := NewAutoVersioner(cs, tracker, nil)

	// Order matters: tracker first (populates system/tree/root/{prefix}),
	// then auto-versioner (reads the settled root).
	notifying.AddNamedSyncHook("root-tracker", tracker.OnTreeChange)
	notifying.AddNamedSyncHook("auto-versioner", av.OnTreeChange)

	nsLI := store.NewNamespacedIndex(notifying, pid)
	tracker.SetLocationIndex(nsLI)
	av.SetLocationIndex(nsLI)

	identity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	tracker.SetLocalPeerID(pid, identity.ContentHash)
	av.SetLocalPeerID(pid, identity.ContentHash)

	tracker.Load()
	av.Load()

	return &autoVersionFixture{
		cs:      cs,
		li:      nsLI,
		nsID:    pid,
		tracker: tracker,
		av:      av,
		events:  events,
		done:    done,
	}
}

func (f *autoVersionFixture) putEntity(t *testing.T, path, typeName string, data interface{}) hash.Hash {
	t.Helper()
	rawData, err := ecf.Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	ent, err := entity.NewEntity(typeName, cbor.RawMessage(rawData))
	if err != nil {
		t.Fatal(err)
	}
	h, err := f.cs.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		f.li.Set(path, h)
	}
	return h
}

func (f *autoVersionFixture) enableTracking(t *testing.T, prefix string) {
	t.Helper()
	absPrefix := resolvePrefix(prefix, f.nsID)
	cfg := types.TrackingConfigData{Prefix: absPrefix, Enabled: true}
	f.putEntity(t, "system/tree/tracking-config/"+f.prefixHash(prefix), string(types.TypeTreeTrackingConfig), cfg)
}

func (f *autoVersionFixture) prefixHash(prefix string) string {
	return PrefixHash(resolvePrefix(prefix, f.nsID))
}

func (f *autoVersionFixture) enableAutoVersion(t *testing.T, prefix string, exclude []string) {
	t.Helper()
	trueVal := true
	absPrefix := resolvePrefix(prefix, f.nsID)
	cfg := types.RevisionConfigData{
		Prefix:      absPrefix,
		AutoVersion: &trueVal,
		Exclude:     exclude,
	}
	f.putEntity(t, configPath(f.prefixHash(prefix)), types.TypeRevisionConfig, cfg)
}

func (f *autoVersionFixture) head(prefix string) (hash.Hash, bool) {
	return f.li.Get(headPath(f.prefixHash(prefix)))
}

func (f *autoVersionFixture) loadVersion(t *testing.T, h hash.Hash) types.RevisionEntryData {
	t.Helper()
	ent, ok := f.cs.Get(h)
	if !ok {
		t.Fatalf("version entity not in content store: %s", h.String())
	}
	v, err := types.RevisionEntryDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode version: %v", err)
	}
	return v
}

// TestAutoVersion_PerWriteEntry verifies §6.1: each matching tree write to a
// tracked prefix produces a version entry.
func TestAutoVersion_PerWriteEntry(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	if _, ok := f.head("data/"); ok {
		t.Fatal("head exists before any write")
	}

	f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})

	h1, ok := f.head("data/")
	if !ok {
		t.Fatal("head missing after first write")
	}
	v1 := f.loadVersion(t, h1)
	if v1.Root.IsZero() {
		t.Fatal("version root is zero")
	}
	if len(v1.Parents) != 0 {
		t.Fatalf("first version has parents: %v", v1.Parents)
	}

	f.putEntity(t, "data/file2", "test/doc", map[string]string{"v": "2"})

	h2, _ := f.head("data/")
	if h2 == h1 {
		t.Fatal("head did not advance on second write")
	}
	v2 := f.loadVersion(t, h2)
	if len(v2.Parents) != 1 || v2.Parents[0] != h1 {
		t.Fatalf("second version parent mismatch: %v", v2.Parents)
	}
}

// TestAutoVersion_SuppressesVersionTranscriptionOps is the F10 part-2
// regression test. Merge / checkout operations transcribe a version's
// bindings into the live tree under MutationContext.Operation = "merge" or
// "checkout". Each operation writes its own version entity capturing the
// post-operation state; auto-version intermediates fired during the
// binding-application loop would be redundant AND non-deterministic
// (mergedBindings is a Go map; iteration order is randomized per goroutine).
//
// Non-deterministic intermediates break cross-peer convergence because each
// peer emits a different intermediate version chain from identical inputs.
// The fix is to skip OnTreeChange's auto-version emission for these
// operations. See the F10 part-2 diagnosis.
func TestAutoVersion_SuppressesVersionTranscriptionOps(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	// Sanity baseline: a normal write fires auto-version → head advances.
	f.putEntity(t, "data/file_pre", "test/doc", map[string]string{"v": "pre"})
	baselineHead, hasBaseline := f.head("data/")
	if !hasBaseline {
		t.Fatal("setup broken: auto-version didn't fire for normal write (no head present)")
	}

	// Construct a synthetic TreeChangeEvent representing a merge handler's
	// binding write. Hash content is irrelevant — what matters is whether
	// OnTreeChange suppresses emission based on Context.Operation.
	mergeEvent := store.TreeChangeEvent{
		Path:       "/" + f.nsID + "/data/file_during_merge",
		Hash:       baselineHead, // any non-zero hash works as a placeholder
		ChangeType: store.ChangeModified,
		Context: &store.MutationContext{
			HandlerPattern: "system/revision",
			Operation:      "merge",
		},
	}
	if result := f.av.OnTreeChange(mergeEvent); result != nil {
		t.Fatalf("OnTreeChange returned non-nil for merge event: %+v", result)
	}
	headAfterMerge, _ := f.head("data/")
	if headAfterMerge != baselineHead {
		t.Fatalf("auto-version fired for merge write — head advanced %s -> %s; merge intermediates not suppressed",
			baselineHead.String(), headAfterMerge.String())
	}

	// Same suppression must apply to checkout — the sibling F10 bug class.
	checkoutEvent := mergeEvent
	checkoutEvent.Path = "/" + f.nsID + "/data/file_during_checkout"
	checkoutEvent.Context = &store.MutationContext{
		HandlerPattern: "system/revision",
		Operation:      "checkout",
	}
	if result := f.av.OnTreeChange(checkoutEvent); result != nil {
		t.Fatalf("OnTreeChange returned non-nil for checkout event: %+v", result)
	}
	headAfterCheckout, _ := f.head("data/")
	if headAfterCheckout != baselineHead {
		t.Fatalf("auto-version fired for checkout write — head advanced %s -> %s; checkout intermediates not suppressed",
			baselineHead.String(), headAfterCheckout.String())
	}

	// Negative control: an event with a non-merge / non-checkout operation
	// MUST still fire auto-version. The suppression is targeted, not blanket.
	normalEvent := mergeEvent
	normalEvent.Path = "/" + f.nsID + "/data/file_normal_write"
	normalEvent.Context = &store.MutationContext{
		HandlerPattern: "system/tree",
		Operation:      "put",
	}
	// Pre-bind via the location index so the tracked-root reflects the new
	// path before auto-version reads it; then call OnTreeChange to simulate
	// the notifying-index emit.
	newHash := f.putEntity(t, "data/file_normal_write", "test/doc",
		map[string]string{"v": "after-baseline"})
	normalEvent.Hash = newHash
	if result := f.av.OnTreeChange(normalEvent); result != nil {
		t.Fatalf("OnTreeChange returned non-nil for normal put event: %+v", result)
	}
	headAfterNormal, _ := f.head("data/")
	if headAfterNormal == baselineHead {
		t.Fatalf("auto-version was suppressed for a normal put — over-broad filter (head unchanged at %s)",
			baselineHead.String())
	}
}

// TestAutoVersion_HeadCASRetry_ChainsFromCurrentHead is the F10 part-4
// regression test. AutoVersioner.fire() and the merge handler both write
// the same head path under different locks; pre-fix this allowed merge to
// silently overwrite AV's emit (orphaning AV's version, losing the last
// burst write captured by that version). The fix uses CompareAndSwap so
// AV's commit only succeeds when head hasn't moved underneath it.
//
// This test simulates the post-CAS-failure retry path by externally
// advancing head between AV emits — equivalent to "merge advanced head
// while AV was about to emit." After the external advance, the next
// tracked write must produce a version that chains from the EXTERNAL
// head (proving fire() re-read head before committing), not from the
// pre-advance head (which would prove fire() used a stale parent).
//
// Diagnosed by the workbench in the F10 part-3 results;
// see also the F10 postmortem.
func TestAutoVersion_HeadCASRetry_ChainsFromCurrentHead(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	// First emit creates V1 from the no-prior-head Set path. Head = V1.
	f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})
	v1Hash, ok := f.head("data/")
	if !ok {
		t.Fatal("setup: no head after first tracked write")
	}

	// Externally advance head to a fake "merge result" version, chaining
	// from V1. This simulates the moment a concurrent merge handler
	// completes its head TreeSet just before AV is about to emit. The CAS
	// fix means AV must observe this new head and chain from it on its
	// NEXT emit, rather than racing with a stale V1 reference.
	fakeRoot, _ := tree.BuildTrie(f.cs, []tree.Binding{{Path: "data/external", Hash: hash.Hash{Digest: hash.ExtendDigest([32]byte{0xEE})}}})
	fakeVer := types.RevisionEntryData{
		Root:    fakeRoot,
		Parents: tree.SortedParents([]hash.Hash{v1Hash}),
	}
	fakeEnt, _ := fakeVer.ToEntity()
	fakeHash, _ := f.cs.Put(fakeEnt)
	headP := headPath(f.prefixHash("data/"))
	if err := f.li.CompareAndSwap(headP, v1Hash, fakeHash); err != nil {
		t.Fatalf("setup CAS to fake head failed: %v", err)
	}
	// Sanity: head now equals fakeHash.
	if got, _ := f.head("data/"); got != fakeHash {
		t.Fatalf("setup: head should be fakeHash %s, got %s", fakeHash, got)
	}

	// Trigger another tracked write. AV.fire() runs:
	//   - reads currentHead = fakeHash (the post-external-advance value)
	//   - builds V2 with parent = fakeHash
	//   - CAS(headP, fakeHash, v2Hash) succeeds (head hasn't moved since
	//     fire() Read it; muPrefix serializes AV against itself)
	f.putEntity(t, "data/file2", "test/doc", map[string]string{"v": "2"})

	v2Hash, ok := f.head("data/")
	if !ok {
		t.Fatal("no head after second tracked write")
	}
	if v2Hash == fakeHash || v2Hash == v1Hash {
		t.Fatalf("head should have advanced to a new version; got existing %s", v2Hash)
	}

	v2 := f.loadVersion(t, v2Hash)
	if len(v2.Parents) != 1 {
		t.Fatalf("V2 should have exactly one parent; got %d (%v)", len(v2.Parents), v2.Parents)
	}
	if v2.Parents[0] != fakeHash {
		t.Fatalf("V2 must chain from fakeHash (current head at emit time), got parent %s — fire() used a stale head",
			v2.Parents[0])
	}

	// fakeHash and v1Hash are both still reachable via lineage walk
	// (V2 → fakeHash → V1). No orphaning.
	if _, present := f.cs.Get(fakeHash); !present {
		t.Fatal("fakeHash should still be in content store")
	}
	if _, present := f.cs.Get(v1Hash); !present {
		t.Fatal("v1Hash should still be in content store")
	}
}

// TestAutoVersion_NoopDedup verifies §6.1 dedup: writing the same value
// produces no new version.
func TestAutoVersion_NoopDedup(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	h := f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})
	head1, _ := f.head("data/")

	// Write the SAME hash at the same path — tracked root doesn't change.
	f.li.Set("data/file1", h)

	head2, _ := f.head("data/")
	if head1 != head2 {
		t.Fatalf("dedup failed: head advanced on no-op write (%s -> %s)", head1.String(), head2.String())
	}
}

// TestAutoVersion_SelfExclude verifies §6.1 reentrancy: auto-version's own
// writes (head, entry, branches) must NOT re-trigger it.
func TestAutoVersion_SelfExclude(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	// Trigger one write, which will cause auto-version to write head. If
	// reentrancy weren't guarded, we'd recurse and overflow.
	f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})

	head, ok := f.head("data/")
	if !ok {
		t.Fatal("no head after write")
	}
	v := f.loadVersion(t, head)
	// A single entry was created (no recursion).
	if len(v.Parents) != 0 {
		t.Fatalf("unexpected recursion: parents %v", v.Parents)
	}
}

// TestAutoVersion_Exclude verifies that config exclude patterns suppress
// version creation for matched paths.
func TestAutoVersion_Exclude(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", []string{"tmp/**"})

	f.putEntity(t, "data/tmp/cache", "test/doc", map[string]string{"v": "t"})
	if _, ok := f.head("data/"); ok {
		t.Fatal("head advanced on excluded path")
	}

	f.putEntity(t, "data/real/file", "test/doc", map[string]string{"v": "r"})
	if _, ok := f.head("data/"); !ok {
		t.Fatal("head did not advance on non-excluded path")
	}
}

// TestAutoVersion_CoordinatesTrackingConfig verifies §6.1 coordination:
// enabling auto_version: true auto-creates an enabled tracking-config for the
// prefix without the operator having to configure it separately.
func TestAutoVersion_CoordinatesTrackingConfig(t *testing.T) {
	f := newAutoVersionFixture(t)
	// NOTE: no enableTracking call — coordination should create it.
	f.enableAutoVersion(t, "data/", nil)

	f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})

	if _, ok := f.head("data/"); !ok {
		t.Fatal("head did not advance — coordination failed to create tracking-config")
	}
	// Tracking-config entity exists.
	if _, ok := f.li.Get("system/tree/tracking-config/" + f.prefixHash("data/")); !ok {
		t.Fatal("tracking-config binding missing after coordination")
	}
}

// TestAutoVersion_CoordinatesTrackingConfigDisable verifies §6.1: transitioning
// auto_version true → false disables the tracking-config.
func TestAutoVersion_CoordinatesTrackingConfigDisable(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableAutoVersion(t, "data/", nil)
	f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})

	// Flip auto_version to false.
	falseVal := false
	absPrefix := resolvePrefix("data/", f.nsID)
	cfg := types.RevisionConfigData{Prefix: absPrefix, AutoVersion: &falseVal}
	f.putEntity(t, configPath(f.prefixHash("data/")), types.TypeRevisionConfig, cfg)

	// Tracking-config should be disabled (entity still present, Enabled: false).
	trackingHash, ok := f.li.Get("system/tree/tracking-config/" + f.prefixHash("data/"))
	if !ok {
		t.Fatal("tracking-config binding missing")
	}
	ent, ok := f.cs.Get(trackingHash)
	if !ok {
		t.Fatal("tracking-config entity missing")
	}
	decoded, err := types.TrackingConfigDataFromEntity(ent)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Enabled {
		t.Fatal("tracking-config still enabled after auto_version: false")
	}
}

// TestAutoVersion_ActiveBranchAdvances verifies that the active branch pointer
// advances together with head.
func TestAutoVersion_ActiveBranchAdvances(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")
	f.enableAutoVersion(t, "data/", nil)

	// Set active branch to "main".
	branchHash := f.putEntity(t, "", "primitive/string", "main")
	f.li.Set(activeBranchPath(f.prefixHash("data/")), branchHash)

	f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})

	head, _ := f.head("data/")
	branchTip, ok := f.li.Get(branchPath(f.prefixHash("data/"), "main"))
	if !ok {
		t.Fatal("active branch did not advance")
	}
	if branchTip != head {
		t.Fatalf("branch tip %s != head %s", branchTip.String(), head.String())
	}
}

// TestAutoVersion_RejectsUniversalWithoutExcludes verifies §6D.4: a universal-
// tree (or system-encompassing) auto_version config missing required excludes
// is rejected — not cached, no versions created, no coordination.
func TestAutoVersion_RejectsUniversalWithoutExcludes(t *testing.T) {
	f := newAutoVersionFixture(t)

	// auto_version: true with prefix "/" but NO exclude covering system/**.
	trueVal := true
	cfg := types.RevisionConfigData{
		Prefix:      "/",
		AutoVersion: &trueVal,
		// missing exclude — should be rejected
	}
	f.putEntity(t, configPath(f.prefixHash("/")), types.TypeRevisionConfig, cfg)

	f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})

	// Config was rejected: not in cache, so no coordination occurred.
	if _, ok := f.av.configs["/"]; ok {
		t.Fatal("rejected universal-tree config was cached")
	}
	// No tracking-config coordinated for "/".
	if _, ok := f.li.Get("system/tree/tracking-config/" + f.prefixHash("/")); ok {
		t.Fatal("tracking-config created for rejected universal-tree config")
	}
}

// TestAutoVersion_AcceptsSystemPrefixWithExcludes verifies §6.1/§6D.4: a
// system-encompassing prefix with required excludes is accepted and
// coordinated. Using "system/" rather than "/" because the underlying
// RootTracker's universal-tree ("/") support is tracked separately.
func TestAutoVersion_AcceptsSystemPrefixWithExcludes(t *testing.T) {
	f := newAutoVersionFixture(t)

	trueVal := true
	cfg := types.RevisionConfigData{
		Prefix:      resolvePrefix("system/", f.nsID),
		AutoVersion: &trueVal,
		Exclude:     []string{"system/**"},
	}
	f.putEntity(t, configPath(f.prefixHash("system/")), types.TypeRevisionConfig, cfg)

	if _, ok := f.av.configs[resolvePrefix("system/", f.nsID)]; !ok {
		t.Fatal("accepted system/ config not cached")
	}
	if _, ok := f.li.Get("system/tree/tracking-config/" + f.prefixHash("system/")); !ok {
		t.Fatal("tracking-config missing after coordination for system/")
	}
}

// TestAutoVersion_DisabledConfig verifies that auto_version: false (or absent)
// suppresses version creation.
func TestAutoVersion_DisabledConfig(t *testing.T) {
	f := newAutoVersionFixture(t)
	f.enableTracking(t, "data/")

	falseVal := false
	cfg := types.RevisionConfigData{Prefix: resolvePrefix("data/", f.nsID), AutoVersion: &falseVal}
	f.putEntity(t, configPath(f.prefixHash("data/")), types.TypeRevisionConfig, cfg)

	f.putEntity(t, "data/file1", "test/doc", map[string]string{"v": "1"})

	if _, ok := f.head("data/"); ok {
		t.Fatal("head advanced with auto_version: false")
	}
}

// TestAutoVersion_NestedPrefixes pins the option-(b) eventual-consistency
// behavior ratified by Amendment 4: nested auto-version configs each advance
// independently. A single write to a path matching BOTH a parent and a child
// config fires both AV configs serially; each takes its own per-prefix lock;
// each DAG receives its own commit; no deadlock; no missing commits.
//
// Cross-DAG temporal observation of partial state during a merge is permitted
// per the amendment's "no shared lock state across nested configs" clause —
// this test pins the non-merge baseline (write under nested configs converges
// eventually on each DAG). The merge-vs-write nested case is documented as
// a known eventual-consistency window; structural enforcement would require
// the deferred PrefixCoordinator refactor.
func TestAutoVersion_NestedPrefixes(t *testing.T) {
	f := newAutoVersionFixture(t)

	// Both parent and nested prefixes get tracking + auto-version.
	f.enableTracking(t, "archives/")
	f.enableTracking(t, "archives/notes/")
	f.enableAutoVersion(t, "archives/", nil)
	f.enableAutoVersion(t, "archives/notes/", nil)

	// Write at the nested path — matches BOTH configs.
	f.putEntity(t, "archives/notes/file1", "test/doc", map[string]string{"v": "1"})

	parentHead, ok := f.head("archives/")
	if !ok {
		t.Fatal("parent prefix head missing after nested write")
	}
	childHead, ok := f.head("archives/notes/")
	if !ok {
		t.Fatal("child prefix head missing after nested write")
	}
	if parentHead == childHead {
		t.Fatalf("nested configs must produce independent DAGs (different version entities), got parent==child=%s", parentHead)
	}

	parentV1 := f.loadVersion(t, parentHead)
	childV1 := f.loadVersion(t, childHead)
	if len(parentV1.Parents) != 0 {
		t.Fatalf("parent DAG's first version should have no parents, got %v", parentV1.Parents)
	}
	if len(childV1.Parents) != 0 {
		t.Fatalf("child DAG's first version should have no parents, got %v", childV1.Parents)
	}

	// Second write at a parent-only path — matches only the parent config.
	f.putEntity(t, "archives/other", "test/doc", map[string]string{"v": "2"})

	parentHead2, _ := f.head("archives/")
	if parentHead2 == parentHead {
		t.Fatal("parent head did not advance on parent-only write")
	}
	childHead2, _ := f.head("archives/notes/")
	if childHead2 != childHead {
		t.Fatalf("child head should NOT advance for parent-only write (independent DAGs), got %s → %s", childHead, childHead2)
	}
	parentV2 := f.loadVersion(t, parentHead2)
	if len(parentV2.Parents) != 1 || parentV2.Parents[0] != parentHead {
		t.Fatalf("parent DAG's second version parent mismatch: %v (want [%s])", parentV2.Parents, parentHead)
	}

	// Third write at the nested path again — matches both configs; each
	// advances its own DAG independently.
	f.putEntity(t, "archives/notes/file2", "test/doc", map[string]string{"v": "3"})

	parentHead3, _ := f.head("archives/")
	childHead3, _ := f.head("archives/notes/")
	if parentHead3 == parentHead2 {
		t.Fatal("parent head did not advance on second nested write")
	}
	if childHead3 == childHead {
		t.Fatal("child head did not advance on second nested write")
	}
	parentV3 := f.loadVersion(t, parentHead3)
	childV2 := f.loadVersion(t, childHead3)
	if len(parentV3.Parents) != 1 || parentV3.Parents[0] != parentHead2 {
		t.Fatalf("parent DAG's third version parent mismatch: %v (want [%s])", parentV3.Parents, parentHead2)
	}
	if len(childV2.Parents) != 1 || childV2.Parents[0] != childHead {
		t.Fatalf("child DAG's second version parent mismatch: %v (want [%s])", childV2.Parents, childHead)
	}
}
