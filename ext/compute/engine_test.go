package compute

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

func TestDeterministicID(t *testing.T) {
	id1 := deterministicID("app/cell/A1")
	id2 := deterministicID("app/cell/A1")
	id3 := deterministicID("app/cell/A2")

	if id1 != id2 {
		t.Fatalf("same path should produce same ID: %s vs %s", id1, id2)
	}
	if id1 == id3 {
		t.Fatalf("different paths should produce different IDs")
	}
	if len(id1) != 52 {
		t.Fatalf("expected 52-char base32, got %d chars: %s", len(id1), id1)
	}
}

func TestWalkTreeLookups(t *testing.T) {
	cs := store.NewMemoryContentStore()

	// Build: lookup/tree("path/a") + lookup/tree("path/b")
	lookupA := mustE(types.ComputeLookupTreeData{Path: "/peer/path/a"}.ToEntity())
	lookupB := mustE(types.ComputeLookupTreeData{Path: "/peer/path/b"}.ToEntity())
	hashA, _ := cs.Put(lookupA)
	hashB, _ := cs.Put(lookupB)

	// arithmetic: lookupA + lookupB
	arith := mustE(types.ComputeArithmeticData{
		Op: "add", Left: hashA, Right: hashB,
	}.ToEntity())
	cs.Put(arith)

	deps := walkTreeLookups(arith, cs, "", "")
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %v", len(deps), deps)
	}

	found := map[string]bool{}
	for _, d := range deps {
		found[d] = true
	}
	if !found["/peer/path/a"] || !found["/peer/path/b"] {
		t.Fatalf("expected both paths, got %v", deps)
	}
}

func TestAuditSubgraph(t *testing.T) {
	cs := store.NewMemoryContentStore()

	lookupTree := mustE(types.ComputeLookupTreeData{Path: "/peer/data"}.ToEntity())
	cs.Put(lookupTree)

	result := auditSubgraph(lookupTree, cs, "", "", auditConfig{})
	if len(result.ReadPaths) != 1 || result.ReadPaths[0] != "/peer/data" {
		t.Fatalf("expected 1 read path, got %v", result.ReadPaths)
	}
}

func TestWalkTreeLookupsRelativePaths(t *testing.T) {
	cs := store.NewMemoryContentStore()

	lookupRel := mustE(types.ComputeLookupTreeData{Path: "data/input", Relative: true}.ToEntity())
	lookupAbs := mustE(types.ComputeLookupTreeData{Path: "/peer/other/value"}.ToEntity())
	relHash, _ := cs.Put(lookupRel)
	absHash, _ := cs.Put(lookupAbs)

	arith := mustE(types.ComputeArithmeticData{
		Op: "add", Left: relHash, Right: absHash,
	}.ToEntity())
	cs.Put(arith)

	deps := walkTreeLookups(arith, cs, "/peer/app/job", "")
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %v", len(deps), deps)
	}

	found := map[string]bool{}
	for _, d := range deps {
		found[d] = true
	}
	if !found["/peer/app/job/data/input"] {
		t.Fatalf("expected resolved relative path, got %v", deps)
	}
	if !found["/peer/other/value"] {
		t.Fatalf("expected absolute path preserved, got %v", deps)
	}
}

func TestAuditSubgraphRelativePaths(t *testing.T) {
	cs := store.NewMemoryContentStore()

	lookupRel := mustE(types.ComputeLookupTreeData{Path: "data/x", Relative: true}.ToEntity())
	cs.Put(lookupRel)

	result := auditSubgraph(lookupRel, cs, "/peer/root", "", auditConfig{})
	if len(result.ReadPaths) != 1 {
		t.Fatalf("expected 1 read path, got %v", result.ReadPaths)
	}
	if result.ReadPaths[0] != "/peer/root/data/x" {
		t.Fatalf("expected resolved path /peer/root/data/x, got %s", result.ReadPaths[0])
	}
}

// EXTENSION-COMPUTE v3.20 / S8: a bare (peer-relative) lookup_tree path with
// relative absent/false must be canonicalized to /{local_peer_id}/path for
// both resolution and dep-tracking. Without canonicalization, the dep-index
// keys on the verbatim bare string while tree writes notify on the canonical
// path → reactive subgraph silently never recomputes.
func TestWalkTreeLookupsCanonicalizesBarePaths(t *testing.T) {
	cs := store.NewMemoryContentStore()

	bare := mustE(types.ComputeLookupTreeData{Path: "app/x"}.ToEntity()) // relative:false implicit
	absolute := mustE(types.ComputeLookupTreeData{Path: "/peer/other/y"}.ToEntity())
	bareHash, _ := cs.Put(bare)
	absHash, _ := cs.Put(absolute)

	arith := mustE(types.ComputeArithmeticData{
		Op: "add", Left: bareHash, Right: absHash,
	}.ToEntity())
	cs.Put(arith)

	deps := walkTreeLookups(arith, cs, "", "testpeer")
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %v", len(deps), deps)
	}

	found := map[string]bool{}
	for _, d := range deps {
		found[d] = true
	}
	if !found["/testpeer/app/x"] {
		t.Fatalf("expected bare path canonicalized to /testpeer/app/x, got %v", deps)
	}
	if !found["/peer/other/y"] {
		t.Fatalf("expected absolute path preserved, got %v", deps)
	}
}

func TestAuditSubgraphCanonicalizesBarePath(t *testing.T) {
	cs := store.NewMemoryContentStore()

	bare := mustE(types.ComputeLookupTreeData{Path: "app/x"}.ToEntity())
	cs.Put(bare)

	result := auditSubgraph(bare, cs, "", "testpeer", auditConfig{})
	if len(result.ReadPaths) != 1 || result.ReadPaths[0] != "/testpeer/app/x" {
		t.Fatalf("expected canonical /testpeer/app/x, got %v", result.ReadPaths)
	}
}

func TestAuditSubgraphRelativeHashPath(t *testing.T) {
	cs := store.NewMemoryContentStore()

	lookupHash := mustE(types.ComputeLookupHashData{
		Hash: hash.Hash{}, Path: "data/sealed", Relative: true,
	}.ToEntity())
	cs.Put(lookupHash)

	result := auditSubgraph(lookupHash, cs, "/peer/root", "", auditConfig{})
	if len(result.DataHashes) != 1 {
		t.Fatalf("expected 1 data hash entry, got %v", result.DataHashes)
	}
	if result.DataHashes[0].Path != "/peer/root/data/sealed" {
		t.Fatalf("expected resolved hint path, got %s", result.DataHashes[0].Path)
	}
}

// makeTestGrant creates a minimal capability token for test use.
func makeTestGrant(t *testing.T, cs store.ContentStore) hash.Hash {
	t.Helper()
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: []string{"*"}},
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
		}},
		CreatedAt: 1000,
	}
	capEnt, err := capData.ToEntity()
	if err != nil {
		t.Fatalf("failed to create test grant: %v", err)
	}
	h, _ := cs.Put(capEnt)
	return h
}

func TestReactiveReEvaluation(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	engine := NewEngine(cs, li, nil)
	engine.localPeerID = "testpeer"

	grantHash := makeTestGrant(t, cs)

	// Create a simple expression: lookup/tree("/testpeer/app/value")
	lookupPath := "/testpeer/app/value"
	lookupEnt := mustE(types.ComputeLookupTreeData{Path: lookupPath}.ToEntity())
	lookupHash, _ := cs.Put(lookupEnt)

	// Place the expression in the tree.
	exprPath := store.QualifyPath("testpeer", "app/expr")
	li.Set(exprPath, lookupHash)

	// Place a value at the lookup path.
	valueEnt := mustE(types.ComputeLiteralData{Value: uint64(42)}.ToEntity())
	valueHash, _ := cs.Put(valueEnt)
	li.Set(lookupPath, valueHash)

	// Manually register dependencies (simulating install).
	resultPath := store.QualifyPath("testpeer", "app/expr/result")
	subgraphPath := subgraphPrefix + deterministicID(exprPath)

	sgData := types.ComputeSubgraphData{
		RootExpressionPath: exprPath,
		RootExpression:     lookupHash,
		InstallationGrant:  grantHash,
		ResultPath:         resultPath,
		Status:             "active",
	}
	sgEnt, _ := sgData.ToEntity()
	sgHash, _ := cs.Put(sgEnt)
	li.Set(store.QualifyPath("testpeer", subgraphPath), sgHash)

	engine.registerSubgraphDependencies(subgraphPath, exprPath, lookupEnt)

	// Trigger re-evaluation by changing the dependency.
	newValueEnt := mustE(types.ComputeLiteralData{Value: uint64(100)}.ToEntity())
	newValueHash, _ := cs.Put(newValueEnt)

	evt := store.TreeChangeEvent{
		Path:       lookupPath,
		Hash:       newValueHash,
		ChangeType: store.ChangeModified,
	}

	engine.OnTreeChange(evt)

	// Check that a result was written.
	resultHash, ok := li.Get(resultPath)
	if !ok {
		t.Fatal("expected result to be written at result path")
	}
	resultEnt, ok := cs.Get(resultHash)
	if !ok {
		t.Fatal("expected result entity in store")
	}
	// The result should be a compute/result wrapping the value 100.
	if resultEnt.Type != types.TypeComputeResult {
		t.Fatalf("expected compute/result, got %s", resultEnt.Type)
	}
}

func TestReactiveConvergence(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	engine := NewEngine(cs, li, nil)
	engine.localPeerID = "testpeer"

	grantHash := makeTestGrant(t, cs)

	lookupPath := "/testpeer/app/value"
	lookupEnt := mustE(types.ComputeLookupTreeData{Path: lookupPath}.ToEntity())
	lookupHash, _ := cs.Put(lookupEnt)

	exprPath := store.QualifyPath("testpeer", "app/expr")
	li.Set(exprPath, lookupHash)

	// Put value at path.
	valueEnt := mustE(types.ComputeLiteralData{Value: uint64(42)}.ToEntity())
	valueHash, _ := cs.Put(valueEnt)
	li.Set(lookupPath, valueHash)

	resultPath := store.QualifyPath("testpeer", "app/expr/result")
	subgraphPath := subgraphPrefix + deterministicID(exprPath)

	sgData := types.ComputeSubgraphData{
		RootExpressionPath: exprPath,
		RootExpression:     lookupHash,
		InstallationGrant:  grantHash,
		ResultPath:         resultPath,
		Status:             "active",
	}
	sgEnt, _ := sgData.ToEntity()
	sgHash, _ := cs.Put(sgEnt)
	li.Set(store.QualifyPath("testpeer", subgraphPath), sgHash)

	engine.registerSubgraphDependencies(subgraphPath, exprPath, lookupEnt)

	// First evaluation: should write result.
	evt := store.TreeChangeEvent{
		Path:       lookupPath,
		Hash:       valueHash,
		ChangeType: store.ChangeModified,
	}
	engine.OnTreeChange(evt)

	resultHash1, ok := li.Get(resultPath)
	if !ok {
		t.Fatal("expected result after first evaluation")
	}

	// Trigger again with same value — convergence should prevent duplicate write.
	engine.OnTreeChange(evt)

	resultHash2, _ := li.Get(resultPath)
	if resultHash1 != resultHash2 {
		t.Fatal("convergence check should have prevented re-write of same result")
	}
}

func TestFrozenSubgraphSkipped(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	engine := NewEngine(cs, li, nil)
	engine.localPeerID = "testpeer"

	lookupPath := "/testpeer/app/value"
	lookupEnt := mustE(types.ComputeLookupTreeData{Path: lookupPath}.ToEntity())
	lookupHash, _ := cs.Put(lookupEnt)

	exprPath := store.QualifyPath("testpeer", "app/expr")
	li.Set(exprPath, lookupHash)

	resultPath := store.QualifyPath("testpeer", "app/expr/result")
	subgraphPath := subgraphPrefix + deterministicID(exprPath)

	// Create a frozen subgraph.
	sgData := types.ComputeSubgraphData{
		RootExpressionPath: exprPath,
		RootExpression:     lookupHash,
		ResultPath:         resultPath,
		Status:             "frozen",
	}
	sgEnt, _ := sgData.ToEntity()
	sgHash, _ := cs.Put(sgEnt)
	li.Set(store.QualifyPath("testpeer", subgraphPath), sgHash)

	engine.registerSubgraphDependencies(subgraphPath, exprPath, lookupEnt)

	// Trigger — should be skipped because frozen.
	valueEnt := mustE(types.ComputeLiteralData{Value: uint64(99)}.ToEntity())
	valueHash, _ := cs.Put(valueEnt)
	li.Set(lookupPath, valueHash)

	evt := store.TreeChangeEvent{
		Path:       lookupPath,
		Hash:       valueHash,
		ChangeType: store.ChangeModified,
	}
	engine.OnTreeChange(evt)

	_, ok := li.Get(resultPath)
	if ok {
		t.Fatal("frozen subgraph should not have produced a result")
	}
}

func TestCascadeDepthFreeze(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	engine := NewEngine(cs, li, nil)
	engine.localPeerID = "testpeer"

	lookupPath := "/testpeer/app/value"
	lookupEnt := mustE(types.ComputeLookupTreeData{Path: lookupPath}.ToEntity())
	lookupHash, _ := cs.Put(lookupEnt)

	exprPath := store.QualifyPath("testpeer", "app/expr")
	li.Set(exprPath, lookupHash)

	valueEnt := mustE(types.ComputeLiteralData{Value: uint64(1)}.ToEntity())
	valueHash, _ := cs.Put(valueEnt)
	li.Set(lookupPath, valueHash)

	resultPath := store.QualifyPath("testpeer", "app/expr/result")
	subgraphPath := subgraphPrefix + deterministicID(exprPath)

	sgData := types.ComputeSubgraphData{
		RootExpressionPath: exprPath,
		RootExpression:     lookupHash,
		ResultPath:         resultPath,
		Status:             "active",
	}
	sgEnt, _ := sgData.ToEntity()
	sgHash, _ := cs.Put(sgEnt)
	li.Set(store.QualifyPath("testpeer", subgraphPath), sgHash)

	engine.registerSubgraphDependencies(subgraphPath, exprPath, lookupEnt)

	// Trigger with cascade depth at limit.
	depth := uint64(DefaultMaxCascadeDepth)
	evt := store.TreeChangeEvent{
		Path:       lookupPath,
		Hash:       valueHash,
		ChangeType: store.ChangeModified,
		Context:    &store.MutationContext{CascadeDepth: &depth},
	}
	engine.OnTreeChange(evt)

	// Check that the subgraph was frozen.
	updatedSGHash, ok := li.Get(store.QualifyPath("testpeer", subgraphPath))
	if !ok {
		t.Fatal("subgraph should still exist")
	}
	updatedSG, _ := cs.Get(updatedSGHash)
	var updatedData types.ComputeSubgraphData
	if err := ecf.Decode(updatedSG.Data, &updatedData); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if updatedData.Status != "frozen" {
		t.Fatalf("expected frozen, got %s", updatedData.Status)
	}

	// Check error at result path.
	errHash, ok := li.Get(resultPath)
	if !ok {
		t.Fatal("expected error entity at result path")
	}
	errEnt, _ := cs.Get(errHash)
	if errEnt.Type != types.TypeComputeError {
		t.Fatalf("expected compute/error at result, got %s", errEnt.Type)
	}
}

// PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §7.1: dispatch MUST fail-closed
// when the handler grant is missing, instead of falling back to caller cap.
func TestEvaluateAtPathFailsClosedWhenGrantMissing(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	exprPath := "/peer1/app/handler/expr"
	exprEnt, _ := types.ComputeLiteralData{Value: int64(1)}.ToEntity()
	exprHash, _ := cs.Put(exprEnt)
	li.Set(exprPath, exprHash)

	hctx := &handler.HandlerContext{
		LocalPeerID:    "peer1",
		Store:          cs,
		LocationIndex:  li,
		HandlerPattern: "app/handler",
		// HandlerGrant intentionally omitted (zero-valued).
		CallerCapability: makeCapEntity(t, []string{"*"}, []string{"*"}, []string{"*"}),
	}
	req := &handler.Request{
		Path:      "app/handler",
		Operation: "process",
		Context:   hctx,
	}

	h := NewHandler(nil)
	resp, err := h.EvaluateAtPath(context.Background(), exprPath, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403 permission_denied, got status %d", resp.Status)
	}
	if resp.Result.Type != types.TypeError {
		t.Fatalf("expected error result, got %s", resp.Result.Type)
	}
}

// EXTENSION-COMPUTE v3.19c §3.2 (arch b2be616): an impure-op
// permission_denied that arises *during* evaluation surfaces as the F10
// value-form — status 200 + compute/error{code:"permission_denied"} — not
// a transport 4xx. 4xx/403 is reserved for pre-eval authz failures (the
// EXECUTE/install being unauthorized, or §3.3 install pre-audit reject).
//
// Without this dedicated pin, a future change that re-raises eval-time
// permission_denied as 4xx could pass the existing eval-layer denial tests
// (which check ErrPermissionDenied at the Evaluate() boundary) AND the F10
// pin (which uses index_out_of_range) while silently regressing §3.2's
// permission_denied path. Mirrors Python's TestInEvalPermissionDenied and
// Rust's test_v319c_3_2_impure_op_permission_denied_during_eval_returns_200.
func TestInEvalPermissionDeniedReturns200(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// Build a value at a path OUTSIDE the handler's grant scope.
	forbiddenPath := "/peer1/system/secret/value"
	valueEnt, _ := types.ComputeLiteralData{Value: int64(42)}.ToEntity()
	li.Set(forbiddenPath, mustPut(t, cs, valueEnt))

	// Expression: compute/lookup/tree at the forbidden path. Lives under
	// the handler's slot so the dispatch authorizes the handler EXECUTE,
	// but the lookup target is out of scope — the denial fires during
	// evaluation.
	exprPath := "/peer1/app/handler/expr"
	lookupEnt := mustE(types.ComputeLookupTreeData{Path: forbiddenPath}.ToEntity())
	exprHash, _ := cs.Put(lookupEnt)
	li.Set(exprPath, exprHash)

	// Handler grant restricted to its own subtree only — does NOT cover
	// /peer1/system/secret. The dispatch reaches the handler (no pre-eval
	// 403), eval starts, the lookup hits the capability check, denial
	// fires *during* evaluation.
	handlerGrant := makeCapEntity(t, []string{"get"}, []string{"system/tree"}, []string{"/peer1/app/handler/*"})

	hctx := &handler.HandlerContext{
		LocalPeerID:      "peer1",
		Store:            cs,
		LocationIndex:    li,
		HandlerPattern:   "app/handler",
		HandlerGrant:     handlerGrant,
		CallerCapability: makeCapEntity(t, []string{"*"}, []string{"*"}, []string{"*"}),
	}
	req := &handler.Request{
		Path:      "app/handler",
		Operation: "process",
		Context:   hctx,
	}

	h := NewHandler(nil)
	resp, err := h.EvaluateAtPath(context.Background(), exprPath, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200 (in-eval denial surfaces as F10 value per §3.2 v3.19c), got status %d", resp.Status)
	}
	if resp.Result.Type != types.TypeComputeError {
		t.Fatalf("expected compute/error body at status 200, got %s", resp.Result.Type)
	}
	errData, err := types.ComputeErrorDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode compute/error: %v", err)
	}
	if errData.Code != ErrPermissionDenied {
		t.Fatalf("expected compute/error{code=permission_denied}, got code=%s", errData.Code)
	}
}

// PROPOSAL §4 / E3: bare primitives are wrapped at the dispatch boundary.
// Entity type comes from the operation's declared output_type; defaults to
// primitive/any when no output_type is declared.
func TestUnwrapEntityNativeResult(t *testing.T) {
	t.Run("primitive_wraps_in_output_type", func(t *testing.T) {
		ent, err := unwrapEntityNativeResult(int64(42), "app/result")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ent.Type != "app/result" {
			t.Fatalf("expected app/result, got %s", ent.Type)
		}
		var v int64
		if err := ecf.Decode(ent.Data, &v); err != nil {
			t.Fatalf("decode bare primitive data: %v", err)
		}
		if v != 42 {
			t.Fatalf("expected 42, got %d", v)
		}
	})

	t.Run("primitive_defaults_to_primitive_any", func(t *testing.T) {
		ent, err := unwrapEntityNativeResult("hello", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ent.Type != "primitive/any" {
			t.Fatalf("expected primitive/any default, got %s", ent.Type)
		}
		var s string
		if err := ecf.Decode(ent.Data, &s); err != nil {
			t.Fatalf("decode bare primitive data: %v", err)
		}
		if s != "hello" {
			t.Fatalf("expected \"hello\", got %q", s)
		}
	})

	t.Run("entity_passes_through_unchanged", func(t *testing.T) {
		original, _ := types.ComputeLiteralData{Value: int64(7)}.ToEntity()
		ent, err := unwrapEntityNativeResult(original, "primitive/any")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ent.Type != original.Type || ent.ContentHash != original.ContentHash {
			t.Fatalf("entity should pass through unchanged; got type=%s", ent.Type)
		}
	})
}

// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F3: audit walker collects the static
// literal resource from compute/apply.resource and the install-time check uses
// it instead of the handler path.
func TestAuditSubgraphCollectsStaticResource(t *testing.T) {
	cs := store.NewMemoryContentStore()

	resourceLit := mustE(types.ComputeLiteralData{
		Value: types.ResourceTarget{Targets: []string{"/peer/system/secret/x"}},
	}.ToEntity())
	resourceHash, _ := cs.Put(resourceLit)

	apply := mustE(types.ComputeApplyData{
		Path:      "system/tree",
		Operation: "get",
		Resource:  resourceHash,
	}.ToEntity())
	cs.Put(apply)

	result := auditSubgraph(apply, cs, "", "", auditConfig{})
	if result.Err != nil {
		t.Fatalf("unexpected audit error: %v", result.Err)
	}
	if len(result.HandlerTargets) != 1 {
		t.Fatalf("expected 1 handler target, got %d", len(result.HandlerTargets))
	}
	tgt := result.HandlerTargets[0]
	if tgt.Resource == nil {
		t.Fatal("expected static resource to be collected, got nil")
	}
	if len(tgt.Resource.Targets) != 1 || tgt.Resource.Targets[0] != "/peer/system/secret/x" {
		t.Fatalf("expected resource [/peer/system/secret/x], got %v", tgt.Resource.Targets)
	}
}

// F3: dynamic resource (non-literal expression) is deferred to runtime — the
// audit walker leaves Resource nil so the install-time check_grant_covers
// passes the resource dimension.
func TestAuditSubgraphDynamicResourceDeferred(t *testing.T) {
	cs := store.NewMemoryContentStore()

	// A lookup/scope is not a compute/literal — the static resolver returns nil.
	dynamicResource := mustE(types.ComputeLookupScopeData{Name: "target_path"}.ToEntity())
	resourceHash, _ := cs.Put(dynamicResource)

	apply := mustE(types.ComputeApplyData{
		Path:      "system/tree",
		Operation: "get",
		Resource:  resourceHash,
	}.ToEntity())
	cs.Put(apply)

	result := auditSubgraph(apply, cs, "", "", auditConfig{})
	if result.Err != nil {
		t.Fatalf("unexpected audit error: %v", result.Err)
	}
	if len(result.HandlerTargets) != 1 {
		t.Fatalf("expected 1 handler target, got %d", len(result.HandlerTargets))
	}
	if result.HandlerTargets[0].Resource != nil {
		t.Fatal("dynamic resource expression must leave handler target Resource nil for runtime")
	}
}

// F5 install-time: capability override without resource fails the audit walk.
func TestAuditSubgraphF5RejectsCapabilityWithoutResource(t *testing.T) {
	cs := store.NewMemoryContentStore()

	// A compute/literal capability — value doesn't matter for F5.
	capLit := mustE(types.ComputeLiteralData{Value: "anything"}.ToEntity())
	capHash, _ := cs.Put(capLit)

	apply := mustE(types.ComputeApplyData{
		Path:       "system/tree",
		Operation:  "get",
		Capability: capHash,
		// No Resource — F5 violation.
	}.ToEntity())
	cs.Put(apply)

	result := auditSubgraph(apply, cs, "", "", auditConfig{})
	if result.Err == nil {
		t.Fatal("expected audit error for capability without resource")
	}
	if result.Err.Code != ErrInvalidExpression {
		t.Fatalf("expected invalid_expression code, got %q", result.Err.Code)
	}
}
