package history

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

// unwrapEnvelope decodes a system/envelope entity response, returning the inner
// root entity and included map.
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

// setupHandlerTest creates a full test environment with recorder, handler, and indexes.
func setupHandlerTest(t *testing.T) (*Handler, *Recorder, store.ContentStore, *store.NotifyingLocationIndex, *store.NamespacedIndex) {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	events := make(chan store.TreeChangeEvent, 256)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	nli := store.NewNotifyingLocationIndex(li, events, done)
	recorder := NewRecorder(cs, testPeerID, nil)
	nli.AddNamedSyncHook("history-recorder", recorder.OnTreeChange)

	nsli := store.NewNamespacedIndex(nli, testPeerID)
	recorder.SetLocalPeerID(testPeerID, hash.Hash{})
	recorder.SetLocationIndex(nsli)

	h := NewHandler(cs, recorder)
	return h, recorder, cs, nli, nsli
}

func makeHandlerContext(cs store.ContentStore, li store.LocationIndex) *handler.HandlerContext {
	return &handler.HandlerContext{
		LocalPeerID:    crypto.PeerID(testPeerID),
		Store:          cs,
		LocationIndex:  li,
		HandlerPattern: "system/history",
	}
}

func TestHandlerQuery(t *testing.T) {
	h, recorder, cs, nli, nsli := setupHandlerTest(t)

	putConfig(t, nli, cs, "all", types.HistoryConfigData{
		Pattern: "*",
		Enabled: true,
	})
	recorder.Load()

	path := "/" + testPeerID + "/docs/report"

	// Write two versions.
	ent1 := makeTestEntity(t, "test/doc", "v1")
	h1, _ := cs.Put(ent1)
	nli.Set(path, h1)

	ent2 := makeTestEntity(t, "test/doc", "v2")
	h2, _ := cs.Put(ent2)
	nli.Set(path, h2)

	// Query history.
	params := types.HistoryQueryParamsData{Path: path}
	paramsEnt, err := params.ToEntity()
	if err != nil {
		t.Fatalf("params to entity: %v", err)
	}

	req := &handler.Request{
		Operation: "query",
		Params:    paramsEnt,
		Context:   makeHandlerContext(cs, nsli),
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("handle query: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status: got %d, want 200", resp.Status)
	}

	root, _ := unwrapEnvelope(t, resp)
	var result types.HistoryQueryResultData
	if err := ecf.Decode(root.Data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	if result.Path != path {
		t.Errorf("path: got %q, want %q", result.Path, path)
	}
	if len(result.Transitions) != 2 {
		t.Fatalf("transitions: got %d, want 2", len(result.Transitions))
	}
	// Newest first.
	if result.Transitions[0].Event != "updated" {
		t.Errorf("first transition event: got %q, want %q", result.Transitions[0].Event, "updated")
	}
	if result.Transitions[0].Hash != h2 {
		t.Errorf("first transition hash: got %s, want %s", result.Transitions[0].Hash, h2)
	}
	if result.Transitions[1].Event != "created" {
		t.Errorf("second transition event: got %q, want %q", result.Transitions[1].Event, "created")
	}
	if result.Transitions[1].Hash != h1 {
		t.Errorf("second transition hash: got %s, want %s", result.Transitions[1].Hash, h1)
	}
	if result.HasMore {
		t.Error("has_more should be false")
	}
}

func TestHandlerQueryLimit(t *testing.T) {
	h, recorder, cs, nli, nsli := setupHandlerTest(t)

	putConfig(t, nli, cs, "all", types.HistoryConfigData{
		Pattern: "*",
		Enabled: true,
	})
	recorder.Load()

	path := "/" + testPeerID + "/docs/report"

	// Write 5 versions.
	for i := 0; i < 5; i++ {
		ent := makeTestEntity(t, "test/doc", string(rune('a'+i)))
		h, _ := cs.Put(ent)
		nli.Set(path, h)
	}

	// Query with limit 2.
	limit := uint64(2)
	params := types.HistoryQueryParamsData{Path: path, Limit: &limit}
	paramsEnt, _ := params.ToEntity()

	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: "query",
		Params:    paramsEnt,
		Context:   makeHandlerContext(cs, nsli),
	})

	root, _ := unwrapEnvelope(t, resp)
	var result types.HistoryQueryResultData
	ecf.Decode(root.Data, &result)

	if len(result.Transitions) != 2 {
		t.Errorf("transitions: got %d, want 2", len(result.Transitions))
	}
	if !result.HasMore {
		t.Error("has_more should be true when limited")
	}
}

func TestHandlerQueryEventFilter(t *testing.T) {
	h, recorder, cs, nli, nsli := setupHandlerTest(t)

	putConfig(t, nli, cs, "all", types.HistoryConfigData{
		Pattern: "*",
		Enabled: true,
	})
	recorder.Load()

	path := "/" + testPeerID + "/docs/report"

	// Create, then update.
	ent1 := makeTestEntity(t, "test/doc", "v1")
	h1, _ := cs.Put(ent1)
	nli.Set(path, h1)

	ent2 := makeTestEntity(t, "test/doc", "v2")
	h2, _ := cs.Put(ent2)
	nli.Set(path, h2)

	// Query for only "created" events.
	params := types.HistoryQueryParamsData{
		Path:   path,
		Events: []string{"created"},
	}
	paramsEnt, _ := params.ToEntity()

	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: "query",
		Params:    paramsEnt,
		Context:   makeHandlerContext(cs, nsli),
	})

	root, _ := unwrapEnvelope(t, resp)
	var result types.HistoryQueryResultData
	ecf.Decode(root.Data, &result)

	if len(result.Transitions) != 1 {
		t.Fatalf("transitions: got %d, want 1 (only created)", len(result.Transitions))
	}
	if result.Transitions[0].Event != "created" {
		t.Errorf("event: got %q, want %q", result.Transitions[0].Event, "created")
	}
	_ = h2
}

func TestHandlerQueryNoHistory(t *testing.T) {
	h, _, cs, _, nsli := setupHandlerTest(t)

	// Query a path with no history.
	params := types.HistoryQueryParamsData{Path: "/" + testPeerID + "/nonexistent"}
	paramsEnt, _ := params.ToEntity()

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "query",
		Params:    paramsEnt,
		Context:   makeHandlerContext(cs, nsli),
	})

	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status: got %d, want 200", resp.Status)
	}

	root, _ := unwrapEnvelope(t, resp)
	var result types.HistoryQueryResultData
	ecf.Decode(root.Data, &result)

	if len(result.Transitions) != 0 {
		t.Errorf("transitions: got %d, want 0", len(result.Transitions))
	}
	if result.HasMore {
		t.Error("has_more should be false")
	}
}

func TestHandlerRollback(t *testing.T) {
	h, recorder, cs, nli, nsli := setupHandlerTest(t)

	putConfig(t, nli, cs, "all", types.HistoryConfigData{
		Pattern: "*",
		Enabled: true,
	})
	recorder.Load()

	path := "/" + testPeerID + "/docs/report"

	// Write two versions.
	ent1 := makeTestEntity(t, "test/doc", "original")
	h1, _ := cs.Put(ent1)
	nli.Set(path, h1)

	ent2 := makeTestEntity(t, "test/doc", "modified")
	h2, _ := cs.Put(ent2)
	nli.Set(path, h2)
	_ = h2

	// Verify current binding is h2.
	currentHash, _ := nsli.Get(path)
	if currentHash != h2 {
		t.Fatalf("current binding should be h2")
	}

	// Rollback to h1.
	params := types.HistoryRollbackParamsData{
		Path:       path,
		TargetHash: h1,
	}
	paramsEnt, _ := params.ToEntity()

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "rollback",
		Params:    paramsEnt,
		Context:   makeHandlerContext(cs, nsli),
	})
	if err != nil {
		t.Fatalf("handle rollback: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status: got %d, want 200", resp.Status)
	}

	// Verify binding is now h1.
	restoredHash, _ := nsli.Get(path)
	if restoredHash != h1 {
		t.Errorf("binding after rollback: got %s, want %s", restoredHash, h1)
	}

	// Verify a new transition was recorded for the rollback.
	headPath := "/" + testPeerID + "/" + HeadPointerPath(path)
	headHash, _ := nli.Get(headPath)
	transEnt, _ := cs.Get(headHash)
	td, _ := types.TransitionDataFromEntity(transEnt)
	if td.Event != "updated" {
		t.Errorf("rollback transition event: got %q, want %q", td.Event, "updated")
	}
	if td.Hash != h1 {
		t.Errorf("rollback transition hash: got %s, want %s", td.Hash, h1)
	}
}

func TestHandlerRollbackNotInHistory(t *testing.T) {
	h, recorder, cs, nli, nsli := setupHandlerTest(t)

	putConfig(t, nli, cs, "all", types.HistoryConfigData{
		Pattern: "*",
		Enabled: true,
	})
	recorder.Load()

	path := "/" + testPeerID + "/docs/report"

	// Write one version.
	ent := makeTestEntity(t, "test/doc", "hello")
	entHash, _ := cs.Put(ent)
	nli.Set(path, entHash)

	// Try to rollback to a hash that's NOT in history.
	fakeEntity := makeTestEntity(t, "test/doc", "fake")
	fakeHash, _ := cs.Put(fakeEntity)

	params := types.HistoryRollbackParamsData{
		Path:       path,
		TargetHash: fakeHash,
	}
	paramsEnt, _ := params.ToEntity()

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "rollback",
		Params:    paramsEnt,
		Context:   makeHandlerContext(cs, nsli),
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if resp.Status != 404 {
		t.Errorf("status: got %d, want 404", resp.Status)
	}
}

func TestHandlerManifest(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h := NewHandler(cs, nil)

	manifest := h.Manifest()
	if manifest.Pattern != "system/history" {
		t.Errorf("pattern: got %q, want %q", manifest.Pattern, "system/history")
	}
	if manifest.Name != "history" {
		t.Errorf("name: got %q, want %q", manifest.Name, "history")
	}
	if _, ok := manifest.Operations["query"]; !ok {
		t.Error("missing query operation")
	}
	if _, ok := manifest.Operations["rollback"]; !ok {
		t.Error("missing rollback operation")
	}
}

func TestHandlerQueryShortFormPath(t *testing.T) {
	h, recorder, cs, nli, nsli := setupHandlerTest(t)

	putConfig(t, nli, cs, "all", types.HistoryConfigData{
		Pattern: "*",
		Enabled: true,
	})
	recorder.Load()

	// Write using absolute path.
	ent := makeTestEntity(t, "test/doc", "hello")
	entHash, _ := cs.Put(ent)
	absPath := "/" + testPeerID + "/docs/report"
	nli.Set(absPath, entHash)

	// Query using short-form path — should be canonicalized.
	params := types.HistoryQueryParamsData{Path: "docs/report"}
	paramsEnt, _ := params.ToEntity()

	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: "query",
		Params:    paramsEnt,
		Context:   makeHandlerContext(cs, nsli),
	})

	root, _ := unwrapEnvelope(t, resp)
	var result types.HistoryQueryResultData
	ecf.Decode(root.Data, &result)

	if result.Path != absPath {
		t.Errorf("result path: got %q, want %q", result.Path, absPath)
	}
	if len(result.Transitions) != 1 {
		t.Errorf("transitions: got %d, want 1", len(result.Transitions))
	}
}

func TestHandlerRegisterTypes(t *testing.T) {
	cs := store.NewMemoryContentStore()
	h := NewHandler(cs, nil)

	reg := types.NewTypeRegistry()
	types.RegisterCoreTypes(reg)
	h.RegisterTypes(reg)

	// Check that all 6 history types are registered.
	expectedTypes := []string{
		types.TypeHistoryTransition,
		types.TypeHistoryConfig,
		types.TypeHistoryQueryParams,
		types.TypeHistoryQueryResult,
		types.TypeHistoryRollbackParams,
		types.TypeHistoryRollbackResult,
	}
	for _, tn := range expectedTypes {
		if _, ok := reg.Get(tn); !ok {
			t.Errorf("type %q not registered", tn)
		}
	}
}

// TestHandlerRollbackCreatesTransition verifies that rollback creates a new
// history transition (since it goes through normal Set).
func TestHandlerRollbackCreatesTransition(t *testing.T) {
	h, recorder, cs, nli, nsli := setupHandlerTest(t)

	putConfig(t, nli, cs, "all", types.HistoryConfigData{
		Pattern: "*",
		Enabled: true,
	})
	recorder.Load()

	path := "/" + testPeerID + "/docs/report"

	// Write v1, v2, v3.
	var hashes [3]entity.Entity
	var hashVals [3]interface{}
	_ = hashes
	_ = hashVals
	ent1 := makeTestEntity(t, "test/doc", "v1")
	h1, _ := cs.Put(ent1)
	nli.Set(path, h1)

	ent2 := makeTestEntity(t, "test/doc", "v2")
	h2, _ := cs.Put(ent2)
	nli.Set(path, h2)

	ent3 := makeTestEntity(t, "test/doc", "v3")
	h3, _ := cs.Put(ent3)
	nli.Set(path, h3)
	_ = h3

	// Rollback to v1.
	params := types.HistoryRollbackParamsData{Path: path, TargetHash: h1}
	paramsEnt, _ := params.ToEntity()
	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: "rollback",
		Params:    paramsEnt,
		Context:   makeHandlerContext(cs, nsli),
	})
	if resp.Status != 200 {
		t.Fatalf("rollback failed: status %d", resp.Status)
	}

	// Query full history — should have 4 transitions: rollback + v3 + v2 + v1.
	qParams := types.HistoryQueryParamsData{Path: path}
	qParamsEnt, _ := qParams.ToEntity()
	qResp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: "query",
		Params:    qParamsEnt,
		Context:   makeHandlerContext(cs, nsli),
	})

	root, _ := unwrapEnvelope(t, qResp)
	var result types.HistoryQueryResultData
	ecf.Decode(root.Data, &result)

	if len(result.Transitions) != 4 {
		t.Errorf("transitions after rollback: got %d, want 4", len(result.Transitions))
	}
	// Most recent should be the rollback write (updated, hash=h1).
	if len(result.Transitions) >= 1 {
		latest := result.Transitions[0]
		if latest.Event != "updated" {
			t.Errorf("latest event: got %q, want %q", latest.Event, "updated")
		}
		if latest.Hash != h1 {
			t.Errorf("latest hash: got %s, want %s (rolled back to v1)", latest.Hash, h1)
		}
		if latest.PreviousHash != h3 {
			t.Errorf("latest previous_hash: got %s, want %s (was v3)", latest.PreviousHash, h3)
		}
	}
}
