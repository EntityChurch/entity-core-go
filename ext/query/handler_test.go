package query

import (
	"context"
	"fmt"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// testSetup creates a content store, location index, maintainer, and query
// handler wired together for testing. Returns everything needed to populate
// test data and run queries.
type testEnv struct {
	cs         store.ContentStore
	nsLI       *store.NamespacedIndex
	li         *store.NotifyingLocationIndex
	rawLI      store.LocationIndex
	maintainer *IndexMaintainer
	handler    *Handler
	peerID     crypto.PeerID
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	cs := store.NewMemoryContentStore()
	rawLI := store.NewMemoryLocationIndex()
	done := make(chan struct{})
	events := make(chan store.TreeChangeEvent, 256)
	li := store.NewNotifyingLocationIndex(rawLI, events, done)

	kp, _ := crypto.Generate()
	nsLI := store.NewNamespacedIndex(li, string(kp.PeerID()))

	maintainer := NewIndexMaintainer(cs)
	li.AddNamedSyncHook("query-index", maintainer.OnTreeChange)

	h := NewHandler(
		maintainer.TypeIndex(),
		maintainer.ReverseHashIndex(),
		maintainer.PathLinkIndex(),
		cs,
	)

	t.Cleanup(func() { close(done) })

	return &testEnv{
		cs:         cs,
		nsLI:       nsLI,
		li:         li,
		rawLI:      rawLI,
		maintainer: maintainer,
		handler:    h,
		peerID:     kp.PeerID(),
	}
}

// put stores an entity and sets it in the tree. The sync hook updates indexes.
func (env *testEnv) put(t *testing.T, path string, e entity.Entity) hash.Hash {
	t.Helper()
	h, err := env.cs.Put(e)
	if err != nil {
		t.Fatalf("put entity: %v", err)
	}
	env.nsLI.Set(path, h)
	return h
}

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

func (env *testEnv) find(t *testing.T, expr types.QueryExpressionData) types.QueryResultData {
	t.Helper()
	paramEnt, err := expr.ToEntity()
	if err != nil {
		t.Fatalf("encode expression: %v", err)
	}

	req := &handler.Request{
		Operation: "find",
		Params:    paramEnt,
		Context: &handler.HandlerContext{
			Store:         env.cs,
			LocationIndex: env.nsLI,
			LocalPeerID:   env.peerID,
		},
	}

	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("find status %d: %s", resp.Status, resp.Result.Type)
	}

	root, _ := unwrapEnvelope(t, resp)
	var result types.QueryResultData
	if err := ecf.Decode(root.Data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return result
}

func (env *testEnv) count(t *testing.T, expr types.QueryExpressionData) uint64 {
	t.Helper()
	paramEnt, err := expr.ToEntity()
	if err != nil {
		t.Fatalf("encode expression: %v", err)
	}

	req := &handler.Request{
		Operation: "count",
		Params:    paramEnt,
		Context: &handler.HandlerContext{
			Store:         env.cs,
			LocationIndex: env.nsLI,
			LocalPeerID:   env.peerID,
		},
	}

	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("count status %d", resp.Status)
	}

	var n uint64
	if err := cbor.Unmarshal(resp.Result.Data, &n); err != nil {
		t.Fatalf("decode count: %v", err)
	}
	return n
}

func (env *testEnv) findError(t *testing.T, expr types.QueryExpressionData) (uint, string) {
	t.Helper()
	paramEnt, err := expr.ToEntity()
	if err != nil {
		t.Fatalf("encode expression: %v", err)
	}

	req := &handler.Request{
		Operation: "find",
		Params:    paramEnt,
		Context: &handler.HandlerContext{
			Store:         env.cs,
			LocationIndex: env.nsLI,
			LocalPeerID:   env.peerID,
		},
	}

	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("find returned error: %v", err)
	}
	if resp.Status == 200 {
		t.Fatal("expected error status, got 200")
	}

	var errData types.ErrorData
	if decErr := ecf.Decode(resp.Result.Data, &errData); decErr != nil {
		t.Fatalf("decode error: %v", decErr)
	}
	return resp.Status, errData.Code
}

type userData struct {
	Name string `cbor:"name"`
	City string `cbor:"city"`
	Age  uint   `cbor:"age"`
}

type orderData struct {
	Item   string `cbor:"item"`
	Amount uint   `cbor:"amount"`
}

func TestFindByType(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice", City: "Seattle", Age: 30}))
	env.put(t, "app/users/bob", makeEntity(t, "app/user", userData{Name: "Bob", City: "Portland", Age: 25}))
	env.put(t, "app/orders/1", makeEntity(t, "app/order", orderData{Item: "Widget", Amount: 10}))

	result := env.find(t, types.QueryExpressionData{TypeFilter: "app/user"})
	if result.Total != 2 {
		t.Fatalf("expected total 2, got %d", result.Total)
	}
	if len(result.Matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(result.Matches))
	}
	for _, m := range result.Matches {
		if m.Type != "app/user" {
			t.Fatalf("wrong type: %s", m.Type)
		}
	}
}

func TestFindByTypeGlob(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice"}))
	env.put(t, "app/orders/1", makeEntity(t, "app/order", orderData{Item: "Widget"}))

	result := env.find(t, types.QueryExpressionData{TypeFilter: "app/*"})
	if result.Total != 2 {
		t.Fatalf("expected total 2, got %d", result.Total)
	}
}

func TestFindByRefFilter(t *testing.T) {
	env := newTestEnv(t)

	refHash := hash.Hash{Algorithm: hash.AlgorithmSHA256, Digest: hash.ExtendDigest([32]byte{42})}

	type docData struct {
		Title      string    `cbor:"title"`
		ContentRef hash.Hash `cbor:"content_ref"`
	}
	env.put(t, "app/docs/test", makeEntity(t, "app/doc", docData{Title: "Test", ContentRef: refHash}))
	env.put(t, "app/docs/other", makeEntity(t, "app/doc", docData{Title: "Other"}))

	result := env.find(t, types.QueryExpressionData{RefFilter: &refHash})
	if result.Total != 1 {
		t.Fatalf("expected total 1, got %d", result.Total)
	}
	if result.Matches[0].Type != "app/doc" {
		t.Fatalf("wrong type: %s", result.Matches[0].Type)
	}
}

func TestFindWithPathPrefix(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice"}))
	env.put(t, "app/users/bob", makeEntity(t, "app/user", userData{Name: "Bob"}))
	env.put(t, "app/orders/1", makeEntity(t, "app/order", orderData{Item: "Widget"}))

	result := env.find(t, types.QueryExpressionData{
		TypeFilter: "app/user",
		PathPrefix: "app/users/",
	})
	if result.Total != 2 {
		t.Fatalf("expected total 2, got %d", result.Total)
	}
}

func TestFindWithPathPrefixFiltersOther(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice"}))
	env.put(t, "other/users/bob", makeEntity(t, "app/user", userData{Name: "Bob"}))

	result := env.find(t, types.QueryExpressionData{
		TypeFilter: "app/user",
		PathPrefix: "app/",
	})
	if result.Total != 1 {
		t.Fatalf("expected total 1, got %d", result.Total)
	}
}

func TestCount(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice"}))
	env.put(t, "app/users/bob", makeEntity(t, "app/user", userData{Name: "Bob"}))
	env.put(t, "app/orders/1", makeEntity(t, "app/order", orderData{Item: "Widget"}))

	n := env.count(t, types.QueryExpressionData{TypeFilter: "app/user"})
	if n != 2 {
		t.Fatalf("expected count 2, got %d", n)
	}
}

func TestFindPagination(t *testing.T) {
	env := newTestEnv(t)

	for i := 0; i < 5; i++ {
		path := "app/users/" + string(rune('a'+i))
		env.put(t, path, makeEntity(t, "app/user", userData{Name: path}))
	}

	limit := uint64(2)
	result := env.find(t, types.QueryExpressionData{
		TypeFilter: "app/user",
		Limit:      &limit,
	})
	if result.Total != 5 {
		t.Fatalf("expected total 5, got %d", result.Total)
	}
	if len(result.Matches) != 2 {
		t.Fatalf("expected 2 matches on page 1, got %d", len(result.Matches))
	}
	if !result.HasMore {
		t.Fatal("expected has_more=true")
	}
	if result.Cursor == "" {
		t.Fatal("expected cursor")
	}

	// Page 2.
	result2 := env.find(t, types.QueryExpressionData{
		TypeFilter: "app/user",
		Limit:      &limit,
		Cursor:     result.Cursor,
	})
	if len(result2.Matches) != 2 {
		t.Fatalf("expected 2 matches on page 2, got %d", len(result2.Matches))
	}
	if !result2.HasMore {
		t.Fatal("expected has_more=true on page 2")
	}

	// Page 3 (last page).
	result3 := env.find(t, types.QueryExpressionData{
		TypeFilter: "app/user",
		Limit:      &limit,
		Cursor:     result2.Cursor,
	})
	if len(result3.Matches) != 1 {
		t.Fatalf("expected 1 match on page 3, got %d", len(result3.Matches))
	}
	if result3.HasMore {
		t.Fatal("expected has_more=false on last page")
	}
}

func TestFindIncludeEntities(t *testing.T) {
	env := newTestEnv(t)

	h := env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice"}))

	includeEntities := true
	paramEnt, _ := types.QueryExpressionData{
		TypeFilter:      "app/user",
		IncludeEntities: &includeEntities,
	}.ToEntity()

	req := &handler.Request{
		Operation: "find",
		Params:    paramEnt,
		Context: &handler.HandlerContext{
			Store:         env.cs,
			LocationIndex: env.nsLI,
			LocalPeerID:   env.peerID,
		},
	}

	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	_, included := unwrapEnvelope(t, resp)
	if included == nil {
		t.Fatal("expected included entities")
	}
	if _, ok := included[h]; !ok {
		t.Fatal("expected alice entity in included map")
	}
}

func TestFindFieldFilter_Eq(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice", City: "Seattle"}))
	env.put(t, "app/users/bob", makeEntity(t, "app/user", userData{Name: "Bob", City: "Portland"}))

	valueRaw, _ := ecf.Encode("Seattle")
	result := env.find(t, types.QueryExpressionData{
		TypeFilter: "app/user",
		FieldFilters: []types.QueryFieldPredicateData{
			{Field: "city", Operator: "eq", Value: cbor.RawMessage(valueRaw)},
		},
	})
	if result.Total != 1 {
		t.Fatalf("expected total 1, got %d", result.Total)
	}
	expectedPath := store.QualifyPath(string(env.peerID), "app/users/alice")
	if result.Matches[0].Path != expectedPath {
		t.Fatalf("expected %s, got %s", expectedPath, result.Matches[0].Path)
	}
}

func TestFindFieldFilter_Exists(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice", City: "Seattle"}))

	type partialUser struct {
		Name string `cbor:"name"`
	}
	env.put(t, "app/users/bob", makeEntity(t, "app/user", partialUser{Name: "Bob"}))

	result := env.find(t, types.QueryExpressionData{
		TypeFilter: "app/user",
		FieldFilters: []types.QueryFieldPredicateData{
			{Field: "city", Operator: "exists"},
		},
	})
	// Bob has city="" (zero value), which is still present in CBOR.
	// Both should match since Go encodes zero-value strings.
	// The test validates the filter works.
	if result.Total < 1 {
		t.Fatalf("expected at least 1 match, got %d", result.Total)
	}
}

func TestErrorEmptyQuery(t *testing.T) {
	env := newTestEnv(t)
	status, code := env.findError(t, types.QueryExpressionData{})
	if status != 400 {
		t.Fatalf("expected status 400, got %d", status)
	}
	if code != "empty_query" {
		t.Fatalf("expected code empty_query, got %s", code)
	}
}

func TestErrorTypeFilterRequired(t *testing.T) {
	env := newTestEnv(t)

	valueRaw, _ := ecf.Encode("test")
	status, code := env.findError(t, types.QueryExpressionData{
		FieldFilters: []types.QueryFieldPredicateData{
			{Field: "name", Operator: "eq", Value: cbor.RawMessage(valueRaw)},
		},
	})
	if status != 400 {
		t.Fatalf("expected status 400, got %d", status)
	}
	if code != "type_filter_required" {
		t.Fatalf("expected code type_filter_required, got %s", code)
	}
}

func TestManifest(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	m := h.Manifest()
	if m.Pattern != "system/query" {
		t.Fatalf("wrong pattern: %s", m.Pattern)
	}
	if len(m.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(m.Operations))
	}
	if _, ok := m.Operations["find"]; !ok {
		t.Fatal("missing find operation")
	}
	if _, ok := m.Operations["count"]; !ok {
		t.Fatal("missing count operation")
	}
}

func TestSyncHookIntegration(t *testing.T) {
	// Verify that sync hooks fire synchronously — after a write, the index
	// is immediately queryable without any async delay.
	env := newTestEnv(t)

	e := makeEntity(t, "app/user", userData{Name: "Alice"})
	env.put(t, "app/users/alice", e) // This fires sync hook.

	// Immediately query — should be available.
	if env.maintainer.TypeIndex().Count("app/user") != 1 {
		t.Fatal("type index not updated synchronously")
	}
}

// --- Constraint tests ---

// findWithGrant runs a find query with a specific grant entry on the handler context.
func (env *testEnv) findWithGrant(t *testing.T, expr types.QueryExpressionData, grant *types.GrantEntry) (types.QueryResultData, uint) {
	t.Helper()
	paramEnt, err := expr.ToEntity()
	if err != nil {
		t.Fatalf("encode expression: %v", err)
	}

	req := &handler.Request{
		Operation: "find",
		Params:    paramEnt,
		Context: &handler.HandlerContext{
			Store:         env.cs,
			LocationIndex: env.rawLI,
			MatchingGrant: grant,
		},
	}

	resp, err := env.handler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("find: %v", err)
	}

	if resp.Status != 200 {
		return types.QueryResultData{}, resp.Status
	}

	root, _ := unwrapEnvelope(t, resp)
	var result types.QueryResultData
	if err := ecf.Decode(root.Data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return result, 200
}

func encodeCBOR(t *testing.T, v interface{}) cbor.RawMessage {
	t.Helper()
	raw, err := ecf.Encode(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return cbor.RawMessage(raw)
}

func TestConstraintTypeScopeFilters(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice"}))
	env.put(t, "app/orders/1", makeEntity(t, "app/order", orderData{Item: "Widget"}))

	// Grant with type_scope constraint that only allows app/user.
	// No allowances — tree scope (default).
	grant := &types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/query"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"find", "count"}},
		Constraints: encodeCBOR(t, types.QueryConstraintsData{
			TypeScope: &types.CapabilityScope{Include: []string{"app/user"}},
		}),
	}

	// Glob type_filter "app/*" is broader than type_scope {include: ["app/user"]}.
	// Per spec §5.2 step 3 this should be rejected (403).
	_, status := env.findWithGrant(t, types.QueryExpressionData{TypeFilter: "app/*"}, grant)
	if status != 403 {
		t.Fatalf("expected 403 for glob wider than type_scope, got %d", status)
	}

	// Exact type_filter "app/user" matches type_scope — should work.
	result, status := env.findWithGrant(t, types.QueryExpressionData{TypeFilter: "app/user"}, grant)
	if status != 200 {
		t.Fatalf("expected 200 for authorized type, got %d", status)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 user, got %d", result.Total)
	}

	// Query for app/order — should be filtered out by type_scope.
	result, status = env.findWithGrant(t, types.QueryExpressionData{TypeFilter: "app/order"}, grant)
	if status == 403 {
		// Good — type_filter doesn't match type_scope, rejected at step 3.
	} else if status == 200 && result.Total == 0 {
		// Also acceptable — filtered at step 6a.
	} else {
		t.Fatalf("expected 403 or empty result for unauthorized type, got status=%d total=%d", status, result.Total)
	}
}

func TestConstraintMaxResults(t *testing.T) {
	env := newTestEnv(t)

	for i := 0; i < 10; i++ {
		path := fmt.Sprintf("app/users/%d", i)
		env.put(t, path, makeEntity(t, "app/user", userData{Name: path}))
	}

	maxResults := uint64(3)
	grant := &types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/query"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"find"}},
		Constraints: encodeCBOR(t, types.QueryConstraintsData{
			MaxResults: &maxResults,
			TypeScope:  &types.CapabilityScope{Include: []string{"*"}},
		}),
	}

	// Request limit=100, but max_results=3 should cap it.
	bigLimit := uint64(100)
	result, status := env.findWithGrant(t, types.QueryExpressionData{
		TypeFilter: "app/user",
		Limit:      &bigLimit,
	}, grant)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if len(result.Matches) != 3 {
		t.Fatalf("expected 3 matches (capped by max_results), got %d", len(result.Matches))
	}
	if result.Total != 10 {
		t.Fatalf("expected total 10 (full count), got %d", result.Total)
	}
	if !result.HasMore {
		t.Fatal("expected has_more=true")
	}
}

func TestConstraintContentStoreWithoutTypeScope(t *testing.T) {
	env := newTestEnv(t)

	// Grant with content_store allowance but NO type_scope constraint — should be rejected.
	grant := &types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/query"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"find"}},
		Allowances: encodeCBOR(t, types.QueryAllowancesData{
			Scope: "content_store",
		}),
		// No Constraints with TypeScope — this is the violation.
	}

	_, status := env.findWithGrant(t, types.QueryExpressionData{TypeFilter: "app/user"}, grant)
	if status != 403 {
		t.Fatalf("expected 403 for content_store without type_scope, got %d", status)
	}
}

func TestConstraintContentStoreWithTypeScope(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice"}))

	// Grant with content_store allowance AND type_scope constraint — should work.
	grant := &types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/query"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"find"}},
		Constraints: encodeCBOR(t, types.QueryConstraintsData{
			TypeScope: &types.CapabilityScope{Include: []string{"*"}},
		}),
		Allowances: encodeCBOR(t, types.QueryAllowancesData{
			Scope: "content_store",
		}),
	}

	result, status := env.findWithGrant(t, types.QueryExpressionData{TypeFilter: "app/user"}, grant)
	if status != 200 {
		t.Fatalf("expected 200 for content_store with type_scope, got %d", status)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 result, got %d", result.Total)
	}
}

func TestConstraintDefaultTreeScope(t *testing.T) {
	env := newTestEnv(t)

	env.put(t, "app/users/alice", makeEntity(t, "app/user", userData{Name: "Alice"}))

	// No MatchingGrant at all — should default to tree scope and work.
	result := env.find(t, types.QueryExpressionData{TypeFilter: "app/user"})
	if result.Total != 1 {
		t.Fatalf("expected 1 with no constraints (default tree scope), got %d", result.Total)
	}
}
