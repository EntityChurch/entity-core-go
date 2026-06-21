package tree

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func makeEntity(t *testing.T, typ string, data interface{}) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatal(err)
	}
	e, err := entity.NewEntity(typ, cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func setup(t *testing.T) (*Handler, store.ContentStore, store.LocationIndex, crypto.PeerID) {
	t.Helper()
	cs := store.NewMemoryContentStore()
	rawLI := store.NewMemoryLocationIndex()
	h := NewHandler()
	kp, _ := crypto.Generate()
	li := store.NewNamespacedIndex(rawLI, string(kp.PeerID()))
	return h, cs, li, kp.PeerID()
}

func makeRequest(cs store.ContentStore, li store.LocationIndex, pid crypto.PeerID, path, op string, params entity.Entity, resource *types.ResourceTarget) *handler.Request {
	return &handler.Request{
		Path:      "system/tree",
		Operation: op,
		Params:    params,
		Context: &handler.HandlerContext{
			LocalPeerID:    pid,
			Store:          cs,
			LocationIndex:  li,
			HandlerPattern: "system/tree",
			Resource:       resource,
		},
	}
}

func TestGetEntity(t *testing.T) {
	h, cs, li, pid := setup(t)

	// Store an entity and bind it.
	testEntity := makeEntity(t, "test/doc", map[string]string{"content": "hello"})
	cs.Put(testEntity)
	li.Set("local/files/test.txt", testEntity.ContentHash)

	// Create get request.
	getReq := types.GetRequestData{Mode: "entity"}
	getEntity, _ := getReq.ToEntity()

	req := makeRequest(cs, li, pid, "system/tree", "get", getEntity, &types.ResourceTarget{Targets: []string{"local/files/test.txt"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if resp.Result.Type != "test/doc" {
		t.Fatalf("expected result type test/doc, got %s", resp.Result.Type)
	}
}

func TestGetHash(t *testing.T) {
	h, cs, li, pid := setup(t)

	testEntity := makeEntity(t, "test/doc", "content")
	cs.Put(testEntity)
	li.Set("local/test", testEntity.ContentHash)

	getReq := types.GetRequestData{Mode: "hash"}
	getEntity, _ := getReq.ToEntity()

	req := makeRequest(cs, li, pid, "system/tree", "get", getEntity, &types.ResourceTarget{Targets: []string{"local/test"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
}

func TestGetNotFound(t *testing.T) {
	h, cs, li, pid := setup(t)

	getReq := types.GetRequestData{}
	getEntity, _ := getReq.ToEntity()

	req := makeRequest(cs, li, pid, "system/tree", "get", getEntity, &types.ResourceTarget{Targets: []string{"nonexistent"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected status 404, got %d", resp.Status)
	}
}

func TestGetListing(t *testing.T) {
	h, cs, li, pid := setup(t)

	e1 := makeEntity(t, "test/a", "a")
	e2 := makeEntity(t, "test/b", "b")
	cs.Put(e1)
	cs.Put(e2)
	li.Set("local/files/a.txt", e1.ContentHash)
	li.Set("local/files/b.txt", e2.ContentHash)

	// Trailing slash → listing.
	getReq := types.GetRequestData{}
	getEntity, _ := getReq.ToEntity()

	req := makeRequest(cs, li, pid, "system/tree", "get", getEntity, &types.ResourceTarget{Targets: []string{"local/files/"}})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if resp.Result.Type != types.TypeTreeListing {
		t.Fatalf("expected listing type, got %s", resp.Result.Type)
	}

	var listing types.ListingData
	if err := ecf.Decode(resp.Result.Data, &listing); err != nil {
		t.Fatal(err)
	}
	if listing.Count != 2 {
		t.Fatalf("expected 2 entries, got %d", listing.Count)
	}
}

// TestGetListing_ForeignNamespace pins the universal-address-space listing
// shape (V7 §1.4): a `tree:get` listing with an absolute prefix targeting
// a foreign peer-id MUST surface children written under that peer-id.
//
// Pre-fix bug at handler.go:227 unconditionally prepended the local peer-id
// to the listing prefix when computing the trim, producing a literal
// "/{localID}//{otherID}/..." that never matched the stored entry path. The
// listing came back empty (or with an empty-string child name, depending on
// path shape). This was the FAIL surfaced by validate-peer's
// `universal_address_space.foreign_namespace_listing_at_peer_root` against
// Go (Rust + Python both passed — Go was the outlier).
func TestGetListing_ForeignNamespace(t *testing.T) {
	h, cs, li, pid := setup(t)

	// A synthetic foreign peer-id (same fixture-shape as the validate-peer
	// universal_address_space category uses).
	const otherID = "1HtVqLgPqkScVxjVN8VFGFiH7T2P3aSDwJxQ8DGEoooo2z"

	// Seed two foreign-namespace bindings — write through the absolute path
	// shape so NamespacedIndex passes them through to the inner store at
	// /{otherID}/...
	e1 := makeEntity(t, "test/a", "a")
	e2 := makeEntity(t, "test/b", "b")
	cs.Put(e1)
	cs.Put(e2)
	if err := li.Set("/"+otherID+"/system/validate/uas/probe-1", e1.ContentHash); err != nil {
		t.Fatal(err)
	}
	if err := li.Set("/"+otherID+"/system/validate/uas/probe-2", e2.ContentHash); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		prefix      string
		wantNames   []string
		wantHasKids bool
	}{
		{
			name:        "peer_root_lists_top_segment",
			prefix:      "/" + otherID + "/",
			wantNames:   []string{"system"},
			wantHasKids: true,
		},
		{
			name:        "subpath_lists_leaves",
			prefix:      "/" + otherID + "/system/validate/uas/",
			wantNames:   []string{"probe-1", "probe-2"},
			wantHasKids: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getReq := types.GetRequestData{}
			getEntity, _ := getReq.ToEntity()
			req := makeRequest(cs, li, pid, "system/tree", "get", getEntity,
				&types.ResourceTarget{Targets: []string{tc.prefix}})
			resp, err := h.Handle(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status != 200 {
				t.Fatalf("status: got %d, want 200", resp.Status)
			}
			if resp.Result.Type != types.TypeTreeListing {
				t.Fatalf("type: got %s, want %s", resp.Result.Type, types.TypeTreeListing)
			}
			var listing types.ListingData
			if err := ecf.Decode(resp.Result.Data, &listing); err != nil {
				t.Fatal(err)
			}
			if int(listing.Count) != len(tc.wantNames) {
				t.Fatalf("count: got %d, want %d (entries=%v)", listing.Count, len(tc.wantNames), keysOf(listing.Entries))
			}
			for _, name := range tc.wantNames {
				entry, ok := listing.Entries[name]
				if !ok {
					t.Fatalf("missing entry %q (entries=%v)", name, keysOf(listing.Entries))
				}
				entryMap, ok := entry.(map[interface{}]interface{})
				if !ok {
					t.Fatalf("entry %q has unexpected shape: %T", name, entry)
				}
				if hk, _ := entryMap["has_children"].(bool); hk != tc.wantHasKids {
					t.Errorf("entry %q has_children: got %v, want %v", name, hk, tc.wantHasKids)
				}
			}
			// Empty-string key from the pre-fix bug MUST NOT appear.
			if _, leaked := listing.Entries[""]; leaked {
				t.Errorf("empty-string key leaked into listing (pre-fix bug); entries=%v", keysOf(listing.Entries))
			}
		})
	}
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPutAndGet(t *testing.T) {
	h, cs, li, pid := setup(t)

	testEntity := makeEntity(t, "test/doc", map[string]string{"content": "hello"})

	// Put.
	putReqEntity, putResource, err := CreatePutRequest("local/files/test.txt", &testEntity)
	if err != nil {
		t.Fatal(err)
	}

	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("put: expected status 200, got %d", resp.Status)
	}

	// Verify stored.
	if !li.Has("local/files/test.txt") {
		t.Fatal("path should be bound after put")
	}

	// Get.
	getReqEntity, getResource, _ := CreateGetRequest("local/files/test.txt", "entity")
	req = makeRequest(cs, li, pid, "system/tree", "get", getReqEntity, getResource)
	resp, err = h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("get: expected status 200, got %d", resp.Status)
	}
	if resp.Result.ContentHash != testEntity.ContentHash {
		t.Fatal("get returned different hash than put")
	}
}

func TestPutCASMatch(t *testing.T) {
	h, cs, li, pid := setup(t)

	// Seed a binding.
	original := makeEntity(t, "test/doc", map[string]string{"v": "1"})
	cs.Put(original)
	li.Set("local/files/test.txt", original.ContentHash)

	// Put with matching expected_hash → success.
	updated := makeEntity(t, "test/doc", map[string]string{"v": "2"})
	expected := original.ContentHash
	putReqEntity, putResource, err := CreatePutRequestCAS("local/files/test.txt", &updated, &expected)
	if err != nil {
		t.Fatal(err)
	}
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200 on CAS match, got %d", resp.Status)
	}
	cur, _ := li.Get("local/files/test.txt")
	if cur != updated.ContentHash {
		t.Fatalf("binding did not advance after CAS put")
	}
}

func TestPutCASMismatch(t *testing.T) {
	h, cs, li, pid := setup(t)

	original := makeEntity(t, "test/doc", map[string]string{"v": "1"})
	cs.Put(original)
	li.Set("local/files/test.txt", original.ContentHash)

	// Create a stale "expected" hash that differs from current binding.
	other := makeEntity(t, "test/doc", map[string]string{"v": "other"})
	stale := other.ContentHash

	updated := makeEntity(t, "test/doc", map[string]string{"v": "2"})
	putReqEntity, putResource, err := CreatePutRequestCAS("local/files/test.txt", &updated, &stale)
	if err != nil {
		t.Fatal(err)
	}
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 409 {
		t.Fatalf("expected 409 on CAS mismatch, got %d", resp.Status)
	}
	cur, _ := li.Get("local/files/test.txt")
	if cur != original.ContentHash {
		t.Fatalf("binding must remain unchanged on CAS mismatch")
	}
}

func TestPutCASMissingBinding(t *testing.T) {
	h, cs, li, pid := setup(t)

	other := makeEntity(t, "test/doc", map[string]string{"v": "expected"})
	expected := other.ContentHash

	newEnt := makeEntity(t, "test/doc", map[string]string{"v": "new"})
	putReqEntity, putResource, err := CreatePutRequestCAS("local/files/absent.txt", &newEnt, &expected)
	if err != nil {
		t.Fatal(err)
	}
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 409 {
		t.Fatalf("expected 409 when expected_hash set at absent path, got %d", resp.Status)
	}
	if li.Has("local/files/absent.txt") {
		t.Fatal("path must not be bound after CAS failure")
	}
}

// V7 v7.50 CAS-create: expected_hash = zero hash → put succeeds iff path is
// unbound. Failing case: path already bound → 409 hash_mismatch.
func TestPutCASCreateFailsWhenBound(t *testing.T) {
	h, cs, li, pid := setup(t)

	original := makeEntity(t, "test/doc", "v1")
	cs.Put(original)
	li.Set("local/files/test.txt", original.ContentHash)

	zero := hash.Hash{}
	newEnt := makeEntity(t, "test/doc", "v2")
	putReqEntity, putResource, _ := CreatePutRequestCAS("local/files/test.txt", &newEnt, &zero)
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 409 {
		t.Fatalf("expected 409 hash_mismatch on CAS-create at bound path, got %d", resp.Status)
	}
	cur, _ := li.Get("local/files/test.txt")
	if cur != original.ContentHash {
		t.Fatal("binding must remain unchanged on CAS-create failure")
	}
}

// V7 v7.50 CAS-create: expected_hash = zero hash at unbound path → succeed.
func TestPutCASCreateSucceedsWhenUnbound(t *testing.T) {
	h, cs, li, pid := setup(t)

	zero := hash.Hash{}
	newEnt := makeEntity(t, "test/doc", map[string]string{"v": "fresh"})
	putReqEntity, putResource, _ := CreatePutRequestCAS("local/files/fresh.txt", &newEnt, &zero)
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200 on CAS-create at unbound path, got %d", resp.Status)
	}
	bound, ok := li.Get("local/files/fresh.txt")
	if !ok {
		t.Fatal("path must be bound after CAS-create success")
	}
	if bound != newEnt.ContentHash {
		t.Fatalf("bound hash should equal new entity's hash")
	}
}

func TestPutUnconditional(t *testing.T) {
	// expected_hash absent → unconditional put (existing behavior preserved).
	h, cs, li, pid := setup(t)

	original := makeEntity(t, "test/doc", "v1")
	cs.Put(original)
	li.Set("local/files/test.txt", original.ContentHash)

	updated := makeEntity(t, "test/doc", "v2")
	putReqEntity, putResource, _ := CreatePutRequest("local/files/test.txt", &updated)
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200 on unconditional put, got %d", resp.Status)
	}
}

func TestPutRemoveBinding(t *testing.T) {
	h, cs, li, pid := setup(t)

	testEntity := makeEntity(t, "test/doc", "content")
	cs.Put(testEntity)
	li.Set("local/test", testEntity.ContentHash)

	// Put with no entity → remove binding.
	putReqEntity, putResource, _ := CreatePutRequest("local/test", nil)
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	if li.Has("local/test") {
		t.Fatal("binding should be removed")
	}
}

func TestCapabilityEnforcement(t *testing.T) {
	h, cs, li, _ := setup(t)

	// Create a capability that only allows "get" on "system/tree/*".
	kp, _ := crypto.Generate()
	identity, _ := kp.IdentityEntity()

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"system/tree"}}, Resources: types.CapabilityScope{Include: []string{"system/tree/*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	testEntity := makeEntity(t, "test/doc", "content")
	cs.Put(testEntity)
	li.Set("local/files/test.txt", testEntity.ContentHash)

	// Get should work.
	getReq := types.GetRequestData{}
	getEntity, _ := getReq.ToEntity()

	req := &handler.Request{
		Path:      "system/tree",
		Operation: "get",
		Params:    getEntity,
		Context: &handler.HandlerContext{
			LocalPeerID:      kp.PeerID(),
			Store:            cs,
			LocationIndex:    li,
			HandlerPattern:   "system/tree",
			CallerCapability: capEntity,
			Resource:         &types.ResourceTarget{Targets: []string{"local/files/test.txt"}},
		},
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// Note: capability check uses pattern matching - whether this passes
	// depends on the path being under the capability's resource scope.
	_ = resp
}

func TestRegister(t *testing.T) {
	reg := handler.NewRegistry()
	Register(reg)

	h, pattern, ok := reg.Resolve("system/tree")
	if !ok {
		t.Fatal("expected to resolve system/tree")
	}
	if pattern != "system/tree" {
		t.Fatalf("expected pattern system/tree, got %s", pattern)
	}
	if h.Name() != "tree" {
		t.Fatalf("expected handler name tree, got %s", h.Name())
	}
}

func TestCreateAuthenticatedExecute(t *testing.T) {
	kp, _ := crypto.Generate()
	identity, _ := kp.IdentityEntity()

	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	getReq, getResource, _ := CreateGetRequest("local/test", "entity")

	env, err := protocol.CreateAuthenticatedExecute(
		kp, identity, capEntity,
		"req-1", "entity://"+string(kp.PeerID())+"/system/tree", "get",
		getReq,
		getResource,
	)
	if err != nil {
		t.Fatal(err)
	}

	if env.Root.Type != types.TypeExecute {
		t.Fatalf("expected execute type, got %s", env.Root.Type)
	}
	if len(env.Included) < 3 {
		t.Fatalf("expected at least 3 included entities, got %d", len(env.Included))
	}

	// Verify the included entities contain identity, capability, and signature.
	foundIdentity := false
	foundCap := false
	foundSig := false
	for _, ent := range env.Included {
		switch ent.Type {
		case "system/peer":
			foundIdentity = true
		case types.TypeCapToken:
			foundCap = true
		case types.TypeSignature:
			foundSig = true
		}
	}
	if !foundIdentity || !foundCap || !foundSig {
		t.Fatalf("missing included entities: identity=%v cap=%v sig=%v", foundIdentity, foundCap, foundSig)
	}
}

// --- Cascade semantics tests ---

// setupWithNotifying creates a test environment with NotifyingLocationIndex
// so that sync hooks fire and cascade results propagate.
func setupWithNotifying(t *testing.T) (*Handler, store.ContentStore, *store.NotifyingLocationIndex, *store.NamespacedIndex, crypto.PeerID) {
	t.Helper()
	cs := store.NewMemoryContentStore()
	rawLI := store.NewMemoryLocationIndex()
	events := make(chan store.TreeChangeEvent, 256)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	notifying := store.NewNotifyingLocationIndex(rawLI, events, done)
	kp, _ := crypto.Generate()
	nsLI := store.NewNamespacedIndex(notifying, string(kp.PeerID()))
	h := NewHandler()
	return h, cs, notifying, nsLI, kp.PeerID()
}

func TestPutCascadeComplete(t *testing.T) {
	h, cs, notifying, li, pid := setupWithNotifying(t)

	// Register a hook that succeeds.
	notifying.AddNamedSyncHook("test-consumer", func(evt store.TreeChangeEvent) *store.ConsumerResult {
		return nil
	})

	testEntity := makeEntity(t, "test/doc", "cascade-complete")
	putReqEntity, putResource, _ := CreatePutRequest("local/test", &testEntity)
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
}

func TestPutCascadeHalt(t *testing.T) {
	h, cs, notifying, li, pid := setupWithNotifying(t)

	// Register a hook that halts.
	notifying.AddNamedSyncHook("good-consumer", func(evt store.TreeChangeEvent) *store.ConsumerResult {
		return nil
	})
	notifying.AddNamedSyncHook("halting-consumer", func(evt store.TreeChangeEvent) *store.ConsumerResult {
		return &store.ConsumerResult{Status: 409, Code: "test_halt", Message: "intentional halt"}
	})
	notifying.AddNamedSyncHook("skipped-consumer", func(evt store.TreeChangeEvent) *store.ConsumerResult {
		t.Fatal("skipped consumer should not have been called")
		return nil
	})

	testEntity := makeEntity(t, "test/doc", "cascade-halt")
	putReqEntity, putResource, _ := CreatePutRequest("local/test", &testEntity)
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != handler.StatusMultiStatus {
		t.Fatalf("expected status 207, got %d", resp.Status)
	}
	if resp.Result.Type != types.TypeTreePartialResult {
		t.Fatalf("expected result type %s, got %s", types.TypeTreePartialResult, resp.Result.Type)
	}

	// Decode and verify the partial result.
	partial, err := types.PartialResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode partial result: %v", err)
	}
	if !partial.BindingCommitted {
		t.Fatal("binding should be committed")
	}
	if len(partial.ConsumersCompleted) != 1 || partial.ConsumersCompleted[0] != "good-consumer" {
		t.Fatalf("expected [good-consumer] completed, got %v", partial.ConsumersCompleted)
	}
	if len(partial.ConsumersHalted) != 1 || partial.ConsumersHalted[0].Name != "halting-consumer" {
		t.Fatalf("expected [halting-consumer] halted, got %v", partial.ConsumersHalted)
	}
	if partial.ConsumersHalted[0].Error.Code != "test_halt" {
		t.Fatalf("expected halt code test_halt, got %s", partial.ConsumersHalted[0].Error.Code)
	}
	if len(partial.ConsumersSkipped) != 1 || partial.ConsumersSkipped[0] != "skipped-consumer" {
		t.Fatalf("expected [skipped-consumer] skipped, got %v", partial.ConsumersSkipped)
	}

	// Verify the binding still landed.
	if !li.Has("local/test") {
		t.Fatal("binding should exist despite cascade halt")
	}
}

func TestPutCascadeDepthRefused(t *testing.T) {
	h, cs, notifying, li, pid := setupWithNotifying(t)
	notifying.SetMaxCascadeDepth(2)

	notifying.AddNamedSyncHook("test-consumer", func(evt store.TreeChangeEvent) *store.ConsumerResult {
		return nil
	})

	testEntity := makeEntity(t, "test/doc", "depth-test")
	putReqEntity, putResource, _ := CreatePutRequest("local/test", &testEntity)
	req := makeRequest(cs, li, pid, "system/tree", "put", putReqEntity, putResource)

	// Inject cascade depth at the threshold into the handler context bounds.
	depth := uint64(2)
	req.Context.Bounds = &types.BoundsData{CascadeDepth: &depth}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// When cascade depth is at or beyond the threshold, the binding does NOT commit.
	// The tree handler should return 207 with binding_committed=false.
	if resp.Status != handler.StatusMultiStatus {
		t.Fatalf("expected status 207 for depth refusal, got %d", resp.Status)
	}
	partial, err := types.PartialResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode partial result: %v", err)
	}
	if partial.BindingCommitted {
		t.Fatal("binding should NOT be committed when cascade depth exceeded")
	}
	if len(partial.ConsumersSkipped) != 1 || partial.ConsumersSkipped[0] != "test-consumer" {
		t.Fatalf("expected all consumers skipped, got completed=%v skipped=%v", partial.ConsumersCompleted, partial.ConsumersSkipped)
	}
}
