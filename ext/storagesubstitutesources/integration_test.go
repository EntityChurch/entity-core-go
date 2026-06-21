package storagesubstitutesources_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	contentext "go.entitychurch.org/entity-core-go/ext/content"
	"go.entitychurch.org/entity-core-go/ext/storagesubstitutehttp"
	"go.entitychurch.org/entity-core-go/ext/storagesubstitutesources"
)

// testLocalPeerIDIntegration is the local peer id used to canonicalize
// cap-resource patterns in integration tests (V7 §5.5 / PR-8). 46+ Base58
// chars so it passes looksLikePeerID.
const testLocalPeerIDIntegration = crypto.PeerID("2KZFtestIntegrationLocalPeerIDAAAAAAAAAAAAAAAA")

// mkConsultCapForIntegration builds a CallerCapability permitting the
// consult gate (the public package-level constants on
// storagesubstitutesources name the (handler, op, resource) tuple).
func mkConsultCapForIntegration(t *testing.T) entity.Entity {
	t.Helper()
	// D-2: cap resource pattern covers the namespace the integration test
	// reads into ("system/content"). Wildcarded so a single grant covers
	// the namespace.
	g := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{storagesubstitutesources.HandlerPatternSources}},
		Resources:  types.CapabilityScope{Include: []string{"system/content/*", "system/content"}},
		Operations: types.CapabilityScope{Include: []string{storagesubstitutesources.OperationConsult}},
	}
	granterHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	granterHash.Digest[0] = 0xa1
	granteeHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	granteeHash.Digest[0] = 0xa2
	tokenData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{g},
		Granter:   types.SingleSigGranter(granterHash),
		Grantee:   granteeHash,
		CreatedAt: 1,
	}
	ent, err := tokenData.ToEntity()
	if err != nil {
		t.Fatalf("token ToEntity: %v", err)
	}
	holdingStore := store.NewMemoryContentStore()
	h, err := holdingStore.Put(ent)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ent.ContentHash = h
	return ent
}

// TestEndToEnd_ContentMiss_OrchestratorFetchesViaHTTP wires the full chain:
//   - The ext/content handler with a MissResolver installed (the
//     orchestrator's Resolve method).
//   - The orchestrator with a stub Execute that dispatches to a real
//     storagesubstitutehttp.Handler.
//   - The HTTP handler points at an httptest.Server serving a single
//     content-hash-addressed entity body.
//
// content:get misses locally → orchestrator → HTTP handler → fetch +
// verify → ingest → resolver returns Found → handler reports found.
func TestEndToEnd_ContentMiss_OrchestratorFetchesViaHTTP(t *testing.T) {
	// 1. Build the payload entity + its hash. The "publisher" serves this
	//    over HTTP.
	dataBytes, err := ecf.Encode("hello via the chain")
	if err != nil {
		t.Fatalf("ecf.Encode: %v", err)
	}
	payload, err := entity.NewEntity("test/payload", dataBytes)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	wire, err := ecf.Encode(payload)
	if err != nil {
		t.Fatalf("ecf.Encode payload: %v", err)
	}

	// 2. Spin up the mock HTTP origin.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(wire)
	}))
	defer origin.Close()

	// 3. Construct a substitute source pointing at the origin, claimed by
	//    a publisher peer.
	claimed := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	claimed.Digest[0] = 0xab
	src, err := types.NewHTTPSource("origin-mirror", claimed, types.TransportEndpoint{
		TreeURLPrefix:    origin.URL,
		ContentURLPrefix: origin.URL,
		ContentLayout:    types.ContentLayoutFlat,
	}, 10)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}

	// 4. Publish the source into a fresh store + index.
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	srcEnt, _ := src.ToEntity()
	srcHash, err := cs.Put(srcEnt)
	if err != nil {
		t.Fatalf("Put src: %v", err)
	}
	if err := li.Set(types.SubstituteSourcePathPrefix+srcHash.String(), srcHash); err != nil {
		t.Fatalf("li.Set: %v", err)
	}

	// 5. Build the http convention handler + an Execute stub that routes
	//    system/substitute/http:try directly to it (mimicking what a
	//    PeerBuilder integration would arrange).
	httpHandler := storagesubstitutehttp.NewHandler(
		storagesubstitutehttp.WithHTTPClient(origin.Client()),
		storagesubstitutehttp.WithAllowHTTP(true),
	)

	executeFn := func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		if uri == "system/substitute/http" && op == types.OpSubstituteTry {
			return httpHandler.Handle(ctx, &handler.Request{
				Operation: op,
				Params:    params,
			})
		}
		return &handler.Response{Status: 404}, nil
	}

	// 6. Construct the orchestrator + content handler with the resolver.
	orch := storagesubstitutesources.New()
	contentHandler := contentext.NewHandler(contentext.WithMissResolver(orch))

	// 7. Build a HandlerContext for the content:get call. resource_target
	//    is needed because content:get gates on resource per §6.2.
	//    CallerCapability scoped to the consult gate per
	//    RULING-NAMED-CAPABILITY-MAPPING §4 — chain consultation
	//    is gated default-deny; production deployments emit a real grant.
	resource := &types.ResourceTarget{Targets: []string{"system/content"}}
	hctx := &handler.HandlerContext{
		Store:            cs,
		LocationIndex:    li,
		Execute:          executeFn,
		HandlerPattern:   "system/content",
		Resource:         resource,
		LocalPeerID:      testLocalPeerIDIntegration,
		CallerCapability: mkConsultCapForIntegration(t),
	}

	// 8. Inject the claimed source into ctx (per Ruling 4 — local plumbing).
	ctx := storagesubstitutesources.WithClaimedSource(context.Background(), claimed)

	// 9. content:get for the payload hash; it MUST miss locally, walk the
	//    chain, fetch from origin, verify, ingest, and report found.
	getReqData := types.ContentGetRequestData{Hashes: []hash.Hash{payload.ContentHash}}
	getReqEnt, _ := getReqData.ToEntity()
	resp, err := contentHandler.Handle(ctx, &handler.Request{
		Operation: "get",
		Params:    getReqEnt,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("content:get: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	respData, err := types.ContentGetResponseDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(respData.Missing) != 0 {
		t.Errorf("expected 0 missing, got %d", len(respData.Missing))
	}
	if len(respData.Found) != 1 || respData.Found[0] != payload.ContentHash {
		t.Errorf("expected found=[%s], got %v", payload.ContentHash, respData.Found)
	}
	if _, ok := resp.Included[payload.ContentHash]; !ok {
		t.Errorf("expected payload in Included map")
	}
}

// TestEndToEnd_NoClaimedSource_BypassesChain confirms that without a
// claimed source on context, the orchestrator's resolver returns empty
// (no consultation) and the content handler reports missing — proves
// the bare-hash-bypass per §3-RES.2 / Ruling 4 holds end-to-end.
func TestEndToEnd_NoClaimedSource_BypassesChain(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// Set up a source that would otherwise serve, but we'll never reach it.
	claimed := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	claimed.Digest[0] = 0xab
	src, _ := types.NewHTTPSource("would-serve", claimed, types.TransportEndpoint{
		TreeURLPrefix:    "https://nope.example.com",
		ContentURLPrefix: "https://nope.example.com",
		ContentLayout:    types.ContentLayoutFlat,
	}, 10)
	srcEnt, _ := src.ToEntity()
	srcHash, _ := cs.Put(srcEnt)
	_ = li.Set(types.SubstituteSourcePathPrefix+srcHash.String(), srcHash)

	orch := storagesubstitutesources.New()
	contentHandler := contentext.NewHandler(contentext.WithMissResolver(orch))

	executeFn := func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		t.Fatalf("Execute MUST NOT be called when no claimed source is on ctx")
		return nil, nil
	}

	resource := &types.ResourceTarget{Targets: []string{"system/content"}}
	hctx := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  li,
		Execute:        executeFn,
		HandlerPattern: "system/content",
		Resource:       resource,
	}

	// Note: ctx has NO claimed source.
	target := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	target.Digest[0] = 0xef
	getReqData := types.ContentGetRequestData{Hashes: []hash.Hash{target}}
	getReqEnt, _ := getReqData.ToEntity()
	resp, err := contentHandler.Handle(context.Background(), &handler.Request{
		Operation: "get",
		Params:    getReqEnt,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("content:get: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	respData, _ := types.ContentGetResponseDataFromEntity(resp.Result)
	if len(respData.Missing) != 1 {
		t.Errorf("expected 1 missing, got %d", len(respData.Missing))
	}
}
