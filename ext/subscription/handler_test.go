package subscription

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

func setupTestEngine(t *testing.T) (*Engine, crypto.Keypair, entity.Entity) {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(cs, li, nil)
	return engine, kp, identity
}

func makeDeliveryToken(t *testing.T, kp crypto.Keypair, identity entity.Entity, deliverURI, deliverOp string) entity.Entity {
	t.Helper()
	now := uint64(time.Now().UnixMilli())
	expires := now + 3600000 // 1 hour
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/inbox/*"}},
				Resources:  types.CapabilityScope{Include: []string{deliverURI}},
				Operations: types.CapabilityScope{Include: []string{deliverOp}},
			},
		},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	ent, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return ent
}

func TestSubscribeCreatesEntity(t *testing.T) {
	engine, kp, identity := setupTestEngine(t)

	deliverURI := "system/inbox/my-notifications"
	token := makeDeliveryToken(t, kp, identity, deliverURI, "receive")

	included := map[hash.Hash]entity.Entity{
		token.ContentHash: token,
	}

	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: token.ContentHash,
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      included,
	}

	req := &handler.Request{
		Path:      "system/subscription",
		Operation: "subscribe",
		Params:    params,
		Context:   hctx,
	}

	resp, err := engine.HandleSubscribe(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	entries := li.List("system/subscription/")
	if len(entries) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(entries))
	}

	engine.mu.RLock()
	count := len(engine.subscriptions)
	engine.mu.RUnlock()
	if count != 1 {
		t.Fatalf("expected 1 subscription in engine, got %d", count)
	}
}

// EXTENSION-SUBSCRIPTION v3.13 / v3.14 §2.3: include_payload requires the
// caller's capability to cover tree:get on the subscribed resource. A subscribe
// request with include_payload=true but no caller capability (or insufficient
// scope) MUST be rejected with 403 payload_unauthorized.
func TestSubscribeIncludePayloadWithoutGetCapRejects(t *testing.T) {
	engine, kp, identity := setupTestEngine(t)

	deliverURI := "system/inbox/my-notifications"
	token := makeDeliveryToken(t, kp, identity, deliverURI, "receive")
	included := map[hash.Hash]entity.Entity{token.ContentHash: token}

	subReqData := types.SubscriptionRequestData{
		DeliverTo:      types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken:   token.ContentHash,
		IncludePayload: true,
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		LocalPeerID:   kp.PeerID(),
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      included,
		// No CallerCapability — should reject with 403 payload_unauthorized.
	}
	req := &handler.Request{
		Path: "system/subscription", Operation: "subscribe",
		Params: params, Context: hctx,
	}

	resp, err := engine.HandleSubscribe(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403 payload_unauthorized, got %d", resp.Status)
	}
	codeData, _ := types.ErrorDataFromEntity(resp.Result)
	if codeData.Code != "payload_unauthorized" {
		t.Fatalf("expected code payload_unauthorized, got %q", codeData.Code)
	}
}

// Positive: include_payload=true with a caller capability covering tree:get
// on the resource succeeds, and the subscription persists IncludePayload=true.
func TestSubscribeIncludePayloadWithGetCapSucceeds(t *testing.T) {
	engine, kp, identity := setupTestEngine(t)

	deliverURI := "system/inbox/my-notifications"
	token := makeDeliveryToken(t, kp, identity, deliverURI, "receive")

	// Build a caller cap with tree:get on local/data/* — must use the
	// engine's content store so granter resolution finds the identity.
	now := uint64(time.Now().UnixMilli())
	expires := now + 3600000
	callerCapData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"local/data/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	callerCap, err := callerCapData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	included := map[hash.Hash]entity.Entity{
		token.ContentHash:    token,
		identity.ContentHash: identity,
	}

	subReqData := types.SubscriptionRequestData{
		DeliverTo:      types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken:   token.ContentHash,
		IncludePayload: true,
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	if _, err := cs.Put(identity); err != nil {
		t.Fatal(err)
	}
	hctx := &handler.HandlerContext{
		AuthorHash:       identity.ContentHash,
		LocalPeerID:      kp.PeerID(),
		Store:            cs,
		LocationIndex:    li,
		Resource:         &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:         included,
		CallerCapability: callerCap,
	}
	req := &handler.Request{
		Path: "system/subscription", Operation: "subscribe",
		Params: params, Context: hctx,
	}

	resp, err := engine.HandleSubscribe(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		codeData, _ := types.ErrorDataFromEntity(resp.Result)
		t.Fatalf("expected 200, got %d (%s: %s)", resp.Status, codeData.Code, codeData.Message)
	}

	// Verify persisted IncludePayload by reading the subscription back.
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	if len(engine.subscriptions) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(engine.subscriptions))
	}
	for _, sub := range engine.subscriptions {
		if !sub.data.IncludePayload {
			t.Fatal("expected persisted IncludePayload=true on subscription")
		}
	}
}

func TestSubscribeMissingDeliverToken(t *testing.T) {
	engine, _, _ := setupTestEngine(t)

	subReqData := types.SubscriptionRequestData{
		DeliverTo: types.DeliverySpec{URI: "system/inbox/test", Operation: "receive"},
		// DeliverToken is zero — missing.
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx := &handler.HandlerContext{
		Store:         store.NewMemoryContentStore(),
		LocationIndex: store.NewMemoryLocationIndex(),
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      make(map[hash.Hash]entity.Entity),
	}

	req := &handler.Request{
		Path:      "system/subscription",
		Operation: "subscribe",
		Params:    params,
		Context:   hctx,
	}

	resp, err := engine.HandleSubscribe(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

func TestSubscribeInsufficientTokenScope(t *testing.T) {
	engine, kp, identity := setupTestEngine(t)

	// Create a token that only covers a different URI.
	deliverURI := "system/inbox/wrong-path"
	token := makeDeliveryToken(t, kp, identity, deliverURI, "receive")

	included := map[hash.Hash]entity.Entity{
		token.ContentHash: token,
	}

	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: "system/inbox/my-notifications", Operation: "receive"},
		DeliverToken: token.ContentHash,
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		Store:         store.NewMemoryContentStore(),
		LocationIndex: store.NewMemoryLocationIndex(),
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      included,
	}

	req := &handler.Request{
		Path:      "system/subscription",
		Operation: "subscribe",
		Params:    params,
		Context:   hctx,
	}

	resp, err := engine.HandleSubscribe(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected status 403, got %d", resp.Status)
	}
}

func TestUnsubscribeRemovesEntity(t *testing.T) {
	engine, kp, identity := setupTestEngine(t)

	deliverURI := "system/inbox/my-notifications"
	token := makeDeliveryToken(t, kp, identity, deliverURI, "receive")

	included := map[hash.Hash]entity.Entity{
		token.ContentHash: token,
	}

	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: token.ContentHash,
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      included,
	}

	subReq := &handler.Request{
		Path:      "system/subscription",
		Operation: "subscribe",
		Params:    params,
		Context:   hctx,
	}

	subResp, err := engine.HandleSubscribe(context.Background(), subReq)
	if err != nil {
		t.Fatal(err)
	}
	if subResp.Status != 200 {
		t.Fatalf("subscribe: expected status 200, got %d", subResp.Status)
	}

	engine.mu.RLock()
	var subID string
	for id := range engine.subscriptions {
		subID = id
		break
	}
	engine.mu.RUnlock()

	cancelData := types.SubscriptionCancelData{SubscriptionID: subID}
	cancelParams, err := cancelData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	cancelHctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      make(map[hash.Hash]entity.Entity),
	}

	cancelReq := &handler.Request{
		Path:      "system/subscription",
		Operation: "unsubscribe",
		Params:    cancelParams,
		Context:   cancelHctx,
	}

	cancelResp, err := engine.HandleUnsubscribe(context.Background(), cancelReq)
	if err != nil {
		t.Fatal(err)
	}
	if cancelResp.Status != 200 {
		t.Fatalf("unsubscribe: expected status 200, got %d", cancelResp.Status)
	}

	entries := li.List("system/subscription/")
	if len(entries) != 0 {
		t.Fatalf("expected 0 subscriptions after unsubscribe, got %d", len(entries))
	}

	engine.mu.RLock()
	count := len(engine.subscriptions)
	engine.mu.RUnlock()
	if count != 0 {
		t.Fatalf("expected 0 subscriptions in engine, got %d", count)
	}
}

func TestUnsubscribeNonOwnerReturns403(t *testing.T) {
	engine, kp, identity := setupTestEngine(t)

	deliverURI := "system/inbox/my-notifications"
	token := makeDeliveryToken(t, kp, identity, deliverURI, "receive")

	included := map[hash.Hash]entity.Entity{
		token.ContentHash: token,
	}

	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: token.ContentHash,
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      included,
	}

	subReq := &handler.Request{
		Path:      "system/subscription",
		Operation: "subscribe",
		Params:    params,
		Context:   hctx,
	}
	subResp, err := engine.HandleSubscribe(context.Background(), subReq)
	if err != nil {
		t.Fatal(err)
	}
	if subResp.Status != 200 {
		t.Fatalf("subscribe: expected 200, got %d", subResp.Status)
	}

	engine.mu.RLock()
	var subID string
	for id := range engine.subscriptions {
		subID = id
		break
	}
	engine.mu.RUnlock()

	otherKP, _ := crypto.Generate()
	otherIdentity, _ := otherKP.IdentityEntity()

	cancelData := types.SubscriptionCancelData{SubscriptionID: subID}
	cancelParams, _ := cancelData.ToEntity()

	cancelHctx := &handler.HandlerContext{
		AuthorHash:    otherIdentity.ContentHash,
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      make(map[hash.Hash]entity.Entity),
	}

	cancelReq := &handler.Request{
		Path:      "system/subscription",
		Operation: "unsubscribe",
		Params:    cancelParams,
		Context:   cancelHctx,
	}

	cancelResp, err := engine.HandleUnsubscribe(context.Background(), cancelReq)
	if err != nil {
		t.Fatal(err)
	}
	if cancelResp.Status != 403 {
		t.Fatalf("expected status 403 for non-owner, got %d", cancelResp.Status)
	}
}

func TestSubscribeAtCapacityReturnsRedirect(t *testing.T) {
	engine, kp, identity := setupTestEngine(t)
	engine.SetMaxSubscribersPerPrefix(2)

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// Fill capacity with 2 subscriptions from different identities.
	for i := 0; i < 2; i++ {
		otherKP, _ := crypto.Generate()
		otherIdentity, _ := otherKP.IdentityEntity()

		deliverURI := "system/inbox/other"
		token := makeDeliveryToken(t, otherKP, otherIdentity, deliverURI, "receive")

		subReqData := types.SubscriptionRequestData{
			DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
			DeliverToken: token.ContentHash,
		}
		params, _ := subReqData.ToEntity()

		hctx := &handler.HandlerContext{
			AuthorHash:    otherIdentity.ContentHash,
			Store:         cs,
			LocationIndex: li,
			Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
			Included:      map[hash.Hash]entity.Entity{token.ContentHash: token},
		}

		resp, err := engine.HandleSubscribe(context.Background(), &handler.Request{
			Path: "system/subscription", Operation: "subscribe",
			Params: params, Context: hctx,
		})
		if err != nil {
			t.Fatalf("subscribe %d: %v", i, err)
		}
		if resp.Status != 200 {
			t.Fatalf("subscribe %d: expected 200, got %d", i, resp.Status)
		}
	}

	// Third subscription from the original identity should get 303 redirect.
	deliverURI := "system/inbox/my-notifications"
	token := makeDeliveryToken(t, kp, identity, deliverURI, "receive")

	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: token.ContentHash,
	}
	params, _ := subReqData.ToEntity()

	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      map[hash.Hash]entity.Entity{token.ContentHash: token},
	}

	resp, err := engine.HandleSubscribe(context.Background(), &handler.Request{
		Path: "system/subscription", Operation: "subscribe",
		Params: params, Context: hctx,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 303 {
		t.Fatalf("expected status 303, got %d", resp.Status)
	}

	// Decode redirect data.
	redirectData, err := types.SubscriptionRedirectDataFromEntity(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	if redirectData.Reason != "at_capacity" {
		t.Fatalf("expected reason 'at_capacity', got %q", redirectData.Reason)
	}
	if redirectData.Capacity == nil || *redirectData.Capacity != 2 {
		t.Fatalf("expected capacity 2, got %v", redirectData.Capacity)
	}
	// Alternatives should contain the 2 subscriber identities (not the requester).
	if len(redirectData.Alternatives) != 2 {
		t.Fatalf("expected 2 alternatives, got %d", len(redirectData.Alternatives))
	}
	// None of the alternatives should be the requester's identity.
	for _, alt := range redirectData.Alternatives {
		if alt == identity.ContentHash {
			t.Fatal("alternatives should not contain the requester's identity")
		}
	}
}

func TestSubscribeNoCapacityLimitAllowsUnlimited(t *testing.T) {
	engine, _, _ := setupTestEngine(t)
	// maxSubscribersPerPrefix defaults to 0 = no limit.

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// Create 5 subscriptions — all should succeed.
	for i := 0; i < 5; i++ {
		otherKP, _ := crypto.Generate()
		otherIdentity, _ := otherKP.IdentityEntity()

		deliverURI := "system/inbox/other"
		token := makeDeliveryToken(t, otherKP, otherIdentity, deliverURI, "receive")

		subReqData := types.SubscriptionRequestData{
			DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
			DeliverToken: token.ContentHash,
		}
		params, _ := subReqData.ToEntity()

		hctx := &handler.HandlerContext{
			AuthorHash:    otherIdentity.ContentHash,
			Store:         cs,
			LocationIndex: li,
			Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
			Included:      map[hash.Hash]entity.Entity{token.ContentHash: token},
		}

		resp, err := engine.HandleSubscribe(context.Background(), &handler.Request{
			Path: "system/subscription", Operation: "subscribe",
			Params: params, Context: hctx,
		})
		if err != nil {
			t.Fatalf("subscribe %d: %v", i, err)
		}
		if resp.Status != 200 {
			t.Fatalf("subscribe %d: expected 200, got %d", i, resp.Status)
		}
	}

	engine.mu.RLock()
	count := len(engine.subscriptions)
	engine.mu.RUnlock()
	if count != 5 {
		t.Fatalf("expected 5 subscriptions, got %d", count)
	}
}

func TestSubscribeRenewalBypassesCapacity(t *testing.T) {
	engine, kp, identity := setupTestEngine(t)
	engine.SetMaxSubscribersPerPrefix(1)

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	deliverURI := "system/inbox/my-notifications"

	// First subscribe — succeeds and fills capacity.
	token := makeDeliveryToken(t, kp, identity, deliverURI, "receive")
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: token.ContentHash,
	}
	params, _ := subReqData.ToEntity()

	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      map[hash.Hash]entity.Entity{token.ContentHash: token},
	}

	resp, err := engine.HandleSubscribe(context.Background(), &handler.Request{
		Path: "system/subscription", Operation: "subscribe",
		Params: params, Context: hctx,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("first subscribe: expected 200, got %d", resp.Status)
	}

	// Same subscriber renewing with a new token — should succeed (renewal
	// is checked before capacity) even though capacity is now 1/1.
	token2 := makeDeliveryToken(t, kp, identity, deliverURI, "receive")
	subReqData2 := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: token2.ContentHash,
	}
	params2, _ := subReqData2.ToEntity()

	hctx2 := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/data/*"}},
		Included:      map[hash.Hash]entity.Entity{token2.ContentHash: token2},
	}

	resp2, err := engine.HandleSubscribe(context.Background(), &handler.Request{
		Path: "system/subscription", Operation: "subscribe",
		Params: params2, Context: hctx2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Status != 200 {
		t.Fatalf("renewal: expected 200, got %d", resp2.Status)
	}
}

func TestSubscriberIdentitiesForPrefix(t *testing.T) {
	engine, _, _ := setupTestEngine(t)

	// Register 3 subscriptions from different identities.
	var identityHashes []hash.Hash
	for i := 0; i < 3; i++ {
		otherKP, _ := crypto.Generate()
		otherIdentity, _ := otherKP.IdentityEntity()
		identityHashes = append(identityHashes, otherIdentity.ContentHash)

		engine.Register(types.SubscriptionData{
			SubscriptionID:     fmt.Sprintf("sub-%d", i),
			Pattern:            "/local/data/*",
			SubscriberIdentity: otherIdentity.ContentHash,
			DeliverURI:         "system/inbox/test",
		})
	}

	// Ask for identities excluding the first one.
	result := engine.SubscriberIdentitiesForPrefix("/local/data/*", identityHashes[0], 10)
	if len(result) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(result))
	}
	for _, r := range result {
		if r == identityHashes[0] {
			t.Fatal("excluded identity should not appear")
		}
	}

	// Test maxCount limit.
	result2 := engine.SubscriberIdentitiesForPrefix("/local/data/*", hash.Hash{}, 1)
	if len(result2) != 1 {
		t.Fatalf("expected 1 identity with maxCount=1, got %d", len(result2))
	}
}
