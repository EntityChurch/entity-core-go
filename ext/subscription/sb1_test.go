package subscription

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// makeDeliveryTokenWithGranterGrantee constructs a deliver_token with
// explicitly-controlled granter/grantee/parent fields. Used by SB1 tests to
// vary the chain shape so we can observe the chain-root check in isolation.
func makeDeliveryTokenWithGranterGrantee(t *testing.T, granter, grantee hash.Hash, parent *hash.Hash, deliverURI, deliverOp string) entity.Entity {
	t.Helper()
	now := uint64(time.Now().UnixMilli())
	expires := now + 3600000
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/inbox/*"}},
				Resources:  types.CapabilityScope{Include: []string{deliverURI}},
				Operations: types.CapabilityScope{Include: []string{deliverOp}},
			},
		},
		Granter:   types.SingleSigGranter(granter),
		Grantee:   grantee,
		Parent:    parent,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	ent, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return ent
}

func TestSB1AdversaryReferencesAdminTokenRejected(t *testing.T) {
	// Subscriber (writer) is adv. Admin issued a deliver_token authorizing
	// delivery to admin's inbox; that token exists in the local store from
	// a prior legitimate flow. Adversary tries to subscribe and reference
	// admin's token to spam admin's inbox. SB1 must reject.
	engine, _, _ := setupTestEngine(t)

	advKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	advID, _ := advKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()

	deliverURI := "system/inbox/admin-inbox"
	adminToken := makeDeliveryTokenWithGranterGrantee(t,
		adminID.ContentHash, adminID.ContentHash, nil, deliverURI, "receive")

	included := map[hash.Hash]entity.Entity{
		adminToken.ContentHash: adminToken,
		advID.ContentHash:      advID,
		adminID.ContentHash:    adminID,
	}
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: adminToken.ContentHash,
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx := &handler.HandlerContext{
		AuthorHash:    advID.ContentHash,
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
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "embedded_cap_unauthorized" {
		t.Fatalf("expected embedded_cap_unauthorized, got %q", errData.Code)
	}
}

func TestSB1SubscriberIssuesOwnTokenAccepted(t *testing.T) {
	// Subscriber issues their own deliver_token (granter=subscriber).
	// Writer is in granter chain → SB1 passes.
	engine, kp, identity := setupTestEngine(t)

	deliverURI := "system/inbox/my-inbox"
	token := makeDeliveryTokenWithGranterGrantee(t,
		identity.ContentHash, identity.ContentHash, nil, deliverURI, "receive")
	_ = kp

	included := map[hash.Hash]entity.Entity{
		token.ContentHash:    token,
		identity.ContentHash: identity,
	}
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: token.ContentHash,
	}
	params, _ := subReqData.ToEntity()

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
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
}

func TestSB1ChainUnreachable(t *testing.T) {
	// Leaf token references a parent not in envelope or store. SB1 surfaces
	// 404 chain_unreachable.
	engine, _, identity := setupTestEngine(t)

	deliverURI := "system/inbox/x"
	missingParent := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	for i := 0; i < hash.SHA256DigestSize; i++ {
		missingParent.Digest[i] = byte(i + 1)
	}
	otherKP, _ := crypto.Generate()
	otherID, _ := otherKP.IdentityEntity()
	leaf := makeDeliveryTokenWithGranterGrantee(t,
		otherID.ContentHash, identity.ContentHash, &missingParent, deliverURI, "receive")

	included := map[hash.Hash]entity.Entity{
		leaf.ContentHash:     leaf,
		identity.ContentHash: identity,
		otherID.ContentHash:  otherID,
	}
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: leaf.ContentHash,
	}
	params, _ := subReqData.ToEntity()
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
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "chain_unreachable" {
		t.Fatalf("expected chain_unreachable, got %q", errData.Code)
	}
}

func TestSB1MultiLevelChainWriterIsLeafGranter(t *testing.T) {
	// 3-peer subscribe pattern from FEEDBACK §1.3 option (c): root issued by
	// other-peer to subscriber; subscriber re-attenuates leaf to delivery
	// agent. Subscriber is leaf granter → SB1 passes.
	engine, _, subscriberIdentity := setupTestEngine(t)
	otherKP, _ := crypto.Generate()
	otherID, _ := otherKP.IdentityEntity()
	agentKP, _ := crypto.Generate()
	agentID, _ := agentKP.IdentityEntity()

	deliverURI := "system/inbox/x"

	root := makeDeliveryTokenWithGranterGrantee(t,
		otherID.ContentHash, subscriberIdentity.ContentHash, nil, deliverURI, "receive")
	rootHash := root.ContentHash
	leaf := makeDeliveryTokenWithGranterGrantee(t,
		subscriberIdentity.ContentHash, agentID.ContentHash, &rootHash, deliverURI, "receive")

	included := map[hash.Hash]entity.Entity{
		root.ContentHash:               root,
		leaf.ContentHash:               leaf,
		subscriberIdentity.ContentHash: subscriberIdentity,
		otherID.ContentHash:            otherID,
		agentID.ContentHash:            agentID,
	}
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
		DeliverToken: leaf.ContentHash,
	}
	params, _ := subReqData.ToEntity()
	hctx := &handler.HandlerContext{
		AuthorHash:    subscriberIdentity.ContentHash,
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
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
}
