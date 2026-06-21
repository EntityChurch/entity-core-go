package subscription_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/inbox"
	"go.entitychurch.org/entity-core-go/ext/subscription"

	"github.com/fxamacker/cbor/v2"
)

// newTestPeer creates a peer with inbox + subscription extensions wired.
func newTestPeer(t *testing.T, kp crypto.Keypair) (*peer.Peer, *subscription.Engine) {
	t.Helper()

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	engine := subscription.NewEngine(cs, li, nil)
	engineCtx, cancelEngine := context.WithCancel(context.Background())

	p, err := peer.New(
		peer.WithIdentity(kp),
		peer.WithStore(cs),
		peer.WithLocationIndex(li),
		peer.WithTreeEventBuffer(64),
		peer.WithHandler("system/inbox", inbox.NewHandler()),
		peer.WithHandler("system/subscription", subscription.NewHandler(engine)),
		peer.WithNamedSyncHook("subscription/notification", engine.OnTreeChange),
		peer.WithCloseFunc(cancelEngine),
	)
	if err != nil {
		t.Fatal(err)
	}

	engine.SetLocationIndex(p.LocationIndex())
	engine.Deliver = subscription.MakeDeliveryFunc(
		p.Keypair(), p.Identity(), p.Store(), p.LocationIndex(), p.Dispatcher(),
	)
	engine.StartDelivery(engineCtx)

	return p, engine
}

func TestSubscribeAndNotify(t *testing.T) {
	kp, _ := crypto.Generate()
	p, engine := newTestPeer(t, kp)
	defer p.Close()

	identity := p.Identity()
	cs := p.Store()
	li := p.LocationIndex()

	// Create a delivery token for notification delivery.
	now := uint64(time.Now().UnixMilli())
	expires := now + 3600000
	inboxURI := "system/inbox/test-notifications"
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/inbox/*"}},
				Resources:  types.CapabilityScope{Include: []string{inboxURI}},
				Operations: types.CapabilityScope{Include: []string{"receive"}},
			},
		},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	// Store the delivery token — needed by the engine during delivery.
	tokenHash, err := cs.Put(capEntity)
	if err != nil {
		t.Fatal(err)
	}

	// Also need the capability token signature for chain verification.
	sig := kp.Sign(capEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	cs.Put(sigEntity)

	// Subscribe to "local/data/*" via the engine directly.
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: inboxURI, Operation: "receive"},
		DeliverToken: tokenHash,
	}
	params, err := subReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	included := map[hash.Hash]entity.Entity{
		capEntity.ContentHash: capEntity,
		sigEntity.ContentHash: sigEntity,
		identity.ContentHash:  identity,
	}

	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		LocalPeerID:   kp.PeerID(),
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
		t.Fatalf("subscribe: expected status 200, got %d", resp.Status)
	}

	// Now put an entity at a path matching the subscription.
	raw, _ := ecf.Encode(map[string]string{"content": "hello subscriptions"})
	testEntity, _ := entity.NewEntity("test/subscription-doc", cbor.RawMessage(raw))
	testHash, _ := cs.Put(testEntity)

	li.Set("local/data/my-file", testHash)

	// Wait for notification to be delivered.
	time.Sleep(200 * time.Millisecond)

	// Check that the notification was stored at the inbox path.
	entries := li.List(inboxURI + "/")
	if len(entries) == 0 {
		t.Fatal("expected notification entity stored at inbox path")
	}

	// Verify the notification entity.
	notifHash := entries[0].Hash
	notifEntity, ok := cs.Get(notifHash)
	if !ok {
		t.Fatal("notification entity not in store")
	}
	if notifEntity.Type != types.TypeInboxNotification {
		t.Fatalf("expected notification type %s, got %s", types.TypeInboxNotification, notifEntity.Type)
	}

	notifData, err := types.InboxNotificationDataFromEntity(notifEntity)
	if err != nil {
		t.Fatal(err)
	}
	if notifData.Event != "created" {
		t.Fatalf("expected event 'created', got %s", notifData.Event)
	}
	expectedURI := "/" + string(kp.PeerID()) + "/local/data/my-file"
	if notifData.URI != expectedURI {
		t.Fatalf("expected URI %q, got %q", expectedURI, notifData.URI)
	}
	if notifData.Hash != testHash {
		t.Fatalf("notification hash should match stored entity hash")
	}
}

func TestSubscribeMaxEventsTermination(t *testing.T) {
	kp, _ := crypto.Generate()
	p, engine := newTestPeer(t, kp)
	defer p.Close()

	identity := p.Identity()
	cs := p.Store()
	li := p.LocationIndex()

	// Create delivery token.
	now := uint64(time.Now().UnixMilli())
	expires := now + 3600000
	inboxURI := "system/inbox/max-events"
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/inbox/*"}},
				Resources:  types.CapabilityScope{Include: []string{inboxURI}},
				Operations: types.CapabilityScope{Include: []string{"receive"}},
			},
		},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, _ := cs.Put(capEntity)

	// Sign the token.
	sig := kp.Sign(capEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, _ := sigData.ToEntity()
	cs.Put(sigEntity)

	// Subscribe with max_events=2.
	maxEvents := uint64(2)
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: inboxURI, Operation: "receive"},
		DeliverToken: tokenHash,
		Limits:       &types.SubscriptionLimitsData{MaxEvents: &maxEvents},
	}
	params, _ := subReqData.ToEntity()

	included := map[hash.Hash]entity.Entity{
		capEntity.ContentHash: capEntity,
		sigEntity.ContentHash: sigEntity,
		identity.ContentHash:  identity,
	}

	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		LocalPeerID:   kp.PeerID(),
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/limited/*"}},
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
		t.Fatalf("subscribe: expected 200, got %d", resp.Status)
	}

	// Trigger 3 events.
	for i := 0; i < 3; i++ {
		raw, _ := ecf.Encode(map[string]string{"n": string(rune('a' + i))})
		ent, _ := entity.NewEntity("test/limit-doc", cbor.RawMessage(raw))
		h, _ := cs.Put(ent)
		li.Set("local/limited/file-"+string(rune('a'+i)), h)
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	// Count delivered notifications.
	entries := li.List(inboxURI + "/")
	if len(entries) > 2 {
		t.Fatalf("expected at most 2 notifications (max_events=2), got %d", len(entries))
	}

	// Verify subscription entity was removed from tree.
	subEntries := li.List("system/subscription/")
	if len(subEntries) != 0 {
		t.Fatalf("subscription should have been terminated, but found %d entries", len(subEntries))
	}
}

func TestUnsubscribeStopsNotifications(t *testing.T) {
	kp, _ := crypto.Generate()
	p, engine := newTestPeer(t, kp)
	defer p.Close()

	identity := p.Identity()
	cs := p.Store()
	li := p.LocationIndex()

	// Create delivery token.
	now := uint64(time.Now().UnixMilli())
	expires := now + 3600000
	inboxURI := "system/inbox/unsub-test"
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/inbox/*"}},
				Resources:  types.CapabilityScope{Include: []string{inboxURI}},
				Operations: types.CapabilityScope{Include: []string{"receive"}},
			},
		},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	capEntity, _ := capData.ToEntity()
	tokenHash, _ := cs.Put(capEntity)

	sig := kp.Sign(capEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, _ := sigData.ToEntity()
	cs.Put(sigEntity)

	// Subscribe.
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: inboxURI, Operation: "receive"},
		DeliverToken: tokenHash,
	}
	params, _ := subReqData.ToEntity()

	included := map[hash.Hash]entity.Entity{
		capEntity.ContentHash: capEntity,
		sigEntity.ContentHash: sigEntity,
		identity.ContentHash:  identity,
	}

	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		LocalPeerID:   kp.PeerID(),
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/unsub/*"}},
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

	// Get subscription ID.
	subEntries := li.List("system/subscription/")
	if len(subEntries) == 0 {
		t.Fatal("expected subscription entity in tree")
	}
	qualifiedPrefix := store.QualifyPath(string(kp.PeerID()), "system/subscription/")
	subID := strings.TrimPrefix(subEntries[0].Path, qualifiedPrefix)

	// Trigger one event — should be delivered.
	raw, _ := ecf.Encode(map[string]string{"v": "1"})
	ent, _ := entity.NewEntity("test/unsub-doc", cbor.RawMessage(raw))
	h, _ := cs.Put(ent)
	li.Set("local/unsub/file1", h)
	time.Sleep(100 * time.Millisecond)

	preCount := len(li.List(inboxURI + "/"))
	if preCount == 0 {
		t.Fatal("expected at least 1 notification before unsubscribe")
	}

	// Unsubscribe.
	cancelData := types.SubscriptionCancelData{SubscriptionID: subID}
	cancelParams, _ := cancelData.ToEntity()

	cancelHctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		LocalPeerID:   kp.PeerID(),
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"local/unsub/*"}},
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
		t.Fatalf("unsubscribe: expected 200, got %d", cancelResp.Status)
	}

	// Trigger another event — should NOT be delivered.
	raw2, _ := ecf.Encode(map[string]string{"v": "2"})
	ent2, _ := entity.NewEntity("test/unsub-doc", cbor.RawMessage(raw2))
	h2, _ := cs.Put(ent2)
	li.Set("local/unsub/file2", h2)
	time.Sleep(100 * time.Millisecond)

	postCount := len(li.List(inboxURI + "/"))
	if postCount != preCount {
		t.Fatalf("expected no new notifications after unsubscribe: had %d, now %d", preCount, postCount)
	}
}

func TestSubscriptionNamespaceIsolation(t *testing.T) {
	kp, _ := crypto.Generate()
	p, engine := newTestPeer(t, kp)
	defer p.Close()

	identity := p.Identity()
	cs := p.Store()
	li := p.LocationIndex()
	localPeerID := string(kp.PeerID())

	// Create a delivery token for notification delivery.
	now := uint64(time.Now().UnixMilli())
	expires := now + 3600000
	inboxURI := "system/inbox/ns-isolation"
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/inbox/*"}},
				Resources:  types.CapabilityScope{Include: []string{inboxURI}},
				Operations: types.CapabilityScope{Include: []string{"receive"}},
			},
		},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, _ := cs.Put(capEntity)

	sig := kp.Sign(capEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, _ := sigData.ToEntity()
	cs.Put(sigEntity)

	// Subscribe to "data/*" (local namespace).
	subReqData := types.SubscriptionRequestData{
		DeliverTo:    types.DeliverySpec{URI: inboxURI, Operation: "receive"},
		DeliverToken: tokenHash,
	}
	params, _ := subReqData.ToEntity()

	included := map[hash.Hash]entity.Entity{
		capEntity.ContentHash: capEntity,
		sigEntity.ContentHash: sigEntity,
		identity.ContentHash:  identity,
	}

	hctx := &handler.HandlerContext{
		AuthorHash:    identity.ContentHash,
		LocalPeerID:   kp.PeerID(),
		Store:         cs,
		LocationIndex: li,
		Resource:      &types.ResourceTarget{Targets: []string{"data/*"}},
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
		t.Fatalf("subscribe: expected status 200, got %d", resp.Status)
	}

	// Write to LOCAL namespace — should trigger notification.
	raw, _ := ecf.Encode(map[string]string{"content": "local write"})
	localEnt, _ := entity.NewEntity("test/ns-doc", cbor.RawMessage(raw))
	localHash, _ := cs.Put(localEnt)
	li.Set("data/local-file", localHash)

	time.Sleep(200 * time.Millisecond)

	localNotifs := li.List(inboxURI + "/")
	if len(localNotifs) == 0 {
		t.Fatal("expected notification for local write")
	}
	localCount := len(localNotifs)

	// Write to REMOTE namespace — should NOT trigger notification.
	remotePeerID := "RemotePeer123456789012345678901234567890ABCD"
	raw2, _ := ecf.Encode(map[string]string{"content": "remote write"})
	remoteEnt, _ := entity.NewEntity("test/ns-doc", cbor.RawMessage(raw2))
	remoteHash, _ := cs.Put(remoteEnt)

	// Use NamespacedIndex.SetNS to write under remote namespace.
	p.NamespacedIndex().SetNS(remotePeerID, "data/remote-file", remoteHash)

	time.Sleep(200 * time.Millisecond)

	// Verify no additional notifications were delivered.
	afterNotifs := li.List(inboxURI + "/")
	if len(afterNotifs) != localCount {
		t.Fatalf("expected no new notifications for remote write: had %d, now %d (remote peer: %s, local peer: %s)",
			localCount, len(afterNotifs), remotePeerID, localPeerID)
	}
}

func TestInboxHandlerRegistered(t *testing.T) {
	kp, _ := crypto.Generate()
	p, _ := newTestPeer(t, kp)
	defer p.Close()

	handlers := p.Registry().Handlers()
	if _, ok := handlers["system/inbox"]; !ok {
		t.Fatal("inbox handler should be registered")
	}

	// Verify the handler interface is in the tree.
	if _, ok := p.LocationIndex().Get("system/handler/system/inbox"); !ok {
		t.Fatal("inbox handler interface should be in tree")
	}
}

func TestSubscriptionHandlerRegistered(t *testing.T) {
	kp, _ := crypto.Generate()
	p, _ := newTestPeer(t, kp)
	defer p.Close()

	// Verify the subscription handler is registered.
	handlers := p.Registry().Handlers()
	if _, ok := handlers["system/subscription"]; !ok {
		t.Fatal("subscription handler should be registered")
	}

	// Verify the handler interface is in the tree.
	interfaceHash, ok := p.LocationIndex().Get("system/handler/system/subscription")
	if !ok {
		t.Fatal("subscription handler interface should be in tree")
	}

	interfaceEntity, ok := p.Store().Get(interfaceHash)
	if !ok {
		t.Fatal("subscription handler interface entity not in store")
	}

	interfaceData, err := types.HandlerInterfaceDataFromEntity(interfaceEntity)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := interfaceData.Operations["subscribe"]; !ok {
		t.Fatal("subscription handler should have subscribe operation")
	}
	if _, ok := interfaceData.Operations["unsubscribe"]; !ok {
		t.Fatal("subscription handler should have unsubscribe operation")
	}

	// Verify the tree handler does NOT have subscribe/unsubscribe.
	treeHash, ok := p.LocationIndex().Get("system/handler/system/tree")
	if !ok {
		t.Fatal("tree handler interface should be in tree")
	}
	treeEntity, ok := p.Store().Get(treeHash)
	if !ok {
		t.Fatal("tree handler interface entity not in store")
	}
	treeData, err := types.HandlerInterfaceDataFromEntity(treeEntity)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := treeData.Operations["subscribe"]; ok {
		t.Fatal("tree handler should NOT have subscribe operation")
	}
	if _, ok := treeData.Operations["unsubscribe"]; ok {
		t.Fatal("tree handler should NOT have unsubscribe operation")
	}
}
