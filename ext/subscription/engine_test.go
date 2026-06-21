package subscription

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func setupEngine(t *testing.T) (*Engine, store.ContentStore, store.LocationIndex, entity.Entity) {
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
	return engine, cs, li, identity
}

func storeDeliveryToken(t *testing.T, cs store.ContentStore, identity entity.Entity) hash.Hash {
	t.Helper()
	now := uint64(time.Now().UnixMilli())
	expires := now + 3600000
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/inbox/*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
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
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestEventMatchingRespectsFilter(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)

	tokenHash := storeDeliveryToken(t, cs, identity)

	var mu sync.Mutex
	var delivered []DeliveryRequest
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		delivered = append(delivered, req)
		mu.Unlock()
		return nil
	}

	// Subscribe to "created" events only.
	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-1",
		Pattern:            "local/data/*",
		Events:             []string{"created"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	// Send a "created" event — should match.
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{1})},
		ChangeType: store.ChangeCreated,
	})

	// Send an "updated" event — should NOT match.
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:         "local/data/file1",
		Hash:         hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{2})},
		PreviousHash: hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{1})},
		ChangeType:   store.ChangeModified,
	})

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(delivered)
	mu.Unlock()

	if count != 1 {
		t.Fatalf("expected 1 delivery (created only), got %d", count)
	}
}

// EXTENSION-SUBSCRIPTION v3.14 §4.2: when sub.data.IncludePayload is true and
// the event's Hash is resolvable in the content store, the engine attaches the
// entity to the delivery's Included map. Non-include_payload subscribers see
// the lean (nil/empty Included) shape.
func TestIncludePayloadAttachesEntityToDelivery(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)
	tokenHash := storeDeliveryToken(t, cs, identity)

	// Put the entity that will be the "current value" of the path into the
	// engine's content store, so the engine can resolve it at delivery time.
	rawData, _ := ecf.Encode(map[string]string{"v": "payload-content"})
	payloadEnt, _ := entity.NewEntity("test/doc", cbor.RawMessage(rawData))
	if _, err := cs.Put(payloadEnt); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var delivered []DeliveryRequest
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		delivered = append(delivered, req)
		mu.Unlock()
		return nil
	}

	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-payload",
		Pattern:            "local/data/*",
		Events:             []string{"created", "updated"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
		IncludePayload:     true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       payloadEnt.ContentHash,
		ChangeType: store.ChangeCreated,
	})

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(delivered) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(delivered))
	}
	req := delivered[0]
	if req.Included == nil {
		t.Fatal("expected Included to be populated when IncludePayload=true")
	}
	got, ok := req.Included[payloadEnt.ContentHash]
	if !ok {
		t.Fatalf("expected payload entity %s in delivery.Included; got keys: %v",
			payloadEnt.ContentHash, mapKeys(req.Included))
	}
	if got.ContentHash != payloadEnt.ContentHash {
		t.Fatal("included entity hash does not match payload entity")
	}
}

// Subscribers that do not opt into IncludePayload see the lean shape
// regardless of whether the entity is in the source's content store.
func TestIncludePayloadOffDoesNotAttachEntity(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)
	tokenHash := storeDeliveryToken(t, cs, identity)

	rawData, _ := ecf.Encode(map[string]string{"v": "payload-content"})
	payloadEnt, _ := entity.NewEntity("test/doc", cbor.RawMessage(rawData))
	cs.Put(payloadEnt)

	var mu sync.Mutex
	var delivered []DeliveryRequest
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		delivered = append(delivered, req)
		mu.Unlock()
		return nil
	}

	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-no-payload",
		Pattern:            "local/data/*",
		Events:             []string{"created"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
		IncludePayload:     false, // explicit
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       payloadEnt.ContentHash,
		ChangeType: store.ChangeCreated,
	})

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(delivered) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(delivered))
	}
	if len(delivered[0].Included) != 0 {
		t.Fatalf("expected empty Included when IncludePayload=false, got %d entries",
			len(delivered[0].Included))
	}
}

// EXTENSION-SUBSCRIPTION v3.14: source-side resolution failure (entity not in
// store at delivery time) ⇒ deliver hash-only fallback, debug log, never
// fail-stop. The subscription continues; the delivery has nil/empty Included.
func TestIncludePayloadResolutionFailureFallsBackToHashOnly(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)
	tokenHash := storeDeliveryToken(t, cs, identity)

	// Deliberately do NOT put the payload entity in cs — simulate the
	// rare race where the change event fires but the entity isn't yet
	// (or no longer is) in the engine's content store.
	unresolvableHash := hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{0xDE, 0xAD})}

	var mu sync.Mutex
	var delivered []DeliveryRequest
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		delivered = append(delivered, req)
		mu.Unlock()
		return nil
	}

	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-rare-race",
		Pattern:            "local/data/*",
		Events:             []string{"created"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
		IncludePayload:     true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       unresolvableHash,
		ChangeType: store.ChangeCreated,
	})

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(delivered) != 1 {
		t.Fatalf("expected 1 delivery (hash-only fallback), got %d", len(delivered))
	}
	if len(delivered[0].Included) != 0 {
		t.Fatalf("expected empty Included on resolution failure (hash-only fallback), got %d",
			len(delivered[0].Included))
	}
}

func mapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestMaxEventsTerminates(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)

	tokenHash := storeDeliveryToken(t, cs, identity)

	var mu sync.Mutex
	var delivered []DeliveryRequest
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		delivered = append(delivered, req)
		mu.Unlock()
		return nil
	}

	maxEvents := uint64(2)
	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-max",
		Pattern:            "local/data/*",
		Events:             []string{"created", "updated", "deleted"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
		Limits:             &types.SubscriptionLimitsData{MaxEvents: &maxEvents},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	// Send 3 events — only first 2 should be delivered.
	for i := 0; i < 3; i++ {
		engine.OnTreeChange(store.TreeChangeEvent{
			Path:       "local/data/file1",
			Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{byte(i + 1)})},
			ChangeType: store.ChangeCreated,
		})
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(delivered)
	mu.Unlock()

	if count != 2 {
		t.Fatalf("expected 2 deliveries before max_events termination, got %d", count)
	}

	// Verify subscription was removed.
	engine.mu.RLock()
	_, exists := engine.subscriptions["sub-max"]
	engine.mu.RUnlock()
	if exists {
		t.Fatal("subscription should have been terminated after max_events")
	}
}

func TestMaxDurationTerminates(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)

	tokenHash := storeDeliveryToken(t, cs, identity)

	var mu sync.Mutex
	var delivered []DeliveryRequest
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		delivered = append(delivered, req)
		mu.Unlock()
		return nil
	}

	maxDuration := uint64(50) // 50ms
	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-dur",
		Pattern:            "local/data/*",
		Events:             []string{"created", "updated", "deleted"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
		Limits:             &types.SubscriptionLimitsData{MaxDurationMs: &maxDuration},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	// First event should succeed.
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{1})},
		ChangeType: store.ChangeCreated,
	})
	time.Sleep(10 * time.Millisecond)

	// Wait for duration to expire.
	time.Sleep(60 * time.Millisecond)

	// Second event should be rejected.
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file2",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{2})},
		ChangeType: store.ChangeCreated,
	})
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(delivered)
	mu.Unlock()

	if count != 1 {
		t.Fatalf("expected 1 delivery before duration expiry, got %d", count)
	}
}

func TestDeliverTokenExpiryTerminates(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)

	// Create an already-expired token.
	now := uint64(time.Now().UnixMilli())
	expired := now - 1000 // expired 1 second ago
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			},
		},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: now - 2000,
		ExpiresAt: &expired,
	}
	tokenEnt, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := cs.Put(tokenEnt)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var delivered []DeliveryRequest
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		delivered = append(delivered, req)
		mu.Unlock()
		return nil
	}

	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-expired",
		Pattern:            "local/data/*",
		Events:             []string{"created", "updated", "deleted"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{1})},
		ChangeType: store.ChangeCreated,
	})
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(delivered)
	mu.Unlock()

	if count != 0 {
		t.Fatalf("expected 0 deliveries with expired token, got %d", count)
	}

	// Verify subscription was terminated.
	engine.mu.RLock()
	_, exists := engine.subscriptions["sub-expired"]
	engine.mu.RUnlock()
	if exists {
		t.Fatal("subscription should have been terminated on token expiry")
	}
}

func TestPatternMatching(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		match   bool
	}{
		{"local/data/config", "local/data/config", true},
		{"local/data/config", "local/data/other", false},
		{"local/data/*", "local/data/config", true},
		{"local/data/*", "local/data/sub/deep", true},
		{"local/data/*", "local/other/config", false},
		{"*", "anything/at/all", true},
	}

	for _, tt := range tests {
		got := matchPattern(tt.pattern, tt.path)
		if got != tt.match {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.match)
		}
	}
}

func TestRateLimitDropsWithoutTerminating(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)

	tokenHash := storeDeliveryToken(t, cs, identity)

	var mu sync.Mutex
	var delivered []DeliveryRequest
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		delivered = append(delivered, req)
		mu.Unlock()
		return nil
	}

	rateLimit := uint64(1) // 1 per minute
	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-rate",
		Pattern:            "local/data/*",
		Events:             []string{"created", "updated", "deleted"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
		Limits:             &types.SubscriptionLimitsData{RateLimit: &rateLimit},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	// Send 3 rapid events — first should deliver, rest should be rate-limited.
	for i := 0; i < 3; i++ {
		engine.OnTreeChange(store.TreeChangeEvent{
			Path:       "local/data/file1",
			Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{byte(i + 1)})},
			ChangeType: store.ChangeCreated,
		})
		time.Sleep(5 * time.Millisecond)
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(delivered)
	mu.Unlock()

	if count != 1 {
		t.Fatalf("expected 1 delivery with rate limit, got %d", count)
	}

	// Subscription should still exist (rate limiting doesn't terminate).
	engine.mu.RLock()
	_, exists := engine.subscriptions["sub-rate"]
	engine.mu.RUnlock()
	if !exists {
		t.Fatal("subscription should still exist after rate limiting")
	}
}

// EXTENSION-SUBSCRIPTION v3.15 §5.2 (Within-subscription ordering MUST):
// Within a single subscription, deliveries MUST arrive in tree-change order.
// Even with a parallel shard pool, all deliveries for one subscription_id
// land in the same shard and therefore drain via a single goroutine — order
// is preserved. This test bursts 200 events into one subscription with a
// slow Deliver and asserts the observed order matches the enqueue order.
func TestV315_WithinSubscriptionOrderingPreserved(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)
	tokenHash := storeDeliveryToken(t, cs, identity)

	const N = 200
	var mu sync.Mutex
	observed := make([]byte, 0, N)
	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		// Recover the sequence byte from req.Params (notification entity).
		// The InboxNotificationData stores the URI; we encoded the sequence
		// into the URI suffix below. Easier: parse from the URI suffix.
		// Find the trailing "/seqXX" segment.
		uri := req.Resource.Targets[0]
		mu.Lock()
		// uri is the deliver_uri ("inbox") — instead we read req.Params.Data
		// We embed sequence in PreviousHash's first byte for robustness.
		_ = uri
		// We'll decode the InboxNotificationData to recover Hash's first byte
		// (which we set to the sequence in the change events below).
		if notif, err := types.InboxNotificationDataFromEntity(req.Params); err == nil {
			observed = append(observed, notif.Hash.Digest[0])
		}
		mu.Unlock()
		// Inject latency so parallel shards (if mis-routed) would interleave.
		time.Sleep(time.Millisecond)
		return nil
	}

	// Force a multi-shard pool so routing logic is exercised; the single
	// subscription_id MUST still see strict order.
	engine.SetDeliveryWorkers(4)

	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-order",
		Pattern:            "local/data/*",
		Events:             []string{"created"},
		DeliverURI:         "system/inbox/test",
		DeliverOperation:   "receive",
		SubscriberIdentity: identity.ContentHash,
		DeliverToken:       tokenHash,
		CreatedAt:          uint64(time.Now().UnixMilli()),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	for i := 0; i < N; i++ {
		var h hash.Hash
		h.Digest[0] = byte(i)
		engine.OnTreeChange(store.TreeChangeEvent{
			Path:       "local/data/file",
			Hash:       h,
			ChangeType: store.ChangeCreated,
		})
	}

	// Drain — bound by N×1ms plus headroom.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := len(observed) >= N
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(observed) != N {
		t.Fatalf("expected %d deliveries, got %d", N, len(observed))
	}
	for i, got := range observed {
		if got != byte(i) {
			t.Fatalf("within-subscription order violated at index %d: got seq=%d (full prefix: %v)",
				i, got, observed[:i+1])
		}
	}
}

// EXTENSION-SUBSCRIPTION v3.15 §5.2 (Cross-subscription parallelism MAY):
// Different subscriptions land on different shards by FNV-32 hash of
// subscription_id; if two subscriptions happen to hash to different shards
// (the common case), their deliveries proceed concurrently. We don't assert
// strict concurrency timing (flaky); we assert (a) cross-subscription drains
// don't serialize on a single goroutine — measured via in-flight peak —
// and (b) all expected deliveries arrive.
func TestV315_CrossSubscriptionParallelism(t *testing.T) {
	engine, cs, _, identity := setupEngine(t)
	tokenHash := storeDeliveryToken(t, cs, identity)

	const subCount = 8
	const perSub = 25
	var (
		mu        sync.Mutex
		inFlight  int
		peak      int
		delivered = make(map[string]int)
	)

	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		mu.Unlock()

		// Hold the slot long enough that a single-loop drain would
		// serialize observably.
		time.Sleep(2 * time.Millisecond)

		mu.Lock()
		notif, _ := types.InboxNotificationDataFromEntity(req.Params)
		delivered[notif.SubscriptionID]++
		inFlight--
		mu.Unlock()
		return nil
	}
	engine.SetDeliveryWorkers(subCount)

	// Distinct subscription_ids that hash across shards. Pattern is the
	// same so each tree change matches all of them.
	for i := 0; i < subCount; i++ {
		engine.Register(types.SubscriptionData{
			SubscriptionID:     "sub-par-" + string(rune('a'+i)),
			Pattern:            "local/data/*",
			Events:             []string{"created"},
			DeliverURI:         "system/inbox/test",
			DeliverOperation:   "receive",
			SubscriberIdentity: identity.ContentHash,
			DeliverToken:       tokenHash,
			CreatedAt:          uint64(time.Now().UnixMilli()),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.StartDelivery(ctx)

	for i := 0; i < perSub; i++ {
		var h hash.Hash
		h.Digest[0] = byte(i)
		engine.OnTreeChange(store.TreeChangeEvent{
			Path:       "local/data/file",
			Hash:       h,
			ChangeType: store.ChangeCreated,
		})
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		total := 0
		for _, c := range delivered {
			total += c
		}
		done := total >= subCount*perSub
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for id, c := range delivered {
		if c != perSub {
			t.Errorf("subscription %s: expected %d deliveries, got %d", id, perSub, c)
		}
	}
	// Single-loop ceiling would peak at 1. Sharded across distinct
	// subscription_ids we expect >= 2 concurrent dispatches. Conservative
	// to avoid flake on slow CI.
	if peak < 2 {
		t.Errorf("expected cross-subscription parallelism (peak in-flight >= 2), got peak=%d — pool is serializing", peak)
	}
}

// shardFor stability — the FNV-32 routing must be a pure function of
// subscription_id so a subscription always lands in the same shard across
// the engine's lifetime (a single goroutine drains it ⇒ within-sub order).
func TestV315_ShardForStableAndBounded(t *testing.T) {
	engine := &Engine{deliveryShards: make([]chan pendingDelivery, 8)}
	const id = "sub-deadbeef"
	first := engine.shardFor(id)
	for i := 0; i < 100; i++ {
		if got := engine.shardFor(id); got != first {
			t.Fatalf("shardFor(%q) unstable: first=%d got=%d at i=%d", id, first, got, i)
		}
	}
	if first < 0 || first >= 8 {
		t.Fatalf("shardFor returned out-of-range %d (len=8)", first)
	}

	// Single-shard degenerate case: always 0.
	engine.deliveryShards = make([]chan pendingDelivery, 1)
	if got := engine.shardFor(id); got != 0 {
		t.Fatalf("single-shard shardFor: expected 0, got %d", got)
	}
}
