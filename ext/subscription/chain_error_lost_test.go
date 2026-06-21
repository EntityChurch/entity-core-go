package subscription

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestLostMarker_OnTransportFailure verifies EXTENSION-SUBSCRIPTION §4.7:
// the engine binds a `lost` marker when DeliverFunc returns an error.
func TestLostMarker_OnTransportFailure(t *testing.T) {
	engine, cs, li, identity := setupEngine(t)

	tokenHash := storeDeliveryToken(t, cs, identity)

	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		return errors.New("transport-down")
	}

	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-transport-fail",
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

	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{1})},
		ChangeType: store.ChangeCreated,
		Context:    &store.MutationContext{ChainID: "chain-A"},
	})

	// Allow the deliveryLoop to run and the marker bind to settle.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countMarkers(t, li, "system/runtime/chain-errors/lost/chain-A/sub-transport-fail/delivery_failed/") > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := countMarkers(t, li, "system/runtime/chain-errors/lost/chain-A/sub-transport-fail/delivery_failed/"); got == 0 {
		t.Fatalf("expected lost marker bound at chain-A/sub-transport-fail/delivery_failed/; found 0")
	}
}

// TestLostMarker_OnRateLimit verifies §4.7: rate_limited reason marker.
func TestLostMarker_OnRateLimit(t *testing.T) {
	engine, cs, li, identity := setupEngine(t)
	tokenHash := storeDeliveryToken(t, cs, identity)

	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error { return nil }

	rateLimit := uint64(60) // 60/min ⇒ ≥1s between deliveries; second event ⇒ rate-limited
	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-rate",
		Pattern:            "local/data/*",
		Events:             []string{"created"},
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

	// Fire first event — accepted (no prior delivery, no rate-limit hit).
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{1})},
		ChangeType: store.ChangeCreated,
		Context:    &store.MutationContext{ChainID: "chain-R"},
	})
	// Wait for the first delivery to record lastDelivery, then fire a second
	// event that should be rate-limited.
	time.Sleep(150 * time.Millisecond)
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file2",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{2})},
		ChangeType: store.ChangeCreated,
		Context:    &store.MutationContext{ChainID: "chain-R"},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countMarkers(t, li, "system/runtime/chain-errors/lost/chain-R/sub-rate/rate_limited/") > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := countMarkers(t, li, "system/runtime/chain-errors/lost/chain-R/sub-rate/rate_limited/"); got == 0 {
		t.Fatalf("expected lost marker with reason=rate_limited; found 0")
	}
}

// TestLostMarker_OnMaxEventsReached verifies §4.7: max_events_reached marker.
func TestLostMarker_OnMaxEventsReached(t *testing.T) {
	engine, cs, li, identity := setupEngine(t)
	tokenHash := storeDeliveryToken(t, cs, identity)

	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error { return nil }

	maxEvents := uint64(1)
	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-cap",
		Pattern:            "local/data/*",
		Events:             []string{"created"},
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

	// First event delivers + bumps deliveredCount to 1.
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file1",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{1})},
		ChangeType: store.ChangeCreated,
		Context:    &store.MutationContext{ChainID: "chain-M"},
	})
	// Wait for delivery tracking to update.
	time.Sleep(200 * time.Millisecond)
	// Second event: checkLimits sees deliveredCount >= 1 → limitTerminate.
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file2",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{2})},
		ChangeType: store.ChangeCreated,
		Context:    &store.MutationContext{ChainID: "chain-M"},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countMarkers(t, li, "system/runtime/chain-errors/lost/chain-M/sub-cap/max_events_reached/") > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := countMarkers(t, li, "system/runtime/chain-errors/lost/chain-M/sub-cap/max_events_reached/"); got == 0 {
		t.Fatalf("expected lost marker with reason=max_events_reached; found 0")
	}
}

// TestLostMarker_BoundOnEmptyChainID confirms the engine falls back to a
// stable "none" chain segment when the triggering tree change carries no
// chain causality, rather than silently dropping the §4.7 marker.
func TestLostMarker_BoundOnEmptyChainID(t *testing.T) {
	engine, cs, li, identity := setupEngine(t)
	tokenHash := storeDeliveryToken(t, cs, identity)

	engine.Deliver = func(ctx context.Context, req DeliveryRequest) error {
		return errors.New("down")
	}

	engine.Register(types.SubscriptionData{
		SubscriptionID:     "sub-no-chain",
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

	// No Context on the tree change ⇒ no ChainID.
	engine.OnTreeChange(store.TreeChangeEvent{
		Path:       "local/data/file",
		Hash:       hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{9})},
		ChangeType: store.ChangeCreated,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countMarkers(t, li, "system/runtime/chain-errors/lost/none/sub-no-chain/delivery_failed/") > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := countMarkers(t, li, "system/runtime/chain-errors/lost/none/sub-no-chain/delivery_failed/"); got == 0 {
		t.Fatal("expected lost marker bound under chain segment 'none' when ChainID empty")
	}
}

// countMarkers walks the location index and counts bindings whose path
// starts with prefix. Tests assert at-least-one rather than exact-one
// because same-reason re-binding is idempotent per §4.7.
func countMarkers(t *testing.T, li store.LocationIndex, prefix string) int {
	t.Helper()
	n := 0
	for _, entry := range li.List("") {
		if strings.HasPrefix(entry.Path, prefix) {
			n++
		}
	}
	return n
}
