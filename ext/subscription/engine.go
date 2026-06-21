package subscription

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// DeliveryRequest describes a notification delivery for the peer to dispatch.
type DeliveryRequest struct {
	RequestID    string
	DeliverURI   string
	DeliverToken entity.Entity
	Params       entity.Entity
	Resource     *types.ResourceTarget
	ChainID      string
	CascadeDepth *uint64 // Cascade depth from emission context (G-3, SUB §4.5)
	// Included carries entities bundled with the delivery envelope's
	// `included` map (EXTENSION-SUBSCRIPTION v3.14, §4.2). Populated when the
	// subscription opted into `include_payload` and the engine successfully
	// resolved the changed entity at delivery time. On source-side resolution
	// failure the engine delivers hash-only (Included nil/empty) with a
	// debug log — never fail-stop. Receivers MAY fall back to a cross-peer
	// GET in that case.
	Included map[hash.Hash]entity.Entity
}

// DeliverFunc dispatches a notification delivery. Injected by the peer to
// avoid importing the protocol package.
type DeliverFunc func(ctx context.Context, req DeliveryRequest) error

// activeSubscription is the runtime state for a registered subscription.
type activeSubscription struct {
	data           types.SubscriptionData
	deliveredCount uint64
	lastDelivery   time.Time
	createdAt      time.Time
}

// Engine manages active subscriptions and delivers notifications on tree changes.
type Engine struct {
	mu            sync.RWMutex
	subscriptions map[string]*activeSubscription // id -> state
	pathIndex     map[string][]string            // qualified pattern -> []subscription_id

	store         store.ContentStore
	locationIndex store.LocationIndex
	debugLog      *log.Logger

	// Inspect hooks (GUIDE-INSPECTABILITY v1.1 §2.1 #6 + #7). Append-only via
	// AddEmitHook / AddDeliverHook; readers are inline on the hot path with no
	// lock — callers MUST register before the peer starts accepting traffic.
	emitHooks    []namedEmitHook
	deliverHooks []namedDeliverHook

	// maxSubscribersPerPrefix limits how many active subscriptions a single
	// pattern/prefix can have. 0 means no limit (default).
	maxSubscribersPerPrefix uint64

	// Deliver is injected after construction — dispatches notification via callback.
	Deliver DeliverFunc

	// deliveryShards is a fixed-size pool of per-shard delivery queues, each
	// drained by its own goroutine (started by StartDelivery). Delivery
	// requests are routed to a shard by FNV-32 hash of the subscription_id —
	// every delivery for a given subscription lands in the same shard, so its
	// goroutine drains them in tree-change order (EXTENSION-SUBSCRIPTION
	// v3.15 §5.2 within-subscription ordering MUST). Across subscriptions
	// the shards parallelize (v3.15 §5.2 SHOULD; §11.2). Workbench-go's
	// Stage 5 K-worker microbench measured K=4 → 3.8×; default shard count
	// is runtime.NumCPU() capped at maxDeliveryShards.
	//
	// Per-shard queues are intentionally non-blocking on the OnTreeChange
	// producer side (drop-on-full). Blocking here would create a deadlock
	// cycle when Deliver triggers cross-peer signature ingestion that writes
	// back to the local tree: OnTreeChange (under Set) blocks → fanOut
	// blocks → emit blocks → the next Set within Deliver's call stack
	// hangs → the shard's drain goroutine never advances.
	deliveryShards []chan pendingDelivery

	// deliveryQueueSize is the total buffer capacity across all shards.
	// Configurable via SetDeliveryQueueSize; defaults to
	// defaultDeliveryQueueSize. Per-shard capacity = deliveryQueueSize /
	// len(deliveryShards), with a floor of 1.
	deliveryQueueSize int

	// deliveryWorkers is the configured shard count. Set via
	// SetDeliveryWorkers; default 0 → resolved at StartDelivery to
	// min(runtime.NumCPU(), maxDeliveryShards).
	deliveryWorkers int

	// droppedDeliveries counts notifications dropped when a shard queue was
	// full. Exposed via DroppedDeliveries() for monitoring. Operators should
	// alert on growth — a non-zero rate means a shard is undersized for the
	// workload or that Deliver is too slow.
	droppedDeliveries atomic.Uint64
}

// defaultDeliveryQueueSize is the total buffer capacity across all delivery
// shards. The previous single-queue default (256) dropped notifications
// during bursty workloads; 65536 × ~256 bytes per pendingDelivery ≈ 16 MiB
// worst-case is acceptable for a peer process. Split evenly across shards.
const defaultDeliveryQueueSize = 65536

// maxDeliveryShards caps the auto-resolved shard count when
// SetDeliveryWorkers is not called. K=4 → 3.8× and K=8 → 5× per
// workbench-go's Stage 5 microbench; returns diminish past CPU count.
const maxDeliveryShards = 8

// pendingDelivery pairs a delivery request with the subscription ID so the
// delivery goroutine can update tracking state after successful delivery.
type pendingDelivery struct {
	req            DeliveryRequest
	subscriptionID string
}

// NewEngine creates a subscription engine.
func NewEngine(cs store.ContentStore, li store.LocationIndex, logger *log.Logger) *Engine {
	return &Engine{
		subscriptions: make(map[string]*activeSubscription),
		pathIndex:     make(map[string][]string),
		store:         cs,
		locationIndex: li,
		debugLog:      logger,
	}
}

// SetLocationIndex replaces the engine's location index. Call this after peer
// construction to ensure the engine uses the peer's wrapped index (with
// namespace and notification layers) rather than the raw underlying index.
func (e *Engine) SetLocationIndex(li store.LocationIndex) {
	e.locationIndex = li
}

// SetMaxSubscribersPerPrefix configures the maximum number of direct subscribers
// allowed per pattern/prefix. A value of 0 means no limit (default).
func (e *Engine) SetMaxSubscribersPerPrefix(n uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxSubscribersPerPrefix = n
}

// MaxSubscribersPerPrefix returns the configured capacity limit.
func (e *Engine) MaxSubscribersPerPrefix() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.maxSubscribersPerPrefix
}

// SubscriberCountForPrefix counts active subscriptions for a given qualified pattern.
func (e *Engine) SubscriberCountForPrefix(pattern string) int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.pathIndex[pattern])
}

// SubscriberIdentitiesForPrefix returns the identity hashes of subscribers for
// a given qualified pattern. Used by the redirect response to provide
// alternatives. Returns at most maxCount entries in randomized order.
// Excludes the given excludeIdentity (the requesting subscriber).
func (e *Engine) SubscriberIdentitiesForPrefix(pattern string, excludeIdentity hash.Hash, maxCount int) []hash.Hash {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ids := e.pathIndex[pattern]
	if len(ids) == 0 {
		return nil
	}

	// Collect unique subscriber identities, excluding the requester.
	seen := make(map[hash.Hash]struct{})
	var identities []hash.Hash
	for _, id := range ids {
		sub, ok := e.subscriptions[id]
		if !ok {
			continue
		}
		ident := sub.data.SubscriberIdentity
		if ident == excludeIdentity {
			continue
		}
		if _, dup := seen[ident]; dup {
			continue
		}
		seen[ident] = struct{}{}
		identities = append(identities, ident)
	}

	// Randomize order to distribute load across alternatives.
	// Use a simple Fisher-Yates shuffle with time-based seed.
	if len(identities) > 1 {
		seed := time.Now().UnixNano()
		for i := len(identities) - 1; i > 0; i-- {
			j := int(seed>>uint(i)) % (i + 1)
			if j < 0 {
				j = -j
			}
			identities[i], identities[j] = identities[j], identities[i]
		}
	}

	if maxCount > 0 && len(identities) > maxCount {
		identities = identities[:maxCount]
	}
	return identities
}

func (e *Engine) debugf(format string, args ...any) {
	if e.debugLog != nil {
		e.debugLog.Printf("subscription: "+format, args...)
	}
}

// Load scans the location index for subscription entities at
// system/subscription/* and rebuilds the engine's in-memory routing maps.
// Required after restart with persistent storage: subscription entities live
// in the tree (TreeSet at handle_subscribe time) but the engine's
// subscriptions/pathIndex maps are runtime-only and start empty on cold boot.
// Without this Load(), tree changes after restart would not match any
// subscription and no deliveries would fire — subscribers would silently
// stop receiving notifications.
//
// Must be called after SetLocationIndex and before StartDelivery. Safe to
// call multiple times — Register is idempotent on (SubscriptionID).
//
// See docs/architecture/proposals/active/DESIGN-SQLITE-PERSISTENCE.md §4.3
// and the extension-persistence-classification feedback.
func (e *Engine) Load() {
	e.mu.RLock()
	li := e.locationIndex
	cs := e.store
	e.mu.RUnlock()
	if li == nil || cs == nil {
		return
	}
	loaded := 0
	for _, entry := range li.List("") {
		ent, ok := cs.Get(entry.Hash)
		if !ok || ent.Type != types.TypeSubscription {
			continue
		}
		sub, err := types.SubscriptionDataFromEntity(ent)
		if err != nil {
			continue
		}
		e.Register(sub)
		loaded++
	}
	if loaded > 0 {
		e.debugf("loaded %d subscriptions from tree", loaded)
	}
}

// Register adds a subscription to the engine's index.
// sub.Pattern must be a qualified path pattern (e.g. "{peerID}/data/*").
func (e *Engine) Register(sub types.SubscriptionData) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.subscriptions[sub.SubscriptionID] = &activeSubscription{
		data:      sub,
		createdAt: time.UnixMilli(int64(sub.CreatedAt)),
	}
	e.pathIndex[sub.Pattern] = append(e.pathIndex[sub.Pattern], sub.SubscriptionID)
	e.debugf("registered subscription %s for pattern=%s", sub.SubscriptionID, sub.Pattern)
}

// Remove removes a subscription from the engine's index.
func (e *Engine) Remove(subscriptionID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	sub, ok := e.subscriptions[subscriptionID]
	if !ok {
		return
	}

	// Remove from path index.
	pattern := sub.data.Pattern
	ids := e.pathIndex[pattern]
	for i, id := range ids {
		if id == subscriptionID {
			e.pathIndex[pattern] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	if len(e.pathIndex[pattern]) == 0 {
		delete(e.pathIndex, pattern)
	}

	delete(e.subscriptions, subscriptionID)
	e.debugf("removed subscription %s", subscriptionID)
}

// FindRenewal checks if a subscription already exists for the same subscriber,
// pattern, and callback URI. Returns the existing subscription ID or empty string.
func (e *Engine) FindRenewal(subscriberIdentity hash.Hash, pattern, callbackURI string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for id, sub := range e.subscriptions {
		if sub.data.SubscriberIdentity == subscriberIdentity &&
			sub.data.Pattern == pattern &&
			sub.data.DeliverURI == callbackURI {
			return id
		}
	}
	return ""
}

// OnTreeChange is the sync hook callback for the emit pipeline. Registered as
// "subscription/notification" at position 6 (after auto-version). Performs
// subscription matching and limit checking synchronously, then queues delivery
// requests for async processing by the delivery goroutine started via
// StartDelivery. Returns nil — subscriptions never halt the cascade.
func (e *Engine) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	// Map change type to event string.
	var eventStr string
	switch evt.ChangeType {
	case store.ChangeCreated:
		eventStr = "created"
	case store.ChangeModified:
		eventStr = "updated"
	case store.ChangeDeleted:
		eventStr = "deleted"
	default:
		return nil
	}

	// Find matching subscriptions against the qualified path.
	matchingIDs := e.matchSubscriptions(evt.Path)
	if len(matchingIDs) == 0 {
		return nil
	}

	notifURI := evt.Path

	e.debugf("event %s at %s matches %d subscriptions", eventStr, evt.Path, len(matchingIDs))

	for _, subID := range matchingIDs {
		e.mu.RLock()
		sub, ok := e.subscriptions[subID]
		e.mu.RUnlock()
		if !ok {
			continue
		}

		// Check event filter.
		if !containsEvent(sub.data.Events, eventStr) {
			continue
		}

		// Extract chain causality from the triggering tree change for
		// §4.7 lost-marker chain_id inheritance per §4.5.
		chainID := ""
		if evt.Context != nil {
			chainID = evt.Context.ChainID
		}

		// Check limits. §4.7 requires the engine to bind a lost marker for
		// limit-exceeded suppression (rate_limited / max_events_reached /
		// max_duration_reached) — not silently drop.
		action, limitReason := e.checkLimits(sub)
		if action == limitDeny {
			e.bindLostMarker(chainID, sub.data.SubscriptionID, limitReason, sub.data.DeliverURI, 0, "")
			continue
		}
		if action == limitTerminate {
			e.bindLostMarker(chainID, sub.data.SubscriptionID, limitReason, sub.data.DeliverURI, 0, "")
			e.terminateSubscription(sub.data.SubscriptionID, "limit_reached")
			continue
		}

		// Validate delivery token before delivery. Token-side failures are
		// capability rejections per §4.7's three-class taxonomy — bind a
		// marker before terminating.
		deliverTokenEntity, ok := e.store.Get(sub.data.DeliverToken)
		if !ok {
			e.debugf("deliver token %s not found, terminating subscription %s",
				sub.data.DeliverToken, sub.data.SubscriptionID)
			e.bindLostMarker(chainID, sub.data.SubscriptionID, "deliver_token_missing", sub.data.DeliverURI, 0, "")
			e.terminateSubscription(sub.data.SubscriptionID, "deliver_token_missing")
			continue
		}

		// Check delivery token expiry.
		capData, err := types.CapabilityTokenDataFromEntity(deliverTokenEntity)
		if err != nil {
			e.debugf("invalid delivery token for subscription %s: %v", sub.data.SubscriptionID, err)
			e.bindLostMarker(chainID, sub.data.SubscriptionID, "deliver_token_invalid", sub.data.DeliverURI, 0, "")
			e.terminateSubscription(sub.data.SubscriptionID, "deliver_token_invalid")
			continue
		}
		if capData.ExpiresAt != nil && *capData.ExpiresAt < uint64(time.Now().UnixMilli()) {
			e.debugf("delivery token expired for subscription %s", sub.data.SubscriptionID)
			e.bindLostMarker(chainID, sub.data.SubscriptionID, "deliver_token_expired", sub.data.DeliverURI, 0, "")
			e.terminateSubscription(sub.data.SubscriptionID, "deliver_token_expired")
			continue
		}

		// Construct notification with canonical entity:// URI.
		notification := types.InboxNotificationData{
			SubscriptionID: sub.data.SubscriptionID,
			Event:          eventStr,
			URI:            notifURI,
			Hash:           evt.Hash,
			PreviousHash:   evt.PreviousHash,
		}
		notifEntity, err := notification.ToEntity()
		if err != nil {
			e.debugf("failed to create notification entity: %v", err)
			continue
		}

		// Inspect: emit-event fires here, at the matcher's "decided to
		// notify + built notification" boundary. Distinct from deliver
		// (fired at the wire-attempt boundary in deliveryLoop).
		e.fireEmit(EmitEvent{
			SubscriptionID:   sub.data.SubscriptionID,
			SourceChangeURI:  evt.Path,
			NotificationHash: notifEntity.ContentHash,
			Timestamp:        time.Now(),
		})

		if e.Deliver == nil {
			e.debugf("no deliver function configured, dropping notification")
			continue
		}

		deliveryReq := DeliveryRequest{
			RequestID:    fmt.Sprintf("notif-%s-%d", sub.data.SubscriptionID, time.Now().UnixNano()),
			DeliverURI:   sub.data.DeliverURI,
			DeliverToken: deliverTokenEntity,
			Params:       notifEntity,
			Resource:     &types.ResourceTarget{Targets: []string{sub.data.DeliverURI}},
			ChainID:      chainID, // §4.7: needed at deliveryLoop for lost-marker on transport failure
		}
		// Inherit cascade_depth from emission context (G-3, SUB §4.5).
		if evt.Context != nil && evt.Context.CascadeDepth != nil {
			deliveryReq.CascadeDepth = evt.Context.CascadeDepth
		}
		// EXTENSION-SUBSCRIPTION v3.14 §4.2: when the subscription opted into
		// include_payload, bundle the changed entity into the delivery
		// envelope's `included`. Removed events (Hash zero) bundle nothing.
		// Source-side resolution failure ⇒ hash-only fallback + debug log;
		// never fail-stop (the receiver MAY fall back to GET).
		if sub.data.IncludePayload && !evt.Hash.IsZero() {
			if ent, ok := e.store.Get(evt.Hash); ok {
				deliveryReq.Included = map[hash.Hash]entity.Entity{
					evt.Hash: ent,
				}
			} else {
				e.debugf("include_payload: entity %s unresolvable at delivery (sub=%s); delivering hash-only",
					evt.Hash, sub.data.SubscriptionID)
			}
		}

		// Queue for async delivery on the subscription's shard. Non-blocking:
		// drop if shard full. See `deliveryShards` field doc for the
		// deadlock-avoidance rationale. Drops are counted and exposed via
		// DroppedDeliveries() so operators can monitor saturation without
		// relying on debug logging.
		shard := e.shardFor(sub.data.SubscriptionID)
		select {
		case e.deliveryShards[shard] <- pendingDelivery{req: deliveryReq, subscriptionID: sub.data.SubscriptionID}:
		default:
			e.droppedDeliveries.Add(1)
			e.debugf("delivery shard full, dropping notification for subscription %s (shard=%d cap=%d, total dropped=%d)",
				sub.data.SubscriptionID, shard, cap(e.deliveryShards[shard]), e.droppedDeliveries.Load())
		}
	}
	return nil
}

// shardFor maps a subscription_id to a delivery-shard index via FNV-32 hash.
// Stable: a given subscription always lands in the same shard, which is what
// preserves within-subscription tree-change ordering (v3.15 §5.2 MUST).
func (e *Engine) shardFor(subscriptionID string) int {
	if len(e.deliveryShards) <= 1 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(subscriptionID))
	return int(h.Sum32() % uint32(len(e.deliveryShards)))
}

// StartDelivery starts the async delivery shard pool that drains queued
// delivery requests from OnTreeChange. Call this after wiring engine.Deliver.
// Spawns one goroutine per shard; each owns its own queue. Within a shard
// (and therefore within a subscription, since FNV(subscription_id) is the
// shard key), deliveries are dispatched strictly in enqueue order — that is
// the EXTENSION-SUBSCRIPTION v3.15 §5.2 within-subscription ordering MUST.
// Across shards, deliveries proceed concurrently (§5.2 cross-subscription
// MAY parallelize; §11.2 SHOULD).
func (e *Engine) StartDelivery(ctx context.Context) {
	workers := e.resolveDeliveryWorkers()
	perShard := e.resolveShardCapacity(workers)
	e.deliveryShards = make([]chan pendingDelivery, workers)
	for i := range e.deliveryShards {
		e.deliveryShards[i] = make(chan pendingDelivery, perShard)
		go e.deliveryLoop(ctx, e.deliveryShards[i])
	}
}

// SetDeliveryQueueSize configures the total async delivery buffer capacity
// across all shards. Must be called BEFORE StartDelivery. A value <= 0 falls
// back to the default (defaultDeliveryQueueSize). Per-shard capacity = total
// / shard count (floored at 1).
//
// Tune up for high-throughput delivery (mount-time bursts, large peer
// fan-out). Tune down only if memory pressure is a concern; the default
// is sized for 1000+ -file mount bursts.
func (e *Engine) SetDeliveryQueueSize(n int) {
	e.deliveryQueueSize = n
}

// SetDeliveryWorkers configures the number of delivery shards (workers).
// Must be called BEFORE StartDelivery. A value <= 0 resolves to
// min(runtime.NumCPU(), maxDeliveryShards) at StartDelivery time. Each
// shard owns one goroutine and one queue; FNV-32(subscription_id) routes
// deliveries to a shard, which is what preserves within-subscription
// ordering while letting cross-subscription work proceed in parallel
// (EXTENSION-SUBSCRIPTION v3.15 §5.2; workbench-go K=4 → 3.8× microbench).
func (e *Engine) SetDeliveryWorkers(n int) {
	e.deliveryWorkers = n
}

func (e *Engine) resolveDeliveryWorkers() int {
	if e.deliveryWorkers > 0 {
		return e.deliveryWorkers
	}
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	if n > maxDeliveryShards {
		n = maxDeliveryShards
	}
	return n
}

func (e *Engine) resolveShardCapacity(workers int) int {
	total := e.deliveryQueueSize
	if total <= 0 {
		total = defaultDeliveryQueueSize
	}
	per := total / workers
	if per < 1 {
		per = 1
	}
	return per
}

// DroppedDeliveries returns the running count of notification-delivery drops
// caused by a full delivery shard. Non-zero means a shard is undersized for
// the workload (or that Deliver is too slow). Monitor with an alert: any
// sustained growth indicates silent notification loss.
func (e *Engine) DroppedDeliveries() uint64 {
	return e.droppedDeliveries.Load()
}

// DeliveryQueueDepth returns the current total depth across all delivery
// shards. Useful for ops dashboards alongside DroppedDeliveries — when
// total depth approaches total capacity, drops are imminent. Note: drops
// happen per-shard, so a hot shard can drop while aggregate depth looks
// healthy.
func (e *Engine) DeliveryQueueDepth() int {
	total := 0
	for _, ch := range e.deliveryShards {
		total += len(ch)
	}
	return total
}

func (e *Engine) deliveryLoop(ctx context.Context, shard chan pendingDelivery) {
	for {
		select {
		case <-ctx.Done():
			return
		case pd, ok := <-shard:
			if !ok {
				return
			}
			deliverErr := e.Deliver(ctx, pd.req)
			// Inspect: deliver-event fires here regardless of outcome.
			// Status 0 + non-empty ErrorCode = transport error; otherwise
			// the Deliver fn surfaces 2xx success or 4xx/5xx failure
			// inside its own return shape (today: nil/non-nil error only).
			devt := DeliverEvent{
				SubscriptionID:   pd.subscriptionID,
				NotificationHash: pd.req.Params.ContentHash,
				DeliverURI:       pd.req.DeliverURI,
				Timestamp:        time.Now(),
			}
			if deliverErr != nil {
				devt.ErrorCode = deliverErr.Error()
			} else {
				devt.Status = 200
			}
			e.fireDeliver(devt)

			if deliverErr != nil {
				// §4.7 transport-failure marker. Engine — not dispatcher —
				// owns this binding so CAT-CHAIN-COMPLETION sees a uniform
				// path family across impls. Reason "delivery_failed" is a
				// catch-all for transport/handler-rejection failures where
				// the DeliverFunc surfaces only an error (today's contract);
				// when DeliverFunc evolves to surface structured codes (e.g.,
				// capability_denied, recv_timeout), the {reason} should
				// upgrade to the specific code per CONTINUATION §3.10.5.
				e.bindLostMarker(pd.req.ChainID, pd.subscriptionID, "delivery_failed",
					pd.req.DeliverURI, 0, deliverErr.Error())
				e.debugf("notification delivery failed for subscription %s: %v",
					pd.subscriptionID, deliverErr)
				continue
			}
			// Update delivery tracking.
			e.mu.Lock()
			if activeSub, ok := e.subscriptions[pd.subscriptionID]; ok {
				activeSub.deliveredCount++
				activeSub.lastDelivery = time.Now()
			}
			e.mu.Unlock()
		}
	}
}

type limitAction int

const (
	limitAllow     limitAction = iota
	limitDeny                  // Drop notification, don't terminate.
	limitTerminate             // Terminate subscription.
)

// checkLimits returns the action plus the canonical §4.7 marker reason for
// non-allow outcomes. Reason is empty for limitAllow. The reason vocabulary
// matches EXTENSION-SUBSCRIPTION §4.7: rate_limited / max_events_reached /
// max_duration_reached.
func (e *Engine) checkLimits(sub *activeSubscription) (limitAction, string) {
	limits := sub.data.Limits
	if limits == nil {
		return limitAllow, ""
	}

	if limits.MaxEvents != nil {
		if sub.deliveredCount >= *limits.MaxEvents {
			return limitTerminate, "max_events_reached"
		}
	}

	if limits.MaxDurationMs != nil {
		elapsed := uint64(time.Since(sub.createdAt).Milliseconds())
		if elapsed >= *limits.MaxDurationMs {
			return limitTerminate, "max_duration_reached"
		}
	}

	if limits.RateLimit != nil && *limits.RateLimit > 0 {
		// Simple rate limiting: check if last delivery was within the rate window.
		// Rate limit is max notifications per minute.
		if !sub.lastDelivery.IsZero() {
			minInterval := time.Minute / time.Duration(*limits.RateLimit)
			if time.Since(sub.lastDelivery) < minInterval {
				return limitDeny, "rate_limited"
			}
		}
	}

	return limitAllow, ""
}

func (e *Engine) terminateSubscription(subscriptionID, reason string) {
	e.debugf("terminating subscription %s: %s", subscriptionID, reason)

	// Remove from engine index.
	e.Remove(subscriptionID)

	// Remove subscription entity from tree.
	path := "system/subscription/" + subscriptionID
	e.locationIndex.Remove(path)
}

// matchSubscriptions finds all subscription IDs whose pattern matches the qualified path.
func (e *Engine) matchSubscriptions(path string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for pattern, ids := range e.pathIndex {
		if matchPattern(pattern, path) {
			matched = append(matched, ids...)
		}
	}

	return matched
}

// matchPattern checks if a path matches a subscription pattern.
// Exact match or subtree wildcard (pattern ends with /*).
func matchPattern(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	if pattern == "*" {
		return true
	}
	return false
}

func containsEvent(events []string, event string) bool {
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}
