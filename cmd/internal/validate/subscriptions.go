package validate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catSubscriptions = "subscriptions"

// matchesPattern checks whether actual matches expected, allowing for qualified
// forms. A peer may return a bare pattern ("data/*"), a qualified pattern
// ("{peerID}/data/*"), or a full entity URI ("entity://{peerID}/data/*") — all
// are valid representations of the same subscription scope.
func matchesPattern(actual, expected, remotePeerID string) bool {
	if actual == expected {
		return true
	}
	qualified := "/" + remotePeerID + "/" + expected
	if actual == qualified {
		return true
	}
	fullURI := "entity://" + remotePeerID + "/" + expected
	return actual == fullURI
}

// runSubscriptions validates the subscription extension (subscribe, unsubscribe,
// notification delivery via inbox handler). This is "Layer 1" validation —
// same-peer delivery where the inbox handler stores notifications locally.
func runSubscriptions(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catSubscriptions)

	// --- Declare all checks ---

	// Step 1: Handler manifests
	r.Declare("subscription_handler_present", "SUBSCRIPTION §3")
	r.Declare("inbox_handler_present", "INBOX §2")

	// Step 2: Subscribe
	r.Declare("subscribe_returns_200", "SUBSCRIPTION §3")
	r.Declare("subscribe_result_has_subscription_id", "SUBSCRIPTION §3")
	r.Declare("subscribe_result_has_pattern", "SUBSCRIPTION §3")
	r.Declare("subscribe_result_has_events", "SUBSCRIPTION §3")

	// Step 3: Subscription entity stored
	r.Declare("subscription_entity_stored", "SUBSCRIPTION §4")
	r.Declare("subscription_entity_type", "SUBSCRIPTION §4")
	r.Declare("subscription_entity_fields", "SUBSCRIPTION §4")

	// Step 4: Notification delivery
	r.Declare("notification_delivered", "SUBSCRIPTION §5")
	r.Declare("notification_listing_roundtrip", "SUBSCRIPTION §5")
	r.Declare("notification_entity_type", "SUBSCRIPTION §5")
	r.Declare("notification_fields_subscription_id", "SUBSCRIPTION §5")
	r.Declare("notification_fields_event", "SUBSCRIPTION §5")
	r.Declare("notification_fields_uri", "SUBSCRIPTION §5")
	r.Declare("notification_fields_hash", "SUBSCRIPTION §5")

	// Step 4b: Notification URI format
	r.Declare("notification_uri_bare_path", "INBOX v5.4 §2.2 (M1)")

	// Step 5: Unsubscribe
	r.Declare("unsubscribe_returns_200", "SUBSCRIPTION §6")
	r.Declare("unsubscribe_removes_entity", "SUBSCRIPTION §6")

	// Step 6: Error cases
	r.Declare("subscribe_missing_deliver_token", "SUBSCRIPTION §3")
	r.Declare("subscribe_missing_resource", "SUBSCRIPTION §3")

	// Step 7: Cleanup
	r.Declare("cleanup", "")

	// Step 8: Max events enforcement
	r.Declare("max_events_subscribe", "SUBSCRIPTION §7")
	r.Declare("max_events_enforced", "SUBSCRIPTION §7")
	r.Declare("max_events_auto_terminated", "SUBSCRIPTION §7")

	// Step 9: Subscription renewal
	r.Declare("renewal_first_subscribe", "SUBSCRIPTION §8")
	r.Declare("renewal_second_subscribe", "SUBSCRIPTION §8")
	r.Declare("renewal_same_id", "SUBSCRIPTION §8")
	r.Declare("renewal_no_duplicate", "SUBSCRIPTION §8")

	// Step 10: Qualified delivery URI
	r.Declare("qualified_uri_token", "SUBSCRIPTION §4")
	r.Declare("qualified_uri_subscribe", "SUBSCRIPTION §4")

	// PROPOSAL-COHERENT-CAPABILITY-AUTHORITY §10 conformance vectors.
	r.Declare("sb1_subscribe_adversary_rejected", "COHERENT-CAP §5.1")

	// EXTENSION-SUBSCRIPTION v3.14 include_payload diagnostic checks.
	// These pinpoint feature presence/absence as Rust + Python land
	// the convergent-mirror recipe; the end-to-end gate lives in the
	// convergent_mirror multi-peer category.
	r.Declare("include_payload_field_persisted", "SUBSCRIPTION §2.1 v3.14")
	r.Declare("include_payload_unauthorized", "SUBSCRIPTION §2.3 v3.13")

	// --- Step 1: Handler manifests ---

	r.Run("subscription_handler_present", func() CheckOutcome {
		subManifestPath := "system/handler/system/subscription"
		ent, _, err := client.TreeGet(ctx, subManifestPath)
		if err != nil {
			return FailCheck("failed to fetch subscription handler manifest: " + err.Error())
		}
		return PassCheck(fmt.Sprintf("subscription handler manifest present (type: %s)", ent.Type))
	})

	r.Run("inbox_handler_present", func() CheckOutcome {
		inboxManifestPath := "system/handler/system/inbox"
		ent, _, err := client.TreeGet(ctx, inboxManifestPath)
		if err != nil {
			return FailCheck("failed to fetch inbox handler manifest: " + err.Error())
		}
		return PassCheck(fmt.Sprintf("inbox handler manifest present (type: %s)", ent.Type))
	})

	// --- Step 2: Subscribe to a test path pattern ---

	inboxURI := "system/inbox/validate-sub-test"
	inboxOp := "receive"
	pattern := "system/validate/sub-test/*"

	r.Run("subscribe_returns_200", func() CheckOutcome {
		tokenEntity, tokenSigEntity, err := client.CreateDeliveryToken(inboxURI, inboxOp)
		if err != nil {
			return FailCheck("failed to create delivery token: " + err.Error())
		}
		r.Store("token_entity", tokenEntity)
		r.Store("token_sig_entity", tokenSigEntity)

		subID, env, _, err := client.Subscribe(ctx, pattern, inboxURI, inboxOp, tokenEntity, tokenSigEntity, []string{"created", "updated", "deleted"}, nil)
		if err != nil {
			// Try to extract status from the error or envelope.
			respData, decErr := types.ExecuteResponseDataFromEntity(env.Root)
			if decErr == nil && respData.Status != 200 {
				return FailCheck(fmt.Sprintf("subscribe returned status %d (expected 200)", respData.Status))
			}
			return FailCheck("subscribe failed: " + err.Error())
		}
		r.Store("sub_id", subID)
		r.Store("sub_env", env)
		return PassCheck("subscribe returned status 200")
	})

	r.Run("subscribe_result_has_subscription_id", func() CheckOutcome {
		if out, ok := r.Require("subscribe_returns_200"); !ok {
			return out
		}
		subID := r.Load("sub_id").(string)
		if subID != "" {
			return PassCheck(fmt.Sprintf("subscription_id: %s", subID))
		}
		return FailCheck("subscribe result missing subscription_id")
	})

	r.Run("subscribe_result_has_pattern", func() CheckOutcome {
		if out, ok := r.Require("subscribe_result_has_subscription_id"); !ok {
			return out
		}
		env := r.Load("sub_env").(entity.Envelope)
		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return FailCheck("failed to decode subscribe response: " + err.Error())
		}
		var resultEntity entity.Entity
		if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
			return FailCheck("failed to decode subscribe result entity: " + err.Error())
		}
		subData, err := types.SubscriptionDataFromEntity(resultEntity)
		if err != nil {
			return FailCheck("failed to decode subscription data: " + err.Error())
		}
		r.Store("sub_data", subData)
		if matchesPattern(subData.Pattern, pattern, string(client.RemotePeerID())) {
			return PassCheck(fmt.Sprintf("pattern: %s", subData.Pattern))
		}
		return FailCheck(fmt.Sprintf("pattern=%q (expected %q or qualified form)", subData.Pattern, pattern))
	})

	r.Run("subscribe_result_has_events", func() CheckOutcome {
		if out, ok := r.Require("subscribe_result_has_pattern"); !ok {
			return out
		}
		subData := r.Load("sub_data").(types.SubscriptionData)
		if len(subData.Events) > 0 {
			return PassCheck(fmt.Sprintf("events: %v", subData.Events))
		}
		return FailCheck("subscribe result has no events")
	})

	// --- Step 3: Subscription entity stored ---

	r.Run("subscription_entity_stored", func() CheckOutcome {
		if out, ok := r.Require("subscribe_result_has_subscription_id"); !ok {
			return out
		}
		subID := r.Load("sub_id").(string)
		subPath := fmt.Sprintf("system/subscription/%s", subID)
		ent, _, err := client.TreeGet(ctx, subPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("failed to get subscription entity at %s: %v", subPath, err))
		}
		r.Store("sub_entity", ent)
		return PassCheck(fmt.Sprintf("subscription entity stored at %s", subPath))
	})

	r.Run("subscription_entity_type", func() CheckOutcome {
		if out, ok := r.Require("subscription_entity_stored"); !ok {
			return out
		}
		ent := r.Load("sub_entity").(entity.Entity)
		if ent.Type == types.TypeSubscription {
			return PassCheck("subscription entity type is system/subscription")
		}
		return FailCheck(fmt.Sprintf("subscription entity type is %q (expected %q)", ent.Type, types.TypeSubscription))
	})

	r.Run("subscription_entity_fields", func() CheckOutcome {
		if out, ok := r.Require("subscription_entity_stored"); !ok {
			return out
		}
		ent := r.Load("sub_entity").(entity.Entity)
		subID := r.Load("sub_id").(string)
		subData, err := types.SubscriptionDataFromEntity(ent)
		if err != nil {
			return FailCheck("failed to decode subscription entity: " + err.Error())
		}

		var fieldIssues []string
		if subData.SubscriptionID != subID {
			fieldIssues = append(fieldIssues, fmt.Sprintf("subscription_id=%q (expected %q)", subData.SubscriptionID, subID))
		}
		if !matchesPattern(subData.Pattern, pattern, string(client.RemotePeerID())) {
			fieldIssues = append(fieldIssues, fmt.Sprintf("pattern=%q (expected %q or qualified form)", subData.Pattern, pattern))
		}
		if subData.DeliverURI != inboxURI {
			fieldIssues = append(fieldIssues, fmt.Sprintf("deliver_uri=%q (expected %q)", subData.DeliverURI, inboxURI))
		}
		if len(subData.Events) == 0 {
			fieldIssues = append(fieldIssues, "events is empty")
		}
		if subData.SubscriberIdentity.IsZero() {
			fieldIssues = append(fieldIssues, "subscriber_identity is zero")
		}
		if subData.DeliverToken.IsZero() {
			fieldIssues = append(fieldIssues, "deliver_token is zero")
		}
		if subData.CreatedAt == 0 {
			fieldIssues = append(fieldIssues, "created_at is zero")
		}

		if len(fieldIssues) == 0 {
			return PassCheck(fmt.Sprintf("all fields valid (events=%v, deliver_uri=%s)", subData.Events, subData.DeliverURI))
		}
		return FailCheck(fmt.Sprintf("field issues: %v", fieldIssues))
	})

	// --- Step 4: Notification delivery ---

	r.Run("notification_delivered", func() CheckOutcome {
		if out, ok := r.Require("subscribe_result_has_subscription_id"); !ok {
			return out
		}

		// PUT a test entity at a path matching the subscription pattern.
		testData, _ := ecf.Encode(map[string]interface{}{
			"label": "subscription-validation-test",
			"seq":   1,
		})
		testEntity, err := entity.NewEntity("system/validate/sub-test-data", cbor.RawMessage(testData))
		if err != nil {
			return FailCheck("failed to create test entity: " + err.Error())
		}

		testPath := "system/validate/sub-test/entity-1"
		_, err = client.TreePut(ctx, testPath, testEntity)
		if err != nil {
			return FailCheck("failed to put test entity: " + err.Error())
		}
		r.Store("test_entity", testEntity)
		r.Store("test_path", testPath)

		// Poll for notification delivery at inbox storage path.
		notifPrefix := inboxURI + "/"

		var notifEntries map[string]interface{}
		var pollErr error
		for attempt := 0; attempt < 10; attempt++ {
			time.Sleep(200 * time.Millisecond)
			notifEntries, _, pollErr = client.TreeListing(ctx, notifPrefix)
			if pollErr == nil && len(notifEntries) > 0 {
				break
			}
		}

		if pollErr != nil || len(notifEntries) == 0 {
			msg := "no notification delivered after 2s polling"
			if pollErr != nil {
				msg = fmt.Sprintf("notification poll failed: %v", pollErr)
			}
			return FailCheck(msg)
		}

		r.Store("notif_entries", notifEntries)
		r.Store("notif_prefix", notifPrefix)
		return PassCheck(fmt.Sprintf("notification delivered (%d entries at %s)", len(notifEntries), notifPrefix))
	})

	r.Run("notification_listing_roundtrip", func() CheckOutcome {
		if out, ok := r.Require("notification_delivered"); !ok {
			return out
		}
		notifEntries := r.Load("notif_entries").(map[string]interface{})
		notifPrefix := r.Load("notif_prefix").(string)

		// Verify ALL listed notification entries are individually fetchable.
		fetchFailed := 0
		for key := range notifEntries {
			entryHash := extractListingHash(notifEntries[key])
			if entryHash.IsZero() {
				continue
			}
			p := notifPrefix + key
			ent, _, err := client.TreeGet(ctx, p)
			if err != nil {
				fetchFailed++
				return FailCheck(fmt.Sprintf("listed notification %q not fetchable: %v", p, err))
			} else if ent.ContentHash != entryHash {
				fetchFailed++
				return FailCheck(fmt.Sprintf("notification %q hash mismatch: listing=%s get=%s", p, entryHash, ent.ContentHash))
			}
		}
		return PassCheck(fmt.Sprintf("all %d listed notifications individually fetchable", len(notifEntries)))
	})

	r.Run("notification_entity_type", func() CheckOutcome {
		if out, ok := r.Require("notification_delivered"); !ok {
			return out
		}
		notifEntries := r.Load("notif_entries").(map[string]interface{})
		notifPrefix := r.Load("notif_prefix").(string)

		// Read the first notification entity to validate its contents.
		var notifPath string
		for key := range notifEntries {
			notifPath = notifPrefix + key
			break
		}

		notifEnt, _, err := client.TreeGet(ctx, notifPath)
		if err != nil {
			return WarnCheck("failed to fetch notification entity: " + err.Error())
		}

		r.Store("notif_entity", notifEnt)
		r.Store("notif_path", notifPath)
		if notifEnt.Type == types.TypeInboxNotification {
			return PassCheck("notification entity type is system/protocol/inbox/notification")
		}
		return FailCheck(fmt.Sprintf("notification entity type is %q (expected %q)", notifEnt.Type, types.TypeInboxNotification))
	})

	r.Run("notification_fields_subscription_id", func() CheckOutcome {
		if out, ok := r.Require("notification_entity_type"); !ok {
			return out
		}
		notifEnt := r.Load("notif_entity").(entity.Entity)
		subID := r.Load("sub_id").(string)

		notifData, err := types.InboxNotificationDataFromEntity(notifEnt)
		if err != nil {
			return FailCheck("failed to decode notification data: " + err.Error())
		}
		r.Store("notif_data", notifData)

		if notifData.SubscriptionID == subID {
			return PassCheck("notification subscription_id matches")
		}
		return FailCheck(fmt.Sprintf("notification subscription_id=%q (expected %q)", notifData.SubscriptionID, subID))
	})

	r.Run("notification_fields_event", func() CheckOutcome {
		if out, ok := r.Require("notification_fields_subscription_id"); !ok {
			return out
		}
		notifData := r.Load("notif_data").(types.InboxNotificationData)
		if notifData.Event == "created" {
			return PassCheck("notification event is 'created'")
		}
		return FailCheck(fmt.Sprintf("notification event=%q (expected 'created')", notifData.Event))
	})

	r.Run("notification_fields_uri", func() CheckOutcome {
		if out, ok := r.Require("notification_fields_subscription_id"); !ok {
			return out
		}
		notifData := r.Load("notif_data").(types.InboxNotificationData)
		testPath := r.Load("test_path").(string)
		if matchesPattern(notifData.URI, testPath, string(client.RemotePeerID())) {
			return PassCheck(fmt.Sprintf("notification URI: %s", notifData.URI))
		}
		return FailCheck(fmt.Sprintf("notification URI=%q (expected %q or qualified form)", notifData.URI, testPath))
	})

	r.Run("notification_fields_hash", func() CheckOutcome {
		if out, ok := r.Require("notification_fields_subscription_id"); !ok {
			return out
		}
		notifData := r.Load("notif_data").(types.InboxNotificationData)
		testEntity := r.Load("test_entity").(entity.Entity)
		if notifData.Hash == testEntity.ContentHash {
			return PassCheck("notification hash matches PUT entity hash")
		}
		return FailCheck(fmt.Sprintf("notification hash=%s (expected %s)", notifData.Hash, testEntity.ContentHash))
	})

	// --- Step 4b: Notification URI format ---

	r.Run("notification_uri_bare_path", func() CheckOutcome {
		if out, ok := r.Require("notification_fields_subscription_id"); !ok {
			return out
		}
		notifData := r.Load("notif_data").(types.InboxNotificationData)
		if strings.HasPrefix(notifData.URI, "entity://") {
			return FailCheck(fmt.Sprintf("notification URI starts with entity:// (%q) — INBOX v5.4 §2.2 (M1) requires bare tree path", notifData.URI))
		}
		return PassCheck(fmt.Sprintf("notification URI is bare tree path: %s", notifData.URI))
	})

	// --- Step 5: Unsubscribe ---

	r.Run("unsubscribe_returns_200", func() CheckOutcome {
		if out, ok := r.Require("subscribe_result_has_subscription_id"); !ok {
			return out
		}
		subID := r.Load("sub_id").(string)

		env, _, err := client.Unsubscribe(ctx, subID)
		if err != nil {
			return FailCheck("unsubscribe failed: " + err.Error())
		}

		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return FailCheck("failed to decode unsubscribe response: " + err.Error())
		}

		if respData.Status == 200 {
			return PassCheck("unsubscribe returned status 200")
		}
		return FailCheck(fmt.Sprintf("unsubscribe returned status %d (expected 200)", respData.Status))
	})

	r.Run("unsubscribe_removes_entity", func() CheckOutcome {
		if out, ok := r.Require("unsubscribe_returns_200"); !ok {
			return out
		}
		subID := r.Load("sub_id").(string)
		subPath := fmt.Sprintf("system/subscription/%s", subID)
		_, _, getErr := client.TreeGet(ctx, subPath)
		if getErr != nil {
			return PassCheck("subscription entity removed from tree after unsubscribe")
		}
		return FailCheck(fmt.Sprintf("subscription entity still exists at %s after unsubscribe", subPath))
	})

	// --- Step 6: Error cases ---

	r.Run("subscribe_missing_deliver_token", func() CheckOutcome {
		uri := fmt.Sprintf("entity://%s/system/subscription", string(client.RemotePeerID()))

		subReqNoToken := types.SubscriptionRequestData{
			Events: []string{"created"},
			DeliverTo: types.DeliverySpec{
				URI:       "system/inbox/validate-error-test",
				Operation: "receive",
			},
			// DeliverToken intentionally zero/missing.
		}
		params, err := subReqNoToken.ToEntity()
		if err != nil {
			return WarnCheck("could not build subscribe params: " + err.Error())
		}

		resource := &types.ResourceTarget{Targets: []string{"system/validate/sub-test/*"}}
		env, _, sendErr := client.SendExecute(ctx, uri, "subscribe", params, resource)
		if sendErr != nil {
			return WarnCheck("subscribe without token: send error: " + sendErr.Error())
		}

		respData, decErr := types.ExecuteResponseDataFromEntity(env.Root)
		if decErr == nil && respData.Status >= 400 {
			return PassCheck(fmt.Sprintf("subscribe without delivery token returns %d", respData.Status))
		} else if decErr == nil {
			return FailCheck(fmt.Sprintf("subscribe without delivery token returned status %d (expected >= 400)", respData.Status))
		}
		return WarnCheck("could not decode error response: " + decErr.Error())
	})

	r.Run("subscribe_missing_resource", func() CheckOutcome {
		uri := fmt.Sprintf("entity://%s/system/subscription", string(client.RemotePeerID()))

		tokenEntity, tokenSigEntity, err := client.CreateDeliveryToken("system/inbox/validate-error-test", "receive")
		if err != nil {
			return WarnCheck("failed to create token for error test: " + err.Error())
		}

		subReqNoResource := types.SubscriptionRequestData{
			Events: []string{"created"},
			DeliverTo: types.DeliverySpec{
				URI:       "system/inbox/validate-error-test",
				Operation: "receive",
			},
			DeliverToken: tokenEntity.ContentHash,
		}
		params, err := subReqNoResource.ToEntity()
		if err != nil {
			return WarnCheck("could not build subscribe params: " + err.Error())
		}

		extras := map[hash.Hash]entity.Entity{
			tokenEntity.ContentHash:    tokenEntity,
			tokenSigEntity.ContentHash: tokenSigEntity,
		}
		env, _, sendErr := client.SendExecuteWithIncluded(ctx, uri, "subscribe", params, nil, extras)
		if sendErr != nil {
			return WarnCheck("subscribe without resource: send error: " + sendErr.Error())
		}

		respData, decErr := types.ExecuteResponseDataFromEntity(env.Root)
		if decErr == nil && respData.Status >= 400 {
			return PassCheck(fmt.Sprintf("subscribe without resource target returns %d", respData.Status))
		} else if decErr == nil {
			return FailCheck(fmt.Sprintf("subscribe without resource returned status %d (expected >= 400)", respData.Status))
		}
		return WarnCheck("could not decode error response: " + decErr.Error())
	})

	// --- Step 7: Cleanup ---

	r.Run("cleanup", func() CheckOutcome {
		subID, _ := r.Load("sub_id").(string)

		// Remove the test entity at system/validate/sub-test/entity-1.
		cleanupPath("system/validate/sub-test/entity-1", ctx, client)

		// Remove notification entries at the deliver URI prefix.
		notifPrefix := inboxURI + "/"
		entries, _, err := client.TreeListing(ctx, notifPrefix)
		if err == nil {
			for key := range entries {
				cleanupPath(notifPrefix+key, ctx, client)
			}
		}

		_ = subID
		return PassCheck("cleaned up subscription test entities")
	})

	// --- Step 8: Max events enforcement ---

	r.Run("max_events_subscribe", func() CheckOutcome {
		maxInboxURI := "system/inbox/validate-sub-limits"
		maxInboxOp := "receive"
		maxPattern := "system/validate/sub-limit-test/*"

		tokenEntity, tokenSigEntity, err := client.CreateDeliveryToken(maxInboxURI, maxInboxOp)
		if err != nil {
			return FailCheck("failed to create delivery token: " + err.Error())
		}

		maxEvents := uint64(2)
		limits := &types.SubscriptionLimitsData{MaxEvents: &maxEvents}

		subID, _, _, err := client.Subscribe(ctx, maxPattern, maxInboxURI, maxInboxOp, tokenEntity, tokenSigEntity, []string{"created", "updated", "deleted"}, limits)
		if err != nil {
			return FailCheck("subscribe with max_events failed: " + err.Error())
		}
		r.Store("max_events_sub_id", subID)
		r.Store("max_events_inbox_uri", maxInboxURI)
		r.Store("max_events_pattern", maxPattern)
		return PassCheck(fmt.Sprintf("subscribed with max_events=2 (id: %s)", subID))
	})

	r.Run("max_events_enforced", func() CheckOutcome {
		if out, ok := r.Require("max_events_subscribe"); !ok {
			return out
		}
		maxInboxURI := r.Load("max_events_inbox_uri").(string)

		// PUT 3 entities.
		for i := 1; i <= 3; i++ {
			testData, _ := ecf.Encode(map[string]interface{}{"seq": i})
			testEntity, _ := entity.NewEntity("system/validate/sub-limit-data", cbor.RawMessage(testData))
			path := fmt.Sprintf("system/validate/sub-limit-test/entity-%d", i)
			client.TreePut(ctx, path, testEntity)
			time.Sleep(100 * time.Millisecond)
		}

		// Wait for delivery processing.
		time.Sleep(500 * time.Millisecond)

		// Poll for notifications — should have at most 2.
		notifPrefix := maxInboxURI + "/"
		notifEntries, _, listErr := client.TreeListing(ctx, notifPrefix)
		r.Store("max_events_notif_entries", notifEntries)
		r.Store("max_events_notif_prefix", notifPrefix)

		if listErr != nil {
			return WarnCheck("failed to list notifications: " + listErr.Error())
		} else if len(notifEntries) <= 2 {
			return PassCheck(fmt.Sprintf("max_events enforced: %d notifications delivered (max_events=2)", len(notifEntries)))
		}
		return FailCheck(fmt.Sprintf("max_events not enforced: %d notifications delivered (expected <= 2)", len(notifEntries)))
	})

	r.Run("max_events_auto_terminated", func() CheckOutcome {
		if out, ok := r.Require("max_events_subscribe"); !ok {
			return out
		}
		subID := r.Load("max_events_sub_id").(string)

		// Check subscription entity was auto-deleted.
		subPath := fmt.Sprintf("system/subscription/%s", subID)
		_, _, getErr := client.TreeGet(ctx, subPath)

		// Cleanup regardless of result.
		for i := 1; i <= 3; i++ {
			cleanupPath(fmt.Sprintf("system/validate/sub-limit-test/entity-%d", i), ctx, client)
		}
		notifEntries, _ := r.Load("max_events_notif_entries").(map[string]interface{})
		notifPrefix, _ := r.Load("max_events_notif_prefix").(string)
		if notifEntries != nil {
			for key := range notifEntries {
				cleanupPath(notifPrefix+key, ctx, client)
			}
		}

		if getErr != nil {
			return PassCheck("subscription auto-terminated after max_events reached")
		}
		return WarnCheck("subscription still exists after max_events should have been reached")
	})

	// --- Step 9: Subscription renewal ---

	r.Run("renewal_first_subscribe", func() CheckOutcome {
		renewInboxURI := "system/inbox/validate-sub-renew"
		renewInboxOp := "receive"
		renewPattern := "system/validate/sub-renew/*"

		token1, sig1, err := client.CreateDeliveryToken(renewInboxURI, renewInboxOp)
		if err != nil {
			return FailCheck("failed to create first delivery token: " + err.Error())
		}

		subID1, _, _, err := client.Subscribe(ctx, renewPattern, renewInboxURI, renewInboxOp, token1, sig1, []string{"created"}, nil)
		if err != nil {
			return FailCheck("first subscribe failed: " + err.Error())
		}
		r.Store("renewal_sub_id_1", subID1)
		r.Store("renewal_inbox_uri", renewInboxURI)
		r.Store("renewal_inbox_op", renewInboxOp)
		r.Store("renewal_pattern", renewPattern)
		return PassCheck(fmt.Sprintf("first subscription created (id: %s)", subID1))
	})

	r.Run("renewal_second_subscribe", func() CheckOutcome {
		if out, ok := r.Require("renewal_first_subscribe"); !ok {
			return out
		}
		renewInboxURI := r.Load("renewal_inbox_uri").(string)
		renewInboxOp := r.Load("renewal_inbox_op").(string)
		renewPattern := r.Load("renewal_pattern").(string)

		token2, sig2, err := client.CreateDeliveryToken(renewInboxURI, renewInboxOp)
		if err != nil {
			// Cleanup first subscription.
			subID1 := r.Load("renewal_sub_id_1").(string)
			client.Unsubscribe(ctx, subID1)
			return FailCheck("failed to create second delivery token: " + err.Error())
		}

		subID2, _, _, err := client.Subscribe(ctx, renewPattern, renewInboxURI, renewInboxOp, token2, sig2, []string{"created"}, nil)
		if err != nil {
			subID1 := r.Load("renewal_sub_id_1").(string)
			client.Unsubscribe(ctx, subID1)
			return FailCheck("second subscribe (renewal) failed: " + err.Error())
		}
		r.Store("renewal_sub_id_2", subID2)
		return PassCheck(fmt.Sprintf("second subscription returned (id: %s)", subID2))
	})

	r.Run("renewal_same_id", func() CheckOutcome {
		if out, ok := r.Require("renewal_second_subscribe"); !ok {
			return out
		}
		subID1 := r.Load("renewal_sub_id_1").(string)
		subID2 := r.Load("renewal_sub_id_2").(string)

		if subID1 == subID2 {
			return PassCheck("renewal returned same subscription_id")
		}
		return PassCheck(fmt.Sprintf("renewal returned new subscription_id (%s → %s) — old subscription replaced", subID1, subID2))
	})

	r.Run("renewal_no_duplicate", func() CheckOutcome {
		if out, ok := r.Require("renewal_second_subscribe"); !ok {
			return out
		}
		renewPattern := r.Load("renewal_pattern").(string)
		renewInboxURI := r.Load("renewal_inbox_uri").(string)
		subID1 := r.Load("renewal_sub_id_1").(string)
		subID2 := r.Load("renewal_sub_id_2").(string)

		listing, _, listErr := client.TreeListing(ctx, "system/subscription/")
		if listErr != nil {
			return WarnCheck("failed to list subscriptions: " + listErr.Error())
		}

		// Count subscriptions that match our pattern by reading each.
		matchCount := 0
		for key := range listing {
			subPath := "system/subscription/" + key
			ent, _, getErr := client.TreeGet(ctx, subPath)
			if getErr != nil {
				continue
			}
			subData, decErr := types.SubscriptionDataFromEntity(ent)
			if decErr != nil {
				continue
			}
			if matchesPattern(subData.Pattern, renewPattern, string(client.RemotePeerID())) && subData.DeliverURI == renewInboxURI {
				matchCount++
			}
		}

		// Cleanup.
		client.Unsubscribe(ctx, subID2)
		if subID1 != subID2 {
			client.Unsubscribe(ctx, subID1)
		}

		if matchCount <= 1 {
			return PassCheck(fmt.Sprintf("no duplicate subscriptions (%d matching entries)", matchCount))
		}
		return FailCheck(fmt.Sprintf("%d duplicate subscriptions found for same (pattern, deliver_uri)", matchCount))
	})

	// --- Step 10: Qualified delivery URI ---

	r.Run("qualified_uri_token", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		qualifiedInboxURI := "entity://" + peerID + "/system/inbox/validate-sub-qualified"
		qualifiedPattern := "system/validate/sub-qualified/*"

		tokenEntity, tokenSigEntity, err := client.CreateDeliveryToken(qualifiedInboxURI, "receive")
		if err != nil {
			return FailCheck("failed to create delivery token with entity:// URI: " + err.Error())
		}
		r.Store("qualified_token_entity", tokenEntity)
		r.Store("qualified_token_sig_entity", tokenSigEntity)
		r.Store("qualified_inbox_uri", qualifiedInboxURI)
		r.Store("qualified_pattern", qualifiedPattern)
		return PassCheck("delivery token created with entity:// URI")
	})

	r.Run("qualified_uri_subscribe", func() CheckOutcome {
		if out, ok := r.Require("qualified_uri_token"); !ok {
			return out
		}
		qualifiedInboxURI := r.Load("qualified_inbox_uri").(string)
		qualifiedPattern := r.Load("qualified_pattern").(string)
		tokenEntity := r.Load("qualified_token_entity").(entity.Entity)
		tokenSigEntity := r.Load("qualified_token_sig_entity").(entity.Entity)

		subID, _, _, err := client.Subscribe(ctx, qualifiedPattern, qualifiedInboxURI, "receive", tokenEntity, tokenSigEntity, []string{"created", "updated", "deleted"}, nil)
		if err != nil {
			return FailCheck("subscribe with entity:// qualified delivery URI failed: " + err.Error())
		}

		// Unsubscribe to clean up.
		client.Unsubscribe(ctx, subID)

		// Clean up inbox path.
		cleanupPath("system/inbox/validate-sub-qualified", ctx, client)

		return PassCheck("subscribe succeeded with entity:// qualified delivery URI")
	})

	// SB1 §10: subscriber references a deliver_token whose authority chain
	// doesn't include the subscriber → 403 embedded_cap_unauthorized. Closes
	// the spam exploit (Finding 4 in our security review).
	r.Run("sb1_subscribe_adversary_rejected", func() CheckOutcome {
		deliverURI := "system/inbox/validate-sb1-foreign-target"
		defer cleanupPath(deliverURI, ctx, client)

		foreignCap, foreignSig, foreignID, err := client.ForeignCapability(
			[]string{"system/inbox"}, []string{deliverURI}, []string{"receive"},
		)
		if err != nil {
			return FailCheck("build foreign deliver_token: " + err.Error())
		}

		subReq := types.SubscriptionRequestData{
			DeliverTo:    types.DeliverySpec{URI: deliverURI, Operation: "receive"},
			DeliverToken: foreignCap.ContentHash,
		}
		params, err := subReq.ToEntity()
		if err != nil {
			return FailCheck("build subscribe request: " + err.Error())
		}
		uri := fmt.Sprintf("entity://%s/system/subscription", string(client.RemotePeerID()))
		extras := map[hash.Hash]entity.Entity{
			foreignCap.ContentHash: foreignCap,
			foreignSig.ContentHash: foreignSig,
			foreignID.ContentHash:  foreignID,
		}
		env, _, sendErr := client.SendExecuteWithIncluded(ctx, uri, "subscribe", params,
			&types.ResourceTarget{Targets: []string{"local/sb1-foreign-pattern/*"}}, extras)
		if sendErr != nil {
			return FailCheck("send subscribe: " + sendErr.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		return requireEmbeddedCapUnauthorized(respData, "subscribe with foreign deliver_token")
	})

	// --- EXTENSION-SUBSCRIPTION v3.14 diagnostic checks ---

	// include_payload field persistence (§2.1): subscribing with
	// include_payload=true MUST store the flag on the system/subscription
	// entity so the engine reads it at delivery (§4.2). Failure here means
	// the impl either drops the field at decode or never persists it —
	// convergent_mirror would then fail mysteriously on the source side.
	r.Run("include_payload_field_persisted", func() CheckOutcome {
		ipInbox := "system/inbox/validate-include-payload"
		ipPattern := "system/validate/include-payload-feature/*"

		token, tokenSig, err := client.CreateDeliveryToken(ipInbox, "receive")
		if err != nil {
			return FailCheck("create delivery token: " + err.Error())
		}
		subID, _, _, err := client.SubscribeWithPayload(ctx, ipPattern, ipInbox, "receive",
			token, tokenSig, []string{"created", "updated"}, nil, true)
		if err != nil || subID == "" {
			return FailCheck(fmt.Sprintf("subscribe with include_payload=true: %v", err))
		}
		defer client.Unsubscribe(ctx, subID)

		subPath := "system/subscription/" + subID
		ent, _, err := client.TreeGet(ctx, subPath)
		if err != nil {
			return FailCheck("fetch subscription entity: " + err.Error())
		}
		subData, err := types.SubscriptionDataFromEntity(ent)
		if err != nil {
			return FailCheck("decode subscription entity: " + err.Error())
		}
		if !subData.IncludePayload {
			return FailCheck("subscription entity has include_payload=false after subscribe with include_payload=true (§2.1 v3.14 persistence)")
		}
		return PassCheck("include_payload=true persisted on system/subscription entity")
	})

	// include_payload read-authorization (§2.3 v3.13): subscribing with
	// include_payload=true requires the caller's capability to cover
	// system/tree:get on the resource (because payload delivery pushes
	// entity content). A caller with subscribe-only authority MUST be
	// rejected with 403 payload_unauthorized. This closes the v3.12
	// capability bypass (subscribe could deliver content to a principal
	// authorized only for change-metadata).
	r.Run("include_payload_unauthorized", func() CheckOutcome {
		ipInbox := "system/inbox/validate-include-payload-auth"
		ipPattern := "system/validate/include-payload-auth/*"

		// Mint a narrow self-cap: subscribe-only on system/subscription.
		// No grant for system/tree:get on the resource — the v3.13 check
		// must fail closed.
		narrowCap, narrowCapSig, err := client.CreateDispatchCapabilityWithGrants(
			[]types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/subscription"}},
				Resources:  types.CapabilityScope{Include: []string{ipPattern}},
				Operations: types.CapabilityScope{Include: []string{"subscribe"}},
			}},
		)
		if err != nil {
			return FailCheck("mint narrow subscribe-only cap: " + err.Error())
		}

		// Need a delivery token too — that's a separate authority chain
		// and isn't what's under test. Build it with the connection cap.
		token, tokenSig, err := client.CreateDeliveryToken(ipInbox, "receive")
		if err != nil {
			return FailCheck("create delivery token: " + err.Error())
		}

		subReq := types.SubscriptionRequestData{
			Events: []string{"created", "updated"},
			DeliverTo: types.DeliverySpec{
				URI:       ipInbox,
				Operation: "receive",
			},
			DeliverToken:   token.ContentHash,
			IncludePayload: true,
		}
		params, err := subReq.ToEntity()
		if err != nil {
			return FailCheck("build subscribe request: " + err.Error())
		}
		uri := fmt.Sprintf("entity://%s/system/subscription", string(client.RemotePeerID()))
		extras := map[hash.Hash]entity.Entity{
			token.ContentHash:    token,
			tokenSig.ContentHash: tokenSig,
		}
		respEnv, _, sendErr := client.SendExecuteWithCap(ctx, uri, "subscribe", params,
			&types.ResourceTarget{Targets: []string{ipPattern}},
			narrowCap, narrowCapSig, extras)
		if sendErr != nil {
			return FailCheck("send subscribe with narrow cap: " + sendErr.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode response: " + err.Error())
		}
		if respData.Status == 200 {
			return FailCheck("subscribe with include_payload=true was ACCEPTED despite caller lacking tree:get — §2.3 v3.13 read-authorization bypassed (capability bypass: payload delivery to subscribe-only principal)")
		}
		if respData.Status != 403 {
			return FailCheck(fmt.Sprintf("expected 403 payload_unauthorized; got status %d", respData.Status))
		}
		// Best-effort: error code should be payload_unauthorized.
		errCode := ""
		if respData.Result != nil {
			var errEnt entity.Entity
			if ecf.Decode(respData.Result, &errEnt) == nil {
				if errData, decErr := types.ErrorDataFromEntity(errEnt); decErr == nil {
					errCode = errData.Code
				}
			}
		}
		if errCode == "payload_unauthorized" {
			return PassCheck("subscribe with include_payload=true (no tree:get) rejected 403 payload_unauthorized")
		}
		return PassCheck(fmt.Sprintf("subscribe with include_payload=true (no tree:get) rejected 403 (code=%q; spec says payload_unauthorized)", errCode))
	})

	return r.Results()
}

// cleanupPath removes a single tree path binding (best-effort).
func cleanupPath(path string, ctx context.Context, client *PeerClient) {
	params, resource, err := createRemoveRequest(path)
	if err != nil {
		return
	}
	uri := fmt.Sprintf("entity://%s/system/tree", string(client.RemotePeerID()))
	client.SendExecute(ctx, uri, "put", params, resource)
}
