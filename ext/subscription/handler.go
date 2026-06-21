package subscription

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// HandleSubscribe processes a subscribe operation. Called by the tree handler
// (or any handler that supports subscriptions) to create a new subscription.
func (e *Engine) HandleSubscribe(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	// Decode subscribe request params.
	var subReq types.SubscriptionRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &subReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode subscribe request")
		}
	}

	// Validate delivery token exists in included.
	if subReq.DeliverToken.IsZero() {
		return handler.NewErrorResponse(400, "missing_deliver_token", "subscribe request must include deliver_token")
	}
	deliverTokenEntity, ok := hctx.Included[subReq.DeliverToken]
	if !ok {
		return handler.NewErrorResponse(400, "missing_deliver_token", "deliver_token entity not in included")
	}

	// Validate delivery token grants delivery to the delivery URI.
	capData, err := types.CapabilityTokenDataFromEntity(deliverTokenEntity)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_deliver_token", "could not decode delivery token: "+err.Error())
	}
	if !validateDeliveryTokenScope(capData, subReq.DeliverTo.URI, subReq.DeliverTo.Operation) {
		return handler.NewErrorResponse(403, "deliver_token_insufficient",
			"delivery token does not grant access to delivery URI")
	}

	// SB1: R1 chain-root check on the embedded deliver_token via the unified
	// chain walker (PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.2). Subscriber's
	// identity MUST be in the token's authority chain — closes the spam
	// exploit where a subscriber references admin's deliver_token to force
	// notifications to admin's inbox. The wieldability check at delivery
	// time (V7 §5.2) is non-overlapping; both are necessary.
	resolver := func(h hash.Hash) (entity.Entity, bool) {
		if ent, ok := hctx.Included[h]; ok {
			return ent, true
		}
		return hctx.Store.Get(h)
	}
	found, _, chainErr := capability.CheckCreatorAuthority(deliverTokenEntity, hctx.AuthorHash, resolver, capability.IncludedSignatureResolver(hctx.Included))
	if chainErr != nil {
		if errors.Is(chainErr, ecerrors.ErrChainUnreachable) {
			return handler.NewErrorResponse(404, "chain_unreachable",
				"deliver_token authority chain not fully resolvable from envelope or store")
		}
		if errors.Is(chainErr, ecerrors.ErrChainTooDeep) {
			return handler.NewErrorResponse(400, "chain_too_deep",
				"deliver_token authority chain exceeds maximum depth")
		}
		return handler.NewErrorResponse(500, "internal_error", "chain walk: "+chainErr.Error())
	}
	if !found {
		// Per proposal §3.2: do NOT persist the chain on rejection.
		return handler.NewErrorResponse(403, "embedded_cap_unauthorized",
			"subscriber identity not in deliver_token authority chain")
	}
	// Chain persistence is handled by the existing "store any other included
	// entities" loop later in this function (line below "Store the delivery
	// token entity"), which writes every envelope-included entity. The
	// returned chain isn't needed separately here.

	// Resolve events (default to all three).
	events := subReq.Events
	if len(events) == 0 {
		events = []string{"created", "updated", "deleted"}
	}

	// Resolve limits.
	limits := subReq.Limits

	// Resource target specifies what to watch. It can be:
	//   - Bare path: "data/*" → qualified as "{localPeerID}/data/*"
	//   - Full URI:  "entity://peerB/data/*" → qualified as "peerB/data/*"
	//   - Already qualified: "peerB/data/*" → used as-is
	var target string
	if hctx.Resource != nil && len(hctx.Resource.Targets) > 0 {
		target = hctx.Resource.Targets[0]
	}
	if target == "" {
		return handler.NewErrorResponse(400, "invalid_params", "resource target is required for subscribe")
	}

	pattern := qualifyPattern(target, string(hctx.LocalPeerID))

	// EXTENSION-SUBSCRIPTION v3.13/v3.14 §2.3: include_payload requires
	// read-authorization. `subscribe` is a distinct capability from `get`;
	// without this check, an include_payload subscriber could receive entity
	// content their cap does not otherwise authorize them to read. Net
	// authorization is identical to a `tree:get` pull — moved server-side.
	if subReq.IncludePayload {
		if hctx.CallerCapability.ContentHash.IsZero() {
			return handler.NewErrorResponse(403, "payload_unauthorized",
				"include_payload requires tree:get on the subscribed resource")
		}
		callerCapData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
		if err != nil {
			return handler.NewErrorResponse(403, "payload_unauthorized",
				"include_payload: cannot decode caller capability: "+err.Error())
		}
		granter, err := capability.ResolveGranterPeerID(callerCapData.Granter, hctx.Store, hctx.LocalPeerID)
		if err != nil {
			return handler.NewErrorResponse(403, "payload_unauthorized",
				"include_payload: granter unresolvable: "+err.Error())
		}
		if !capability.CheckPathPermission("get", target, callerCapData, "system/tree", hctx.LocalPeerID, granter) {
			return handler.NewErrorResponse(403, "payload_unauthorized",
				"include_payload requires tree:get on the subscribed resource: "+target)
		}
	}

	// Check for renewal: same subscriber + pattern + deliver_uri.
	existingID := e.FindRenewal(hctx.AuthorHash, pattern, subReq.DeliverTo.URI)
	if existingID != "" {
		return e.handleRenewal(hctx, existingID, subReq, deliverTokenEntity, events, limits)
	}

	// Check subscriber capacity for this prefix (S2).
	maxSubs := e.MaxSubscribersPerPrefix()
	if maxSubs > 0 {
		count := e.SubscriberCountForPrefix(pattern)
		if uint64(count) >= maxSubs {
			alternatives := e.SubscriberIdentitiesForPrefix(pattern, hctx.AuthorHash, 10)
			redirectData := types.SubscriptionRedirectData{
				Reason:       "at_capacity",
				Prefix:       pattern,
				Alternatives: alternatives,
				Capacity:     &maxSubs,
			}
			redirectEntity, err := redirectData.ToEntity()
			if err != nil {
				return nil, fmt.Errorf("create redirect entity: %w", err)
			}
			return &handler.Response{Status: handler.StatusRedirect, Result: redirectEntity}, nil
		}
	}

	// Generate subscription ID.
	subscriptionID := fmt.Sprintf("sub-%d", time.Now().UnixNano())

	// Create subscription entity.
	now := uint64(time.Now().UnixMilli())
	subData := types.SubscriptionData{
		SubscriptionID:     subscriptionID,
		Pattern:            pattern,
		Events:             events,
		DeliverURI:         subReq.DeliverTo.URI,
		DeliverOperation:   subReq.DeliverTo.Operation,
		SubscriberIdentity: hctx.AuthorHash,
		DeliverToken:       deliverTokenEntity.ContentHash,
		CreatedAt:          now,
		Limits:             limits,
		IncludePayload:     subReq.IncludePayload,
	}
	subEntity, err := subData.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("create subscription entity: %w", err)
	}

	// Store subscription entity in tree.
	subHash, err := hctx.Store.Put(subEntity)
	if err != nil {
		return nil, fmt.Errorf("store subscription: %w", err)
	}
	if _, err := hctx.TreeSet("system/subscription/"+subscriptionID, subHash, "subscribe"); err != nil {
		return nil, fmt.Errorf("bind subscription %s: %w", subscriptionID, err)
	}

	// Store the delivery token entity.
	hctx.Store.Put(deliverTokenEntity)

	// Store any other included entities (delegation chain).
	for _, ent := range hctx.Included {
		hctx.Store.Put(ent)
	}

	// Register in engine.
	e.Register(subData)

	// Build response.
	resultMap := map[string]interface{}{
		"subscription_id": subscriptionID,
		"pattern":         pattern,
		"events":          events,
	}
	if limits != nil {
		limitsRaw, _ := ecf.Encode(limits)
		resultMap["limits"] = cbor.RawMessage(limitsRaw)
	}
	resultRaw, _ := ecf.Encode(resultMap)
	resultEntity, _ := entity.NewEntity("system/subscription/result", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// handleRenewal updates an existing subscription's callback token.
func (e *Engine) handleRenewal(hctx *handler.HandlerContext, existingID string, subReq types.SubscriptionRequestData, deliverTokenEntity entity.Entity, events []string, limits *types.SubscriptionLimitsData) (*handler.Response, error) {
	// Load existing subscription.
	subPath := "system/subscription/" + existingID
	subHash, ok := hctx.LocationIndex.Get(subPath)
	if !ok {
		return handler.NewErrorResponse(404, "subscription_not_found", "subscription entity missing from tree")
	}
	subEntity, ok := hctx.Store.Get(subHash)
	if !ok {
		return handler.NewErrorResponse(404, "subscription_not_found", "subscription entity not in store")
	}
	subData, err := types.SubscriptionDataFromEntity(subEntity)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "could not decode existing subscription")
	}

	// Update delivery token.
	subData.DeliverToken = deliverTokenEntity.ContentHash
	if len(events) > 0 {
		subData.Events = events
	}
	if limits != nil {
		subData.Limits = limits
	}
	// EXTENSION-SUBSCRIPTION v3.14: renewal may update include_payload. The
	// caller has already passed the v3.13 read-auth check at the entry to
	// HandleSubscribe (before reaching this path), so we persist the new
	// value unconditionally.
	subData.IncludePayload = subReq.IncludePayload

	// Re-store updated subscription.
	newEntity, err := subData.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("create updated subscription entity: %w", err)
	}
	newHash, err := hctx.Store.Put(newEntity)
	if err != nil {
		return nil, fmt.Errorf("store updated subscription: %w", err)
	}
	if _, err := hctx.TreeSet(subPath, newHash, "subscribe"); err != nil {
		return nil, fmt.Errorf("bind updated subscription %s: %w", subPath, err)
	}

	// Store new delivery token.
	hctx.Store.Put(deliverTokenEntity)

	// Update engine's in-memory state.
	e.mu.Lock()
	if activeSub, ok := e.subscriptions[existingID]; ok {
		activeSub.data = subData
	}
	e.mu.Unlock()

	resultRaw, _ := ecf.Encode(map[string]interface{}{
		"subscription_id": existingID,
		"pattern":         subData.Pattern,
		"events":          subData.Events,
		"renewed":         true,
	})
	resultEntity, _ := entity.NewEntity("system/subscription/result", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// HandleUnsubscribe processes an unsubscribe operation.
func (e *Engine) HandleUnsubscribe(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	// Decode cancel request params.
	var cancelReq types.SubscriptionCancelData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &cancelReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode unsubscribe request")
		}
	}
	if cancelReq.SubscriptionID == "" {
		return handler.NewErrorResponse(400, "invalid_params", "missing subscription_id")
	}

	// Look up subscription.
	subPath := "system/subscription/" + cancelReq.SubscriptionID
	subHash, ok := hctx.LocationIndex.Get(subPath)
	if !ok {
		return handler.NewErrorResponse(404, "subscription_not_found", "subscription not found")
	}
	subEntity, ok := hctx.Store.Get(subHash)
	if !ok {
		return handler.NewErrorResponse(404, "subscription_not_found", "subscription entity not in store")
	}
	subData, err := types.SubscriptionDataFromEntity(subEntity)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "could not decode subscription")
	}

	// Verify caller is the subscriber.
	if subData.SubscriberIdentity != hctx.AuthorHash {
		return handler.NewErrorResponse(403, "not_subscription_owner",
			"only the original subscriber can unsubscribe")
	}

	// Remove from tree.
	hctx.TreeRemove(subPath, "unsubscribe")

	// Remove from engine index.
	e.Remove(cancelReq.SubscriptionID)

	resultRaw, _ := ecf.Encode(map[string]interface{}{"removed": true})
	resultEntity, _ := entity.NewEntity("system/subscription/cancel-result", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// validateDeliveryTokenScope checks whether the capability token grants access
// to the specified delivery URI and operation.
func validateDeliveryTokenScope(capData types.CapabilityTokenData, deliverURI, deliverOp string) bool {
	// Normalize URI to bare path for scope comparison.
	// "entity://peerA/system/inbox/test" → "system/inbox/test"
	deliverPath := entity.ExtractHandlerPath(deliverURI)

	for _, grant := range capData.Grants {
		// Check handler scope includes system/inbox/*.
		if !scopeIncludes(grant.Handlers, "system/inbox") {
			continue
		}
		// Check resource scope includes the delivery path.
		if !scopeIncludes(grant.Resources, deliverPath) && !scopeIncludes(grant.Resources, deliverURI) {
			continue
		}
		// Check operation scope includes the delivery operation.
		if !scopeIncludes(grant.Operations, deliverOp) {
			continue
		}
		return true
	}
	return false
}

// qualifyPattern turns a resource target into an absolute path pattern.
// Full entity URI → "/peerID/path". Already absolute → as-is. Bare path →
// "/{localPeerID}/path".
func qualifyPattern(target, localPeerID string) string {
	if strings.HasPrefix(target, entity.Scheme) {
		uri, err := entity.ParseURI(target)
		if err == nil && uri.PeerID != "" {
			return "/" + uri.PeerID + "/" + uri.Path
		}
	}
	if strings.HasPrefix(target, "/") {
		return target // already absolute
	}
	return "/" + localPeerID + "/" + target
}

// scopeIncludes checks if a scope covers the given value.
func scopeIncludes(scope types.CapabilityScope, value string) bool {
	for _, inc := range scope.Include {
		if inc == "*" || inc == value {
			return true
		}
		// Subtree wildcard: "system/inbox/*" matches "system/inbox" and
		// "system/inbox/anything".
		if len(inc) > 1 && inc[len(inc)-1] == '*' {
			prefix := inc[:len(inc)-1] // e.g. "system/inbox/"
			base := strings.TrimSuffix(prefix, "/")
			if value == base {
				return true
			}
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
	}
	return false
}
