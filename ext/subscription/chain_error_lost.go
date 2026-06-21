package subscription

import (
	"encoding/hex"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// bindLostMarker binds a chain-error `lost` marker at
//
//	system/runtime/chain-errors/lost/{chain_id}/{subscription_id}/{reason}/{marker_hash}
//
// per EXTENSION-SUBSCRIPTION §4.7. The subscription engine — NOT the
// dispatcher — is the marker emitter for outbound notification dispatch
// failures (limit-exceeded suppression, transport failure, capability
// rejection). Cross-impl: Python's engine binds these too; Go-side
// dispatcher must NOT bind for the subscription path or CAT-CHAIN-COMPLETION
// will produce divergent results.
//
// {step_index} is filled with {subscription_id} per §4.7 (the trigger is a
// tree change rather than a chained EXECUTE, so no original-request-id is
// available — the subscription_id is the meaningful correlation key).
//
// Best-effort: a failure to bind the marker is logged and ignored.
// Marker-binding failures must not affect the subscription lifecycle that
// triggered the marker (the failure already happened).
func (e *Engine) bindLostMarker(chainID, subscriptionID, reason, deliverURI string, originalStatus uint, originalCode string) hash.Hash {
	if e.store == nil || e.locationIndex == nil {
		return hash.Hash{}
	}
	if subscriptionID == "" || reason == "" {
		return hash.Hash{}
	}
	// chain_id MAY be empty for subscriptions whose triggering tree change
	// carried no chain causality (e.g. operator-initiated puts). Use a stable
	// "none" segment so the marker is still bindable and observable rather
	// than dropped silently — §4.7 mandates binding regardless.
	if chainID == "" {
		chainID = "none"
	}

	// §3.10.6 timestamp-capture: origination is the moment the failure
	// observation happens (here in the engine).
	now := uint64(time.Now().UnixMilli())

	marker, err := types.ChainErrorLostData{
		Reason:            reason,
		Timestamp:         now,
		ChainID:           chainID,
		StepIndex:         subscriptionID,
		FailedDeliveryURI: deliverURI,
		OriginalStatus:    originalStatus,
		OriginalCode:      originalCode,
	}.ToEntity()
	if err != nil {
		e.debugf("subscription lost-marker entity build failed: %v (sub=%s reason=%s)",
			err, subscriptionID, reason)
		return hash.Hash{}
	}

	markerHash, err := e.store.Put(marker)
	if err != nil {
		e.debugf("subscription lost-marker store failed: %v (sub=%s reason=%s)",
			err, subscriptionID, reason)
		return hash.Hash{}
	}

	markerPath := "system/runtime/chain-errors/lost/" + chainID + "/" + subscriptionID + "/" + reason + "/" + hex.EncodeToString(markerHash.Bytes())
	if err := e.locationIndex.Set(markerPath, markerHash); err != nil {
		// Per CONTINUATION §3.10.8 bind-failure visibility: surface, don't
		// silently claim success.
		e.debugf("subscription lost-marker bind FAILED at %s: %v (sub=%s reason=%s) — operator visibility gap",
			markerPath, err, subscriptionID, reason)
		return hash.Hash{}
	}
	e.debugf("bound subscription lost-marker at %s (chain=%s sub=%s reason=%s)",
		markerPath, chainID, subscriptionID, reason)
	return markerHash
}
