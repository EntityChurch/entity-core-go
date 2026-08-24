package subscription

import (
	"encoding/hex"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
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
	// chain_id arrives straight from wire-supplied notification bounds and
	// reason carries a remote handler's error code, so both name a path segment
	// below and both must be sanitized. The path gets the sanitized form; the
	// body keeps the originals (§3.10.6 + arch ruling 2026-07-17 §2), which is
	// what makes collapsing to a sentinel lossless.
	rawChainID, rawStepKey := chainID, subscriptionID
	pathChainID := store.SanitizePathSegment(chainID, types.ChainIDUnspecified)
	pathStepKey := store.SanitizePathSegment(subscriptionID, types.StepIndexUnspecified)
	pathReason := store.SanitizePathSegment(reason, types.ReasonUnspecified)

	// §3.10.6 timestamp-capture: origination is the moment the failure
	// observation happens (here in the engine).
	now := uint64(time.Now().UnixMilli())

	marker, err := types.ChainErrorLostData{
		Reason:    pathReason,
		Timestamp: now,
		// The RAW wire values — the body is the record, the path is an index.
		ChainID:   rawChainID,
		StepIndex: rawStepKey,
		TargetURI: deliverURI,
		Status:    originalStatus,
		Code:      originalCode,
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

	markerPath := "system/runtime/chain-errors/lost/" + pathChainID + "/" + pathStepKey + "/" + pathReason + "/" + hex.EncodeToString(markerHash.Bytes())
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
