package subscription

import (
	"encoding/hex"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// markerCollectThrottle bounds how often a subscription marker-bind pays for a
// reap sweep — mirrors ext/continuation's collectThrottle.
const markerCollectThrottle = time.Minute

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

	// §3.10.6 sender-side capture: which peer the delivery was aimed at, when
	// the deliver URI names one. Bare-path deliveries leave it absent. Row 17.
	targetPeerID := ""
	if pid, ok := capability.ExtractPeerStrict(deliverURI); ok {
		targetPeerID = string(pid)
	}

	marker, err := types.ChainErrorLostData{
		Reason:    pathReason,
		Timestamp: now,
		// The RAW wire values — the body is the record, the path is an index.
		ChainID:      rawChainID,
		StepIndex:    rawStepKey,
		TargetURI:    deliverURI,
		TargetPeerID: targetPeerID,
		Status:       originalStatus,
		Code:         originalCode,
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

	// Self-reap (row 12): the path that grows this tree must also reap it. The
	// two other `lost`/`rejected` binders (ext/continuation/advance.go,
	// core/protocol/dispatch.go) trigger a throttled sweep at bind time; the
	// subscription engine was the odd one out — it bound and never collected,
	// so a peer whose ONLY marker source is subscription delivery accumulated
	// them until some unrelated dispatch happened to sweep. Same self-reap
	// invariant, now closed here.
	e.maybeCollectMarkers()
	return markerHash
}

// maybeCollectMarkers runs a throttled §3.10 marker sweep from the bind path.
// Bind-time rather than a background ticker, for the same reasons the
// continuation handler documents: binding is when the tree grows, an idle peer
// has nothing to collect, and no ext handler owns a goroutine to leak. The
// retention window is the v1.23 operator knob (system/config/chain-errors →
// retention_ms) when set, else the 24h default; an explicit 0 disables it.
func (e *Engine) maybeCollectMarkers() {
	if e.store == nil || e.locationIndex == nil {
		return
	}
	now := time.Now()
	e.mu.Lock()
	if !e.lastMarkerCollect.IsZero() && now.Sub(e.lastMarkerCollect) < markerCollectThrottle {
		e.mu.Unlock()
		return
	}
	e.lastMarkerCollect = now
	e.mu.Unlock()

	retention := protocol.EffectiveRetention(e.store, e.locationIndex, protocol.DefaultMarkerRetentionMs)
	if retention == protocol.RetainMarkersForever {
		return
	}
	if n := protocol.CollectExpiredMarkers(e.store, e.locationIndex, retention, uint64(now.UnixMilli())); n > 0 {
		e.debugf("collected %d expired chain-error marker(s) (retention %dms)", n, retention)
	}
}
