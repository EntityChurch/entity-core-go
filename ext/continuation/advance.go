package continuation

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)



// --- advance operation (spec §3.3–3.5) ---

// handleAdvance is the entry point for the advance operation.
func (h *Handler) handleAdvance(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	// Decode advance request params.
	var advReq types.ContinuationAdvanceRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &advReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode advance request")
		}
	}

	// Path comes from resource target.
	path := hctx.ExtractResourcePath()
	if path == "" {
		return handler.NewErrorResponse(400, "invalid_params", "resource target path is required")
	}

	// Level 2 capability check.
	if resp := hctx.CheckPathCapability("advance", path); resp != nil {
		return resp, nil
	}

	status := uint(200)
	if advReq.Status != nil {
		status = *advReq.Status
	}

	return h.advanceAtPath(ctx, hctx, path, advReq.Result, status)
}

// advanceAtPath implements the continuation advancement algorithm (spec §3.3).
// Returns {advanced: true} on success, {advanced: false} when no continuation at path.
func (h *Handler) advanceAtPath(ctx context.Context, hctx *handler.HandlerContext, path string, result cbor.RawMessage, status uint) (*handler.Response, error) {
	// Step 1: Check for continuation entity at the path.
	cont, contType := readEntity(hctx, path)

	// Step 2: Forward continuation — advance immediately.
	if contType == types.TypeContinuation {
		contData, err := types.ContinuationDataFromEntity(cont)
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "decode continuation: "+err.Error())
		}
		return h.advanceForward(ctx, hctx, path, contData, result, status)
	}

	// Step 3: Join slot — check if parent is a join entity.
	if contType == "" || (contType != types.TypeContinuation && contType != types.TypeContinuationJoin) {
		parent := parentPath(path)
		slot := lastSegment(path)
		if parent != "" {
			joinEnt, joinType := readEntity(hctx, parent)
			if joinType == types.TypeContinuationJoin {
				joinData, err := types.ContinuationJoinDataFromEntity(joinEnt)
				if err != nil {
					return handler.NewErrorResponse(500, "internal_error", "decode join: "+err.Error())
				}
				return h.advanceJoinSlot(ctx, hctx, parent, slot, joinData, result)
			}
		}
	}

	// Step 4: Direct delivery to join path (not a slot) — error.
	if contType == types.TypeContinuationJoin {
		return handler.NewErrorResponse(400, "join_requires_slot_path",
			"advance on a join continuation requires a slot sub-path")
	}

	// Step 5: No continuation at path.
	return advancementNotFound()
}

// advanceForward implements the forward advancement algorithm (spec §3.4).
func (h *Handler) advanceForward(ctx context.Context, hctx *handler.HandlerContext, path string, cont types.ContinuationData, result cbor.RawMessage, status uint) (*handler.Response, error) {
	// Error path: if delivery status >= 400 and on_error is set.
	if status >= 400 && cont.OnError != nil {
		// Mirror the wire-entry async delivery pattern (core/protocol/dispatch.go:844):
		// the OnError.URI is exposed to the receiving handler as the resource target
		// so inbox.receive (and similar receivers) can extract a write path.
		onErrorResource := &types.ResourceTarget{Targets: []string{cont.OnError.URI}}
		errResp, dispatchErr := h.executeDispatch(ctx, hctx, types.ContinuationData{
			Target:             cont.OnError.URI,
			Operation:          cont.OnError.Operation,
			Resource:           onErrorResource,
			DispatchCapability: cont.DispatchCapability,
		}, result)
		// A malformed on_error continuation (e.g. no dispatch_capability) is a
		// genuine misconfiguration with an observable surface — surface 400.
		if configErr, ok := dispatchErr.(*errInvalidContinuation); ok {
			return handler.NewErrorResponse(400, "invalid_continuation", configErr.msg)
		}
		// on_error delivery is best-effort (§3.4: "dispatch result is not
		// checked"); a transient/permanent failure is silently lost. A.1: the
		// hazard that leaves — a chain whose on_error itself fails having NO
		// observable surface — is closed by binding an informational
		// lost-error marker (§3.4). No reactive behavior: we still treat the
		// advance as error-routed and do not propagate.
		if dispatchErr != nil || (errResp != nil && errResp.Status >= 400) {
			// v1.20 §3.10.6 timestamp-capture discipline: capture at
			// failure-origination, NOT regenerated at marker-bind site.
			// Origination here is the moment we observe the on_error
			// dispatch failed.
			originTS := uint64(time.Now().UnixMilli())
			h.bindLostErrorMarker(hctx, cont.OnError.URI, status, result, types.ChainErrorReasonOnErrorDispatchFailed, originTS, hash.Hash{})
		}
		// Only handle remaining_executions after the error-path dispatch
		// (best-effort — the error was routed or recorded as lost).
		h.handleRemainingExecutions(hctx, path, cont.RemainingExecutions)
		return advancementOK()
	}

	dispatchResp, err := h.executeDispatch(ctx, hctx, cont, result)
	// Configuration errors propagate as 400. Do NOT decrement on failure —
	// the fire didn't complete.
	if configErr, ok := err.(*errInvalidContinuation); ok {
		return handler.NewErrorResponse(400, "invalid_continuation", configErr.msg)
	}
	if err != nil {
		return nil, err
	}
	// v1.13 / I-8: forward dispatch with NO on_error that returns a
	// handler-level non-2xx — bind an informational lost-error marker so
	// the silent-burn is observable. Trigger range is all status >= 400
	// (matches §3.4 is_error). Idempotent re-binding (same {chain_id,
	// step_index} path is content-addressed) keeps a flapping target from
	// multiplying markers. Purely additive: remaining_executions still
	// decrements normally, dispatch is still classified as completed (per
	// the v1.10 forward-dispatch classification), chain still advances.
	if cont.OnError == nil && dispatchResp != nil && dispatchResp.Status >= 400 {
		var dispatchResultRaw cbor.RawMessage
		if dispatchResp.Result.Type != "" {
			dispatchResultRaw = dispatchResp.Result.Data
		}
		// v1.19 §3.10.5 unified rule: {reason} IS result.data.code
		// verbatim, NOT the v1.13 catch-all `forward_dispatch_non2xx`.
		// Distinct error codes at the same step coexist as sibling
		// {reason} paths now. Falls back to V7 §6.12 `protocol_error`
		// when the response is malformed or missing `code`.
		// v1.20 §3.10.6: capture origination timestamp at the moment
		// we observe the non-2xx response.
		originTS := uint64(time.Now().UnixMilli())
		reason := extractReasonFromResult(dispatchResultRaw)
		// WB-27 mirror-pointer per v1.20 §3.10.4: if the response's
		// ErrorData carries a RejectedMarker (receiver-side rejected
		// marker hash), thread it into the sender-side lost-marker
		// body's RejectedMarkerHash field. Zero hash when absent
		// (omitzero on serialization).
		mirror := extractRejectedMarkerFromResult(dispatchResultRaw)
		h.bindLostErrorMarker(hctx, cont.Target, uint(dispatchResp.Status), dispatchResultRaw, reason, originTS, mirror)
	}
	// Only handle remaining_executions after successful dispatch.
	h.handleRemainingExecutions(hctx, path, cont.RemainingExecutions)
	return advancementOK()
}

// extractReasonFromResult returns the canonical {reason} value for a
// chain-error marker derived from a dispatch response per EXTENSION-
// CONTINUATION v1.19 §3.10.5: the response's `result.data.code` verbatim.
// Falls back to V7 §6.12 `protocol_error` when the response is malformed
// or carries an error status without a `code` field (per §3.10.5 missing-
// code fallback).
func extractReasonFromResult(origResult cbor.RawMessage) string {
	if len(origResult) == 0 {
		return types.ChainErrorReasonProtocolError
	}
	var ed types.ErrorData
	if err := ecf.Decode(origResult, &ed); err != nil {
		return types.ChainErrorReasonProtocolError
	}
	if ed.Code == "" {
		return types.ChainErrorReasonProtocolError
	}
	return ed.Code
}

// extractRejectedMarkerFromResult returns the ErrorData.RejectedMarker
// mirror-pointer carried in a dispatch response's error payload per
// EXTENSION-CONTINUATION v1.20 §3.10.4. Returns the zero hash when the
// response is not an ErrorData, the field is absent (omitzero), or the
// response is malformed. Best-effort: the mirror is SHOULD-level per
// §3.10.4 so absence does not invalidate either side's marker.
func extractRejectedMarkerFromResult(origResult cbor.RawMessage) hash.Hash {
	if len(origResult) == 0 {
		return hash.Hash{}
	}
	var ed types.ErrorData
	if err := ecf.Decode(origResult, &ed); err != nil {
		return hash.Hash{}
	}
	return ed.RejectedMarker
}

// bindLostErrorMarker records a chain-dispatch failure as an informational
// marker per EXTENSION-CONTINUATION v1.20 §3.10. The path scheme is:
//
//	system/runtime/chain-errors/lost/{chain_id}/{step_index}/{reason}/{marker_hash}
//
// where {marker_hash} is the V7 §3.5 invariant-pointer hex form of this
// marker's content_hash. Each distinct occurrence lands at its own path
// (tree IS the event log). Same-content redelivery (bytes-identical body)
// is a genuine tree:put no-op per Class A spec.
//
// originTimestampMs MUST be captured at failure-origination time per
// §3.10.6 — NOT regenerated here. Without this discipline, redelivery
// would multiply markers as if each were a new occurrence.
//
// Purely observational and best-effort: any failure here is swallowed so
// the marker can never affect control flow (adds visibility, not
// delivery; MUST NOT trigger advancement/retry/any reactive behavior).
// Go uses the original request ID as the {step_index} segment per v1.14.
func (h *Handler) bindLostErrorMarker(hctx *handler.HandlerContext, failedURI string, origStatus uint, origResult cbor.RawMessage, reason string, originTimestampMs uint64, mirrorReceiverMarker hash.Hash) {
	chainID := ""
	if hctx.Bounds != nil {
		chainID = hctx.Bounds.ChainID
	}
	if chainID == "" {
		chainID = hctx.RequestID
	}
	if chainID == "" {
		chainID = "unknown"
	}
	stepKey := hctx.RequestID
	if stepKey == "" {
		stepKey = "0"
	}

	origCode := ""
	if len(origResult) > 0 {
		var ed types.ErrorData
		if err := ecf.Decode(origResult, &ed); err == nil {
			origCode = ed.Code
		}
	}

	marker, err := types.ChainErrorLostData{
		OriginalCode:       origCode,
		OriginalStatus:     origStatus,
		FailedDeliveryURI:  failedURI,
		OriginalRequestID:  hctx.RequestID,
		Timestamp:          originTimestampMs,
		Reason:             reason,
		ChainID:            chainID,
		StepIndex:          stepKey,
		RejectedMarkerHash: mirrorReceiverMarker,
	}.ToEntity()
	if err != nil {
		return
	}
	markerHash, err := hctx.Store.Put(marker)
	if err != nil {
		return
	}
	// v1.20 path scheme: terminal {marker_hash} segment using V7 §3.5
	// invariant-pointer hex form (lowercase, format-code-included, 66
	// chars). Same encoding used by core/capability/storage_path.go for
	// multi-sig-root paths.
	markerPath := "system/runtime/chain-errors/lost/" + chainID + "/" + stepKey + "/" + reason + "/" + hex.EncodeToString(markerHash.Bytes())
	// Best-effort bind; an error here must not affect advancement.
	// Per F11 (workbench Round 6 Stage 3 cap-delegation negative-case
	// observation): when the bind itself fails (typically because the
	// chain step's propagated cap doesn't cover writes under
	// system/runtime/chain-errors), the prior code silently swallowed
	// the error AND emitted a "bound" log line — operators saw the
	// log and assumed the marker was visible. Distinguish success
	// from failure so the silent-failure case is now operator-visible
	// in the dispatcher's stderr stream.
	if _, bindErr := hctx.TreeSet(markerPath, markerHash, "advance"); bindErr != nil {
		debugLog("F11: lost-error marker bind FAILED at %s: %v (failed_uri=%s status=%d code=%q) — operator visibility gap; chain stalled silently from caller's perspective", markerPath, bindErr, failedURI, origStatus, origCode)
		return
	}
	debugLog("bound lost-error marker at %s (failed_uri=%s status=%d code=%q)", markerPath, failedURI, origStatus, origCode)
}

// advancementOK returns the standard 200 response for successful continuation advancement.
func advancementOK() (*handler.Response, error) {
	resultRaw, _ := ecf.Encode(map[string]interface{}{"advanced": true})
	resultEntity, _ := entity.NewEntity("system/continuation/advancement-result", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// advancementNotFound returns {advanced: false} when no continuation exists at path.
func advancementNotFound() (*handler.Response, error) {
	resultRaw, _ := ecf.Encode(map[string]interface{}{"advanced": false})
	resultEntity, _ := entity.NewEntity("system/continuation/advancement-result", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// errInvalidContinuation is returned when continuation configuration is invalid
// (e.g., result_field without params). This is distinct from target handler errors.
type errInvalidContinuation struct{ msg string }

func (e *errInvalidContinuation) Error() string { return e.msg }

// executeDispatch applies transform, assembles params, and dispatches (spec §3.5).
// Returns errInvalidContinuation for configuration errors in the continuation itself.
func (h *Handler) executeDispatch(ctx context.Context, hctx *handler.HandlerContext, cont types.ContinuationData, rawResult cbor.RawMessage) (*handler.Response, error) {
	// Step 1: Transform (extract + select).
	value := rawResult
	if cont.ResultTransform != nil {
		// hctx.Included carries the envelope's `included` map — threaded so
		// deref_included can resolve hash fields to entities (e.g. the
		// EXTENSION-SUBSCRIPTION v3.14 include_payload mirror recipe).
		value = applyTransform(rawResult, cont.ResultTransform, hctx.Included)
	}

	// Step 2: Assemble params via dispatch mode logic. Merge-mode
	// (PROPOSAL-CONTINUATION-MERGE-ASSEMBLY) takes priority over the
	// existing inject/trigger/pass-through cases when ResultMerge=true.
	var finalParams cbor.RawMessage
	if cont.ResultMerge {
		merged, valueIsMap := mergeAssemble(cont.Params, value)
		if !valueIsMap {
			// §3 footgun: non-map value silently dropped from the merge.
			// Bind a §3.4 marker so the silent burn becomes observable.
			// Dispatch proceeds best-effort with static-only params; the
			// marker is purely informational (no reactive behavior, same
			// contract as the other §3.4 reasons).
			h.bindMergeValueNotMapMarker(hctx, cont.Target, value)
		}
		finalParams = merged
	} else {
		var err error
		finalParams, err = assembleParams(cont.Params, cont.ResultField, value)
		if err != nil {
			return nil, &errInvalidContinuation{msg: err.Error()}
		}
	}

	// Create the params entity.
	paramsEntity, err := entity.NewEntity("primitive/any", finalParams)
	if err != nil {
		return nil, fmt.Errorf("create params entity: %w", err)
	}

	// Step 3: Resolve dynamic EXECUTE fields from the transform, falling back
	// to static values on the continuation entity (spec §3.5 step 3).
	uri := cont.Target
	operation := cont.Operation
	resource := cont.Resource

	if cont.ResultTransform != nil {
		uri = resolveOrDefault(value, cont.ResultTransform.TargetExtract, uri)
		operation = resolveOrDefault(value, cont.ResultTransform.OperationExtract, operation)
		resource = resolveOrDefaultResource(value, cont.ResultTransform.ResourceExtract, resource)
	}

	// Build execute options.
	var opts []handler.ExecuteOption

	if resource != nil {
		opts = append(opts, handler.WithResource(resource))
	}

	// Step 4: deliver_to on continuation becomes deliver_to on the dispatched EXECUTE.
	if cont.DeliverTo != nil {
		opts = append(opts, handler.WithDeliverTo(cont.DeliverTo))
	}

	// Step 5: Capability — dispatch_capability is required (W9).
	// The continuation handler's own grant is for managing continuation entities
	// at system/continuation/* — it is NOT used for dispatching to target handlers.
	if cont.DispatchCapability.IsZero() {
		return nil, &errInvalidContinuation{msg: "continuation must have dispatch_capability to dispatch (W9)"}
	}
	capEnt, ok := hctx.Store.Get(cont.DispatchCapability)
	if !ok {
		return nil, &errInvalidContinuation{msg: "dispatch_capability entity not in content store"}
	}
	opts = append(opts, handler.WithCapability(capEnt))

	// Cross-peer chain transport (EXTENSION-CONTINUATION §4.2 case 3 / §4.3
	// / §8.1): the dispatched EXECUTE to a remote target MUST carry the
	// dispatch_capability's FULL authority chain (caps + signatures +
	// granter identities) so the target peer can VerifyChain to a root it
	// recognizes — the scoped dispatch_capability, not a silent fallback to
	// the broader connection authority. The chain was persisted at install
	// (§3.2 step 5); collect+bundle it from the local store. Harmless for
	// local dispatch (the extra included is ignored); over-inclusion is
	// free (content-addressed dedup at the receiver).
	if bundle, berr := capability.CollectChainBundle(capEnt, hctx.Store, hctx.LocationIndex); berr == nil && len(bundle) > 0 {
		chain := make([]entity.Entity, 0, len(bundle))
		for _, e := range bundle {
			chain = append(chain, e)
		}
		opts = append(opts, handler.WithIncludedChain(chain))
	}

	// Step 6: Dispatch.
	if hctx.Execute == nil {
		return handler.NewErrorResponse(500, "internal_error", "execute function not available")
	}

	resp, err := hctx.Execute(ctx, uri, operation, paramsEntity, opts...)
	if err != nil {
		return nil, fmt.Errorf("continuation dispatch: %w", err)
	}
	return resp, nil
}

// resolveOrDefault navigates a dotted path into the post-transform value.
// Returns the extracted string if successful, otherwise the default.
func resolveOrDefault(value cbor.RawMessage, extractPath, defaultVal string) string {
	if extractPath == "" && defaultVal != "" {
		// No extract path specified — use default.
		// Note: empty extract path WITH empty default means "use the value as-is".
		return defaultVal
	}
	if extractPath == "" && defaultVal == "" {
		return defaultVal
	}

	var decoded interface{}
	if err := cbor.Unmarshal(value, &decoded); err != nil {
		return defaultVal
	}

	extracted := navigate(decoded, extractPath)
	if extracted == nil {
		return defaultVal
	}

	if s, ok := extracted.(string); ok {
		return s
	}
	return defaultVal
}

// resolveOrDefaultResource navigates a dotted path and wraps the result as a ResourceTarget.
// Handles string → {targets: [string]}, array → {targets: array}, or already-formed objects.
func resolveOrDefaultResource(value cbor.RawMessage, extractPath string, defaultVal *types.ResourceTarget) *types.ResourceTarget {
	if extractPath == "" && defaultVal != nil {
		return defaultVal
	}
	// Empty extractPath means "use the whole value as-is" only if explicitly set.
	// We detect this by checking if extractPath was set (non-empty or explicitly "").
	// Since Go can't distinguish "field absent" from "field empty string" in the same way,
	// we treat empty extractPath with nil default as "extract the whole value".

	var decoded interface{}
	if err := cbor.Unmarshal(value, &decoded); err != nil {
		return defaultVal
	}

	extracted := navigate(decoded, extractPath)
	if extracted == nil {
		return defaultVal
	}

	// Wrap extracted value into resource-target structure.
	switch v := extracted.(type) {
	case string:
		return &types.ResourceTarget{Targets: []string{v}}
	case []interface{}:
		targets := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				targets = append(targets, s)
			}
		}
		if len(targets) > 0 {
			return &types.ResourceTarget{Targets: targets}
		}
		return defaultVal
	case map[interface{}]interface{}:
		if t, ok := v["targets"]; ok {
			if arr, ok := t.([]interface{}); ok {
				targets := make([]string, 0, len(arr))
				for _, item := range arr {
					if s, ok := item.(string); ok {
						targets = append(targets, s)
					}
				}
				return &types.ResourceTarget{Targets: targets}
			}
		}
		return defaultVal
	case map[string]interface{}:
		if t, ok := v["targets"]; ok {
			if arr, ok := t.([]interface{}); ok {
				targets := make([]string, 0, len(arr))
				for _, item := range arr {
					if s, ok := item.(string); ok {
						targets = append(targets, s)
					}
				}
				return &types.ResourceTarget{Targets: targets}
			}
		}
		return defaultVal
	default:
		return defaultVal
	}
}

// advanceJoinSlot implements join slot advancement (spec §3.5).
func (h *Handler) advanceJoinSlot(ctx context.Context, hctx *handler.HandlerContext, joinPath, slotName string, join types.ContinuationJoinData, result cbor.RawMessage) (*handler.Response, error) {
	// Validate slot.
	if !slotInExpected(slotName, join.Expected) {
		return handler.NewErrorResponse(400, "unexpected_slot",
			fmt.Sprintf("slot %q not in expected: %v", slotName, join.Expected))
	}

	// Serialize access to this join path.
	jmu := h.getJoinLock(joinPath)
	jmu.Lock()
	defer jmu.Unlock()

	// Re-read the join entity under lock (may have been updated by another slot).
	joinEnt, joinType := readEntity(hctx, joinPath)
	if joinType != types.TypeContinuationJoin {
		return handler.NewErrorResponse(500, "internal_error", "join entity disappeared")
	}
	join, err := types.ContinuationJoinDataFromEntity(joinEnt)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "re-decode join: "+err.Error())
	}

	// Accumulate.
	received := make(map[string]cbor.RawMessage)
	for k, v := range join.Received {
		received[k] = v
	}
	received[slotName] = result

	// Check completeness.
	if allSlotsReceived(join.Expected, received) {
		// All slots filled — dispatch.
		receivedRaw, err := ecf.Encode(received)
		if err != nil {
			return nil, fmt.Errorf("encode received: %w", err)
		}

		// Build a ContinuationData from the join's dispatch fields.
		contData := types.ContinuationData{
			Target:              join.Target,
			Operation:           join.Operation,
			Resource:            join.Resource,
			Params:              join.Params,
			ResultField:         join.ResultField,
			OnError:             join.OnError,
			DeliverTo:           join.DeliverTo,
			RemainingExecutions: join.RemainingExecutions,
			DispatchCapability:  join.DispatchCapability,
		}

		_, dispatchErr := h.executeDispatch(ctx, hctx, contData, cbor.RawMessage(receivedRaw))

		// Lifecycle.
		if join.RemainingExecutions != nil {
			remaining := h.handleRemainingExecutions(hctx, joinPath, join.RemainingExecutions)
			if remaining > 0 {
				// Reset received for next round.
				resetJoinReceived(hctx, joinPath, join)
			}
		} else {
			// Standing join — reset received.
			resetJoinReceived(hctx, joinPath, join)
		}

		if configErr, ok := dispatchErr.(*errInvalidContinuation); ok {
			return handler.NewErrorResponse(400, "invalid_continuation", configErr.msg)
		}
		if dispatchErr != nil {
			return nil, dispatchErr
		}
		return advancementOK()
	}

	// Not complete — update join entity with accumulated received.
	join.Received = received
	updatedEntity, err := join.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("create updated join: %w", err)
	}
	updatedHash, err := hctx.Store.Put(updatedEntity)
	if err != nil {
		return nil, fmt.Errorf("store updated join: %w", err)
	}
	if _, err := hctx.TreeSet(joinPath, updatedHash, "advance"); err != nil {
		return nil, fmt.Errorf("bind updated join %s: %w", joinPath, err)
	}

	resultRaw, _ := ecf.Encode(map[string]interface{}{
		"slot":      slotName,
		"remaining": missingSlots(join.Expected, received),
	})
	resultEntity, _ := entity.NewEntity("system/continuation/join-slot-result", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// handleRemainingExecutions decrements the stored remaining_executions field on the
// continuation entity. Returns the remaining count after decrement.
// nil = unlimited (standing). 0 after decrement = exhausted (delete).
func (h *Handler) handleRemainingExecutions(hctx *handler.HandlerContext, path string, remaining *uint64) uint64 {
	if remaining == nil {
		return 0 // Standing continuation — unlimited.
	}

	current := *remaining
	if current == 0 {
		return 0 // Already exhausted.
	}

	current--
	if current == 0 {
		// Delete continuation.
		if oldHash, ok, _ := hctx.TreeRemove(path, "advance"); ok {
			hctx.Store.Remove(oldHash)
		}
		return 0
	}

	// Update the entity with decremented remaining_executions.
	contentHash, ok := hctx.LocationIndex.Get(path)
	if !ok {
		return current
	}
	ent, ok := hctx.Store.Get(contentHash)
	if !ok {
		return current
	}

	// Re-decode, update, re-store based on type.
	switch ent.Type {
	case types.TypeContinuation:
		contData, err := types.ContinuationDataFromEntity(ent)
		if err != nil {
			return current
		}
		contData.RemainingExecutions = &current
		updated, err := contData.ToEntity()
		if err != nil {
			return current
		}
		newHash, err := hctx.Store.Put(updated)
		if err != nil {
			return current
		}
		if _, err := hctx.TreeSet(path, newHash, "advance"); err != nil {
			debugLog("continuation: bind %s after decrement failed: %v", path, err)
			return current
		}

	case types.TypeContinuationJoin:
		joinData, err := types.ContinuationJoinDataFromEntity(ent)
		if err != nil {
			return current
		}
		joinData.RemainingExecutions = &current
		updated, err := joinData.ToEntity()
		if err != nil {
			return current
		}
		newHash, err := hctx.Store.Put(updated)
		if err != nil {
			return current
		}
		if _, err := hctx.TreeSet(path, newHash, "advance"); err != nil {
			debugLog("continuation: bind join %s after decrement failed: %v", path, err)
			return current
		}
	}

	return current
}

// resetJoinReceived resets the received map on a join entity for the next round.
func resetJoinReceived(hctx *handler.HandlerContext, joinPath string, join types.ContinuationJoinData) {
	join.Received = nil
	updatedEntity, err := join.ToEntity()
	if err != nil {
		return
	}
	updatedHash, err := hctx.Store.Put(updatedEntity)
	if err != nil {
		return
	}
	if _, err := hctx.TreeSet(joinPath, updatedHash, "advance"); err != nil {
		// Surfaced via debug log: a subsequent advance write usually fails
		// the same way and will propagate to the caller — this is the best
		// we can do without changing the function's nil signature.
		debugLog("continuation: reset join bind %s failed: %v", joinPath, err)
	}
}

// debugLog is a package-level helper; the handler's debugf isn't reachable
// from resetJoinReceived which has no handler receiver. We log via stderr
// when this fires so the operator at least sees the warning.
func debugLog(format string, args ...any) {
	log.Printf(format, args...)
}
