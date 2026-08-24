package continuation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
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

	// STANDING-MODEL §4 completion sweep — throttled, so a join whose round
	// expired with no traffic of its own still self-heals off somebody else's.
	// Before the cap check: reaping a foreign join is this peer's own
	// housekeeping on its own tree, not something the caller is authorized for.
	h.maybeSweepJoins(ctx, hctx)

	// Level 2 capability check — split by trigger kind per
	// PROPOSAL-CONTINUATION-STANDING-MODEL §3 (Q2 ruling, MUST):
	//
	//   - Administrative invoke (a bare `advance` EXECUTE — operator/handler
	//     directly managing continuations) stays path-cap-gated on the
	//     continuation path. This is the local/operator path.
	//   - Reactive trigger (an advancement driven by a delivered event — an
	//     inbox route, a subscription poke, flagged via WithReactiveTrigger)
	//     is NOT path-cap-gated here. Delivery-reachability was already enforced
	//     upstream (the receive that delivered to this path passed its own Level-2
	//     check); the advance then dispatches under the continuation's OWN
	//     dispatch_capability (advanceForward → executeDispatch). Requiring the
	//     trigger to also hold advance-cap on the path is the over-restriction
	//     that broke reactive standing continuations cross-peer — a remote peer
	//     would need advance rights on the target's own continuation. §6.1's
	//     escalation mitigation is the install-time in-chain check on
	//     dispatch_capability, not an advance-time caller check.
	if !hctx.ReactiveTrigger {
		if resp := hctx.CheckPathCapability("advance", path); resp != nil {
			return resp, nil
		}
	}

	status := uint(200)
	if advReq.Status != nil {
		status = *advReq.Status
	}

	return h.advanceAtPath(ctx, hctx, path, advReq.Result, status, advReq.RoundID)
}

// advanceAtPath implements the continuation advancement algorithm (spec §3.3).
// Returns {advanced: true} on success, {advanced: false} when no continuation at path.
//
// roundID is the §4.1 round the advance targets, threaded only to the join-slot
// path (a forward continuation has no rounds and ignores it). nil = untracked.
func (h *Handler) advanceAtPath(ctx context.Context, hctx *handler.HandlerContext, path string, result cbor.RawMessage, status uint, roundID *uint64) (*handler.Response, error) {
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
				return h.advanceJoinSlot(ctx, hctx, parent, slot, joinData, result, status, roundID)
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
	// Spec step 6: one chain id for this advance — inherited from the
	// advancing context, or generated when the trigger carried no chain.
	// Resolved once here so the dispatch below and any marker bound for it
	// share the same coordinate.
	chainID := dispatchChainID(hctx)

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
		}, result, chainID)
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
			h.bindLostErrorMarker(hctx, chainID, cont.OnError.URI, status, result, types.ChainErrorReasonOnErrorDispatchFailed, originTS, hash.Hash{})
		}
		// Only handle remaining_executions after the error-path dispatch
		// (best-effort — the error was routed or recorded as lost).
		h.handleRemainingExecutions(hctx, path, cont.RemainingExecutions)
		return advancementOK()
	}

	dispatchResp, err := h.executeDispatch(ctx, hctx, cont, result, chainID)
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
		h.bindLostErrorMarker(hctx, chainID, cont.Target, uint(dispatchResp.Status), dispatchResultRaw, reason, originTS, mirror)
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
func (h *Handler) bindLostErrorMarker(hctx *handler.HandlerContext, chainID, failedURI string, origStatus uint, origResult cbor.RawMessage, reason string, originTimestampMs uint64, mirrorReceiverMarker hash.Hash) {
	h.bindLostErrorMarkerForJoin(hctx, chainID, failedURI, origStatus, origResult, reason, originTimestampMs, mirrorReceiverMarker, "", nil)
}

// bindLostErrorMarkerForJoin is bindLostErrorMarker plus the two
// join-completion coordinates (STANDING-MODEL §4). Split this way rather than
// widened in place so every existing caller keeps its signature and no non-join
// marker can accidentally acquire join fields.
func (h *Handler) bindLostErrorMarkerForJoin(hctx *handler.HandlerContext, chainID, failedURI string, origStatus uint, origResult cbor.RawMessage, reason string, originTimestampMs uint64, mirrorReceiverMarker hash.Hash, joinPath string, joinSlots []string) {
	// chainID is the chain the failing dispatch actually carried, resolved once
	// per advance by dispatchChainID (spec step 6: inherit or generate). It is
	// passed in rather than re-derived so the marker cannot be filed under a
	// different coordinate than the dispatch ran with.
	//
	// The rungs below are a backstop for a caller that reached here without a
	// chain — no longer possible on the advance paths, since step 6 guarantees
	// one. They are deliberately NOT removed: a coordinate invented from a
	// request id is exactly how this defect stayed invisible across three
	// impls for a cycle, so if one ever fires again it should be findable.
	// Removing them would treat the symptom; the fix was upstream, at the seed.
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

	// chainID, stepKey and reason are all wire-reachable — an inbound EXECUTE
	// chooses request_id and bounds.chain_id, and `reason` is the target
	// handler's own error code. Each is interpolated into the marker path
	// below, so each must be exactly one segment.
	//
	// The RAW values are kept: the path gets the sanitized form, the body gets
	// the original (§3.10.6 registry + arch ruling 2026-07-17 §2). Collapsing a
	// coordinate is only lossless because the body recovers it, so these two
	// lines are a pair — never sanitize in place here again.
	rawChainID, rawStepKey := chainID, stepKey
	pathChainID := store.SanitizePathSegment(chainID, types.ChainIDUnspecified)
	pathStepKey := store.SanitizePathSegment(stepKey, types.StepIndexUnspecified)
	pathReason := store.SanitizePathSegment(reason, types.ReasonUnspecified)

	// Self-collection (§3.4 A.1 retention), BEFORE the bind, not after: reap
	// the expired, then record the new. Sweeping afterwards would let a marker
	// whose ORIGINATION timestamp is already older than the window (a
	// redelivery of an old failure — legitimate under §3.10.6) be deleted by
	// the very bind that wrote it, which reads as the write silently failing.
	// Throttled, so the dispatch path does not carry a scan; best-effort, like
	// everything else on this tree.
	h.maybeCollectMarkers(hctx.Store, hctx.LocationIndex)

	origCode := ""
	if len(origResult) > 0 {
		var ed types.ErrorData
		if err := ecf.Decode(origResult, &ed); err == nil {
			origCode = ed.Code
		}
	}

	marker, err := types.ChainErrorLostData{
		Code:               origCode,
		Status:             origStatus,
		TargetURI:          failedURI,
		Timestamp:          originTimestampMs,
		Reason:             pathReason,
		ChainID:            rawChainID,
		StepIndex:          rawStepKey,
		JoinPath:           joinPath,
		JoinSlots:          joinSlots,
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
	markerPath := "system/runtime/chain-errors/lost/" + pathChainID + "/" + pathStepKey + "/" + pathReason + "/" + hex.EncodeToString(markerHash.Bytes())
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

// joinSlotDroppedStale is the §4.1 straggler drop result: the slot targeted a
// round that is no longer current and was NOT admitted. Returned 200 (the
// advance was processed and validly rejected as stale — not a server error;
// a non-2xx would invite the advancer to retry the same stale slot forever)
// with an explicit body so the drop is visible on the wire in addition to the
// durable join_late marker. The status/code contract here was routed to arch
// as a pin candidate and is now PINNED: EXTENSION-CONTINUATION §3.5a (v1.21)
// fixes both the join_late marker and this 5-key 200 drop-body shape.
func joinSlotDroppedStale(slotName string, targetedRound, currentRound uint64) (*handler.Response, error) {
	resultRaw, _ := ecf.Encode(map[string]interface{}{
		"advanced":       false,
		"dropped":        "stale_round",
		"slot":           slotName,
		"targeted_round": targetedRound,
		"current_round":  currentRound,
	})
	resultEntity, _ := entity.NewEntity("system/continuation/advancement-result", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// errInvalidContinuation is returned when continuation configuration is invalid
// (e.g., result_field without params). This is distinct from target handler errors.
type errInvalidContinuation struct{ msg string }

func (e *errInvalidContinuation) Error() string { return e.msg }

// executeDispatch applies transform, assembles params, and dispatches (spec §3.5).
// Returns errInvalidContinuation for configuration errors in the continuation itself.
// dispatchChainID resolves the chain id for one advance, per the spec's
// advance step 6: `context.chain_id or generate_id()`.
//
// Inherit when the advancing context carries a chain — the continuation is a
// step IN that chain and must stay under its coordinate. Generate otherwise:
// an advance triggered by something outside any chain (a subscription delivery
// off a background write, the network handler's retry timer, an operator put)
// still IS a chain, it is simply a root one, and it needs an identity before it
// can dispatch or be recorded against.
//
// Called ONCE per advance so the dispatch and every marker bound for it agree
// on the coordinate; a second call would mint a second id and file the marker
// under a chain that never ran.
func dispatchChainID(hctx *handler.HandlerContext) string {
	if hctx != nil && hctx.Bounds != nil && hctx.Bounds.ChainID != "" {
		return hctx.Bounds.ChainID
	}
	return generateChainID()
}

// generateChainID mints a fresh §3.11 chain id.
//
// A chain_id MUST be a SINGLE PATH SEGMENT — it is a segment of the §3.10.6
// marker path, so any "/" would fork the marker tree into extra levels. It is
// otherwise opaque: §3.11 declares no format and nothing parses one.
func generateChainID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("chain-%d", time.Now().UnixNano())
	}
	return "chain-" + hex.EncodeToString(b[:])
}

// dispatchBounds builds the bounds for a continuation's dispatched EXECUTE:
// the parent's, with ttl decremented, carrying chainID.
//
// The ttl/budget handling mirrors the dispatcher's own default path exactly
// (core/protocol/local.go decrementBounds), because passing explicit bounds
// opts OUT of that path — the intended differences are that chain_id is now
// always populated and that a root chain is seeded with the uniform
// types.DefaultChainTTL. A parentless advance used to yield bounds carrying
// the chain id alone; that shape was honest about inheritance but left ttl
// absent on the wire, which is precisely how TTL ended up unspecified
// cross-peer.
//
// Note the spec's step 6 also shows ttl/budget being reset to peer defaults
// on each dispatch. Go decrements instead, which is the stricter reading and
// is what every existing bounds test pins; that difference is orthogonal to
// the chain id and is left alone here rather than smuggled in.
func dispatchBounds(parent *types.BoundsData, chainID string, ttlSeed uint64) (*types.BoundsData, error) {
	var child types.BoundsData
	if parent != nil {
		child = *parent
		if child.TTL != nil {
			if *child.TTL == 0 {
				return nil, fmt.Errorf("TTL exhausted")
			}
			newTTL := *child.TTL - 1
			child.TTL = &newTTL
		}
	}
	// Seed the uniform TTL when none is inherited — the root-chain case this
	// function's comment used to simply accept ("no inherited ttl to
	// decrement"). Accepting it is what left TTL unspecified cross-peer: a
	// chain Go rooted carried no ttl at all, so whether TTL bounded it was
	// decided by whichever peer it happened to reach. Seeding here makes every
	// chain carry one, decremented exactly once per hop by the branch above.
	// Deliberately above the §3.9 depth ceiling (see types.DefaultChainTTL) so
	// chain_depth stays the binding global brake rather than racing TTL.
	if child.TTL == nil {
		seed := ttlSeed
		child.TTL = &seed
	}
	child.ChainID = chainID
	return &child, nil
}

func (h *Handler) executeDispatch(ctx context.Context, hctx *handler.HandlerContext, cont types.ContinuationData, rawResult cbor.RawMessage, chainID string) (*handler.Response, error) {
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
			h.bindMergeValueNotMapMarker(hctx, chainID, cont.Target, value)
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

	// Spec step 6: dispatch with bounds carrying the chain id —
	//
	//	dispatch(execute, bounds: {..., chain_id: context.chain_id or generate_id()})
	//
	// The `or generate_id()` half is the one that matters and the one Go did
	// not have: this dispatch previously carried NO bounds at all, so a
	// continuation whose trigger had no chain context (a subscription
	// delivery off a background tree write, a timer, an operator put)
	// dispatched with chain_id absent, and every downstream chain-error marker
	// had to invent a coordinate. Generating here is what makes the marker's
	// chain_id a real chain rather than a stringified request id.
	//
	// Additive: it fills a field that was empty and preserves the ttl/budget
	// decrement the default dispatch path applies. Note that it also brings
	// cap-rejected continuation dispatches into the §3.10.3 `rejected` marker
	// scope (which fires only for chain dispatches) — previously they fell
	// outside it for want of a chain id, which was the same defect wearing a
	// different hat.
	childBounds, boundsErr := dispatchBounds(hctx.Bounds, chainID, h.chainTTLSeed)
	if boundsErr != nil {
		return handler.NewErrorResponse(429, "bounds_exceeded", boundsErr.Error())
	}
	opts = append(opts, handler.WithBounds(childBounds))

	// §3.9: "The counter is incremented on each continuation advancement
	// dispatch." THIS is that dispatch — the only site in the tree that
	// increments. The dispatch layer enforces the ceiling; we only count.
	opts = append(opts, handler.WithChainDepth(hctx.ChainDepth+1))

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

// advanceJoinSlot implements join slot advancement (spec §3.5), with the
// STANDING-MODEL §4 completion policy layered on the failure paths only.
//
// `status` is the advance request's status for THIS slot. It is threaded in
// rather than dropped because a delivered non-2xx FILLS its slot — the barrier
// completes and the failure vanishes into the stitch unless the join records it
// (§4 mechanism 1). The slot's payload itself is stored exactly as it arrived:
// an error payload is passed through as-is, never coerced into boundary bytes.
func (h *Handler) advanceJoinSlot(ctx context.Context, hctx *handler.HandlerContext, joinPath, slotName string, join types.ContinuationJoinData, result cbor.RawMessage, status uint, roundID *uint64) (*handler.Response, error) {
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
	h.noteJoinPath(joinPath, join)

	// §4 mechanism 2, on the path that matters most: if the PREVIOUS round
	// blew its deadline while nothing was touching this join, fail it here
	// before accumulating. Without this, the arriving slot would be counted
	// into a dead round and the join would stay one slot short forever — the
	// wedge. Reaping first is what lets the next round "fire clean".
	nowMs := uint64(time.Now().UnixMilli())
	if h.reapExpiredJoinRound(ctx, hctx, joinPath, join, nowMs) {
		// Re-read: the reap rebound (or deleted) the join.
		joinEnt, joinType = readEntity(hctx, joinPath)
		if joinType != types.TypeContinuationJoin {
			return advancementNotFound()
		}
		if join, err = types.ContinuationJoinDataFromEntity(joinEnt); err != nil {
			return handler.NewErrorResponse(500, "internal_error", "re-decode join after reap: "+err.Error())
		}
	}

	// §4.1 straggler guard (MUST): a slot advance targeting a round that is no
	// longer current — a straggler from an abandoned (or already-fired) round —
	// MUST NOT be admitted. Admitting it stitches two generations into one
	// boundary hash: wrong, deterministic-looking, reproducible — the silent
	// seam-collapse §4.1 exists to prevent. Checked HERE, after the reap
	// re-read, so `join.RoundID` is the current generation (the reap above may
	// have advanced it). Additive: only a deadline-carrying join turns rounds
	// over, and only a slot that opted in by tagging `round_id` is checked — an
	// untagged advance is admitted exactly as before §4.1. Dropped LOUDLY: a
	// join_late marker naming the stale slot + the round it targeted, so
	// lateness is observable, not merely survived.
	if roundID != nil && join.CompletionDeadlineMs != nil && *roundID != join.RoundID {
		h.bindJoinLateMarker(hctx, joinPath, join, slotName, *roundID, nowMs)
		debugLog("join %s: slot %q targeted stale round %d (current %d) — dropped loudly (§4.1)", joinPath, slotName, *roundID, join.RoundID)
		return joinSlotDroppedStale(slotName, *roundID, join.RoundID)
	}

	// Accumulate. The payload goes in verbatim — byte fidelity here is what
	// keeps a complete round's assembled params identical to the serial case.
	received := make(map[string]cbor.RawMessage)
	for k, v := range join.Received {
		received[k] = v
	}
	received[slotName] = result

	// §4 mechanism 1: remember a slot that arrived carrying an error. Sparse —
	// an all-good round never grows this map, so its entity bytes are unchanged.
	receivedStatus := make(map[string]uint, len(join.ReceivedStatus))
	for k, v := range join.ReceivedStatus {
		receivedStatus[k] = v
	}
	if status < 200 || status >= 300 {
		receivedStatus[slotName] = status
	} else {
		delete(receivedStatus, slotName) // a redelivered slot may arrive clean
	}
	if len(receivedStatus) == 0 {
		receivedStatus = nil
	}
	join.Received = received
	join.ReceivedStatus = receivedStatus
	armJoinRound(&join, nowMs)

	// Check completeness.
	if allSlotsReceived(join.Expected, received) {
		// All slots filled — dispatch.
		receivedRaw, err := ecf.Encode(received)
		if err != nil {
			return nil, fmt.Errorf("encode received: %w", err)
		}

		// §4 mechanism 1: the barrier completed, but not cleanly. Record the
		// round as failed BEFORE dispatching, so the observation exists whether
		// or not the target rejects. The dispatch still happens with the error
		// payload passed through untouched: it is the target — the
		// determinism-critical stitch — that MUST reject an error slot rather
		// than compute a boundary entity from it. The join's job is to make
		// that decidable, not to make it.
		if errored := join.ErrorSlots(); len(errored) > 0 {
			h.bindJoinIncompleteMarker(hctx, joinPath, join, errored, types.ChainErrorReasonJoinErrorSlot, nowMs)
			debugLog("join %s: round completed with error slot(s) %v — target must reject rather than fold them into a boundary entity", joinPath, errored)
		}

		contData := joinDispatchData(join)

		_, dispatchErr := h.executeDispatch(ctx, hctx, contData, cbor.RawMessage(receivedRaw), dispatchChainID(hctx))

		// Lifecycle: decrement a counted join (deleting it at zero) or reset a
		// standing one. Shared with the deadline-driven fire so both age the
		// join identically.
		h.advanceJoinLifecycle(hctx, joinPath, join)

		if configErr, ok := dispatchErr.(*errInvalidContinuation); ok {
			return handler.NewErrorResponse(400, "invalid_continuation", configErr.msg)
		}
		if dispatchErr != nil {
			return nil, dispatchErr
		}
		return advancementOK()
	}

	// Not complete — update join entity with accumulated received.
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

// debugLog is a package-level helper; the handler's debugf isn't reachable
// from the join reset path, which has no handler receiver on every branch. We
// log via stderr when this fires so the operator at least sees the warning.
func debugLog(format string, args ...any) {
	log.Printf(format, args...)
}
