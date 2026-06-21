package protocol

import (
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Durability Contract — reference implementation of EXTENSION-DURABILITY
// v0.1 (exploratory / optional / not actively developed; extracted from
// EXTENSION-INBOX §10 per the retraction of
// PROPOSAL-DELIVERY-AND-DURABILITY).
//
// The receiver's own configured policy decides what durability it can
// provide; it is reconciled against the request at acceptance — min(request,
// policy), decided from the receiver's own configuration, never a prediction
// of another peer's future state (§4). The verdict is status + the pinned
// `durability` field (§5). When the extension is installed, a
// durability_request is always answered observably, never silently dropped.
// V7 v7.46 itself does not mandate this — the silent-ignore wording was
// restored when v7.47 was reverted.

// DurabilityPolicy is the receiver's own durability configuration
// (EXTENSION-DURABILITY §4).
type DurabilityPolicy struct {
	// MaxSelfDeterminable is the strongest level this peer can guarantee
	// SYNCHRONOUSLY at acceptance: types.DurabilityStored when the peer
	// write-ahead persists the request to its store+tree (findable again
	// via the response's handle, §6), or types.DurabilityNone for a peer
	// with no durable store. Empty is treated as DurabilityNone.
	MaxSelfDeterminable string

	// ReplicationConfigured holds replication-class levels the peer is
	// configured for (its own topology configuration). Replication-class
	// durability is inherently 202-then-observe even when required — no
	// receiver can synchronously prove a second peer holds the data (§5
	// invariant). Empty by default: the Go peer is not configured for any
	// replication topology, so a must_have replication level is refused at
	// acceptance (412) — it knows its own configuration (§5 row 5).
	ReplicationConfigured map[string]bool
}

// DefaultDurabilityPolicy: a peer with a durable store self-determines
// "stored"; not configured for any replication topology.
func DefaultDurabilityPolicy() DurabilityPolicy {
	return DurabilityPolicy{MaxSelfDeterminable: types.DurabilityStored}
}

// Advertisement is the §3 discovery hint: the levels this peer supports,
// weakest to strongest (self-determinable ladder up to MaxSelfDeterminable,
// then any replication-class levels it is configured for). Discovery only —
// the authoritative answer is always the response verdict (§5).
func (p DurabilityPolicy) Advertisement() types.DurabilityAdvertisementData {
	levels := []string{types.DurabilityNone}
	best := p.MaxSelfDeterminable
	if best == "" {
		best = types.DurabilityNone
	}
	if bestRank, _ := durabilityRank(best); bestRank >= 1 {
		levels = append(levels, types.DurabilityStored)
	}
	for lvl := range p.ReplicationConfigured {
		if p.ReplicationConfigured[lvl] {
			levels = append(levels, lvl)
		}
	}
	return types.DurabilityAdvertisementData{
		Levels:              levels,
		MaxSelfDeterminable: best,
	}
}

// durabilityRank returns the position of a level on the self-determinable
// ladder. Replication-class and unknown levels are not self-certifiable at
// acceptance (selfDeterminable=false) — §5 / Decision 2.
func durabilityRank(level string) (rank int, selfDeterminable bool) {
	switch level {
	case types.DurabilityNone, "":
		return 0, true
	case types.DurabilityStored:
		return 1, true
	default:
		return -1, false
	}
}

// levelClass categorizes a requested durability level. EXTENSION-DURABILITY §5 / §8
// distinguishes known replication-class levels (best-effort falls back to
// the strongest self-determinable strength) from genuinely unknown levels
// (fail-closed: applied:none + reason:unknown_level — you don't promise
// what you don't understand).
type levelClass int

const (
	levelSelfDeterminable levelClass = iota
	levelReplicationClass
	levelUnknown
)

func classifyLevel(level string) levelClass {
	switch level {
	case types.DurabilityNone, "", types.DurabilityStored:
		return levelSelfDeterminable
	case types.DurabilityReplicated:
		return levelReplicationClass
	default:
		return levelUnknown
	}
}

// appliedImpliesStore reports whether a reported `applied` level means the
// request is physically persisted (so the originating request must actually
// be preserved for the claim to be honest — the §5 invariant).
func appliedImpliesStore(level string) bool {
	r, _ := durabilityRank(level)
	return r >= 1
}

// durabilityVerdict is the reconciled outcome for one durability_request.
type durabilityVerdict struct {
	// Status is 200 (final), 202 (accepted; Committed completes async), or
	// 412 (required durability unmet — operation NOT performed).
	Status uint
	// Result is the pinned durability field for the response.
	Result types.DurabilityResultData
	// PerformOp is false ONLY on 412 (refuse at acceptance — no run-then-fail).
	PerformOp bool
	// Async is true when Status == 202 (the committed strength completes
	// asynchronously and is observable at the (author,request_id) address).
	Async bool
	// Preserve is true when the originating request must be physically
	// written to the inbox namespace so `applied` is honest (§6).
	Preserve bool
}

// Reconcile reconciles a durability_request against this policy at acceptance
// and produces the verdict per the §5 table. It never reports a
// not-yet-achieved level in `applied`; a promise lives only in `committed`,
// gated to 202; `max_available` appears only on 412.
func (p DurabilityPolicy) Reconcile(req types.DurabilityRequestData) durabilityVerdict {
	bestSelf := p.MaxSelfDeterminable
	if bestSelf == "" {
		bestSelf = types.DurabilityNone
	}
	bestRank, _ := durabilityRank(bestSelf)
	v := durabilityVerdict{Result: types.DurabilityResultData{Requested: req.Level}}

	switch classifyLevel(req.Level) {

	case levelSelfDeterminable:
		reqRank, _ := durabilityRank(req.Level)
		if reqRank <= bestRank {
			// Receiver can do >= X — 200, outcome final.
			v.Status = 200
			v.Result.Applied = req.Level
			if req.Level == "" {
				v.Result.Applied = types.DurabilityNone
			}
			v.PerformOp = true
			v.Preserve = appliedImpliesStore(v.Result.Applied)
			return v
		}
		// Stronger than this peer offers (e.g. wants "stored", peer is "none").
		if req.MustHave {
			return refusal(req.Level, bestSelf)
		}
		// Best-effort, not must-have: take the weaker level, observably.
		v.Status = 200
		v.Result.Applied = bestSelf
		if bestSelf == types.DurabilityNone {
			v.Result.Reason = types.ReasonNoDurableStore
		}
		v.PerformOp = true
		v.Preserve = appliedImpliesStore(bestSelf)
		return v

	case levelReplicationClass:
		if p.ReplicationConfigured[req.Level] {
			// Configured for the replication topology; commit to the pathway.
			// applied reports only physical-now (§5 invariant); committed
			// names the async target.
			v.Status = handler.StatusAccepted
			v.Result.Applied = bestSelf
			if bestSelf == "" {
				v.Result.Applied = types.DurabilityNone
			}
			v.Result.Committed = req.Level
			v.PerformOp = true
			v.Async = true
			v.Preserve = appliedImpliesStore(v.Result.Applied)
			return v
		}
		// Known replication-class but receiver isn't configured for it.
		if req.MustHave {
			return refusal(req.Level, bestSelf)
		}
		// Best-effort: strongest self-determinable, observably.
		v.Status = 200
		v.Result.Applied = bestSelf
		if bestSelf == types.DurabilityNone {
			v.Result.Reason = types.ReasonNoDurableStore
		}
		v.PerformOp = true
		v.Preserve = appliedImpliesStore(bestSelf)
		return v

	default: // levelUnknown — EXTENSION-DURABILITY §5 / §8 fail-closed.
		if req.MustHave {
			return refusal(req.Level, bestSelf)
		}
		// Best-effort UNKNOWN: don't promise what we don't understand.
		// applied:none + reason:unknown_level. The operation still runs.
		v.Status = 200
		v.Result.Applied = types.DurabilityNone
		v.Result.Reason = types.ReasonUnknownLevel
		v.PerformOp = true
		v.Preserve = false
		return v
	}
}

// refusal builds the 412 verdict: required durability unmet, operation NOT
// performed (refused at acceptance — safe to retry elsewhere, no
// double-execution). max_available is the best the receiver could offer.
func refusal(requested, maxAvailable string) durabilityVerdict {
	if maxAvailable == "" {
		maxAvailable = types.DurabilityNone
	}
	return durabilityVerdict{
		Status:    handler.StatusPreconditionFailed,
		PerformOp: false,
		Result: types.DurabilityResultData{
			Requested:    requested,
			Applied:      types.DurabilityNone,
			MaxAvailable: maxAvailable,
			Reason:       types.ReasonRequiredUnmet,
		},
	}
}

// durabilityPolicy returns the dispatcher's configured policy, defaulting to
// a conservative no-durable-store policy when unset (zero-value Dispatcher
// built without NewDispatcher — never overclaims).
func (d *Dispatcher) durabilityPolicy() DurabilityPolicy {
	return d.DurabilityPolicy
}

// finishExecute builds the success EXECUTE_RESPONSE, attaching the durability
// verdict when one was produced. When the verdict is the replication-class
// 202 (accepted; the committed strength completes asynchronously and is
// observable at the (author,request_id) address — §5 row 5), the
// operation result still rides this response but the status is 202.
func (d *Dispatcher) finishExecute(requestID string, resp *handler.Response, dur *types.DurabilityResultData, async bool) (entity.Envelope, error) {
	if dur == nil {
		return d.makeResponse(requestID, resp)
	}
	if async {
		r := *resp
		r.Status = handler.StatusAccepted
		return d.makeResponseDur(requestID, &r, dur)
	}
	return d.makeResponseDur(requestID, resp, dur)
}

// makeResponseDur is makeResponse with the durability verdict attached.
func (d *Dispatcher) makeResponseDur(requestID string, resp *handler.Response, dur *types.DurabilityResultData) (entity.Envelope, error) {
	resultRaw, err := encodeToRaw(resp.Result)
	if err != nil {
		return entity.Envelope{}, err
	}
	respData := types.ExecuteResponseData{
		RequestID:  requestID,
		Status:     resp.Status,
		Result:     resultRaw,
		Durability: dur,
	}
	respEntity, err := respData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(respEntity, resp.Included), nil
}

// make202ResponseDur is make202Response with the durability verdict attached.
func (d *Dispatcher) make202ResponseDur(requestID string, dur *types.DurabilityResultData) (entity.Envelope, error) {
	respData := types.ExecuteResponseData{
		RequestID:  requestID,
		Status:     handler.StatusAccepted,
		Result:     []byte{0xf6}, // CBOR null
		Durability: dur,
	}
	respEntity, err := respData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(respEntity, nil), nil
}

// makeDurabilityDuplicate builds the 409 EXECUTE_RESPONSE for a replayed
// durable request whose (author, request_id) already names a preserved
// entry (EXTENSION-DURABILITY §5 / §8). The durability field reports applied:stored
// with the original `handle` so the sender can verify they're seeing the
// same entry from the first attempt. Status 409, error result body for
// durability-unaware consumers.
func (d *Dispatcher) makeDurabilityDuplicate(requestID, requestedLevel, priorHandle string) (entity.Envelope, error) {
	d.debugf("execute: -> 409 duplicate_request_id requestID=%s handle=%s", requestID, priorHandle)
	errData := types.ErrorData{
		Code:    types.ReasonDuplicateRequestID,
		Message: "durable (author, request_id) already preserved at " + priorHandle,
	}
	errEntity, err := errData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	resultRaw, err := encodeToRaw(errEntity)
	if err != nil {
		return entity.Envelope{}, err
	}
	respData := types.ExecuteResponseData{
		RequestID: requestID,
		Status:    handler.StatusConflict,
		Result:    resultRaw,
		Durability: &types.DurabilityResultData{
			Requested: requestedLevel,
			Applied:   types.DurabilityStored,
			Handle:    priorHandle,
			Reason:    types.ReasonDuplicateRequestID,
		},
	}
	respEntity, err := respData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(respEntity, nil), nil
}

// makeDurabilityRefusal builds the 412 EXECUTE_RESPONSE: a required-durability
// precondition could not be met, so the request is refused and the operation
// is NOT performed (EXTENSION-DURABILITY §5 / §8 — 412 lives within this
// extension's surface only; V7 v7.46 does not reserve 412 at the core level).
// The durability field
// carries the structured verdict; the result entity is a standard
// system/protocol/error so durability-unaware consumers still see a refusal.
func (d *Dispatcher) makeDurabilityRefusal(requestID string, dur types.DurabilityResultData) (entity.Envelope, error) {
	d.debugf("execute: -> 412 durability_required_unmet requested=%s max_available=%s",
		dur.Requested, dur.MaxAvailable)
	errData := types.ErrorData{
		Code:    types.ReasonRequiredUnmet,
		Message: "required durability not met: requested=" + dur.Requested + " max_available=" + dur.MaxAvailable,
	}
	errEntity, err := errData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	resultRaw, err := encodeToRaw(errEntity)
	if err != nil {
		return entity.Envelope{}, err
	}
	respData := types.ExecuteResponseData{
		RequestID:  requestID,
		Status:     handler.StatusPreconditionFailed,
		Result:     resultRaw,
		Durability: &dur,
	}
	respEntity, err := respData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(respEntity, nil), nil
}

// predictDeliverToHandle returns the absolute path the inbox handler will
// write the delivery to, given the request's deliver_to spec and the origin
// request id. The inbox handler (EXTENSION-INBOX §3.2) stores at
// `<inbox_path>/<request_id>`; this is the durable handle for the
// deliver_to + durable case (EXTENSION-DURABILITY §6 / §8). Returns "" if the URI is
// malformed; the caller treats that as no-handle.
func predictDeliverToHandle(spec *types.DeliverySpec, requestID string) string {
	if spec == nil || spec.URI == "" || requestID == "" {
		return ""
	}
	u, err := entity.ParseURI(spec.URI)
	if err != nil || u.PeerID == "" {
		return ""
	}
	return "/" + u.PeerID + "/" + u.Path + "/" + requestID
}

// preserveDurableRequest write-ahead persists the originating EXECUTE entity
// into this peer's inbox namespace at the origin request id so the sender can
// find it again (§6). Only the no-deliver_to durable case calls this; the
// deliver_to path's inbox write-ahead already preserves. Best-effort: a
// storage failure is logged and the verdict downgrades observably rather than
// overclaiming `applied`. Returns the absolute path written to (the `handle`
// returned in the response, EXTENSION-DURABILITY §6 / §8) and a success flag.
func (d *Dispatcher) preserveDurableRequest(requestID string, execEntity entity.Entity) (string, bool) {
	if d.Store == nil || d.LocationIndex == nil || requestID == "" {
		return "", false
	}
	h, err := d.Store.Put(execEntity)
	if err != nil {
		d.debugf("durability: preserve store failed for %s: %v", requestID, err)
		return "", false
	}
	path := store.QualifyPath(string(d.LocalPeerID), "system/inbox/"+requestID)
	mc := &store.MutationContext{
		AuthorHash:     d.LocalIdentityHash,
		HandlerPattern: "system/inbox",
		Operation:      "receive",
	}
	if cw, ok := d.LocationIndex.(store.ContextualWriter); ok {
		if _, err := cw.SetWithContext(path, h, mc); err != nil {
			d.debugf("durability: preserve bind failed for %s: %v", requestID, err)
			return "", false
		}
		return path, true
	}
	if err := d.LocationIndex.Set(path, h); err != nil {
		d.debugf("durability: preserve bind failed for %s: %v", requestID, err)
		return "", false
	}
	return path, true
}
