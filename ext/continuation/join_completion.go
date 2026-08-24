package continuation

// Join completion policy — PROPOSAL-CONTINUATION-STANDING-MODEL §4 (Facet B).
//
// The barrier fires only on allSlotsReceived and a standing join resets
// `received` only after firing, so a slot that never arrives wedges that round
// AND every subsequent one: the join is permanently one slot short and can
// never fire again. §2.3/§3.5 define accumulate-under-CAS and fire-on-complete
// but say nothing about the missing slot. §4 fills that hole with two
// mechanisms that MUST NOT be conflated:
//
//	mechanism 2 — UNDELIVERED. The slot never arrives (dropped trigger, 429
//	  pool refusal, error returning before delivery). Handled here: a per-round
//	  wall budget, then abandon (default) or fire-partial.
//
//	mechanism 1 — DELIVERED-ERROR. The slot arrives carrying a non-2xx result,
//	  which FILLS it — the barrier completes normally and the failure lands in
//	  the stitch, which has no contract for "one of my slots is an error".
//	  Handled in advance.go by preserving the slot's status and refusing to let
//	  the round pass as clean.
//
// Determinism is preserved because both are failure-path only. A complete,
// all-good round assembles byte-identically to what it assembled before this
// file existed; a failed round produces a `lost` marker, never a partial
// boundary entity. A failed round is OBSERVABLY failed, not silently divergent
// — which is the whole point, since a boundary hash computed from an error
// payload would diverge across peers and collapse the cross-peer seam.

import (
	"context"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// joinSweepThrottle bounds how often an operation pays for a join sweep. Same
// shape and reasoning as collectThrottle: the cost stays amortized off the
// dispatch path.
const joinSweepThrottle = time.Minute

// validOnIncomplete reports whether v is a recognized on_incomplete policy.
// Empty means absent, which is JoinOnIncompleteAbandon.
func validOnIncomplete(v string) bool {
	switch v {
	case "", types.JoinOnIncompleteAbandon, types.JoinOnIncompleteFirePartial:
		return true
	default:
		return false
	}
}

// onIncompletePolicy resolves the effective policy — absent means abandon.
func onIncompletePolicy(join types.ContinuationJoinData) string {
	if join.OnIncomplete == "" {
		return types.JoinOnIncompleteAbandon
	}
	return join.OnIncomplete
}

// armJoinRound stamps RoundStartedMs if the round has not begun.
//
// Armed at the round's FIRST slot rather than at install/reset, deliberately. A
// join holding zero slots has not started a round — there is nothing to
// abandon, and arming on an empty join would make an idle standing join emit a
// lost marker every deadline forever, an unbounded marker stream for a join
// nobody is using. §4 says only "reset with `received` each round", which this
// satisfies: the clock lives and dies with `received`.
//
// The cost is stated plainly: a round in which NO slot arrives is invisible to
// the deadline. That case is indistinguishable from an idle join without
// out-of-band knowledge of the tick, so it is the substrate's to notice, not
// the join's. Routed to arch with the round-clock field.
//
// A join with no deadline never arms at all. Nothing could consume the clock,
// and writing it anyway would put a new field — and so new entity bytes — on
// every deadline-less join in the tree, which is exactly the silent change §4
// promises not to make.
func armJoinRound(join *types.ContinuationJoinData, nowMs uint64) {
	if join.CompletionDeadlineMs == nil {
		return
	}
	if join.RoundStartedMs == nil {
		started := nowMs
		join.RoundStartedMs = &started
	}
}

// clearJoinRound drops the round clock and per-slot statuses along with
// `received`. Called from every reset site so the three can never drift apart —
// a stale RoundStartedMs would make the NEXT round inherit this round's
// deadline and abandon itself early.
func clearJoinRound(join *types.ContinuationJoinData) {
	join.Received = nil
	join.RoundStartedMs = nil
	join.ReceivedStatus = nil
}

// reapExpiredJoinRound applies the completion policy to a join whose round has
// exceeded its deadline with slots still missing, and reports whether it acted.
//
// Caller MUST hold the join lock: this reads, decides, and rebinds.
//
// abandon (default) — bind a lost marker naming the missing slots, reset the
// round, return. The next round starts clean; a standing per-tick join
// self-heals instead of wedging, which is the load-bearing change for realtime
// reuse and the direct analogue of §3's "owns its liveness independent of any
// trigger."
//
// fire-partial — dispatch the target with the partial `received` plus an
// explicit incomplete marker naming the missing slots, then reset. Opt-in only.
func (h *Handler) reapExpiredJoinRound(ctx context.Context, hctx *handler.HandlerContext, joinPath string, join types.ContinuationJoinData, nowMs uint64) bool {
	if !join.IncompleteRound(nowMs) {
		return false
	}
	missing := join.MissingSlots()

	if onIncompletePolicy(join) == types.JoinOnIncompleteFirePartial {
		h.firePartialRound(ctx, hctx, joinPath, join, missing, nowMs)
		return true
	}

	// abandon: the round failed and says so.
	h.bindJoinIncompleteMarker(hctx, joinPath, join, missing, types.ChainErrorReasonJoinIncomplete, nowMs)
	h.resetJoinRound(hctx, joinPath, join)
	debugLog("join %s: round abandoned at deadline, missing %v — reset for next round", joinPath, missing)
	return true
}

// firePartialRound dispatches a short round with an explicit incomplete marker.
//
// The marker rides IN the assembled params next to the slot values, not beside
// them, because the target reads one payload — a signal it has to fetch
// separately is a signal it will forget to fetch. Its presence is the whole
// contract: a target that opted into fire-partial and then ignores the marker
// has chosen partial input, which is exactly what opting in means.
func (h *Handler) firePartialRound(ctx context.Context, hctx *handler.HandlerContext, joinPath string, join types.ContinuationJoinData, missing []string, nowMs uint64) {
	payload := map[string]interface{}{
		types.JoinIncompleteField: map[string]interface{}{
			"missing":  missing,
			"expected": join.Expected,
		},
	}
	for slot, value := range join.Received {
		var decoded interface{}
		if err := ecf.Decode(value, &decoded); err != nil {
			// Undecodable slot payload: keep it out of the assembled map
			// rather than guess at its shape. It is named in `missing`'s
			// sibling `expected` and the slot simply does not appear, which
			// is the same observation a never-delivered slot produces.
			debugLog("join %s: fire-partial could not decode slot %q: %v", joinPath, slot, err)
			continue
		}
		payload[slot] = decoded
	}
	receivedRaw, err := ecf.Encode(payload)
	if err != nil {
		debugLog("join %s: fire-partial encode failed: %v — falling back to abandon", joinPath, err)
		h.bindJoinIncompleteMarker(hctx, joinPath, join, missing, types.ChainErrorReasonJoinIncomplete, nowMs)
		h.resetJoinRound(hctx, joinPath, join)
		return
	}

	contData := joinDispatchData(join)
	_, dispatchErr := h.executeDispatch(ctx, hctx, contData, cbor.RawMessage(receivedRaw), dispatchChainID(hctx))
	if dispatchErr != nil {
		debugLog("join %s: fire-partial dispatch failed: %v", joinPath, dispatchErr)
	}
	h.advanceJoinLifecycle(hctx, joinPath, join)
	debugLog("join %s: round fired PARTIAL at deadline, missing %v", joinPath, missing)
}

// joinDispatchData projects a join's dispatch fields onto a ContinuationData so
// the join and non-join fire paths share one dispatcher. Kept in one place
// because a field added to the join but forgotten here fires with a silently
// different spec than the join was installed with.
func joinDispatchData(join types.ContinuationJoinData) types.ContinuationData {
	return types.ContinuationData{
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
}

// advanceJoinLifecycle runs the post-fire lifecycle: decrement a counted join's
// remaining_executions (deleting it at zero) or reset a standing one. Extracted
// from advanceJoinSlot so a deadline-driven fire and a slot-driven fire age the
// join identically — a fire-partial that skipped the decrement would let a
// counted join fire more times than it was installed for.
func (h *Handler) advanceJoinLifecycle(hctx *handler.HandlerContext, joinPath string, join types.ContinuationJoinData) {
	if join.RemainingExecutions != nil {
		if remaining := h.handleRemainingExecutions(hctx, joinPath, join.RemainingExecutions); remaining > 0 {
			h.resetJoinRound(hctx, joinPath, join)
		}
		return
	}
	h.resetJoinRound(hctx, joinPath, join)
}

// resetJoinRound clears the round and rebinds the join, ready for the next one.
func (h *Handler) resetJoinRound(hctx *handler.HandlerContext, joinPath string, join types.ContinuationJoinData) {
	clearJoinRound(&join)
	updatedEntity, err := join.ToEntity()
	if err != nil {
		debugLog("join %s: reset build entity failed: %v", joinPath, err)
		return
	}
	updatedHash, err := hctx.Store.Put(updatedEntity)
	if err != nil {
		debugLog("join %s: reset store failed: %v", joinPath, err)
		return
	}
	if _, err := hctx.TreeSet(joinPath, updatedHash, "advance"); err != nil {
		// Surfaced rather than swallowed: a failed reset leaves the join
		// holding a stale round, which is the wedge this whole file exists to
		// prevent, so an operator needs to see it.
		debugLog("join %s: reset bind FAILED: %v — round not cleared, join may wedge", joinPath, err)
	}
}

// bindJoinIncompleteMarker records a failed round as a §3.10 `lost` marker
// NAMING the slots it failed on — §4's actual requirement, and the whole
// diagnostic content of the observation.
//
// Reuses the ordinary marker path and body: a failed join round is a chain
// failure like any other, and giving it its own sink would mean every consumer
// that already walks the lost tree misses it. The reason segment distinguishes
// the two mechanisms (join_incomplete = slots never arrived; join_error_slot =
// slots arrived carrying errors), and the slots ride in the body.
//
// Status is 0 because no downstream response produced this — a round that
// expired, or one that completed with an error slot, are engine-internal
// observations (Appendix A class), not a wire verdict. TargetURI is the join's
// dispatch target, which is what a reader wants to know did NOT receive a clean
// round.
func (h *Handler) bindJoinIncompleteMarker(hctx *handler.HandlerContext, joinPath string, join types.ContinuationJoinData, slots []string, reason string, nowMs uint64) {
	h.bindLostErrorMarkerForJoin(hctx, dispatchChainID(hctx), join.Target, 0, nil, reason, nowMs, hash.Hash{}, joinPath, slots)
}

// --- the sweep (§4: "reaped by the existing CollectExpired* sweep extended to
// joins — not a new subsystem") ---

// noteJoinPath registers a join path as sweepable. Called wherever a join is
// installed or advanced, so the index fills from ordinary traffic.
//
// Handler-side rather than a tree index: joins install at arbitrary
// resource-target paths, so the alternative is a full location-index walk per
// sweep, which is a real cost on a large tree to find a handful of joins. The
// tradeoff is stated in maybeSweepJoins.
func (h *Handler) noteJoinPath(joinPath string, join types.ContinuationJoinData) {
	if join.CompletionDeadlineMs == nil {
		return // wait-forever joins are never reapable; don't track them
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.joinPaths == nil {
		h.joinPaths = make(map[string]struct{})
	}
	h.joinPaths[joinPath] = struct{}{}
}

// maybeSweepJoins runs a throttled pass over the tracked deadline-carrying
// joins, reaping any whose round has expired.
//
// Bind-time and throttled, matching maybeCollectMarkers: nothing in ext owns a
// goroutine, and adding a reaper loop would introduce a lifecycle (start, stop,
// leak-on-drop) to enforce a deadline that only matters when the peer is doing
// something anyway.
//
// Two consequences, stated rather than discovered later:
//
//  1. An expired round is reaped at the next continuation operation, not at the
//     instant of the deadline. The deadline is therefore an eligibility
//     threshold, like the marker retention window — a round is never reaped
//     EARLY, which is the direction that would matter.
//  2. The index is handler memory, so a peer restart forgets joins installed
//     before it. Those are still correct: advanceJoinSlot checks the deadline
//     on touch, so the first slot of the next round reaps the stale one before
//     accumulating. Restart delays the marker; it does not lose the self-heal.
func (h *Handler) maybeSweepJoins(ctx context.Context, hctx *handler.HandlerContext) {
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return
	}
	now := time.Now()
	h.mu.Lock()
	if !h.lastJoinSweep.IsZero() && now.Sub(h.lastJoinSweep) < joinSweepThrottle {
		h.mu.Unlock()
		return
	}
	h.lastJoinSweep = now
	paths := make([]string, 0, len(h.joinPaths))
	for p := range h.joinPaths {
		paths = append(paths, p)
	}
	h.mu.Unlock()

	nowMs := uint64(now.UnixMilli())
	for _, joinPath := range paths {
		h.sweepOneJoin(ctx, hctx, joinPath, nowMs)
	}
}

// sweepOneJoin reaps a single tracked join under its lock, dropping it from the
// index if it is no longer a deadline-carrying join at that path.
func (h *Handler) sweepOneJoin(ctx context.Context, hctx *handler.HandlerContext, joinPath string, nowMs uint64) {
	jmu := h.getJoinLock(joinPath)
	jmu.Lock()
	defer jmu.Unlock()

	joinEnt, joinType := readEntity(hctx, joinPath)
	if joinType != types.TypeContinuationJoin {
		h.forgetJoinPath(joinPath) // exhausted, abandoned, or replaced
		return
	}
	join, err := types.ContinuationJoinDataFromEntity(joinEnt)
	if err != nil {
		return // undecodable: leave it alone rather than act on a guess
	}
	if join.CompletionDeadlineMs == nil {
		h.forgetJoinPath(joinPath)
		return
	}
	h.reapExpiredJoinRound(ctx, hctx, joinPath, join, nowMs)
}

func (h *Handler) forgetJoinPath(joinPath string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.joinPaths, joinPath)
}
