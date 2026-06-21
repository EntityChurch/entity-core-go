package validate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// durApplied safely extracts the applied level for error messages.
func durApplied(d *types.DurabilityResultData) string {
	if d == nil {
		return "<nil>"
	}
	return d.Applied
}

const catDurability = "durability"

// runDurability validates the EXTENSION-DURABILITY v0.1 reference design
// (EXPLORATORY · OPTIONAL · NOT ACTIVELY DEVELOPED — extracted from
// EXTENSION-DURABILITY per the retraction of
// PROPOSAL-DELIVERY-AND-DURABILITY). Absence of the extension is conformant;
// this category validates behavior for peers that DO implement the surface.
// Tiering follows the EXTENSION-CONTINUATION §8 pattern: MUST checks fail;
// SHOULD/MAY checks warn.
//
// The probe targets `system/tree` get on a bootstrap type entity that exists
// on every conformant peer. Durability is reconciled at acceptance BEFORE
// the handler runs (EXTENSION-DURABILITY §5 invariant), so the handler choice
// is immaterial — it only has to pass dispatch authorization so the request
// reaches the durability decision point.
func runDurability(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catDurability)

	// MUST — EXTENSION-DURABILITY §8 / EXTENSION-INBOX §5 / §8.
	r.Declare("no_silent_discard", "EXTENSION-DURABILITY §5 / §8")
	r.Declare("requested_echoed", "EXTENSION-DURABILITY §5")
	r.Declare("applied_is_concrete_level", "EXTENSION-DURABILITY §5 (applied invariant)")
	r.Declare("committed_only_on_202", "EXTENSION-DURABILITY §8 (invariant)")
	r.Declare("max_available_only_on_412", "EXTENSION-DURABILITY §8 (invariant)")
	r.Declare("must_have_unmet_refused_412", "EXTENSION-DURABILITY §5 / §8")
	r.Declare("refusal_not_performed", "EXTENSION-DURABILITY §5 (412 = not performed)")
	r.Declare("refusal_max_available_present", "EXTENSION-DURABILITY §5")
	r.Declare("best_effort_not_refused", "EXTENSION-DURABILITY §5 (rows 2/3)")
	r.Declare("must_have_stored_observable", "EXTENSION-DURABILITY §5 (row 1/4)")
	// MUST — deliver_to + durability rides the 202 ack with the durability
	// field attached (§5 / §7.1 — 202 meaning reused, not a new sense).
	r.Declare("deliver_to_durability_attached", "EXTENSION-DURABILITY §5 (202 ack + durability)")
	r.Declare("deliver_to_durability_applied_concrete", "EXTENSION-DURABILITY §5 (applied invariant)")
	// MUST — EXTENSION-DURABILITY additions.
	r.Declare("handle_present_when_applied", "EXTENSION-DURABILITY §5 / §6 / §8")
	r.Declare("duplicate_request_id_returns_409", "EXTENSION-DURABILITY §5 / §8")
	r.Declare("unknown_level_not_must_have_returns_none", "EXTENSION-DURABILITY §5 / §8")
	// SHOULD / §6.
	r.Declare("advertisement_present", "EXTENSION-DURABILITY §3 (MAY)")
	r.Declare("durable_entry_preserved", "EXTENSION-DURABILITY §6")

	uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())
	const probePath = "system/type/system/hash" // bootstrap type, always present

	// sendDur sends an EXECUTE carrying durability_request{level,mustHave} to a
	// benign tree get. Returns the decoded EXECUTE_RESPONSE and the request id.
	sendDur := func(level string, mustHave bool) (types.ExecuteResponseData, string, error) {
		params, resource, err := tree.CreateGetRequest(probePath, "entity")
		if err != nil {
			return types.ExecuteResponseData{}, "", err
		}
		dr := &types.DurabilityRequestData{Level: level, MustHave: mustHave}
		env, reqID, _, err := client.SendExecuteWithDurability(ctx, uri, "get", params, resource, dr)
		if err != nil {
			return types.ExecuteResponseData{}, reqID, err
		}
		resp, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return types.ExecuteResponseData{}, reqID, fmt.Errorf("decode response: %w", err)
		}
		return resp, reqID, nil
	}

	// authBlocked reports whether a response is an auth refusal unrelated to
	// durability (narrow validation grants) — those Skip, not Fail.
	authBlocked := func(s uint) bool { return s == 401 || s == 403 }

	// --- Probe 1: best-effort "stored", no deliver_to (matrix Scenario 4). ---
	resp1, reqID1, err1 := sendDur(types.DurabilityStored, false)

	r.Run("no_silent_discard", func() CheckOutcome {
		if err1 != nil {
			return FailCheck("durability request failed: " + err1.Error())
		}
		if authBlocked(resp1.Status) {
			return SkipCheck(fmt.Sprintf("validation grants do not authorize the probe (status %d)", resp1.Status))
		}
		if resp1.Durability == nil {
			return FailCheck(fmt.Sprintf(
				"durability_request was NOT answered with a durability field (status %d) — silent discard is non-conformant (EXTENSION-DURABILITY §8)",
				resp1.Status))
		}
		return PassCheck(fmt.Sprintf("durability_request answered observably: status=%d durability=%+v",
			resp1.Status, *resp1.Durability))
	})

	r.Run("requested_echoed", func() CheckOutcome {
		if out, ok := r.Require("no_silent_discard"); !ok {
			return out
		}
		if resp1.Durability.Requested != types.DurabilityStored {
			return FailCheck(fmt.Sprintf("durability.requested = %q, expected %q",
				resp1.Durability.Requested, types.DurabilityStored))
		}
		return PassCheck("durability.requested echoes the asked level")
	})

	r.Run("applied_is_concrete_level", func() CheckOutcome {
		if out, ok := r.Require("no_silent_discard"); !ok {
			return out
		}
		// applied MUST be a level physically in place now — never empty, and
		// for a best-effort request never a not-yet-achieved promise. The
		// honest outcomes for "stored" best-effort are "stored" or "none".
		switch resp1.Durability.Applied {
		case types.DurabilityStored:
			return PassCheck("applied = stored (physically preserved)")
		case types.DurabilityNone:
			if resp1.Durability.Reason != types.ReasonNoDurableStore {
				return WarnCheck("applied = none without reason no_durable_store (reason spelling is impl-pinned, §7)")
			}
			return PassCheck("applied = none, reason no_durable_store (honest: no durable store)")
		case "":
			return FailCheck("durability.applied is empty — it MUST name a concrete level (or 'none'), never blank (§5)")
		default:
			return PassCheck("applied = " + resp1.Durability.Applied + " (concrete level)")
		}
	})

	// --- Probe 2: must_have replicated — not self-certifiable at acceptance;
	// a peer not configured for the replication topology MUST refuse (412),
	// operation NOT performed (matrix Scenario 6 required path). ---
	resp2, _, err2 := sendDur(types.DurabilityReplicated, true)

	r.Run("must_have_unmet_refused_412", func() CheckOutcome {
		if err2 != nil {
			return FailCheck("must_have durability request failed: " + err2.Error())
		}
		if authBlocked(resp2.Status) {
			return SkipCheck(fmt.Sprintf("validation grants do not authorize the probe (status %d)", resp2.Status))
		}
		// 202 is conformant ONLY if the peer is genuinely configured for the
		// replication topology (then committed names it). Otherwise the
		// must_have precondition is unmet and MUST be 412.
		if resp2.Status == 202 {
			if resp2.Durability != nil && resp2.Durability.Committed == types.DurabilityReplicated {
				return PassCheck("202: peer is configured for replication; committed=replicated (observable at request-id address)")
			}
			return FailCheck("status 202 without committed=replicated — a must_have replication ack MUST carry the committed target (§5 row 5)")
		}
		if resp2.Status != 412 {
			return FailCheck(fmt.Sprintf(
				"must_have replicated, peer not replication-configured: expected 412 (refused, not performed), got %d (§5 / §8)",
				resp2.Status))
		}
		if resp2.Durability == nil {
			return FailCheck("412 refusal MUST still carry the durability field (§5)")
		}
		if resp2.Durability.Reason != types.ReasonRequiredUnmet {
			return WarnCheck(fmt.Sprintf("412 reason = %q, expected %q (reason spelling is impl-pinned, §7)",
				resp2.Durability.Reason, types.ReasonRequiredUnmet))
		}
		return PassCheck("must_have unmet refused with 412, reason durability_required_unmet")
	})

	r.Run("refusal_not_performed", func() CheckOutcome {
		if out, ok := r.Require("must_have_unmet_refused_412"); !ok {
			return out
		}
		if resp2.Status != 412 {
			return SkipCheck("peer is replication-configured (202 path) — not-performed assertion applies to the 412 path")
		}
		// 412 = refused at acceptance: the operation did NOT run, so the
		// result is an error entity, not the tree get's result entity.
		var resultEnt entity.Entity
		if err := ecf.Decode(resp2.Result, &resultEnt); err != nil {
			return FailCheck("412 result undecodable: " + err.Error())
		}
		if resultEnt.Type != types.TypeError {
			return FailCheck(fmt.Sprintf(
				"412 result type = %q, expected %q — a refusal MUST NOT carry the operation's result (no run-then-fail, §5)",
				resultEnt.Type, types.TypeError))
		}
		return PassCheck("operation not performed: 412 carries an error result, not the handler's output")
	})

	r.Run("refusal_max_available_present", func() CheckOutcome {
		if out, ok := r.Require("must_have_unmet_refused_412"); !ok {
			return out
		}
		if resp2.Status != 412 {
			return SkipCheck("202 path — max_available applies to 412")
		}
		if resp2.Durability.MaxAvailable == "" {
			return FailCheck("412 durability MUST carry max_available (the best the receiver could offer, §5)")
		}
		return PassCheck("412 carries max_available = " + resp2.Durability.MaxAvailable)
	})

	// --- Probe 3: best-effort replicated (not must_have) — NOT a refusal;
	// the peer takes the strongest it can, observably (§5 rows 2/3). ---
	resp3, _, err3 := sendDur(types.DurabilityReplicated, false)

	r.Run("best_effort_not_refused", func() CheckOutcome {
		if err3 != nil {
			return FailCheck("best-effort replicated request failed: " + err3.Error())
		}
		if authBlocked(resp3.Status) {
			return SkipCheck(fmt.Sprintf("validation grants do not authorize the probe (status %d)", resp3.Status))
		}
		if resp3.Status == 412 {
			return FailCheck("best-effort (must_have=false) MUST NOT be refused with 412 — that is the must_have-only outcome (§5)")
		}
		if resp3.Durability == nil {
			return FailCheck("best-effort durability request answered without a durability field (silent discard, §5)")
		}
		if resp3.Durability.Applied == "" {
			return FailCheck("best-effort applied is empty — MUST name a concrete level (§5)")
		}
		return PassCheck(fmt.Sprintf("best-effort honored observably: status=%d applied=%s",
			resp3.Status, resp3.Durability.Applied))
	})

	// --- Probe 4: must_have stored — row 1 (met → 200) or row 4 (no store →
	// 412). Both are conformant; neither is silent and neither overclaims. ---
	resp4, _, err4 := sendDur(types.DurabilityStored, true)

	r.Run("must_have_stored_observable", func() CheckOutcome {
		if err4 != nil {
			return FailCheck("must_have stored request failed: " + err4.Error())
		}
		if authBlocked(resp4.Status) {
			return SkipCheck(fmt.Sprintf("validation grants do not authorize the probe (status %d)", resp4.Status))
		}
		if resp4.Durability == nil {
			return FailCheck("must_have stored answered without a durability field (silent discard, §5)")
		}
		switch resp4.Status {
		case 412:
			if resp4.Durability.Reason != types.ReasonRequiredUnmet {
				return WarnCheck("412 without reason durability_required_unmet (reason spelling impl-pinned, §7)")
			}
			return PassCheck("no durable store: must_have stored refused 412 (conformant — row 4)")
		case 202:
			if resp4.Durability.Committed == "" {
				return FailCheck("202 without committed — a 202 verdict MUST name the async-completing strength (§5)")
			}
			return PassCheck("202: stored completes asynchronously, committed=" + resp4.Durability.Committed)
		default:
			if resp4.Durability.Applied != types.DurabilityStored {
				return FailCheck(fmt.Sprintf(
					"must_have stored not refused but applied=%q (expected stored — applied MUST be the level physically in place, §5)",
					resp4.Durability.Applied))
			}
			return PassCheck("must_have stored met: status 200, applied=stored")
		}
	})

	// --- Probe 5: deliver_to + durability (matrix Scenarios 5/7). The 202
	// async-ack MUST carry the durability field — the verdict is independent
	// of the delivery acknowledgement, and silently dropping it on this code
	// path is the same EXTENSION-DURABILITY §8 violation as silent-discard on the sync path. ---
	deliverURI := fmt.Sprintf("entity://%s/system/inbox/validate-durability", client.RemotePeerID())
	tokenEnt, tokenSig, tokErr := client.CreateDeliveryToken(deliverURI, "receive")

	var resp5 types.ExecuteResponseData
	var resp5Err error
	if tokErr == nil {
		params, resource, perr := tree.CreateGetRequest(probePath, "entity")
		if perr == nil {
			deliverSpec := &types.DeliverySpec{URI: deliverURI, Operation: "receive"}
			dr := &types.DurabilityRequestData{Level: types.DurabilityStored, MustHave: false}
			env, _, _, serr := client.SendExecuteAsyncWithDurability(ctx, uri, "get", params, resource, dr, deliverSpec, tokenEnt, tokenSig)
			if serr != nil {
				resp5Err = serr
			} else if d, derr := types.ExecuteResponseDataFromEntity(env.Root); derr != nil {
				resp5Err = fmt.Errorf("decode response: %w", derr)
			} else {
				resp5 = d
			}
		} else {
			resp5Err = perr
		}
	} else {
		resp5Err = tokErr
	}

	r.Run("deliver_to_durability_attached", func() CheckOutcome {
		if resp5Err != nil {
			return FailCheck("deliver_to+durability probe failed: " + resp5Err.Error())
		}
		if authBlocked(resp5.Status) {
			return SkipCheck(fmt.Sprintf("validation grants do not authorize the probe (status %d)", resp5.Status))
		}
		// Expected: 202 ack (deliver_to triggers async ack). Some impls may
		// instead 412 if they treat must_have semantics differently, but we
		// sent must_have=false so 412 here is non-conformant.
		if resp5.Status == 412 {
			return FailCheck("412 on best-effort deliver_to+durability — must_have=false MUST NOT refuse (§5)")
		}
		if resp5.Status != 202 {
			return WarnCheck(fmt.Sprintf("expected 202 ack with deliver_to, got %d — durability check still applies", resp5.Status))
		}
		if resp5.Durability == nil {
			return FailCheck("202 ack to deliver_to+durability_request carries NO durability field — EXTENSION-DURABILITY §8 / §5 silent-discard on the async-ack code path")
		}
		return PassCheck("202 deliver_to ack carries durability field: " + fmt.Sprintf("%+v", *resp5.Durability))
	})

	r.Run("deliver_to_durability_applied_concrete", func() CheckOutcome {
		if out, ok := r.Require("deliver_to_durability_attached"); !ok {
			return out
		}
		if resp5.Durability.Requested != types.DurabilityStored {
			return FailCheck(fmt.Sprintf("durability.requested = %q, expected %q (echo invariant, §5)",
				resp5.Durability.Requested, types.DurabilityStored))
		}
		if resp5.Durability.Applied == "" {
			return FailCheck("durability.applied is empty on the 202 ack — MUST name a concrete level (§5 invariant)")
		}
		// On the 202 deliver_to path, committed is only set if the peer is
		// genuinely doing async-completing durability (replication-class).
		// For default policies committed stays empty and that is conformant —
		// only the §8 invariant (committed-only-on-202) matters here.
		return PassCheck(fmt.Sprintf("applied=%s on 202 ack (committed=%q)",
			resp5.Durability.Applied, resp5.Durability.Committed))
	})

	// --- EXTENSION-DURABILITY MUSTs (§9.2.2 / §9.2.4 / §9.2.5). ---

	r.Run("handle_present_when_applied", func() CheckOutcome {
		if out, ok := r.Require("no_silent_discard"); !ok {
			return out
		}
		if resp1.Durability == nil {
			return FailCheck("probe 1 returned no durability field")
		}
		if resp1.Durability.Applied == types.DurabilityNone {
			return SkipCheck("probe 1 applied=none — handle is not required (EXTENSION-DURABILITY §6: 'Present when applied != none')")
		}
		if resp1.Durability.Handle == "" {
			return FailCheck("durability.handle is empty when applied != none — EXTENSION-DURABILITY §6 MUST: receiver MUST return the path where the durable entry can be read")
		}
		return PassCheck("durability.handle present: " + resp1.Durability.Handle)
	})

	r.Run("duplicate_request_id_returns_409", func() CheckOutcome {
		// Send a fresh durable request with a known request_id, then replay
		// the same (author, request_id). Second response MUST be 409.
		params, resource, perr := tree.CreateGetRequest(probePath, "entity")
		if perr != nil {
			return FailCheck("create probe params: " + perr.Error())
		}
		dr := &types.DurabilityRequestData{Level: types.DurabilityStored, MustHave: false}
		// Unique per-run id so prior runs against the same peer don't poison
		// the receiver's idempotency cache.
		fixedReqID := fmt.Sprintf("validate-dup-%d", time.Now().UnixNano())
		env1, _, _, err := client.SendExecuteWithDurabilityID(ctx, fixedReqID, uri, "get", params, resource, dr)
		if err != nil {
			return FailCheck("first durable request failed: " + err.Error())
		}
		resp, err := types.ExecuteResponseDataFromEntity(env1.Root)
		if err != nil {
			return FailCheck("decode first response: " + err.Error())
		}
		if authBlocked(resp.Status) {
			return SkipCheck(fmt.Sprintf("validation grants do not authorize the probe (status %d)", resp.Status))
		}
		if resp.Durability == nil || resp.Durability.Applied != types.DurabilityStored {
			return SkipCheck(fmt.Sprintf(
				"first request did not preserve (applied=%q) — dedup MUST only applies on previously-preserved entries (§9.2.4)",
				durApplied(resp.Durability)))
		}
		// Replay with the same request_id.
		env2, _, _, err := client.SendExecuteWithDurabilityID(ctx, fixedReqID, uri, "get", params, resource, dr)
		if err != nil {
			return FailCheck("duplicate durable request failed: " + err.Error())
		}
		resp2, err := types.ExecuteResponseDataFromEntity(env2.Root)
		if err != nil {
			return FailCheck("decode duplicate response: " + err.Error())
		}
		if resp2.Status != 409 {
			return FailCheck(fmt.Sprintf(
				"duplicate (author, request_id) returned status %d (expected 409) — EXTENSION-DURABILITY §9.2.4 MUST",
				resp2.Status))
		}
		return PassCheck("duplicate (author, request_id) returned 409 (§9.2.4)")
	})

	r.Run("unknown_level_not_must_have_returns_none", func() CheckOutcome {
		// Unknown level + not must_have → applied:none + reason:unknown_level.
		// Don't promise what you don't understand (§9.2.5).
		respU, _, errU := sendDur("quantum-entanglement", false)
		if errU != nil {
			return FailCheck("unknown-level request failed: " + errU.Error())
		}
		if authBlocked(respU.Status) {
			return SkipCheck(fmt.Sprintf("validation grants do not authorize the probe (status %d)", respU.Status))
		}
		if respU.Status == 412 {
			return FailCheck("unknown level + not-must-have returned 412 — EXTENSION-DURABILITY §5 / §8: 412 is only for must_have, not best-effort")
		}
		if respU.Durability == nil {
			return FailCheck("unknown-level response without durability field — silent discard (§5)")
		}
		if respU.Durability.Applied != types.DurabilityNone {
			return FailCheck(fmt.Sprintf(
				"unknown level + not-must-have returned applied=%q (expected 'none' — §9.2.5: don't promise what you don't understand)",
				respU.Durability.Applied))
		}
		if respU.Durability.Reason != types.ReasonUnknownLevel {
			return WarnCheck(fmt.Sprintf(
				"unknown level applied=none but reason=%q (EXTENSION-DURABILITY §5 / §8 names 'unknown_level' as canonical spelling)",
				respU.Durability.Reason))
		}
		return PassCheck("unknown level + not-must-have: applied=none, reason=unknown_level (§9.2.5)")
	})

	// --- Cross-cutting invariants over every collected verdict (§8). ---
	collected := []struct {
		status uint
		dur    *types.DurabilityResultData
	}{
		{resp1.Status, resp1.Durability},
		{resp2.Status, resp2.Durability},
		{resp3.Status, resp3.Durability},
		{resp4.Status, resp4.Durability},
		{resp5.Status, resp5.Durability},
	}

	r.Run("committed_only_on_202", func() CheckOutcome {
		for _, c := range collected {
			if c.dur != nil && c.dur.Committed != "" && c.status != 202 {
				return FailCheck(fmt.Sprintf(
					"committed=%q present with status %d — committed MUST appear ONLY with 202 (§8)",
					c.dur.Committed, c.status))
			}
		}
		return PassCheck("committed appears only with status 202 across all verdicts")
	})

	r.Run("max_available_only_on_412", func() CheckOutcome {
		for _, c := range collected {
			if c.dur != nil && c.dur.MaxAvailable != "" && c.status != 412 {
				return FailCheck(fmt.Sprintf(
					"max_available=%q present with status %d — max_available MUST appear ONLY with 412 (§8)",
					c.dur.MaxAvailable, c.status))
			}
		}
		return PassCheck("max_available appears only with status 412 across all verdicts")
	})

	// --- §3 advertise supported durability (SHOULD → warn if absent).
	// The spec does NOT pin a path or shape for the advertisement; it only
	// says "A receiver SHOULD expose the durability levels it supports
	// (discovery)" and "Absence ... does not change the response contract."
	// This check tries Go's convention (`system/durability` carrying a
	// `system/durability-advertisement` entity) plus a few plausible
	// alternate paths, then on miss WARNs with a clear "path is a Go
	// convention, not spec-pinned" message. ---
	r.Run("advertisement_present", func() CheckOutcome {
		candidates := []string{
			types.DurabilityAdvertisementPath, // "system/durability" — Go convention
			"system/inbox/durability",         // inbox extension might own it
			"system/peer/durability",          // peer-state subtree
		}
		var triedAt string
		for _, p := range candidates {
			ent, _, gerr := client.TreeGet(ctx, p)
			if gerr != nil {
				triedAt = p
				continue
			}
			if ad, derr := types.DurabilityAdvertisementDataFromEntity(ent); derr == nil && len(ad.Levels) > 0 {
				return PassCheck(fmt.Sprintf(
					"advertises durability levels %v (max_self_determinable=%s) at %s",
					ad.Levels, ad.MaxSelfDeterminable, p))
			}
			// Entity present but unreadable as DurabilityAdvertisementData —
			// could be a different advertisement shape; informational.
			return WarnCheck(fmt.Sprintf(
				"entity present at %s but not decodable as system/durability-advertisement — advertisement shape is NOT spec-pinned (§3), peer may use a different convention",
				p))
		}
		return WarnCheck(fmt.Sprintf(
			"no durability advertisement at any of %v — §3 is SHOULD-tier and the path/shape is NOT spec-pinned; absence does not change the response contract (last tried: %s)",
			candidates, triedAt))
	})

	// --- §6 find it again — now via the `handle` returned in the response
	// (EXTENSION-DURABILITY §6). The receiver chooses the storage layout; the
	// sender reads the handle as any tree path. Falls back to Go's convention
	// path + listing scan for impls that haven't shipped EXTENSION-DURABILITY yet. ---
	r.Run("durable_entry_preserved", func() CheckOutcome {
		if out, ok := r.Require("no_silent_discard"); !ok {
			return out
		}
		if resp1.Durability == nil || resp1.Durability.Applied != types.DurabilityStored {
			return SkipCheck("probe 1 did not achieve 'stored' durability — nothing to look up")
		}
		// EXTENSION-DURABILITY §6 — follow the handle returned in the response.
		// The receiver chose the storage path; we don't guess.
		if h := resp1.Durability.Handle; h != "" {
			if ent, _, gerr := client.TreeGet(ctx, h); gerr == nil {
				if ent.Type == "" {
					return FailCheck(fmt.Sprintf(
						"preserved entry at handle %s has empty type — `applied: stored` means a real entity is physically in place (§5 invariant)",
						h))
				}
				if err := ent.Validate(); err != nil {
					return FailCheck(fmt.Sprintf(
						"preserved entry at handle %s does not validate: %v",
						h, err))
				}
				return PassCheck(fmt.Sprintf(
					"durable request preserved at handle %s (EXTENSION-DURABILITY §6); type=%s, content_hash validates",
					h, ent.Type))
			}
			return WarnCheck(fmt.Sprintf(
				"handle %s returned by receiver but TreeGet failed — `applied: stored` unverifiable",
				h))
		}
		// Pre-Amendment-1 fallback: try the Go convention path + listing scan.
		if ent, _, gerr := client.TreeGet(ctx, "system/inbox/"+reqID1); gerr == nil {
			if ent.Type == "" {
				return FailCheck(fmt.Sprintf(
					"preserved entry at system/inbox/%s has empty type — `applied: stored` means a real entity is physically in place (§5 invariant)",
					reqID1))
			}
			if err := ent.Validate(); err != nil {
				return FailCheck(fmt.Sprintf(
					"preserved entry at system/inbox/%s does not validate (content_hash != hash({type, data})): %v — `applied: stored` MUST be honest (§5)",
					reqID1, err))
			}
			return PassCheck(fmt.Sprintf(
				"durable request findable at system/inbox/%s (Go convention), type=%s, content_hash validates",
				reqID1, ent.Type))
		}
		// Fallback: list under system/inbox/ and look for ANY entry whose
		// key contains the request_id — catches impls that store at a
		// different sub-path encoding under the inbox namespace.
		entries, _, lerr := client.TreeListing(ctx, "system/inbox/")
		if lerr != nil {
			return WarnCheck(fmt.Sprintf(
				"durable entry not found at system/inbox/%s and listing under system/inbox/ failed (%v); the §6 lookup mechanism is NOT spec-pinned to a sub-path so this is not necessarily a defect — but `applied: stored` is unverifiable from outside",
				reqID1, lerr))
		}
		for key := range entries {
			if strings.Contains(key, reqID1) {
				return PassCheck(fmt.Sprintf(
					"durable request findable under system/inbox/ at key %q (alternate sub-path encoding from Go convention) — conformant per §6 (path not spec-pinned)",
					key))
			}
		}
		return WarnCheck(fmt.Sprintf(
			"durable request NOT findable under system/inbox/ by either `system/inbox/%s` (Go convention) or substring match in the listing — `applied: stored` is unverifiable from outside, but §6 does not pin the path encoding so this is informational, not a §8 MUST violation",
			reqID1))
	})

	return r.Results()
}
