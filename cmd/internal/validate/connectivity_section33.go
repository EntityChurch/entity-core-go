package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// catSection33Ref cites the two §3.3 status-code rows this probe gates, and the
// §9.1 conformance rows landed at 0.8.2.7 that give them a wire citation.
const catSection33Ref = "V7 §3.3 / §9.1 (0.8.2.7)"

// totalHandlerSkipMarker is the stable phrase the §3.3 404-row check stamps on a
// SKIP taken because the peer registers a catch-all handler (the total-handler
// exception, ENTITY-CORE-PROTOCOL §3.3 0.8.2.8). isTotalHandlerSkip keys the
// gate exemption on it: such a peer is conformant, so the spec forbids scoring
// the SKIP as a failure. Keep it distinctive so it can never match the OTHER
// skip this check emits (the unattributable control-404 case), which stays
// scored — that one is a genuine "cannot tell" and is not a conformant posture.
const totalHandlerSkipMarker = "§3.3 total-handler declared SKIP (0.8.2.8)"

// runSection33CodeProbe gates the two ORACLE-DRIVABLE rows of the §3.3 status-code
// table, generalized from the retired-synonym incident to the whole code slot
// (ENTITY-CORE-PROTOCOL §3.3 slot rule + §9.1, 0.8.2.7):
//
//   - 501 row: an operation absent from a REGISTERED handler's manifest MUST
//     answer 501 `unsupported_operation`. The slot carries no synonym for THIS
//     row — `unknown_operation`, `not_implemented`, `not_supported` and
//     `not_available` are all non-conformant spellings of it. (`unsupported_mode`
//     is NOT a synonym: it is a distinct, defined 501 code for the registry
//     live-registration row, REGISTRY §6a.9.2, un-retired at 0.8.2.8. This
//     probe targets `system/tree` — not a registry path — so `unsupported_mode`
//     is still a wrong answer HERE, but as a mis-routed distinct code, not a
//     retired synonym.)
//   - 404 row: a path on the local peer with NO registered handler MUST answer
//     404 `handler_not_found` — distinct from the 501 (handler present, op absent)
//     and from an entity-level `not_found` raised INSIDE a registered handler.
//
// The 500 row is deliberately NOT gated: it is not drivable by a conformance
// client (a peer cannot be made to fail internally on demand over the wire), so
// §3.3 (0.8.2.7) marks it satisfied by source audit, not a validate-peer check.
// A check for it would be one that can never fail — the anti-pattern this repo
// calls a control that can't discriminate.
//
// Teeth (carry-the-teeth): the two rows cross-discriminate, so neither is a
// false pass. The 501 check's positive control is a KNOWN op on the same
// registered path returning non-501 — proof the handler is reached, so the 501
// is attributable to the OP name, not an absent handler. The 404 check's control
// sends the same unknown op to the registered path and requires it NOT be 404 —
// proof the peer distinguishes no-handler from op-missing; a peer that answered
// 404 for both would otherwise false-pass. Either control failing degrades the
// check to SKIP (unattributable), never a silent PASS.
func runSection33CodeProbe(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catConnectivity)
	r.Declare("unsupported_operation_on_registered_handler", catSection33Ref)
	r.Declare("handler_not_found_on_unregistered_path", catSection33Ref)

	if !client.Connected() {
		skip := func() CheckOutcome {
			return SkipCheck("client not connected/handshaked — cannot send authenticated EXECUTE")
		}
		r.Run("unsupported_operation_on_registered_handler", skip)
		r.Run("handler_not_found_on_unregistered_path", skip)
		return r.Results()
	}

	// An operation no handler implements. Distinctive so a log trace maps back.
	const bogusOp = "conformance-probe-no-such-op-3f9a"
	registeredURI := fmt.Sprintf("entity://%s/system/tree", client.remotePeerID)

	dispatch := func(uri, op string, params entity.Entity, resource *types.ResourceTarget) (uint, string, error) {
		env, _, err := client.SendExecute(ctx, uri, op, params, resource)
		if err != nil {
			return 0, "", err
		}
		status, code, _, derr := extractStatusAndCode(env)
		return status, code, derr
	}

	r.Run("unsupported_operation_on_registered_handler", func() CheckOutcome {
		params, resource, err := tree.CreateGetRequest("system/tree", "entity")
		if err != nil {
			return FailCheck("build tree:get params: " + err.Error())
		}
		// Positive control: a KNOWN op on the registered handler must be reached
		// (non-501), so a 501 for the bogus op is attributable to the op name and
		// not to an absent/unreachable handler.
		ctlStatus, ctlCode, err := dispatch(registeredURI, "get", params, resource)
		if err != nil {
			return FailCheck("control get send/recv: " + err.Error())
		}
		if ctlStatus == 501 {
			return SkipCheck(fmt.Sprintf("control: system/tree:get itself answered 501/%q — cannot attribute the probe's 501 to the op", ctlCode))
		}
		status, code, err := dispatch(registeredURI, bogusOp, params, resource)
		if err != nil {
			return FailCheck("probe send/recv: " + err.Error())
		}
		if status != 501 || code != "unsupported_operation" {
			return FailCheck(fmt.Sprintf(
				"registered handler + unknown op answered %d/%q, want 501/unsupported_operation "+
					"(§3.3 501 slot; unknown_operation/not_implemented/not_supported/not_available retired 0.8.2.7; "+
					"unsupported_mode is a distinct registry code per §6a.9.2, wrong on this system/tree path); "+
					"control system/tree:get=%d/%q", status, code, ctlStatus, ctlCode))
		}
		return PassCheck(fmt.Sprintf("unknown op on registered handler → 501/unsupported_operation (control get=%d/%q)", ctlStatus, ctlCode))
	})

	r.Run("handler_not_found_on_unregistered_path", func() CheckOutcome {
		const noHandlerPath = "system/no-such-handler-conformance-3f9a"
		noHandlerURI := fmt.Sprintf("entity://%s/%s", client.remotePeerID, noHandlerPath)
		status, code, err := dispatch(noHandlerURI, bogusOp, entity.Entity{}, &types.ResourceTarget{Targets: []string{noHandlerPath}})
		if err != nil {
			return FailCheck("probe send/recv: " + err.Error())
		}
		// Discrimination control: the SAME unknown op on a REGISTERED path.
		params, treeResource, cerr := tree.CreateGetRequest("system/tree", "entity")
		if cerr != nil {
			return FailCheck("build control params: " + cerr.Error())
		}
		ctlStatus, ctlCode, err := dispatch(registeredURI, bogusOp, params, treeResource)
		if err != nil {
			return FailCheck("control send/recv: " + err.Error())
		}
		return classifyHandlerNotFound(status, code, ctlStatus, ctlCode)
	})

	return r.Results()
}

// classifyHandlerNotFound maps the §3.3 404-row probe to an outcome. Pure so the
// SKIP/FAIL/PASS decision carries deterministic teeth (go-on-go never reaches the
// catch-all SKIP branch — go registers no `*` — so the wire run alone cannot
// regression-guard it).
//
//   - probe 501: a handler IS registered at the "no-handler" path — the peer uses
//     a catch-all (`*`), so no unregistered path exists. §3.3 satisfaction-mode
//     (0.8.2.7) is explicit that "a check MUST NOT be pinned to a row it cannot
//     reach", so the 404 row is not drivable against this posture → SKIP, never
//     FAIL. (core-py registers `*` by default — cf SA-PY-36. The 501-slot
//     correctness of that answer is gated by the sibling check above.)
//   - control 404: the registered path ALSO 404s an unknown op, so the peer does
//     not distinguish no-handler from op-missing — unattributable → SKIP.
//   - probe 404/handler_not_found with a discriminating control → PASS.
//   - anything else → FAIL.
func classifyHandlerNotFound(probeStatus uint, probeCode string, ctlStatus uint, ctlCode string) CheckOutcome {
	if probeStatus == 501 {
		// §3.3 total-handler exception (0.8.2.8): at a peer that registers a
		// catch-all pattern no unregistered path exists, so this row's input is
		// unconstructible and the probe reaches the catch-all instead. Such a
		// peer is CONFORMANT; the check MUST record a declared SKIP naming the
		// catch-all and MUST NOT report the fallback's answer as a failure of
		// this row. isTotalHandlerSkip keys on totalHandlerSkipMarker below so
		// the gate exempts it — without that, a spec-mandated declared SKIP
		// still fails the run (the exact blocker core-py hit on the python
		// passes, cf SA-PY-36).
		return SkipCheck(fmt.Sprintf(
			"%s: probe path answered 501/%q — a handler is registered here (peer uses a catch-all `*`); the 404 handler_not_found row is not drivable against this posture (§3.3 satisfaction-mode, total-handler exception, 0.8.2.8; cf SA-PY-36)",
			totalHandlerSkipMarker, probeCode))
	}
	if ctlStatus == 404 {
		return SkipCheck(fmt.Sprintf("control: registered path also answered 404/%q for an unknown op — peer does not distinguish no-handler from op-missing, cannot attribute", ctlCode))
	}
	if probeStatus != 404 || probeCode != "handler_not_found" {
		return FailCheck(fmt.Sprintf(
			"unregistered local path answered %d/%q, want 404/handler_not_found (§3.3 404 row 0.8.2.7); "+
				"registered-path control=%d/%q", probeStatus, probeCode, ctlStatus, ctlCode))
	}
	return PassCheck(fmt.Sprintf("no handler at local path → 404/handler_not_found (registered-path control=%d/%q discriminates)", ctlStatus, ctlCode))
}
