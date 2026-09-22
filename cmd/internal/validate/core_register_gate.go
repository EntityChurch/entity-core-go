package validate

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §10.1 of PROPOSAL-V7-V7.74-CORE-EXTENSIBILITY-BOUNDARY: the core-tier
// dynamic-register gate. Under `--profile core`, exercise the wire
// register-and-dispatch round-trip and assert the spec-required write
// set actually lands in the tree:
//
//   1. Precondition (impl-private body-binding seam): bind a trivial
//      body for the test pattern. Default seam is entity-native compute
//      (an `expression_path` pointing at a literal-returning expression).
//      Peers with a different body-binding mechanism (compiled, FFI,
//      SDK-bound) plug a different seam here. The proposal pins the
//      *protocol-level* round-trip; the body-binding mechanism stays
//      per-impl per V7 §9.4.
//   2. Wire `EXECUTE system/handler operation:"register"` for the
//      pattern. Assert response status = 200 + result decodes as
//      register-result with the same pattern.
//   3. Assert the spec-required tree state lands:
//        - manifest at system/handler/<pattern> (TypeHandlerInterface)
//        - handler entity at <pattern> (TypeHandler)
//        - grant at system/capability/grants/<pattern>
//        - signature at system/signature/{grant_hash_hex} (v7.74 v0.4
//          §3.4 invariant-pointer convergence)
//   4. Wire dispatch EXECUTE entity://<target>/<pattern> + assert the
//      response round-trips correctly (proves the body is invoked).
//   5. Wire unregister + assert the grant-signature is also removed
//      (writer/unregister symmetry — v0.4 §10.1 unregister-teardown
//      addition per Go cohort review).
//
// What this gate does NOT test: the body-binding mechanism itself
// (impl-private per §9.4). A 501-stubbed register or a peer with no
// body-binding seam fails at step 1 (SKIP) or step 3 (manifest
// assertion FAIL), exactly the keystone-stub case the gate exists to
// surface.

const coreRegisterTestPattern = "app/validate/core-register/echo"
const coreRegisterTestSlot = coreRegisterTestPattern
const coreRegisterTestExprPath = coreRegisterTestPattern + "/expr"

// The §2.4a negative half's patterns. Both are NON-reserved app/* paths: the
// `system/*` reservation the old negative half keyed on was WITHDRAWN at
// 0.8.2.13 (§6.2/§3162 — installation at any path is authorized by the
// dispatch capability check on `resource`; refusing `system/*` is deployment
// policy, not a protocol constraint, §3164), so a `system/*`-refusal check now
// FAILs a conformant peer that permits the registration.
//
// The re-base keeps the valuable conjunct — *a refused register publishes
// nothing* — and moves the refusal mechanism to an ATTRIBUTABLE capability
// denial: a register presenting a child cap that does NOT cover the
// `system/handler` handler is refused `403 capability_denied` on §5.2
// Dimension 2. The §5.5a trap the earlier capability attempt hit (a
// peer-relative child resource canonicalizes granter-local and refuses on the
// RESOURCE dimension, not the handler one) is avoided by giving the child
// `resources: ["/*/*"]` (absolute/universal — it covers the target, so the
// only failing dimension is `handlers`). A positive control — the same
// register under the covering connection cap succeeds — both proves the check
// discriminates and gates the arm on the peer being armed for register.
const coreRegisterCtrlPattern = "app/validate/core-register-positive-control"
const coreRegisterNegPattern = "app/validate/core-register-cap-refused"

// runCoreRegisterGate is the §10.1 gate. Declares + runs its own
// checks under the `handlers` category (uses the runner from the
// caller so checks merge into the existing `handlers` category result
// stream).
func runCoreRegisterGate(ctx context.Context, client *PeerClient, r *CheckRunner) {
	peerID := string(client.RemotePeerID())

	r.Declare("core_register_body_binding", "V7 §9.4, PROPOSAL v7.74 §10.1 step 1")
	r.Declare("core_register_op_status", "V7 §3.12, §6.2; PROPOSAL v7.74 §10.1 step 2")
	r.Declare("core_register_op_result", "V7 §3.12; PROPOSAL v7.74 §10.1 step 3")
	r.Declare("core_register_manifest_at_path", "V7 §6.2 N3; PROPOSAL v7.74 §10.1 step 4")
	r.Declare("core_register_handler_at_path", "V7 §6.2 N2; PROPOSAL v7.74 §10.1 step 4")
	r.Declare("core_register_grant_at_path", "V7 §6.2, §6.8; PROPOSAL v7.74 §10.1 step 4")
	r.Declare("core_register_grant_signature_at_invariant_path", "V7 §3.5, v7.74 v0.4 §3.4; PROPOSAL v7.74 §10.1 step 4")
	r.Declare("core_register_unregister_status", "V7 §6.2; PROPOSAL v7.74 §10.1 unregister teardown")
	r.Declare("core_register_unregister_signature_removed", "v7.74 v0.4 §3.4 writer/unregister symmetry; PROPOSAL v7.74 §10.1 unregister teardown")
	r.Declare("validate_echo_dispatch", "GUIDE-CONFORMANCE §7a.1 — verbatim-echo dispatch (the §10.1 dispatch half, moved off compute/literal)")

	// The default body-binding seam is entity-native compute. Probe
	// reachability before the gate runs — without it the seam can't
	// fire and the gate SKIPs honestly (the right surface for keystone
	// peers that have no body-binding mechanism for the test pattern).
	if !client.GrantsAllow("app/validate/core-register") {
		reason := "connection grants do not cover app/validate/core-register/* (body-binding seam unreachable)"
		for _, n := range []string{
			"core_register_body_binding",
			"core_register_op_status",
			"core_register_op_result",
			"core_register_manifest_at_path",
			"core_register_handler_at_path",
			"core_register_grant_at_path",
			"core_register_grant_signature_at_invariant_path",
			"core_register_unregister_status",
			"core_register_unregister_signature_removed",
			"validate_echo_dispatch",
		} {
			n := n
			r.Run(n, func() CheckOutcome { return SkipCheck(reason) })
		}
		return
	}

	// Best-effort prior cleanup so reruns succeed.
	_ = unregisterHandler(ctx, client, peerID, coreRegisterTestPattern)

	// Step 1: impl-private body-binding seam. The Go default seam is
	// entity-native compute: put a literal-returning expression at
	// expressionPath. Other impls plug different seams in their own
	// validator builds. The literal value 42 is arbitrary; the only
	// invariant the gate asserts in step 6 is "response round-trips
	// correctly" (status 200 + result entity decodable).
	r.Run("core_register_body_binding", func() CheckOutcome {
		litEnt, err := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		if err != nil {
			return FailCheck("build literal expression: " + err.Error())
		}
		if _, err := client.TreePut(ctx, coreRegisterTestExprPath, litEnt); err != nil {
			return FailCheck("body-binding seam (entity-native expression put): " + err.Error())
		}
		return PassCheck("entity-native echo body bound at " + coreRegisterTestExprPath)
	})

	// Step 2: wire register.
	r.Run("core_register_op_status", func() CheckOutcome {
		if out, ok := r.Require("core_register_body_binding"); !ok {
			return out
		}
		respData, err := sendCoreRegister(ctx, client, peerID, coreRegisterTestPattern,
			coreRegisterTestExprPath, wildcardScope(peerID))
		if err != nil {
			return FailCheck("dispatch system/handler:register: " + err.Error())
		}
		r.Store("register_resp", respData)
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("register returned status %d", respData.Status))
		}
		return PassCheck("register returned 200")
	})

	// Step 3a: result decode + pattern match.
	r.Run("core_register_op_result", func() CheckOutcome {
		if out, ok := r.Require("core_register_op_status"); !ok {
			return out
		}
		respData := r.Load("register_resp").(types.ExecuteResponseData)
		var regResult types.RegisterResultData
		inner, err := decodeResultData(respData, &regResult)
		if err != nil {
			return FailCheck("decode register-result: " + err.Error())
		}
		if inner.Type != types.TypeHandlerRegisterRes {
			return FailCheck(fmt.Sprintf("result type=%q (expected %q)", inner.Type, types.TypeHandlerRegisterRes))
		}
		if regResult.Pattern != coreRegisterTestPattern {
			return FailCheck(fmt.Sprintf("result pattern=%q (expected %q)", regResult.Pattern, coreRegisterTestPattern))
		}
		return PassCheck(fmt.Sprintf("register-result pattern=%q", regResult.Pattern))
	})

	// Step 3b: manifest entity at system/handler/<pattern>.
	r.Run("core_register_manifest_at_path", func() CheckOutcome {
		if out, ok := r.Require("core_register_op_status"); !ok {
			return out
		}
		manifestPath := "system/handler/" + coreRegisterTestPattern
		ent, _, err := client.TreeGet(ctx, manifestPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("no entity at %s: %v", manifestPath, err))
		}
		if ent.Type != types.TypeHandlerInterface {
			return FailCheck(fmt.Sprintf("type=%q (expected %q) at %s", ent.Type, types.TypeHandlerInterface, manifestPath))
		}
		return PassCheck(fmt.Sprintf("manifest entity present at %s", manifestPath))
	})

	// Step 3c: handler entity at <pattern>.
	r.Run("core_register_handler_at_path", func() CheckOutcome {
		if out, ok := r.Require("core_register_op_status"); !ok {
			return out
		}
		ent, _, err := client.TreeGet(ctx, coreRegisterTestPattern)
		if err != nil {
			return FailCheck(fmt.Sprintf("no entity at %s: %v", coreRegisterTestPattern, err))
		}
		if ent.Type != types.TypeHandler {
			return FailCheck(fmt.Sprintf("type=%q (expected %q) at %s", ent.Type, types.TypeHandler, coreRegisterTestPattern))
		}
		return PassCheck(fmt.Sprintf("handler entity present at %s", coreRegisterTestPattern))
	})

	// Step 3d: grant at system/capability/grants/<pattern>.
	r.Run("core_register_grant_at_path", func() CheckOutcome {
		if out, ok := r.Require("core_register_op_status"); !ok {
			return out
		}
		grantPath := "system/capability/grants/" + coreRegisterTestPattern
		ent, _, err := client.TreeGet(ctx, grantPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("no entity at %s: %v", grantPath, err))
		}
		if ent.Type != types.TypeCapToken {
			return FailCheck(fmt.Sprintf("type=%q (expected %q) at %s", ent.Type, types.TypeCapToken, grantPath))
		}
		r.Store("grant_entity", ent)
		return PassCheck(fmt.Sprintf("grant entity present at %s", grantPath))
	})

	// Step 3e: grant-signature at system/signature/{grant_hash_hex}
	// (v7.74 v0.4 §3.4 — the invariant-pointer convergence; same
	// convention as every other signature in the address space). The
	// path derives from the grant entity's content hash so the gate
	// follows the exact spec contract end-to-end.
	r.Run("core_register_grant_signature_at_invariant_path", func() CheckOutcome {
		if out, ok := r.Require("core_register_grant_at_path"); !ok {
			return out
		}
		grantEnt := r.Load("grant_entity").(entity.Entity)
		sigPath := types.LocalSignaturePath(grantEnt.ContentHash)
		ent, _, err := client.TreeGet(ctx, sigPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("no signature entity at %s (v7.74 v0.4 §3.4 invariant-pointer path; computed from grant_hash=%s): %v",
				sigPath, grantEnt.ContentHash, err))
		}
		if ent.Type != types.TypeSignature {
			return FailCheck(fmt.Sprintf("type=%q (expected %q) at %s", ent.Type, types.TypeSignature, sigPath))
		}
		// Confirm the signature actually targets this grant — guards
		// against a path coincidence where a stray signature happens to
		// live at the same hex-named slot. The signer field is also
		// asserted equal to the responder's identity hash via the
		// signature's structural shape (V7 §3.5).
		var sigData types.SignatureData
		if err := ecf.Decode(ent.Data, &sigData); err != nil {
			return FailCheck("decode system/signature: " + err.Error())
		}
		if !bytes.Equal(sigData.Target.Bytes(), grantEnt.ContentHash.Bytes()) {
			return FailCheck(fmt.Sprintf("signature.target=%s mismatches grant.content_hash=%s",
				sigData.Target, grantEnt.ContentHash))
		}
		r.Store("grant_sig_path", sigPath)
		return PassCheck(fmt.Sprintf("grant signature at %s targets grant.content_hash", sigPath))
	})

	// Step 4 — dispatch half. Per GUIDE-CONFORMANCE §7a.3, the
	// register/unregister CONTRACT (the five normative writes above +
	// unregister symmetry below) is what §10.1 actually gates. The old
	// step here was "register a literal-returning compute expression and
	// dispatch it"; that forced the compute extension into the core gate
	// (A-011). §7a moved the dispatch half to system/validate/echo —
	// behavioral contract, compute-free body, mechanism per impl.
	//
	// SKIP rather than FAIL when the target 404s system/validate/echo
	// (peer not started with --validate); a peer running without the
	// opt-in falls back to the §7a.4 code-attestation floor. Resolves
	// A-011: the gate no longer assumes a compute-extension body.
	r.Run("validate_echo_dispatch", func() CheckOutcome {
		if !client.HasConformanceHandlers(ctx) {
			return SkipCheck("target peer not run with --validate (system/validate/echo absent; §7a.4 falls back to code-attestation floor)")
		}
		if err := client.SendEchoProbe(ctx, "register-gate-dispatch-half"); err != nil {
			return FailCheck(err.Error())
		}
		return PassCheck("system/validate/echo verbatim-echo round-trips the dispatch half (§7a.1)")
	})

	// Step 5: wire unregister.
	r.Run("core_register_unregister_status", func() CheckOutcome {
		if out, ok := r.Require("core_register_op_status"); !ok {
			return out
		}
		if err := unregisterHandler(ctx, client, peerID, coreRegisterTestPattern); err != nil {
			return FailCheck("unregister: " + err.Error())
		}
		return PassCheck("unregister returned 200")
	})

	// Step 5b: signature is also removed (writer/unregister symmetry).
	// Half-removed state — grant gone, signature lingering — is the
	// v0.4 §10.1 hazard the unregister-teardown coverage exists to
	// prevent.
	r.Run("core_register_unregister_signature_removed", func() CheckOutcome {
		if out, ok := r.Require("core_register_unregister_status"); !ok {
			return out
		}
		if out, ok := r.Require("core_register_grant_signature_at_invariant_path"); !ok {
			return out
		}
		sigPath := r.Load("grant_sig_path").(string)
		_, _, err := client.TreeGet(ctx, sigPath)
		if err == nil {
			return FailCheck(fmt.Sprintf("signature still present at %s after unregister (writer/unregister symmetry violation)", sigPath))
		}
		return PassCheck(fmt.Sprintf("signature at %s removed by unregister", sigPath))
	})

}

// sendCoreRegister issues the wire register-op without the
// best-effort prior cleanup that `registerHandler` does (the gate
// already cleaned up above) and without `registerHandler`'s
// post-decode invariant assertions (the gate scores those as
// separate checks). Returns the raw response data so the gate can
// score `op_status` and `op_result` independently.
func sendCoreRegister(ctx context.Context, client *PeerClient, peerID, pattern, expressionPath string, scope []types.GrantEntry) (types.ExecuteResponseData, error) {
	manifest := types.HandlerManifestData{
		Pattern: pattern,
		Name:    pattern,
		Operations: map[string]types.HandlerOperationSpec{
			"compute": {InputType: "primitive/any", OutputType: "primitive/any"},
		},
		ExpressionPath: expressionPath,
		InternalScope:  scope,
	}
	req := types.RegisterRequestData{
		Manifest:       manifest,
		RequestedScope: scope,
	}
	reqEnt, err := req.ToEntity()
	if err != nil {
		return types.ExecuteResponseData{}, fmt.Errorf("build register-request entity: %w", err)
	}
	uri := fmt.Sprintf("entity://%s/system/handler", peerID)
	resource := &types.ResourceTarget{Targets: []string{"system/handler/" + pattern}}
	env, _, err := client.SendExecute(ctx, uri, "register", reqEnt, resource)
	if err != nil {
		return types.ExecuteResponseData{}, fmt.Errorf("dispatch register: %w", err)
	}
	return types.ExecuteResponseDataFromEntity(env.Root)
}

// runCoreRegisterNegativeHalf is the GUIDE-CONFORMANCE §2.4a negative half
// for `system/handler:register`, deliberately split out of
// runCoreRegisterGate so it runs under EVERY profile.
//
// Re-based at 0.8.2.13's withdrawal of the `system/*` reservation: the refusal
// mechanism is now an ATTRIBUTABLE capability denial (a register presenting a
// child cap that does not cover the `system/handler` handler → 403
// capability_denied on §5.2 Dimension 2), not the withdrawn §6.6 prefix rule.
// The valuable conjunct — *a refused register publishes nothing* — is kept.
// A positive control registers the same shape under the covering connection
// cap: it proves the check discriminates (a refuse-everything peer fails it)
// and gates the negative arm on the peer being armed for register (a default
// peer whose connection cap does not cover `system/handler` cannot reach the
// arm, and the control SKIPs it rather than scoring a refusal it cannot
// attribute to Dimension 2).
func runCoreRegisterNegativeHalf(ctx context.Context, client *PeerClient, r *CheckRunner) {
	peerID := string(client.RemotePeerID())

	r.Declare("core_register_capability_positive_control", "GUIDE-CONFORMANCE §2.4a negative half, control — a register under the covering connection cap at a non-reserved pattern MUST succeed (200). Proves the capability-refusal arm below discriminates (one arm alone passes on a peer that refuses everything), and gates it on the peer being armed for register. SKIPs when the peer is not armed with register-covering grants.")
	r.Declare("core_register_capability_refused", "GUIDE-CONFORMANCE §2.4a negative half, conjunct 1 (re-based at 0.8.2.13) — a register presenting a capability that does NOT cover the system/handler handler MUST be refused 403 capability_denied (§5.2 Dimension 2). Replaces the withdrawn §6.6 system/* prefix refusal; the child cap carries resources:[/*/*] so the only failing dimension is handlers (avoids the §5.5a namespace-frame false attribution).")
	r.Declare("core_register_refused_publishes_nothing", "GUIDE-CONFORMANCE §2.4a negative half, conjuncts 2+3 — THE ONE THAT MATTERS. A refused register MUST leave NONE of the artifacts the positive half asserts: manifest at system/handler/<pattern>, handler entity at <pattern>, grant at system/capability/grants/<pattern>. A 403 that published anyway satisfies a status-only check while defeating the gate — the register analogue of policy_manual_publishes_nothing.")

	// Positive control + arming gate. Register under the covering connection
	// cap at a non-reserved pattern; 200 means the peer is armed and the
	// capability surface is reachable. Clean up so it cannot be confused with
	// the negative arm's "published nothing".
	r.Run("core_register_capability_positive_control", func() CheckOutcome {
		_ = unregisterHandler(ctx, client, peerID, coreRegisterCtrlPattern)
		respData, err := sendCoreRegister(ctx, client, peerID, coreRegisterCtrlPattern,
			coreRegisterCtrlPattern+"/expr", wildcardScope(peerID))
		if err != nil {
			return FailCheck("dispatch positive-control register: " + err.Error())
		}
		if respData.Status != 200 {
			return SkipCheck(fmt.Sprintf("positive-control register returned %d, not 200 — the peer is not armed with grants covering system/handler:register (e.g. started without --open-access/--debug-grants); the capability-refusal arm is not reachable, so it is not measured here rather than scored on a refusal it cannot attribute to Dimension 2", respData.Status))
		}
		_ = unregisterHandler(ctx, client, peerID, coreRegisterCtrlPattern)
		return PassCheck("register under the covering connection cap at a non-reserved pattern succeeded (200) — the capability surface is reachable and the refusal arm below discriminates")
	})

	// Negative arm: present a child cap that does NOT cover system/handler.
	r.Run("core_register_capability_refused", func() CheckOutcome {
		if out, ok := r.Require("core_register_capability_positive_control"); !ok {
			return out
		}
		// Child cap: handlers scoped to system/tree (NOT system/handler),
		// resources /*/* (absolute/universal — covers the target, so it is NOT
		// the refusing dimension), operations register. Delegated from the
		// connection cap, so the chain validates; the register then fails §5.2
		// Dimension 2 because system/handler is not in {system/tree}.
		narrow := types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			Operations: types.CapabilityScope{Include: []string{"register"}},
		}
		narrowCap, narrowSig, err := buildAttenuatedChildCap(client, narrow)
		if err != nil {
			return FailCheck("build narrow child cap: " + err.Error())
		}
		manifest := types.HandlerManifestData{
			Pattern: coreRegisterNegPattern,
			Name:    coreRegisterNegPattern,
			Operations: map[string]types.HandlerOperationSpec{
				"compute": {InputType: "primitive/any", OutputType: "primitive/any"},
			},
			ExpressionPath: coreRegisterNegPattern + "/expr",
		}
		regReq, err := types.RegisterRequestData{Manifest: manifest}.ToEntity()
		if err != nil {
			return FailCheck("build register-request: " + err.Error())
		}
		resource := &types.ResourceTarget{Targets: []string{"system/handler/" + coreRegisterNegPattern}}
		uri := fmt.Sprintf("entity://%s/system/handler", peerID)
		env, err := buildDelegatedExecute(client, narrowCap, narrowSig, uri, "register", regReq, resource)
		if err != nil {
			return FailCheck("build delegated register execute: " + err.Error())
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send delegated register: " + err.Error())
		}
		status, code, _, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("extract response: " + err.Error())
		}
		if status == 200 {
			return FailCheck("register presenting a cap that does NOT cover system/handler returned 200 — the §5.2 Dimension 2 handler-scope check is absent; any holder of any grant could install a handler")
		}
		if status == 403 && code == "capability_denied" {
			return PassCheck("register presenting a cap scoped to system/tree (not system/handler) refused 403 capability_denied — §5.2 Dimension 2 enforced; resources:[/*/*] rules out a §5.5a namespace-frame refusal, so the denial is attributable to the handler dimension")
		}
		return FailCheck(fmt.Sprintf("register under a non-covering cap returned status=%d code=%q; §5.2 pins 403 capability_denied for a handler-scope miss", status, code))
	})

	r.Run("core_register_refused_publishes_nothing", func() CheckOutcome {
		if out, ok := r.Require("core_register_capability_refused"); !ok {
			return out
		}
		// The same writes the positive half asserts, inverted. The
		// grant-signature is covered transitively: no grant entity means
		// no invariant-pointer slot for a signature to occupy.
		probes := []struct{ label, path string }{
			{"manifest", "system/handler/" + coreRegisterNegPattern},
			{"handler entity", coreRegisterNegPattern},
			{"grant", "system/capability/grants/" + coreRegisterNegPattern},
		}
		var leaked []string
		for _, p := range probes {
			ent, _, err := client.TreeGet(ctx, p.path)
			if err == nil {
				leaked = append(leaked, fmt.Sprintf("%s at %s (type=%q)", p.label, p.path, ent.Type))
			}
		}
		if len(leaked) > 0 {
			return FailCheck(fmt.Sprintf(
				"refused register PUBLISHED %d of %d probed artifacts: %s — a 403 that writes anyway passes every status-only check (GUIDE-CONFORMANCE §2.4a conjuncts 2+3)",
				len(leaked), len(probes), strings.Join(leaked, "; ")))
		}
		return PassCheck("capability-refused register left no manifest, no handler entity and no grant — so no invariant-pointer slot to carry a grant-signature either")
	})
}
