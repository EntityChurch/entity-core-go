package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catEntityNative = "entity_native"

// runEntityNative validates the entity-native handler dispatch contract from
// PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH (V7 §3.7, §6.6; COMPUTE §3, §4).
//
// Handlers are registered via the spec-defined system/handler:register
// operation (V7 §3.12, §6.2). Patterns live under app/validate/entity-native/*
// because V7 §6.6 reserves system/* for bootstrap handlers only.
//
// Each test registers a fresh handler under app/validate/entity-native/{slot}
// with its own expression and scope, so tests are independent and can be run
// individually via -category entity_native.
func runEntityNative(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catEntityNative)

	r.Declare("dispatch_basic", "V7 §6.6, PROPOSAL §1")
	r.Declare("scope_params", "PROPOSAL §2 (E1)")
	r.Declare("scope_operation", "PROPOSAL §2 (E1)")
	r.Declare("result_unwrapped", "PROPOSAL §4 (E3)")
	r.Declare("missing_grant_fail_closed", "PROPOSAL §7.1")
	r.Declare("lookup_tree_within_scope", "PROPOSAL §3.1")
	r.Declare("lookup_tree_outside_scope", "PROPOSAL §7.2")
	r.Declare("dual_check_handler_grant_blocks", "PROPOSAL §3.2")
	r.Declare("dual_check_both_pass", "PROPOSAL §3.2")
	r.Declare("multiple_operations", "PROPOSAL §2 (E1)")
	r.Declare("hot_swap_expression", "PROPOSAL §1, §5")
	r.Declare("dispatch_with_deliver_to", "V7 §6.6, PROPOSAL-DISPATCH-CONTRACT-SCOPE A.2")

	peerID := string(client.RemotePeerID())
	root := "app/validate/entity-native"

	// 1. dispatch_basic: literal-returning handler.
	r.Run("dispatch_basic", func() CheckOutcome {
		slot := root + "/basic"
		exprPath := slot + "/expr"

		litEnt, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, litEnt); err != nil {
			return FailCheck("put expression: " + err.Error())
		}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, wildcardScope(peerID)); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		val, err := callEntityNative(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if !numEq(val, 42) {
			return FailCheck(fmt.Sprintf("expected 42, got %v", val))
		}
		return PassCheck("dispatch returns expression value")
	})

	// 2. scope_params: expression reads field("x", lookup/scope("params")).
	r.Run("scope_params", func() CheckOutcome {
		slot := root + "/params"
		exprPath := slot + "/expr"

		paramsLookup, _ := types.ComputeLookupScopeData{Name: "params"}.ToEntity()
		paramsLookupH := putCE(ctx, client, slot+"/p-lookup", paramsLookup)
		fieldExpr, _ := types.ComputeFieldData{Name: "x", Entity: paramsLookupH}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, fieldExpr); err != nil {
			return FailCheck("put expression: " + err.Error())
		}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, wildcardScope(peerID)); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		paramsEnt, _ := buildAnyParams(map[string]interface{}{"x": uint64(7)})
		val, err := callEntityNative(ctx, client, peerID, slot, "compute", &paramsEnt)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if !numEq(val, 7) {
			return FailCheck(fmt.Sprintf("expected 7, got %v", val))
		}
		return PassCheck("expression reads params via lookup/scope")
	})

	// 3. scope_operation: expression returns lookup/scope("operation").
	r.Run("scope_operation", func() CheckOutcome {
		slot := root + "/op"
		exprPath := slot + "/expr"

		opLookup, _ := types.ComputeLookupScopeData{Name: "operation"}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, opLookup); err != nil {
			return FailCheck("put expression: " + err.Error())
		}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, wildcardScope(peerID)); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		val, err := callEntityNative(ctx, client, peerID, slot, "ping", nil)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		s, ok := val.(string)
		if !ok || s != "ping" {
			return FailCheck(fmt.Sprintf(`expected "ping", got %v (%T)`, val, val))
		}
		return PassCheck("expression reads operation via lookup/scope")
	})

	// 4. result_unwrapped: response payload is the value, not compute/result wrapper.
	r.Run("result_unwrapped", func() CheckOutcome {
		if out, ok := r.Require("dispatch_basic"); !ok {
			return out
		}
		slot := root + "/basic"
		respEnt, err := callEntityNativeRaw(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if respEnt.Type == types.TypeComputeResult {
			return FailCheck("response is compute/result-wrapped — proposal §4 (E3) requires raw result")
		}
		return PassCheck("response is unwrapped (type: " + respEnt.Type + ")")
	})

	// 5. missing_grant_fail_closed (§7.1): the dispatcher MUST refuse to invoke
	// an entity-native handler when its grant entity is absent. This test
	// intentionally bypasses system/handler:register — register's atomic install
	// always creates a grant, so we direct-tree-put just the handler entity to
	// reach the runtime state §7.1 protects against (e.g., revocation, partial
	// snapshot restore, storage corruption).
	r.Run("missing_grant_fail_closed", func() CheckOutcome {
		slot := root + "/nogrant"
		exprPath := slot + "/expr"

		litEnt, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, litEnt); err != nil {
			return FailCheck("put expression: " + err.Error())
		}
		if err := putHandlerEntityDirect(ctx, client, peerID, slot, exprPath); err != nil {
			return FailCheck("put handler entity: " + err.Error())
		}

		respData, err := executeRaw(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if respData.Status != 403 {
			return FailCheck(fmt.Sprintf("expected 403 with no handler grant, got status %d", respData.Status))
		}
		return PassCheck("dispatch fails closed (403) when handler grant is missing")
	})

	// 6. lookup_tree_within_scope: expression reads a path covered by the handler grant.
	r.Run("lookup_tree_within_scope", func() CheckOutcome {
		slot := root + "/lts"
		exprPath := slot + "/expr"
		dataPath := slot + "/data/value"

		valEnt, _ := types.ComputeLiteralData{Value: uint64(99)}.ToEntity()
		if _, err := client.TreePut(ctx, dataPath, valEnt); err != nil {
			return FailCheck("put data: " + err.Error())
		}
		qual := fmt.Sprintf("/%s/%s", peerID, dataPath)
		lookupTree, _ := types.ComputeLookupTreeData{Path: qual}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, lookupTree); err != nil {
			return FailCheck("put expression: " + err.Error())
		}

		// Grant covers the entire slot subtree (handler reads its own data).
		scope := []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: []string{"get"}},
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{fmt.Sprintf("/%s/%s/*", peerID, slot)}},
		}}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, scope); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		val, err := callEntityNative(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if !numEq(val, 99) {
			return FailCheck(fmt.Sprintf("expected 99, got %v", val))
		}
		return PassCheck("lookup/tree succeeds within handler grant scope")
	})

	// 7. lookup_tree_outside_scope (§7.2 + §3.2 v3.19c clarification):
	// expression reads a path NOT covered by the handler grant. The denial
	// arises during evaluation → 200 + compute/error{permission_denied}
	// per F10/§3.2 (the determinism-safe line: 4xx is reserved for pre-
	// eval authz failures only).
	r.Run("lookup_tree_outside_scope", func() CheckOutcome {
		if out, ok := r.Require("dispatch_basic"); !ok {
			return out
		}
		slot := root + "/lto"
		exprPath := slot + "/expr"
		forbiddenPath := "app/validate/entity-native-forbidden/value"

		valEnt, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
		if _, err := client.TreePut(ctx, forbiddenPath, valEnt); err != nil {
			return FailCheck("put forbidden data: " + err.Error())
		}
		qual := fmt.Sprintf("/%s/%s", peerID, forbiddenPath)
		lookupTree, _ := types.ComputeLookupTreeData{Path: qual}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, lookupTree); err != nil {
			return FailCheck("put expression: " + err.Error())
		}

		// Grant restricted to the handler's own subtree only.
		scope := []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: []string{"get"}},
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{fmt.Sprintf("/%s/%s/*", peerID, slot)}},
		}}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, scope); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		respData, err := executeRaw(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if err := assertInEvalPermissionDenied(respData); err != nil {
			return FailCheck(err.Error())
		}
		return PassCheck("out-of-scope tree read surfaced as 200 + compute/error{permission_denied} (in-eval denial per §3.2 / F10)")
	})

	// 8. dual_check_handler_grant_blocks (§3.2 + v3.19c clarification):
	// expression tries to escape its scope via compute/apply with the
	// caller's broader capability. The dual-check fires during evaluation
	// → 200 + compute/error{permission_denied}.
	r.Run("dual_check_handler_grant_blocks", func() CheckOutcome {
		if out, ok := r.Require("dispatch_basic"); !ok {
			return out
		}
		slot := root + "/escape"
		exprPath := slot + "/expr"

		callerCapLookup, _ := types.ComputeLookupScopeData{Name: "caller_capability"}.ToEntity()
		callerCapH := putCE(ctx, client, slot+"/cap-lookup", callerCapLookup)
		// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F5: capability override
		// requires resource. The denial here is semantic (handler grant
		// doesn't cover system/tree), not structural — Resource is set so
		// F5 passes and the dual-check actually runs against the target.
		resourceLit, _ := types.ComputeLiteralData{
			Value: types.ResourceTarget{Targets: []string{fmt.Sprintf("/%s/%s/data/x", peerID, slot)}},
		}.ToEntity()
		resourceH := putCE(ctx, client, slot+"/res-lit", resourceLit)
		applyEnt, _ := types.ComputeApplyData{
			Path:       "system/tree",
			Operation:  "get",
			Resource:   resourceH,
			Capability: callerCapH,
		}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, applyEnt); err != nil {
			return FailCheck("put expression: " + err.Error())
		}

		// Handler grant covers only system/clock — system/tree is OUT of scope.
		scope := []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: []string{"now"}},
			Handlers:   types.CapabilityScope{Include: []string{"system/clock"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
		}}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, scope); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		respData, err := executeRaw(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if err := assertInEvalPermissionDenied(respData); err != nil {
			return FailCheck(err.Error())
		}
		return PassCheck("handler-grant escape attempt surfaced as 200 + compute/error{permission_denied} (in-eval dual-check denial per §3.2 / F10)")
	})

	// 9. dual_check_both_pass: both handler grant and provided cap cover target.
	r.Run("dual_check_both_pass", func() CheckOutcome {
		slot := root + "/dualok"
		exprPath := slot + "/expr"
		dataPath := slot + "/data/v"

		valEnt, _ := types.ComputeLiteralData{Value: uint64(123)}.ToEntity()
		if _, err := client.TreePut(ctx, dataPath, valEnt); err != nil {
			return FailCheck("put data: " + err.Error())
		}

		resourceLit, _ := types.ComputeLiteralData{Value: fmt.Sprintf("/%s/%s", peerID, dataPath)}.ToEntity()
		resourceH := putCE(ctx, client, slot+"/res-lit", resourceLit)
		// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F1+F5: thread resource as
		// the apply.Resource field (carries through to the dispatched EXECUTE
		// per F4) so the dual-check sees the target at full resolution.
		applyResourceLit, _ := types.ComputeLiteralData{
			Value: types.ResourceTarget{Targets: []string{fmt.Sprintf("/%s/%s", peerID, dataPath)}},
		}.ToEntity()
		applyResourceH := putCE(ctx, client, slot+"/apply-res-lit", applyResourceLit)
		callerCapLookup, _ := types.ComputeLookupScopeData{Name: "caller_capability"}.ToEntity()
		callerCapH := putCE(ctx, client, slot+"/cap-lookup", callerCapLookup)
		applyEnt, _ := types.ComputeApplyData{
			Path:       "system/tree",
			Operation:  "get",
			Resource:   applyResourceH,
			Args:       map[string]hash.Hash{"resource": resourceH},
			Capability: callerCapH,
		}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, applyEnt); err != nil {
			return FailCheck("put expression: " + err.Error())
		}

		scope := []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: []string{"*"}},
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
		}}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, scope); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		respData, err := executeRaw(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("expected 200 dispatch through dual-check, got %d", respData.Status))
		}
		return PassCheck("dual-check passes when both handler grant and provided cap cover target")
	})

	// 10. multiple_operations: same expression branches on lookup/scope("operation").
	r.Run("multiple_operations", func() CheckOutcome {
		slot := root + "/multi"
		exprPath := slot + "/expr"

		// expr: if (operation == "double") then 20 else 30
		opLookup, _ := types.ComputeLookupScopeData{Name: "operation"}.ToEntity()
		opH := putCE(ctx, client, slot+"/op", opLookup)
		doubleLit, _ := types.ComputeLiteralData{Value: "double"}.ToEntity()
		doubleH := putCE(ctx, client, slot+"/lit-double", doubleLit)
		condEnt, _ := types.ComputeCompareData{Op: "eq", Left: opH, Right: doubleH}.ToEntity()
		condH := putCE(ctx, client, slot+"/cond", condEnt)
		thenLit, _ := types.ComputeLiteralData{Value: uint64(20)}.ToEntity()
		thenH := putCE(ctx, client, slot+"/then", thenLit)
		elseLit, _ := types.ComputeLiteralData{Value: uint64(30)}.ToEntity()
		elseH := putCE(ctx, client, slot+"/else", elseLit)
		ifEnt, _ := types.ComputeIfData{Condition: condH, Then: thenH, Else: &elseH}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, ifEnt); err != nil {
			return FailCheck("put expression: " + err.Error())
		}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, wildcardScope(peerID)); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		v1, err := callEntityNative(ctx, client, peerID, slot, "double", nil)
		if err != nil {
			return FailCheck("dispatch double: " + err.Error())
		}
		if !numEq(v1, 20) {
			return FailCheck(fmt.Sprintf(`op "double": expected 20, got %v`, v1))
		}
		v2, err := callEntityNative(ctx, client, peerID, slot, "other", nil)
		if err != nil {
			return FailCheck("dispatch other: " + err.Error())
		}
		if !numEq(v2, 30) {
			return FailCheck(fmt.Sprintf(`op "other": expected 30, got %v`, v2))
		}
		return PassCheck("expression branches on operation scope binding")
	})

	// 11. hot_swap_expression: replace the entity at expression_path; next call sees new logic.
	r.Run("hot_swap_expression", func() CheckOutcome {
		slot := root + "/swap"
		exprPath := slot + "/expr"

		litA, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, litA); err != nil {
			return FailCheck("put expression A: " + err.Error())
		}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, wildcardScope(peerID)); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		v1, err := callEntityNative(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch A: " + err.Error())
		}
		if !numEq(v1, 1) {
			return FailCheck(fmt.Sprintf("pre-swap expected 1, got %v", v1))
		}

		litB, _ := types.ComputeLiteralData{Value: uint64(99)}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, litB); err != nil {
			return FailCheck("put expression B: " + err.Error())
		}

		v2, err := callEntityNative(ctx, client, peerID, slot, "compute", nil)
		if err != nil {
			return FailCheck("dispatch B: " + err.Error())
		}
		if !numEq(v2, 99) {
			return FailCheck(fmt.Sprintf("post-swap expected 99, got %v", v2))
		}
		return PassCheck("hot-swap: replacing expression at expression_path takes effect on next call")
	})

	// dispatch_with_deliver_to: entity-native + async delivery must return 202.
	// PROPOSAL-DISPATCH-CONTRACT-SCOPE A.2 / V7 §6.6 v7.49: handler shape is
	// not a dispatch-contract dimension — entity-native handlers MUST honor
	// deliver_to with the same 202 semantics as compiled handlers. Earlier
	// impls returned 400 async_unsupported; this guards the regression.
	r.Run("dispatch_with_deliver_to", func() CheckOutcome {
		slot := root + "/deliver"
		exprPath := slot + "/expr"
		inboxPath := "system/inbox/entity-native-deliver-result"

		litEnt, _ := types.ComputeLiteralData{Value: uint64(99)}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, litEnt); err != nil {
			return FailCheck("put expression: " + err.Error())
		}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, wildcardScope(peerID)); err != nil {
			return FailCheck("register handler: " + err.Error())
		}

		deliverURI := "entity://" + peerID + "/" + inboxPath
		tokenEnt, tokenSigEnt, err := client.CreateDeliveryToken(deliverURI, "receive")
		if err != nil {
			return FailCheck("create delivery token: " + err.Error())
		}

		paramsRaw, _ := ecf.Encode(map[string]interface{}{})
		params, _ := entity.NewEntity("primitive/any", cbor.RawMessage(paramsRaw))
		uri := "entity://" + peerID + "/" + slot
		resource := &types.ResourceTarget{Targets: []string{slot}}
		deliverTo := &types.DeliverySpec{URI: deliverURI, Operation: "receive"}

		env, _, err := client.SendExecuteAsync(ctx, uri, "compute", params, resource,
			deliverTo, tokenEnt, tokenSigEnt)
		if err != nil {
			return FailCheck("send async execute: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return FailCheck("decode response: " + err.Error())
		}
		if respData.Status == 400 {
			// Specifically catch the regression — async_unsupported was the
			// pre-v3.14 / pre-A.2 failure mode for entity-native + deliver_to.
			return FailCheck(fmt.Sprintf("entity-native + deliver_to rejected with 400 (regression of A.2 uniformity): %+v", respData))
		}
		if respData.Status != 202 {
			return FailCheck(fmt.Sprintf("expected status 202, got %d", respData.Status))
		}
		return PassCheck("entity-native + deliver_to returns 202 (uniform with compiled handlers)")
	})

	return r.Results()
}

// --- Registration helpers ---

// registerHandler installs an entity-native handler at pattern via the spec-
// defined system/handler:register operation (V7 §3.12, §6.2). The handlers
// handler atomically writes the manifest, interface entity, and grant.
//
// Idempotent: silently unregisters any prior handler at the same pattern
// first so the validation suite can be rerun against the same peer.
//
// expressionPath is the bare tree path of the compute expression (without the
// peer-id prefix); the dispatch layer canonicalizes when invoking the eval.
// scope is the grant the handler will receive — it must cover whatever impure
// operations the expression performs (tree reads, sub-dispatches).
func registerHandler(ctx context.Context, client *PeerClient, peerID, pattern, expressionPath string, scope []types.GrantEntry) error {
	// Best-effort unregister: ignore "not registered" so first-run works.
	_ = unregisterHandler(ctx, client, peerID, pattern)

	manifest := types.HandlerManifestData{
		Pattern: pattern,
		Name:    pattern, // human-readable name; pattern is fine for tests
		Operations: map[string]types.HandlerOperationSpec{
			// The contract is open — the expression handles whatever operation
			// arrives via lookup/scope("operation"). Declare a small set of
			// validation-friendly operations here; entity-native handlers
			// don't bind operation logic to declarations.
			"compute": {InputType: "primitive/any", OutputType: "primitive/any"},
			"ping":    {InputType: "primitive/any", OutputType: "primitive/any"},
			"double":  {InputType: "primitive/any", OutputType: "primitive/any"},
			"other":   {InputType: "primitive/any", OutputType: "primitive/any"},
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
		return fmt.Errorf("build register-request entity: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/handler", peerID)
	resource := &types.ResourceTarget{Targets: []string{"system/handler/" + pattern}}
	env, _, err := client.SendExecute(ctx, uri, "register", reqEnt, resource)
	if err != nil {
		return fmt.Errorf("dispatch system/handler:register: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return fmt.Errorf("decode register response: %w", err)
	}
	if respData.Status != 200 {
		return fmt.Errorf("register returned status %d", respData.Status)
	}
	// Typed-decode the register result and assert minimum invariants:
	// pattern matches what we asked for, and the granted token is structurally
	// populated (non-zero grantee, at least one grant). Catches cross-impl
	// register-result shape regressions that status-only checks would miss.
	var regResult types.RegisterResultData
	inner, err := decodeResultData(respData, &regResult)
	if err != nil {
		return fmt.Errorf("register result: %w", err)
	}
	if inner.Type != types.TypeHandlerRegisterRes {
		return fmt.Errorf("register result type=%q (expected %q)", inner.Type, types.TypeHandlerRegisterRes)
	}
	if regResult.Pattern != pattern {
		return fmt.Errorf("register result pattern=%q (expected %q)", regResult.Pattern, pattern)
	}
	if regResult.Grant.Grantee.IsZero() {
		return fmt.Errorf("register result grant.grantee is zero")
	}
	if len(regResult.Grant.Grants) == 0 {
		return fmt.Errorf("register result grant has no grant entries")
	}
	return nil
}

// unregisterHandler removes a previously-registered handler. Returns nil on
// 200 or 404 (not registered); error otherwise. Used by registerHandler to
// keep the validation suite idempotent across reruns.
func unregisterHandler(ctx context.Context, client *PeerClient, peerID, pattern string) error {
	// V7 §3.2: pattern is in resource; params is empty primitive/any.
	emptyParams, err := buildAnyParams(map[string]interface{}{})
	if err != nil {
		return err
	}
	uri := fmt.Sprintf("entity://%s/system/handler", peerID)
	resource := &types.ResourceTarget{Targets: []string{"system/handler/" + pattern}}
	env, _, err := client.SendExecute(ctx, uri, "unregister", emptyParams, resource)
	if err != nil {
		return err
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return err
	}
	if respData.Status == 200 || respData.Status == 404 {
		return nil
	}
	return fmt.Errorf("unregister returned status %d", respData.Status)
}

// putHandlerEntityDirect bypasses system/handler:register to write only the
// handler entity — no grant. Used solely by missing_grant_fail_closed to set
// up the runtime state §7.1 protects against. Production callers should use
// register; see V7 §6.2.
func putHandlerEntityDirect(ctx context.Context, client *PeerClient, peerID, pattern, expressionPath string) error {
	handlerEnt, err := types.HandlerData{
		Interface:      "system/handler/" + pattern,
		ExpressionPath: expressionPath,
	}.ToEntity()
	if err != nil {
		return fmt.Errorf("build handler entity: %w", err)
	}
	if _, err := client.TreePut(ctx, pattern, handlerEnt); err != nil {
		return fmt.Errorf("put handler at %s: %w", pattern, err)
	}
	return nil
}

// callEntityNative dispatches an EXECUTE to the entity-native handler and
// extracts the unwrapped result value.
func callEntityNative(ctx context.Context, client *PeerClient, peerID, pattern, op string, params *entity.Entity) (interface{}, error) {
	respEnt, err := callEntityNativeRaw(ctx, client, peerID, pattern, op, params)
	if err != nil {
		return nil, err
	}
	if respEnt.Type == types.TypeComputeError {
		var d types.ComputeErrorData
		_ = ecf.Decode(respEnt.Data, &d)
		return nil, fmt.Errorf("compute error: %s — %s", d.Code, d.Message)
	}
	if respEnt.Type == types.TypeComputeResult {
		var d types.ComputeResultData
		if err := ecf.Decode(respEnt.Data, &d); err != nil {
			return nil, fmt.Errorf("decode compute/result: %w", err)
		}
		return d.Value, nil
	}
	if respEnt.Type == "primitive/any" {
		var v interface{}
		if err := ecf.Decode(respEnt.Data, &v); err != nil {
			return nil, fmt.Errorf("decode primitive/any: %w", err)
		}
		return v, nil
	}
	return respEnt, nil
}

// callEntityNativeRaw returns the response result entity without unwrapping.
// Errors only on transport / protocol failures, not handler-level non-200.
func callEntityNativeRaw(ctx context.Context, client *PeerClient, peerID, pattern, op string, params *entity.Entity) (entity.Entity, error) {
	respData, err := executeRaw(ctx, client, peerID, pattern, op, params)
	if err != nil {
		return entity.Entity{}, err
	}
	if respData.Status != 200 {
		return entity.Entity{}, fmt.Errorf("dispatch status %d", respData.Status)
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		return entity.Entity{}, fmt.Errorf("decode result: %w", err)
	}
	return resultEnt, nil
}

// executeRaw sends an EXECUTE to the entity-native handler and returns the
// raw ExecuteResponseData. Used by tests that need to assert specific status
// codes (e.g., 403 for fail-closed checks). When params is nil, sends a
// well-formed empty-map placeholder so the dispatch layer's params-validity
// check does not short-circuit before reaching the entity-native handler.
func executeRaw(ctx context.Context, client *PeerClient, peerID, pattern, op string, params *entity.Entity) (types.ExecuteResponseData, error) {
	uri := fmt.Sprintf("entity://%s/%s", peerID, pattern)
	var paramsEnt entity.Entity
	if params != nil {
		paramsEnt = *params
	} else {
		empty, err := buildAnyParams(map[string]interface{}{})
		if err != nil {
			return types.ExecuteResponseData{}, fmt.Errorf("build empty params: %w", err)
		}
		paramsEnt = empty
	}
	env, _, err := client.SendExecute(ctx, uri, op, paramsEnt, nil)
	if err != nil {
		return types.ExecuteResponseData{}, err
	}
	return types.ExecuteResponseDataFromEntity(env.Root)
}

// buildAnyParams wraps a key/value map as a primitive/any entity for use as
// EXECUTE params.
func buildAnyParams(m map[string]interface{}) (entity.Entity, error) {
	raw, err := ecf.Encode(m)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity("primitive/any", cbor.RawMessage(raw))
}

// wildcardScope returns a permissive grant scope used for tests where the
// grant should not be the limiting factor.
func wildcardScope(peerID string) []types.GrantEntry {
	return []types.GrantEntry{{
		Operations: types.CapabilityScope{Include: []string{"*"}},
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
	}}
}

// assertInEvalPermissionDenied checks that a dispatched compute response
// surfaces an in-eval permission_denied as the F10 / §3.2 value-form:
// status 200, body compute/error{code: "permission_denied"}. Returns nil
// on conformance or a descriptive error otherwise.
//
// Per EXTENSION-COMPUTE v3.19c §3.2 (merged from arch b2be616): a
// permission_denied that arises from evaluating an impure operation is a
// propagated compute/error value at status 200, the same as any other
// propagated error (§1.5 / F10). 4xx/403 is reserved for authz failures
// before evaluation — the eval/install EXECUTE being unauthorized, or the
// §3.3 install pre-audit rejecting an under-capable subgraph. The
// determinism-safe line: a pre-flight-403-vs-runtime-200 split keyed on
// whether the denied target is statically determinable would make the
// status implementation-dependent.
func assertInEvalPermissionDenied(respData types.ExecuteResponseData) error {
	if respData.Status != 200 {
		return fmt.Errorf("expected 200 + compute/error{permission_denied} (in-eval denial per §3.2 / F10); got status %d", respData.Status)
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	if resultEnt.Type != types.TypeComputeError {
		return fmt.Errorf("expected compute/error body at status 200, got type=%s", resultEnt.Type)
	}
	errData, err := types.ComputeErrorDataFromEntity(resultEnt)
	if err != nil {
		return fmt.Errorf("decode compute/error: %w", err)
	}
	if errData.Code != "permission_denied" {
		return fmt.Errorf("expected compute/error{code=permission_denied}, got code=%s", errData.Code)
	}
	return nil
}
