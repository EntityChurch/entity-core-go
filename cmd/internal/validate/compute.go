package validate

import (
	"bytes"
	"context"
	"fmt"
	"math"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catCompute = "compute"

func runCompute(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catCompute)

	// --- Declare all checks ---

	// Handler presence and manifest.
	r.Declare("handler_present", "COMPUTE §3.1")
	r.Declare("handler_manifest_decode", "COMPUTE §3.1")
	r.Declare("handler_op_eval", "COMPUTE §3.1")
	r.Declare("handler_op_install", "COMPUTE §3.1")
	r.Declare("handler_op_uninstall", "COMPUTE §3.1")

	// Type registration.
	r.Declare("types_expression", "COMPUTE §2.1")
	r.Declare("types_inline", "COMPUTE §2.2")
	r.Declare("types_value", "COMPUTE §2.3")
	r.Declare("types_result_error", "COMPUTE §2.4")
	r.Declare("types_subgraph", "COMPUTE §2.5")

	// Deterministic result checks — literals.
	r.Declare("eval_literal_int", "COMPUTE §4.1")
	r.Declare("eval_literal_string", "COMPUTE §4.1")
	r.Declare("eval_literal_bool", "COMPUTE §4.1")

	// Deterministic result checks — arithmetic.
	r.Declare("eval_arithmetic_add", "COMPUTE §2.2, §8.1")
	r.Declare("eval_arithmetic_sub", "COMPUTE §2.2, §8.1")
	r.Declare("eval_arithmetic_mul", "COMPUTE §2.2, §8.1")
	r.Declare("eval_arithmetic_div_exact", "COMPUTE §2.2, §8.1")
	r.Declare("eval_arithmetic_div_float", "COMPUTE §2.2, §8.1")
	r.Declare("eval_arithmetic_mod", "COMPUTE §2.2, §8.1")
	r.Declare("eval_division_by_zero", "COMPUTE §9.1")

	// Deterministic result checks — comparison.
	r.Declare("eval_compare_eq_true", "COMPUTE §2.2, §8.1")
	r.Declare("eval_compare_eq_false", "COMPUTE §2.2, §8.1")
	r.Declare("eval_compare_lt", "COMPUTE §2.2, §8.1")
	r.Declare("eval_compare_neq", "COMPUTE §2.2, §8.1")

	// Deterministic result checks — logic.
	r.Declare("eval_logic_and", "COMPUTE §2.2, §8.1")
	r.Declare("eval_logic_or", "COMPUTE §2.2, §8.1")
	r.Declare("eval_logic_not", "COMPUTE §2.2, §8.1")

	// Deterministic result checks — if/let/lambda.
	r.Declare("eval_if_true_branch", "COMPUTE §2.1, §8.1")
	r.Declare("eval_if_false_branch", "COMPUTE §2.1, §8.1")
	r.Declare("eval_let_sequential", "COMPUTE §2.1, §8.2")
	r.Declare("eval_lambda_apply", "COMPUTE §2.1, §8.1")

	// Lookup.
	r.Declare("eval_lookup_scope", "COMPUTE §2.1")
	r.Declare("eval_lookup_tree_non_expr", "COMPUTE §2.1")
	r.Declare("eval_lookup_tree_evaluates_expr", "COMPUTE §2.1")

	// Construct + canonical ordering.
	r.Declare("eval_construct_deterministic", "COMPUTE §2.2, §8.2")
	r.Declare("eval_construct_field_extract", "COMPUTE §2.2")

	// Closure captures outer scope.
	r.Declare("eval_closure_captures_scope", "COMPUTE §4.4")

	// If short-circuit — non-taken branch must not be evaluated.
	r.Declare("eval_if_short_circuit", "COMPUTE §2.1")

	// Budget and depth enforcement.
	r.Declare("eval_depth_limit", "COMPUTE §5.4")

	// Error propagation.
	r.Declare("eval_error_propagation", "COMPUTE §7.2")

	// Error codes.
	r.Declare("eval_error_not_found", "COMPUTE §9.1")
	r.Declare("eval_error_non_expression", "COMPUTE §4.7")

	// v3.6 A1–A4: Normative arithmetic test vectors.
	r.Declare("v36_div_negative", "COMPUTE §2.2 A3")
	r.Declare("v36_div_repeating", "COMPUTE §2.2 A3")
	r.Declare("v36_mod_neg_dividend", "COMPUTE §2.2 A4")
	r.Declare("v36_mod_neg_divisor", "COMPUTE §2.2 A4")
	r.Declare("v36_mod_both_neg", "COMPUTE §2.2 A4")
	r.Declare("v36_add_mixed_float", "COMPUTE §2.2 A1")
	r.Declare("v36_eq_cross_type", "COMPUTE §2.2 A2")
	r.Declare("v36_eq_incompatible", "COMPUTE §2.2 A2")
	r.Declare("v36_lt_string", "COMPUTE §2.2 A2")
	r.Declare("v36_lt_type_mismatch", "COMPUTE §2.2 A2")

	// v3.6 D2: Expression-graph scoping (content store oracle).
	r.Declare("v36_resolve_rejects_non_compute", "COMPUTE §4.2 D2")

	// v3.7 D6: compute/lookup/hash — pure data access.
	r.Declare("v37_lookup_hash_type_registered", "COMPUTE §2.1 D6")
	r.Declare("v37_lookup_hash_eval", "COMPUTE §4.1 D6")
	r.Declare("v37_lookup_hash_field_extract", "COMPUTE §4.1 D6")

	// v3.8 T2/T3: Tail call optimization — tail positions don't consume depth.
	r.Declare("v38_tco_if_chain", "COMPUTE §4.1 T2/T3")
	r.Declare("v38_tco_let_chain", "COMPUTE §4.1 T2/T3")

	// v3.8 R1/R2: Relative paths for transferable compute.
	r.Declare("v38_relative_lookup_tree", "COMPUTE §2.1 R1/R2")

	// v3.8 T3: Non-tail depth still enforced (heavy — runs last among v3.8 checks).
	r.Declare("v38_depth_non_tail", "COMPUTE §5.4 T3")

	// Algorithm: recursive fibonacci via tree self-reference.
	r.Declare("algo_fibonacci_5", "COMPUTE §4.1, §8.1")
	r.Declare("algo_fibonacci_10", "COMPUTE §4.1, §8.1")

	// Reactive spreadsheet: install, verify, change dependency, verify update.
	r.Declare("reactive_install", "COMPUTE §3.3, §7.1")
	r.Declare("reactive_initial_result", "COMPUTE §7.2")
	r.Declare("reactive_update_dependency", "COMPUTE §7.2")
	r.Declare("reactive_converged_result", "COMPUTE §7.2")
	r.Declare("reactive_second_update", "COMPUTE §7.2")
	r.Declare("reactive_final_result", "COMPUTE §7.2")

	// v3.8 Dynamic handlers — installed compute subgraphs as callable functions.
	r.Declare("v38_tco_sum_2000", "COMPUTE §4.1 T2/T3")
	r.Declare("v38_newton_sqrt", "COMPUTE §4.1 T2/T3")
	r.Declare("v38_apply_handler_mode", "COMPUTE §4.1, §3.1")
	r.Declare("v38_dynamic_handler", "COMPUTE §7.2, §4.1")
	r.Declare("v38_dynamic_handler_swap", "COMPUTE §7.2, §4.1")
	r.Declare("v38_cascade_chain", "COMPUTE §7.2, §7.3")

	// v3.10 compute/apply resource ceiling (PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING).
	r.Declare("v310_apply_resource_field_accepted", "COMPUTE §2.1 F1")
	r.Declare("v310_f5_eval_capability_without_resource", "COMPUTE §4.1 F5")
	r.Declare("v310_f5_install_capability_without_resource", "COMPUTE §3.3 F5")

	// PROPOSAL-COHERENT-CAPABILITY-AUTHORITY §10 conformance vectors.
	r.Declare("cp1_install_static_literal_adversary_rejected", "COHERENT-CAP §6.1")
	r.Declare("cp1_install_static_literal_self_issued_accepted", "COHERENT-CAP §6.1")
	r.Declare("cp1_install_dynamic_capability_deferred", "COHERENT-CAP §6.1")

	// v3.14 standard-IR floor (PROPOSAL-COMPUTE-STANDARD-IR-FLOOR).
	// N.1: compute/index, compute/length (§2.2).
	r.Declare("v314_index_basic", "COMPUTE §2.2 N.1")
	r.Declare("v314_index_negative", "COMPUTE §2.2 N.1")
	r.Declare("v314_index_past_end", "COMPUTE §2.2 N.1")
	r.Declare("v314_index_type_mismatch", "COMPUTE §2.2 N.1")
	r.Declare("v314_length_empty", "COMPUTE §2.2 N.1")
	r.Declare("v314_length_nonempty", "COMPUTE §2.2 N.1")
	r.Declare("v314_length_type_mismatch", "COMPUTE §2.2 N.1")

	// v3.16 §2.2 rules 8-11: sign-agnostic add/sub/mul, signed-default
	// div/mod/compare, signed-canonical wire encoding, eager numeric-cast.
	r.Declare("v316_sign_agnostic_add", "COMPUTE §2.2 rule 8 (v3.16)")
	r.Declare("v316_uint_wraparound_add", "COMPUTE §2.2 rule 8 (v3.16)")
	r.Declare("v316_int_wraparound_add", "COMPUTE §2.2 rule 8 (v3.16)")
	r.Declare("v316_signed_canonical_encoding", "COMPUTE §2.2 rule 10 (v3.16 A.5)")
	r.Declare("v316_eager_cast_unsigned_div", "COMPUTE §2.2 rule 11 (v3.16 A.6)")
	r.Declare("v316_eager_cast_not_through_let", "COMPUTE §2.2 rule 11 (v3.16 A.6)")
	r.Declare("v316_uint_round_trip", "COMPUTE §2.2 rule 10 + SA-7 (v3.16, realization confirm)")

	// v3.17 rule 11 Option A (SA-AMD3-1) — enumerated strip points: cast
	// intent does NOT flow through `if`, `lookup/scope`, `construct`, or
	// closure-arg binding (in addition to `let`, already covered above).
	// Each must produce signed-default on a value with bit 63 set.
	r.Declare("v317_cast_through_if_branch", "COMPUTE §2.2 rule 11 (v3.17 SA-AMD3-1)")
	r.Declare("v317_cast_through_lookup_scope", "COMPUTE §2.2 rule 11 (v3.17 SA-AMD3-1)")
	r.Declare("v317_cast_through_closure_arg", "COMPUTE §2.2 rule 11 (v3.17 SA-AMD3-1)")

	// N.4: compute/numeric-cast (§2.2).
	r.Declare("v314_cast_int_to_uint_negative", "COMPUTE §2.2 N.4")
	r.Declare("v314_cast_float_truncate", "COMPUTE §2.2 N.4")
	r.Declare("v314_cast_nan_to_int", "COMPUTE §9.1 cast_out_of_range")
	r.Declare("v314_cast_inf_to_int", "COMPUTE §9.1 cast_out_of_range")
	r.Declare("v314_cast_neg_float_to_uint", "COMPUTE §9.1 cast_out_of_range")
	r.Declare("v314_cast_to_invalid_type", "COMPUTE §2.2 N.4")

	// N.2: pinned args types for collection builtins + store (§3.5).
	r.Declare("v314_args_types_registered", "COMPUTE §3.5 N.2")

	// N.2: builtin handler dispatches as aliases for the inline form (§3.5).
	r.Declare("v314_builtin_arithmetic_alias", "COMPUTE §3.5 N.2")
	r.Declare("v314_builtin_map", "COMPUTE §3.5 §962 N.2")
	r.Declare("v314_builtin_filter", "COMPUTE §3.5 §962 N.2")
	r.Declare("v314_builtin_fold", "COMPUTE §3.5 §962 N.2")
	r.Declare("v314_builtin_fold_empty", "COMPUTE §3.5 §962 N.2")

	// Cross-cutting: v3.14 compute interacts with entity-native dispatch.
	r.Declare("v314_builtin_store_roundtrip", "COMPUTE §3.5 §6.3 + V7 §6.6")
	r.Declare("v314_compute_apply_to_entity_native", "COMPUTE §2.1 + V7 §6.6 + PROPOSAL-DISPATCH A.1")

	// v3.19 conformance vectors (PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE).
	// N.5 — navigation composes; F10 — evaluated compute/error returns status 200;
	// F11 — filter-args lambda key is `fn`. These five vectors are the cross-impl
	// gate: a v3.19-aligned peer MUST pass them; pre-fix impls (Rust/Python
	// pending) will fail one or more in expected ways (status pin, arg-key
	// lookup miss, navigation rejection).
	r.Declare("v319_n5_nested_field", "COMPUTE N.5 (v3.19)")
	r.Declare("v319_n5_closure_field", "COMPUTE N.5 (v3.19) — closure-captured-param navigation; tracks F9-B-residual (scope-binding identity spec fork)")
	r.Declare("v319_n5_compute_compose", "COMPUTE N.5 (v3.19)")
	r.Declare("v319_n5_disambiguation", "COMPUTE N.5 (v3.19) — record whose keys happen to be {type, data, name} navigates as a record, NOT envelope-peeled; cross-impl disambiguation gate (Python heuristic vs Go flat-read)")
	r.Declare("v319_f10_error_at_200", "COMPUTE F10 (v3.19) — strict status-200 pin for evaluated compute/error")
	r.Declare("v319_f11_filter_fn_arg", "COMPUTE F11 (v3.19) — filter-args lambda key renamed predicate → fn")

	// v3.19b CORE conformance vectors (PROPOSAL §5b; EXTENSION-COMPUTE v3.19b §2.3).
	// Same-peer kind-tagged scope round-trip (N1 + N4 — load_scope rides the
	// closure's authorization; binding entities resolve via direct content-store
	// access). Missing-binding produces compute/error{scope_unreachable} at
	// status 200 (N8 + F10 error-as-value).
	r.Declare("v319b_scope_entity_round_trip", "COMPUTE v3.19b §2.3 N1+N3+N4 — kind-tagged scope binding round-trip; entity captured into scope survives capture/load + field-navigates .data")
	r.Declare("v319b_scope_unreachable", "COMPUTE v3.19b §2.3 N8 + F10 — a kind:entity binding whose hash doesn't resolve yields compute/error{scope_unreachable} at status 200")
	r.Declare("v319b_scope_hash_agreement", "COMPUTE v3.19b N2 — captures a fixed-content scope and prints the resulting compute/scope content_hash; cross-impl hashes must agree bit-for-bit (the N2 ratification gate)")
	r.Declare("v319c_construct_entity_valued_field", "COMPUTE v3.19c Part A R3 — M1 hash-gate: a compute/construct with an entity-valued field MUST produce a content_hash byte-identical to entity.NewEntity-built form (per V7 §1.4 bare system/hash refs). Cross-impl three-way agreement on the materialized form is the ratification gate.")
	r.Declare("v319c_construct_navigation_chain", "COMPUTE v3.19c Part A R3 — in-flight navigation composes through constructed entities. field(field(construct(app/wrapper,{inner:construct(app/user,{name:'alice'})}),'inner'),'name') → 'alice'. The whole chain evaluates within a single compute eval (typed in-flight values, no boundary materialization between hops).")
	r.Declare("v319c_inline_vs_builtin_construct_hash_agreement", "COMPUTE v3.19c Part A R3 — adopted from Rust's catch: build the same construct two ways (inline compute/construct expression AND system/compute/builtins/construct handler-form alias). Materialized content_hashes MUST match. Catches the duplicate-path bug class Rust hit; Go's single path (builtins.go::builtinConstruct delegates to inline evalConstruct) passes trivially.")
	r.Declare("v319c_readback_navigation_returns_hash", "COMPUTE v3.19c Part A R3 + N3 (arch 6e73d3d read-back ruling) — cross-impl regression detector. Read-back nav of a system/hash field on a *materialized* (stored / hand-built) entity MUST return the bare hash bytes, NOT auto-resolve to the referenced entity. The caller follows the ref via explicit compute/lookup/hash. No shape-sniffing, no 'N-byte = entity ref' heuristic (N3 forbids it; per V7 §1.2 the hash length itself isn't an invariant — system/hash is variable-length with an extensible LEB128 format-code). An auto-resolved Entity result means a heuristic snuck back in.")

	// --- Run checks ---

	peerID := string(client.RemotePeerID())
	tp := "system/validate/compute-test"

	// Step 1: Handler manifest.

	r.Run("handler_present", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/compute")
		if err != nil {
			return FailCheck("failed to fetch compute handler manifest: " + err.Error())
		}
		r.Store("manifest_entity", ent)
		return PassCheck(fmt.Sprintf("compute handler manifest present (type: %s)", ent.Type))
	})

	r.Run("handler_manifest_decode", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		ent := r.Load("manifest_entity").(entity.Entity)
		handlerData, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode handler manifest: " + err.Error())
		}
		r.Store("handler_data", handlerData)
		return PassCheck("handler manifest decoded")
	})

	for _, op := range []string{"eval", "install", "uninstall"} {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			handlerData := r.Load("handler_data").(types.HandlerInterfaceData)
			if _, exists := handlerData.Operations[op]; !exists {
				return FailCheck("compute handler missing operation: " + op)
			}
			return PassCheck("compute handler has operation: " + op)
		})
	}

	// Step 2: Type registration.

	r.Run("types_expression", func() CheckOutcome {
		for _, t := range []string{
			types.TypeComputeLiteral, types.TypeComputeLookupScope, types.TypeComputeLookupTree,
			types.TypeComputeApply, types.TypeComputeIf, types.TypeComputeLet, types.TypeComputeLambda,
		} {
			if _, _, err := client.TreeGet(ctx, "system/type/"+t); err != nil {
				return FailCheck("expression type not registered: " + t)
			}
		}
		return PassCheck("all 7 core expression types registered")
	})

	r.Run("types_inline", func() CheckOutcome {
		// EXTENSION-COMPUTE v3.14 §2.2 + §10.1 — eight inline types.
		// N.1 added compute/index and compute/length; N.4 added compute/numeric-cast.
		for _, t := range []string{
			types.TypeComputeArithmetic, types.TypeComputeCompare, types.TypeComputeLogic,
			types.TypeComputeField, types.TypeComputeConstruct,
			types.TypeComputeIndex, types.TypeComputeLength, types.TypeComputeNumericCast,
		} {
			if _, _, err := client.TreeGet(ctx, "system/type/"+t); err != nil {
				return FailCheck("inline type not registered: " + t)
			}
		}
		return PassCheck("all 8 inline expression types registered")
	})

	r.Run("types_value", func() CheckOutcome {
		for _, t := range []string{types.TypeComputeClosure, types.TypeComputeScope} {
			if _, _, err := client.TreeGet(ctx, "system/type/"+t); err != nil {
				return FailCheck("value type not registered: " + t)
			}
		}
		return PassCheck("value types (closure, scope) registered")
	})

	r.Run("types_result_error", func() CheckOutcome {
		for _, t := range []string{types.TypeComputeResult, types.TypeComputeError} {
			if _, _, err := client.TreeGet(ctx, "system/type/"+t); err != nil {
				return FailCheck("type not registered: " + t)
			}
		}
		return PassCheck("result and error types registered")
	})

	r.Run("types_subgraph", func() CheckOutcome {
		if _, _, err := client.TreeGet(ctx, "system/type/"+types.TypeComputeSubgraph); err != nil {
			return FailCheck("subgraph type not registered")
		}
		return PassCheck("subgraph metadata type registered")
	})

	// Step 3: Deterministic literal evaluation.

	r.Run("eval_literal_int", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalAndExtractValue(ctx, client, peerID, tp+"/lit-int",
			types.ComputeLiteralData{Value: uint64(42)})
		if err != nil {
			return FailCheck("eval literal int: " + err.Error())
		}
		if !numEq(val, 42) {
			return FailCheck(fmt.Sprintf("eval literal int: expected 42, got %v (%T)", val, val))
		}
		return PassCheck("eval literal int=42 → 42")
	})

	r.Run("eval_literal_string", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalAndExtractValue(ctx, client, peerID, tp+"/lit-str",
			types.ComputeLiteralData{Value: "hello"})
		if err != nil {
			return FailCheck("eval literal string: " + err.Error())
		}
		if val != "hello" {
			return FailCheck(fmt.Sprintf("eval literal string: expected 'hello', got %v", val))
		}
		return PassCheck("eval literal string='hello' → 'hello'")
	})

	r.Run("eval_literal_bool", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalAndExtractValue(ctx, client, peerID, tp+"/lit-bool",
			types.ComputeLiteralData{Value: true})
		if err != nil {
			return FailCheck("eval literal bool: " + err.Error())
		}
		if val != true {
			return FailCheck(fmt.Sprintf("eval literal bool: expected true, got %v", val))
		}
		return PassCheck("eval literal bool=true → true")
	})

	// Step 4: Deterministic arithmetic.

	arithTests := []struct {
		name           string
		op             string
		left, right    uint64
		expectInt      bool
		expectIntVal   int64
		expectFloatVal float64
	}{
		{"eval_arithmetic_add", "add", 3, 4, true, 7, 0},
		{"eval_arithmetic_sub", "sub", 10, 3, true, 7, 0},
		{"eval_arithmetic_mul", "mul", 5, 6, true, 30, 0},
		{"eval_arithmetic_div_exact", "div", 10, 2, true, 5, 0},
		{"eval_arithmetic_mod", "mod", 10, 3, true, 1, 0},
	}

	for _, tt := range arithTests {
		tt := tt
		r.Run(tt.name, func() CheckOutcome {
			if out, ok := r.Require("handler_present"); !ok {
				return out
			}
			val, err := computeEvalBinaryOp(ctx, client, peerID, tp, tt.name,
				types.TypeComputeArithmetic, tt.op, uint64(tt.left), uint64(tt.right))
			if err != nil {
				return FailCheck(fmt.Sprintf("eval %s: %v", tt.op, err))
			}
			if !numEq(val, float64(tt.expectIntVal)) {
				return FailCheck(fmt.Sprintf("eval %s(%d,%d): expected %d, got %v (%T)",
					tt.op, tt.left, tt.right, tt.expectIntVal, val, val))
			}
			return PassCheck(fmt.Sprintf("eval %s(%d,%d) → %d", tt.op, tt.left, tt.right, tt.expectIntVal))
		})
	}

	r.Run("eval_arithmetic_div_float", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "div-float",
			types.TypeComputeArithmetic, "div", uint64(7), uint64(2))
		if err != nil {
			return FailCheck("eval div float: " + err.Error())
		}
		if !numEq(val, 3.5) {
			return FailCheck(fmt.Sprintf("eval div(7,2): expected 3.5, got %v (%T)", val, val))
		}
		return PassCheck("eval div(7,2) → 3.5")
	})

	r.Run("eval_division_by_zero", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		errCode, err := computeEvalExpectError(ctx, client, peerID, tp, "div-zero",
			types.TypeComputeArithmetic, "div", uint64(1), uint64(0))
		if err != nil {
			return FailCheck("eval div/0: " + err.Error())
		}
		if errCode != "division_by_zero" {
			return FailCheck(fmt.Sprintf("eval div/0: expected error code division_by_zero, got %s", errCode))
		}
		return PassCheck("eval div(1,0) → compute/error{code: division_by_zero}")
	})

	// Step 5: Deterministic comparison.

	r.Run("eval_compare_eq_true", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "cmp-eq-t",
			types.TypeComputeCompare, "eq", uint64(5), uint64(5))
		if err != nil {
			return FailCheck("eval eq: " + err.Error())
		}
		if val != true {
			return FailCheck(fmt.Sprintf("eval eq(5,5): expected true, got %v", val))
		}
		return PassCheck("eval eq(5,5) → true")
	})

	r.Run("eval_compare_eq_false", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "cmp-eq-f",
			types.TypeComputeCompare, "eq", uint64(5), uint64(6))
		if err != nil {
			return FailCheck("eval eq: " + err.Error())
		}
		if val != false {
			return FailCheck(fmt.Sprintf("eval eq(5,6): expected false, got %v", val))
		}
		return PassCheck("eval eq(5,6) → false")
	})

	r.Run("eval_compare_lt", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "cmp-lt",
			types.TypeComputeCompare, "lt", uint64(3), uint64(5))
		if err != nil {
			return FailCheck("eval lt: " + err.Error())
		}
		if val != true {
			return FailCheck(fmt.Sprintf("eval lt(3,5): expected true, got %v", val))
		}
		return PassCheck("eval lt(3,5) → true")
	})

	r.Run("eval_compare_neq", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "cmp-neq",
			types.TypeComputeCompare, "neq", uint64(3), uint64(5))
		if err != nil {
			return FailCheck("eval neq: " + err.Error())
		}
		if val != true {
			return FailCheck(fmt.Sprintf("eval neq(3,5): expected true, got %v", val))
		}
		return PassCheck("eval neq(3,5) → true")
	})

	// Step 6: Deterministic logic.

	r.Run("eval_logic_and", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "logic-and",
			types.TypeComputeLogic, "and", true, true)
		if err != nil {
			return FailCheck("eval and: " + err.Error())
		}
		if val != true {
			return FailCheck(fmt.Sprintf("eval and(true,true): expected true, got %v", val))
		}
		return PassCheck("eval and(true,true) → true")
	})

	r.Run("eval_logic_or", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "logic-or",
			types.TypeComputeLogic, "or", false, true)
		if err != nil {
			return FailCheck("eval or: " + err.Error())
		}
		if val != true {
			return FailCheck(fmt.Sprintf("eval or(false,true): expected true, got %v", val))
		}
		return PassCheck("eval or(false,true) → true")
	})

	r.Run("eval_logic_not", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalUnaryLogic(ctx, client, peerID, tp, true)
		if err != nil {
			return FailCheck("eval not: " + err.Error())
		}
		if val != false {
			return FailCheck(fmt.Sprintf("eval not(true): expected false, got %v", val))
		}
		return PassCheck("eval not(true) → false")
	})

	// Step 7: Deterministic if/let/lambda with value checks.

	r.Run("eval_if_true_branch", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalIfExpr(ctx, client, peerID, tp, true, "yes", "no")
		if err != nil {
			return FailCheck("eval if(true): " + err.Error())
		}
		if val != "yes" {
			return FailCheck(fmt.Sprintf("eval if(true,'yes','no'): expected 'yes', got %v", val))
		}
		return PassCheck("eval if(true,'yes','no') → 'yes'")
	})

	r.Run("eval_if_false_branch", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalIfExpr(ctx, client, peerID, tp, false, "yes", "no")
		if err != nil {
			return FailCheck("eval if(false): " + err.Error())
		}
		if val != "no" {
			return FailCheck(fmt.Sprintf("eval if(false,'yes','no'): expected 'no', got %v", val))
		}
		return PassCheck("eval if(false,'yes','no') → 'no'")
	})

	r.Run("eval_let_sequential", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// let x=5, y=x+1 in y → 6
		val, err := computeEvalLetSequential(ctx, client, peerID, tp)
		if err != nil {
			return FailCheck("eval let sequential: " + err.Error())
		}
		if !numEq(val, 6) {
			return FailCheck(fmt.Sprintf("eval let x=5, y=x+1 in y: expected 6, got %v (%T)", val, val))
		}
		return PassCheck("eval let x=5, y=x+1 in y → 6")
	})

	r.Run("eval_lambda_apply", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// let f = lambda(a): a+1 in f(10) → 11
		val, err := computeEvalLambdaApply(ctx, client, peerID, tp)
		if err != nil {
			return FailCheck("eval lambda apply: " + err.Error())
		}
		if !numEq(val, 11) {
			return FailCheck(fmt.Sprintf("eval lambda(a):a+1 applied to 10: expected 11, got %v (%T)", val, val))
		}
		return PassCheck("eval lambda(a):a+1 applied to 10 → 11")
	})

	// Step 8: Lookup.

	r.Run("eval_lookup_scope", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// let x=42 in lookup/scope("x") → 42
		val, err := computeEvalLookupScopeExpr(ctx, client, peerID, tp)
		if err != nil {
			return FailCheck("eval lookup/scope: " + err.Error())
		}
		if !numEq(val, 42) {
			return FailCheck(fmt.Sprintf("eval lookup/scope: expected 42, got %v", val))
		}
		return PassCheck("eval let x=42 in lookup/scope('x') → 42")
	})

	r.Run("eval_lookup_tree_non_expr", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		valuePath := tp + "/tree-val"
		raw, _ := ecf.Encode(map[string]interface{}{"name": "test-data"})
		valueEnt, _ := entity.NewEntity("app/test-data", cbor.RawMessage(raw))
		if _, err := client.TreePut(ctx, valuePath, valueEnt); err != nil {
			return FailCheck("put test value failed: " + err.Error())
		}
		qualPath := fmt.Sprintf("/%s/%s", peerID, valuePath)
		resultEnt, err := computeEvalLookupTreeEntity(ctx, client, peerID, tp, qualPath)
		if err != nil {
			return FailCheck("eval lookup/tree: " + err.Error())
		}
		if resultEnt.Type != "app/test-data" {
			return FailCheck(fmt.Sprintf("lookup/tree returned type %s, expected app/test-data", resultEnt.Type))
		}
		return PassCheck("eval lookup/tree of non-expression → returned entity as-is")
	})

	r.Run("eval_lookup_tree_evaluates_expr", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		exprPath := tp + "/tree-expr"
		litEnt, _ := types.ComputeLiteralData{Value: uint64(99)}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, litEnt); err != nil {
			return FailCheck("put expression failed: " + err.Error())
		}
		qualPath := fmt.Sprintf("/%s/%s", peerID, exprPath)
		val, err := computeEvalLookupTreeValue(ctx, client, peerID, tp, qualPath)
		if err != nil {
			return FailCheck("eval lookup/tree (expression): " + err.Error())
		}
		if !numEq(val, 99) {
			return FailCheck(fmt.Sprintf("lookup/tree of literal(99): expected 99, got %v", val))
		}
		return PassCheck("eval lookup/tree of compute/literal(99) → 99 (spreadsheet semantic)")
	})

	// Step 9: Construct + canonical ordering.
	// Build construct with fields "bb", "a", "ccc" — ECF order: "a"(1), "bb"(2), "ccc"(3).
	// All peers must produce the same content hash for the constructed entity.

	r.Run("eval_construct_deterministic", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		resultEnt, err := computeEvalConstructMultiField(ctx, client, peerID, tp)
		if err != nil {
			return FailCheck("eval construct: " + err.Error())
		}
		if resultEnt.Type != "app/test-construct" {
			return FailCheck(fmt.Sprintf("construct type: expected app/test-construct, got %s", resultEnt.Type))
		}
		r.Store("construct_hash", resultEnt.ContentHash)
		// v3.19c Part A R3: the materialized constructed entity is BARE per
		// M1 / V7 §1.4 — fields are inlined bare values (primitive/record)
		// or bare system/hash refs (entity-kind). No kind tags in wire data.
		// This is the same shape entity.NewEntity produces.
		var fields map[string]interface{}
		if err := ecf.Decode(resultEnt.Data, &fields); err != nil {
			return FailCheck("construct: failed to decode fields: " + err.Error())
		}
		if fields["a"] != "alpha" || fields["bb"] != "beta" || fields["ccc"] != "gamma" {
			return FailCheck(fmt.Sprintf("construct fields mismatch: %v", fields))
		}
		return PassCheck(fmt.Sprintf("eval construct{a,bb,ccc} → deterministic hash %s (v3.19c R3 bare materialized fields)", resultEnt.ContentHash))
	})

	// Field extraction from the constructed entity.
	r.Run("eval_construct_field_extract", func() CheckOutcome {
		if out, ok := r.Require("eval_construct_deterministic"); !ok {
			return out
		}
		val, err := computeEvalFieldExtract(ctx, client, peerID, tp)
		if err != nil {
			return FailCheck("eval field extract: " + err.Error())
		}
		if val != "beta" {
			return FailCheck(fmt.Sprintf("field('bb', construct): expected 'beta', got %v", val))
		}
		return PassCheck("eval field('bb', construct{a,bb,ccc}) → 'beta'")
	})

	// Step 10: Closure captures outer scope.
	// let x = 100 in (let f = lambda(a): a + x in f(5)) → 105

	r.Run("eval_closure_captures_scope", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalClosureCapturesScope(ctx, client, peerID, tp)
		if err != nil {
			return FailCheck("eval closure scope capture: " + err.Error())
		}
		if !numEq(val, 105) {
			return FailCheck(fmt.Sprintf("let x=100 in (let f=lambda(a):a+x in f(5)): expected 105, got %v", val))
		}
		return PassCheck("eval closure captures outer scope: let x=100 in lambda(a):a+x applied to 5 → 105")
	})

	// Step 10b: If short-circuit — non-taken branch must not evaluate.
	// if(true, 42, lookup/tree("nonexistent")) → 42 (else branch not evaluated).

	r.Run("eval_if_short_circuit", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		condEnt, _ := types.ComputeLiteralData{Value: true}.ToEntity()
		thenEnt, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		condHash := putCE(ctx, client, tp+"/sc-cond", condEnt)
		thenHash := putCE(ctx, client, tp+"/sc-then", thenEnt)
		// Else branch: lookup/tree to nonexistent path — would error if evaluated.
		nonexistent := fmt.Sprintf("/%s/%s/shortcircuit-missing-%d", peerID, tp, 777777)
		elseExpr, _ := types.ComputeLookupTreeData{Path: nonexistent}.ToEntity()
		elseHash := putCE(ctx, client, tp+"/sc-else", elseExpr)
		ifEnt, _ := types.ComputeIfData{Condition: condHash, Then: thenHash, Else: &elseHash}.ToEntity()
		path := tp + "/if-shortcircuit"
		if _, err := client.TreePut(ctx, path, ifEnt); err != nil {
			return FailCheck("put if-shortcircuit: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("if short-circuit: " + err.Error() + " (else branch may have been evaluated)")
		}
		if !numEq(val, 42) {
			return FailCheck(fmt.Sprintf("if(true, 42, error-branch): expected 42, got %v", val))
		}
		return PassCheck("if(true, 42, lookup/tree(nonexistent)) → 42 (else branch not evaluated)")
	})

	// Step 10c: Depth limit — nested expression exceeding depth should error.

	r.Run("eval_depth_limit", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Build a nested if chain: if(true, if(true, if(true, ... 42 ...)))
		// Each if nesting adds eval depth. Use 600 levels — above recommended
		// max depth of 1024 when counting sub-expression evaluations (~3 per if).
		// All entities share the same condition (true literal) to minimize puts.
		condEnt, _ := types.ComputeLiteralData{Value: true}.ToEntity()
		condHash := putCE(ctx, client, tp+"/depth-cond", condEnt)
		innerEnt, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		currentHash := putCE(ctx, client, tp+"/depth-inner", innerEnt)
		for i := 0; i < 600; i++ {
			ifEnt, _ := types.ComputeIfData{Condition: condHash, Then: currentHash}.ToEntity()
			currentHash = putCE(ctx, client, fmt.Sprintf("%s/depth-%d", tp, i), ifEnt)
		}
		depthPath := tp + "/depth-test"
		outerIf, _ := types.ComputeIfData{Condition: condHash, Then: currentHash}.ToEntity()
		if _, err := client.TreePut(ctx, depthPath, outerIf); err != nil {
			return FailCheck("put depth test: " + err.Error())
		}
		resp, err := computeEvalAtPath(ctx, client, peerID, depthPath)
		if err != nil {
			return FailCheck("depth test request failed: " + err.Error())
		}
		// v3.19 F10: depth-exceeded is a compute/error that may surface at 200.
		// Treat "200 with non-error result" as the only true success path.
		if resp.Status == 200 {
			if resultEnt, decErr := decodeComputeEntity(resp); decErr == nil && resultEnt.Type != types.TypeComputeError {
				return WarnCheck("depth test succeeded at 601 nested ifs — peer may have higher depth limit")
			}
		}
		return PassCheck(fmt.Sprintf("deeply nested expression rejected (status %d / compute/error)", resp.Status))
	})

	// Step 11: Error propagation.
	// add(1, lookup/tree("nonexistent")) → compute/error propagates through add.

	r.Run("eval_error_propagation", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		errCode, err := computeEvalErrorPropagation(ctx, client, peerID, tp)
		if err != nil {
			return FailCheck("eval error propagation: " + err.Error())
		}
		if errCode != "not_found" {
			return FailCheck(fmt.Sprintf("error propagation: expected not_found, got %s", errCode))
		}
		return PassCheck("eval add(1, lookup/tree(nonexistent)) → not_found error propagated through arithmetic")
	})

	// Step 12: Error codes.

	r.Run("eval_error_not_found", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		nonexistent := fmt.Sprintf("/%s/%s/does-not-exist-%d", peerID, tp, 999999)
		errCode, err := computeEvalLookupTreeError(ctx, client, peerID, tp, nonexistent)
		if err != nil {
			return FailCheck("eval not_found: " + err.Error())
		}
		if errCode != "not_found" {
			return FailCheck(fmt.Sprintf("lookup/tree nonexistent: expected not_found, got %s", errCode))
		}
		return PassCheck("eval lookup/tree(nonexistent) → compute/error{code: not_found}")
	})

	r.Run("eval_error_non_expression", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		path := tp + "/non-expr"
		raw, _ := ecf.Encode(map[string]interface{}{"x": 1})
		nonExprEnt, _ := entity.NewEntity("app/not-compute", cbor.RawMessage(raw))
		if _, err := client.TreePut(ctx, path, nonExprEnt); err != nil {
			return FailCheck("put non-expression: " + err.Error())
		}
		resp, err := computeEvalAtPath(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval non-expression: " + err.Error())
		}
		if resp.Status == 200 {
			return FailCheck("eval of non-expression should not return 200")
		}
		return PassCheck(fmt.Sprintf("eval of non-expression entity → rejected with status %d", resp.Status))
	})

	// Step 13: v3.6 A1–A4 test vectors.

	r.Run("v36_div_negative", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// v3.16 §2.2 rule 9: div is signed-default; rule 8 makes arithmetic
		// sign-agnostic so mixed-sign literals work directly — no cast needed.
		// (v3.14/v3.15 required cast-wrappings here per the now-removed rule 9.)
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-div-neg",
			types.TypeComputeArithmetic, "div", int64(-7), int64(2))
		if err != nil {
			return FailCheck("div(-7,2): " + err.Error())
		}
		if !numEq(val, -3.5) {
			return FailCheck(fmt.Sprintf("div(-7,2): expected -3.5, got %v (%T)", val, val))
		}
		return PassCheck("div(-7,2) → -3.5")
	})

	r.Run("v36_div_repeating", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-div-rep",
			types.TypeComputeArithmetic, "div", uint64(1), uint64(3))
		if err != nil {
			return FailCheck("div(1,3): " + err.Error())
		}
		if !numEq(val, 1.0/3.0) {
			return FailCheck(fmt.Sprintf("div(1,3): expected ~0.333..., got %v (%T)", val, val))
		}
		return PassCheck("div(1,3) → 0.333... (IEEE 754)")
	})

	r.Run("v36_mod_neg_dividend", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// v3.16: signed-default mod (rule 9); no cast needed — mixed-sign
		// literals work directly under rule 8 sign-agnosticism.
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-mod-neg-a",
			types.TypeComputeArithmetic, "mod", int64(-7), int64(3))
		if err != nil {
			return FailCheck("mod(-7,3): " + err.Error())
		}
		if !numEq(val, -1) {
			return FailCheck(fmt.Sprintf("mod(-7,3): expected -1 (truncated), got %v (%T)", val, val))
		}
		return PassCheck("mod(-7,3) → -1 (truncated remainder)")
	})

	r.Run("v36_mod_neg_divisor", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-mod-neg-b",
			types.TypeComputeArithmetic, "mod", int64(7), int64(-3))
		if err != nil {
			return FailCheck("mod(7,-3): " + err.Error())
		}
		if !numEq(val, 1) {
			return FailCheck(fmt.Sprintf("mod(7,-3): expected 1 (truncated), got %v (%T)", val, val))
		}
		return PassCheck("mod(7,-3) → 1 (truncated remainder)")
	})

	r.Run("v36_mod_both_neg", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-mod-neg-ab",
			types.TypeComputeArithmetic, "mod", int64(-7), int64(-3))
		if err != nil {
			return FailCheck("mod(-7,-3): " + err.Error())
		}
		if !numEq(val, -1) {
			return FailCheck(fmt.Sprintf("mod(-7,-3): expected -1 (truncated), got %v (%T)", val, val))
		}
		return PassCheck("mod(-7,-3) → -1 (truncated remainder)")
	})

	r.Run("v36_add_mixed_float", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-add-mixed",
			types.TypeComputeArithmetic, "add", uint64(1), float64(2.5))
		if err != nil {
			return FailCheck("add(1,2.5): " + err.Error())
		}
		if !numEq(val, 3.5) {
			return FailCheck(fmt.Sprintf("add(1,2.5): expected 3.5, got %v (%T)", val, val))
		}
		return PassCheck("add(1,2.5) → 3.5 (mixed float promotion)")
	})

	r.Run("v36_eq_cross_type", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-eq-cross",
			types.TypeComputeCompare, "eq", uint64(1), float64(1.0))
		if err != nil {
			return FailCheck("eq(1,1.0): " + err.Error())
		}
		if val != true {
			return FailCheck(fmt.Sprintf("eq(1,1.0): expected true, got %v", val))
		}
		return PassCheck("eq(1,1.0) → true (numeric cross-type)")
	})

	r.Run("v36_eq_incompatible", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-eq-incompat",
			types.TypeComputeCompare, "eq", uint64(1), "1")
		if err != nil {
			return FailCheck("eq(1,'1'): " + err.Error())
		}
		if val != false {
			return FailCheck(fmt.Sprintf("eq(1,'1'): expected false, got %v", val))
		}
		return PassCheck("eq(1,'1') → false (incompatible types)")
	})

	r.Run("v36_lt_string", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v36-lt-str",
			types.TypeComputeCompare, "lt", "abc", "abd")
		if err != nil {
			return FailCheck("lt('abc','abd'): " + err.Error())
		}
		if val != true {
			return FailCheck(fmt.Sprintf("lt('abc','abd'): expected true, got %v", val))
		}
		return PassCheck("lt('abc','abd') → true (lexicographic)")
	})

	r.Run("v36_lt_type_mismatch", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		errCode, err := computeEvalExpectError(ctx, client, peerID, tp, "v36-lt-mismatch",
			types.TypeComputeCompare, "lt", uint64(1), "abc")
		if err != nil {
			return FailCheck("lt(1,'abc'): " + err.Error())
		}
		if errCode != "type_mismatch" {
			return FailCheck(fmt.Sprintf("lt(1,'abc'): expected type_mismatch, got %s", errCode))
		}
		return PassCheck("lt(1,'abc') → type_mismatch error")
	})

	// Step 14: v3.6 D2 — content store oracle test.

	r.Run("v36_resolve_rejects_non_compute", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Store a non-compute entity and get its hash.
		nonComputePath := tp + "/d2-target"
		raw, _ := ecf.Encode(map[string]interface{}{"secret": "data"})
		nonComputeEnt, _ := entity.NewEntity("app/secret-type", cbor.RawMessage(raw))
		if _, err := client.TreePut(ctx, nonComputePath, nonComputeEnt); err != nil {
			return FailCheck("put non-compute entity: " + err.Error())
		}
		targetHash := nonComputeEnt.ContentHash

		// Build arithmetic expression referencing the non-compute hash.
		litEnt, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
		litHash := putCE(ctx, client, tp+"/d2-lit", litEnt)
		arithEnt, _ := types.ComputeArithmeticData{
			Op: "add", Left: litHash, Right: targetHash,
		}.ToEntity()
		exprPath := tp + "/d2-oracle"
		if _, err := client.TreePut(ctx, exprPath, arithEnt); err != nil {
			return FailCheck("put oracle expression: " + err.Error())
		}
		resp, err := computeEvalAtPath(ctx, client, peerID, exprPath)
		if err != nil {
			return FailCheck("eval oracle expression: " + err.Error())
		}
		// v3.19 F10: a rejected oracle resolve surfaces as compute/error at
		// status 200 in v3.19+ (was 400 pre-fix). "Success" now means status
		// 200 with a result that is NOT compute/error.
		resultEnt, decErr := decodeComputeEntity(resp)
		if resp.Status == 200 && (decErr != nil || resultEnt.Type != types.TypeComputeError) {
			return FailCheck("oracle expression should not succeed — non-compute hash should not resolve")
		}
		// The error must be not_found (hash didn't resolve), NOT unknown_type
		// (which would leak the entity type name).
		if decErr == nil && resultEnt.Type == types.TypeComputeError {
			errData, _ := types.ComputeErrorDataFromEntity(resultEnt)
			if errData.Code == "unknown_type" {
				return FailCheck("SECURITY: resolve leaked type name via unknown_type error — D2 not implemented")
			}
			if errData.Code == "not_found" {
				return PassCheck("non-compute hash ref → not_found (D2 scoping active, no type leak)")
			}
			return PassCheck(fmt.Sprintf("non-compute hash ref → error code=%s (resolve rejected)", errData.Code))
		}
		return PassCheck(fmt.Sprintf("non-compute hash ref → rejected with status %d", resp.Status))
	})

	// Step 15: v3.7 D6 — compute/lookup/hash.

	r.Run("v37_lookup_hash_type_registered", func() CheckOutcome {
		if _, _, err := client.TreeGet(ctx, "system/type/"+types.TypeComputeLookupHash); err != nil {
			return FailCheck("compute/lookup/hash type not registered")
		}
		return PassCheck("compute/lookup/hash type registered")
	})

	r.Run("v37_lookup_hash_eval", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Test compute/lookup/hash targeting a compute entity (Tier 1 — always resolves).
		// Non-compute targets require install (sealed set) or reverse index;
		// explicit eval of non-compute targets is implementation-defined per §5.5.
		litEnt, _ := types.ComputeLiteralData{Value: uint64(77)}.ToEntity()
		litHash := putCE(ctx, client, tp+"/hash-target-lit", litEnt)

		lookupEnt, _ := types.ComputeLookupHashData{Hash: litHash}.ToEntity()
		exprPath := tp + "/hash-lookup"
		if _, err := client.TreePut(ctx, exprPath, lookupEnt); err != nil {
			return FailCheck("put lookup/hash expression: " + err.Error())
		}

		val, err := extractResultValue(ctx, client, peerID, exprPath)
		if err != nil {
			return FailCheck("eval lookup/hash: " + err.Error())
		}
		if !numEq(val, 77) {
			return FailCheck(fmt.Sprintf("lookup/hash(literal(77)): expected 77, got %v", val))
		}
		return PassCheck("eval compute/lookup/hash(literal(77)) → 77 (Tier 1, compute target)")
	})

	r.Run("v37_lookup_hash_field_extract", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Test compute/lookup/hash targeting a compute/construct result, then field extract.
		// The construct produces a non-expression entity, but it's created during
		// evaluation and stored in content store — accessible via Tier 1 since
		// the construct result flows as a value, not through resolve().
		nameEnt, _ := types.ComputeLiteralData{Value: "hash-field-test"}.ToEntity()
		nameHash := putCE(ctx, client, tp+"/hash-field-name", nameEnt)

		constructEnt, _ := types.ComputeConstructData{
			EntityType: "app/hash-field-data",
			Fields:     map[string]hash.Hash{"name": nameHash},
		}.ToEntity()
		constructHash := putCE(ctx, client, tp+"/hash-field-construct", constructEnt)

		// let data = construct{name: "hash-field-test"} in field("name", data)
		lookupData, _ := types.ComputeLookupScopeData{Name: "data"}.ToEntity()
		lookupDataHash := putCE(ctx, client, tp+"/hash-field-scope", lookupData)

		fieldEnt, _ := types.ComputeFieldData{Name: "name", Entity: lookupDataHash}.ToEntity()
		fieldHash := putCE(ctx, client, tp+"/hash-field-field", fieldEnt)

		letEnt, _ := types.ComputeLetData{
			Bindings: []types.ComputeLetBinding{{Name: "data", Value: constructHash}},
			Body:     fieldHash,
		}.ToEntity()
		letPath := tp + "/hash-field-extract"
		if _, err := client.TreePut(ctx, letPath, letEnt); err != nil {
			return FailCheck("put let expression: " + err.Error())
		}

		val, err := extractResultValue(ctx, client, peerID, letPath)
		if err != nil {
			return FailCheck("eval field extract: " + err.Error())
		}
		if val != "hash-field-test" {
			return FailCheck(fmt.Sprintf("field('name', construct): expected 'hash-field-test', got %v", val))
		}
		return PassCheck("eval let data=construct in field('name', data) → 'hash-field-test'")
	})

	// Step 16: v3.8 Tail call optimization.

	r.Run("v38_tco_if_chain", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Chain 1100 if(true, next) expressions. Each if branch is a tail position.
		// Without TCO, this would need 1100 depth (exceeds 1024 limit).
		// With TCO, the trampoline reuses the depth frame: O(1) depth, O(n) budget.
		condEnt, _ := types.ComputeLiteralData{Value: true}.ToEntity()
		condHash := putCE(ctx, client, tp+"/tco-if-cond", condEnt)
		finalEnt, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		currentHash := putCE(ctx, client, tp+"/tco-if-final", finalEnt)
		for i := 0; i < 1100; i++ {
			ifEnt, _ := types.ComputeIfData{Condition: condHash, Then: currentHash}.ToEntity()
			currentHash = putCE(ctx, client, fmt.Sprintf("%s/tco-if-%d", tp, i), ifEnt)
		}
		outerIf, _ := types.ComputeIfData{Condition: condHash, Then: currentHash}.ToEntity()
		path := tp + "/tco-if-chain"
		if _, err := client.TreePut(ctx, path, outerIf); err != nil {
			return FailCheck("put tco if chain: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("tco if chain (1101 levels): " + err.Error() +
				" — tail call optimization may not be implemented (v3.8 T2/T3)")
		}
		if !numEq(val, 42) {
			return FailCheck(fmt.Sprintf("tco if chain: expected 42, got %v", val))
		}
		return PassCheck("1101 chained if(true, next) → 42 (O(1) depth via TCO)")
	})

	r.Run("v38_tco_let_chain", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Chain 1100 let(_=1, body=next). The let body is a tail position.
		litEnt, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
		litHash := putCE(ctx, client, tp+"/tco-let-lit", litEnt)
		finalEnt, _ := types.ComputeLiteralData{Value: uint64(99)}.ToEntity()
		currentHash := putCE(ctx, client, tp+"/tco-let-final", finalEnt)
		for i := 0; i < 1100; i++ {
			letEnt, _ := types.ComputeLetData{
				Bindings: []types.ComputeLetBinding{{Name: "_", Value: litHash}},
				Body:     currentHash,
			}.ToEntity()
			currentHash = putCE(ctx, client, fmt.Sprintf("%s/tco-let-%d", tp, i), letEnt)
		}
		outerLet, _ := types.ComputeLetData{
			Bindings: []types.ComputeLetBinding{{Name: "_", Value: litHash}},
			Body:     currentHash,
		}.ToEntity()
		path := tp + "/tco-let-chain"
		if _, err := client.TreePut(ctx, path, outerLet); err != nil {
			return FailCheck("put tco let chain: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("tco let chain (1101 levels): " + err.Error() +
				" — tail call optimization may not be implemented (v3.8 T2/T3)")
		}
		if !numEq(val, 99) {
			return FailCheck(fmt.Sprintf("tco let chain: expected 99, got %v", val))
		}
		return PassCheck("1101 chained let(_=1 in next) → 99 (O(1) depth via TCO)")
	})

	// Step 16b: v3.8 Relative paths.

	r.Run("v38_relative_lookup_tree", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Put a value at {tp}/v38-rel/data/input.
		dataPath := tp + "/v38-rel/data/input"
		dataEnt, _ := types.ComputeLiteralData{Value: uint64(77)}.ToEntity()
		if _, err := client.TreePut(ctx, dataPath, dataEnt); err != nil {
			return FailCheck("put relative data: " + err.Error())
		}
		// Create lookup/tree with relative:true, path: "data/input".
		// Store it at {tp}/v38-rel — the expression's tree path becomes SubgraphRoot.
		lookupEnt, _ := types.ComputeLookupTreeData{Path: "data/input", Relative: true}.ToEntity()
		exprPath := tp + "/v38-rel"
		if _, err := client.TreePut(ctx, exprPath, lookupEnt); err != nil {
			return FailCheck("put relative expression: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, exprPath)
		if err != nil {
			return FailCheck("eval relative lookup/tree: " + err.Error() +
				" — relative path resolution may not be implemented (v3.8 R1/R2)")
		}
		if !numEq(val, 77) {
			return FailCheck(fmt.Sprintf("relative lookup/tree: expected 77, got %v", val))
		}
		return PassCheck("eval lookup/tree{path: 'data/input', relative: true} → 77 (resolved against expression path)")
	})

	// Step 16c: v3.8 Non-tail depth enforcement (heavy — 1100 entities).

	r.Run("v38_depth_non_tail", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Non-tail nesting: add(1, add(1, add(1, ...))). Arithmetic operands are
		// NOT tail positions, so depth accumulates. 1100 levels exceeds the 1024
		// default depth limit — this MUST fail even with TCO active.
		litEnt, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
		litHash := putCE(ctx, client, tp+"/ntd-lit", litEnt)
		currentHash := litHash
		for i := 0; i < 1100; i++ {
			addEnt, _ := types.ComputeArithmeticData{Op: "add", Left: litHash, Right: currentHash}.ToEntity()
			currentHash = putCE(ctx, client, fmt.Sprintf("%s/ntd-%d", tp, i), addEnt)
		}
		addEnt, _ := types.ComputeArithmeticData{Op: "add", Left: litHash, Right: currentHash}.ToEntity()
		path := tp + "/non-tail-depth"
		if _, err := client.TreePut(ctx, path, addEnt); err != nil {
			return FailCheck("put non-tail depth: " + err.Error())
		}
		resp, err := computeEvalAtPath(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("non-tail depth request: " + err.Error())
		}
		// v3.19 F10: depth-exceeded surfaces as compute/error at status 200.
		if resp.Status == 200 {
			if resultEnt, decErr := decodeComputeEntity(resp); decErr == nil && resultEnt.Type != types.TypeComputeError {
				return WarnCheck("1101 nested non-tail adds succeeded — peer may have higher depth limit")
			}
		}
		return PassCheck(fmt.Sprintf("1101 nested non-tail adds rejected (status %d / compute/error) — depth limit enforced for non-tail calls", resp.Status))
	})

	// Step 17: Recursive fibonacci — real algorithm test.
	//
	// Builds: fib = lambda(n): if(lte(n, 1), n, add(fib(n-1), fib(n-2)))
	// where fib self-references via compute/lookup/tree (spreadsheet semantic).
	// Then evaluates fib(10) → 55.
	//
	// Expression graph (~12 entities, ~177 eval operations):
	//   fib-lambda body: if(lte(n, 1), n, add(apply(lookup/tree(fib), n-1), apply(lookup/tree(fib), n-2)))
	//   fib-call: let fib = lambda in apply(fib, {n: 10})

	r.Run("algo_fibonacci_5", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalFibonacci(ctx, client, peerID, tp, 5)
		if err != nil {
			return FailCheck("fibonacci(5): " + err.Error())
		}
		if !numEq(val, 5) {
			return FailCheck(fmt.Sprintf("fibonacci(5): expected 5, got %v (%T)", val, val))
		}
		return PassCheck("fibonacci(5) → 5")
	})

	r.Run("algo_fibonacci_10", func() CheckOutcome {
		if out, ok := r.Require("algo_fibonacci_5"); !ok {
			return out
		}
		// Reuses the same fib-lambda tree path as fib(5) — tests that the
		// second run with different input doesn't produce stale results.
		val, err := computeEvalFibonacci(ctx, client, peerID, tp, 10)
		if err != nil {
			return FailCheck("fibonacci(10): " + err.Error())
		}
		if !numEq(val, 55) {
			return FailCheck(fmt.Sprintf("fibonacci(10): expected 55, got %v (%T)", val, val))
		}
		return PassCheck("fibonacci(10) → 55 (same tree paths as fib(5), no stale state)")
	})

	// Step 17: Reactive spreadsheet.
	//
	// Spreadsheet layout:
	//   A1: literal value (changes over time)
	//   B1: lookup/tree(A1) * 2 (reactive formula)
	//
	// Flow: put A1=10 → install B1 → verify result=20 → change A1=25 →
	//   verify result=50 → change A1=0 → verify result=0.

	r.Run("reactive_install", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		sp := tp + "/spreadsheet"
		a1Path := sp + "/A1"
		b1Path := sp + "/B1"

		// A1 = 10.
		a1Ent, _ := types.ComputeLiteralData{Value: uint64(10)}.ToEntity()
		if _, err := client.TreePut(ctx, a1Path, a1Ent); err != nil {
			return FailCheck("put A1: " + err.Error())
		}

		// B1 = lookup/tree(A1) * 2.
		qualA1 := fmt.Sprintf("/%s/%s", peerID, a1Path)
		lookupA1, _ := types.ComputeLookupTreeData{Path: qualA1}.ToEntity()
		lit2, _ := types.ComputeLiteralData{Value: uint64(2)}.ToEntity()
		a1RefH := putCE(ctx, client, sp+"/a1-ref", lookupA1)
		l2H := putCE(ctx, client, sp+"/lit2", lit2)
		b1Expr, _ := types.ComputeArithmeticData{Op: "mul", Left: a1RefH, Right: l2H}.ToEntity()
		if _, err := client.TreePut(ctx, b1Path, b1Expr); err != nil {
			return FailCheck("put B1: " + err.Error())
		}

		// Install B1 as reactive subgraph.
		qualB1 := fmt.Sprintf("/%s/%s", peerID, b1Path)
		installReq, _ := types.ComputeInstallRequestData{}.ToEntity()

		uri := fmt.Sprintf("entity://%s/system/compute", peerID)
		env, _, err := client.SendExecute(ctx, uri, "install", installReq,
			&types.ResourceTarget{Targets: []string{qualB1}})
		if err != nil {
			return FailCheck("install B1: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("install B1: status %d", respData.Status))
		}
		r.Store("spreadsheet_prefix", sp)
		r.Store("spreadsheet_a1_path", a1Path)
		r.Store("spreadsheet_result_path", qualB1+"/result")
		return PassCheck("installed B1 = A1 * 2 as reactive subgraph")
	})

	r.Run("reactive_initial_result", func() CheckOutcome {
		if out, ok := r.Require("reactive_install"); !ok {
			return out
		}
		// Change A1 from 10 to 25 — this triggers reactive re-evaluation.
		a1Path := r.Load("spreadsheet_a1_path").(string)
		a1Ent, _ := types.ComputeLiteralData{Value: uint64(25)}.ToEntity()
		if _, err := client.TreePut(ctx, a1Path, a1Ent); err != nil {
			return FailCheck("update A1 to 25: " + err.Error())
		}
		resultPath := r.Load("spreadsheet_result_path").(string)
		val, err := readComputeResultValue(ctx, client, resultPath)
		if err != nil {
			return FailCheck("read result after A1=25: " + err.Error())
		}
		if !numEq(val, 50) {
			return FailCheck(fmt.Sprintf("B1 after A1=25: expected 50 (25*2), got %v (%T)", val, val))
		}
		return PassCheck("B1 = A1*2 = 25*2 = 50 (first reactive update)")
	})

	r.Run("reactive_update_dependency", func() CheckOutcome {
		if out, ok := r.Require("reactive_initial_result"); !ok {
			return out
		}
		a1Path := r.Load("spreadsheet_a1_path").(string)
		a1Ent, _ := types.ComputeLiteralData{Value: uint64(7)}.ToEntity()
		if _, err := client.TreePut(ctx, a1Path, a1Ent); err != nil {
			return FailCheck("update A1 to 7: " + err.Error())
		}
		return PassCheck("updated A1 = 7")
	})

	r.Run("reactive_converged_result", func() CheckOutcome {
		if out, ok := r.Require("reactive_update_dependency"); !ok {
			return out
		}
		resultPath := r.Load("spreadsheet_result_path").(string)
		val, err := readComputeResultValue(ctx, client, resultPath)
		if err != nil {
			return FailCheck("read converged result: " + err.Error())
		}
		if !numEq(val, 14) {
			return FailCheck(fmt.Sprintf("B1 after A1=7: expected 14 (7*2), got %v (%T)", val, val))
		}
		return PassCheck("B1 = A1*2 = 7*2 = 14 (second reactive update)")
	})

	r.Run("reactive_second_update", func() CheckOutcome {
		if out, ok := r.Require("reactive_converged_result"); !ok {
			return out
		}
		a1Path := r.Load("spreadsheet_a1_path").(string)
		a1Ent, _ := types.ComputeLiteralData{Value: uint64(0)}.ToEntity()
		if _, err := client.TreePut(ctx, a1Path, a1Ent); err != nil {
			return FailCheck("update A1 to 0: " + err.Error())
		}
		return PassCheck("updated A1 = 0")
	})

	r.Run("reactive_final_result", func() CheckOutcome {
		if out, ok := r.Require("reactive_second_update"); !ok {
			return out
		}
		resultPath := r.Load("spreadsheet_result_path").(string)
		val, err := readComputeResultValue(ctx, client, resultPath)
		if err != nil {
			return FailCheck("read final result: " + err.Error())
		}
		if !numEq(val, 0) {
			return FailCheck(fmt.Sprintf("B1 after A1=0: expected 0 (0*2), got %v (%T)", val, val))
		}
		return PassCheck("B1 = A1*2 = 0*2 = 0 (third reactive update, zero case)")
	})

	// Step 20: v3.8 Dynamic handlers — TCO-powered algorithms as installed subgraphs.

	// Tail-recursive sum(2000): sum_iter(n, acc) = if n<=0 then acc else sum_iter(n-1, acc+n)
	// 2000 iterations exceed depth=1024 without TCO. With TCO: O(1) depth.
	// sum(2000) = 2000 * 2001 / 2 = 2,001,000
	r.Run("v38_tco_sum_2000", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalTailRecursiveSum(ctx, client, peerID, tp, 2000)
		if err != nil {
			return FailCheck("tco sum(2000): " + err.Error())
		}
		expected := float64(2000 * 2001 / 2)
		if !numEq(val, expected) {
			return FailCheck(fmt.Sprintf("sum(2000): expected %.0f, got %v (%T)", expected, val, val))
		}
		return PassCheck(fmt.Sprintf("tail-recursive sum(2000) → %.0f (2000 iterations via TCO)", expected))
	})

	// Newton's method sqrt(2): newton(x, guess, n) = if n<=0 then guess else newton(x, (guess+x/guess)/2, n-1)
	// 20 iterations of Newton's method converges to machine precision.
	r.Run("v38_newton_sqrt", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalNewtonSqrt(ctx, client, peerID, tp, 2.0, 20)
		if err != nil {
			return FailCheck("newton sqrt(2): " + err.Error())
		}
		f, ok := toValidateFloat(val)
		if !ok {
			return FailCheck(fmt.Sprintf("newton sqrt(2): expected float, got %v (%T)", val, val))
		}
		diff := f - 1.4142135623730951
		if diff < 0 {
			diff = -diff
		}
		if diff > 1e-6 {
			return FailCheck(fmt.Sprintf("newton sqrt(2): expected ~1.41421, got %v (diff=%v)", f, diff))
		}
		return PassCheck(fmt.Sprintf("newton sqrt(2) → %.10f (20 TCO iterations, converged)", f))
	})

	// compute/apply handler mode: dispatches from inside a compute expression to
	// another handler via path+operation. Tests that the evaluator can call other
	// handlers (system/compute, system/tree, builtins, etc.) from within expressions.
	r.Run("v38_apply_handler_mode", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		sp := tp + "/hdispatch"

		// Store a compute expression at a tree path: literal(42) + literal(8) = 50
		lit42, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		lit8, _ := types.ComputeLiteralData{Value: uint64(8)}.ToEntity()
		l42H := putCE(ctx, client, sp+"/lit42", lit42)
		l8H := putCE(ctx, client, sp+"/lit8", lit8)
		targetExpr, _ := types.ComputeArithmeticData{Op: "add", Left: l42H, Right: l8H}.ToEntity()
		targetPath := sp + "/target-expr"
		if _, err := client.TreePut(ctx, targetPath, targetExpr); err != nil {
			return FailCheck("put target expression: " + err.Error())
		}

		// Build a compute/apply that dispatches to system/compute eval via handler mode.
		// V7 §3.2 path-as-resource: eval reads the expression path from the
		// dispatched EXECUTE's resource. compute/apply's Resource field is the
		// hash of a compute expression that evaluates to a
		// system/protocol/resource-target value (PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F2/F4).
		qualTarget := fmt.Sprintf("/%s/%s", peerID, targetPath)
		resourceLit, _ := types.ComputeLiteralData{
			Value: types.ResourceTarget{Targets: []string{qualTarget}},
		}.ToEntity()
		resourceHash := putCE(ctx, client, sp+"/resource-lit", resourceLit)

		applyExpr, _ := types.ComputeApplyData{
			Path:      "system/compute",
			Operation: "eval",
			Resource:  resourceHash,
		}.ToEntity()
		callerPath := sp + "/handler-dispatch"
		if _, err := client.TreePut(ctx, callerPath, applyExpr); err != nil {
			return FailCheck("put dispatch expression: " + err.Error())
		}

		val, err := extractResultValue(ctx, client, peerID, callerPath)
		if err != nil {
			return FailCheck("handler dispatch eval: " + err.Error() +
				" — compute/apply handler-mode dispatch to system/compute via resource field")
		}
		if !numEq(val, 50) {
			return FailCheck(fmt.Sprintf("handler dispatch: expected 50, got %v", val))
		}
		return PassCheck("compute/apply handler mode: dispatched to system/compute eval → 50")
	})

	// Dynamic handler: installed subgraph with a tree-referenced function.
	// fn stored at fn_path, subgraph applies fn to input. Change input → result updates.
	r.Run("v38_dynamic_handler", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		sp := tp + "/dynhandler"
		fnPath := sp + "/fn"
		inputPath := sp + "/input"
		exprPath := sp + "/expr"

		// fn = lambda(x): x * 2
		lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
		xH := putCE(ctx, client, sp+"/x", lookupX)
		lit2, _ := types.ComputeLiteralData{Value: uint64(2)}.ToEntity()
		l2H := putCE(ctx, client, sp+"/lit2", lit2)
		body, _ := types.ComputeArithmeticData{Op: "mul", Left: xH, Right: l2H}.ToEntity()
		bodyH := putCE(ctx, client, sp+"/body", body)
		doubleFn, _ := types.ComputeLambdaData{Params: []string{"x"}, Body: bodyH}.ToEntity()
		if _, err := client.TreePut(ctx, fnPath, doubleFn); err != nil {
			return FailCheck("put fn: " + err.Error())
		}

		// input = 5
		inputEnt, _ := types.ComputeLiteralData{Value: uint64(5)}.ToEntity()
		if _, err := client.TreePut(ctx, inputPath, inputEnt); err != nil {
			return FailCheck("put input: " + err.Error())
		}

		// expr = let f = lookup/tree(fn) in apply(f, {x: lookup/tree(input)})
		qualFn := fmt.Sprintf("/%s/%s", peerID, fnPath)
		qualInput := fmt.Sprintf("/%s/%s", peerID, inputPath)
		lookupFn, _ := types.ComputeLookupTreeData{Path: qualFn}.ToEntity()
		fnRefH := putCE(ctx, client, sp+"/fn-ref", lookupFn)
		lookupInput, _ := types.ComputeLookupTreeData{Path: qualInput}.ToEntity()
		inputRefH := putCE(ctx, client, sp+"/input-ref", lookupInput)
		lookupF, _ := types.ComputeLookupScopeData{Name: "f"}.ToEntity()
		fH := putCE(ctx, client, sp+"/f", lookupF)
		applyExpr, _ := types.ComputeApplyData{Fn: fH, Args: map[string]hash.Hash{"x": inputRefH}}.ToEntity()
		applyH := putCE(ctx, client, sp+"/apply", applyExpr)
		letExpr, _ := types.ComputeLetData{
			Bindings: []types.ComputeLetBinding{{Name: "f", Value: fnRefH}},
			Body:     applyH,
		}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, letExpr); err != nil {
			return FailCheck("put expr: " + err.Error())
		}

		// Install as reactive subgraph.
		qualExpr := fmt.Sprintf("/%s/%s", peerID, exprPath)
		installReq, _ := types.ComputeInstallRequestData{}.ToEntity()
		uri := fmt.Sprintf("entity://%s/system/compute", peerID)
		env, _, err := client.SendExecute(ctx, uri, "install", installReq,
			&types.ResourceTarget{Targets: []string{qualExpr}})
		if err != nil {
			return FailCheck("install dynamic handler: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("install: status %d", respData.Status))
		}

		// Trigger by changing input to 7 (triggers reactive re-eval).
		newInput, _ := types.ComputeLiteralData{Value: uint64(7)}.ToEntity()
		if _, err := client.TreePut(ctx, inputPath, newInput); err != nil {
			return FailCheck("update input: " + err.Error())
		}

		resultPath := qualExpr + "/result"
		val, err := readComputeResultValue(ctx, client, resultPath)
		if err != nil {
			return FailCheck("read result: " + err.Error())
		}
		if !numEq(val, 14) {
			return FailCheck(fmt.Sprintf("dynamic handler double(7): expected 14, got %v", val))
		}

		r.Store("dynhandler_prefix", sp)
		r.Store("dynhandler_fn_path", fnPath)
		r.Store("dynhandler_input_path", inputPath)
		r.Store("dynhandler_result_path", resultPath)
		return PassCheck("dynamic handler: lambda(x):x*2 installed, input=7 → result=14")
	})

	// Hot-swap the function: change lambda from double to triple, verify behavior changes.
	r.Run("v38_dynamic_handler_swap", func() CheckOutcome {
		if out, ok := r.Require("v38_dynamic_handler"); !ok {
			return out
		}
		sp := r.Load("dynhandler_prefix").(string)
		fnPath := r.Load("dynhandler_fn_path").(string)
		inputPath := r.Load("dynhandler_input_path").(string)
		resultPath := r.Load("dynhandler_result_path").(string)

		// Swap fn to lambda(x): x * 3
		lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
		xH := putCE(ctx, client, sp+"/swap-x", lookupX)
		lit3, _ := types.ComputeLiteralData{Value: uint64(3)}.ToEntity()
		l3H := putCE(ctx, client, sp+"/swap-lit3", lit3)
		tripleBody, _ := types.ComputeArithmeticData{Op: "mul", Left: xH, Right: l3H}.ToEntity()
		tripleBodyH := putCE(ctx, client, sp+"/swap-body", tripleBody)
		tripleFn, _ := types.ComputeLambdaData{Params: []string{"x"}, Body: tripleBodyH}.ToEntity()
		if _, err := client.TreePut(ctx, fnPath, tripleFn); err != nil {
			return FailCheck("swap fn: " + err.Error())
		}

		// Trigger re-eval by changing input to 10.
		newInput, _ := types.ComputeLiteralData{Value: uint64(10)}.ToEntity()
		if _, err := client.TreePut(ctx, inputPath, newInput); err != nil {
			return FailCheck("update input: " + err.Error())
		}

		val, err := readComputeResultValue(ctx, client, resultPath)
		if err != nil {
			return FailCheck("read swapped result: " + err.Error())
		}
		if !numEq(val, 30) {
			return FailCheck(fmt.Sprintf("swapped handler triple(10): expected 30, got %v", val))
		}
		return PassCheck("hot-swap: lambda(x):x*3 replaces x*2, input=10 → result=30")
	})

	// Cascade chain: subgraph A's result feeds subgraph B's dependency.
	// A: lookup(input) * 2 → intermediate
	// B: lookup(intermediate) + 10 → output
	// input=5 → intermediate=10 → output=20
	r.Run("v38_cascade_chain", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		sp := tp + "/cascade"
		inputPath := sp + "/input"
		exprAPath := sp + "/expr-a"
		exprBPath := sp + "/expr-b"

		// input = 5
		inputEnt, _ := types.ComputeLiteralData{Value: uint64(5)}.ToEntity()
		if _, err := client.TreePut(ctx, inputPath, inputEnt); err != nil {
			return FailCheck("put input: " + err.Error())
		}

		// Subgraph A: lookup(input) * 2
		qualInput := fmt.Sprintf("/%s/%s", peerID, inputPath)
		lookupInput, _ := types.ComputeLookupTreeData{Path: qualInput}.ToEntity()
		inputRefH := putCE(ctx, client, sp+"/a-input", lookupInput)
		lit2, _ := types.ComputeLiteralData{Value: uint64(2)}.ToEntity()
		l2H := putCE(ctx, client, sp+"/a-lit2", lit2)
		mulExpr, _ := types.ComputeArithmeticData{Op: "mul", Left: inputRefH, Right: l2H}.ToEntity()
		if _, err := client.TreePut(ctx, exprAPath, mulExpr); err != nil {
			return FailCheck("put expr A: " + err.Error())
		}

		// Install A with result at intermediate
		qualA := fmt.Sprintf("/%s/%s", peerID, exprAPath)
		intermediateResult := qualA + "/result"
		installA, _ := types.ComputeInstallRequestData{}.ToEntity()
		uri := fmt.Sprintf("entity://%s/system/compute", peerID)
		envA, _, err := client.SendExecute(ctx, uri, "install", installA,
			&types.ResourceTarget{Targets: []string{qualA}})
		if err != nil {
			return FailCheck("install A: " + err.Error())
		}
		respA, _ := types.ExecuteResponseDataFromEntity(envA.Root)
		if respA.Status != 200 {
			return FailCheck(fmt.Sprintf("install A: status %d", respA.Status))
		}

		// Subgraph B: field("value", lookup/tree(A/result)) + 10
		// A writes a compute/result entity. B must extract the "value" field
		// because compute/result is a value type, not an expression type.
		lookupIntermediate, _ := types.ComputeLookupTreeData{Path: intermediateResult}.ToEntity()
		intRefH := putCE(ctx, client, sp+"/b-int", lookupIntermediate)
		fieldExpr, _ := types.ComputeFieldData{Name: "value", Entity: intRefH}.ToEntity()
		fieldH := putCE(ctx, client, sp+"/b-field", fieldExpr)
		lit10, _ := types.ComputeLiteralData{Value: uint64(10)}.ToEntity()
		l10H := putCE(ctx, client, sp+"/b-lit10", lit10)
		addExpr, _ := types.ComputeArithmeticData{Op: "add", Left: fieldH, Right: l10H}.ToEntity()
		if _, err := client.TreePut(ctx, exprBPath, addExpr); err != nil {
			return FailCheck("put expr B: " + err.Error())
		}

		// Install B
		qualB := fmt.Sprintf("/%s/%s", peerID, exprBPath)
		installB, _ := types.ComputeInstallRequestData{}.ToEntity()
		envB, _, err := client.SendExecute(ctx, uri, "install", installB,
			&types.ResourceTarget{Targets: []string{qualB}})
		if err != nil {
			return FailCheck("install B: " + err.Error())
		}
		respB, _ := types.ExecuteResponseDataFromEntity(envB.Root)
		if respB.Status != 200 {
			return FailCheck(fmt.Sprintf("install B: status %d", respB.Status))
		}

		// Trigger cascade: change input to 15
		// A: 15 * 2 = 30 → writes to intermediate
		// B: 30 + 10 = 40 → writes to output
		newInput, _ := types.ComputeLiteralData{Value: uint64(15)}.ToEntity()
		if _, err := client.TreePut(ctx, inputPath, newInput); err != nil {
			return FailCheck("update input: " + err.Error())
		}

		outputPath := qualB + "/result"
		val, err := readComputeResultValue(ctx, client, outputPath)
		if err != nil {
			return FailCheck("read cascade output: " + err.Error())
		}
		if !numEq(val, 40) {
			return FailCheck(fmt.Sprintf("cascade: expected 40 (15*2+10), got %v", val))
		}
		return PassCheck("cascade chain: input=15 → A=15*2=30 → B=30+10=40")
	})

	// --- v3.10 compute/apply resource ceiling
	// (PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING) ---

	// F1: Resource field on compute/apply is accepted and a static-literal
	// resource flows through to the dispatched EXECUTE without error.
	// This is the smoke test that the new field is wired end-to-end.
	r.Run("v310_apply_resource_field_accepted", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		sp := tp + "/v310-resource-field"

		// Target expression: literal(7).
		litTarget, _ := types.ComputeLiteralData{Value: uint64(7)}.ToEntity()
		targetPath := sp + "/target-expr"
		if _, err := client.TreePut(ctx, targetPath, litTarget); err != nil {
			return FailCheck("put target: " + err.Error())
		}
		qualTarget := fmt.Sprintf("/%s/%s", peerID, targetPath)

		// Build apply with explicit Resource literal targeting the qualified path.
		resourceLit, _ := types.ComputeLiteralData{
			Value: types.ResourceTarget{Targets: []string{qualTarget}},
		}.ToEntity()
		resourceHash := putCE(ctx, client, sp+"/resource-lit", resourceLit)

		applyExpr, _ := types.ComputeApplyData{
			Path:      "system/compute",
			Operation: "eval",
			Resource:  resourceHash,
		}.ToEntity()
		applyPath := sp + "/apply"
		if _, err := client.TreePut(ctx, applyPath, applyExpr); err != nil {
			return FailCheck("put apply: " + err.Error())
		}

		val, err := extractResultValue(ctx, client, peerID, applyPath)
		if err != nil {
			return FailCheck("eval with resource field: " + err.Error())
		}
		if !numEq(val, 7) {
			return FailCheck(fmt.Sprintf("expected 7, got %v", val))
		}
		return PassCheck("compute/apply.resource accepted; eval returned 7")
	})

	// F5 runtime: capability override without resource → invalid_expression.
	// Builds a `compute/apply` whose `capability` field points at a literal cap
	// entity but with no `resource` field. Eval must reject before dispatch.
	r.Run("v310_f5_eval_capability_without_resource", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		sp := tp + "/v310-f5-eval"

		// Build a literal expression whose value is some cap-shaped entity.
		// For F5 we don't need it to be a real cap — eval must reject before
		// looking at the cap's contents, since the structural error is
		// "capability without resource".
		dummyCapLit, _ := types.ComputeLiteralData{Value: "dummy"}.ToEntity()
		capHash := putCE(ctx, client, sp+"/cap", dummyCapLit)

		applyExpr, _ := types.ComputeApplyData{
			Path:       "system/clock",
			Operation:  "now",
			Capability: capHash,
			// Resource intentionally omitted — F5 violation.
		}.ToEntity()
		applyPath := sp + "/apply"
		if _, err := client.TreePut(ctx, applyPath, applyExpr); err != nil {
			return FailCheck("put apply: " + err.Error())
		}

		resp, err := computeEvalAtPath(ctx, client, peerID, applyPath)
		if err != nil {
			return FailCheck("eval call failed: " + err.Error())
		}
		code, decErr := decodeComputeErrorCode(resp)
		if decErr != nil {
			return FailCheck(fmt.Sprintf("expected error response, got status=%d, decode err: %v",
				resp.Status, decErr))
		}
		if code != "invalid_expression" {
			return FailCheck(fmt.Sprintf(
				"expected invalid_expression for capability without resource (F5), got code=%q",
				code))
		}
		return PassCheck("compute/apply with capability and no resource correctly rejected as invalid_expression at eval (F5)")
	})

	// F5 install: same rule at install audit time.
	r.Run("v310_f5_install_capability_without_resource", func() CheckOutcome {
		if out, ok := r.Require("handler_op_install"); !ok {
			return out
		}
		sp := tp + "/v310-f5-install"

		dummyCapLit, _ := types.ComputeLiteralData{Value: "dummy"}.ToEntity()
		capHash := putCE(ctx, client, sp+"/cap", dummyCapLit)

		applyExpr, _ := types.ComputeApplyData{
			Path:       "system/clock",
			Operation:  "now",
			Capability: capHash,
		}.ToEntity()
		exprPath := sp + "/expr"
		if _, err := client.TreePut(ctx, exprPath, applyExpr); err != nil {
			return FailCheck("put expr: " + err.Error())
		}

		qualExpr := fmt.Sprintf("/%s/%s", peerID, exprPath)
		reqEnt, err := types.ComputeInstallRequestData{}.ToEntity()
		if err != nil {
			return FailCheck("build install request: " + err.Error())
		}

		uri := fmt.Sprintf("entity://%s/system/compute", peerID)
		env, _, err := client.SendExecute(ctx, uri, "install", reqEnt,
			&types.ResourceTarget{Targets: []string{qualExpr}})
		if err != nil {
			return FailCheck("install call failed: " + err.Error())
		}
		respData, decErr := types.ExecuteResponseDataFromEntity(env.Root)
		if decErr != nil {
			return FailCheck("decode install response: " + decErr.Error())
		}
		// Implementations may surface this as a 400 (status code) and/or via a
		// compute/error result entity. Accept both shapes; the install MUST fail.
		if respData.Status >= 200 && respData.Status < 300 {
			return FailCheck(fmt.Sprintf(
				"install of capability-without-resource subgraph should fail (F5), got status=%d",
				respData.Status))
		}
		// If the result decodes as a compute/error, prefer checking its code.
		if code, codeErr := decodeComputeErrorCode(respData); codeErr == nil {
			if code != "invalid_expression" {
				return FailCheck(fmt.Sprintf(
					"expected invalid_expression at install (F5), got code=%q", code))
			}
		}
		return PassCheck(fmt.Sprintf(
			"install of capability-without-resource subgraph correctly rejected (status=%d) (F5)",
			respData.Status))
	})

	// CP1 §10: install of a compute/apply with a static-literal capability
	// referencing a foreign cap (writer not in chain) → 403 embedded_cap_unauthorized.
	r.Run("cp1_install_static_literal_adversary_rejected", func() CheckOutcome {
		if out, ok := r.Require("handler_op_install"); !ok {
			return out
		}
		sp := tp + "/cp1-static-foreign"

		foreignCap, foreignSig, foreignID, err := client.ForeignCapability(
			[]string{"system/tree"}, []string{"*"}, []string{"put"},
		)
		if err != nil {
			return FailCheck("build foreign cap: " + err.Error())
		}
		// compute/literal whose value is the foreign cap entity hash (33-byte form).
		capRefLit, _ := types.ComputeLiteralData{Value: foreignCap.ContentHash.Bytes()}.ToEntity()
		capRefHash := putCE(ctx, client, sp+"/cap-lit", capRefLit)
		// resource literal — F5 requires resource alongside capability.
		resLit, _ := types.ComputeLiteralData{
			Value: types.ResourceTarget{Targets: []string{"/" + peerID + "/system/data"}},
		}.ToEntity()
		resHash := putCE(ctx, client, sp+"/res-lit", resLit)

		applyExpr, _ := types.ComputeApplyData{
			Path:       "system/tree",
			Operation:  "put",
			Resource:   resHash,
			Capability: capRefHash,
		}.ToEntity()
		exprPath := sp + "/expr"
		if _, err := client.TreePut(ctx, exprPath, applyExpr); err != nil {
			return FailCheck("put expr: " + err.Error())
		}

		qualExpr := fmt.Sprintf("/%s/%s", peerID, exprPath)
		reqEnt, err := types.ComputeInstallRequestData{}.ToEntity()
		if err != nil {
			return FailCheck("build install request: " + err.Error())
		}

		uri := fmt.Sprintf("entity://%s/system/compute", peerID)
		extras := map[hash.Hash]entity.Entity{
			foreignCap.ContentHash: foreignCap,
			foreignSig.ContentHash: foreignSig,
			foreignID.ContentHash:  foreignID,
		}
		env, _, err := client.SendExecuteWithIncluded(ctx, uri, "install", reqEnt,
			&types.ResourceTarget{Targets: []string{qualExpr}}, extras)
		if err != nil {
			return FailCheck("send install: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		return requireEmbeddedCapUnauthorized(respData, "compute install with foreign static-literal capability (CP1)")
	})

	// CP1 positive control: install of a compute/apply whose static-literal
	// capability is rooted in the installer (granter chain contains the
	// EXECUTE author) → 200. Pairs with the adversary test above: without this
	// a peer that 4xx's all static-literal caps would still pass the adversary
	// case, masking over-rejection of legitimate chains.
	r.Run("cp1_install_static_literal_self_issued_accepted", func() CheckOutcome {
		if out, ok := r.Require("handler_op_install"); !ok {
			return out
		}
		sp := tp + "/cp1-static-self"

		selfCap, selfSig, err := client.CreateDispatchCapability(
			[]string{"system/tree"}, []string{"*"}, []string{"put"},
		)
		if err != nil {
			return FailCheck("build self-issued cap: " + err.Error())
		}
		capRefLit, _ := types.ComputeLiteralData{Value: selfCap.ContentHash.Bytes()}.ToEntity()
		capRefHash := putCE(ctx, client, sp+"/cap-lit", capRefLit)
		resLit, _ := types.ComputeLiteralData{
			Value: types.ResourceTarget{Targets: []string{"/" + peerID + "/system/data"}},
		}.ToEntity()
		resHash := putCE(ctx, client, sp+"/res-lit", resLit)

		applyExpr, _ := types.ComputeApplyData{
			Path:       "system/tree",
			Operation:  "put",
			Resource:   resHash,
			Capability: capRefHash,
		}.ToEntity()
		exprPath := sp + "/expr"
		if _, err := client.TreePut(ctx, exprPath, applyExpr); err != nil {
			return FailCheck("put expr: " + err.Error())
		}

		qualExpr := fmt.Sprintf("/%s/%s", peerID, exprPath)
		reqEnt, err := types.ComputeInstallRequestData{}.ToEntity()
		if err != nil {
			return FailCheck("build install request: " + err.Error())
		}

		uri := fmt.Sprintf("entity://%s/system/compute", peerID)
		extras := map[hash.Hash]entity.Entity{
			selfCap.ContentHash: selfCap,
			selfSig.ContentHash: selfSig,
		}
		env, _, err := client.SendExecuteWithIncluded(ctx, uri, "install", reqEnt,
			&types.ResourceTarget{Targets: []string{qualExpr}}, extras)
		if err != nil {
			return FailCheck("send install: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status >= 200 && respData.Status < 300 {
			return PassCheck("install accepted with self-issued static-literal capability (CP1 chain-root pass)")
		}
		if code, codeErr := decodeResultErrorCode(respData); codeErr == nil && code == "embedded_cap_unauthorized" {
			return FailCheck(fmt.Sprintf("CP1 over-rejection: self-issued static-literal cap surfaced embedded_cap_unauthorized at status=%d — peer is rejecting valid chains, not just adversarial ones", respData.Status))
		}
		// Other rejections are a setup/permission issue, not CP1 over-rejection.
		// Warn so the failure is visible without masking other categories.
		if code, codeErr := decodeResultErrorCode(respData); codeErr == nil {
			return WarnCheck(fmt.Sprintf("install returned status=%d code=%q — not the CP1 rejection we're guarding against, but install didn't succeed", respData.Status, code))
		}
		return WarnCheck(fmt.Sprintf("install returned status=%d with undecodable error", respData.Status))
	})

	// CP1 §10: install of a compute/apply with a dynamic capability
	// expression (non-literal) → 200 (chain check deferred to runtime per
	// proposal §6.1). Sanity check that the dynamic path doesn't
	// over-eagerly reject at install time.
	r.Run("cp1_install_dynamic_capability_deferred", func() CheckOutcome {
		if out, ok := r.Require("handler_op_install"); !ok {
			return out
		}
		sp := tp + "/cp1-dynamic"

		// Dynamic capability: compute/lookup/scope (not a literal).
		dynCap, _ := types.ComputeLookupScopeData{Name: "caller_capability"}.ToEntity()
		dynCapHash := putCE(ctx, client, sp+"/dyn-cap", dynCap)
		resLit, _ := types.ComputeLiteralData{
			Value: types.ResourceTarget{Targets: []string{"/" + peerID + "/system/data"}},
		}.ToEntity()
		resHash := putCE(ctx, client, sp+"/res-lit", resLit)

		applyExpr, _ := types.ComputeApplyData{
			Path:       "system/tree",
			Operation:  "put",
			Resource:   resHash,
			Capability: dynCapHash,
		}.ToEntity()
		exprPath := sp + "/expr"
		if _, err := client.TreePut(ctx, exprPath, applyExpr); err != nil {
			return FailCheck("put expr: " + err.Error())
		}

		qualExpr := fmt.Sprintf("/%s/%s", peerID, exprPath)
		reqEnt, err := types.ComputeInstallRequestData{}.ToEntity()
		if err != nil {
			return FailCheck("build install request: " + err.Error())
		}

		uri := fmt.Sprintf("entity://%s/system/compute", peerID)
		env, _, err := client.SendExecute(ctx, uri, "install", reqEnt,
			&types.ResourceTarget{Targets: []string{qualExpr}})
		if err != nil {
			return FailCheck("send install: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		// Dynamic path: install should NOT reject with embedded_cap_unauthorized.
		// 200 is the expected happy path; other 4xx are tolerable as long as
		// they're not the chain-root rejection (which would be over-eager).
		if respData.Status >= 200 && respData.Status < 300 {
			return PassCheck("install accepted with dynamic capability (CP1 deferred to runtime)")
		}
		if code, codeErr := decodeComputeErrorCode(respData); codeErr == nil && code == "embedded_cap_unauthorized" {
			return FailCheck("dynamic capability MUST NOT trigger CP1 chain-root rejection at install — defer to runtime")
		}
		return WarnCheck(fmt.Sprintf("dynamic-capability install returned status=%d — non-200 but didn't surface CP1 rejection", respData.Status))
	})

	// --- v3.14 standard-IR floor checks ---

	// N.1: compute/index — basic positive case.
	r.Run("v314_index_basic", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalIndexExpr(ctx, client, peerID, tp, "v314-idx",
			[]interface{}{"a", "b", "c"}, int64(1))
		if err != nil {
			return FailCheck("index([a,b,c], 1): " + err.Error())
		}
		if s, ok := val.(string); !ok || s != "b" {
			return FailCheck(fmt.Sprintf("index([a,b,c], 1): expected \"b\", got %v (%T)", val, val))
		}
		return PassCheck("index([a,b,c], 1) → \"b\"")
	})

	r.Run("v314_index_negative", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		code, err := computeEvalIndexExprError(ctx, client, peerID, tp, "v314-idx-neg",
			[]interface{}{int64(1), int64(2)}, int64(-1))
		if err != nil {
			return FailCheck("expected error: " + err.Error())
		}
		if code != "index_out_of_range" {
			return FailCheck("expected index_out_of_range, got " + code)
		}
		return PassCheck("negative index → index_out_of_range")
	})

	r.Run("v314_index_past_end", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		code, err := computeEvalIndexExprError(ctx, client, peerID, tp, "v314-idx-end",
			[]interface{}{int64(1), int64(2)}, int64(5))
		if err != nil {
			return FailCheck("expected error: " + err.Error())
		}
		if code != "index_out_of_range" {
			return FailCheck("expected index_out_of_range, got " + code)
		}
		return PassCheck("index past end → index_out_of_range")
	})

	r.Run("v314_index_type_mismatch", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		code, err := computeEvalIndexExprError(ctx, client, peerID, tp, "v314-idx-tm",
			"not-an-array", int64(0))
		if err != nil {
			return FailCheck("expected error: " + err.Error())
		}
		if code != "type_mismatch" {
			return FailCheck("expected type_mismatch on non-array, got " + code)
		}
		return PassCheck("index on non-array → type_mismatch")
	})

	r.Run("v314_length_empty", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalLengthExpr(ctx, client, peerID, tp, "v314-len-e",
			[]interface{}{})
		if err != nil {
			return FailCheck("length([]): " + err.Error())
		}
		if !numEq(val, 0) {
			return FailCheck(fmt.Sprintf("length([]): expected 0, got %v (%T)", val, val))
		}
		return PassCheck("length([]) → 0")
	})

	r.Run("v314_length_nonempty", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalLengthExpr(ctx, client, peerID, tp, "v314-len-n",
			[]interface{}{uint64(10), uint64(20), uint64(30), uint64(40)})
		if err != nil {
			return FailCheck("length(4-elt): " + err.Error())
		}
		if !numEq(val, 4) {
			return FailCheck(fmt.Sprintf("length(4-elt): expected 4, got %v (%T)", val, val))
		}
		return PassCheck("length(4-element array) → 4")
	})

	r.Run("v314_length_type_mismatch", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		code, err := computeEvalLengthExprError(ctx, client, peerID, tp, "v314-len-tm",
			"hello")
		if err != nil {
			return FailCheck("expected error: " + err.Error())
		}
		if code != "type_mismatch" {
			return FailCheck("expected type_mismatch, got " + code)
		}
		return PassCheck("length(string) → type_mismatch")
	})

	// v3.16 rule 8: sign-agnostic. The v3.14 mixed→type_mismatch rule was
	// removed in v3.16 (the WASM/LLVM/JVM model — add/sub/mul are 64-bit
	// two's-complement and don't branch on signedness). add(-1, 2) → 1.
	r.Run("v316_sign_agnostic_add", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v316-sign-agnostic",
			types.TypeComputeArithmetic, "add", int64(-1), int64(2))
		if err != nil {
			return FailCheck("expected success for sign-agnostic add: " + err.Error())
		}
		if !numEq(val, 1) {
			return FailCheck(fmt.Sprintf("expected 1, got %v (%T)", val, val))
		}
		return PassCheck("add(-1, 2) → 1 (rule 8 sign-agnostic; rule 9 mixed→error removed)")
	})

	// Rule 8 + rule 10: 2^64 - 1 + 1 wraps to bit pattern 0. Signed-canonical
	// encoding (rule 10): bit-63 clear → CBOR major type 0 → value 0.
	r.Run("v316_uint_wraparound_add", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v316-uwrap",
			types.TypeComputeArithmetic, "add", uint64(1<<64-1), uint64(1))
		if err != nil {
			return FailCheck("wrap add: " + err.Error())
		}
		if !numEq(val, 0) {
			return FailCheck(fmt.Sprintf("expected wrap → 0, got %v (%T)", val, val))
		}
		return PassCheck("add(2^64-1, 1) → 0 (rule 8 wrap at 2^64; rule 10 signed-canonical encoding)")
	})

	// Rule 8: int boundary wrap — MinInt64 + (-1) → bit pattern 0x7FFF...FF
	// (= MaxInt64 under signed two's-complement). Per rule 10 the result
	// encodes as the signed interpretation (the negative wrap-around value).
	r.Run("v316_int_wraparound_add", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v316-iwrap",
			types.TypeComputeArithmetic, "add", int64(-1<<63), int64(-1))
		if err != nil {
			return FailCheck("int wrap add: " + err.Error())
		}
		if !numEq(val, float64(int64(1<<63-1))) {
			return FailCheck(fmt.Sprintf("expected int wrap → MaxInt64, got %v (%T)", val, val))
		}
		return PassCheck("add(MinInt64, -1) → MaxInt64 (rule 8 two's-complement wrap, sign-agnostic)")
	})

	// A.5: signed-canonical wire encoding. sub(3, 5) produces bit pattern
	// 0xFF...FE which MUST encode as CBOR major type 1 (int64 -2), not major
	// type 0 (uint64 2^64-2). Cross-impl wire-form agreement.
	r.Run("v316_signed_canonical_encoding", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBinaryOp(ctx, client, peerID, tp, "v316-canonical",
			types.TypeComputeArithmetic, "sub", uint64(3), uint64(5))
		if err != nil {
			return FailCheck("sub: " + err.Error())
		}
		if !numEq(val, -2) {
			return FailCheck(fmt.Sprintf("expected -2 (signed canonical), got %v (%T)", val, val))
		}
		return PassCheck("sub(3, 5) → -2 (rule 10 signed-canonical wire encoding)")
	})

	// A.6: eager numeric-cast triggers unsigned interpretation for the
	// immediately-following sign-sensitive op. div(cast(MaxUint-1, uint), 2)
	// = unsigned div → 2^63-1; without cast, signed → -1.
	r.Run("v316_eager_cast_unsigned_div", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalEagerCastDiv(ctx, client, peerID, tp, "v316-cast-div",
			uint64(1<<64-2), uint64(2))
		if err != nil {
			return FailCheck("eager-cast div: " + err.Error())
		}
		if !numEq(val, float64((uint64(1)<<63)-1)) {
			return FailCheck(fmt.Sprintf("expected 2^63-1 (unsigned div), got %v (%T)", val, val))
		}
		return PassCheck("div(cast(MaxUint-1, uint), 2) → 2^63-1 (rule 11 eager cast)")
	})

	// A.6 negative: cast through compute/let bindings does NOT preserve the
	// unsigned interpretation. let y = cast(x, uint) in div(y, 2) → signed.
	r.Run("v316_eager_cast_not_through_let", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalCastThroughLet(ctx, client, peerID, tp, "v316-cast-let",
			uint64(1<<64-2), uint64(2))
		if err != nil {
			return FailCheck("let cast div: " + err.Error())
		}
		// Signed: int64(MaxUint-1) = -2; -2 / 2 = -1.
		if !numEq(val, -1) {
			return FailCheck(fmt.Sprintf("expected -1 (signed div of -2 by 2), got %v (%T)", val, val))
		}
		return PassCheck("let y = cast(uint) in div(y, 2) → signed (rule 11 doesn't flow through let)")
	})

	// Deferred sub-question (realization-time confirm): a uint value in
	// [2^63, 2^64) survives store/read AS LONG AS readers recover the
	// unsigned interpretation via cast at point-of-use. Per JVM-model lean:
	// the bit pattern round-trips (signed wire form, rule 10), unsigned
	// interpretation requires the cast on the read side.
	r.Run("v316_uint_round_trip", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalUintRoundTrip(ctx, client, peerID, tp, "v316-roundtrip",
			uint64(1<<64-2))
		if err != nil {
			return FailCheck("uint round-trip: " + err.Error())
		}
		// (MaxUint-1)/2 unsigned = 2^63-1.
		if !numEq(val, float64((uint64(1)<<63)-1)) {
			return FailCheck(fmt.Sprintf("expected 2^63-1 after round-trip + cast div, got %v (%T)", val, val))
		}
		return PassCheck("store → read → cast(uint) → div(2) preserves unsigned interpretation (JVM-model lean confirmed)")
	})

	// v3.17 Option A: cast does NOT survive an `if` branch into a sign-
	// sensitive op. div(if(true, cast(x, uint), x), 2) — the cast is not the
	// direct operand entity of div (the if is), so div uses signed-default.
	// Same value as v316 cast vectors: x = MaxUint-1 = 0xFFF...FE.
	// Signed: -2 / 2 = -1. Unsigned would be 2^63-1 (the v316 unsigned-div
	// result). This vector surfaces the Option A/B divergence.
	r.Run("v317_cast_through_if_branch", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalCastThroughIf(ctx, client, peerID, tp, "v317-cast-if",
			uint64(1<<64-2), uint64(2))
		if err != nil {
			return FailCheck("cast through if div: " + err.Error())
		}
		if !numEq(val, -1) {
			return FailCheck(fmt.Sprintf("expected -1 (signed-default, cast stripped by if), got %v (%T)", val, val))
		}
		return PassCheck("div(if(_, cast(x, uint), x), 2) → -1 (rule 11 v3.17: if drops cast intent)")
	})

	// v3.17 Option A: cast does NOT survive a direct `lookup/scope` indirection.
	// let y = cast(x, uint) in div(y, 2) is already covered by
	// v316_eager_cast_not_through_let; this vector tests a slightly different
	// shape: cast bound at outer scope, looked up via lookup/scope in arithmetic.
	// (The let case already exercises this internally, but a dedicated vector
	// makes the strip point unambiguous in conformance reports.)
	r.Run("v317_cast_through_lookup_scope", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Equivalent to the let case structurally — included for explicit
		// per-strip-point conformance reporting per the v3.17 §2.2 rule 11
		// enumeration.
		val, err := computeEvalCastThroughLet(ctx, client, peerID, tp, "v317-cast-lookup",
			uint64(1<<64-2), uint64(2))
		if err != nil {
			return FailCheck("cast through lookup/scope div: " + err.Error())
		}
		if !numEq(val, -1) {
			return FailCheck(fmt.Sprintf("expected -1 (signed-default, cast stripped by lookup/scope), got %v (%T)", val, val))
		}
		return PassCheck("lookup/scope of let-bound cast → signed-default (rule 11 v3.17 strip point)")
	})

	// v3.17 Option A: cast does NOT survive a closure-arg binding into a
	// sign-sensitive op inside the closure body. apply(lambda(y): div(y, 2),
	// {y: cast(x, uint)}) — the arg is bound into closure scope, stripping
	// the cast intent. Same expected result: -1.
	r.Run("v317_cast_through_closure_arg", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalCastThroughClosureArg(ctx, client, peerID, tp, "v317-cast-closure",
			uint64(1<<64-2), uint64(2))
		if err != nil {
			return FailCheck("cast through closure-arg div: " + err.Error())
		}
		if !numEq(val, -1) {
			return FailCheck(fmt.Sprintf("expected -1 (signed-default, cast stripped by closure-arg binding), got %v (%T)", val, val))
		}
		return PassCheck("apply(lambda, {y: cast(x, uint)}) → div(y, 2) → signed (rule 11 v3.17 strip point)")
	})

	// N.4: compute/numeric-cast.
	r.Run("v314_cast_int_to_uint_negative", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalNumericCast(ctx, client, peerID, tp, "v314-cast-iu",
			int64(-1), "primitive/uint")
		if err != nil {
			return FailCheck("cast(-1, uint): " + err.Error())
		}
		// -1 reinterpreted as uint64 → MaxUint64.
		if !numEq(val, float64(^uint64(0))) {
			return FailCheck(fmt.Sprintf("cast(-1, uint): expected MaxUint64, got %v (%T)", val, val))
		}
		return PassCheck("cast(int(-1), uint) → MaxUint64 (bit-reinterpret)")
	})

	r.Run("v314_cast_float_truncate", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalNumericCast(ctx, client, peerID, tp, "v314-cast-trunc",
			float64(3.7), "primitive/int")
		if err != nil {
			return FailCheck("cast(3.7, int): " + err.Error())
		}
		if !numEq(val, 3) {
			return FailCheck(fmt.Sprintf("cast(3.7, int): expected 3, got %v (%T)", val, val))
		}
		return PassCheck("cast(3.7, int) → 3 (truncate toward zero)")
	})

	r.Run("v314_cast_nan_to_int", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		code, err := computeEvalNumericCastError(ctx, client, peerID, tp, "v314-cast-nan",
			math.NaN(), "primitive/int")
		if err != nil {
			return FailCheck("expected error: " + err.Error())
		}
		if code != "cast_out_of_range" {
			return FailCheck("expected cast_out_of_range, got " + code)
		}
		return PassCheck("cast(NaN, int) → cast_out_of_range")
	})

	r.Run("v314_cast_inf_to_int", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		code, err := computeEvalNumericCastError(ctx, client, peerID, tp, "v314-cast-inf",
			math.Inf(1), "primitive/int")
		if err != nil {
			return FailCheck("expected error: " + err.Error())
		}
		if code != "cast_out_of_range" {
			return FailCheck("expected cast_out_of_range, got " + code)
		}
		return PassCheck("cast(+Inf, int) → cast_out_of_range")
	})

	r.Run("v314_cast_neg_float_to_uint", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		code, err := computeEvalNumericCastError(ctx, client, peerID, tp, "v314-cast-neg",
			float64(-1.5), "primitive/uint")
		if err != nil {
			return FailCheck("expected error: " + err.Error())
		}
		if code != "cast_out_of_range" {
			return FailCheck("expected cast_out_of_range, got " + code)
		}
		return PassCheck("cast(-1.5, uint) → cast_out_of_range")
	})

	r.Run("v314_cast_to_invalid_type", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		code, err := computeEvalNumericCastError(ctx, client, peerID, tp, "v314-cast-bad",
			int64(1), "primitive/bool")
		if err != nil {
			return FailCheck("expected error: " + err.Error())
		}
		if code != "type_mismatch" {
			return FailCheck("expected type_mismatch on non-numeric to_type, got " + code)
		}
		return PassCheck("cast(1, primitive/bool) → type_mismatch")
	})

	// N.2: pinned args types registered at system/type/...
	r.Run("v314_args_types_registered", func() CheckOutcome {
		for _, t := range []string{
			types.TypeComputeMapArgs, types.TypeComputeFilterArgs,
			types.TypeComputeFoldArgs, types.TypeComputeStoreArgs,
		} {
			if _, _, err := client.TreeGet(ctx, "system/type/"+t); err != nil {
				return FailCheck("args type not registered: " + t)
			}
		}
		return PassCheck("all 4 builtin args types registered")
	})

	// N.2: builtin handler dispatch as inline alias.
	r.Run("v314_builtin_arithmetic_alias", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBuiltinArithmetic(ctx, client, peerID, tp, "v314-blt-arith",
			"add", uint64(3), uint64(4))
		if err != nil {
			return FailCheck("builtin arithmetic alias: " + err.Error())
		}
		if !numEq(val, 7) {
			return FailCheck(fmt.Sprintf("builtin add(3,4): expected 7, got %v (%T)", val, val))
		}
		return PassCheck("apply(builtins/arithmetic, add, 3, 4) → 7 (alias §3.5)")
	})

	r.Run("v314_builtin_map", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBuiltinMap(ctx, client, peerID, tp, "v314-blt-map",
			[]interface{}{uint64(10), uint64(20), uint64(30)})
		if err != nil {
			return FailCheck("builtin map: " + err.Error())
		}
		arr, ok := val.([]interface{})
		if !ok || len(arr) != 3 {
			return FailCheck(fmt.Sprintf("expected 3-element array, got %v (%T)", val, val))
		}
		want := []float64{11, 21, 31}
		for i, w := range want {
			if !numEq(arr[i], w) {
				return FailCheck(fmt.Sprintf("map[%d]: expected %v, got %v (%T)", i, w, arr[i], arr[i]))
			}
		}
		return PassCheck("map(lambda x: x+1, [10,20,30]) → [11,21,31]")
	})

	r.Run("v314_builtin_filter", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBuiltinFilter(ctx, client, peerID, tp, "v314-blt-filter",
			[]interface{}{uint64(1), uint64(7), uint64(3), uint64(9), uint64(2)})
		if err != nil {
			return FailCheck("builtin filter: " + err.Error())
		}
		arr, ok := val.([]interface{})
		if !ok || len(arr) != 2 {
			return FailCheck(fmt.Sprintf("expected 2-element array, got %v (%T)", val, val))
		}
		if !numEq(arr[0], 7) || !numEq(arr[1], 9) {
			return FailCheck(fmt.Sprintf("expected [7,9], got %v", arr))
		}
		return PassCheck("filter(lambda x: x>5, [1,7,3,9,2]) → [7,9]")
	})

	r.Run("v314_builtin_fold", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBuiltinFold(ctx, client, peerID, tp, "v314-blt-fold",
			[]interface{}{uint64(1), uint64(2), uint64(3), uint64(4)}, uint64(0))
		if err != nil {
			return FailCheck("builtin fold: " + err.Error())
		}
		if !numEq(val, 10) {
			return FailCheck(fmt.Sprintf("fold(+, [1..4], 0): expected 10, got %v (%T)", val, val))
		}
		return PassCheck("fold(lambda acc,x: acc+x, [1,2,3,4], 0) → 10")
	})

	r.Run("v314_builtin_fold_empty", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		val, err := computeEvalBuiltinFold(ctx, client, peerID, tp, "v314-blt-fold-empty",
			[]interface{}{}, uint64(42))
		if err != nil {
			return FailCheck("builtin fold empty: " + err.Error())
		}
		if !numEq(val, 42) {
			return FailCheck(fmt.Sprintf("fold(+, [], 42): expected 42, got %v (%T)", val, val))
		}
		return PassCheck("fold(_, [], 42) → 42 (initial returned for empty)")
	})

	// Cross-cutting: builtinStore must dispatch through system/tree:put and
	// the value MUST become readable at the target path. Exercises the
	// integration between v3.14's store builtin (§3.5), §6.3 W4 capability
	// gating (handled by the tree handler), and V7 §6.6 in-process dispatch.
	r.Run("v314_builtin_store_roundtrip", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		targetPath := tp + "/v314-store-target"
		qualTarget := fmt.Sprintf("/%s/%s", peerID, targetPath)

		pathLit, _ := types.ComputeLiteralData{Value: qualTarget}.ToEntity()
		valueLit, _ := types.ComputeLiteralData{Value: uint64(123)}.ToEntity()
		pathH := putCE(ctx, client, tp+"/v314-store-path", pathLit)
		valueH := putCE(ctx, client, tp+"/v314-store-val", valueLit)

		apply, err := types.ComputeApplyData{
			Path:      "system/compute/builtins/store",
			Operation: "eval",
			Args:      map[string]hash.Hash{"path": pathH, "value": valueH},
		}.ToEntity()
		if err != nil {
			return FailCheck("build apply: " + err.Error())
		}
		applyPath := tp + "/v314-store-apply"
		if _, err := client.TreePut(ctx, applyPath, apply); err != nil {
			return FailCheck("put apply: " + err.Error())
		}

		// Eval drives the side effect.
		resp, err := computeEvalAtPath(ctx, client, peerID, applyPath)
		if err != nil {
			return FailCheck("eval apply: " + err.Error())
		}
		if resp.Status != 200 {
			code, _ := decodeComputeErrorCode(resp)
			return FailCheck(fmt.Sprintf("eval status=%d code=%s — store builtin should dispatch system/tree:put", resp.Status, code))
		}

		// Verify the value actually landed.
		readEnt, _, err := client.TreeGet(ctx, targetPath)
		if err != nil {
			return FailCheck("read written value: " + err.Error())
		}
		if readEnt.Type != "primitive/any" {
			return FailCheck(fmt.Sprintf("expected primitive/any at %s, got %s", targetPath, readEnt.Type))
		}
		// Confirm the encoded value is 123.
		var got interface{}
		if err := ecf.Decode(readEnt.Data, &got); err != nil {
			return FailCheck("decode written value: " + err.Error())
		}
		if !numEq(got, 123) {
			return FailCheck(fmt.Sprintf("expected 123 at %s, got %v (%T)", targetPath, got, got))
		}
		return PassCheck("builtin store wrote uint(123) to " + targetPath + " via dispatch chain")
	})

	// Cross-cutting: compute/apply handler-mode dispatching to an entity-
	// native handler. Exercises the integration between v3.14 compute and
	// V7 §6.6 / PROPOSAL-DISPATCH-CONTRACT-SCOPE A.1 (tree-walk dispatch +
	// EvaluateExpression hook). v38_apply_handler_mode covers dispatch to a
	// compiled handler (system/compute); this covers the entity-native
	// branch where the target's tree entry has expression_path set.
	r.Run("v314_compute_apply_to_entity_native", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		slot := "app/validate/entity-native/v314-cross"
		exprPath := slot + "/expr"

		// Target expression: params.x + 1.
		paramsLookup, _ := types.ComputeLookupScopeData{Name: "params"}.ToEntity()
		pLookupH := putCE(ctx, client, slot+"/p-lookup", paramsLookup)
		fieldX, _ := types.ComputeFieldData{Name: "x", Entity: pLookupH}.ToEntity()
		fieldXH := putCE(ctx, client, slot+"/field-x", fieldX)
		one, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
		oneH := putCE(ctx, client, slot+"/one", one)
		addExpr, _ := types.ComputeArithmeticData{Op: "add", Left: fieldXH, Right: oneH}.ToEntity()
		if _, err := client.TreePut(ctx, exprPath, addExpr); err != nil {
			return FailCheck("put expr: " + err.Error())
		}
		if err := registerHandler(ctx, client, peerID, slot, exprPath, wildcardScope(peerID)); err != nil {
			return FailCheck("register entity-native handler: " + err.Error())
		}

		// Caller compute expression: apply(slot, "compute", {x: literal(41)}).
		// Builds the params entity from a single arg.
		xLit, _ := types.ComputeLiteralData{Value: uint64(41)}.ToEntity()
		xLitH := putCE(ctx, client, tp+"/v314-cross-x", xLit)
		callerApply, _ := types.ComputeApplyData{
			Path:      slot,
			Operation: "compute",
			Args:      map[string]hash.Hash{"x": xLitH},
		}.ToEntity()
		callerPath := tp + "/v314-cross-caller"
		if _, err := client.TreePut(ctx, callerPath, callerApply); err != nil {
			return FailCheck("put caller: " + err.Error())
		}

		val, err := extractResultValue(ctx, client, peerID, callerPath)
		if err != nil {
			return FailCheck("eval compute → entity-native: " + err.Error())
		}
		// Entity-native handlers wrap bare primitive results in the declared
		// output_type (default primitive/any) — see compute/handler.go
		// unwrapEntityNativeResult. compute/apply returns the wrapped entity
		// as-is; consumers downstream of the apply must decode the wrapper to
		// recover the primitive. See SA-COMPUTE-V314-5 in
		// COMPUTE-V314-CROSS-IMPL-DIVERGENCES.md.
		if ent, ok := val.(entity.Entity); ok && ent.Type == "primitive/any" {
			var raw interface{}
			if err := ecf.Decode(ent.Data, &raw); err != nil {
				return FailCheck("decode primitive/any wrapper: " + err.Error())
			}
			val = raw
		}
		if !numEq(val, 42) {
			return FailCheck(fmt.Sprintf("expected 42 (41 + 1), got %v (%T)", val, val))
		}
		return PassCheck("compute/apply → entity-native handler → params.x+1 = 42 (v3.14 ↔ V7 §6.6 integration)")
	})

	// --- v3.19 conformance vectors (PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE) ---

	// N.5 vector A: field(field(literal({user:{name:"alice"}}),"user"),"name") → "alice".
	// The inner field returns a bare record/map (not an entity); the outer field
	// must accept it. Pre-N.5 impls reject the outer field with type_mismatch.
	r.Run("v319_n5_nested_field", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		litEnt, _ := types.ComputeLiteralData{Value: map[string]interface{}{
			"user": map[string]interface{}{"name": "alice"},
		}}.ToEntity()
		litH := putCE(ctx, client, tp+"/v319-n5-lit", litEnt)
		userField, _ := types.ComputeFieldData{Name: "user", Entity: litH}.ToEntity()
		userH := putCE(ctx, client, tp+"/v319-n5-user", userField)
		nameField, _ := types.ComputeFieldData{Name: "name", Entity: userH}.ToEntity()
		path := tp + "/v319-n5-nested"
		if _, err := client.TreePut(ctx, path, nameField); err != nil {
			return FailCheck("put nested field: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval nested field: " + err.Error())
		}
		if val != "alice" {
			return FailCheck(fmt.Sprintf("expected 'alice', got %v (%T)", val, val))
		}
		return PassCheck("field(field(literal({user:{name:'alice'}}),'user'),'name') → 'alice'")
	})

	// N.5 vector B: a filter whose lambda closes over a record-valued scope
	// binding and navigates into it. Exercises the closure-capture + scope
	// round-trip + N.5 bare-map field path. Uses a bare-map literal (not an
	// entity) to avoid the F9-B-residual scope-binding-identity issue that is
	// filed for spec resolution; the spec-intended success path is what's
	// tested here.
	r.Run("v319_n5_closure_field", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		paramsLit, _ := types.ComputeLiteralData{Value: map[string]interface{}{
			"numbers":   []interface{}{uint64(1), uint64(15), uint64(3), uint64(20)},
			"threshold": uint64(10),
		}}.ToEntity()
		paramsLitH := putCE(ctx, client, tp+"/v319-cf-params", paramsLit)

		lookupParams1, _ := types.ComputeLookupScopeData{Name: "params"}.ToEntity()
		lookupParams1H := putCE(ctx, client, tp+"/v319-cf-lookup1", lookupParams1)
		numbersField, _ := types.ComputeFieldData{Name: "numbers", Entity: lookupParams1H}.ToEntity()
		numbersH := putCE(ctx, client, tp+"/v319-cf-numbers", numbersField)

		lookupParams2, _ := types.ComputeLookupScopeData{Name: "params"}.ToEntity()
		lookupParams2H := putCE(ctx, client, tp+"/v319-cf-lookup2", lookupParams2)
		thresholdField, _ := types.ComputeFieldData{Name: "threshold", Entity: lookupParams2H}.ToEntity()
		thresholdH := putCE(ctx, client, tp+"/v319-cf-threshold", thresholdField)

		lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
		lookupXH := putCE(ctx, client, tp+"/v319-cf-x", lookupX)
		cmpEnt, _ := types.ComputeCompareData{Op: "gt", Left: lookupXH, Right: thresholdH}.ToEntity()
		cmpH := putCE(ctx, client, tp+"/v319-cf-cmp", cmpEnt)

		lambdaEnt, _ := types.ComputeLambdaData{Params: []string{"x"}, Body: cmpH}.ToEntity()
		lambdaH := putCE(ctx, client, tp+"/v319-cf-lambda", lambdaEnt)

		filterApply, _ := types.ComputeApplyData{
			Path:      "system/compute/builtins/filter",
			Operation: "eval",
			Args:      map[string]hash.Hash{"collection": numbersH, "fn": lambdaH},
		}.ToEntity()
		filterH := putCE(ctx, client, tp+"/v319-cf-filter", filterApply)

		letEnt, _ := types.ComputeLetData{
			Bindings: []types.ComputeLetBinding{{Name: "params", Value: paramsLitH}},
			Body:     filterH,
		}.ToEntity()
		path := tp + "/v319-n5-closure"
		if _, err := client.TreePut(ctx, path, letEnt); err != nil {
			return FailCheck("put closure-field: " + err.Error())
		}

		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval closure-field: " + err.Error())
		}
		arr, ok := val.([]interface{})
		if !ok {
			return FailCheck(fmt.Sprintf("expected array, got %T", val))
		}
		if len(arr) != 2 || !numEq(arr[0], 15) || !numEq(arr[1], 20) {
			return FailCheck(fmt.Sprintf("expected [15, 20], got %v", arr))
		}
		return PassCheck("filter with lambda closing over scope.params and field-navigating into it → [15, 20]")
	})

	// N.5 vector C: two-level field chain over a literal-record-of-records,
	// matching the compute→compute-compose shape (outer extracts inner.value
	// then inner.value.sum). Tests that an intermediate bare-map value remains
	// a valid field target.
	r.Run("v319_n5_compute_compose", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		litEnt, _ := types.ComputeLiteralData{Value: map[string]interface{}{
			"value": map[string]interface{}{"sum": uint64(1060), "count": uint64(53)},
		}}.ToEntity()
		litH := putCE(ctx, client, tp+"/v319-cc-lit", litEnt)
		valueField, _ := types.ComputeFieldData{Name: "value", Entity: litH}.ToEntity()
		valueH := putCE(ctx, client, tp+"/v319-cc-value", valueField)
		sumField, _ := types.ComputeFieldData{Name: "sum", Entity: valueH}.ToEntity()
		path := tp + "/v319-n5-compose"
		if _, err := client.TreePut(ctx, path, sumField); err != nil {
			return FailCheck("put compose field: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval compose field: " + err.Error())
		}
		if !numEq(val, 1060) {
			return FailCheck(fmt.Sprintf("expected 1060, got %v (%T)", val, val))
		}
		return PassCheck("field(field(literal({value:{sum:1060}}),'value'),'sum') → 1060 (compute→compose navigation shape)")
	})

	// N.5 disambiguation gate: a legit record whose key names happen to be the
	// {type, data, content_hash} envelope-key set must navigate as a bare record
	// (return the record's `name` field as a string), NOT envelope-peeled (which
	// would silently drop fields). Python's `_field_record` peels {type, data}
	// envelopes via heuristic — proven by Python's own memo §2 to silently drop
	// fields on the legit-record case. Go's evalField reads any map flat. This
	// vector exposes the cross-impl disambiguation divergence today and tracks
	// the v3.19b TO-VERIFY item (the disambiguation rule requires the kind tag).
	r.Run("v319_n5_disambiguation", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// literal({"type": "premium", "data": {"x": 1}, "name": "alice"})
		// — a legit record using key names that envelope-peeling would misread.
		recLit, _ := types.ComputeLiteralData{Value: map[string]interface{}{
			"type": "premium",
			"data": map[string]interface{}{"x": uint64(1)},
			"name": "alice",
		}}.ToEntity()
		recH := putCE(ctx, client, tp+"/v319-disamb-rec", recLit)

		// field(rec, "name") — must return "alice" (the record's name field).
		// An envelope-peeling impl would navigate into rec["data"] and miss "name".
		nameField, _ := types.ComputeFieldData{Name: "name", Entity: recH}.ToEntity()
		path := tp + "/v319-disambig-name"
		if _, err := client.TreePut(ctx, path, nameField); err != nil {
			return FailCheck("put disambig field: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval disambig field: " + err.Error() + " — envelope-peeling impls may misread the record as an entity envelope and miss 'name'")
		}
		if val != "alice" {
			return FailCheck(fmt.Sprintf("disambig field('name'): expected 'alice' (flat record read), got %v (%T) — likely envelope-peel heuristic silently dropped the field", val, val))
		}
		return PassCheck("field({type:'premium', data:{x:1}, name:'alice'}, 'name') → 'alice' (record read, NOT envelope-peeled)")
	})

	// F10 strict status-pin: index([10,20], 99) → status 200, compute/error,
	// code=index_out_of_range. Pre-fix impls return status 400 — this is the
	// cross-impl gate for the F10 atomic cut.
	r.Run("v319_f10_error_at_200", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		arrLit, _ := types.ComputeLiteralData{Value: []interface{}{uint64(10), uint64(20)}}.ToEntity()
		arrH := putCE(ctx, client, tp+"/v319-f10-arr", arrLit)
		idxLit, _ := types.ComputeLiteralData{Value: uint64(99)}.ToEntity()
		idxH := putCE(ctx, client, tp+"/v319-f10-idx", idxLit)
		idxEnt, _ := types.ComputeIndexData{Array: arrH, Index: idxH}.ToEntity()
		path := tp + "/v319-f10"
		if _, err := client.TreePut(ctx, path, idxEnt); err != nil {
			return FailCheck("put index expr: " + err.Error())
		}
		resp, err := computeEvalAtPath(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval index out-of-range: " + err.Error())
		}
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("F10: expected status 200 for evaluated compute/error, got %d (pre-v3.19 impl)", resp.Status))
		}
		code, err := decodeComputeErrorCodeAnyStatus(resp)
		if err != nil {
			return FailCheck("F10 result body: " + err.Error())
		}
		if code != "index_out_of_range" {
			return FailCheck(fmt.Sprintf("F10: expected code=index_out_of_range, got %s", code))
		}
		return PassCheck("index([10,20], 99) → status=200, type=compute/error, code=index_out_of_range (F10 strict pin)")
	})

	// F11 strict arg-key gate: builtins/filter with lambda passed under "fn"
	// (the v3.19 rename of "predicate"). Pre-fix impls expecting "predicate"
	// return a not_found / missing-arg compute/error on this vector.
	r.Run("v319_f11_filter_fn_arg", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// lambda(x): x > 5 — same shape as buildGreaterThanFiveLambda, inlined
		// here so the test is self-contained and obviously exercising "fn".
		lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
		lookupXH := putCE(ctx, client, tp+"/v319-f11-x", lookupX)
		five, _ := types.ComputeLiteralData{Value: uint64(5)}.ToEntity()
		fiveH := putCE(ctx, client, tp+"/v319-f11-five", five)
		cmpEnt, _ := types.ComputeCompareData{Op: "gt", Left: lookupXH, Right: fiveH}.ToEntity()
		cmpH := putCE(ctx, client, tp+"/v319-f11-cmp", cmpEnt)
		lambdaEnt, _ := types.ComputeLambdaData{Params: []string{"x"}, Body: cmpH}.ToEntity()
		lambdaH := putCE(ctx, client, tp+"/v319-f11-lambda", lambdaEnt)

		collLit, _ := types.ComputeLiteralData{Value: []interface{}{
			uint64(1), uint64(7), uint64(3), uint64(9), uint64(2),
		}}.ToEntity()
		collH := putCE(ctx, client, tp+"/v319-f11-coll", collLit)

		filterApply, _ := types.ComputeApplyData{
			Path:      "system/compute/builtins/filter",
			Operation: "eval",
			// F11: under v3.19 the lambda key is "fn", not "predicate".
			Args: map[string]hash.Hash{"collection": collH, "fn": lambdaH},
		}.ToEntity()
		path := tp + "/v319-f11"
		if _, err := client.TreePut(ctx, path, filterApply); err != nil {
			return FailCheck("put filter apply: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval filter with fn arg: " + err.Error() + " (pre-v3.19 impls likely still expect 'predicate')")
		}
		arr, ok := val.([]interface{})
		if !ok {
			return FailCheck(fmt.Sprintf("expected array, got %T", val))
		}
		if len(arr) != 2 || !numEq(arr[0], 7) || !numEq(arr[1], 9) {
			return FailCheck(fmt.Sprintf("expected [7, 9], got %v", arr))
		}
		return PassCheck("filter([1,7,3,9,2], lambda(x): x>5) with arg key 'fn' → [7, 9] (F11 rename accepted)")
	})

	// --- v3.19b CORE conformance vectors (PROPOSAL §5b; EXTENSION-COMPUTE v3.19b §2.3) ---

	// N1+N3+N4: kind-tagged scope binding round-trip.
	// Construct an app/user entity inline; Let-bind it into scope; apply a
	// closure that captures the scope and navigates field(user, "name"). The
	// scope round-trip MUST preserve entity identity (kind="entity" binding
	// resolves to the same entity at load time) and field navigation MUST go
	// through .data (N3: navigate-by-kind, not flat). Pre-v3.19b impls that
	// inline the envelope into scope (Go) or store an opaque hash (Rust)
	// produce a wrong-level navigation; this vector flips green when each
	// impl cuts v3.19b.
	r.Run("v319b_scope_entity_round_trip", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// app/user entity built via compute/construct
		nameLit, _ := types.ComputeLiteralData{Value: "alice"}.ToEntity()
		nameH := putCE(ctx, client, tp+"/v319b-rt-name", nameLit)
		userConstruct, _ := types.ComputeConstructData{
			EntityType: "app/user",
			Fields:     map[string]hash.Hash{"name": nameH},
		}.ToEntity()
		userH := putCE(ctx, client, tp+"/v319b-rt-user", userConstruct)

		// Inside the lambda body: field(scope.user_ent, "name")
		lookupUser, _ := types.ComputeLookupScopeData{Name: "user_ent"}.ToEntity()
		lookupUserH := putCE(ctx, client, tp+"/v319b-rt-lookup", lookupUser)
		nameField, _ := types.ComputeFieldData{Name: "name", Entity: lookupUserH}.ToEntity()
		nameFieldH := putCE(ctx, client, tp+"/v319b-rt-field", nameField)

		// Lambda body wrapping (single-arg, body navigates scope)
		lambdaEnt, _ := types.ComputeLambdaData{Params: []string{"_"}, Body: nameFieldH}.ToEntity()
		lambdaH := putCE(ctx, client, tp+"/v319b-rt-lambda", lambdaEnt)

		// Apply the lambda with a dummy arg — the closure captures scope on
		// evaluation and the body retrieves user_ent through LoadScope.
		zero, _ := types.ComputeLiteralData{Value: uint64(0)}.ToEntity()
		zeroH := putCE(ctx, client, tp+"/v319b-rt-zero", zero)
		apply, _ := types.ComputeApplyData{
			Fn:   lambdaH,
			Args: map[string]hash.Hash{"_": zeroH},
		}.ToEntity()
		applyH := putCE(ctx, client, tp+"/v319b-rt-apply", apply)

		// Let("user_ent", <constructed entity>, apply(...))
		letEnt, _ := types.ComputeLetData{
			Bindings: []types.ComputeLetBinding{{Name: "user_ent", Value: userH}},
			Body:     applyH,
		}.ToEntity()
		path := tp + "/v319b-scope-rt"
		if _, err := client.TreePut(ctx, path, letEnt); err != nil {
			return FailCheck("put scope-round-trip expr: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval scope-round-trip: " + err.Error() + " (pre-v3.19b impls likely lose entity identity in capture/load)")
		}
		if val != "alice" {
			return FailCheck(fmt.Sprintf("expected 'alice' (entity round-trip preserved + navigate-by-kind to .data), got %v (%T)", val, val))
		}
		return PassCheck("Let(user_ent=construct app/user{name:alice}, apply(λ_. field(scope.user_ent,'name'), [0])) → 'alice' (v3.19b N1+N3+N4)")
	})

	// N8 + F10: scope_unreachable as error-as-value at status 200.
	// Build a closure manually whose env points at a compute/scope entity
	// containing a binding hash that doesn't resolve. Apply the closure;
	// expect compute/error{scope_unreachable} at status 200 (not transport
	// failure).
	r.Run("v319b_scope_unreachable", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Fabricate a hash that won't resolve in any content store.
		// 33 bytes: algorithm byte (0x00 = ECFv1-SHA256, per hash.AlgorithmSHA256)
		// + 32 0xFF bytes. Valid shape but vanishingly unlikely to be the hash
		// of any real entity.
		ghostHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
		for i := 0; i < hash.SHA256DigestSize; i++ {
			ghostHash.Digest[i] = 0xff
		}

		// Build a compute/scope entity with one kind=entity binding pointing
		// at the ghost hash. PutEntity it locally so the closure's env
		// resolves but its binding does not.
		scopeData := types.ComputeScopeData{
			Bindings: map[string]types.ComputeScopeBinding{
				"ghost": {
					Kind:       types.ScopeBindingKindEntity,
					EntityHash: &ghostHash,
				},
			},
		}
		scopeEnt, err := scopeData.ToEntity()
		if err != nil {
			return FailCheck("build scope entity: " + err.Error())
		}
		// Store the scope entity at a tree path so the receiver has it locally.
		scopePath := tp + "/v319b-unreach-scope"
		if _, err := client.TreePut(ctx, scopePath, scopeEnt); err != nil {
			return FailCheck("put scope entity: " + err.Error())
		}

		// Body: a literal — the body itself never references the ghost binding,
		// but load_scope eagerly resolves all bindings on apply per N8.
		bodyLit, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		bodyH := putCE(ctx, client, tp+"/v319b-unreach-body", bodyLit)

		// Build a closure manually referencing the scope.
		scopeHash := scopeEnt.ContentHash
		closureData := types.ComputeClosureData{
			Params: []string{"_"},
			Body:   bodyH,
			Env:    &scopeHash,
		}
		closureEnt, err := closureData.ToEntity()
		if err != nil {
			return FailCheck("build closure entity: " + err.Error())
		}
		closurePath := tp + "/v319b-unreach-closure"
		if _, err := client.TreePut(ctx, closurePath, closureEnt); err != nil {
			return FailCheck("put closure entity: " + err.Error())
		}

		// Apply the closure: load_scope tries to resolve "ghost" → miss → N8.
		zero, _ := types.ComputeLiteralData{Value: uint64(0)}.ToEntity()
		zeroH := putCE(ctx, client, tp+"/v319b-unreach-zero", zero)
		closureH := closureEnt.ContentHash
		apply, _ := types.ComputeApplyData{
			Fn:   closureH,
			Args: map[string]hash.Hash{"_": zeroH},
		}.ToEntity()
		applyPath := tp + "/v319b-unreach-apply"
		if _, err := client.TreePut(ctx, applyPath, apply); err != nil {
			return FailCheck("put apply: " + err.Error())
		}

		resp, err := computeEvalAtPath(ctx, client, peerID, applyPath)
		if err != nil {
			return FailCheck("eval scope-unreachable: " + err.Error())
		}
		// F10: must surface as a compute/error VALUE at status 200, not a
		// transport-layer 4xx.
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("expected status 200 (error-as-value per F10), got %d", resp.Status))
		}
		code, err := decodeComputeErrorCodeAnyStatus(resp)
		if err != nil {
			return FailCheck("decode error code: " + err.Error())
		}
		if code != "scope_unreachable" {
			return FailCheck(fmt.Sprintf("expected code=scope_unreachable (N8), got %s", code))
		}
		return PassCheck("apply(closure with env→scope having ghost-hash binding) → status=200, compute/error{scope_unreachable} (v3.19b N8 + F10)")
	})

	// N2 ratification: capture a fixed-content scope; verify all three impls
	// produce identical compute/scope content hashes. The vector stages a
	// Let with one value binding (uint=42); the lambda body looks up the
	// binding to force scope-capture. Eval the lambda (no apply) → returns
	// the closure entity. closure.env is the captured scope's hash. Print
	// it in the PASS message so cross-impl runs can compare bit-for-bit.
	r.Run("v319b_scope_hash_agreement", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// scope binding "n" = 42 (value-kind)
		lit42, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		lit42H := putCE(ctx, client, tp+"/v319b-hashagr-42", lit42)

		// lambda body: lookup_scope("n") — forces scope capture of "n"
		lookupN, _ := types.ComputeLookupScopeData{Name: "n"}.ToEntity()
		lookupNH := putCE(ctx, client, tp+"/v319b-hashagr-lookup", lookupN)
		lambdaEnt, _ := types.ComputeLambdaData{Params: []string{"_"}, Body: lookupNH}.ToEntity()
		lambdaH := putCE(ctx, client, tp+"/v319b-hashagr-lambda", lambdaEnt)

		// Let("n", 42, lambda(_)→lookup_scope("n")) → produces a closure
		letEnt, _ := types.ComputeLetData{
			Bindings: []types.ComputeLetBinding{{Name: "n", Value: lit42H}},
			Body:     lambdaH,
		}.ToEntity()
		path := tp + "/v319b-hashagr-let"
		if _, err := client.TreePut(ctx, path, letEnt); err != nil {
			return FailCheck("put let: " + err.Error())
		}

		// Eval — result is the closure entity (returned directly per SA-1)
		resp, err := computeEvalAtPath(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval: " + err.Error())
		}
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("status %d (expected 200)", resp.Status))
		}
		resultEnt, err := decodeComputeEntity(resp)
		if err != nil {
			return FailCheck("decode: " + err.Error())
		}
		if resultEnt.Type != types.TypeComputeClosure {
			return FailCheck(fmt.Sprintf("expected compute/closure, got %s", resultEnt.Type))
		}
		var cd types.ComputeClosureData
		if err := ecf.Decode(resultEnt.Data, &cd); err != nil {
			return FailCheck("decode closure: " + err.Error())
		}
		if cd.Env == nil || cd.Env.IsZero() {
			return FailCheck("closure.env is missing — scope wasn't captured")
		}
		// PASS message includes the scope hash so cross-impl runs can
		// compare bit-for-bit. Identical scope contents (one value-kind
		// binding "n"=42 in ECF canonical form) MUST produce identical
		// content hashes across Go/Rust/Python.
		return PassCheck(fmt.Sprintf("compute/scope hash for Let(n=42, λ_.lookup_scope(n)): %s (v3.19b N2 — must match cross-impl)", cd.Env.String()))
	})

	// N5 measurement vector: a compute/construct with one entity-valued
	// field. The field expression is a construct that yields an entity;
	// the outer construct then has that entity in its `name` field position.
	// Per v3.19b N1, entity-valued fields should be referenced-by-hash; per
	// the deferred N5, impls may currently inline or hash-ref differently.
	// Prints the constructed entity's content_hash so cross-impl divergence
	// is observable. (If the hashes match, N5 is observably consistent and
	// closes via doc-only spec text. If they differ, N5 needs alignment in
	// v3.19c.)
	// v3.19c Part A — the genome-identity gate. Builds the same compute/
	// construct expression Go's v3.19c cut targets: app/wrapper{inner: app/
	// user{name:"alice"}}. Per N1, the entity-valued `inner` field is hash-
	// ref'd + kind-tagged (`{kind:"entity", entity_hash:H}`); per A.4 the
	// encoding reuses the scope-binding encoder so the canonical bytes match
	// scope's N2 wire shape exactly. Identical input → bit-identical
	// constructed-entity content_hash three-way. Reports Go's hash in the
	// PASS message so cross-impl runs can compare directly.
	r.Run("v319c_construct_entity_valued_field", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Inner construct: app/user{name: "alice"} — produces an entity.
		nameLit, _ := types.ComputeLiteralData{Value: "alice"}.ToEntity()
		nameH := putCE(ctx, client, tp+"/v319c-cf-name", nameLit)
		innerConstruct, _ := types.ComputeConstructData{
			EntityType: "app/user",
			Fields:     map[string]hash.Hash{"name": nameH},
		}.ToEntity()
		innerH := putCE(ctx, client, tp+"/v319c-cf-inner", innerConstruct)

		// Outer construct: app/wrapper{inner: <app/user entity>}.
		// Under v3.19c R3, the materialized form has bare data per V7 §1.4:
		// `inner` becomes a bare 33-byte system/hash content_hash of the
		// inner app/user entity. The materialized constructed-entity hash
		// MUST equal the hand-built form (entity.NewEntity with the same
		// shape).
		outerConstruct, _ := types.ComputeConstructData{
			EntityType: "app/wrapper",
			Fields:     map[string]hash.Hash{"inner": innerH},
		}.ToEntity()
		path := tp + "/v319c-cf-outer"
		if _, err := client.TreePut(ctx, path, outerConstruct); err != nil {
			return FailCheck("put outer construct: " + err.Error())
		}
		resp, err := computeEvalAtPath(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval outer: " + err.Error())
		}
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("status %d (expected 200)", resp.Status))
		}
		resultEnt, err := decodeComputeEntity(resp)
		if err != nil {
			return FailCheck("decode: " + err.Error())
		}
		if resultEnt.Type != "app/wrapper" {
			return FailCheck(fmt.Sprintf("expected app/wrapper, got %s", resultEnt.Type))
		}
		// Build the hand-built reference: app/user{name:"alice"} via NewEntity,
		// then app/wrapper{inner: <hash of that>} via NewEntity. The compute-
		// constructed hash MUST equal this reference per M1.
		handBuiltInnerData, _ := ecf.Encode(map[string]interface{}{"name": "alice"})
		handBuiltInner, _ := entity.NewEntity("app/user", cbor.RawMessage(handBuiltInnerData))
		handBuiltOuterData, _ := ecf.Encode(map[string]interface{}{"inner": handBuiltInner.ContentHash})
		handBuiltOuter, _ := entity.NewEntity("app/wrapper", cbor.RawMessage(handBuiltOuterData))
		if resultEnt.ContentHash != handBuiltOuter.ContentHash {
			return FailCheck(fmt.Sprintf("materialized compute-constructed hash %s != hand-built hash %s — M1 violation (per V7 §1.4 they MUST be byte-identical)", resultEnt.ContentHash, handBuiltOuter.ContentHash))
		}
		return PassCheck(fmt.Sprintf("compute-constructed app/wrapper{inner=app/user{name:'alice'}} content_hash %s == hand-built form (v3.19c R3 M1: materialized == hand-built per V7 §1.4)", resultEnt.ContentHash))
	})

	// v3.19c Part A R3: in-flight navigation chain through constructed
	// entities. The whole chain is a single compute eval — outer construct
	// and inner construct both produce in-flight *constructedValue typed
	// forms; evalField navigates typed fields directly (no shape sniff). No
	// materialization happens between hops because there's no boundary
	// crossing mid-chain. Once a constructed entity is materialized at a
	// boundary, subsequent navigation through it follows V7-bare convention
	// (explicit compute/lookup/hash for entity-valued fields).
	r.Run("v319c_construct_navigation_chain", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Build: outer = construct(app/wrapper, {inner: construct(app/user, {name:"alice"})})
		nameLit, _ := types.ComputeLiteralData{Value: "alice"}.ToEntity()
		nameH := putCE(ctx, client, tp+"/v319c-nav-name", nameLit)
		innerCtor, _ := types.ComputeConstructData{
			EntityType: "app/user",
			Fields:     map[string]hash.Hash{"name": nameH},
		}.ToEntity()
		innerH := putCE(ctx, client, tp+"/v319c-nav-inner", innerCtor)
		outerCtor, _ := types.ComputeConstructData{
			EntityType: "app/wrapper",
			Fields:     map[string]hash.Hash{"inner": innerH},
		}.ToEntity()
		outerH := putCE(ctx, client, tp+"/v319c-nav-outer", outerCtor)

		// field(outer, "inner") — must transparently unwrap kind:"entity"
		innerField, _ := types.ComputeFieldData{Name: "inner", Entity: outerH}.ToEntity()
		innerFieldH := putCE(ctx, client, tp+"/v319c-nav-field-inner", innerField)

		// field(field(outer, "inner"), "name") — must unwrap kind:"value"
		nameField, _ := types.ComputeFieldData{Name: "name", Entity: innerFieldH}.ToEntity()
		path := tp + "/v319c-nav-chain"
		if _, err := client.TreePut(ctx, path, nameField); err != nil {
			return FailCheck("put nav chain: " + err.Error())
		}

		val, err := extractResultValue(ctx, client, peerID, path)
		if err != nil {
			return FailCheck("eval nav chain: " + err.Error() + " — pre-v3.19c impls may not unwrap kind-tagged construct fields, breaking composition")
		}
		if val != "alice" {
			return FailCheck(fmt.Sprintf("nav chain: expected 'alice', got %v (%T)", val, val))
		}
		return PassCheck("field(field(construct(app/wrapper,{inner:construct(app/user,{name:'alice'})}),'inner'),'name') → 'alice' (v3.19c Part A — navigation composes through constructed entities via kind-tag unwrap)")
	})

	// v3.19c Part A R3 — Rust's parity catch (adopted defensively).
	// Build the same logical construct two ways: (a) directly via the inline
	// compute/construct expression evaluator, (b) via system/compute/builtins/
	// construct handler-form alias. Materialized content_hashes MUST match.
	// On Go's single-path impl (builtins.go::builtinConstruct delegates to
	// inline evalConstruct via evaluateInner), this passes trivially. On any
	// future impl that introduces a fork, it catches the bug class Rust hit.
	r.Run("v319c_inline_vs_builtin_construct_hash_agreement", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Common field literal
		nLit, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
		nH := putCE(ctx, client, tp+"/v319c-parity-n", nLit)

		// Path (a): inline compute/construct expression
		inlineCtor, _ := types.ComputeConstructData{
			EntityType: "app/parity",
			Fields:     map[string]hash.Hash{"n": nH},
		}.ToEntity()
		inlinePath := tp + "/v319c-parity-inline"
		if _, err := client.TreePut(ctx, inlinePath, inlineCtor); err != nil {
			return FailCheck("put inline: " + err.Error())
		}
		respA, err := computeEvalAtPath(ctx, client, peerID, inlinePath)
		if err != nil {
			return FailCheck("inline eval: " + err.Error())
		}
		if respA.Status != 200 {
			return FailCheck(fmt.Sprintf("inline status %d", respA.Status))
		}
		inlineEnt, err := decodeComputeEntity(respA)
		if err != nil {
			return FailCheck("inline decode: " + err.Error())
		}

		// Path (b): system/compute/builtins/construct handler-form alias.
		// builtinConstruct expects entity_type + the field-name → field-hash
		// mapping in args (skipping the reserved entity_type key).
		entityTypeLit, _ := types.ComputeLiteralData{Value: "app/parity"}.ToEntity()
		etH := putCE(ctx, client, tp+"/v319c-parity-etype", entityTypeLit)
		builtinApply, _ := types.ComputeApplyData{
			Path:      "system/compute/builtins/construct",
			Operation: "eval",
			Args: map[string]hash.Hash{
				"entity_type": etH,
				"n":           nH,
			},
		}.ToEntity()
		builtinPath := tp + "/v319c-parity-builtin"
		if _, err := client.TreePut(ctx, builtinPath, builtinApply); err != nil {
			return FailCheck("put builtin: " + err.Error())
		}
		respB, err := computeEvalAtPath(ctx, client, peerID, builtinPath)
		if err != nil {
			return FailCheck("builtin eval: " + err.Error())
		}
		if respB.Status != 200 {
			return FailCheck(fmt.Sprintf("builtin status %d", respB.Status))
		}
		builtinEnt, err := decodeComputeEntity(respB)
		if err != nil {
			return FailCheck("builtin decode: " + err.Error())
		}

		if inlineEnt.ContentHash != builtinEnt.ContentHash {
			return FailCheck(fmt.Sprintf("inline %s != builtin %s (duplicate-path bug — Rust's catch)",
				inlineEnt.ContentHash, builtinEnt.ContentHash))
		}
		return PassCheck(fmt.Sprintf("inline compute/construct == system/compute/builtins/construct handler-form, content_hash %s (Rust's parity catch — Go's single delegation path passes)", inlineEnt.ContentHash))
	})

	// v3.19c Part A R3 + N3 — cross-impl read-back-nav regression detector.
	// Arch's 6e73d3d ruling: on a *materialized* (stored / hand-built / read
	// back) entity, navigating a system/hash field returns the bare bytes;
	// the caller follows the ref via explicit compute/lookup/hash. The
	// 33-byte-auto-resolve heuristic Rust had pre-fix is forbidden for two
	// independent reasons:
	//   (1) N3 — shape-sniffing is disallowed (would misfire on a real
	//       33-byte primitive bytes value).
	//   (2) Crypto-agility (arch 39bc8a2) — system/hash is variable-length
	//       with an extensible LEB128 format-code (V7 §1.2); 33 bytes is
	//       today's ecfv1-sha256 accident, never an invariant.
	//
	// This vector hand-builds an outer wrapper whose `inner` field is a bare
	// hash of a stored inner entity, evaluates field(lookup_hash(outer),
	// "inner") fresh (no in-flight typing exists for the outer), and asserts
	// the result is the bare hash bytes — NOT the unwrapped inner entity. A
	// returned entity means an auto-resolve heuristic crept back in.
	r.Run("v319c_readback_navigation_returns_hash", func() CheckOutcome {
		if out, ok := r.Require("handler_present"); !ok {
			return out
		}
		// Hand-build inner = app/user{name:"alice"} and put it in tree so
		// the content store has it (the old shape-sniff would resolve it).
		innerData, _ := ecf.Encode(map[string]interface{}{"name": "alice"})
		innerEnt, _ := entity.NewEntity("app/user", cbor.RawMessage(innerData))
		if _, err := client.TreePut(ctx, tp+"/v319c-readback-inner", innerEnt); err != nil {
			return FailCheck("put inner: " + err.Error())
		}
		// Hand-build outer wrapper = app/wrapper{inner:<bare innerHash>} —
		// the bare V7 §1.4 form (what materialize() produces). Put it in
		// tree.
		wrapperData, _ := ecf.Encode(map[string]interface{}{"inner": innerEnt.ContentHash})
		wrapperEnt, _ := entity.NewEntity("app/wrapper", cbor.RawMessage(wrapperData))
		if _, err := client.TreePut(ctx, tp+"/v319c-readback-wrapper", wrapperEnt); err != nil {
			return FailCheck("put wrapper: " + err.Error())
		}
		// Bring the wrapper into eval via compute/lookup/tree — read-back
		// path (the wrapper was NOT produced by compute/construct in this
		// eval, so no in-flight typing assists field navigation). Tree
		// lookup authorizes via the caller's capability path permission.
		wrapperTreePath := tp + "/v319c-readback-wrapper"
		lookupExpr, _ := types.ComputeLookupTreeData{
			Path: wrapperTreePath,
		}.ToEntity()
		lookupPath := tp + "/v319c-readback-lookup"
		if _, err := client.TreePut(ctx, lookupPath, lookupExpr); err != nil {
			return FailCheck("put lookup expr: " + err.Error())
		}
		fieldExpr, _ := types.ComputeFieldData{
			Name:   "inner",
			Entity: lookupExpr.ContentHash,
		}.ToEntity()
		fieldPath := tp + "/v319c-readback-field"
		if _, err := client.TreePut(ctx, fieldPath, fieldExpr); err != nil {
			return FailCheck("put field expr: " + err.Error())
		}
		val, err := extractResultValue(ctx, client, peerID, fieldPath)
		if err != nil {
			return FailCheck("eval field: " + err.Error())
		}
		// N3 check: result MUST NOT be an entity (auto-resolved). A
		// returned entity.Entity means a shape-sniff snuck in — unless
		// it's a compute/error, which surfaces a setup/auth failure
		// distinct from the N3 question.
		if ent, ok := val.(entity.Entity); ok {
			if ent.Type == types.TypeComputeError {
				if d, derr := types.ComputeErrorDataFromEntity(ent); derr == nil {
					return FailCheck(fmt.Sprintf("read-back field eval returned compute/error{code=%s, msg=%s} — setup issue, not an N3 result", d.Code, d.Message))
				}
				return FailCheck("read-back field eval returned compute/error — setup issue, not an N3 result")
			}
			return FailCheck(fmt.Sprintf("field(stored_wrapper,'inner') auto-resolved to entity type=%s — N3 violation. The bare hash must be returned as bytes; caller follows via explicit compute/lookup/hash.", ent.Type))
		}
		bs, ok := val.([]byte)
		if !ok {
			return FailCheck(fmt.Sprintf("read-back field returned %T, expected []byte (bare system/hash ref)", val))
		}
		// Compare structurally to the inner content_hash on the wire —
		// algorithm byte || digest. No fixed-length assertion (crypto-
		// agility per arch 39bc8a2 + V7 §1.2).
		expected := innerEnt.ContentHash.Bytes()
		if !bytes.Equal(bs, expected) {
			return FailCheck(fmt.Sprintf("read-back field bytes don't match inner content_hash: got %x, expected %x", bs, expected))
		}
		return PassCheck(fmt.Sprintf("field(lookup_tree('%s'), 'inner') → bare %d-byte system/hash ref (N3 read-back ruling: no auto-resolve, no shape-sniff). Caller follows via explicit compute/lookup/hash.", wrapperTreePath, len(bs)))
	})

	return r.Results()
}

// --- Core eval helpers ---

// computeEvalAtPath sends an eval EXECUTE targeting the given tree path.
func computeEvalAtPath(ctx context.Context, client *PeerClient, peerID, exprPath string) (types.ExecuteResponseData, error) {
	uri := fmt.Sprintf("entity://%s/system/compute/%s", peerID, exprPath)
	raw, _ := ecf.Encode(map[string]interface{}{})
	params, _ := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
	resource := &types.ResourceTarget{Targets: []string{fmt.Sprintf("/%s/%s", peerID, exprPath)}}
	env, _, err := client.SendExecute(ctx, uri, "eval", params, resource)
	if err != nil {
		return types.ExecuteResponseData{}, err
	}
	return types.ExecuteResponseDataFromEntity(env.Root)
}

// computeEvalAndExtractValue puts a single expression, evals it, and returns the result value.
func computeEvalAndExtractValue(ctx context.Context, client *PeerClient, peerID, path string, data interface{ ToEntity() (entity.Entity, error) }) (interface{}, error) {
	ent, err := data.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("create entity: %w", err)
	}
	if _, err := client.TreePut(ctx, path, ent); err != nil {
		return nil, fmt.Errorf("put: %w", err)
	}
	return extractResultValue(ctx, client, peerID, path)
}

// extractResultValue evals expression at path and decodes the result value.
func extractResultValue(ctx context.Context, client *PeerClient, peerID, path string) (interface{}, error) {
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("status %d", resp.Status)
	}
	return decodeComputeValue(resp)
}

// decodeComputeValue extracts the value from a successful eval response.
// If result is compute/result, returns the value field. Otherwise returns
// the result entity itself.
func decodeComputeValue(resp types.ExecuteResponseData) (interface{}, error) {
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return nil, fmt.Errorf("decode result entity: %w", err)
	}
	if resultEnt.Type == types.TypeComputeResult {
		var d types.ComputeResultData
		if err := ecf.Decode(resultEnt.Data, &d); err != nil {
			return nil, fmt.Errorf("decode compute/result: %w", err)
		}
		return d.Value, nil
	}
	return resultEnt, nil
}

// decodeComputeEntity extracts the result as an entity from a successful eval response.
func decodeComputeEntity(resp types.ExecuteResponseData) (entity.Entity, error) {
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
	}
	return resultEnt, nil
}

// decodeComputeErrorCodeAnyStatus extracts the compute/error code regardless
// of the response status. v3.19 surfaces evaluated compute/error at status 200
// per PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE F10; pre-v3.19 impls
// surface it at 400. Either way, the body is a compute/error entity — this
// helper handles both.
func decodeComputeErrorCodeAnyStatus(resp types.ExecuteResponseData) (string, error) {
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return "", fmt.Errorf("status %d: decode result: %w", resp.Status, err)
	}
	if resultEnt.Type != types.TypeComputeError {
		return "", fmt.Errorf("status %d: expected compute/error, got %s", resp.Status, resultEnt.Type)
	}
	errData, err := types.ComputeErrorDataFromEntity(resultEnt)
	if err != nil {
		return "", err
	}
	return errData.Code, nil
}

// decodeComputeErrorCode extracts the error code from an eval error response.
func decodeComputeErrorCode(resp types.ExecuteResponseData) (string, error) {
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return "", fmt.Errorf("decode result: %w", err)
	}
	if resultEnt.Type != types.TypeComputeError {
		return "", fmt.Errorf("expected compute/error, got %s", resultEnt.Type)
	}
	errData, err := types.ComputeErrorDataFromEntity(resultEnt)
	if err != nil {
		return "", err
	}
	return errData.Code, nil
}

// --- Expression builders ---

// computeEvalBinaryOp builds op(literal(left), literal(right)) and returns the result value.
func computeEvalBinaryOp(ctx context.Context, client *PeerClient, peerID, tp, suffix, exprType, op string, left, right interface{}) (interface{}, error) {
	leftEnt, _ := types.ComputeLiteralData{Value: left}.ToEntity()
	rightEnt, _ := types.ComputeLiteralData{Value: right}.ToEntity()
	leftHash := putCE(ctx, client, tp+"/"+suffix+"-l", leftEnt)
	rightHash := putCE(ctx, client, tp+"/"+suffix+"-r", rightEnt)

	var exprEnt entity.Entity
	var err error
	switch exprType {
	case types.TypeComputeArithmetic:
		exprEnt, err = types.ComputeArithmeticData{Op: op, Left: leftHash, Right: rightHash}.ToEntity()
	case types.TypeComputeCompare:
		exprEnt, err = types.ComputeCompareData{Op: op, Left: leftHash, Right: rightHash}.ToEntity()
	case types.TypeComputeLogic:
		exprEnt, err = types.ComputeLogicData{Op: op, Left: leftHash, Right: &rightHash}.ToEntity()
	default:
		return nil, fmt.Errorf("unknown binary type: %s", exprType)
	}
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, exprEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// computeEvalExpectError builds op(literal(left), literal(right)) and expects an error.
func computeEvalExpectError(ctx context.Context, client *PeerClient, peerID, tp, suffix, exprType, op string, left, right interface{}) (string, error) {
	leftEnt, _ := types.ComputeLiteralData{Value: left}.ToEntity()
	rightEnt, _ := types.ComputeLiteralData{Value: right}.ToEntity()
	leftHash := putCE(ctx, client, tp+"/"+suffix+"-l", leftEnt)
	rightHash := putCE(ctx, client, tp+"/"+suffix+"-r", rightEnt)

	var exprEnt entity.Entity
	switch exprType {
	case types.TypeComputeArithmetic:
		exprEnt, _ = types.ComputeArithmeticData{Op: op, Left: leftHash, Right: rightHash}.ToEntity()
	case types.TypeComputeCompare:
		exprEnt, _ = types.ComputeCompareData{Op: op, Left: leftHash, Right: rightHash}.ToEntity()
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, exprEnt); err != nil {
		return "", err
	}
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return "", err
	}
	// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE F10: evaluated compute/error
	// surfaces at status 200 in v3.19+ (was 400 pre-fix). Detect via the result
	// entity type, not the status code; the new dedicated `f10_error_at_200`
	// check below is the strict v3.19 status-pin gate.
	return decodeComputeErrorCodeAnyStatus(resp)
}

func computeEvalUnaryLogic(ctx context.Context, client *PeerClient, peerID, tp string, value interface{}) (interface{}, error) {
	valEnt, _ := types.ComputeLiteralData{Value: value}.ToEntity()
	valHash := putCE(ctx, client, tp+"/not-v", valEnt)
	logicEnt, _ := types.ComputeLogicData{Op: "not", Left: valHash}.ToEntity()
	path := tp + "/logic-not"
	if _, err := client.TreePut(ctx, path, logicEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalIfExpr(ctx context.Context, client *PeerClient, peerID, tp string, cond bool, thenVal, elseVal string) (interface{}, error) {
	condEnt, _ := types.ComputeLiteralData{Value: cond}.ToEntity()
	thenEnt, _ := types.ComputeLiteralData{Value: thenVal}.ToEntity()
	elseEnt, _ := types.ComputeLiteralData{Value: elseVal}.ToEntity()
	condHash := putCE(ctx, client, tp+"/if-c", condEnt)
	thenHash := putCE(ctx, client, tp+"/if-t", thenEnt)
	elseHash := putCE(ctx, client, tp+"/if-e", elseEnt)
	suffix := "if-true"
	if !cond {
		suffix = "if-false"
	}
	ifEnt, _ := types.ComputeIfData{Condition: condHash, Then: thenHash, Else: &elseHash}.ToEntity()
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, ifEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalLetSequential(ctx context.Context, client *PeerClient, peerID, tp string) (interface{}, error) {
	lit5, _ := types.ComputeLiteralData{Value: uint64(5)}.ToEntity()
	lit1, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
	lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
	lookupY, _ := types.ComputeLookupScopeData{Name: "y"}.ToEntity()
	lit5H := putCE(ctx, client, tp+"/let-5", lit5)
	lit1H := putCE(ctx, client, tp+"/let-1", lit1)
	xH := putCE(ctx, client, tp+"/let-lx", lookupX)
	yH := putCE(ctx, client, tp+"/let-ly", lookupY)
	addEnt, _ := types.ComputeArithmeticData{Op: "add", Left: xH, Right: lit1H}.ToEntity()
	addH := putCE(ctx, client, tp+"/let-add", addEnt)
	letEnt, _ := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "x", Value: lit5H}, {Name: "y", Value: addH}},
		Body:     yH,
	}.ToEntity()
	path := tp + "/let-seq"
	if _, err := client.TreePut(ctx, path, letEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalLambdaApply(ctx context.Context, client *PeerClient, peerID, tp string) (interface{}, error) {
	lookupA, _ := types.ComputeLookupScopeData{Name: "a"}.ToEntity()
	lit1, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
	aH := putCE(ctx, client, tp+"/lam-a", lookupA)
	l1H := putCE(ctx, client, tp+"/lam-1", lit1)
	body, _ := types.ComputeArithmeticData{Op: "add", Left: aH, Right: l1H}.ToEntity()
	bodyH := putCE(ctx, client, tp+"/lam-body", body)
	lambda, _ := types.ComputeLambdaData{Params: []string{"a"}, Body: bodyH}.ToEntity()
	lamH := putCE(ctx, client, tp+"/lam-def", lambda)
	arg, _ := types.ComputeLiteralData{Value: uint64(10)}.ToEntity()
	argH := putCE(ctx, client, tp+"/lam-arg", arg)
	lookupF, _ := types.ComputeLookupScopeData{Name: "f"}.ToEntity()
	fH := putCE(ctx, client, tp+"/lam-f", lookupF)
	apply, _ := types.ComputeApplyData{Fn: fH, Args: map[string]hash.Hash{"a": argH}}.ToEntity()
	applyH := putCE(ctx, client, tp+"/lam-apply", apply)
	letEnt, _ := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "f", Value: lamH}},
		Body:     applyH,
	}.ToEntity()
	path := tp + "/lam-test"
	if _, err := client.TreePut(ctx, path, letEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalLookupScopeExpr(ctx context.Context, client *PeerClient, peerID, tp string) (interface{}, error) {
	lit42, _ := types.ComputeLiteralData{Value: uint64(42)}.ToEntity()
	lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
	lit42H := putCE(ctx, client, tp+"/scope-42", lit42)
	xH := putCE(ctx, client, tp+"/scope-lx", lookupX)
	letEnt, _ := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "x", Value: lit42H}},
		Body:     xH,
	}.ToEntity()
	path := tp + "/scope-test"
	if _, err := client.TreePut(ctx, path, letEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalLookupTreeValue(ctx context.Context, client *PeerClient, peerID, tp, targetPath string) (interface{}, error) {
	lookupEnt, _ := types.ComputeLookupTreeData{Path: targetPath}.ToEntity()
	path := tp + "/tree-lv"
	if _, err := client.TreePut(ctx, path, lookupEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalLookupTreeEntity(ctx context.Context, client *PeerClient, peerID, tp, targetPath string) (entity.Entity, error) {
	lookupEnt, _ := types.ComputeLookupTreeData{Path: targetPath}.ToEntity()
	path := tp + "/tree-le"
	if _, err := client.TreePut(ctx, path, lookupEnt); err != nil {
		return entity.Entity{}, err
	}
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return entity.Entity{}, err
	}
	if resp.Status != 200 {
		return entity.Entity{}, fmt.Errorf("status %d", resp.Status)
	}
	return decodeComputeEntity(resp)
}

func computeEvalLookupTreeError(ctx context.Context, client *PeerClient, peerID, tp, targetPath string) (string, error) {
	lookupEnt, _ := types.ComputeLookupTreeData{Path: targetPath}.ToEntity()
	path := tp + "/tree-err"
	if _, err := client.TreePut(ctx, path, lookupEnt); err != nil {
		return "", err
	}
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return "", err
	}
	return decodeComputeErrorCodeAnyStatus(resp)
}

// construct{a: "alpha", bb: "beta", ccc: "gamma"} — 3 fields at different lengths.
func computeEvalConstructMultiField(ctx context.Context, client *PeerClient, peerID, tp string) (entity.Entity, error) {
	aEnt, _ := types.ComputeLiteralData{Value: "alpha"}.ToEntity()
	bbEnt, _ := types.ComputeLiteralData{Value: "beta"}.ToEntity()
	cccEnt, _ := types.ComputeLiteralData{Value: "gamma"}.ToEntity()
	aH := putCE(ctx, client, tp+"/con-a", aEnt)
	bbH := putCE(ctx, client, tp+"/con-bb", bbEnt)
	cccH := putCE(ctx, client, tp+"/con-ccc", cccEnt)
	constructEnt, _ := types.ComputeConstructData{
		EntityType: "app/test-construct",
		Fields:     map[string]hash.Hash{"a": aH, "bb": bbH, "ccc": cccH},
	}.ToEntity()
	path := tp + "/construct"
	if _, err := client.TreePut(ctx, path, constructEnt); err != nil {
		return entity.Entity{}, err
	}
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return entity.Entity{}, err
	}
	if resp.Status != 200 {
		return entity.Entity{}, fmt.Errorf("status %d", resp.Status)
	}
	return decodeComputeEntity(resp)
}

// field("bb", construct{a,bb,ccc}) → "beta"
func computeEvalFieldExtract(ctx context.Context, client *PeerClient, peerID, tp string) (interface{}, error) {
	// Reuse the construct from the previous test.
	constructPath := tp + "/construct"
	qualPath := fmt.Sprintf("/%s/%s", peerID, constructPath)
	lookupCon, _ := types.ComputeLookupTreeData{Path: qualPath}.ToEntity()
	conH := putCE(ctx, client, tp+"/field-con", lookupCon)
	fieldEnt, _ := types.ComputeFieldData{Name: "bb", Entity: conH}.ToEntity()
	path := tp + "/field-bb"
	if _, err := client.TreePut(ctx, path, fieldEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// let x = 100 in (let f = lambda(a): a + x in f(5)) → 105
func computeEvalClosureCapturesScope(ctx context.Context, client *PeerClient, peerID, tp string) (interface{}, error) {
	lookupA, _ := types.ComputeLookupScopeData{Name: "a"}.ToEntity()
	lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
	lookupF, _ := types.ComputeLookupScopeData{Name: "f"}.ToEntity()
	lit100, _ := types.ComputeLiteralData{Value: uint64(100)}.ToEntity()
	lit5, _ := types.ComputeLiteralData{Value: uint64(5)}.ToEntity()
	aH := putCE(ctx, client, tp+"/cap-a", lookupA)
	xH := putCE(ctx, client, tp+"/cap-x", lookupX)
	fH := putCE(ctx, client, tp+"/cap-f", lookupF)
	l100H := putCE(ctx, client, tp+"/cap-100", lit100)
	l5H := putCE(ctx, client, tp+"/cap-5", lit5)
	// body: a + x
	body, _ := types.ComputeArithmeticData{Op: "add", Left: aH, Right: xH}.ToEntity()
	bodyH := putCE(ctx, client, tp+"/cap-body", body)
	// lambda(a): a + x
	lambda, _ := types.ComputeLambdaData{Params: []string{"a"}, Body: bodyH}.ToEntity()
	lamH := putCE(ctx, client, tp+"/cap-lam", lambda)
	// apply(f, {a: 5})
	apply, _ := types.ComputeApplyData{Fn: fH, Args: map[string]hash.Hash{"a": l5H}}.ToEntity()
	applyH := putCE(ctx, client, tp+"/cap-apply", apply)
	// inner let: let f = lambda in apply
	innerLet, _ := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "f", Value: lamH}},
		Body:     applyH,
	}.ToEntity()
	innerH := putCE(ctx, client, tp+"/cap-inner", innerLet)
	// outer let: let x = 100 in inner
	outerLet, _ := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "x", Value: l100H}},
		Body:     innerH,
	}.ToEntity()
	path := tp + "/cap-test"
	if _, err := client.TreePut(ctx, path, outerLet); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// add(1, lookup/tree("nonexistent")) → error propagates through arithmetic.
func computeEvalErrorPropagation(ctx context.Context, client *PeerClient, peerID, tp string) (string, error) {
	lit1, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
	nonexistent := fmt.Sprintf("/%s/%s/propagation-missing-%d", peerID, tp, 888888)
	lookupMissing, _ := types.ComputeLookupTreeData{Path: nonexistent}.ToEntity()
	l1H := putCE(ctx, client, tp+"/prop-1", lit1)
	missH := putCE(ctx, client, tp+"/prop-miss", lookupMissing)
	addEnt, _ := types.ComputeArithmeticData{Op: "add", Left: l1H, Right: missH}.ToEntity()
	path := tp + "/prop-test"
	if _, err := client.TreePut(ctx, path, addEnt); err != nil {
		return "", err
	}
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return "", err
	}
	return decodeComputeErrorCodeAnyStatus(resp)
}

// --- Utility ---

func putCE(ctx context.Context, client *PeerClient, path string, ent entity.Entity) hash.Hash {
	_, _ = client.TreePut(ctx, path, ent)
	return ent.ContentHash
}

// numEq compares a value against an expected number, handling CBOR int/uint/float coercion.
// readComputeResultValue reads a compute/result entity from a tree path and
// extracts its value. Used for checking reactive evaluation results.
func readComputeResultValue(ctx context.Context, client *PeerClient, qualifiedPath string) (interface{}, error) {
	// Strip the leading /{peerID}/ to get the bare path for TreeGet.
	barePath := qualifiedPath
	if len(barePath) > 1 && barePath[0] == '/' {
		parts := barePath[1:] // strip leading /
		if idx := indexOf(parts, '/'); idx >= 0 {
			barePath = parts[idx+1:]
		}
	}
	ent, _, err := client.TreeGet(ctx, barePath)
	if err != nil {
		return nil, fmt.Errorf("tree get %s: %w", barePath, err)
	}
	if ent.Type == types.TypeComputeResult {
		var d types.ComputeResultData
		if err := ecf.Decode(ent.Data, &d); err != nil {
			return nil, fmt.Errorf("decode compute/result: %w", err)
		}
		return d.Value, nil
	}
	return ent, nil
}

func indexOf(s string, b byte) int {
	for i := range s {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func toValidateFloat(val interface{}) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case uint64:
		return float64(v), true
	case int64:
		return float64(v), true
	}
	return 0, false
}

// computeEvalTailRecursiveSum builds sum_iter(n, acc) = if n<=0 then acc else sum_iter(n-1, acc+n).
// Evaluates sum(N) = N*(N+1)/2 using N tail-recursive iterations.
func computeEvalTailRecursiveSum(ctx context.Context, client *PeerClient, peerID, tp string, n uint64) (interface{}, error) {
	p := tp + "/tco-sum"

	lit0, _ := types.ComputeLiteralData{Value: uint64(0)}.ToEntity()
	lit1, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
	l0H := putCE(ctx, client, p+"/lit0", lit0)
	l1H := putCE(ctx, client, p+"/lit1", lit1)

	lookupN, _ := types.ComputeLookupScopeData{Name: "n"}.ToEntity()
	lookupAcc, _ := types.ComputeLookupScopeData{Name: "acc"}.ToEntity()
	nH := putCE(ctx, client, p+"/n", lookupN)
	accH := putCE(ctx, client, p+"/acc", lookupAcc)

	// n <= 0
	cmp, _ := types.ComputeCompareData{Op: "lte", Left: nH, Right: l0H}.ToEntity()
	cmpH := putCE(ctx, client, p+"/cmp", cmp)

	// n - 1
	nMinus1, _ := types.ComputeArithmeticData{Op: "sub", Left: nH, Right: l1H}.ToEntity()
	nm1H := putCE(ctx, client, p+"/nm1", nMinus1)

	// acc + n
	accPlusN, _ := types.ComputeArithmeticData{Op: "add", Left: accH, Right: nH}.ToEntity()
	apnH := putCE(ctx, client, p+"/apn", accPlusN)

	// Self-reference via tree lookup.
	sumIterQual := fmt.Sprintf("/%s/%s/sum-iter", peerID, tp)
	selfRef, _ := types.ComputeLookupTreeData{Path: sumIterQual}.ToEntity()
	selfH := putCE(ctx, client, p+"/self", selfRef)

	// Recursive call: apply(self, {n: n-1, acc: acc+n})
	recurse, _ := types.ComputeApplyData{Fn: selfH, Args: map[string]hash.Hash{"n": nm1H, "acc": apnH}}.ToEntity()
	recurseH := putCE(ctx, client, p+"/recurse", recurse)

	// if n <= 0 then acc else recurse
	ifExpr, _ := types.ComputeIfData{Condition: cmpH, Then: accH, Else: &recurseH}.ToEntity()
	ifH := putCE(ctx, client, p+"/if", ifExpr)

	// lambda(n, acc): <body>
	sumIterLambda, _ := types.ComputeLambdaData{Params: []string{"n", "acc"}, Body: ifH}.ToEntity()
	if _, err := client.TreePut(ctx, tp+"/sum-iter", sumIterLambda); err != nil {
		return nil, fmt.Errorf("put sum-iter lambda: %w", err)
	}

	// Entry: let f = lookup/tree(sum-iter) in apply(f, {n: N, acc: 0})
	litN, _ := types.ComputeLiteralData{Value: n}.ToEntity()
	litNH := putCE(ctx, client, p+"/arg-n", litN)
	lookupF, _ := types.ComputeLookupScopeData{Name: "f"}.ToEntity()
	fH := putCE(ctx, client, p+"/f", lookupF)
	treeRef, _ := types.ComputeLookupTreeData{Path: sumIterQual}.ToEntity()
	treeRefH := putCE(ctx, client, p+"/tree-ref", treeRef)
	apply, _ := types.ComputeApplyData{Fn: fH, Args: map[string]hash.Hash{"n": litNH, "acc": l0H}}.ToEntity()
	applyH := putCE(ctx, client, p+"/apply", apply)
	entry, _ := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "f", Value: treeRefH}},
		Body:     applyH,
	}.ToEntity()
	entryPath := tp + "/sum-entry"
	if _, err := client.TreePut(ctx, entryPath, entry); err != nil {
		return nil, fmt.Errorf("put sum entry: %w", err)
	}
	return extractResultValue(ctx, client, peerID, entryPath)
}

// computeEvalNewtonSqrt builds newton(x, guess, n) = if n<=0 then guess else newton(x, (guess+x/guess)/2, n-1).
// Evaluates sqrt(x) using iterative Newton's method with `iters` tail-recursive steps.
func computeEvalNewtonSqrt(ctx context.Context, client *PeerClient, peerID, tp string, x float64, iters uint64) (interface{}, error) {
	p := tp + "/newton"

	lit0, _ := types.ComputeLiteralData{Value: uint64(0)}.ToEntity()
	lit1, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
	lit2, _ := types.ComputeLiteralData{Value: uint64(2)}.ToEntity()
	l0H := putCE(ctx, client, p+"/lit0", lit0)
	l1H := putCE(ctx, client, p+"/lit1", lit1)
	l2H := putCE(ctx, client, p+"/lit2", lit2)

	lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
	lookupG, _ := types.ComputeLookupScopeData{Name: "guess"}.ToEntity()
	lookupN, _ := types.ComputeLookupScopeData{Name: "n"}.ToEntity()
	xH := putCE(ctx, client, p+"/x", lookupX)
	gH := putCE(ctx, client, p+"/guess", lookupG)
	nH := putCE(ctx, client, p+"/n", lookupN)

	// n <= 0
	cmp, _ := types.ComputeCompareData{Op: "lte", Left: nH, Right: l0H}.ToEntity()
	cmpH := putCE(ctx, client, p+"/cmp", cmp)

	// x / guess
	xDivG, _ := types.ComputeArithmeticData{Op: "div", Left: xH, Right: gH}.ToEntity()
	xdgH := putCE(ctx, client, p+"/xdg", xDivG)

	// guess + x/guess
	gPlusXdg, _ := types.ComputeArithmeticData{Op: "add", Left: gH, Right: xdgH}.ToEntity()
	gpxH := putCE(ctx, client, p+"/gpx", gPlusXdg)

	// (guess + x/guess) / 2
	nextGuess, _ := types.ComputeArithmeticData{Op: "div", Left: gpxH, Right: l2H}.ToEntity()
	ngH := putCE(ctx, client, p+"/ng", nextGuess)

	// n - 1
	nMinus1, _ := types.ComputeArithmeticData{Op: "sub", Left: nH, Right: l1H}.ToEntity()
	nm1H := putCE(ctx, client, p+"/nm1", nMinus1)

	// Self-reference
	newtonQual := fmt.Sprintf("/%s/%s/newton-fn", peerID, tp)
	selfRef, _ := types.ComputeLookupTreeData{Path: newtonQual}.ToEntity()
	selfH := putCE(ctx, client, p+"/self", selfRef)

	// Recursive: apply(self, {x: x, guess: next_guess, n: n-1})
	recurse, _ := types.ComputeApplyData{Fn: selfH, Args: map[string]hash.Hash{
		"x": xH, "guess": ngH, "n": nm1H,
	}}.ToEntity()
	recurseH := putCE(ctx, client, p+"/recurse", recurse)

	// if n <= 0 then guess else recurse
	ifExpr, _ := types.ComputeIfData{Condition: cmpH, Then: gH, Else: &recurseH}.ToEntity()
	ifH := putCE(ctx, client, p+"/if", ifExpr)

	// lambda(x, guess, n): <body>
	newtonLambda, _ := types.ComputeLambdaData{Params: []string{"x", "guess", "n"}, Body: ifH}.ToEntity()
	if _, err := client.TreePut(ctx, tp+"/newton-fn", newtonLambda); err != nil {
		return nil, fmt.Errorf("put newton lambda: %w", err)
	}

	// Entry: apply(newton, {x: X, guess: X, n: ITERS})
	litX, _ := types.ComputeLiteralData{Value: x}.ToEntity()
	litXH := putCE(ctx, client, p+"/arg-x", litX)
	litIters, _ := types.ComputeLiteralData{Value: iters}.ToEntity()
	litItersH := putCE(ctx, client, p+"/arg-iters", litIters)

	lookupF, _ := types.ComputeLookupScopeData{Name: "f"}.ToEntity()
	fH := putCE(ctx, client, p+"/f", lookupF)
	treeRef, _ := types.ComputeLookupTreeData{Path: newtonQual}.ToEntity()
	treeRefH := putCE(ctx, client, p+"/tree-ref", treeRef)

	apply, _ := types.ComputeApplyData{Fn: fH, Args: map[string]hash.Hash{
		"x": litXH, "guess": litXH, "n": litItersH,
	}}.ToEntity()
	applyH := putCE(ctx, client, p+"/apply", apply)
	entry, _ := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "f", Value: treeRefH}},
		Body:     applyH,
	}.ToEntity()

	entryPath := tp + "/newton-entry"
	if _, err := client.TreePut(ctx, entryPath, entry); err != nil {
		return nil, fmt.Errorf("put newton entry: %w", err)
	}
	return extractResultValue(ctx, client, peerID, entryPath)
}

func numEq(val interface{}, expected float64) bool {
	switch v := val.(type) {
	case uint64:
		return float64(v) == expected
	case int64:
		return float64(v) == expected
	case float64:
		return math.Abs(v-expected) < 1e-9
	}
	return false
}

// computeEvalFibonacci builds a recursive fibonacci via tree self-reference.
//
// The expression graph:
//
//	fib-path: lambda(n): if(lte(n, 1), n, add(apply(fib, {n: n-1}), apply(fib, {n: n-2})))
//	eval-path: let fib=lookup/tree(fib-path) in apply(fib, {n: N})
//
// The lambda body references fib via lookup/tree — when the tree entity is a
// lambda, lookup/tree evaluates it to a closure (spreadsheet semantic), which
// can then be applied. This is the standard recursion pattern in the compute
// extension.
func computeEvalFibonacci(ctx context.Context, client *PeerClient, peerID, tp string, n uint64) (interface{}, error) {
	p := tp + "/fib"

	// Shared sub-expressions.
	lookupN, _ := types.ComputeLookupScopeData{Name: "n"}.ToEntity()
	nH := putCE(ctx, client, p+"/n", lookupN)

	lit0, _ := types.ComputeLiteralData{Value: uint64(0)}.ToEntity()
	lit1, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
	lit2, _ := types.ComputeLiteralData{Value: uint64(2)}.ToEntity()
	l0H := putCE(ctx, client, p+"/lit0", lit0)
	_ = l0H
	l1H := putCE(ctx, client, p+"/lit1", lit1)
	l2H := putCE(ctx, client, p+"/lit2", lit2)

	// lte(n, 1) — base case condition.
	cond, _ := types.ComputeCompareData{Op: "lte", Left: nH, Right: l1H}.ToEntity()
	condH := putCE(ctx, client, p+"/cond", cond)

	// n - 1, n - 2.
	nMinus1, _ := types.ComputeArithmeticData{Op: "sub", Left: nH, Right: l1H}.ToEntity()
	nMinus2, _ := types.ComputeArithmeticData{Op: "sub", Left: nH, Right: l2H}.ToEntity()
	nm1H := putCE(ctx, client, p+"/nm1", nMinus1)
	nm2H := putCE(ctx, client, p+"/nm2", nMinus2)

	// Self-reference: lookup/tree to the fib lambda path.
	fibQualPath := fmt.Sprintf("/%s/%s/fib-lambda", peerID, tp)
	fibRef, _ := types.ComputeLookupTreeData{Path: fibQualPath}.ToEntity()
	fibRefH := putCE(ctx, client, p+"/self-ref", fibRef)

	// apply(fib, {n: n-1}) and apply(fib, {n: n-2}).
	applyNm1, _ := types.ComputeApplyData{Fn: fibRefH, Args: map[string]hash.Hash{"n": nm1H}}.ToEntity()
	applyNm2, _ := types.ComputeApplyData{Fn: fibRefH, Args: map[string]hash.Hash{"n": nm2H}}.ToEntity()
	aNm1H := putCE(ctx, client, p+"/apply-nm1", applyNm1)
	aNm2H := putCE(ctx, client, p+"/apply-nm2", applyNm2)

	// add(fib(n-1), fib(n-2)).
	addBranch, _ := types.ComputeArithmeticData{Op: "add", Left: aNm1H, Right: aNm2H}.ToEntity()
	addH := putCE(ctx, client, p+"/add", addBranch)

	// if(lte(n, 1), n, add(fib(n-1), fib(n-2))).
	ifExpr, _ := types.ComputeIfData{Condition: condH, Then: nH, Else: &addH}.ToEntity()
	ifH := putCE(ctx, client, p+"/if", ifExpr)

	// lambda(n): <body>
	fibLambda, _ := types.ComputeLambdaData{Params: []string{"n"}, Body: ifH}.ToEntity()

	// Store the lambda at the tree path that the self-reference points to.
	fibLambdaPath := tp + "/fib-lambda"
	if _, err := client.TreePut(ctx, fibLambdaPath, fibLambda); err != nil {
		return nil, fmt.Errorf("put fib lambda: %w", err)
	}

	// Entry point: let fib = lookup/tree(fib-path) in apply(fib, {n: N})
	litN, _ := types.ComputeLiteralData{Value: n}.ToEntity()
	litNH := putCE(ctx, client, p+"/arg-n", litN)

	lookupFib, _ := types.ComputeLookupScopeData{Name: "fib"}.ToEntity()
	fibScopeH := putCE(ctx, client, p+"/fib-scope", lookupFib)

	applyFib, _ := types.ComputeApplyData{Fn: fibScopeH, Args: map[string]hash.Hash{"n": litNH}}.ToEntity()
	applyFibH := putCE(ctx, client, p+"/apply-fib", applyFib)

	fibTreeRef, _ := types.ComputeLookupTreeData{Path: fibQualPath}.ToEntity()
	fibTreeRefH := putCE(ctx, client, p+"/fib-tree-ref", fibTreeRef)

	entryLet, _ := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "fib", Value: fibTreeRefH}},
		Body:     applyFibH,
	}.ToEntity()

	entryPath := tp + "/fib-entry"
	if _, err := client.TreePut(ctx, entryPath, entryLet); err != nil {
		return nil, fmt.Errorf("put fib entry: %w", err)
	}

	return extractResultValue(ctx, client, peerID, entryPath)
}

// --- v3.14 standard-IR floor helpers ---

// computeEvalIndexExpr builds index(literal(array), literal(idx)) and returns
// the result value.
func computeEvalIndexExpr(ctx context.Context, client *PeerClient, peerID, tp, suffix string, array interface{}, idx int64) (interface{}, error) {
	arrEnt, _ := types.ComputeLiteralData{Value: array}.ToEntity()
	idxEnt, _ := types.ComputeLiteralData{Value: idx}.ToEntity()
	arrH := putCE(ctx, client, tp+"/"+suffix+"-arr", arrEnt)
	idxH := putCE(ctx, client, tp+"/"+suffix+"-idx", idxEnt)
	expr, err := types.ComputeIndexData{Array: arrH, Index: idxH}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, expr); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalIndexExprError(ctx context.Context, client *PeerClient, peerID, tp, suffix string, array interface{}, idx int64) (string, error) {
	arrEnt, _ := types.ComputeLiteralData{Value: array}.ToEntity()
	idxEnt, _ := types.ComputeLiteralData{Value: idx}.ToEntity()
	arrH := putCE(ctx, client, tp+"/"+suffix+"-arr", arrEnt)
	idxH := putCE(ctx, client, tp+"/"+suffix+"-idx", idxEnt)
	expr, _ := types.ComputeIndexData{Array: arrH, Index: idxH}.ToEntity()
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, expr); err != nil {
		return "", err
	}
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return "", err
	}
	return decodeComputeErrorCode(resp)
}

// computeEvalLengthExpr builds length(literal(array)) and returns the value.
func computeEvalLengthExpr(ctx context.Context, client *PeerClient, peerID, tp, suffix string, array interface{}) (interface{}, error) {
	arrEnt, _ := types.ComputeLiteralData{Value: array}.ToEntity()
	arrH := putCE(ctx, client, tp+"/"+suffix+"-arr", arrEnt)
	expr, err := types.ComputeLengthData{Array: arrH}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, expr); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalLengthExprError(ctx context.Context, client *PeerClient, peerID, tp, suffix string, array interface{}) (string, error) {
	arrEnt, _ := types.ComputeLiteralData{Value: array}.ToEntity()
	arrH := putCE(ctx, client, tp+"/"+suffix+"-arr", arrEnt)
	expr, _ := types.ComputeLengthData{Array: arrH}.ToEntity()
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, expr); err != nil {
		return "", err
	}
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return "", err
	}
	return decodeComputeErrorCode(resp)
}

// computeEvalNumericCast builds numeric-cast(literal(value), toType) and
// returns the result value.
func computeEvalNumericCast(ctx context.Context, client *PeerClient, peerID, tp, suffix string, value interface{}, toType string) (interface{}, error) {
	valEnt, _ := types.ComputeLiteralData{Value: value}.ToEntity()
	valH := putCE(ctx, client, tp+"/"+suffix+"-v", valEnt)
	expr, err := types.ComputeNumericCastData{Value: valH, ToType: toType}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, expr); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

func computeEvalNumericCastError(ctx context.Context, client *PeerClient, peerID, tp, suffix string, value interface{}, toType string) (string, error) {
	valEnt, _ := types.ComputeLiteralData{Value: value}.ToEntity()
	valH := putCE(ctx, client, tp+"/"+suffix+"-v", valEnt)
	expr, _ := types.ComputeNumericCastData{Value: valH, ToType: toType}.ToEntity()
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, expr); err != nil {
		return "", err
	}
	resp, err := computeEvalAtPath(ctx, client, peerID, path)
	if err != nil {
		return "", err
	}
	return decodeComputeErrorCode(resp)
}

// computeEvalBuiltinArithmetic builds apply(system/compute/builtins/arithmetic,
// eval, {op, left, right}) — the handler-mode alias for the inline form.
func computeEvalBuiltinArithmetic(ctx context.Context, client *PeerClient, peerID, tp, suffix, op string, left, right interface{}) (interface{}, error) {
	opEnt, _ := types.ComputeLiteralData{Value: op}.ToEntity()
	leftEnt, _ := types.ComputeLiteralData{Value: left}.ToEntity()
	rightEnt, _ := types.ComputeLiteralData{Value: right}.ToEntity()
	opH := putCE(ctx, client, tp+"/"+suffix+"-op", opEnt)
	leftH := putCE(ctx, client, tp+"/"+suffix+"-l", leftEnt)
	rightH := putCE(ctx, client, tp+"/"+suffix+"-r", rightEnt)

	apply, err := types.ComputeApplyData{
		Path:      "system/compute/builtins/arithmetic",
		Operation: "eval",
		Args:      map[string]hash.Hash{"op": opH, "left": leftH, "right": rightH},
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, apply); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// buildIncrementLambda stores compute/lambda(x): x + 1 at a tree path and
// returns its hash. Lambdas are expressions that evaluate to closure values;
// referencing the lambda hash from compute/apply args lets the evaluator
// produce the closure on demand. Pre-evaluating to a closure and storing the
// closure as the arg target is non-portable — it only works on impls that
// bypass arg evaluation. See COMPUTE-V314-CROSS-IMPL-DIVERGENCES.md.
func buildIncrementLambda(ctx context.Context, client *PeerClient, peerID, tp, suffix string) (hash.Hash, error) {
	lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
	one, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
	xH := putCE(ctx, client, tp+"/"+suffix+"-x", lookupX)
	oneH := putCE(ctx, client, tp+"/"+suffix+"-1", one)
	body, _ := types.ComputeArithmeticData{Op: "add", Left: xH, Right: oneH}.ToEntity()
	bodyH := putCE(ctx, client, tp+"/"+suffix+"-body", body)
	lambda, _ := types.ComputeLambdaData{Params: []string{"x"}, Body: bodyH}.ToEntity()
	return client.TreePut(ctx, tp+"/"+suffix+"-lambda", lambda)
}

// buildGreaterThanFiveLambda stores compute/lambda(x): x > 5.
func buildGreaterThanFiveLambda(ctx context.Context, client *PeerClient, peerID, tp, suffix string) (hash.Hash, error) {
	lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
	five, _ := types.ComputeLiteralData{Value: uint64(5)}.ToEntity()
	xH := putCE(ctx, client, tp+"/"+suffix+"-x", lookupX)
	fiveH := putCE(ctx, client, tp+"/"+suffix+"-5", five)
	body, _ := types.ComputeCompareData{Op: "gt", Left: xH, Right: fiveH}.ToEntity()
	bodyH := putCE(ctx, client, tp+"/"+suffix+"-body", body)
	lambda, _ := types.ComputeLambdaData{Params: []string{"x"}, Body: bodyH}.ToEntity()
	return client.TreePut(ctx, tp+"/"+suffix+"-lambda", lambda)
}

// buildBinaryAddLambda stores compute/lambda(acc, x): acc + x for fold.
func buildBinaryAddLambda(ctx context.Context, client *PeerClient, peerID, tp, suffix string) (hash.Hash, error) {
	lookupAcc, _ := types.ComputeLookupScopeData{Name: "acc"}.ToEntity()
	lookupX, _ := types.ComputeLookupScopeData{Name: "x"}.ToEntity()
	accH := putCE(ctx, client, tp+"/"+suffix+"-acc", lookupAcc)
	xH := putCE(ctx, client, tp+"/"+suffix+"-x", lookupX)
	body, _ := types.ComputeArithmeticData{Op: "add", Left: accH, Right: xH}.ToEntity()
	bodyH := putCE(ctx, client, tp+"/"+suffix+"-body", body)
	lambda, _ := types.ComputeLambdaData{Params: []string{"acc", "x"}, Body: bodyH}.ToEntity()
	return client.TreePut(ctx, tp+"/"+suffix+"-lambda", lambda)
}

// computeEvalBuiltinMap dispatches system/compute/builtins/map with collection
// and a (lambda x: x+1) closure. Returns the result array.
func computeEvalBuiltinMap(ctx context.Context, client *PeerClient, peerID, tp, suffix string, collection []interface{}) (interface{}, error) {
	fnH, err := buildIncrementLambda(ctx, client, peerID, tp, suffix+"-fn")
	if err != nil {
		return nil, err
	}
	collEnt, _ := types.ComputeLiteralData{Value: collection}.ToEntity()
	collH := putCE(ctx, client, tp+"/"+suffix+"-coll", collEnt)
	apply, err := types.ComputeApplyData{
		Path:      "system/compute/builtins/map",
		Operation: "eval",
		Args:      map[string]hash.Hash{"collection": collH, "fn": fnH},
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, apply); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// computeEvalBuiltinFilter dispatches builtins/filter with (lambda x: x > 5).
func computeEvalBuiltinFilter(ctx context.Context, client *PeerClient, peerID, tp, suffix string, collection []interface{}) (interface{}, error) {
	predH, err := buildGreaterThanFiveLambda(ctx, client, peerID, tp, suffix+"-pred")
	if err != nil {
		return nil, err
	}
	collEnt, _ := types.ComputeLiteralData{Value: collection}.ToEntity()
	collH := putCE(ctx, client, tp+"/"+suffix+"-coll", collEnt)
	apply, err := types.ComputeApplyData{
		Path:      "system/compute/builtins/filter",
		Operation: "eval",
		Args:      map[string]hash.Hash{"collection": collH, "fn": predH},
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, apply); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// computeEvalBuiltinFold dispatches builtins/fold with (lambda acc,x: acc+x).
func computeEvalBuiltinFold(ctx context.Context, client *PeerClient, peerID, tp, suffix string, collection []interface{}, initial interface{}) (interface{}, error) {
	fnH, err := buildBinaryAddLambda(ctx, client, peerID, tp, suffix+"-fn")
	if err != nil {
		return nil, err
	}
	collEnt, _ := types.ComputeLiteralData{Value: collection}.ToEntity()
	initEnt, _ := types.ComputeLiteralData{Value: initial}.ToEntity()
	collH := putCE(ctx, client, tp+"/"+suffix+"-coll", collEnt)
	initH := putCE(ctx, client, tp+"/"+suffix+"-init", initEnt)
	apply, err := types.ComputeApplyData{
		Path:      "system/compute/builtins/fold",
		Operation: "eval",
		Args:      map[string]hash.Hash{"collection": collH, "fn": fnH, "initial": initH},
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, apply); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// --- v3.16 (Amendment 2) helpers ---

// computeEvalEagerCastDiv constructs div(numeric-cast(leftVal, uint), rightVal).
// The cast at the operand position triggers unsigned interpretation per rule 11.
func computeEvalEagerCastDiv(ctx context.Context, client *PeerClient, peerID, tp, suffix string, leftVal, rightVal uint64) (interface{}, error) {
	leftLit, _ := types.ComputeLiteralData{Value: leftVal}.ToEntity()
	rightLit, _ := types.ComputeLiteralData{Value: rightVal}.ToEntity()
	leftLitH := putCE(ctx, client, tp+"/"+suffix+"-l", leftLit)
	rightLitH := putCE(ctx, client, tp+"/"+suffix+"-r", rightLit)
	leftCast, _ := types.ComputeNumericCastData{Value: leftLitH, ToType: "primitive/uint"}.ToEntity()
	leftCastH := putCE(ctx, client, tp+"/"+suffix+"-lcast", leftCast)
	div, err := types.ComputeArithmeticData{Op: "div", Left: leftCastH, Right: rightLitH}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, div); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// computeEvalCastThroughLet constructs `let y = cast(leftVal, uint) in
// div(y, rightVal)`. Per rule 11 the cast is consumed by the binding, so
// div uses signed-default — the negative case for the eager-cast rule.
func computeEvalCastThroughLet(ctx context.Context, client *PeerClient, peerID, tp, suffix string, leftVal, rightVal uint64) (interface{}, error) {
	leftLit, _ := types.ComputeLiteralData{Value: leftVal}.ToEntity()
	rightLit, _ := types.ComputeLiteralData{Value: rightVal}.ToEntity()
	leftLitH := putCE(ctx, client, tp+"/"+suffix+"-l", leftLit)
	rightLitH := putCE(ctx, client, tp+"/"+suffix+"-r", rightLit)
	cast, _ := types.ComputeNumericCastData{Value: leftLitH, ToType: "primitive/uint"}.ToEntity()
	castH := putCE(ctx, client, tp+"/"+suffix+"-cast", cast)
	lookupY, _ := types.ComputeLookupScopeData{Name: "y"}.ToEntity()
	lookupYH := putCE(ctx, client, tp+"/"+suffix+"-y", lookupY)
	div, _ := types.ComputeArithmeticData{Op: "div", Left: lookupYH, Right: rightLitH}.ToEntity()
	divH := putCE(ctx, client, tp+"/"+suffix+"-div", div)
	letEnt, err := types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "y", Value: castH}},
		Body:     divH,
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, letEnt); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// computeEvalUintRoundTrip writes a uint value, reads it back via lookup/tree,
// then divs (cast(read, uint), 2). Confirms the JVM-model lean for the
// deferred sub-question: bit pattern survives store/read; unsigned
// interpretation is recovered via cast at point-of-use.
func computeEvalUintRoundTrip(ctx context.Context, client *PeerClient, peerID, tp, suffix string, val uint64) (interface{}, error) {
	storePath := tp + "/" + suffix + "-stored"
	valLit, _ := types.ComputeLiteralData{Value: val}.ToEntity()
	if _, err := client.TreePut(ctx, storePath, valLit); err != nil {
		return nil, err
	}
	qualPath := fmt.Sprintf("/%s/%s", peerID, storePath)
	lookup, _ := types.ComputeLookupTreeData{Path: qualPath}.ToEntity()
	lookupH := putCE(ctx, client, tp+"/"+suffix+"-lookup", lookup)
	// lookup returns the literal entity; we want its value. Extract via
	// compute/field on the literal's data — but easier path: just cast the
	// lookup result. The cast acts on whatever value comes through.
	cast, _ := types.ComputeNumericCastData{Value: lookupH, ToType: "primitive/uint"}.ToEntity()
	castH := putCE(ctx, client, tp+"/"+suffix+"-cast", cast)
	twoLit, _ := types.ComputeLiteralData{Value: uint64(2)}.ToEntity()
	twoH := putCE(ctx, client, tp+"/"+suffix+"-2", twoLit)
	div, err := types.ComputeArithmeticData{Op: "div", Left: castH, Right: twoH}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix + "-div"
	if _, err := client.TreePut(ctx, path, div); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// computeEvalCastThroughIf builds `div(if(true, cast(leftVal, uint), leftVal),
// rightVal)`. Per v3.17 rule 11 Option A the `if` is a strip point — the
// cast is NOT the direct operand of div, so div uses signed-default.
func computeEvalCastThroughIf(ctx context.Context, client *PeerClient, peerID, tp, suffix string, leftVal, rightVal uint64) (interface{}, error) {
	leftLit, _ := types.ComputeLiteralData{Value: leftVal}.ToEntity()
	rightLit, _ := types.ComputeLiteralData{Value: rightVal}.ToEntity()
	leftLitH := putCE(ctx, client, tp+"/"+suffix+"-l", leftLit)
	rightLitH := putCE(ctx, client, tp+"/"+suffix+"-r", rightLit)

	cast, _ := types.ComputeNumericCastData{Value: leftLitH, ToType: "primitive/uint"}.ToEntity()
	castH := putCE(ctx, client, tp+"/"+suffix+"-cast", cast)

	condLit, _ := types.ComputeLiteralData{Value: true}.ToEntity()
	condH := putCE(ctx, client, tp+"/"+suffix+"-cond", condLit)

	ifEnt, _ := types.ComputeIfData{Condition: condH, Then: castH, Else: &leftLitH}.ToEntity()
	ifH := putCE(ctx, client, tp+"/"+suffix+"-if", ifEnt)

	div, err := types.ComputeArithmeticData{Op: "div", Left: ifH, Right: rightLitH}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, div); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}

// computeEvalCastThroughClosureArg builds
// `apply(lambda(y): div(y, rightVal), {y: cast(leftVal, uint)})`. Per v3.17
// rule 11 closure-arg binding is a strip point — the cast lands in closure
// scope, lookup/scope("y") inside the body resolves to an untagged value,
// so div uses signed-default.
func computeEvalCastThroughClosureArg(ctx context.Context, client *PeerClient, peerID, tp, suffix string, leftVal, rightVal uint64) (interface{}, error) {
	leftLit, _ := types.ComputeLiteralData{Value: leftVal}.ToEntity()
	rightLit, _ := types.ComputeLiteralData{Value: rightVal}.ToEntity()
	leftLitH := putCE(ctx, client, tp+"/"+suffix+"-l", leftLit)
	rightLitH := putCE(ctx, client, tp+"/"+suffix+"-r", rightLit)

	cast, _ := types.ComputeNumericCastData{Value: leftLitH, ToType: "primitive/uint"}.ToEntity()
	castH := putCE(ctx, client, tp+"/"+suffix+"-cast", cast)

	// lambda(y): div(lookup/scope("y"), right)
	lookupY, _ := types.ComputeLookupScopeData{Name: "y"}.ToEntity()
	lookupYH := putCE(ctx, client, tp+"/"+suffix+"-yref", lookupY)
	body, _ := types.ComputeArithmeticData{Op: "div", Left: lookupYH, Right: rightLitH}.ToEntity()
	bodyH := putCE(ctx, client, tp+"/"+suffix+"-body", body)
	lambda, _ := types.ComputeLambdaData{Params: []string{"y"}, Body: bodyH}.ToEntity()
	lambdaH := putCE(ctx, client, tp+"/"+suffix+"-lambda", lambda)

	apply, err := types.ComputeApplyData{
		Fn:   lambdaH,
		Args: map[string]hash.Hash{"y": castH},
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	path := tp + "/" + suffix
	if _, err := client.TreePut(ctx, path, apply); err != nil {
		return nil, err
	}
	return extractResultValue(ctx, client, peerID, path)
}
