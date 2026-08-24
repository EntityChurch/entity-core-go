package compute

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The v3.24 collection primitives — range / group-by / concat / assoc
// (EXTENSION-COMPUTE §3.5 "The v3.24 collection primitives"). All four are
// MUST-given-COMPUTE (§10.1): they produce boundary bytes, so a peer that
// computes a different result is divergent, not merely slower. Evaluated
// internally within the evaluator (the §3.5 SHOULD) alongside map/filter/fold.
//
// Error-propagation posture is governed by §7.2, not a rule of its own
// (v3.25, C-4 — go's original split was ruled correct and is now spec-cited):
//   - CONTROL positions short-circuit (evalControlArg → evalOperand): a value
//     that STEERS the computation — range's n, assoc's index, group-by's
//     derived key, concat's collections — is a §7.2 consumed operand, so an
//     error there propagates (as compute/index already does for its index).
//   - DATA positions contain (evalDataArg → Evaluate): a value PLACED INTO the
//     output — assoc's value (the SA-9 store case), group-by's members, concat's
//     copied elements — flows in as a value, exactly as map already lets a
//     closure's error-result become an output element.

// evalControlArg resolves and evaluates a consumed/steering arg, short-circuiting
// on an error-as-value (§2131). Missing arg → missing_argument.
func evalControlArg(args map[string]hash.Hash, key string, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	h, ok := args[key]
	if !ok {
		return nil, newComputeError(ErrMissingArgument, "missing "+key+" arg")
	}
	target, err := resolveOrError(h, ctx, key)
	if err != nil {
		return nil, err
	}
	return evalOperand(target, scope, budget, ctx)
}

// evalDataArg resolves and evaluates an arg whose value is PLACED INTO an
// output array; an error-as-value is NOT short-circuited — it flows in as a
// value (container semantics, matching map's element results).
func evalDataArg(args map[string]hash.Hash, key string, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	h, ok := args[key]
	if !ok {
		return nil, newComputeError(ErrMissingArgument, "missing "+key+" arg")
	}
	target, err := resolveOrError(h, ctx, key)
	if err != nil {
		return nil, err
	}
	return Evaluate(target, scope, budget, ctx)
}

// builtinRange returns [0 … n-1], empty when n is 0 (§3.5). Single-argument
// form only — a start offset is expressed inside the lambda.
func builtinRange(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	nVal, err := evalControlArg(d.Args, "n", scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	n, isInt, inInt64 := asIndex(nVal)
	if !isInt {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("range n must be an integer, got %T", nVal))
	}
	// v3.25 (C-3, ruled): a negative n, or an n exceeding the maximum
	// representable array length (uint64 above MaxInt64, inInt64 == false), is
	// count_out_of_range — NOT type_mismatch (an out-of-domain magnitude is not
	// a type error, §2.2) and NOT clamped to []: n is a loop bound, so a silent
	// empty would propagate a well-formed wrong answer carrying no error. go's
	// v3.24 type_mismatch here was anchored to the C-2 assoc defect; corrected.
	if !inInt64 || n < 0 {
		return nil, newComputeError(ErrCountOutOfRange,
			fmt.Sprintf("range n must be non-negative and representable, got %s", indexMagnitude(nVal, n, inInt64)))
	}
	// Charge the budget per produced element so range(huge) exhausts rather
	// than OOMs — matches the per-Evaluate decrement map/filter/fold pay.
	if n > int64(budget.Operations) {
		return nil, newComputeError(ErrBudgetExhausted,
			fmt.Sprintf("range(%d) exceeds remaining budget %d", n, budget.Operations))
	}
	budget.Operations -= int(n)
	out := make([]interface{}, n)
	for i := int64(0); i < n; i++ {
		out[i] = i
	}
	return out, nil
}

// builtinGroupBy applies fn to each element to derive a key and returns the
// elements grouped by that key in ONE PASS (§3.5). Within each group elements
// keep input index order; groups are ordered by FIRST APPEARANCE of their key
// (no key-sort — keys have no total order in this extension).
//
// v3.25 (C-1, ruled): the RESULT is an array of system/compute/group{key,
// members} — the KEY IS CARRIED, not dropped (a histogram/bucketing/router
// output is unreadable without its labels). The shape was ruled in the design
// record; go's v3.24 array-of-arrays lost it in the fold and is corrected.
// Each group is an in-flight *constructedValue encoded by runtime kind (§4.1) —
// a pinned type name, not a type-extension registration.
//
// Key equality is byte-identity over the canonical ECF encoding of the derived
// key — the protocol's own value-identity, well-defined for arbitrary key types.
func builtinGroupBy(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	arr, err := resolveCollection(d, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	fn, err := resolveClosureArg(d.Args, "fn", scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	order := make([]string, 0, len(arr))
	groups := make(map[string][]interface{})
	keyVals := make(map[string]interface{})
	for _, elt := range arr {
		keyVal, err := invokeClosure(fn, []interface{}{elt}, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
		// The derived key STEERS grouping — an error key cannot be grouped, so
		// it short-circuits (§7.2 consumed position) even though the key now has
		// an output slot: grouping by an error would make its message string
		// structurally load-bearing (§3.5 v3.25).
		if ce, isErr := computeErrorFromValue(keyVal); isErr {
			return nil, ce
		}
		keyBytes, err := canonicalKeyBytes(keyVal, ctx)
		if err != nil {
			return nil, err
		}
		k := string(keyBytes)
		if _, seen := groups[k]; !seen {
			order = append(order, k)
			keyVals[k] = keyVal
		}
		groups[k] = append(groups[k], elt)
	}
	out := make([]interface{}, 0, len(order))
	for _, k := range order {
		out = append(out, &constructedValue{
			entityType: types.TypeComputeGroup,
			fields:     map[string]interface{}{"key": keyVals[k], "members": groups[k]},
		})
	}
	return out, nil
}

// canonicalKeyBytes materializes a group-by key value and canonically encodes
// it (ECF), yielding the byte-identity used for key equality.
func canonicalKeyBytes(v interface{}, ctx *EvalContext) ([]byte, error) {
	mv, err := materialize(v, ctx.ContentStore)
	if err != nil {
		return nil, err
	}
	raw, err := ecf.Encode(mv)
	if err != nil {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("group-by key is not encodable (%T)", v))
	}
	return raw, nil
}

// builtinConcat joins arrays order-preserving, ONE LEVEL — no recursive flatten
// (§3.5). Element types across all collections MUST match; a mismatch is a
// type_mismatch error-as-value, not a fault. concat() → empty; concat(a) → a.
//
// The `collections` arg is a single hash that evaluates to an array whose
// elements are each an array (the sub-collections). Copied elements retain
// their value form — an error-as-value already present in an input flows into
// the output (container semantics).
func builtinConcat(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	collsVal, err := evalControlArg(d.Args, "collections", scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	colls, ok := collsVal.([]interface{})
	if !ok {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("concat collections must be an array of arrays, got %T", collsVal))
	}
	out := make([]interface{}, 0)
	var tag string
	var typed bool
	for _, c := range colls {
		sub, ok := c.([]interface{})
		if !ok {
			return nil, newComputeError(ErrTypeMismatch,
				fmt.Sprintf("concat: each collection must be an array, got %T", c))
		}
		for _, elt := range sub {
			// v3.25 (C-4, ruled): a compute/error element is TYPE-TRANSPARENT to
			// the element-type-match check — it neither matches nor mismatches and
			// flows through untouched. Per §1.5 an error is a poisoned value OF the
			// element type (the NaN analogy), not a value of a different type, and
			// §7.2 scopes concat to consuming its collections, never their elements.
			if _, isErr := computeErrorFromValue(elt); isErr {
				out = append(out, elt)
				continue
			}
			et := elementTypeTag(elt)
			if !typed {
				tag, typed = et, true
			} else if et != tag {
				return nil, newComputeError(ErrTypeMismatch,
					fmt.Sprintf("concat: element type %q does not match %q", et, tag))
			}
			out = append(out, elt)
		}
	}
	return out, nil
}

// elementTypeTag classifies a compute value for concat's element-type-match
// check. int/uint collapse to one "integer" tag — they are annotations, not
// distinct value types (§2.2).
func elementTypeTag(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case int64, uint64:
		return "integer"
	case float64:
		return "float"
	case string:
		return "string"
	case []byte:
		return "bytes"
	case []interface{}:
		return "array"
	case entity.Entity:
		return "entity:" + t.Type
	default:
		return fmt.Sprintf("%T", v)
	}
}

// builtinAssoc returns a new array identical to collection except at index,
// which carries value (§3.5). v3.25 (C-2, ruled): an out-of-range index —
// negative, or ≥ the collection's length — is index_out_of_range, the SAME
// code and condition as compute/index (§2.2). go's v3.24 type_mismatch here
// re-litigated §2.2's cross-impl ruling (F-2) and is corrected: one document
// must not answer one malformed program with two codes depending on which
// array operation it reached. assoc MUST NOT be an implicit lowering target
// [MUST] — go performs no fold→assoc lowering, so there is nothing to suppress.
func builtinAssoc(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	arr, err := resolveCollection(d, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	idxVal, err := evalControlArg(d.Args, "index", scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	idx, isInt, inInt64 := asIndex(idxVal)
	if !isInt {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("assoc index must be an integer, got %T", idxVal))
	}
	if !inInt64 || idx < 0 || idx >= int64(len(arr)) {
		return nil, newComputeError(ErrIndexOutOfRange,
			fmt.Sprintf("assoc index %s out of range for array of length %d",
				indexMagnitude(idxVal, idx, inInt64), len(arr)))
	}
	// value is a DATA position — an error-as-value flows into the array.
	val, err := evalDataArg(d.Args, "value", scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, len(arr))
	copy(out, arr)
	out[idx] = val
	return out, nil
}
