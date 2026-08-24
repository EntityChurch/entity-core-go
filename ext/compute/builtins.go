package compute

import (
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Builtin path constants per EXTENSION-COMPUTE §3.5.
const (
	builtinPrefix     = "system/compute/builtins/"
	BuiltinArithmetic = builtinPrefix + "arithmetic"
	BuiltinCompare    = builtinPrefix + "compare"
	BuiltinLogic      = builtinPrefix + "logic"
	BuiltinField      = builtinPrefix + "field"
	BuiltinConstruct  = builtinPrefix + "construct"
	BuiltinMap        = builtinPrefix + "map"
	BuiltinFilter     = builtinPrefix + "filter"
	BuiltinFold       = builtinPrefix + "fold"
	BuiltinStore      = builtinPrefix + "store"
	// v3.24 collection primitives.
	BuiltinRange   = builtinPrefix + "range"
	BuiltinGroupBy = builtinPrefix + "group-by"
	BuiltinConcat  = builtinPrefix + "concat"
	BuiltinAssoc   = builtinPrefix + "assoc"
)

// IsBuiltinPath reports whether a path is a system/compute/builtins/* address.
func IsBuiltinPath(path string) bool {
	return strings.HasPrefix(path, builtinPrefix)
}

// evalBuiltin handles compute/apply targeting a system/compute/builtins/* path.
// Per EXTENSION-COMPUTE §3.5 ("implementations MAY treat the handler dispatches
// as aliases for the inline types internally"), we intercept these in-process
// to avoid round-tripping through the dispatcher. The inline-equivalent
// builtins (arithmetic, compare, logic, field, construct) reuse the inline
// expression evaluators; map/filter/fold/store are implemented natively here.
//
// Operation MUST be "eval" per §9.2.
func evalBuiltin(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	if d.Operation != "eval" {
		return nil, newComputeError(ErrInvalidExpression,
			"builtin "+d.Path+" requires operation \"eval\", got "+d.Operation)
	}

	switch d.Path {
	case BuiltinArithmetic:
		return builtinViaInline(d, scope, budget, ctx, func(args map[string]hash.Hash) (entity.Entity, error) {
			return types.ComputeArithmeticData{
				Op:    mustStringArg(args, "op", scope, ctx),
				Left:  args["left"],
				Right: args["right"],
			}.ToEntity()
		})
	case BuiltinCompare:
		return builtinViaInline(d, scope, budget, ctx, func(args map[string]hash.Hash) (entity.Entity, error) {
			return types.ComputeCompareData{
				Op:    mustStringArg(args, "op", scope, ctx),
				Left:  args["left"],
				Right: args["right"],
			}.ToEntity()
		})
	case BuiltinField:
		return builtinViaInline(d, scope, budget, ctx, func(args map[string]hash.Hash) (entity.Entity, error) {
			return types.ComputeFieldData{
				Name:   mustStringArg(args, "name", scope, ctx),
				Entity: args["entity"],
			}.ToEntity()
		})
	case BuiltinConstruct:
		return builtinConstruct(d, scope, budget, ctx)
	case BuiltinLogic:
		return builtinLogic(d, scope, budget, ctx)
	case BuiltinMap:
		return builtinMap(d, scope, budget, ctx)
	case BuiltinFilter:
		return builtinFilter(d, scope, budget, ctx)
	case BuiltinFold:
		return builtinFold(d, scope, budget, ctx)
	case BuiltinRange:
		return builtinRange(d, scope, budget, ctx)
	case BuiltinGroupBy:
		return builtinGroupBy(d, scope, budget, ctx)
	case BuiltinConcat:
		return builtinConcat(d, scope, budget, ctx)
	case BuiltinAssoc:
		return builtinAssoc(d, scope, budget, ctx)
	case BuiltinStore:
		return builtinStore(d, scope, budget, ctx)
	default:
		return nil, newComputeError(ErrInvalidExpression, "unknown builtin: "+d.Path)
	}
}

// builtinViaInline rebuilds the equivalent inline expression entity from the
// apply args and runs the existing inline evaluator. The result hash is
// identical to writing the inline form directly (per §3.5 alias guarantee).
// `build` constructs the inline expression entity from the args map.
func builtinViaInline(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext, build func(map[string]hash.Hash) (entity.Entity, error)) (interface{}, error) {
	ent, err := build(d.Args)
	if err != nil {
		return nil, newComputeError(ErrInvalidExpression, "builtin alias build failed: "+err.Error())
	}
	return evaluateInner(ent, scope, budget, ctx)
}

// mustStringArg resolves a string-valued arg hash. Returns "" if the arg is
// missing or doesn't evaluate to a string — the inline evaluator's op
// validation will reject empty/unknown ops with invalid_expression.
func mustStringArg(args map[string]hash.Hash, key string, scope *Scope, ctx *EvalContext) string {
	h, ok := args[key]
	if !ok {
		return ""
	}
	ent, ok := resolve(h, ctx)
	if !ok {
		return ""
	}
	v, err := Evaluate(ent, scope, NewBudget(64, 16), ctx)
	if err != nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// builtinConstruct unpacks the apply args' "fields" map (a map of {field_name: hash})
// and the "entity_type" string, then evaluates via the inline construct path.
// Construct's args shape is map-of-hashes, which doesn't fit builtinViaInline.
func builtinConstruct(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	entityType := mustStringArg(d.Args, "entity_type", scope, ctx)
	if entityType == "" {
		return nil, newComputeError(ErrInvalidExpression,
			"system/compute/builtins/construct requires entity_type arg")
	}
	// "fields" arg is a hash → expression that evaluates to a map of {name → hash}.
	// In the simple alias case, callers pass each field hash directly under that
	// field name — i.e. d.Args already carries the field hashes. Filter out the
	// reserved entity_type key.
	fields := make(map[string]hash.Hash, len(d.Args))
	for k, v := range d.Args {
		if k == "entity_type" {
			continue
		}
		fields[k] = v
	}
	ent, err := types.ComputeConstructData{EntityType: entityType, Fields: fields}.ToEntity()
	if err != nil {
		return nil, newComputeError(ErrInvalidExpression, "construct alias build failed: "+err.Error())
	}
	return evaluateInner(ent, scope, budget, ctx)
}

// builtinLogic mirrors the inline form. The "not" op uses left only.
func builtinLogic(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	op := mustStringArg(d.Args, "op", scope, ctx)
	logicData := types.ComputeLogicData{
		Op:   op,
		Left: d.Args["left"],
	}
	if right, ok := d.Args["right"]; ok {
		logicData.Right = &right
	}
	ent, err := logicData.ToEntity()
	if err != nil {
		return nil, newComputeError(ErrInvalidExpression, "logic alias build failed: "+err.Error())
	}
	return evaluateInner(ent, scope, budget, ctx)
}

// --- Collection builtins (§3.5 §962): map / filter / fold ---

// resolveCollection evaluates the "collection" arg and asserts the result is
// an array, returning it as []interface{}. Returns type_mismatch otherwise.
func resolveCollection(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) ([]interface{}, error) {
	h, ok := d.Args["collection"]
	if !ok {
		return nil, newComputeError(ErrInvalidExpression, "missing collection arg")
	}
	target, err := resolveOrError(h, ctx, "collection")
	if err != nil {
		return nil, err
	}
	// The `collection` operand is a CONSUMED position (§7.2 — its length/elements
	// are read to drive map/filter/fold/assoc/group-by), so a compute/error there
	// MUST short-circuit, exactly as compute/index's and compute/length's array
	// operands do (both use evalOperand). Using bare Evaluate here masked a
	// value-form error as `type_mismatch`: an SA-1 error (or a lookup onto a stored
	// error) is not a Go-error, so it fell through to the "not an array" branch
	// below and reported the wrong code. is_error is kind-based (§4.1), so both
	// representations funnel through evalOperand — the minted form via its
	// Go-error, the value form via the is_error check inside evalOperand.
	// (Cross-impl: core-rust + core-py each traced go's type_mismatch here to this
	// one Evaluate-vs-evalOperand slip and routed it back — docs/validation/reports
	// 2026-08-21. The go compute corpus LOCKED 352/352 anyway because no vector
	// placed an error in the COLLECTION operand: the exact "two readings agree
	// everywhere your fixtures live" gap.)
	val, err := evalOperand(target, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	arr, ok := val.([]interface{})
	if !ok {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("collection must be an array, got %T", val))
	}
	return arr, nil
}

// resolveClosureArg evaluates an arg hash to a compute/closure entity. A
// compute/lambda is evaluated first to produce the closure.
func resolveClosureArg(args map[string]hash.Hash, key string, scope *Scope, budget *Budget, ctx *EvalContext) (entity.Entity, error) {
	h, ok := args[key]
	if !ok {
		return entity.Entity{}, newComputeError(ErrInvalidExpression, "missing "+key+" arg")
	}
	target, err := resolveOrError(h, ctx, key)
	if err != nil {
		return entity.Entity{}, err
	}
	if target.Type == types.TypeComputeClosure {
		return target, nil
	}
	val, err := Evaluate(target, scope, budget, ctx)
	if err != nil {
		return entity.Entity{}, err
	}
	ent, ok := val.(entity.Entity)
	if !ok || ent.Type != types.TypeComputeClosure {
		return entity.Entity{}, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("%s must resolve to a closure, got %T", key, val))
	}
	return ent, nil
}

// invokeClosure runs a closure with the given pre-evaluated argument values.
// Mirrors evalApplyClosure but for in-process invocation where values (not
// hashes) are already in hand — used by map/filter/fold to call fn per element.
func invokeClosure(closureEnt entity.Entity, args []interface{}, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var closureData types.ComputeClosureData
	if err := ecf.Decode(closureEnt.Data, &closureData); err != nil {
		return nil, err
	}
	if len(args) != len(closureData.Params) {
		return nil, newComputeError(ErrMissingArgument,
			fmt.Sprintf("closure expects %d args, got %d", len(closureData.Params), len(args)))
	}
	var envHash hash.Hash
	if closureData.Env != nil {
		envHash = *closureData.Env
	}
	newScope, err := LoadScope(envHash, ctx)
	if err != nil {
		return nil, err
	}
	for i, param := range closureData.Params {
		newScope.Set(param, args[i])
	}
	bodyTarget, err := resolveOrError(closureData.Body, ctx, "closure body")
	if err != nil {
		return nil, err
	}
	return Evaluate(bodyTarget, newScope, budget, ctx)
}

// isShortCircuitLimitCode reports whether a compute/error code SHORT-CIRCUITS
// even in an otherwise-contained closure-result position — map's output element,
// fold's accumulator. The discriminator (arch §8, PROPOSAL-COMPUTE-CLOSURE-RESULT-
// POSITIONS §8.1–§8.3, EXTENSION-COMPUTE 3.27 D5) is NOT "limit-ness" and NOT the
// two-against-one vote — it is one sentence of §5.1: a counter that is NOT restored
// on unwind makes element i's outcome a function of elements 1…i−1, which a
// contained result would fork across peers:
//
//   - budget_exhausted (§8.1): `operations` is decremented once per evaluate()
//     and NEVER restored, and §10.4 makes memoization impl-defined, so two
//     conformant peers with identical IR/inputs/budget can exhaust at a different
//     element. Contained, that yields [v₁…v_{k−1}, E, E, …] with a different k
//     per peer — different boundary bytes for one program (§8.1 determinism MUST,
//     AE-1). And a well-formed array of contained budget_exhausted is a
//     successful-looking result for an evaluation the peer ABORTED. SHORT-CIRCUITS.
//   - cascade_limit (§8.2): the §7.3 counter is shared across the entire causal
//     chain (chain_id, cross-peer) and reaching it FREEZES the subgraph; a
//     well-formed array reporting element-wise cascade_limit values for a
//     structurally-halted computation is exactly what §7.3 refuses. SHORT-CIRCUITS.
//
// depth_exceeded is NOT here (§8.3): `depth` is restored on unwind (§5.1's own
// parenthetical), so it is element-local — map(f,xs) where f recurses too deep on
// element 2 yields [a, E, c], the §1.5 NaN model. It CONTAINS like any other error
// and needs no carve-out at all. rust and py were right and go was the 1-of-3
// outlier; the spec arbitrates against go here (§8.3, ruling h §2).
func isShortCircuitLimitCode(code string) bool {
	switch code {
	case ErrBudgetExhausted, ErrCascadeLimit:
		return true
	}
	return false
}

// containOrPropagate implements the §2.4 provenance-independence boundary (arch
// C-8 ruling 172589e) for the MINTED arm of a CONTAINED closure-result position —
// map's output element and fold's accumulator, the two places a primitive PLACES a
// closure result without reading it. A MINTED *ComputeError (the closure body
// raised) must produce the same contained bytes as a value-form compute/error that
// flowed in on the success path, so it is converted to its entity form and returned
// as a value with a nil error. The ONE exception is a short-circuit eval-limit code
// (isShortCircuitLimitCode — budget_exhausted / cascade_limit, §8.1/§8.2): those
// short-circuit even here. depth_exceeded contains like any other error (§8.3). A
// non-*ComputeError infra failure (corrupt/unresolvable closure) also propagates.
//
// Prefer containClosureResult, which unifies BOTH arms; call this directly only
// where the value form cannot occur.
func containOrPropagate(err error) (interface{}, error) {
	ce, ok := err.(*ComputeError)
	if !ok || isShortCircuitLimitCode(ce.Code) {
		return nil, err
	}
	errEnt, eerr := ce.ToEntity()
	if eerr != nil {
		return nil, eerr
	}
	return errEnt, nil
}

// containClosureResult is the SINGLE boundary-hash-determining rule for a contained
// closure-result position, covering BOTH arms symmetrically (arch §8.4 / D6 /
// SA-PY-25: the disposition is keyed on the CODE, never the variant — a value-form
// budget_exhausted short-circuits exactly as a minted one does, because §2.4 makes
// "two errors with the same code the same materialized entity"). Callers pass the
// (value, err) pair a closure/Evaluate returned:
//
//		contained, perr := containClosureResult(v, err)
//		if perr != nil { return nil, perr }   // short-circuit (limit code) or infra failure
//		v = contained                          // ordinary error contained, or plain value
//
//	  - err != nil (MINTED arm): delegate to containOrPropagate.
//	  - err == nil, v is a value-form compute/error whose code short-circuits
//	    (§8.4): short-circuit it, returning the *ComputeError so map/fold abort.
//	  - otherwise: the value is contained unchanged (an ordinary value, or an
//	    ordinary/ depth_exceeded compute/error placed as-is per the NaN model).
//
// Keep this the ONE implementation shared by map and fold (charter: a
// hash-determining concept implemented in more than one place MUST share it).
func containClosureResult(v interface{}, err error) (interface{}, error) {
	if err != nil {
		return containOrPropagate(err)
	}
	if ce, isErr := computeErrorFromValue(v); isErr && isShortCircuitLimitCode(ce.Code) {
		return nil, ce
	}
	return v, nil
}

// builtinMap applies fn to each element of collection in index order, returns
// a new array of results (§962).
//
// The closure RESULT is a CONTAINED output element (arch C-8 ruling 172589e:
// "map never reads it; §1.5's NaN model is element-wise"). A closure that yields
// a compute/error for an element places that error INTO the output array as a
// value — it does NOT short-circuit the map — so mapping a fallible fn returns
// an array with error markers, NaN-style. Both error representations converge
// here: a value-form error result already flowed in as the element value; a
// minted *ComputeError (the closure body raised — div-by-zero, type_mismatch, …)
// is now converted to its entity form and contained the same way, killing the
// §2.4 provenance asymmetry (minted used to abort the whole map). The boundary
// reduces every contained compute/error element to code-only (materialize(),
// eval_construct.go), so the two representations produce identical boundary
// bytes. The ONE exception is the evaluation-limit codes — see isEvalLimitCode.
func builtinMap(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	arr, err := resolveCollection(d, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	fn, err := resolveClosureArg(d.Args, "fn", scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(arr))
	for _, elt := range arr {
		v, err := invokeClosure(fn, []interface{}{elt}, scope, budget, ctx)
		// Both arms through the ONE boundary rule: a minted OR value-form error is
		// contained as the output element (§1.5 NaN model), EXCEPT a short-circuit
		// eval-limit code (budget_exhausted / cascade_limit) which aborts the whole
		// map — keyed on the code, not on whether it was minted (§8.4/D6). A
		// value-form budget_exhausted contained-here was the §2.4 provenance
		// asymmetry the minted-only carve-out reinstated (CV-9c).
		contained, perr := containClosureResult(v, err)
		if perr != nil {
			return nil, perr
		}
		out = append(out, contained)
	}
	return out, nil
}

// builtinFilter retains elements for which predicate is truthy, in index
// order (§962).
func builtinFilter(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	arr, err := resolveCollection(d, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	pred, err := resolveClosureArg(d.Args, "fn", scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(arr))
	for _, elt := range arr {
		v, err := invokeClosure(pred, []interface{}{elt}, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
		// The predicate RESULT is CONSUMED — read for truthiness (§7.2 general
		// rule + arch C-8 ruling: "filter's predicate result short-circuits").
		// A value-form compute/error here MUST short-circuit, not be run through
		// truthy(): truthy(errorEntity) hits the default `return true`, so the
		// element would be silently KEPT on a failed predicate — the provenance
		// asymmetry §2.4 forbids (a minted predicate error already short-circuits
		// via the err!=nil return above). This is the same evalOperand chokepoint
		// the collection operand uses, applied to the closure result.
		if ce, isErr := computeErrorFromValue(v); isErr {
			return nil, ce
		}
		if truthy(v) {
			out = append(out, elt)
		}
	}
	return out, nil
}

// builtinFold threads initial through fn(acc, element) left-to-right and
// returns the final accumulator (§962).
func builtinFold(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	arr, err := resolveCollection(d, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	fn, err := resolveClosureArg(d.Args, "fn", scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	initialHash, ok := d.Args["initial"]
	if !ok {
		return nil, newComputeError(ErrInvalidExpression, "missing initial arg")
	}
	initialTarget, err := resolveOrError(initialHash, ctx, "initial")
	if err != nil {
		return nil, err
	}
	// The accumulator is a CONTAINED position (arch C-8 ruling 172589e: "fold binds
	// it into the next closure invocation and never reads it, so a closure that
	// ignores its accumulator RECOVERS" — CV-8d). An error accumulator — value-form
	// or minted — is threaded onward as an ordinary value; fold NEVER short-circuits
	// on it. This is the shape §1.5's error-as-value model requires (errors are
	// ordinary values a program may inspect, §4.1 is_error), and it is what the old
	// short-circuit got exactly backwards. The empty-collection case pins it:
	// fold([], fn, E) = E, the error contained as the final accumulator.
	//
	// `initial` is bound (contained), not consumed: a value-form error initial
	// arrives as a value from Evaluate (err==nil); a minted one is contained the
	// same way map's output element is. Both arms go through containClosureResult,
	// so an ordinary or depth_exceeded error is contained and a short-circuit
	// eval-limit code (budget/cascade) aborts, keyed on the code (§8.4/D6).
	// `collection`, by contrast, is CONSUMED — resolveCollection short-circuits a
	// value-form error collection (§7.2), unchanged.
	acc, err := containClosureResult(Evaluate(initialTarget, scope, budget, ctx))
	if err != nil {
		return nil, err
	}
	for _, elt := range arr {
		// Minted OR value-form closure result contained as the new accumulator
		// (map's rule); only a short-circuit eval-limit code aborts. No short-circuit
		// on an ordinary error acc — the closure may ignore it next iteration and
		// recover (CV-8d).
		next, ierr := containClosureResult(invokeClosure(fn, []interface{}{acc, elt}, scope, budget, ctx))
		if ierr != nil {
			return nil, ierr
		}
		acc = next
	}
	return acc, nil
}

// builtinStore writes value to path via dispatch through system/tree:put.
// Capability gating is handled by the tree handler against ctx.Capability
// (the EXECUTE caller's grant), satisfying §6.3 W4.
func builtinStore(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	if ctx.DispatchExecute == nil {
		return nil, newComputeError(ErrInvalidExpression,
			"system/compute/builtins/store requires dispatch capability")
	}

	pathHash, ok := d.Args["path"]
	if !ok {
		return nil, newComputeError(ErrInvalidExpression, "store missing path arg")
	}
	valueHash, ok := d.Args["value"]
	if !ok {
		return nil, newComputeError(ErrInvalidExpression, "store missing value arg")
	}

	pathTarget, err := resolveOrError(pathHash, ctx, "store path")
	if err != nil {
		return nil, err
	}
	// store's `path` is a CONSUMED operand — it steers WHERE the write goes, like
	// assoc's `index` steers where the update lands — so a compute/error path
	// SHORT-CIRCUITS, it does not become type_mismatch. §200 states this as the
	// store model directly: an error-valued store field "would short-circuit to
	// that error" (which is exactly why `resource`/`capability` are shape-checked
	// BEFORE eval). Bare Evaluate + .(string) masked a value-form error path as
	// type_mismatch — the resolveCollection slip on store's own operand, and
	// internally inconsistent with assoc's index (which routes through evalOperand).
	// Only `value` is the write/contain position (materialized code-only below).
	// [Cross-impl coordination: found by the 2026-08-21 consumed-operand sweep, not
	//  by a peer or a vector; flagged to rust/py to confirm their store-path handling
	//  agrees rather than seeding a store vector unilaterally.]
	pathVal, err := evalOperand(pathTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	pathStr, ok := pathVal.(string)
	if !ok {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("store path must be a string, got %T", pathVal))
	}

	valueTarget, err := resolveOrError(valueHash, ctx, "store value")
	if err != nil {
		return nil, err
	}
	valueVal, err := Evaluate(valueTarget, scope, budget, ctx)

	// §2.4 (v3.23 ruling B; N1 §2.3 / §2148): SA-9 store is a WRITE /
	// materialization site, not a consumed position — a compute/error reaching
	// store's value materializes code-only and is written to the path, the
	// imperative analog of the §7.2 reactive result_path crossing in engine.go.
	// It never re-embeds message/at (those would leak impl prose into the
	// content-addressed result and break cross-peer convergence). is_error is
	// kind-based, so BOTH in-language representations funnel here identically:
	//   - minted:     Evaluate returns a *ComputeError (Go-error);
	//   - value-form: Evaluate returns a compute/error VALUE (SA-1, nil Go-error) —
	//                 a literal, or a lookup onto a stored error.
	// A non-ComputeError Go error is an infra fault, not a compute value — it
	// propagates. Route both error forms through the same code-only
	// ToMaterializedEntity path; the value form would otherwise fall through to
	// materialize() below, which rejects a compute/error entity post-v3.23.
	//
	// NOTE (spec-issue 2026-08-16, store-value: write vs short-circuit): §2137's
	// "error short-circuit normative" lists compute/apply (handler mode) among the
	// consumers that short-circuit, while N1/§2.4/§2148 list SA-9 store among the
	// WRITE sites where an error materializes. The store builtin is a handler-mode
	// apply, so the two rules point opposite ways for store's value. This impl
	// follows the write-site taxonomy (materialize code-only) per arch's gate; the
	// tension is routed for a worked example.
	var storeErr *ComputeError
	if err != nil {
		ce, isCE := err.(*ComputeError)
		if !isCE {
			return nil, err
		}
		storeErr = ce
	} else if ce, isErr := computeErrorFromValue(valueVal); isErr {
		storeErr = ce
	}

	var valueEnt entity.Entity
	if storeErr != nil {
		valueEnt, err = storeErr.ToMaterializedEntity()
		if err != nil {
			return nil, err
		}
	} else {
		// v3.19c Part A M3 boundary 3: store→tree crosses the compute→non-compute
		// boundary. Materialize an in-flight *constructedValue to a bare entity.
		valueVal, err = materialize(valueVal, ctx.ContentStore)
		if err != nil {
			return nil, err
		}
		var ok bool
		valueEnt, ok = valueVal.(entity.Entity)
		if !ok {
			// Wrap a bare primitive in primitive/any so it has an entity form
			// (mirrors the wire shape primitive/* use for bare values).
			raw, encErr := ecf.Encode(valueVal)
			if encErr != nil {
				return nil, newComputeError(ErrTypeMismatch,
					fmt.Sprintf("cannot encode store value: %v", encErr))
			}
			valueEnt, err = entity.NewEntity("primitive/any", raw)
			if err != nil {
				return nil, err
			}
		}
	}

	entBytes, err := ecf.Encode(valueEnt)
	if err != nil {
		return nil, newComputeError(ErrInvalidExpression, "encode store value: "+err.Error())
	}
	putReq := types.PutRequestData{Entity: entBytes}
	paramsEnt, err := putReq.ToEntity()
	if err != nil {
		return nil, newComputeError(ErrInvalidExpression, "build put-request: "+err.Error())
	}

	resource := &types.ResourceTarget{Targets: []string{pathStr}}
	resp, err := ctx.DispatchExecute("system/tree", "put", resource, paramsEnt, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status >= 400 {
		if resp.Result.Type == types.TypeComputeError {
			ed, decErr := types.ComputeErrorDataFromEntity(resp.Result)
			if decErr == nil {
				return nil, &ComputeError{Code: ed.Code, Message: ed.Message, At: ed.At}
			}
		}
		return nil, newComputeError(ErrPermissionDenied,
			fmt.Sprintf("store dispatch to system/tree:put failed: status %d", resp.Status))
	}
	return resp.Result, nil
}
