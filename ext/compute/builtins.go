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
	val, err := Evaluate(target, scope, budget, ctx)
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

// builtinMap applies fn to each element of collection in index order, returns
// a new array of results (§962).
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
		if err != nil {
			return nil, err
		}
		out = append(out, v)
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
	acc, err := Evaluate(initialTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	for _, elt := range arr {
		acc, err = invokeClosure(fn, []interface{}{acc, elt}, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
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
	pathVal, err := Evaluate(pathTarget, scope, budget, ctx)
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
	if err != nil {
		return nil, err
	}
	// v3.19c Part A M3 boundary 3: store→tree crosses the compute→non-compute
	// boundary. Materialize an in-flight *constructedValue to a bare entity.
	valueVal, err = materialize(valueVal, ctx.ContentStore)
	if err != nil {
		return nil, err
	}
	valueEnt, ok := valueVal.(entity.Entity)
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
