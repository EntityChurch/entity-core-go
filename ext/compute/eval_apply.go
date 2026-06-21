package compute

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

func evalApply(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeApplyData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	if d.Path != "" {
		return evalApplyHandler(d, ent.ContentHash, scope, budget, ctx)
	}
	if !d.Fn.IsZero() {
		return evalApplyClosure(d, scope, budget, ctx)
	}
	return nil, newComputeError(ErrInvalidExpression, "compute/apply requires path or fn")
}

func evalApplyHandler(d types.ComputeApplyData, applyHash hash.Hash, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	if d.Operation == "" {
		return nil, newComputeError(ErrInvalidExpression, "compute/apply handler mode requires operation")
	}
	// Builtin aliasing per §3.5 — these dispatch in-process so map/filter/fold
	// have direct access to the evaluator (closures need scope + budget). The
	// inline-equivalent builtins (arithmetic/compare/...) reuse their inline
	// evaluators, producing hash-equal results per the §3.5 alias guarantee.
	// Capability override + resource still need full handling, so we only
	// shortcut when neither is in play.
	if IsBuiltinPath(d.Path) && d.Capability.IsZero() && d.Resource.IsZero() {
		return evalBuiltin(d, scope, budget, ctx)
	}
	if ctx.DispatchExecute == nil {
		return nil, newComputeError(ErrInvalidExpression, "handler dispatch not available")
	}

	// F5 runtime: capability override requires resource — without it the
	// dual-check sees null on the resource dimension and the handler-grant
	// ceiling is bypassed at full resolution.
	if !d.Capability.IsZero() && d.Resource.IsZero() {
		return nil, newComputeError(ErrInvalidExpression,
			"compute/apply with capability field MUST also have resource field")
	}

	// SI-3 (v3.16 §2.1): resolve the target's declared input_type from the
	// handler interface entity in the tree. Empty → no-type-extension fallback
	// (§2.1) where every arg is inlined regardless of field type.
	paramsType := resolveHandlerInputType(d.Path, d.Operation, ctx)
	if paramsType == "" {
		paramsType = "primitive/any"
	}

	// SA-2 (v3.16 §2.1): when the input_type is resolvable, encode each arg
	// per the declared field type — system/hash fields receive the entity's
	// content hash; other fields receive the evaluated value inline. Without a
	// type extension (no field schema) we stay in the no-type-extension fallback.
	fieldTypes := resolveInputFieldTypes(paramsType, ctx)

	resolvedArgs := make(map[string]interface{})
	for _, entry := range canonicalSorted(d.Args) {
		target, err := resolveOrError(entry.Hash, ctx, "arg "+entry.Key)
		if err != nil {
			return nil, err
		}
		value, err := Evaluate(target, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
		// v3.19c Part A M3 boundary 4: apply-arg crosses compute→non-compute.
		// An in-flight *constructedValue becomes a bare entity.Entity per M1
		// before the V30 input_type-driven encoding picks hash-ref vs inline.
		value, err = materialize(value, ctx.ContentStore)
		if err != nil {
			return nil, err
		}
		encoded, err := encodeArgForField(entry.Key, value, fieldTypes, ctx)
		if err != nil {
			return nil, err
		}
		resolvedArgs[entry.Key] = encoded
	}

	raw, err := ecf.Encode(resolvedArgs)
	if err != nil {
		return nil, err
	}
	paramsEnt, err := entity.NewEntity(paramsType, raw)
	if err != nil {
		return nil, err
	}

	// Resolve and evaluate the resource expression if present (F2).
	// The expression must yield a system/protocol/resource-target struct.
	var resource *types.ResourceTarget
	if !d.Resource.IsZero() {
		resTarget, err := resolveOrError(d.Resource, ctx, "resource")
		if err != nil {
			return nil, err
		}
		resValue, err := Evaluate(resTarget, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
		resource, err = coerceResourceTarget(resValue)
		if err != nil {
			return nil, err
		}
	}

	// Dual-check (PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §3.2,
	// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F2).
	// When a capability override is present, both ctx.Capability (handler
	// grant ceiling) AND the provided capability must cover the target at
	// full resolution including resource. The evaluator is the only place
	// with both grants in hand.
	var override *entity.Entity
	if !d.Capability.IsZero() {
		capTarget, err := resolveOrError(d.Capability, ctx, "capability")
		if err != nil {
			return nil, err
		}
		capValue, err := Evaluate(capTarget, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
		capEnt, ok := capValue.(entity.Entity)
		if !ok {
			return nil, newComputeError(ErrTypeMismatch,
				fmt.Sprintf("compute/apply capability field must resolve to an entity, got %T", capValue))
		}
		if err := dualCheck(ctx, &capEnt, d.Path, d.Operation, resource); err != nil {
			return nil, err
		}
		override = &capEnt
	}

	resp, err := ctx.DispatchExecute(d.Path, d.Operation, resource, paramsEnt, override)
	if err != nil {
		return nil, err
	}
	if resp.Status >= 400 {
		if resp.Result.Type == types.TypeComputeError {
			errData, decErr := types.ComputeErrorDataFromEntity(resp.Result)
			if decErr == nil {
				return nil, &ComputeError{Code: errData.Code, Message: errData.Message, At: errData.At}
			}
		}
		return nil, newComputeError(ErrNotFound, fmt.Sprintf("handler dispatch failed: status %d", resp.Status))
	}
	// SA-4 (v3.16 §2.1): handler-mode compute/apply MUST wrap bare-primitive
	// returns in compute/result uniformly. Detect the entity-native /
	// compiled-handler primitive/any wrapper and rewrap; everything else
	// (compute/result already, or entity-typed) passes through unchanged.
	return wrapHandlerReturnSA4(resp.Result, applyHash)
}

// wrapHandlerReturnSA4 enforces §2.1 SA-4. primitive/any wrappings (the
// entity-native/compiled bare-primitive convention) are unwrapped and
// re-wrapped in compute/result so downstream consumers see one shape per
// dispatch target. Pre-wrapped compute/result and entity-typed results are
// returned as-is.
func wrapHandlerReturnSA4(result entity.Entity, applyHash hash.Hash) (interface{}, error) {
	if result.Type != "primitive/any" {
		return result, nil
	}
	var bare interface{}
	if err := ecf.Decode(result.Data, &bare); err != nil {
		return result, nil // can't unwrap — leave as-is rather than fail
	}
	d := types.ComputeResultData{Value: bare, Expression: applyHash}
	return d.ToEntity()
}

func evalApplyClosure(d types.ComputeApplyData, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	fnTarget, err := resolveOrError(d.Fn, ctx, "closure fn")
	if err != nil {
		return nil, err
	}

	// If the resolved entity is already a closure (value type), use it directly.
	// Otherwise evaluate it (e.g., a lambda expression produces a closure).
	var closureEnt entity.Entity
	if fnTarget.Type == types.TypeComputeClosure {
		closureEnt = fnTarget
	} else {
		fnValue, err := Evaluate(fnTarget, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
		var ok bool
		closureEnt, ok = fnValue.(entity.Entity)
		if !ok || closureEnt.Type != types.TypeComputeClosure {
			return nil, newComputeError(ErrTypeMismatch, "Apply target is not a closure")
		}
	}

	var closureData types.ComputeClosureData
	if err := ecf.Decode(closureEnt.Data, &closureData); err != nil {
		return nil, err
	}

	var envHash hash.Hash
	if closureData.Env != nil {
		envHash = *closureData.Env
	}
	newScope, err := LoadScope(envHash, ctx)
	if err != nil {
		return nil, err
	}

	for _, param := range closureData.Params {
		argHash, argOk := d.Args[param]
		if !argOk {
			return nil, newComputeError(ErrMissingArgument, "Missing argument: "+param)
		}
		argTarget, err := resolveOrError(argHash, ctx, "closure arg "+param)
		if err != nil {
			return nil, err
		}
		argVal, err := Evaluate(argTarget, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
		newScope.Set(param, argVal)
	}

	bodyTarget, err := resolveOrError(closureData.Body, ctx, "closure body")
	if err != nil {
		return nil, err
	}
	return tailCall{entity: bodyTarget, scope: newScope}, nil
}

// resolveInputFieldTypes loads the input_type's TypeDefinition from
// system/type/{typeName} and returns name → declared TypeRef. Empty result
// when no type definition exists (no-type-extension fallback). Used by
// SA-2 per-field arg encoding.
func resolveInputFieldTypes(typeName string, ctx *EvalContext) map[string]string {
	if typeName == "" || typeName == "primitive/any" {
		return nil
	}
	if ctx.LocationIndex == nil || ctx.ContentStore == nil {
		return nil
	}
	typePath := "system/type/" + typeName
	h, ok := ctx.LocationIndex.Get(typePath)
	if !ok {
		return nil
	}
	ent, ok := ctx.ContentStore.Get(h)
	if !ok || ent.Type != types.TypeType {
		return nil
	}
	var td types.TypeDefinition
	if err := ecf.Decode(ent.Data, &td); err != nil {
		return nil
	}
	if len(td.Fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(td.Fields))
	for name, spec := range td.Fields {
		out[name] = spec.TypeRef
	}
	return out
}

// encodeArgForField applies the SA-2 value-encoding table for a single arg.
// Field type system/hash → value must be entity (stored, hash returned);
// primitive value at a system/hash field → type_mismatch. Other field types
// (including primitive/any and unknown fields per open-type rule) inline
// the value. Without a field schema (fieldTypes nil — no-type-extension
// fallback) every arg is inlined.
func encodeArgForField(name string, value interface{}, fieldTypes map[string]string, ctx *EvalContext) (interface{}, error) {
	if fieldTypes == nil {
		return value, nil
	}
	fieldType, known := fieldTypes[name]
	if !known {
		// Open type — preserve per V7 §2.10.
		return value, nil
	}
	if fieldType != "system/hash" {
		return value, nil
	}
	// system/hash field: value must be an entity. Store and return its hash.
	ent, ok := value.(entity.Entity)
	if !ok {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("arg %q expects system/hash (entity), got %T", name, value))
	}
	if ctx.ContentStore != nil {
		if _, err := ctx.ContentStore.Put(ent); err != nil {
			return nil, newComputeError(ErrInvalidExpression,
				fmt.Sprintf("arg %q: store failed: %v", name, err))
		}
	}
	return ent.ContentHash, nil
}

// resolveHandlerInputType reads the handler interface at system/handler/{path}
// and returns the declared input_type for the operation. Returns "" if no
// interface is bound at that path or the operation isn't declared — callers
// default to primitive/any (the §2.1 no-type-extension fallback). SI-3 (v3.16).
func resolveHandlerInputType(path, operation string, ctx *EvalContext) string {
	if ctx.LocationIndex == nil || ctx.ContentStore == nil {
		return ""
	}
	ifacePath := "system/handler/" + path
	ifaceHash, ok := ctx.LocationIndex.Get(ifacePath)
	if !ok {
		return ""
	}
	ifaceEnt, ok := ctx.ContentStore.Get(ifaceHash)
	if !ok {
		return ""
	}
	ifaceData, err := types.HandlerInterfaceDataFromEntity(ifaceEnt)
	if err != nil {
		return ""
	}
	spec, ok := ifaceData.Operations[operation]
	if !ok {
		return ""
	}
	return spec.InputType
}

// dualCheck enforces the handler-grant ceiling on compute/apply with an explicit
// capability override (PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §3.2,
// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F2). Both the eval context's
// capability and the provided capability MUST cover the target at full
// resolution including resource; otherwise the override could be used to
// escape the handler's scope.
// Pre-checks are skipped when ctx.Capability is unset (test contexts).
func dualCheck(ctx *EvalContext, provided *entity.Entity, targetPath, targetOp string, resource *types.ResourceTarget) error {
	exec := types.ExecuteData{Operation: targetOp, Resource: resource}
	peerID := crypto.PeerID(ctx.LocalPeerID)

	if !ctx.Capability.ContentHash.IsZero() {
		ceilingData, err := types.CapabilityTokenDataFromEntity(ctx.Capability)
		if err != nil {
			return newComputeError(ErrPermissionDenied,
				"cannot decode evaluation capability: "+err.Error())
		}
		ceilingGranter, gerr := capability.ResolveGranterPeerID(ceilingData.Granter, ctx.ContentStore, peerID)
		if gerr != nil {
			return newComputeError(ErrPermissionDenied, "granter unresolvable: "+gerr.Error())
		}
		if !capability.CheckPermission(exec, ceilingData, targetPath, peerID, ceilingGranter) {
			return newComputeError(ErrPermissionDenied,
				"handler grant does not cover target: "+targetPath+":"+targetOp)
		}
	}

	if provided == nil || provided.ContentHash.IsZero() {
		return newComputeError(ErrPermissionDenied,
			"compute/apply capability field resolved to an empty capability")
	}
	providedData, err := types.CapabilityTokenDataFromEntity(*provided)
	if err != nil {
		return newComputeError(ErrPermissionDenied,
			"cannot decode provided capability: "+err.Error())
	}
	providedGranter, gerr := capability.ResolveGranterPeerID(providedData.Granter, ctx.ContentStore, peerID)
	if gerr != nil {
		return newComputeError(ErrPermissionDenied, "granter unresolvable: "+gerr.Error())
	}
	if !capability.CheckPermission(exec, providedData, targetPath, peerID, providedGranter) {
		return newComputeError(ErrPermissionDenied,
			"provided capability does not cover target: "+targetPath+":"+targetOp)
	}
	return nil
}
