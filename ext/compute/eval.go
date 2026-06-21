package compute

import (
	"fmt"
	"sort"
	"strings"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// tailCall is the trampoline continuation for tail call optimization (v3.8 T2).
// Returned by evaluateInner from tail positions; never escapes Evaluate().
type tailCall struct {
	entity entity.Entity
	scope  *Scope
}

// EvalContext provides the environment for expression evaluation.
//
// Capability fields per PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §6.1:
//   - Capability:       authorization ceiling for impure ops (handler grant for
//     entity-native dispatch; installation grant for reactive;
//     caller's cap for explicit eval)
//   - CallerCapability: chain initiator, propagated to sub-dispatches for
//     history attribution; absent for autonomous (reactive) eval
//   - Author:           identity that initiated the chain
type EvalContext struct {
	ContentStore          store.ContentStore
	LocationIndex         store.LocationIndex
	LocalPeerID           string
	Capability            entity.Entity
	CallerCapability      entity.Entity
	Author                crypto.PeerID
	Included              map[hash.Hash]entity.Entity
	RegisterDep           func(path string)
	DispatchExecute       func(path, op string, resource *types.ResourceTarget, params entity.Entity, override *entity.Entity) (*handler.Response, error)
	HasContentStoreAccess bool
	AuthorizedDataHashes  map[hash.Hash]bool // D5: sealed set from installed subgraph
	SubgraphRoot          string             // v3.8 R2: root path for relative path resolution
}

// Evaluate evaluates a compute expression entity with scope, budget, and context.
// Uses a trampoline loop for tail call optimization (v3.8 T2): tail positions
// in evaluateInner return tailCall continuations instead of recursing, so
// tail-recursive iteration uses O(1) depth and O(n) budget.
func Evaluate(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	if budget.Depth <= 0 {
		return nil, newComputeError(ErrDepthExceeded, "Maximum evaluation depth exceeded")
	}
	budget.Depth--

	for {
		budget.Operations--
		if budget.Operations <= 0 {
			budget.Depth++
			return nil, newComputeError(ErrBudgetExhausted, "Computation budget exhausted")
		}

		result, err := evaluateInner(ent, scope, budget, ctx)
		if err != nil {
			budget.Depth++
			return nil, err
		}
		if tc, ok := result.(tailCall); ok {
			ent = tc.entity
			scope = tc.scope
			continue
		}

		budget.Depth++
		return result, nil
	}
}

func evaluateInner(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	switch ent.Type {
	case types.TypeComputeLiteral:
		return evalLiteral(ent)

	case types.TypeComputeLookupScope:
		return evalLookupScope(ent, scope)

	case types.TypeComputeLookupTree:
		return evalLookupTree(ent, scope, budget, ctx)

	case types.TypeComputeLookupHash:
		return evalLookupHash(ent, scope, budget, ctx)

	case types.TypeComputeApply:
		return evalApply(ent, scope, budget, ctx)

	case types.TypeComputeIf:
		return evalIf(ent, scope, budget, ctx)

	case types.TypeComputeLet:
		return evalLet(ent, scope, budget, ctx)

	case types.TypeComputeLambda:
		return evalLambda(ent, scope, ctx)

	case types.TypeComputeArithmetic:
		return evalArithmetic(ent, scope, budget, ctx)

	case types.TypeComputeCompare:
		return evalCompare(ent, scope, budget, ctx)

	case types.TypeComputeLogic:
		return evalLogic(ent, scope, budget, ctx)

	case types.TypeComputeField:
		return evalField(ent, scope, budget, ctx)

	case types.TypeComputeConstruct:
		return evalConstruct(ent, scope, budget, ctx)

	case types.TypeComputeIndex:
		return evalIndex(ent, scope, budget, ctx)

	case types.TypeComputeLength:
		return evalLength(ent, scope, budget, ctx)

	case types.TypeComputeNumericCast:
		return evalNumericCast(ent, scope, budget, ctx)

	// SA-1 (v3.16 §2.3): Evaluating a value-type entity returns it as-is —
	// generalizes the compute/lookup/hash "return non-expressions as values"
	// rule (§4.1). Lets pre-computed values be threaded directly as args.
	case types.TypeComputeClosure, types.TypeComputeScope,
		types.TypeComputeResult, types.TypeComputeError:
		return ent, nil

	default:
		return nil, newComputeError(ErrUnknownType, "Unknown compute type: "+ent.Type)
	}
}

func evalLiteral(ent entity.Entity) (interface{}, error) {
	var d types.ComputeLiteralData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}
	return d.Value, nil
}

func evalLookupScope(ent entity.Entity, scope *Scope) (interface{}, error) {
	var d types.ComputeLookupScopeData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}
	if scope.Has(d.Name) {
		return scope.Get(d.Name), nil
	}
	return nil, newComputeError(ErrNotFound, "No scope binding: "+d.Name)
}

func evalLookupTree(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeLookupTreeData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}
	path := d.Path
	if d.Relative && ctx.SubgraphRoot != "" {
		path = store.CleanPath(ctx.SubgraphRoot + "/" + path)
	} else if !strings.HasPrefix(path, "/") && ctx.LocalPeerID != "" {
		// EXTENSION-COMPUTE v3.20 / V7 §5.4: bare path with relative absent/false
		// resolves to /{local_peer_id}/path. Without this, dep-tracking keys on
		// the verbatim bare string while tree writes notify on the canonical
		// absolute path → reactive subgraph silently never recomputes.
		path = store.QualifyPath(ctx.LocalPeerID, path)
	}
	// PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §7.2: ctx.Capability is the
	// ceiling for tree reads. Skip the check only when no capability is bound
	// (test contexts and legacy callers); production entry paths always set it.
	if !ctx.Capability.ContentHash.IsZero() {
		capData, err := types.CapabilityTokenDataFromEntity(ctx.Capability)
		if err != nil {
			return nil, newComputeError(ErrPermissionDenied,
				"cannot decode evaluation capability: "+err.Error())
		}
		granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, ctx.ContentStore, crypto.PeerID(ctx.LocalPeerID))
		if gerr != nil {
			return nil, newComputeError(ErrPermissionDenied, "granter unresolvable: "+gerr.Error())
		}
		if !capability.CheckPathPermission("get", path, capData, "system/tree", crypto.PeerID(ctx.LocalPeerID), granterPeerID) {
			return nil, newComputeError(ErrPermissionDenied,
				"capability does not cover tree read: "+path)
		}
	}
	if ctx.RegisterDep != nil {
		ctx.RegisterDep(path)
	}
	if ctx.LocationIndex == nil {
		return nil, newComputeError(ErrNotFound, "No entity at path: "+path)
	}
	h, ok := ctx.LocationIndex.Get(path)
	if !ok {
		return nil, newComputeError(ErrNotFound, "No entity at path: "+path)
	}
	treeEnt, ok := ctx.ContentStore.Get(h)
	if !ok {
		return nil, newComputeError(ErrNotFound, "No entity at path: "+path)
	}
	if IsComputeExpression(treeEnt) {
		return tailCall{entity: treeEnt, scope: scope}, nil
	}
	return treeEnt, nil
}

func evalLookupHash(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeLookupHashData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}
	// Per spec §4.3: resolve through validate_compute_resolvable.
	// Installed subgraphs: Tier 2 sealed set authorizes non-compute targets.
	// Explicit eval: needs reverse index or content_store_access for non-compute targets.
	target, err := resolveOrError(d.Hash, ctx, "hash lookup")
	if err != nil {
		return nil, err
	}
	if IsComputeExpression(target) {
		return tailCall{entity: target, scope: scope}, nil
	}
	return target, nil
}

func evalIf(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeIfData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	condTarget, err := resolveOrError(d.Condition, ctx, "if condition")
	if err != nil {
		return nil, err
	}
	condition, err := Evaluate(condTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	if truthy(condition) {
		thenTarget, err := resolveOrError(d.Then, ctx, "if then")
		if err != nil {
			return nil, err
		}
		return tailCall{entity: thenTarget, scope: scope}, nil
	}
	if d.Else != nil {
		elseTarget, err := resolveOrError(*d.Else, ctx, "if else")
		if err != nil {
			return nil, err
		}
		return tailCall{entity: elseTarget, scope: scope}, nil
	}
	return nil, nil
}

func evalLet(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeLetData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	newScope := scope.Copy()
	for _, binding := range d.Bindings {
		valueTarget, err := resolveOrError(binding.Value, ctx, "let binding "+binding.Name)
		if err != nil {
			return nil, err
		}
		value, err := Evaluate(valueTarget, newScope, budget, ctx)
		if err != nil {
			return nil, err
		}
		newScope.Set(binding.Name, value)
	}

	bodyTarget, err := resolveOrError(d.Body, ctx, "let body")
	if err != nil {
		return nil, err
	}
	return tailCall{entity: bodyTarget, scope: newScope}, nil
}

func evalLambda(ent entity.Entity, scope *Scope, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeLambdaData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	envEnt, err := CaptureScope(scope, ctx.ContentStore)
	if err != nil {
		return nil, err
	}

	closureData := types.ComputeClosureData{
		Params: d.Params,
		Body:   d.Body,
	}
	if !envEnt.ContentHash.IsZero() {
		closureData.Env = &envEnt.ContentHash
	}
	return closureData.ToEntity()
}


// --- Resolution ---

// resolve resolves a hash to an entity through the layered access model (§4.2)
// with expression-graph scoping (v3.6 D2).
func resolve(h hash.Hash, ctx *EvalContext) (entity.Entity, bool) {
	// Tier 1: envelope included map.
	if ctx.Included != nil {
		if ent, ok := ctx.Included[h]; ok {
			return validateComputeResolvable(ent, h, ctx)
		}
	}
	// Tier 2/3: content store (tree-scoped or direct depending on access model).
	if ctx.ContentStore != nil {
		if ent, ok := ctx.ContentStore.Get(h); ok {
			return validateComputeResolvable(ent, h, ctx)
		}
	}
	return entity.Entity{}, false
}

// validateComputeResolvable checks that a resolved entity is part of the
// compute expression subgraph (v3.6 D2). Non-compute entities are rejected
// to prevent the evaluator from being used as a content store oracle.
func validateComputeResolvable(ent entity.Entity, h hash.Hash, ctx *EvalContext) (entity.Entity, bool) {
	if ctx.HasContentStoreAccess {
		return ent, true
	}
	if isComputeType(ent) {
		return ent, true
	}
	// Tier 2: sealed set from installed subgraph (D5).
	if ctx.AuthorizedDataHashes != nil && ctx.AuthorizedDataHashes[h] {
		return ent, true
	}
	return entity.Entity{}, false
}

// isComputeType returns true if the entity is a compute expression, value,
// result, error, or metadata type (v3.6 D2 §4.2).
func isComputeType(ent entity.Entity) bool {
	switch ent.Type {
	case types.TypeComputeLiteral,
		types.TypeComputeLookupScope, types.TypeComputeLookupTree, types.TypeComputeLookupHash,
		types.TypeComputeApply, types.TypeComputeIf, types.TypeComputeLet, types.TypeComputeLambda,
		types.TypeComputeArithmetic, types.TypeComputeCompare, types.TypeComputeLogic,
		types.TypeComputeField, types.TypeComputeConstruct,
		types.TypeComputeIndex, types.TypeComputeLength, types.TypeComputeNumericCast,
		types.TypeComputeClosure, types.TypeComputeScope,
		types.TypeComputeResult, types.TypeComputeError,
		types.TypeComputeSubgraph,
		types.TypeComputeInstallRequest, types.TypeComputeInstallResult:
		return true
	}
	return false
}

func resolveOrError(h hash.Hash, ctx *EvalContext, label string) (entity.Entity, error) {
	ent, ok := resolve(h, ctx)
	if !ok {
		return entity.Entity{}, newComputeError(ErrNotFound,
			fmt.Sprintf("Cannot resolve hash for %s: %s", label, h))
	}
	return ent, nil
}

// --- Expression detection (§4.7) ---

// IsComputeExpression returns true if the entity is a compute expression type.
func IsComputeExpression(ent entity.Entity) bool {
	switch ent.Type {
	case types.TypeComputeLiteral,
		types.TypeComputeLookupScope, types.TypeComputeLookupTree, types.TypeComputeLookupHash,
		types.TypeComputeApply,
		types.TypeComputeIf, types.TypeComputeLet, types.TypeComputeLambda,
		types.TypeComputeArithmetic, types.TypeComputeCompare, types.TypeComputeLogic,
		types.TypeComputeField, types.TypeComputeConstruct,
		types.TypeComputeIndex, types.TypeComputeLength, types.TypeComputeNumericCast:
		return true
	}
	return false
}

// coerceResourceTarget converts an evaluated resource expression value into
// a *types.ResourceTarget. The expression must yield either a resource-target
// struct (typed or as a CBOR-decoded map) or a system/protocol/resource-target
// entity. Returns invalid_expression error if the value can't be coerced.
func coerceResourceTarget(value interface{}) (*types.ResourceTarget, error) {
	switch v := value.(type) {
	case nil:
		return nil, newComputeError(ErrInvalidExpression,
			"compute/apply resource field resolved to nil")
	case *types.ResourceTarget:
		return v, nil
	case types.ResourceTarget:
		return &v, nil
	case entity.Entity:
		if v.Type != types.TypeResourceTarget {
			return nil, newComputeError(ErrTypeMismatch,
				"compute/apply resource entity must be system/protocol/resource-target, got "+v.Type)
		}
		var rt types.ResourceTarget
		if err := ecf.Decode(v.Data, &rt); err != nil {
			return nil, newComputeError(ErrInvalidExpression,
				"cannot decode resource-target entity: "+err.Error())
		}
		return &rt, nil
	}
	// Generic CBOR-decoded map shape.
	raw, err := ecf.Encode(value)
	if err != nil {
		return nil, newComputeError(ErrInvalidExpression,
			"compute/apply resource field has unsupported value type")
	}
	var rt types.ResourceTarget
	if err := ecf.Decode(raw, &rt); err != nil {
		return nil, newComputeError(ErrInvalidExpression,
			"compute/apply resource field must yield a resource-target struct: "+err.Error())
	}
	if len(rt.Targets) == 0 {
		return nil, newComputeError(ErrInvalidExpression,
			"compute/apply resource-target must have at least one target")
	}
	return &rt, nil
}

// --- Truthiness (§4.5) ---

func truthy(value interface{}) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case int64:
		return v != 0
	case uint64:
		return v != 0
	case float64:
		return v != 0
	case string:
		return v != ""
	case []interface{}:
		return len(v) > 0
	}
	return true
}


// --- Canonical map ordering (§8.2) ---

type mapEntry struct {
	Key  string
	Hash hash.Hash
}

// canonicalSorted returns map entries in ECF canonical map key order:
// sort by encoded byte length, then lexicographically.
func canonicalSorted(m map[string]hash.Hash) []mapEntry {
	entries := make([]mapEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, mapEntry{Key: k, Hash: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		li, lj := len(entries[i].Key), len(entries[j].Key)
		if li != lj {
			return li < lj
		}
		return entries[i].Key < entries[j].Key
	})
	return entries
}
