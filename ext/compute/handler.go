package compute

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Handler implements the system/compute handler with eval, install, and uninstall operations.
type Handler struct {
	engine *Engine
}

// NewHandler creates a compute handler backed by the given engine.
func NewHandler(engine *Engine) *Handler {
	return &Handler{engine: engine}
}

func (h *Handler) Name() string { return "compute" }

func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: "system/compute",
		Name:    "compute",
		Operations: map[string]types.HandlerOperationSpec{
			"eval":      {InputType: "primitive/any", OutputType: "primitive/any"},
			"install":   {InputType: types.TypeComputeInstallRequest, OutputType: types.TypeComputeInstallResult},
			"uninstall": {InputType: "primitive/any", OutputType: "system/protocol/status"},
		},
	}
}

func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	// Compute types are registered in RegisterCoreTypes — re-running ReflectType
	// here would clobber the path-typed field overrides applied there.
}

func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "eval":
		return h.handleEval(ctx, req)
	case "install":
		return h.handleInstall(ctx, req)
	case "uninstall":
		return h.handleUninstall(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"Unknown compute operation: "+req.Operation)
	}
}

func (h *Handler) handleEval(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	// V7 §3.2 path-as-resource: the expression path comes from
	// EXECUTE.resource.targets[0]. Single-target, URI-only.
	if hctx.Resource == nil || len(hctx.Resource.Targets) != 1 {
		return handler.NewErrorResponse(400, "ambiguous_resource",
			"eval requires exactly one resource target (the expression path)")
	}
	exprPath := hctx.Resource.Targets[0]
	if !looksLikeExpressionPath(exprPath, hctx) {
		return handler.NewErrorResponse(400, "ambiguous_resource",
			"eval resource must target an expression path, not the handler pattern")
	}

	// Resolve the expression entity from the tree.
	exprHash, ok := hctx.LocationIndex.Get(exprPath)
	if !ok {
		return handler.NewErrorResponse(404, ErrNotFound, "No entity at path: "+exprPath)
	}
	expression, ok := hctx.Store.Get(exprHash)
	if !ok {
		return handler.NewErrorResponse(404, ErrNotFound, "No entity at path: "+exprPath)
	}

	if !IsComputeExpression(expression) {
		return handler.NewErrorResponse(400, ErrInvalidExpression,
			"Entity at path is not a compute expression: "+expression.Type)
	}

	budget := initBudget(hctx, req.Params)
	evalCtx := h.makeEvalContext(hctx, nil)
	evalCtx.SubgraphRoot = exprPath
	scope := NewScope()

	result, err := Evaluate(expression, scope, budget, evalCtx)
	if err != nil {
		if ce, ok := err.(*ComputeError); ok {
			errEnt, entErr := ce.ToEntity()
			if entErr != nil {
				return handler.NewErrorResponse(500, "internal", "Failed to create error entity")
			}
			// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE F10: an evaluated
			// compute/error is a value (§1.5 error-as-value), surfaced at 200
			// with the entity as the result. 4xx is reserved for dispatch
			// failures — handler-not-found, pre-eval auth, malformed request.
			return &handler.Response{Status: 200, Result: errEnt}, nil
		}
		return handler.NewErrorResponse(500, "internal", err.Error())
	}

	// (B) v3.23: a compute/error arriving as the top-level VALUE (a root literal,
	// or a lookup resolving to a stored error) surfaces via the SAME F10 error-
	// as-value path — status 200, message intact — not materialize(), which post-
	// v3.23 rejects errors outright.
	if ce, isErr := computeErrorFromValue(result); isErr {
		errEnt, entErr := ce.ToEntity()
		if entErr != nil {
			return handler.NewErrorResponse(500, "internal", "Failed to create error entity")
		}
		return &handler.Response{Status: 200, Result: errEnt}, nil
	}

	// v3.19c Part A M3 boundary 1: materialize before crossing the compute→
	// non-compute boundary. An in-flight *constructedValue becomes a bare
	// entity.Entity per M1 / V7 §1.4 (byte-identical to a hand-built one).
	result, err = materialize(result, hctx.Store)
	if err != nil {
		return handler.NewErrorResponse(500, "internal", "Failed to materialize result: "+err.Error())
	}

	resultEnt, err := wrapResult(result, expression.ContentHash)
	if err != nil {
		return handler.NewErrorResponse(500, "internal", "Failed to wrap result: "+err.Error())
	}

	return &handler.Response{Status: 200, Result: resultEnt}, nil
}

func (h *Handler) handleInstall(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	if h.engine == nil {
		return handler.NewErrorResponse(501, "not_implemented", "Reactive mode not available")
	}
	return h.engine.HandleInstall(ctx, req)
}

func (h *Handler) handleUninstall(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	if h.engine == nil {
		return handler.NewErrorResponse(501, "not_implemented", "Reactive mode not available")
	}
	return h.engine.HandleUninstall(ctx, req)
}

// makeEvalContext builds an EvalContext from a HandlerContext.
// For explicit eval, ctx.Capability and ctx.CallerCapability are the same
// thing — the external caller's grant authorizes the eval and is the chain
// initiator (PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §6.1).
func (h *Handler) makeEvalContext(hctx *handler.HandlerContext, registerDep func(string)) *EvalContext {
	return &EvalContext{
		ContentStore:     hctx.Store,
		LocationIndex:    hctx.LocationIndex,
		LocalPeerID:      string(hctx.LocalPeerID),
		Capability:       hctx.CallerCapability,
		CallerCapability: hctx.CallerCapability,
		Author:           hctx.Author,
		Included:         hctx.Included,
		RegisterDep:      registerDep,
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, params entity.Entity, override *entity.Entity) (*handler.Response, error) {
			cap := hctx.CallerCapability
			if override != nil {
				cap = *override
			}
			// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F4: dispatched EXECUTE
			// carries the apply's resource. When the apply has no resource
			// field, we still pass an explicit empty ResourceTarget so the
			// dispatcher does NOT inherit the parent execute's resource —
			// inheritance would point back at the compute expression itself
			// and cause runaway recursion.
			dispatchResource := resource
			if dispatchResource == nil {
				dispatchResource = &types.ResourceTarget{}
			}
			return hctx.Execute(context.Background(), path, op, params,
				handler.WithCapability(cap),
				handler.WithResource(dispatchResource),
			)
		},
	}
}

// initBudget creates a budget per EXTENSION-COMPUTE §5.2:
//
//	request_budget = params.budget or infinity
//	bounds_budget  = bounds.budget or peer_default_max_ops
//	operations     = min(request_budget, bounds_budget, compute_ops_limit)
//	depth          = compute_depth_limit
//
// The request budget is a voluntary self-restriction — a caller asking to be cut
// off early. It can only lower the ceiling (it enters a min), never raise it, so
// honoring it cannot widen what a capability authorizes. Absent or unreadable, it
// is infinity and contributes nothing.
func initBudget(hctx *handler.HandlerContext, params entity.Entity) *Budget {
	ops := DefaultMaxOps
	depth := DefaultMaxDepth

	if hctx.Bounds != nil && hctx.Bounds.Budget != nil && *hctx.Bounds.Budget < uint64(ops) {
		ops = int(*hctx.Bounds.Budget)
	}

	if reqOps, ok := requestBudget(params); ok && reqOps < ops {
		ops = reqOps
	}

	// Compute-specific limits come from the capability's grant-level constraints
	// (ENTITY-CORE-PROTOCOL §5; EXTENSION-COMPUTE §5.2). The matching grant is the
	// authorization-correct source — its constraints are what permitted THIS
	// request. Fall back to scanning the token's grants when the matching grant is
	// unavailable (an in-process dispatch may not populate MatchingGrant).
	var capOps, capDepth int
	if hctx.MatchingGrant != nil {
		capOps, capDepth = computeConstraintsOfGrant(hctx.MatchingGrant)
	} else if !hctx.CallerCapability.ContentHash.IsZero() {
		capOps, capDepth = computeConstraintsOfToken(hctx.CallerCapability)
	}
	if capOps > 0 && capOps < ops {
		ops = capOps
	}
	if capDepth > 0 && capDepth < depth {
		depth = capDepth
	}

	return NewBudget(ops, depth)
}

// requestBudget reads the optional `budget` knob out of an eval request's params
// (§3.2: "params optionally carries operation knobs (budget)").
//
// Params is declared primitive/any, so the body is an open map with no schema to
// decode against — every failure mode here (empty params, a non-map body, a
// missing or non-numeric `budget`) means "the caller did not ask for a limit"
// and returns false, never an error. A malformed knob must not fail the eval:
// the spec's default is infinity, and rejecting the request would turn an
// optional field into a required one.
func requestBudget(params entity.Entity) (int, bool) {
	if len(params.Data) == 0 {
		return 0, false
	}
	var m map[string]interface{}
	if err := ecf.Decode(params.Data, &m); err != nil {
		return 0, false
	}
	v, ok := m["budget"]
	if !ok {
		return 0, false
	}
	n := toIntValue(v)
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// computeLimitsFrom reads max_compute_operations / max_compute_depth out of a
// decoded constraints map's "system/compute" key. Returns (0,0) when absent.
func computeLimitsFrom(constraints map[string]interface{}) (ops, depth int) {
	computeMap := toStringMap(constraints["system/compute"])
	if computeMap == nil {
		return 0, 0
	}
	if v, ok := computeMap["max_compute_operations"]; ok {
		ops = toIntValue(v)
	}
	if v, ok := computeMap["max_compute_depth"]; ok {
		depth = toIntValue(v)
	}
	return
}

// computeConstraintsOfGrant reads the compute resource limits from ONE grant
// entry's `constraints` field.
//
// Per ENTITY-CORE-PROTOCOL §5, `constraints` is a GRANT-level, handler-
// interpreted narrowing field — it lives at grants[].constraints, NOT at the
// token level (CapabilityTokenData has no `constraints` field at all).
// EXTENSION-COMPUTE §5.2 says the limits are "carried on capability tokens via
// the existing `constraints` field (ENTITY-CORE-PROTOCOL §5)", so its pseudocode
// shorthand `capability.data.constraints["system/compute"]` denotes this grant-
// level field, not a literal top-level read. The prior implementation read the
// token's top-level `constraints`, which no conformant capability ever carries,
// so a compute depth/ops constraint reached the evaluator NOWHERE over the wire
// (spec-issue 2026-08-22-a).
func computeConstraintsOfGrant(g *types.GrantEntry) (ops, depth int) {
	if g == nil || len(g.Constraints) == 0 {
		return 0, 0
	}
	var constraints map[string]interface{}
	if err := ecf.Decode(g.Constraints, &constraints); err != nil {
		return 0, 0
	}
	return computeLimitsFrom(constraints)
}

// computeConstraintsOfToken finds the tightest compute limits across every grant
// entry of a capability TOKEN. Used where the specific matching grant is not
// available (the handler-grant ceiling and the reactive §7.4 path, which stores
// only the installing token). Taking the min of positive values is safe because
// a constraint can only narrow (§5.6), so the tightest any grant imposes is a
// valid ceiling.
func computeConstraintsOfToken(tokenEnt entity.Entity) (ops, depth int) {
	td, err := types.CapabilityTokenDataFromEntity(tokenEnt)
	if err != nil {
		return 0, 0
	}
	for i := range td.Grants {
		gOps, gDepth := computeConstraintsOfGrant(&td.Grants[i])
		if gOps > 0 && (ops == 0 || gOps < ops) {
			ops = gOps
		}
		if gDepth > 0 && (depth == 0 || gDepth < depth) {
			depth = gDepth
		}
	}
	return
}

func toStringMap(v interface{}) map[string]interface{} {
	switch m := v.(type) {
	case map[string]interface{}:
		return m
	case map[interface{}]interface{}:
		result := make(map[string]interface{}, len(m))
		for k, val := range m {
			if ks, ok := k.(string); ok {
				result[ks] = val
			}
		}
		return result
	}
	return nil
}

func toIntValue(v interface{}) int {
	switch n := v.(type) {
	case uint64:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// looksLikeExpressionPath returns false when the resource target points to the
// handler manifest rather than an actual expression (e.g. "system/compute").
func looksLikeExpressionPath(path string, hctx *handler.HandlerContext) bool {
	if path == hctx.HandlerPattern || path == "/"+string(hctx.LocalPeerID)+"/"+hctx.HandlerPattern {
		return false
	}
	return true
}

// EvaluateAtPath evaluates a compute expression at the given tree path.
// Called by the dispatch layer for entity-native handlers (V7 §3.7, §6.6).
// Receives the same Request that a compiled handler would get — extracts
// HandlerGrant, CallerCapability, operation, params from the HandlerContext.
func (h *Handler) EvaluateAtPath(ctx context.Context, exprPath string, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	// PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §7.1: handler grant must be
	// present. The dispatcher pre-validates the grant (signature + granter
	// chain) before invoking us, so a populated HandlerGrant here is already
	// known to be issued by local peer authority. We only re-check the zero
	// case as defense-in-depth — should not be reachable in normal flow.
	grant := hctx.HandlerGrant
	if grant.ContentHash.IsZero() {
		return handler.NewErrorResponse(403, ErrPermissionDenied,
			"entity-native handler has no validated grant (dispatcher pre-check should have rejected)")
	}

	exprHash, ok := hctx.LocationIndex.Get(exprPath)
	if !ok {
		return handler.NewErrorResponse(404, ErrNotFound, "No entity at expression path: "+exprPath)
	}
	expression, ok := hctx.Store.Get(exprHash)
	if !ok {
		return handler.NewErrorResponse(404, ErrNotFound, "No entity at expression path: "+exprPath)
	}
	if !IsComputeExpression(expression) {
		return handler.NewErrorResponse(400, ErrInvalidExpression,
			"Entity at expression path is not a compute expression: "+expression.Type)
	}

	// Handler grant is the ceiling for internal operations. Caller capability
	// is bound separately for voluntary restriction (§3.2) and history
	// attribution (§3.3).
	budget := DefaultBudget()
	capOps, capDepth := computeConstraintsOfToken(grant)
	if capOps > 0 && capOps < budget.Operations {
		budget.Operations = capOps
	}
	if capDepth > 0 && capDepth < budget.Depth {
		budget.Depth = capDepth
	}

	evalCtx := &EvalContext{
		ContentStore:     hctx.Store,
		LocationIndex:    hctx.LocationIndex,
		LocalPeerID:      string(hctx.LocalPeerID),
		Capability:       grant,
		CallerCapability: hctx.CallerCapability,
		Author:           hctx.Author,
		Included:         hctx.Included,
		SubgraphRoot:     exprPath,
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, params entity.Entity, override *entity.Entity) (*handler.Response, error) {
			cap := grant
			if override != nil {
				cap = *override
			}
			// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F4: dispatched EXECUTE
			// carries the apply's resource. When the apply has no resource
			// field, we still pass an explicit empty ResourceTarget so the
			// dispatcher does NOT inherit the parent execute's resource —
			// inheritance would point back at the compute expression itself
			// and cause runaway recursion.
			dispatchResource := resource
			if dispatchResource == nil {
				dispatchResource = &types.ResourceTarget{}
			}
			return hctx.Execute(context.Background(), path, op, params,
				handler.WithCapability(cap),
				handler.WithResource(dispatchResource),
			)
		},
	}

	scope := NewScope()
	scope.Set("operation", req.Operation)
	scope.Set("params", req.Params)
	scope.Set("resource", hctx.Resource)
	scope.Set("caller_capability", hctx.CallerCapability)

	result, err := Evaluate(expression, scope, budget, evalCtx)
	if err != nil {
		if ce, ok := err.(*ComputeError); ok {
			errEnt, entErr := ce.ToEntity()
			if entErr != nil {
				return handler.NewErrorResponse(500, "internal", "Failed to create error entity")
			}
			// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE F10: evaluated
			// compute/error → 200 with the entity as the result (error-as-value
			// composition; the outer Apply must see a value, not a transport
			// failure, to propagate NaN-style).
			return &handler.Response{Status: 200, Result: errEnt}, nil
		}
		return handler.NewErrorResponse(500, "internal", err.Error())
	}

	// (B) v3.23: same as boundary 1 — a top-level compute/error VALUE surfaces via
	// the F10 error-as-value path, not materialize().
	if ce, isErr := computeErrorFromValue(result); isErr {
		errEnt, entErr := ce.ToEntity()
		if entErr != nil {
			return handler.NewErrorResponse(500, "internal", "Failed to create error entity")
		}
		return &handler.Response{Status: 200, Result: errEnt}, nil
	}

	// v3.19c Part A M3 boundary 2: materialize before crossing back to the
	// non-compute caller. *constructedValue → bare entity.Entity per M1.
	result, err = materialize(result, hctx.Store)
	if err != nil {
		return handler.NewErrorResponse(500, "internal", "Failed to materialize result: "+err.Error())
	}

	// E3: entity-native dispatch returns unwrapped results. The caller
	// sent EXECUTE to a handler, not to system/compute — they expect
	// the raw result entity, not a compute/result wrapper. Bare primitives
	// are wrapped at the dispatch boundary using the operation's declared
	// output_type, falling back to primitive/any.
	outputType := lookupOperationOutputType(hctx, req.Operation)
	resultEnt, err := unwrapEntityNativeResult(result, outputType)
	if err != nil {
		return handler.NewErrorResponse(500, "internal", "Failed to create result: "+err.Error())
	}
	return &handler.Response{Status: 200, Result: resultEnt}, nil
}

// lookupOperationOutputType reads the handler's interface entity from the tree
// and returns the declared output_type for the given operation. Returns ""
// when the interface or operation entry is missing — callers default to
// primitive/any in that case.
func lookupOperationOutputType(hctx *handler.HandlerContext, operation string) string {
	// HandlerPattern is the bare pattern (e.g., "app/foo"); the interface
	// entity for it lives at "system/handler/{pattern}".
	ifacePath := "system/handler/" + hctx.HandlerPattern
	ifaceHash, ok := hctx.LocationIndex.Get(ifacePath)
	if !ok {
		return ""
	}
	ifaceEnt, ok := hctx.Store.Get(ifaceHash)
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
	return spec.OutputType
}

// unwrapEntityNativeResult converts an evaluation result into the wire-level
// entity carried back to the caller (PROPOSAL §4 / E3). Entities pass through
// unchanged. Bare primitives are wrapped at the dispatch boundary: the entity
// type is the operation's declared output_type, defaulting to primitive/any
// when no output_type was declared. The data field is the encoded primitive
// itself (no field nesting) — same shape primitive/* entities use.
func unwrapEntityNativeResult(result interface{}, outputType string) (entity.Entity, error) {
	if ent, ok := result.(entity.Entity); ok {
		return ent, nil
	}
	raw, err := ecf.Encode(result)
	if err != nil {
		return entity.Entity{}, err
	}
	wrapType := outputType
	if wrapType == "" {
		wrapType = "primitive/any"
	}
	return entity.NewEntity(wrapType, raw)
}

// wrapResult converts an evaluation result to an entity suitable for response.
func wrapResult(result interface{}, expressionHash hash.Hash) (entity.Entity, error) {
	if ent, ok := result.(entity.Entity); ok {
		return ent, nil
	}
	d := types.ComputeResultData{
		Value:      result,
		Expression: expressionHash,
	}
	return d.ToEntity()
}
