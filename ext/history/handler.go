package history

import (
	"context"
	"reflect"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

const handlerPattern = "system/history"

// Handler implements the system/history handler with query and rollback operations.
type Handler struct {
	cs       store.ContentStore
	recorder *Recorder
}

// NewHandler creates a history handler.
func NewHandler(cs store.ContentStore, recorder *Recorder) *Handler {
	return &Handler{cs: cs, recorder: recorder}
}

func (h *Handler) Name() string { return "history" }

// Manifest returns the handler's self-description.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "history",
		Operations: map[string]types.HandlerOperationSpec{
			"query":    {InputType: types.TypeHistoryQueryParams, OutputType: types.TypeHistoryQueryResult},
			"rollback": {InputType: types.TypeHistoryRollbackParams, OutputType: types.TypeHistoryRollbackResult},
		},
	}
}

// RegisterTypes registers history-specific types into the registry.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeHistoryTransition, reflect.TypeOf(types.TransitionData{}))
	r.ReflectType(types.TypeHistoryConfig, reflect.TypeOf(types.HistoryConfigData{}))
	r.ReflectType(types.TypeHistoryQueryParams, reflect.TypeOf(types.HistoryQueryParamsData{}))
	r.ReflectType(types.TypeHistoryQueryResult, reflect.TypeOf(types.HistoryQueryResultData{}))
	r.ReflectType(types.TypeHistoryRollbackParams, reflect.TypeOf(types.HistoryRollbackParamsData{}))
	r.ReflectType(types.TypeHistoryRollbackResult, reflect.TypeOf(types.HistoryRollbackResultData{}))
}

func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "query":
		return h.handleQuery(ctx, req)
	case "rollback":
		return h.handleRollback(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation", "history handler does not support operation: "+req.Operation)
	}
}

func (h *Handler) handleQuery(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	var params types.HistoryQueryParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode query params")
		}
	}

	// Canonicalize path.
	path := canonicalizePath(params.Path, hctx.LocalPeerID)

	// Dual capability check: history handler + target path read access.
	if err := checkHistoryAccess(hctx, "query", path); err != nil {
		return handler.NewErrorResponse(403, "access_denied", err.Error())
	}

	// Look up head pointer.
	headPath := headPointerPath(path)
	headHash, ok := hctx.LocationIndex.Get(headPath)
	if !ok {
		// No history for this path.
		result := types.HistoryQueryResultData{
			Path:        path,
			Transitions: []types.TransitionData{},
			HasMore:     false,
		}
		resultEnt, err := result.ToEntity()
		if err != nil {
			return nil, err
		}
		env := entity.Envelope{Root: resultEnt}
		envEntity, err := env.ToEntity()
		if err != nil {
			return nil, err
		}
		return &handler.Response{Status: 200, Result: envEntity}, nil
	}

	// Walk the chain collecting transitions.
	limit := uint64(50)
	if params.Limit != nil {
		limit = *params.Limit
	}

	var transitions []types.TransitionData
	var included map[hash.Hash]entity.Entity
	currentHash := headHash
	hasMore := false

	for !currentHash.IsZero() && uint64(len(transitions)) < limit {
		ent, ok := hctx.Store.Get(currentHash)
		if !ok {
			break
		}
		td, err := types.TransitionDataFromEntity(ent)
		if err != nil {
			break
		}

		// Check "since" filter: stop if we hit the marker.
		if !params.Since.IsZero() && currentHash == params.Since {
			break
		}

		// Check "before" filter: skip transitions at or after the timestamp.
		if params.Before != nil && td.Timestamp >= *params.Before {
			currentHash = td.Previous
			continue
		}

		// Check event type filter.
		if len(params.Events) > 0 && !containsString(params.Events, td.Event) {
			currentHash = td.Previous
			continue
		}

		transitions = append(transitions, td)

		// Include the transition entity in the response envelope.
		if included == nil {
			included = make(map[hash.Hash]entity.Entity)
		}
		included[currentHash] = ent

		currentHash = td.Previous
	}

	if !currentHash.IsZero() {
		hasMore = true
	}

	result := types.HistoryQueryResultData{
		Path:        path,
		Head:        headHash,
		Transitions: transitions,
		HasMore:     hasMore,
	}
	if result.Transitions == nil {
		result.Transitions = []types.TransitionData{}
	}

	resultEnt, err := result.ToEntity()
	if err != nil {
		return nil, err
	}

	// Wrap in system/envelope: domain entities in inner envelope, protocol envelope stays clean.
	env := entity.Envelope{Root: resultEnt, Included: included}
	envEntity, err := env.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: envEntity}, nil
}

func (h *Handler) handleRollback(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	var params types.HistoryRollbackParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode rollback params")
		}
	}

	// Canonicalize path.
	path := canonicalizePath(params.Path, hctx.LocalPeerID)

	// Dual capability check: history handler + target path write access.
	if err := checkHistoryAccess(hctx, "rollback", path); err != nil {
		return handler.NewErrorResponse(403, "access_denied", err.Error())
	}

	// Verify target_hash appears in this path's history.
	if !IsInHistory(hctx.Store, hctx.LocationIndex, path, params.TargetHash) {
		return handler.NewErrorResponse(404, "not_in_history", "target hash not found in history for this path")
	}

	// Verify the target entity still exists in the content store.
	if !hctx.Store.Has(params.TargetHash) {
		return handler.NewErrorResponse(404, "entity_not_found", "target entity no longer in content store")
	}

	// Restore by rebinding the path. This goes through normal Set which
	// triggers a new history transition via the recorder's sync hook.
	if _, err := hctx.TreeSet(path, params.TargetHash, "rollback"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "rollback bind: "+err.Error())
	}

	result := types.HistoryRollbackResultData{
		Path:     path,
		Restored: params.TargetHash,
	}
	return resultResponse(result)
}

// canonicalizePath converts a short-form path to absolute form.
func canonicalizePath(path string, localPeerID interface{ String() string }) string {
	p := path
	if len(p) > 0 && p[0] != '/' {
		p = "/" + localPeerID.String() + "/" + p
	}
	return p
}

// checkHistoryAccess performs the dual capability check per §4.2.
func checkHistoryAccess(hctx *handler.HandlerContext, operation, targetPath string) error {
	// Level 1 is already checked by the dispatcher (handler scope).
	// Level 2: check target path access.
	if hctx.CallerCapability.ContentHash.IsZero() {
		return nil // no capability to check (internal dispatch)
	}
	capData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
	if err != nil {
		return nil // can't decode capability — skip path check
	}

	targetOp := "get" // query requires read access
	if operation == "rollback" {
		targetOp = "put" // rollback requires write access
	}

	granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
	if gerr != nil {
		return &accessDeniedError{operation: operation, path: targetPath}
	}
	if !capability.CheckPathPermission(targetOp, targetPath, capData, "system/tree", hctx.LocalPeerID, granterPeerID) {
		return &accessDeniedError{operation: operation, path: targetPath}
	}
	return nil
}

type accessDeniedError struct {
	operation string
	path      string
}

func (e *accessDeniedError) Error() string {
	return "insufficient capability for " + e.operation + " on path: " + e.path
}

func resultResponse(data interface{ ToEntity() (entity.Entity, error) }) (*handler.Response, error) {
	ent, err := data.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: ent}, nil
}
