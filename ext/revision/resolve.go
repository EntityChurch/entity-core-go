package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleResolve implements the resolve operation per EXTENSION-REVISION v2.1.
func (h *Handler) handleResolve(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionResolveParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode resolve params")
			return resp, nil
		}
	}

	if params.Prefix == "" || params.Path == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix and path are required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("resolve", params.Prefix); resp != nil {
		return resp, nil
	}

	cPath := conflictPath(ph, params.Path)
	conflictHash, exists := hctx.LocationIndex.Get(cPath)
	if !exists {
		resp, _ := handler.NewErrorResponse(404, "not_found", "no conflict at path: "+params.Path)
		return resp, nil
	}

	if params.Resolved != nil {
		if !hctx.Store.Has(*params.Resolved) {
			resp, _ := handler.NewErrorResponse(404, "resolved_not_found", "resolved entity hash not found in content store")
			return resp, nil
		}
		if _, resp := bind(hctx, params.Prefix+params.Path, *params.Resolved, "resolve"); resp != nil {
			return resp, nil
		}
	} else {
		hctx.TreeRemove(params.Prefix+params.Path, "resolve")
	}

	hctx.TreeRemove(cPath, "resolve")
	hctx.Store.Remove(conflictHash)

	remaining := uint64(hctx.LocationIndex.LenPrefix(conflictListPrefix(ph)))

	result := types.RevisionResolveResultData{
		Path:               params.Path,
		Resolved:           params.Resolved,
		RemainingConflicts: remaining,
	}
	resultEntity, err := result.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create result entity")
		return resp, nil
	}

	return &handler.Response{
		Status: 200,
		Result: resultEntity,
	}, nil
}
