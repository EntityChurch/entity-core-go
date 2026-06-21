package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleFindAncestor implements the find-ancestor operation per EXTENSION-REVISION v2.1.
func (h *Handler) handleFindAncestor(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionAncestorParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode ancestor params")
			return resp, nil
		}
	}

	if params.VersionA.IsZero() || params.VersionB.IsZero() {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "version_a and version_b are required")
		return resp, nil
	}

	ancestor, found := findCommonAncestor(hctx.Store, params.VersionA, params.VersionB)

	result := types.RevisionAncestorResultData{}
	if found {
		result.Ancestor = ancestor
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
