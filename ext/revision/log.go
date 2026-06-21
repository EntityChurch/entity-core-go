package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleLog implements the log operation per EXTENSION-REVISION v2.1 §4.4.2.
func (h *Handler) handleLog(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionLogParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode log params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("log", params.Prefix); resp != nil {
		return resp, nil
	}

	limit := 50
	if params.Limit != nil {
		limit = int(*params.Limit)
	}

	head, ok := hctx.LocationIndex.Get(headPath(ph))
	if !ok {
		result := types.RevisionLogResultData{
			Prefix:   params.Prefix,
			Versions: []hash.Hash{},
			HasMore:  false,
		}
		resultEntity, err := result.ToEntity()
		if err != nil {
			resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create result entity")
			return resp, nil
		}
		env := entity.Envelope{Root: resultEntity}
		envEntity, err := env.ToEntity()
		if err != nil {
			resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create envelope entity")
			return resp, nil
		}
		return &handler.Response{Status: 200, Result: envEntity}, nil
	}

	_, versionHashes := walkHistory(hctx.Store, head, limit+1, params.Since)

	hasMore := len(versionHashes) > limit
	if hasMore {
		versionHashes = versionHashes[:limit]
	}

	included := make(map[hash.Hash]entity.Entity)
	for _, vh := range versionHashes {
		ent, ok := hctx.Store.Get(vh)
		if ok {
			included[vh] = ent
		}
	}

	result := types.RevisionLogResultData{
		Prefix:   params.Prefix,
		Versions: versionHashes,
		HasMore:  hasMore,
	}
	resultEntity, err := result.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create result entity")
		return resp, nil
	}

	// Wrap in system/envelope: domain entities in inner envelope, protocol envelope stays clean.
	env := entity.Envelope{Root: resultEntity, Included: included}
	envEntity, err := env.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create envelope entity")
		return resp, nil
	}
	return &handler.Response{Status: 200, Result: envEntity}, nil
}
