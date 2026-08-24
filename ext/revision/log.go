package revision

import (
	"context"

	"github.com/fxamacker/cbor/v2"

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
		// `since` is REFUSED on log (SA-PY-7, arch ROUTING-2026-08-18-g §3): log
		// takes an inclusive `start_at` cursor, not fetch's exclusive `since`
		// watermark. No installed base, so a stray `since` is a client error, not
		// a field to silently ignore into the wrong semantics.
		var raw map[string]cbor.RawMessage
		if err := ecf.Decode(req.Params.Data, &raw); err == nil {
			if _, hasSince := raw["since"]; hasSince {
				resp, _ := handler.NewErrorResponse(400, "invalid_params",
					"log does not accept 'since'; use 'start_at' (an inclusive anchor that walks toward older versions)")
				return resp, nil
			}
		}
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

	// start_at is an inclusive anchor: begin the walk AT it (not at head) and
	// move toward older ancestors. Absent → walk from head, the default.
	walkRoot := head
	if !params.StartAt.IsZero() {
		walkRoot = params.StartAt
	}
	_, versionHashes := walkHistory(hctx.Store, walkRoot, limit+1, hash.Hash{})

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
