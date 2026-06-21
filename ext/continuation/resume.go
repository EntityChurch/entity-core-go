package continuation

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)



// --- resume operation (spec §3.7) ---

// handleResume implements the resume operation.
func (h *Handler) handleResume(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	// Decode resume request params.
	var resumeReq types.ContinuationResumeRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &resumeReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode resume request")
		}
	}

	// Path comes from resource target.
	path := hctx.ExtractResourcePath()
	if path == "" {
		return handler.NewErrorResponse(400, "invalid_params", "resource target path is required")
	}

	// Read suspended entity.
	contentHash, ok := hctx.LocationIndex.Get(path)
	if !ok {
		return handler.NewErrorResponse(404, "not_found", "no entity at path: "+path)
	}
	suspendedEntity, ok := hctx.Store.Get(contentHash)
	if !ok {
		return handler.NewErrorResponse(404, "not_found", "entity not in store")
	}
	if suspendedEntity.Type != types.TypeContinuationSuspended {
		return handler.NewErrorResponse(400, "not_suspended",
			fmt.Sprintf("entity at path is %s, not %s", suspendedEntity.Type, types.TypeContinuationSuspended))
	}

	suspended, err := types.ContinuationSuspendedDataFromEntity(suspendedEntity)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "decode suspended: "+err.Error())
	}

	// Build params — merge resolution if provided.
	params := suspended.Params
	if len(resumeReq.Resolution) > 0 && len(params) > 0 {
		params, err = mergeResolution(params, resumeReq.Resolution)
		if err != nil {
			return handler.NewErrorResponse(400, "invalid_resolution", err.Error())
		}
	} else if len(resumeReq.Resolution) > 0 {
		params = resumeReq.Resolution
	}

	// Delete suspended entity.
	hctx.TreeRemove(path, "resume")
	hctx.Store.Remove(contentHash)

	// Dispatch.
	if hctx.Execute == nil {
		return handler.NewErrorResponse(500, "internal_error", "execute function not available")
	}

	paramsEntity, err := entity.NewEntity("primitive/any", params)
	if err != nil {
		return nil, fmt.Errorf("create params entity: %w", err)
	}

	var opts []handler.ExecuteOption
	if suspended.Resource != nil {
		opts = append(opts, handler.WithResource(suspended.Resource))
	}
	if resumeReq.Bounds != nil {
		opts = append(opts, handler.WithBounds(resumeReq.Bounds))
	}
	if resumeReq.DeliverTo != nil {
		opts = append(opts, handler.WithDeliverTo(resumeReq.DeliverTo))
	}

	return hctx.Execute(ctx, suspended.Target, suspended.Operation, paramsEntity, opts...)
}

// --- abandon operation (spec §3.7) ---

// handleAbandon implements the abandon operation.
func (h *Handler) handleAbandon(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	// Path comes from resource target.
	path := hctx.ExtractResourcePath()
	if path == "" {
		return handler.NewErrorResponse(400, "invalid_params", "resource target path is required")
	}

	// Read entity and verify it's a suspended continuation.
	contentHash, ok := hctx.LocationIndex.Get(path)
	if !ok {
		return handler.NewErrorResponse(404, "not_found", "no entity at path: "+path)
	}
	ent, ok := hctx.Store.Get(contentHash)
	if !ok {
		return handler.NewErrorResponse(404, "not_found", "entity not in store")
	}
	if ent.Type != types.TypeContinuationSuspended {
		return handler.NewErrorResponse(400, "not_suspended",
			fmt.Sprintf("entity at path is %s, not %s", ent.Type, types.TypeContinuationSuspended))
	}

	hctx.TreeRemove(path, "abandon")
	hctx.Store.Remove(contentHash)

	resultRaw, _ := ecf.Encode(map[string]interface{}{"abandoned": true, "path": path})
	resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}
