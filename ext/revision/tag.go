package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleTag implements the tag operation per EXTENSION-REVISION v2.1.
func (h *Handler) handleTag(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionTagParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode tag params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("tag", params.Prefix); resp != nil {
		return resp, nil
	}

	switch params.Action {
	case "create":
		return h.tagCreate(hctx, params, ph)
	case "list":
		return h.tagList(hctx, params, ph)
	case "delete":
		return h.tagDelete(hctx, params, ph)
	default:
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "tag action must be create, list, or delete")
		return resp, nil
	}
}

func (h *Handler) tagCreate(hctx *handler.HandlerContext, params types.RevisionTagParamsData, ph string) (*handler.Response, error) {
	if params.Name == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "tag name is required for create")
		return resp, nil
	}

	tp := tagPath(ph, params.Name)
	if _, exists := hctx.LocationIndex.Get(tp); exists {
		resp, _ := handler.NewErrorResponse(409, "already_exists", "tag already exists: "+params.Name)
		return resp, nil
	}

	var targetVersion hash.Hash
	if !params.Version.IsZero() {
		if !hctx.Store.Has(params.Version) {
			resp, _ := handler.NewErrorResponse(404, "not_found", "version not found")
			return resp, nil
		}
		targetVersion = params.Version
	} else {
		head, ok := hctx.LocationIndex.Get(headPath(ph))
		if !ok {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "no head version exists; specify 'version'")
			return resp, nil
		}
		targetVersion = head
	}

	if _, resp := bind(hctx, tp, targetVersion, "tag"); resp != nil {
		return resp, nil
	}

	result := types.RevisionTagResultData{
		Status:  "created",
		Tag:     params.Name,
		Version: targetVersion,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

func (h *Handler) tagList(hctx *handler.HandlerContext, params types.RevisionTagParamsData, ph string) (*handler.Response, error) {
	tags := make(map[string]hash.Hash)
	tagPrefix := tagListPrefix(ph)
	entries := hctx.LocationIndex.List(tagPrefix)
	for _, entry := range entries {
		name := trimPrefix(entry.Path, tagPrefix, hctx.LocalPeerID)
		if name != "" {
			tags[name] = entry.Hash
		}
	}

	result := types.RevisionTagResultData{
		Status: "listed",
		Tags:   tags,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

func (h *Handler) tagDelete(hctx *handler.HandlerContext, params types.RevisionTagParamsData, ph string) (*handler.Response, error) {
	if params.Name == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "tag name is required for delete")
		return resp, nil
	}

	tp := tagPath(ph, params.Name)
	if _, exists := hctx.LocationIndex.Get(tp); !exists {
		resp, _ := handler.NewErrorResponse(404, "not_found", "tag not found: "+params.Name)
		return resp, nil
	}

	hctx.TreeRemove(tp, "delete-tag")

	result := types.RevisionTagResultData{
		Status: "deleted",
		Tag:    params.Name,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}
