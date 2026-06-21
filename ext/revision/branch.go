package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleBranch implements the branch operation per EXTENSION-REVISION v2.1.
func (h *Handler) handleBranch(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionBranchParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode branch params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("branch", params.Prefix); resp != nil {
		return resp, nil
	}

	switch params.Action {
	case "create":
		return h.branchCreate(hctx, params, ph)
	case "list":
		return h.branchList(hctx, params, ph)
	case "delete":
		return h.branchDelete(hctx, params, ph)
	default:
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "branch action must be create, list, or delete")
		return resp, nil
	}
}

func (h *Handler) branchCreate(hctx *handler.HandlerContext, params types.RevisionBranchParamsData, ph string) (*handler.Response, error) {
	if params.Name == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "branch name is required for create")
		return resp, nil
	}

	bp := branchPath(ph, params.Name)
	if _, exists := hctx.LocationIndex.Get(bp); exists {
		resp, _ := handler.NewErrorResponse(409, "already_exists", "branch already exists: "+params.Name)
		return resp, nil
	}

	var targetVersion hash.Hash
	if !params.From.IsZero() {
		if !hctx.Store.Has(params.From) {
			resp, _ := handler.NewErrorResponse(404, "not_found", "source version not found")
			return resp, nil
		}
		targetVersion = params.From
	} else {
		head, ok := hctx.LocationIndex.Get(headPath(ph))
		if !ok {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "no head version exists; specify 'from' version")
			return resp, nil
		}
		targetVersion = head
	}

	if _, resp := bind(hctx, bp, targetVersion, "branch"); resp != nil {
		return resp, nil
	}

	result := types.RevisionBranchResultData{
		Status:  "created",
		Branch:  params.Name,
		Version: targetVersion,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

func (h *Handler) branchList(hctx *handler.HandlerContext, params types.RevisionBranchParamsData, ph string) (*handler.Response, error) {
	branches := make(map[string]hash.Hash)
	branchPrefix := branchListPrefix(ph)
	entries := hctx.LocationIndex.List(branchPrefix)
	for _, entry := range entries {
		name := trimPrefix(entry.Path, branchPrefix, hctx.LocalPeerID)
		if name != "" {
			branches[name] = entry.Hash
		}
	}

	active, _ := readStringEntity(hctx, activeBranchPath(ph))

	result := types.RevisionBranchResultData{
		Status:   "listed",
		Branches: branches,
		Active:   active,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

func (h *Handler) branchDelete(hctx *handler.HandlerContext, params types.RevisionBranchParamsData, ph string) (*handler.Response, error) {
	if params.Name == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "branch name is required for delete")
		return resp, nil
	}

	bp := branchPath(ph, params.Name)
	if _, exists := hctx.LocationIndex.Get(bp); !exists {
		resp, _ := handler.NewErrorResponse(404, "not_found", "branch not found: "+params.Name)
		return resp, nil
	}

	active, onBranch := readStringEntity(hctx, activeBranchPath(ph))
	if onBranch && active == params.Name {
		resp, _ := handler.NewErrorResponse(409, "active_branch", "cannot delete active branch: "+params.Name)
		return resp, nil
	}

	hctx.TreeRemove(bp, "delete-branch")

	result := types.RevisionBranchResultData{
		Status: "deleted",
		Branch: params.Name,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}
