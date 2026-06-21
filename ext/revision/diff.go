package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleDiff implements the diff operation per EXTENSION-REVISION v2.1 §4.4.5.
// Computes the diff between two versions using their trie roots.
func (h *Handler) handleDiff(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionDiffParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode diff params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}
	if params.Base.IsZero() || params.Target.IsZero() {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "base and target are required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	_ = PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("diff", params.Prefix); resp != nil {
		return resp, nil
	}

	// Load both versions.
	verA, ok := loadVersion(hctx, params.Base)
	if !ok {
		resp, _ := handler.NewErrorResponse(404, "not_found", "base version not found")
		return resp, nil
	}
	verB, ok := loadVersion(hctx, params.Target)
	if !ok {
		resp, _ := handler.NewErrorResponse(404, "not_found", "target version not found")
		return resp, nil
	}

	// Recursive trie diff — skips unchanged subtrees via hash comparison.
	added, removed, changed, unchanged := tree.TrieDiff(hctx.Store, verA.Root, verB.Root)

	diff := types.DiffData{
		Base:      verA.Root,
		Target:    verB.Root,
		Added:     added,
		Removed:   removed,
		Changed:   changed,
		Unchanged: unchanged,
	}

	resultEntity, err := diff.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create diff entity")
		return resp, nil
	}

	return &handler.Response{
		Status: 200,
		Result: resultEntity,
	}, nil
}
