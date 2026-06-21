package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleCommit implements the commit operation per EXTENSION-REVISION v2.1 §4.4.1.
// Creates a structural version entry with trie root and sorted parents.
func (h *Handler) handleCommit(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionCommitParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode commit params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("commit", params.Prefix); resp != nil {
		return resp, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Load config for exclude filters.
	cfg, hasCfg := loadConfig(hctx, ph)
	var cfgPtr *types.RevisionConfigData
	if hasCfg {
		cfgPtr = &cfg
	}

	// Build trie from current tree state.
	trieRoot, err := computeTrieRoot(hctx, params.Prefix, cfgPtr)
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to build trie")
		return resp, nil
	}

	// Get current head (parent of new version).
	var parents []hash.Hash
	currentHead, hasHead := hctx.LocationIndex.Get(headPath(ph))
	if hasHead {
		parents = []hash.Hash{currentHead}

		// Dedup per EXTENSION-REVISION §6.2: if the current head already has
		// the same trie root, return it without creating a redundant entry.
		// Prevents trivial no-op commits, especially under auto-version ON.
		if currentVer, ok := loadVersion(hctx, currentHead); ok && currentVer.Root == trieRoot {
			result := types.RevisionCommitResultData{
				Version: currentHead,
				Root:    trieRoot,
			}
			resultEntity, err := result.ToEntity()
			if err != nil {
				resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create result entity")
				return resp, nil
			}
			return &handler.Response{Status: 200, Result: resultEntity}, nil
		}
	}

	// Create structural version entry: {root, parents}.
	version := types.RevisionEntryData{
		Root:    trieRoot,
		Parents: tree.SortedParents(parents),
	}

	versionEntity, err := version.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create version entity")
		return resp, nil
	}
	versionHash, err := hctx.Store.Put(versionEntity)
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to store version")
		return resp, nil
	}

	// Update head pointer.
	if _, resp := bind(hctx, headPath(ph), versionHash, "commit"); resp != nil {
		return resp, nil
	}

	// Advance active branch pointer if on a branch.
	activeBranch, onBranch := readStringEntity(hctx, activeBranchPath(ph))
	if onBranch && activeBranch != "" {
		if _, resp := bind(hctx, branchPath(ph, activeBranch), versionHash, "commit"); resp != nil {
			return resp, nil
		}
	}

	result := types.RevisionCommitResultData{
		Version: versionHash,
		Root:    trieRoot,
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
