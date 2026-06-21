package revision

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleMergeConfig implements EXTENSION-REVISION v3.3 §4.4.18 — the canonical
// write path for the handler-owned merge-config namespace
// (`system/revision/config/merge/{path,type}/{name}`). It enforces the §2.3
// strategy-rejection contract at config-write time (`lww` and `keep-both`
// rejected with 400 `invalid_strategy`) and a CAS guard via expected_hash.
//
// Path scheme follows §2.3, §3.1.1, §5.1, and Rust's reference implementation
// — global (not prefix-scoped); the merge cascade reads these configs
// independent of prefix per §5.1 line 2603. (§4.4.18's pseudocode-prefixing
// with prefix_hash is an internal spec inconsistency flagged separately in
// `docs/validation/spec-issues/REVISION-V3.3-MERGE-CONFIG-PATH-SCHEME.md`.)
func (h *Handler) handleMergeConfig(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	if len(req.Params.Data) == 0 {
		return handler.NewErrorResponse(400, "invalid_params", "merge-config params required")
	}
	params, err := types.RevisionMergeConfigParamsDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			fmt.Sprintf("failed to decode merge-config params: %v", err))
	}

	// Validate scope.
	var writePath string
	switch params.Scope {
	case "path":
		writePath = mergeConfigPathScope(params.Name)
	case "type":
		writePath = mergeConfigTypeScope(params.Name)
	default:
		return handler.NewErrorResponse(400, "invalid_scope",
			fmt.Sprintf("scope must be \"path\" or \"type\", got %q", params.Scope))
	}

	if params.Name == "" {
		return handler.NewErrorResponse(400, "invalid_params", "name is required")
	}

	// CAS guard.
	if params.ExpectedHash != nil {
		current, _ := hctx.LocationIndex.Get(writePath)
		if current != *params.ExpectedHash {
			return handler.NewErrorResponse(409, "stale_expected_hash",
				fmt.Sprintf("expected hash %s, actual %s", params.ExpectedHash.String(), current.String()))
		}
	}

	switch params.Action {
	case "delete":
		_, _, _ = hctx.TreeRemove(writePath, "merge-config")
		result := types.RevisionMergeConfigResultData{Path: writePath, Status: "deleted"}
		return makeMergeConfigResponse(result)

	case "set":
		if params.Config == nil {
			return handler.NewErrorResponse(400, "missing_config",
				"config field is required when action is \"set\"")
		}
		cfg := *params.Config

		// §2.3 strategy-rejection contract — lww / keep-both rejected at
		// config-write time. ValidateDeletionResolution returns an error
		// whose Error() string is "invalid_strategy: ..." for both
		// explicit rejections and unknown strings.
		if err := ValidateDeletionResolution(cfg.DeletionResolution); err != nil {
			return handler.NewErrorResponse(400, "invalid_strategy", err.Error())
		}

		// Idempotent: re-issuing identical content returns no_change.
		cfgEntity, err := cfg.ToEntity()
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error",
				"failed to build merge-config entity: "+err.Error())
		}
		newHash := cfgEntity.ContentHash
		current, _ := hctx.LocationIndex.Get(writePath)
		if current == newHash {
			result := types.RevisionMergeConfigResultData{Path: writePath, Hash: newHash, Status: "no_change"}
			return makeMergeConfigResponse(result)
		}

		if _, err := hctx.Store.Put(cfgEntity); err != nil {
			return handler.NewErrorResponse(500, "internal_error",
				"failed to store merge-config entity: "+err.Error())
		}
		if _, err := hctx.TreeSet(writePath, newHash, "merge-config"); err != nil {
			return handler.NewErrorResponse(500, "internal_error",
				"failed to bind merge-config: "+err.Error())
		}
		result := types.RevisionMergeConfigResultData{Path: writePath, Hash: newHash, Status: "set"}
		return makeMergeConfigResponse(result)

	default:
		return handler.NewErrorResponse(400, "invalid_action",
			fmt.Sprintf("action must be \"set\" or \"delete\", got %q", params.Action))
	}
}

// mergeConfigPathScope returns the canonical path for a per-path merge-config.
// Global namespace per §2.3 + §3.1.1 + §5.1 (merge configs are not
// prefix-scoped; the per-prefix prefix_hash in §4.4.18 pseudocode is a spec
// inconsistency tracked separately).
func mergeConfigPathScope(name string) string {
	return "system/revision/config/merge/path/" + name
}

// mergeConfigTypeScope returns the canonical path for a per-type merge-config.
func mergeConfigTypeScope(name string) string {
	return "system/revision/config/merge/type/" + name
}

// makeMergeConfigResponse wraps a result struct in the standard 200 response.
func makeMergeConfigResponse(result types.RevisionMergeConfigResultData) (*handler.Response, error) {
	resultEntity, err := result.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"failed to build merge-config result: "+err.Error())
	}
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

