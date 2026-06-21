package revision

import (
	"context"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleConfig validates and writes a revision config entity plus its
// corresponding tracking-config entity. Supports "set" and "delete" actions.
// Per PROPOSAL-REVISION-CONFIG-OPERATION §3.1 (R1).
func (h *Handler) handleConfig(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionConfigParamsData
	if len(req.Params.Data) > 0 {
		var err error
		params, err = types.RevisionConfigParamsDataFromEntity(req.Params)
		if err != nil {
			return handler.NewErrorResponse(400, "config/invalid-params",
				fmt.Sprintf("failed to decode config params: %v", err))
		}
	}

	if params.Name == "" {
		return handler.NewErrorResponse(400, "config/missing-name", "params must specify a config name")
	}

	switch params.Action {
	case "set":
		return h.handleConfigSet(hctx, params)
	case "delete":
		return h.handleConfigDelete(hctx, params)
	default:
		return handler.NewErrorResponse(400, "config/invalid-action",
			fmt.Sprintf("action must be \"set\" or \"delete\", got %q", params.Action))
	}
}

func (h *Handler) handleConfigSet(hctx *handler.HandlerContext, params types.RevisionConfigParamsData) (*handler.Response, error) {
	if params.Config == nil {
		return handler.NewErrorResponse(400, "config/missing-config",
			"config field is required when action is \"set\"")
	}
	cfg := *params.Config

	// V1: prefix must not be empty.
	if cfg.Prefix == "" {
		return handler.NewErrorResponse(400, "config/invalid-prefix", "config prefix must not be empty")
	}

	// R2: resolve prefix to absolute, compute hash for storage path.
	cfg.Prefix = resolvePrefix(cfg.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(cfg.Prefix)
	configPathStr := configPath(ph)

	// V2: auto_version exclude enforcement (§2.4 + §6.1).
	if cfg.AutoVersion != nil && *cfg.AutoVersion {
		if missing := missingRequiredExcludes(cfg); len(missing) > 0 {
			return handler.NewErrorResponse(400, "config/missing-required-exclude",
				fmt.Sprintf("auto_version: true requires exclude patterns: %s", strings.Join(missing, ", ")))
		}
	}

	// V3: trie root exclude when prefix encompasses system/tree/root/.
	if cfg.AutoVersion != nil && *cfg.AutoVersion {
		if prefixEncompasses(cfg.Prefix, "system/tree/root/") {
			if !excludeCovers(cfg.Exclude, "system/tree/root/**") {
				return handler.NewErrorResponse(400, "config/missing-trie-root-exclude",
					fmt.Sprintf("auto_version with prefix %q requires system/tree/root/** in exclude", cfg.Prefix))
			}
		}
	}

	// V4: merge_order validation.
	if cfg.MergeOrder != "" {
		if cfg.MergeOrder != "deterministic" && cfg.MergeOrder != "caller-perspective" {
			return handler.NewErrorResponse(400, "config/invalid-merge-order",
				fmt.Sprintf("merge_order must be \"deterministic\" or \"caller-perspective\", got %q", cfg.MergeOrder))
		}
	}

	// V5: oscillation_depth minimum.
	if cfg.OscillationDepth != nil && *cfg.OscillationDepth < 2 {
		return handler.NewErrorResponse(400, "config/oscillation-depth-below-minimum",
			fmt.Sprintf("oscillation_depth must be >= 2, got %d", *cfg.OscillationDepth))
	}

	// CAS guard.
	if params.ExpectedHash != nil {
		currentHash, _ := hctx.LocationIndex.Get(configPathStr)
		if currentHash != *params.ExpectedHash {
			return handler.NewErrorResponse(409, "config/concurrent-modification",
				fmt.Sprintf("expected hash %s, actual %s", params.ExpectedHash.String(), currentHash.String()))
		}
	}

	// Read previous state for tracking-config coordination.
	previousHash, hadPrevious := hctx.LocationIndex.Get(configPathStr)
	wasAutoVersion := false
	if hadPrevious {
		if prevEnt, ok := hctx.Store.Get(previousHash); ok {
			if prevCfg, err := types.RevisionConfigDataFromEntity(prevEnt); err == nil {
				wasAutoVersion = prevCfg.AutoVersion != nil && *prevCfg.AutoVersion
			}
		}
	}

	enablingAutoVersion := cfg.AutoVersion != nil && *cfg.AutoVersion && !wasAutoVersion
	disablingAutoVersion := !(cfg.AutoVersion != nil && *cfg.AutoVersion) && wasAutoVersion

	trackingPathStr := "system/tree/tracking-config/" + trackingConfigKey(cfg.Prefix)
	trackingAction := ""

	// Enable auto-version: write tracking-config FIRST (§6.1 ordering).
	if enablingAutoVersion {
		tcAction, errResp := h.writeTrackingConfig(hctx, trackingPathStr, cfg.Prefix, true)
		if errResp != nil {
			return errResp, nil
		}
		trackingAction = tcAction
	}

	// Write the revision config.
	configEnt, err := cfg.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "config/config-write-failed",
			fmt.Sprintf("failed to encode config entity: %v", err))
	}
	configHash, err := hctx.Store.Put(configEnt)
	if err != nil {
		return handler.NewErrorResponse(500, "config/config-write-failed",
			fmt.Sprintf("failed to store config entity: %v", err))
	}
	cr, err := hctx.TreeSet(configPathStr, configHash, "config")
	if err != nil {
		return handler.NewErrorResponse(500, "config/config-write-failed",
			fmt.Sprintf("bind config: %v", err))
	}
	if cr != nil && !cr.BindingCommitted {
		return handler.NewErrorResponse(500, "config/config-write-failed", "tree.put refused (cascade depth)")
	}

	// Disable auto-version: remove tracking-config AFTER config write (§6.1 ordering).
	if disablingAutoVersion {
		hctx.TreeRemove(trackingPathStr, "config")
		trackingAction = "deleted"
	}

	result := types.RevisionConfigResultData{
		ConfigPath:           configPathStr,
		ConfigHash:           configHash,
		PreviousHash:         previousHash,
		TrackingConfigPath:   trackingPathStr,
		TrackingConfigAction: trackingAction,
	}
	if trackingAction == "" {
		result.TrackingConfigPath = ""
	}
	resultEnt, err := result.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: resultEnt}, nil
}

func (h *Handler) handleConfigDelete(hctx *handler.HandlerContext, params types.RevisionConfigParamsData) (*handler.Response, error) {
	// Under v3.0, we need the prefix to compute the hash for the storage path.
	// The config operation uses Name as the external key. To find the config,
	// we check if Name looks like a prefix (resolve + hash) or if it's a
	// legacy name. For v3.0, Name IS the prefix.
	resolvedName := resolvePrefix(params.Name, string(hctx.LocalPeerID))
	ph := PrefixHash(resolvedName)
	configPathStr := configPath(ph)

	// CAS guard.
	if params.ExpectedHash != nil {
		currentHash, _ := hctx.LocationIndex.Get(configPathStr)
		if currentHash != *params.ExpectedHash {
			return handler.NewErrorResponse(409, "config/concurrent-modification",
				fmt.Sprintf("expected hash %s, actual %s", params.ExpectedHash.String(), currentHash.String()))
		}
	}

	previousHash, hadPrevious := hctx.LocationIndex.Get(configPathStr)
	if !hadPrevious {
		return handler.NewErrorResponse(404, "config/not-found",
			fmt.Sprintf("no config at name %q", params.Name))
	}

	// Read previous config to determine tracking-config cleanup.
	var prevCfg types.RevisionConfigData
	wasAutoVersion := false
	if prevEnt, ok := hctx.Store.Get(previousHash); ok {
		if cfg, err := types.RevisionConfigDataFromEntity(prevEnt); err == nil {
			prevCfg = cfg
			wasAutoVersion = cfg.AutoVersion != nil && *cfg.AutoVersion
		}
	}

	trackingAction := ""
	trackingPathStr := ""

	// Delete config binding first, then tracking-config if needed.
	hctx.TreeRemove(configPathStr, "config")

	if wasAutoVersion {
		trackingPathStr = "system/tree/tracking-config/" + trackingConfigKey(prevCfg.Prefix)
		hctx.TreeRemove(trackingPathStr, "config")
		trackingAction = "deleted"
	}

	result := types.RevisionConfigResultData{
		ConfigPath:           configPathStr,
		PreviousHash:         previousHash,
		TrackingConfigPath:   trackingPathStr,
		TrackingConfigAction: trackingAction,
	}
	resultEnt, err := result.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: resultEnt}, nil
}

// writeTrackingConfig writes or updates a tracking-config entity. Returns
// the action string ("created" or "updated") on success, or an error response.
func (h *Handler) writeTrackingConfig(hctx *handler.HandlerContext, trackingPath, prefix string, enabled bool) (string, *handler.Response) {
	_, existed := hctx.LocationIndex.Get(trackingPath)

	trackingCfg := types.TrackingConfigData{
		Prefix:  prefix,
		Enabled: enabled,
	}
	trackingEnt, err := trackingCfg.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "config/tracking-config-write-failed",
			fmt.Sprintf("failed to encode tracking-config: %v", err))
		return "", resp
	}
	trackingHash, err := hctx.Store.Put(trackingEnt)
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "config/tracking-config-write-failed",
			fmt.Sprintf("failed to store tracking-config: %v", err))
		return "", resp
	}

	cr, err := hctx.TreeSet(trackingPath, trackingHash, "config")
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "config/tracking-config-write-failed",
			fmt.Sprintf("bind tracking-config: %v", err))
		return "", resp
	}
	if cr != nil && !cr.BindingCommitted {
		resp, _ := handler.NewErrorResponse(500, "config/tracking-config-write-failed",
			"tree.put refused (cascade depth)")
		return "", resp
	}

	if existed {
		return "updated", nil
	}
	return "created", nil
}

// prefixEncompasses returns true if prefix is a parent of the target path.
func prefixEncompasses(prefix, target string) bool {
	p := strings.TrimSuffix(strings.TrimPrefix(prefix, "/"), "/")
	if p == "" {
		return true
	}
	return strings.HasPrefix(target, p+"/") || target == p+"/"
}

// excludeCovers returns true if any pattern in the exclude list covers the target.
func excludeCovers(excludes []string, target string) bool {
	for _, e := range excludes {
		if e == "system/**" || e == target {
			return true
		}
	}
	return false
}
