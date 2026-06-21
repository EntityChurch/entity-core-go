package revision

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleFetch implements the fetch operation per EXTENSION-REVISION v2.1 §4.4.6.
// Returns version entries + root trie nodes.
func (h *Handler) handleFetch(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionFetchParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode fetch params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}
	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("fetch", params.Prefix); resp != nil {
		return resp, nil
	}

	head, ok := hctx.LocationIndex.Get(headPath(ph))
	if !ok {
		result := types.RevisionFetchResultData{}
		resultEntity, _ := result.ToEntity()
		env := entity.Envelope{Root: resultEntity}
		envEntity, _ := env.ToEntity()
		return &handler.Response{Status: 200, Result: envEntity}, nil
	}

	limit := 0
	if params.Depth != nil {
		limit = int(*params.Depth)
	}

	_, versionHashes := walkHistory(hctx.Store, head, limit, params.Since)

	included := make(map[hash.Hash]entity.Entity)
	for _, vh := range versionHashes {
		ent, ok := hctx.Store.Get(vh)
		if !ok {
			continue
		}
		included[vh] = ent

		// Include root trie node for each version.
		ver, err := types.RevisionEntryDataFromEntity(ent)
		if err != nil {
			continue
		}
		if trieEnt, ok := hctx.Store.Get(ver.Root); ok {
			included[ver.Root] = trieEnt
		}
	}

	hasMore := false
	if limit > 0 && len(versionHashes) >= limit {
		hasMore = true
	}

	result := types.RevisionFetchResultData{
		Head:     head,
		Versions: versionHashes,
		HasMore:  &hasMore,
	}
	resultEntity, _ := result.ToEntity()

	// Wrap in system/envelope: domain entities in inner envelope, protocol envelope stays clean.
	env := entity.Envelope{Root: resultEntity, Included: included}
	envEntity, err := env.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create envelope entity")
		return resp, nil
	}
	return &handler.Response{Status: 200, Result: envEntity}, nil
}

// handleFetchEntities implements fetch-entities per EXTENSION-REVISION v2.1 §4.4.7.
// Hash-validated incremental entity retrieval.
func (h *Handler) handleFetchEntities(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionFetchEntitiesParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode fetch-entities params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}
	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))

	if params.Snapshot.IsZero() {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "snapshot (trie root) is required")
		return resp, nil
	}

	if resp := hctx.CheckPathCapability("fetch-entities", params.Prefix); resp != nil {
		return resp, nil
	}

	// Validate: collect all hashes in the trie to verify requested hashes belong.
	validHashes := collectTrieHashes(hctx, params.Snapshot)

	var found []hash.Hash
	var missing []hash.Hash
	included := make(map[hash.Hash]entity.Entity)

	for _, reqHash := range params.Hashes {
		if !validHashes[reqHash] {
			// Not in trie — skip (security: don't proxy arbitrary content store access).
			missing = append(missing, reqHash)
			continue
		}
		ent, ok := hctx.Store.Get(reqHash)
		if ok {
			found = append(found, reqHash)
			included[reqHash] = ent
		} else {
			missing = append(missing, reqHash)
		}
	}

	result := types.RevisionFetchEntitiesResultData{
		Found:   found,
		Missing: missing,
	}
	resultEntity, _ := result.ToEntity()

	// Wrap in system/envelope: domain entities in inner envelope, protocol envelope stays clean.
	env := entity.Envelope{Root: resultEntity, Included: included}
	envEntity, err := env.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create envelope entity")
		return resp, nil
	}
	return &handler.Response{Status: 200, Result: envEntity}, nil
}

// collectTrieHashes collects all entity hashes referenced by a trie (nodes + bindings).
// Under v4.0 HAMT shape, bucket entries carry leaf value_hashes directly
// (no per-node Binding field) and link entries point at sub-nodes.
func collectTrieHashes(hctx *handler.HandlerContext, rootHash hash.Hash) map[hash.Hash]bool {
	valid := make(map[hash.Hash]bool)
	var walk func(h hash.Hash)
	walk = func(h hash.Hash) {
		if h.IsZero() || valid[h] {
			return
		}
		valid[h] = true
		node, ok := tree.LoadTrieNode(hctx.Store, h)
		if !ok {
			return
		}
		for _, entry := range node.Data {
			if entry.IsBucket() {
				for _, t := range entry.Bucket {
					valid[t.ValueHash] = true
				}
			} else {
				walk(*entry.Link)
			}
		}
	}
	walk(rootHash)
	return valid
}

// handlePush implements the push operation per EXTENSION-REVISION v2.1 §4.4.8.
func (h *Handler) handlePush(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionPushParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode push params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}
	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("push", params.Prefix); resp != nil {
		return resp, nil
	}

	// Get local head.
	localHead, hasLocalHead := hctx.LocationIndex.Get(headPath(ph))
	if !hasLocalHead {
		result := types.RevisionPushResultData{Status: "nothing_to_push"}
		resultEntity, _ := result.ToEntity()
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	// Get remote head for the specified remote.
	remoteHead, hasRemote := hctx.LocationIndex.Get(remotePath(ph, params.Remote))

	if hasRemote && localHead == remoteHead {
		result := types.RevisionPushResultData{Status: "up_to_date"}
		resultEntity, _ := result.ToEntity()
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	if hasRemote {
		rel := checkRelationship(hctx.Store, localHead, remoteHead)
		switch rel {
		case "behind":
			result := types.RevisionPushResultData{Status: "behind", Message: "local is behind remote; pull first"}
			resultEntity, _ := result.ToEntity()
			return &handler.Response{Status: 200, Result: resultEntity}, nil
		case "diverged":
			result := types.RevisionPushResultData{Status: "diverged", Message: "local and remote have diverged; merge first"}
			resultEntity, _ := result.ToEntity()
			return &handler.Response{Status: 200, Result: resultEntity}, nil
		}
	}

	// Count versions to push.
	_, versionHashes := walkHistory(hctx.Store, localHead, 0, remoteHead)
	vCount := uint64(len(versionHashes))

	// Update remote head pointer.
	if _, resp := bind(hctx, remotePath(ph, params.Remote), localHead, "push"); resp != nil {
		return resp, nil
	}

	result := types.RevisionPushResultData{
		Status:   "pushed",
		Versions: &vCount,
	}
	resultEntity, _ := result.ToEntity()
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}
