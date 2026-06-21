package revision

import (
	"context"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleStatus implements the status operation per EXTENSION-REVISION v2.1 §4.4.3.
func (h *Handler) handleStatus(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	var params types.RevisionStatusParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode status params")
			return resp, nil
		}
	}

	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}

	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))
	ph := PrefixHash(params.Prefix)

	if resp := hctx.CheckPathCapability("status", params.Prefix); resp != nil {
		return resp, nil
	}

	headVal, _ := hctx.LocationIndex.Get(headPath(ph))

	// Read remotes.
	remotes := make(map[string]hash.Hash)
	remotePrefix := "system/revision/" + ph + "/remotes/"
	remoteEntries := hctx.LocationIndex.List(remotePrefix)
	for _, entry := range remoteEntries {
		rest := trimPrefix(entry.Path, remotePrefix, hctx.LocalPeerID)
		if rest == "" {
			continue
		}
		remotes[rest] = entry.Hash
	}

	// Count conflicts.
	var conflicts uint64
	conflictEntries := hctx.LocationIndex.List(conflictListPrefix(ph))
	conflicts = uint64(len(conflictEntries))

	// Pending changes: compare current trie root against head's root.
	var pending uint64
	if !headVal.IsZero() {
		ver, ok := loadVersion(hctx, headVal)
		if ok {
			currentRoot, err := computeTrieRoot(hctx, params.Prefix, nil)
			if err == nil && currentRoot != ver.Root {
				// Count actual path differences by collecting bindings.
				headBindings := trieToBindings(hctx.Store, ver.Root)
				currentBindings := computeBindingsMap(hctx, params.Prefix)
				pending = countDifferences(headBindings, currentBindings)
			}
		}
	}

	// Collect keep-both paths per R4 status surfacing.
	var keepBothPaths []string
	currentBindings := computeBindingsMap(hctx, params.Prefix)
	for path := range currentBindings {
		if strings.Contains(path, ".keep-both-") {
			keepBothPaths = append(keepBothPaths, path)
		}
	}

	status := types.RevisionStatusData{
		Prefix:        params.Prefix,
		Head:          headVal,
		Remotes:       remotes,
		Conflicts:     conflicts,
		Pending:       pending,
		KeepBothPaths: keepBothPaths,
	}

	resultEntity, err := status.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to create status entity")
		return resp, nil
	}

	return &handler.Response{
		Status: 200,
		Result: resultEntity,
	}, nil
}

// countDifferences counts the number of differences between two binding maps.
func countDifferences(a, b map[string]hash.Hash) uint64 {
	var count uint64
	for path, hashA := range a {
		hashB, ok := b[path]
		if !ok || hashA != hashB {
			count++
		}
	}
	for path := range b {
		if _, ok := a[path]; !ok {
			count++
		}
	}
	return count
}
