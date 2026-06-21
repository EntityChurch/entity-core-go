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

// handleFetchDiff is the chain-expressible incremental-sync op
// (PROPOSAL-TREE-EXTRACT-SINCE Amendment 1 / Option E). Standalone
// revision-layer op that bundles the diff closure between the caller's
// supplied base version and the executing peer's current head for
// `Prefix`, returning a `system/envelope` entity wrapping a snapshot of
// the target root.
//
// Why it lives in revision (not tree): the op's input is a version
// hash, and version→trie-root deref is the revision extension's job.
// Putting it in tree (the original `tree:extract.since`) required the
// chain author to deref version→root before dispatch, which is not
// expressible in the continuation transform_ops vocab. See
// PROPOSAL-TREE-EXTRACT-SINCE.md Amendment 1.
//
// Params shape (Shape B): Base is supplied; Target is implicit
// (executing peer's local head). Chain authors wire
// base=$notification.previous_hash; prefix is static. Continuation
// inject-mode supports exactly one dynamic field, so this shape is
// the one chain-expressible variant.
//
// Errors:
//   - 400 invalid_params   — prefix missing or undecodable params
//   - 403 capability_denied — caller lacks fetch-diff cap on prefix
//   - 404 no_local_state   — no revision head bound for prefix
//   - 404 base_not_found   — base hash not in local content store
//   - 400 base_not_a_version — base resolves but isn't a version entry
//   - 500 internal_error   — head version entry missing/undecodable
func (h *Handler) handleFetchDiff(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}

	// fetch-diff reads the *executing* peer's local head. Both calling
	// patterns are legitimate:
	//
	//   - Local dispatch — receiver-local query (recipe author asks
	//     "what's MY diff against this base?"). Executing peer = caller.
	//
	//   - Cross-peer dispatch — the canonical Form 1 follower pattern
	//     per GUIDE-REVISION-AUTO-VERSION §4 lines 105-108: a follower
	//     (B) dispatches fetch-diff at the leader (A) so A returns A's
	//     diff between base and A's current head. Executing peer = A
	//     (the source) is exactly what the follower wants.
	//
	// Prior to this fix a blanket "ConnectionState != nil → reject"
	// guard (commit a1bb154, per the CAS-mirroring exploration Q5)
	// forbade the GUIDE-canonical Form 1 chain. The
	// trap that motivated the guard (recipe-author confusion between
	// "MY head" vs "leader's head") is a *recipe-author* concern, not
	// a primitive-level invariant. Cross-peer fetch-diff is documented
	// elsewhere (GUIDE §4) as the canonical follower-pattern wire op.

	var params types.RevisionFetchDiffParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params",
				"could not decode fetch-diff params")
			return resp, nil
		}
	}
	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}
	params.Prefix = resolvePrefix(params.Prefix, string(hctx.LocalPeerID))

	if resp := hctx.CheckPathCapability("fetch-diff", params.Prefix); resp != nil {
		return resp, nil
	}

	// Resolve executing peer's current head → trie root (= target).
	ph := PrefixHash(params.Prefix)
	headP := "system/revision/" + ph + "/head"
	headHash, ok := hctx.LocationIndex.Get(headP)
	if !ok {
		resp, _ := handler.NewErrorResponse(404, "no_local_state",
			"no revision head bound for prefix: "+params.Prefix)
		return resp, nil
	}
	targetVer, ok := loadVersion(hctx, headHash)
	if !ok {
		resp, _ := handler.NewErrorResponse(500, "internal_error",
			"revision head version entry missing or undecodable")
		return resp, nil
	}
	targetRoot := targetVer.Root

	// Resolve Base. Zero → bootstrap (diff against empty).
	var baseRoot hash.Hash
	if !params.Base.IsZero() {
		baseEnt, ok := hctx.Store.Get(params.Base)
		if !ok {
			resp, _ := handler.NewErrorResponse(404, "base_not_found",
				"server does not have the specified base version; "+
					"caller may retry with base unset (full closure)")
			return resp, nil
		}
		baseVer, derefErr := types.RevisionEntryDataFromEntity(baseEnt)
		if derefErr != nil {
			resp, _ := handler.NewErrorResponse(400, "base_not_a_version",
				"base hash does not resolve to a version entry: "+params.Base.String())
			return resp, nil
		}
		baseRoot = baseVer.Root
	}

	// Bundle the diff closure.
	skip := make(map[hash.Hash]bool)
	if !baseRoot.IsZero() {
		tree.CollectReachableHashes(hctx.Store, baseRoot, skip)
	}
	included := make(map[hash.Hash]entity.Entity)
	tree.CollectTrieEntitiesExcept(hctx.Store, targetRoot, skip, included)

	snap := types.SnapshotData{Root: targetRoot}
	snapEntity, sErr := snap.ToEntity()
	if sErr != nil {
		return nil, sErr
	}
	env := entity.Envelope{Root: snapEntity, Included: included}
	envEntity, eErr := env.ToEntity()
	if eErr != nil {
		return nil, eErr
	}
	return &handler.Response{Status: 200, Result: envEntity}, nil
}
