package revision

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handlePull implements the pull operation per EXTENSION-REVISION
// §4.4.8: the convenience composition of cross-peer fetch +
// incremental fetch-entities trie walk + local merge. Input type is
// `system/revision/fetch-params` (spec line 558) with `Remote`
// identifying the peer to pull from; output is
// `system/revision/merge-result`.
//
// Dispatched on the FOLLOWER (caller-local) — the handler makes
// outbound EXECUTEs to the remote and merges into the local DAG.
// Mirrors the SDK's `RevisionClient.Pull` orchestration; folding
// the trie-walk loop into a single handler op is what makes the
// operation chain-expressible (continuation transforms cannot
// iterate on the caller side; the iteration moves inside the op).
//
// Errors:
//   - 400 invalid_params       — prefix or remote missing/undecodable
//   - 403 capability_denied    — caller lacks pull cap on prefix
//   - 502 remote_fetch_failed  — outbound fetch to the remote errored
//   - 500 remote_empty         — remote has no head at the prefix
//   - 500 internal_error       — handler context lacks Execute hook
const pullMaxRounds = 32

func (h *Handler) handlePull(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if resp := checkContext(hctx); resp != nil {
		return resp, nil
	}
	if hctx.Execute == nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error",
			"handler context missing Execute hook (required for outbound cross-peer dispatch)")
		return resp, nil
	}

	var params types.RevisionFetchParamsData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &params); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "could not decode pull params")
			return resp, nil
		}
	}
	if params.Prefix == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "prefix is required")
		return resp, nil
	}
	if params.Remote == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params",
			"remote peer-id is required for pull")
		return resp, nil
	}
	localPrefix := resolvePrefix(params.Prefix, string(hctx.LocalPeerID))

	if resp := hctx.CheckPathCapability("pull", localPrefix); resp != nil {
		return resp, nil
	}

	// 1. Outbound fetch on the remote. The remote_prefix (if set in
	//    params) routes the remote-side handler at its own prefix
	//    namespace; default is same as local prefix.
	remoteURI := fmt.Sprintf("entity://%s/system/revision", params.Remote)
	remoteFetchParams := types.RevisionFetchParamsData{
		Prefix:       firstNonEmpty(params.RemotePrefix, params.Prefix),
		RemotePrefix: params.RemotePrefix,
		Since:        params.Since,
		Depth:        params.Depth,
	}
	remoteParamEnt, err := remoteFetchParams.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error",
			"encode remote fetch params: "+err.Error())
		return resp, nil
	}
	fetchResp, err := hctx.Execute(ctx, remoteURI, "fetch", remoteParamEnt)
	if err != nil {
		resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
			"revision/fetch on "+params.Remote+": "+err.Error())
		return resp, nil
	}
	if fetchResp == nil || fetchResp.Status >= 400 {
		resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
			fmt.Sprintf("revision/fetch on %s: status=%d", params.Remote, statusOf(fetchResp)))
		return resp, nil
	}

	// 2. Decode envelope, ingest Included (version entries + root trie
	//    nodes) into the local content store.
	if fetchResp.Result.Type != "system/envelope" {
		resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
			"expected system/envelope from remote fetch; got "+fetchResp.Result.Type)
		return resp, nil
	}
	var env entity.Envelope
	if err := ecf.Decode(fetchResp.Result.Data, &env); err != nil {
		resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
			"decode remote fetch envelope: "+err.Error())
		return resp, nil
	}
	for _, ent := range env.Included {
		if _, err := hctx.Store.Put(ent); err != nil {
			resp, _ := handler.NewErrorResponse(500, "internal_error",
				"write fetched entity to local store: "+err.Error())
			return resp, nil
		}
	}
	fetchResult, err := types.RevisionFetchResultDataFromEntity(env.Root)
	if err != nil {
		resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
			"decode remote fetch-result: "+err.Error())
		return resp, nil
	}
	if fetchResult.Head.IsZero() {
		resp, _ := handler.NewErrorResponse(500, "remote_empty",
			"remote "+params.Remote+" has no versions at prefix "+localPrefix)
		return resp, nil
	}

	// 3. Walk the remote's trie locally; iteratively fetch-entities
	//    on the remote until closure is complete.
	versionEnt, ok := hctx.Store.Get(fetchResult.Head)
	if !ok {
		resp, _ := handler.NewErrorResponse(500, "internal_error",
			"version entity missing after fetch ingest")
		return resp, nil
	}
	versionData, err := types.RevisionEntryDataFromEntity(versionEnt)
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error",
			"decode fetched version entry: "+err.Error())
		return resp, nil
	}

	// Iteratively fetch entities until the remote's trie at the
	// fetched head is fully present locally. Exiting with missing > 0
	// (loop bail or maxRounds exhaustion) MUST NOT proceed to merge —
	// the merge would advance the local head to a version whose trie
	// references entities not in the local content store. That looks
	// like "head converged" externally but is observably corrupt
	// (e.g., bidirectional burst tests see "head matches but bob is
	// missing the latest leaf"). Return 502 instead; the standing
	// chain naturally retries on the next head notification, when
	// the remote has presumably caught up.
	remotePullPrefix := firstNonEmpty(params.RemotePrefix, params.Prefix)
	exitedClean := false
	var lastMissing int
	for round := 0; round < pullMaxRounds; round++ {
		missing := collectMissingPullHashes(hctx.Store, versionData.Root)
		lastMissing = len(missing)
		if lastMissing == 0 {
			exitedClean = true
			break
		}
		feParams := types.RevisionFetchEntitiesParamsData{
			Prefix:   remotePullPrefix,
			Snapshot: versionData.Root,
			Hashes:   missing,
		}
		feEnt, err := feParams.ToEntity()
		if err != nil {
			resp, _ := handler.NewErrorResponse(500, "internal_error",
				"encode fetch-entities params: "+err.Error())
			return resp, nil
		}
		feResp, err := hctx.Execute(ctx, remoteURI, "fetch-entities", feEnt)
		if err != nil {
			resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
				fmt.Sprintf("revision/fetch-entities round %d on %s: %v", round+1, params.Remote, err))
			return resp, nil
		}
		if feResp == nil || feResp.Status >= 400 {
			resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
				fmt.Sprintf("revision/fetch-entities round %d on %s: status=%d",
					round+1, params.Remote, statusOf(feResp)))
			return resp, nil
		}
		if feResp.Result.Type != "system/envelope" {
			resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
				fmt.Sprintf("revision/fetch-entities round %d on %s: unexpected result type %q",
					round+1, params.Remote, feResp.Result.Type))
			return resp, nil
		}
		var feEnv entity.Envelope
		if err := ecf.Decode(feResp.Result.Data, &feEnv); err != nil {
			resp, _ := handler.NewErrorResponse(502, "remote_fetch_failed",
				fmt.Sprintf("revision/fetch-entities round %d on %s: decode envelope: %v",
					round+1, params.Remote, err))
			return resp, nil
		}
		ingested := 0
		for _, ent := range feEnv.Included {
			if _, err := hctx.Store.Put(ent); err == nil {
				ingested++
			}
		}
		if ingested == 0 {
			// Remote returned 2xx but no entities — either we asked
			// for hashes the remote doesn't yet have in its store
			// (commit-race: remote's head moved but it hasn't
			// finished persisting the closure), or remote sees the
			// hashes as invalid. Either way, merging now would
			// produce the head-matches-but-data-incomplete corruption.
			// Bail and let the chain retry on the next notification.
			resp, _ := handler.NewErrorResponse(502, "incomplete_fetch",
				fmt.Sprintf("round %d: %d entities still missing, remote returned 0 — chain will retry",
					round+1, lastMissing))
			return resp, nil
		}
	}
	if !exitedClean {
		// maxRounds exhausted. Same corruption hazard as the
		// ingested==0 bail; treat the same way.
		resp, _ := handler.NewErrorResponse(502, "incomplete_fetch",
			fmt.Sprintf("after %d rounds: still %d entities missing — chain will retry",
				pullMaxRounds, lastMissing))
		return resp, nil
	}

	// 4. Local merge against the freshly-fetched remote head.
	mergeReq := &handler.Request{
		Operation: "merge",
		Context:   hctx,
	}
	mergeParams := types.RevisionMergeParamsData{
		Prefix:        localPrefix,
		RemoteVersion: fetchResult.Head,
	}
	mergeEnt, err := mergeParams.ToEntity()
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "internal_error",
			"encode merge params: "+err.Error())
		return resp, nil
	}
	mergeReq.Params = mergeEnt
	return h.handleMerge(ctx, mergeReq)
}

// collectMissingPullHashes walks the trie rooted at `root`, identifies
// trie nodes the local store doesn't have AND leaf binding hashes the
// local store doesn't have. Mirrors the SDK Pull walker
// (entity-workbench-go/entitysdk/revision.go::collectMissingLeafHashes)
// but returns trie nodes too — they may not yet be local on the first
// few rounds since `fetch` only includes the root trie node.
func collectMissingPullHashes(cs interface {
	Get(hash.Hash) (entity.Entity, bool)
	Has(hash.Hash) bool
}, root hash.Hash) []hash.Hash {
	if root.IsZero() {
		return nil
	}
	seen := map[hash.Hash]bool{}
	var missing []hash.Hash
	var visit func(h hash.Hash)
	visit = func(h hash.Hash) {
		if h.IsZero() || seen[h] {
			return
		}
		seen[h] = true
		nodeEnt, ok := cs.Get(h)
		if !ok {
			// Trie node not local yet — request it.
			missing = append(missing, h)
			return
		}
		if nodeEnt.Type != types.TypeTreeSnapshotNode {
			// Not a trie node — treat as leaf, no children to walk.
			return
		}
		var nd types.SnapshotNodeData
		if err := ecf.Decode(nodeEnt.Data, &nd); err != nil {
			return
		}
		for _, entry := range nd.Data {
			if entry.IsBucket() {
				for _, t := range entry.Bucket {
					if t.ValueHash.IsZero() {
						continue
					}
					if !cs.Has(t.ValueHash) {
						missing = append(missing, t.ValueHash)
					}
				}
			} else {
				visit(*entry.Link)
			}
		}
	}
	visit(root)
	return missing
}

func statusOf(r *handler.Response) int {
	if r == nil {
		return 0
	}
	return int(r.Status)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
