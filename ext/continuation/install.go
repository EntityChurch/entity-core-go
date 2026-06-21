package continuation

import (
	"context"
	"errors"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)



// --- install operation (R0/R1 — PROPOSAL-COHERENT-CAPABILITY-AUTHORITY §3) ---

// handleInstall creates a system/continuation (or system/continuation/join)
// entity at the resource-targeted path after running the R1 in-chain
// authorization check (EXTENSION-CONTINUATION §3.1a/§3.2 step 4) on the
// embedded dispatch_capability — the writer must appear as a granter
// anywhere in the cap's authority chain, NOT that the chain roots at the
// writer (a root check is the local sufficient condition only and breaks
// every cross-peer continuation). The continuation entity reaches the
// tree only via this operation; direct tree:put bypasses the validation.
//
// V7 §3.2 path-as-resource: the install path comes from
// EXECUTE.resource.targets[0]. Caller passes a system/continuation or
// system/continuation/join entity directly as params; the handler
// discriminates forward vs join on params.type — one op, two accepted types
// (PROPOSAL-PATH-AS-RESOURCE-HYGIENE).
func (h *Handler) handleInstall(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	if hctx.Resource == nil || len(hctx.Resource.Targets) != 1 {
		return handler.NewErrorResponse(400, "ambiguous_resource",
			"install requires exactly one resource target (the suspended path)")
	}
	installPath := hctx.Resource.Targets[0]

	// Discriminate forward vs join on params.type. The continuation entity
	// itself is the params payload — no wrapper.
	var (
		dispatchCap hash.Hash
		contEntity  entity.Entity
	)
	switch req.Params.Type {
	case types.TypeContinuation:
		var contData types.ContinuationData
		if err := ecf.Decode(req.Params.Data, &contData); err != nil {
			return handler.NewErrorResponse(400, "invalid_params",
				"could not decode system/continuation: "+err.Error())
		}
		if contData.Target == "" || contData.Operation == "" {
			return handler.NewErrorResponse(400, "invalid_continuation",
				"forward continuation requires target and operation")
		}
		if contData.DispatchCapability.IsZero() {
			return handler.NewErrorResponse(400, "missing_dispatch_capability",
				"continuation requires dispatch_capability for the deferred dispatch")
		}
		// G1 fail-closed: an unrecognized transform_ops op is rejected at
		// install, never silently skipped at advance (EXTENSION-CONTINUATION
		// §2.2 / §8.1). The op set is closed; unknown ops can't be analyzed
		// for the total/pure/bounded contract, so they must not persist.
		if badOp, ok := firstUnknownTransformOp(contData.ResultTransform); ok {
			return handler.NewErrorResponse(400, "unknown_transform_op",
				"unrecognized transform_ops op: "+badOp)
		}
		// Recognized-op argument-shape validation. EXTENSION-CONTINUATION
		// v1.15 §2.2 pins `400 invalid_transform_args` as the code for
		// the recognized-op-but-bad-args class (currently only
		// `collect_keys` with both `field` and `fields` set).
		if reason, ok := firstInvalidTransformOpArgs(contData.ResultTransform); ok {
			return handler.NewErrorResponse(400, "invalid_transform_args", reason)
		}
		// Merge-mode mutual exclusivity with result_field
		// (PROPOSAL-CONTINUATION-MERGE-ASSEMBLY §3). Both express "what
		// to do with the transformed value"; combining is ambiguous.
		if contData.ResultMerge && contData.ResultField != "" {
			return handler.NewErrorResponse(400, "invalid_continuation",
				"result_merge: true is mutually exclusive with result_field")
		}
		dispatchCap = contData.DispatchCapability
		var err error
		contEntity, err = contData.ToEntity()
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "build continuation: "+err.Error())
		}
	case types.TypeContinuationJoin:
		var joinData types.ContinuationJoinData
		if err := ecf.Decode(req.Params.Data, &joinData); err != nil {
			return handler.NewErrorResponse(400, "invalid_params",
				"could not decode system/continuation/join: "+err.Error())
		}
		if joinData.DispatchCapability.IsZero() {
			return handler.NewErrorResponse(400, "missing_dispatch_capability",
				"continuation requires dispatch_capability for the deferred dispatch")
		}
		dispatchCap = joinData.DispatchCapability
		var err error
		contEntity, err = joinData.ToEntity()
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "build continuation: "+err.Error())
		}
	default:
		return handler.NewErrorResponse(400, "invalid_params",
			"install expects system/continuation or system/continuation/join in params, got "+req.Params.Type)
	}

	// Resolve dispatch_capability — required to be in envelope's included or local store.
	capEnt, ok := resolveCap(hctx, dispatchCap)
	if !ok {
		return handler.NewErrorResponse(404, "dispatch_capability_not_found",
			"referenced dispatch_capability not in envelope or local store")
	}

	// R1 in-chain authorization check (EXTENSION-CONTINUATION §3.1a, §3.2
	// step 4): walk the dispatch_capability's authority chain end-to-end and
	// require the writer's identity to appear as a granter ANYWHERE in the
	// chain — not that the chain roots at the writer. CheckCreatorAuthority
	// already implements this (it returns true on the first granter match at
	// any depth). The walker enforces chain reachability before identity
	// matching, so unreachable parents surface as 404 chain_unreachable
	// regardless of whether the writer matches at the leaf. For the local
	// case in-chain ⇔ rooted-at-installer, so local behavior is unchanged;
	// for cross-peer the chain is B-rooted with the installer in-chain as the
	// re-attenuation leaf granter (§4.2 case 3) and this check still passes.
	resolver := func(h hash.Hash) (entity.Entity, bool) {
		if ent, ok := hctx.Included[h]; ok {
			return ent, true
		}
		return hctx.Store.Get(h)
	}
	found, chain, err := capability.CheckCreatorAuthority(capEnt, hctx.AuthorHash, resolver, capability.IncludedSignatureResolver(hctx.Included))
	if err != nil {
		if errors.Is(err, ecerrors.ErrChainUnreachable) {
			return handler.NewErrorResponse(404, "chain_unreachable",
				"dispatch_capability authority chain not fully resolvable from envelope or store")
		}
		if errors.Is(err, ecerrors.ErrChainTooDeep) {
			return handler.NewErrorResponse(400, "chain_too_deep",
				"dispatch_capability authority chain exceeds maximum depth")
		}
		return handler.NewErrorResponse(500, "internal_error", "chain walk: "+err.Error())
	}
	if !found {
		// Per proposal §3.2: do NOT persist the chain on rejection — rejected
		// requests must not contribute to local state.
		return handler.NewErrorResponse(403, "embedded_cap_unauthorized",
			"writer identity not in dispatch_capability authority chain")
	}

	// Persist the collected chain to local store so advance can resolve it
	// without requiring re-delivery (CA-12 chain-entity persistence). The
	// chain comes from CheckCreatorAuthority — no re-walk.
	for _, ent := range chain {
		if _, err := hctx.Store.Put(ent); err != nil {
			return handler.NewErrorResponse(500, "internal_error",
				fmt.Sprintf("persist chain entity %s: %v", ent.ContentHash, err))
		}
	}

	// Persist continuation entity and write to tree.
	contHash, err := hctx.Store.Put(contEntity)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "store continuation: "+err.Error())
	}
	if _, err := hctx.TreeSet(installPath, contHash, "install"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind continuation: "+err.Error())
	}

	return handler.NewResponse(200, types.TypeContinuationInstallResult,
		types.ContinuationInstallResultData{Path: installPath})
}

// resolveCap looks up a capability entity by hash, preferring the envelope's
// Included set (in-flight cap) over the local content store (replicated cap).
func resolveCap(hctx *handler.HandlerContext, h hash.Hash) (entity.Entity, bool) {
	if ent, ok := hctx.Included[h]; ok {
		return ent, true
	}
	return hctx.Store.Get(h)
}
