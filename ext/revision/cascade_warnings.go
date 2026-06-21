package revision

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// collectCascadeWarning checks a CascadeResult for halts and appends warnings.
func collectCascadeWarning(cr *store.CascadeResult, path string, warnings *[]types.RevisionCascadeWarningData) {
	if cr == nil {
		return
	}
	for _, halt := range cr.Halted {
		*warnings = append(*warnings, types.RevisionCascadeWarningData{
			Path:           path,
			ConsumerHalted: halt.Name,
			ErrorCode:      halt.Error.Code,
		})
	}
}

// bind is a small adapter over HandlerContext.TreeSet: it threads any storage
// error into a 500 error response and otherwise returns the cascade result for
// the caller's warning collection. Pattern:
//
//	cr, resp := bind(hctx, path, h, op)
//	if resp != nil { return resp, nil }
//	collectCascadeWarning(cr, path, &warnings)
//
// On storage failure the binding did NOT commit (per V7 §2688) — the caller
// must return immediately and not proceed with partial state.
func bind(hctx *handler.HandlerContext, path string, h hash.Hash, op string) (*store.CascadeResult, *handler.Response) {
	cr, err := hctx.TreeSet(path, h, op)
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "storage_error", fmt.Sprintf("%s: bind %s: %v", op, path, err))
		return nil, resp
	}
	return cr, nil
}

// bindMerged is the marker-aware version of bind, mirroring
// applyMergedBindingToTree's signature. Used by revert/checkout/cherry-pick/
// merge when applying merged trie bindings to the live tree.
func bindMerged(hctx *handler.HandlerContext, path string, h hash.Hash, op string) (*store.CascadeResult, *handler.Response) {
	cr, err := applyMergedBindingToTree(hctx, path, h, op)
	if err != nil {
		resp, _ := handler.NewErrorResponse(500, "storage_error", fmt.Sprintf("%s: bind %s: %v", op, path, err))
		return nil, resp
	}
	return cr, nil
}
