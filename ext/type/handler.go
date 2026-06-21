// Package typeext implements the system/type handler per EXTENSION-TYPE
// v1.1. The package name is "typeext" because "type" is a Go reserved word.
//
// Owned ops (v1.1 §7.1):
//   - validate    (MUST, §8.3)
//   - compare     (SHOULD, §7.2 — T5)
//   - compatible  (SHOULD, §7.3 — T5)
//   - converge    (MAY,    §7.4 — T6, deferred)
//   - adopt       (MAY,    §7.5 — T6, deferred)
//   - reconcile   (MAY,    §7.6 — T6, deferred)
//
// Resolution strategy: Strategy 1 (path-convention) only per v1.1 §1.5.
package typeext

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

const handlerPattern = "system/type"

// Handler implements the system/type handler.
type Handler struct{}

// NewHandler returns a stateless type-handler instance.
func NewHandler() *Handler { return &Handler{} }

func (h *Handler) Name() string { return "types" }

// Manifest returns the handler's self-description per §7.1. All six ops
// (validate, compare, compatible, converge, adopt, reconcile) are wired.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "types",
		Operations: map[string]types.HandlerOperationSpec{
			"validate": {
				InputType:  types.TypeValidateReq,
				OutputType: types.TypeValidateRes,
			},
			"compare": {
				InputType:  types.TypeTypeCompareRequest,
				OutputType: types.TypeTypeCompareResult,
			},
			"compatible": {
				InputType:  types.TypeTypeCompatibleRequest,
				OutputType: types.TypeTypeCompatibilityReport,
			},
			"converge": {
				InputType:  types.TypeTypeConvergeRequest,
				OutputType: types.TypeType,
			},
			"adopt": {
				InputType:  types.TypeTypeAdoptRequest,
				OutputType: types.TypeType,
			},
			"reconcile": {
				InputType:  types.TypeTypeReconcileRequest,
				OutputType: types.TypeTypeReconcileResult,
			},
		},
	}
}

// RegisterTypes is a no-op — type-extension types are registered in
// RegisterCoreTypes.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches to the operation per §2.3 / §7.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "validate":
		return h.handleValidate(ctx, req)
	case "compare":
		return h.handleCompare(ctx, req)
	case "compatible":
		return h.handleCompatible(ctx, req)
	case "converge":
		return h.handleConverge(ctx, req)
	case "adopt":
		return h.handleAdopt(ctx, req)
	case "reconcile":
		return h.handleReconcile(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"system/type handler does not support operation: "+req.Operation)
	}
}

// Compile-time assertion.
var _ handler.Handler = (*Handler)(nil)
