package continuation

import (
	"context"
	"sync"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

const handlerPattern = "system/continuation"

// Handler implements the system/continuation handler with advance, resume, and
// abandon operations (spec §3.3–3.7).
type Handler struct {
	mu        sync.Mutex
	joinLocks map[string]*sync.Mutex // per-join-path serialization
}

// NewHandler creates a new continuation handler.
func NewHandler() *Handler {
	return &Handler{
		joinLocks: make(map[string]*sync.Mutex),
	}
}

func (h *Handler) Name() string { return "continuations" }

// Manifest returns the handler's self-description.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "continuations",
		Operations: map[string]types.HandlerOperationSpec{
			"install": {InputType: types.TypeContinuation, OutputType: types.TypeContinuationInstallResult},
			"advance": {InputType: types.TypeContinuationAdvanceRequest},
			"resume":  {InputType: types.TypeContinuationResumeRequest},
			"abandon": {InputType: types.TypeContinuationAbandonRequest},
		},
	}
}

// RegisterTypes registers continuation-specific types into the registry.
// The continuation types are already registered in RegisterCoreTypes;
// this handler doesn't introduce additional handler-specific types.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "install":
		return h.handleInstall(ctx, req)
	case "advance":
		return h.handleAdvance(ctx, req)
	case "resume":
		return h.handleResume(ctx, req)
	case "abandon":
		return h.handleAbandon(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"continuation handler does not support operation: "+req.Operation)
	}
}
