package subscription

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

const handlerPattern = "system/subscription"

// Handler implements handler.Handler for the system/subscription handler.
// Subscribe and unsubscribe operations are routed to the Engine.
type Handler struct {
	engine *Engine
}

// NewHandler creates a subscription handler backed by the given engine.
func NewHandler(engine *Engine) *Handler {
	return &Handler{engine: engine}
}

func (h *Handler) Name() string { return "subscriptions" }

// Manifest returns the handler's self-description per spec §3.1.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "subscriptions",
		Operations: map[string]types.HandlerOperationSpec{
			"subscribe":   {InputType: types.TypeSubscriptionRequest},
			"unsubscribe": {InputType: types.TypeSubscriptionCancel},
		},
	}
}

// RegisterTypes registers subscription-specific types into the registry.
// Note: subscription types are already registered in RegisterCoreTypes with
// semantic type overrides (pattern/deliver_uri → system/tree/path). Do not
// re-register here.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "subscribe":
		return h.engine.HandleSubscribe(ctx, req)
	case "unsubscribe":
		return h.engine.HandleUnsubscribe(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"subscription handler does not support operation: "+req.Operation)
	}
}

// Register registers the subscription handler with a handler registry.
func Register(reg *handler.Registry, engine *Engine) *Handler {
	h := NewHandler(engine)
	reg.Register(handlerPattern, h)
	return h
}
