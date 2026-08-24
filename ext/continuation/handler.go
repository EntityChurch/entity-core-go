package continuation

import (
	"context"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

const handlerPattern = "system/continuation"

// Handler implements the system/continuation handler with advance, resume, and
// abandon operations (spec §3.3–3.7).
type Handler struct {
	mu        sync.Mutex
	joinLocks map[string]*sync.Mutex // per-join-path serialization

	// markerRetentionMs is the §3.10 chain-error marker retention window.
	// RetainMarkersForever (0) disables collection. See marker_collect.go.
	markerRetentionMs uint64
	// chainTTLSeed is the uniform ttl seeded into a root chain's bounds.
	// See WithChainTTLSeed.
	chainTTLSeed uint64
	// lastCollect throttles the bind-time sweep.
	lastCollect time.Time
}

// HandlerOption configures a continuation Handler.
type HandlerOption func(*Handler)

// WithMarkerRetention sets the §3.10 chain-error marker retention window in
// milliseconds — the named knob behind MarkerRetentionKey.
//
// Pass RetainMarkersForever to keep every marker: the tree IS the event log,
// and an operator who wants the whole history is entitled to it. The default
// is bounded (DefaultMarkerRetentionMs, 24h) because marker BINDING is a MUST,
// so unbounded growth must not be what you get by doing nothing.
func WithMarkerRetention(ms uint64) HandlerOption {
	return func(h *Handler) { h.markerRetentionMs = ms }
}

// WithChainTTLSeed sets the uniform ttl seeded into a root continuation chain
// (types.DefaultChainTTL by default).
//
// This is the operator counterpart to the dispatcher's MaxChainDepth: the two
// bounds are meant to be tuned together, because what matters is the RATIO
// between them, not either number alone. chain_depth counts causal advancement
// levels; ttl is decremented by every dispatch, including the internal
// sub-dispatches a single advancement makes. So seed/ceiling is roughly "how
// many dispatch operations one causal level may spend before the resource
// backstop fires instead of the deterministic depth brake."
//
// Raising this alone widens the resource allowance; to change how LONG a chain
// may get, move the dispatcher's MaxChainDepth. Setting it below the depth
// ceiling re-creates the confound this seed exists to remove (ttl fires first
// and masks the depth brake), so keep seed > ceiling.
func WithChainTTLSeed(ttl uint64) HandlerOption {
	return func(h *Handler) { h.chainTTLSeed = ttl }
}

// NewHandler creates a new continuation handler.
func NewHandler(opts ...HandlerOption) *Handler {
	h := &Handler{
		joinLocks:         make(map[string]*sync.Mutex),
		markerRetentionMs: DefaultMarkerRetentionMs,
		chainTTLSeed:      types.DefaultChainTTL,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
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
