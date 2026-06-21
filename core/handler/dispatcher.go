package handler

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// ExecuteRequest is the value-typed request body for the Dispatcher
// interface. Per SDK-EXTENSION-OPERATIONS v0.8 §11 Content Extension:
//
//	Dispatcher.Execute(ctx, ExecuteRequest) → (ExecuteResponse, error)
//
// Both AppPeer (outer-caller / cross-peer) and HandlerContext
// (handler-internal) satisfy a shared Dispatcher interface via the
// adapter wrappers in core/peer + core/handler. Per Go's review of the
// content-materialization v2 concurrence proposal:
// value types live here so both adapters share the contract without
// either surface having to import the other.
type ExecuteRequest struct {
	// URI is the entity://peer_id/path target. AppPeer dispatch uses the
	// connection's authority when URI omits the peer segment; cross-peer
	// dispatch encodes the target authority in the URI.
	URI string
	// Operation is the handler operation name (e.g. "get", "ingest").
	Operation string
	// Resource is the path-as-resource per V7 §3.2 — namespace path that
	// scopes the cap check. Nil when the op doesn't carry a namespace
	// (rare; most cap-checked ops require a resource per V7 §5.2).
	Resource *types.ResourceTarget
	// Params is the ECF-encoded request body wrapped as an entity. The
	// caller constructs this via the request type's ToEntity() helper.
	Params entity.Entity
	// Capability optionally overrides the cap used for the Level-1
	// check on this dispatch. Nil = use the dispatcher's ambient
	// authority (HandlerContext's CallerCapability or Connection's
	// session cap).
	Capability entity.Entity
}

// ExecuteResponse is the value-typed response from a Dispatcher.Execute
// call. Result + Included are the same shape returned by the existing
// handler.Response — Status is included so callers can branch on the
// op-level result without re-decoding the envelope.
type ExecuteResponse struct {
	// Status is the op-level status code (200 / 4xx / 5xx) per
	// V7 §6.2 response envelope shape.
	Status uint
	// Result is the op-level response entity (e.g. ContentGetResponseData
	// for system/content:get). Empty entity (Type == "") when the op
	// returned an error and the result body is empty.
	Result entity.Entity
	// Included carries any entities the responder hoisted into the
	// envelope's Included map per V7 §3.3 v7.51 envelope-included
	// preservation. Callers that need entities the response references
	// by hash (blob → chunks for system/content:get) look here first
	// before round-tripping for them separately.
	Included map[hash.Hash]entity.Entity
}

// Dispatcher is the shared interface that AppPeer + HandlerContext both
// satisfy, exposing a uniform Execute call shape for SDK helpers that
// need to sequence multiple dispatches (e.g. content.EnsureClosure).
//
// Per V7 §6.8 v7.49 propagated-cap-not-a-gate: each Execute call is
// independently cap-checked by the dispatcher; the caller cannot
// piggy-back authority from a prior dispatch.
type Dispatcher interface {
	Execute(ctx context.Context, req ExecuteRequest) (ExecuteResponse, error)
}

// HandlerContextDispatcher returns a Dispatcher backed by the
// HandlerContext's existing Execute function field. HandlerContext
// itself can't satisfy Dispatcher directly because its Execute field
// has a different shape (variadic options); this adapter bridges.
//
// The returned Dispatcher routes through the same cap-checked dispatch
// path as direct hctx.Execute calls — the handler's internal_scope
// grant is the cap surface.
func HandlerContextDispatcher(hctx *HandlerContext) Dispatcher {
	return handlerCtxDispatcher{hctx: hctx}
}

type handlerCtxDispatcher struct {
	hctx *HandlerContext
}

// Store returns the local content store backing this dispatcher. SDK
// helpers (content.EnsureClosure) use this to read what's already local
// before dispatching system/content:get. The cap-checked dispatcher
// (Execute) remains the only path that writes to the store; Store is
// read-side only from SDK helpers' perspective.
func (d handlerCtxDispatcher) Store() store.ContentStore {
	return d.hctx.Store
}

func (d handlerCtxDispatcher) Execute(ctx context.Context, req ExecuteRequest) (ExecuteResponse, error) {
	var opts []ExecuteOption
	if req.Resource != nil {
		opts = append(opts, WithResource(req.Resource))
	}
	if req.Capability.Type != "" {
		opts = append(opts, WithCapability(req.Capability))
	}
	resp, err := d.hctx.Execute(ctx, req.URI, req.Operation, req.Params, opts...)
	if err != nil {
		return ExecuteResponse{}, err
	}
	return ExecuteResponse{
		Status:   resp.Status,
		Result:   resp.Result,
		Included: resp.Included,
	}, nil
}
