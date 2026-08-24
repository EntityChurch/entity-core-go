package handler

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Handler processes requests dispatched to a registered path pattern.
type Handler interface {
	Handle(ctx context.Context, req *Request) (*Response, error)
	Name() string
}

// ManifestProvider is implemented by handlers that can describe themselves.
// The returned manifest is decomposed by the peer builder into a handler entity
// (at the pattern path) and an interface entity (at system/handler/{pattern}).
type ManifestProvider interface {
	Manifest() types.HandlerManifestData
}

// TypeProvider is implemented by handlers that introduce custom types.
// RegisterTypes is called during peer initialization to populate the type registry.
type TypeProvider interface {
	RegisterTypes(r *types.TypeRegistry)
}

// Request is the input to a handler.
type Request struct {
	Path      string
	Operation string
	Params    entity.Entity
	Context   *HandlerContext
}

// StatusMultiStatus indicates "binding landed, cascade incomplete" — the tree
// write succeeded but at least one Phase 1 emit consumer halted the cascade.
// Per PROPOSAL-CASCADE-SEMANTICS §4.3.
const StatusMultiStatus uint = 207

// StatusRedirect indicates the server understood the request but is redirecting
// the client elsewhere (e.g., subscription at capacity). Analogous to HTTP 303.
// Per PROPOSAL-SUBSCRIPTION-BOUNDED-FANOUT §S2.
const StatusRedirect uint = 303

// StatusAccepted — the request is accepted and completion is asynchronous,
// observed elsewhere. Used by EXTENSION-INBOX §7.1 (inbox-ack semantics —
// normative in V7 v7.46) and by EXTENSION-DURABILITY §5 (the "committed,
// completes asynchronously" verdict — within that extension's surface only).
const StatusAccepted uint = 202

// StatusPreconditionFailed — a required durability precondition could not
// be met; the operation was NOT performed (refused at acceptance, safe to
// retry elsewhere — no double-execution). Used by EXTENSION-DURABILITY §5 /
// §8 only — V7 v7.46 does NOT reserve 412 at the core level.
const StatusPreconditionFailed uint = 412

// StatusConflict — a durable request's (author, request_id) matches a
// previously preserved entry (duplicate). 409 is in V7 §3.3's reserved set
// (duplicate_request_id / path_exists); EXTENSION-DURABILITY §5 / §8 pins
// it as the duplicate-(author, request_id) outcome for the durability MUST.
const StatusConflict uint = 409

// Response is the output from a handler.
type Response struct {
	Status   uint
	Result   entity.Entity
	Included map[hash.Hash]entity.Entity
}

// NewResponse creates a response with the given status and result data.
func NewResponse(status uint, resultType string, resultData interface{}) (*Response, error) {
	raw, err := ecfEncode(resultData)
	if err != nil {
		return nil, err
	}
	ent, err := entity.NewEntity(resultType, cbor.RawMessage(raw))
	if err != nil {
		return nil, err
	}
	return &Response{Status: status, Result: ent}, nil
}

// NewErrorResponse creates an error response.
func NewErrorResponse(status uint, code, message string) (*Response, error) {
	return NewResponse(status, types.TypeError, types.ErrorData{
		Code:    code,
		Message: message,
	})
}

// ExecuteOption configures optional fields on a handler-initiated EXECUTE dispatch.
type ExecuteOption func(*ExecuteOpts)

// ExecuteOpts holds optional overrides for handler-initiated EXECUTE dispatch.
type ExecuteOpts struct {
	Resource   *types.ResourceTarget
	Capability entity.Entity
	DeliverTo  *types.DeliverySpec
	Bounds     *types.BoundsData
	// IncludedChain carries extra entities that MUST travel in a cross-peer
	// dispatched EXECUTE's `included` map beyond what the general V7
	// §3.1/§3.2 rule places (which is only the leaf cap). Used for the
	// continuation dispatch_capability's full authority chain
	// (EXTENSION-CONTINUATION §4.3 / §8.1). Nil for ordinary dispatch —
	// behavior is then unchanged.
	IncludedChain []entity.Entity
	// ChainDepth overrides the dispatched EXECUTE's §3.9 chain-depth counter.
	// Nil (the ordinary case) inherits the caller's depth unchanged; only a
	// continuation advancement sets it, to caller+1. See WithChainDepth.
	ChainDepth *uint64
	// ReactiveTrigger marks this dispatch as a reactive delivery trigger — an
	// advancement driven by a delivered event (an inbox route, a subscription
	// poke) rather than a bare administrative `advance` EXECUTE. It is the O1
	// signal for PROPOSAL-CONTINUATION-STANDING-MODEL §3: a reactive advance is
	// gated by delivery-reachability (already enforced upstream, at the receive)
	// and runs under the continuation's OWN dispatch_capability, so it MUST NOT
	// also require the trigger to hold advance-cap on the continuation path.
	// Per-dispatch and NOT inherited by sub-dispatches — it marks only the one
	// advance the delivery mechanism initiated. See WithReactiveTrigger.
	ReactiveTrigger bool
}

// ApplyOpts processes variadic ExecuteOptions into an ExecuteOpts struct.
func ApplyOpts(opts []ExecuteOption) ExecuteOpts {
	var o ExecuteOpts
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// WithResource overrides the resource target for the dispatched EXECUTE.
func WithResource(r *types.ResourceTarget) ExecuteOption {
	return func(o *ExecuteOpts) { o.Resource = r }
}

// WithCapability overrides the capability used for Level 1 check on the dispatched EXECUTE.
func WithCapability(cap entity.Entity) ExecuteOption {
	return func(o *ExecuteOpts) { o.Capability = cap }
}

// WithDeliverTo attaches a delivery spec to the dispatched EXECUTE.
func WithDeliverTo(spec *types.DeliverySpec) ExecuteOption {
	return func(o *ExecuteOpts) { o.DeliverTo = spec }
}

// WithIncludedChain attaches extra entities (a capability's full authority
// chain: caps + signatures + granter identities) to a cross-peer dispatched
// EXECUTE's `included` map. Required for continuation cross-peer dispatch so
// the target peer can verify the scoped dispatch_capability's chain to a
// root it recognizes (EXTENSION-CONTINUATION §4.3 / §8.1). No effect on
// local dispatch.
func WithIncludedChain(entities []entity.Entity) ExecuteOption {
	return func(o *ExecuteOpts) { o.IncludedChain = entities }
}

// WithBounds overrides bounds on the dispatched EXECUTE instead of decrementing parent bounds.
func WithBounds(b *types.BoundsData) ExecuteOption {
	return func(o *ExecuteOpts) { o.Bounds = b }
}

// WithChainDepth sets the dispatched EXECUTE's EXTENSION-CONTINUATION §3.9
// chain-depth counter. Only a continuation advancement dispatch uses it, at
// caller+1; every other dispatch inherits the caller's depth unchanged.
//
// The counter is the structural brake on a self-referential continuation
// loop — NOT ttl. §3.9 is explicit that "continuation advancement dispatches
// with fresh TTL/budget but inherits the chain depth counter", so a chain
// that dispatches back into its own trigger refills ttl every hop and is
// bounded only by this. That is why §3.9 lands before step 6's fresh bounds
// (arch ruling 15) rather than after.
//
// Deliberately NOT a bounds field: §3.9 pins it as a per-peer execution
// context counter that is not carried in system/bounds on the wire, so
// cross-peer chains reset it at each peer boundary. Each peer bounds its own
// local execution depth; global chain length is bounded by ttl on the wire.
func WithChainDepth(d uint64) ExecuteOption {
	return func(o *ExecuteOpts) { o.ChainDepth = &d }
}

// WithReactiveTrigger marks a handler-initiated advance dispatch as a reactive
// delivery trigger (PROPOSAL-CONTINUATION-STANDING-MODEL §3). The delivery
// mechanism — the inbox route that finds a continuation at a delivered path, or
// a subscription poke — sets this so the continuation advances under its OWN
// dispatch_capability without the trigger needing advance-cap on the path. A
// bare administrative `advance` EXECUTE never sets it and stays path-cap-gated.
// In-process only; no wire field (the authority split is a local check-site
// correction).
func WithReactiveTrigger() ExecuteOption {
	return func(o *ExecuteOpts) { o.ReactiveTrigger = true }
}

// HandlerContext provides the execution environment for handlers.
type HandlerContext struct {
	Author     crypto.PeerID
	AuthorHash hash.Hash
	// SessionPeerID is the authenticated session/connection peer — the
	// peer that holds the underlying connection over which this EXECUTE
	// arrived. For direct EXECUTE this equals Author (the wire-author);
	// for cross-peer dispatch (Bob's relay re-issues Alice's EXECUTE to
	// Charlie's relay) they diverge — Author stays Alice (wire signer),
	// SessionPeerID becomes Bob (the connecting peer). Used by handlers
	// whose policy is *placement-identity* rather than *authorization-
	// identity* — e.g. RELAY §3.2 `put_by == authenticated caller`
	// (cohort R6/R7 ratification: session-peer, not wire-author). Empty
	// for in-process / internal dispatches (no wire session).
	SessionPeerID    crypto.PeerID
	LocalPeerID      crypto.PeerID
	CallerCapability entity.Entity
	HandlerGrant     entity.Entity
	MatchingGrant    *types.GrantEntry // grant entry that passed CheckPermission (for constraints)
	Resource         *types.ResourceTarget
	Store            store.ContentStore
	LocationIndex    store.LocationIndex
	// CapabilityIndex is the observational hash→path index for
	// system/capability/token bindings (V7 v7.62 §5.1 capability_path_for).
	// Populated automatically by TreeSet/TreeRemove for cap entities; consumed
	// by is_revoked. May be nil in manually-built test contexts — TreeSet
	// gracefully no-ops the record when so.
	CapabilityIndex capability.CapabilityIndex
	HandlerPattern  string
	RequestID       string
	Bounds          *types.BoundsData
	// ChainDepth is the EXTENSION-CONTINUATION §3.9 chain-depth counter for
	// this execution context: how many continuation advancements deep this
	// dispatch sits. Incremented only by a continuation advancement dispatch
	// (see WithChainDepth); inherited unchanged by every other sub-dispatch.
	//
	// Zero at wire entry BY DESIGN, not by omission — §3.9 pins the counter as
	// per-peer and not carried in bounds, so a cross-peer chain resets it at
	// each peer boundary. Each peer bounds its own local execution depth.
	ChainDepth uint64
	// ReactiveTrigger is true when this execution is a reactive delivery-driven
	// advancement (set via WithReactiveTrigger by the inbox/subscription
	// delivery path), false for a bare administrative `advance` EXECUTE. Read by
	// the continuation advance handler to select the authority gate per
	// PROPOSAL-CONTINUATION-STANDING-MODEL §3 (the O1 signal). Sourced per-
	// dispatch from ExecuteOpts, NOT inherited from the parent context, so it
	// marks only the advance the delivery mechanism initiated — never its
	// onward chain dispatches.
	ReactiveTrigger bool
	Included        map[hash.Hash]entity.Entity
	// Execute dispatches a local or remote EXECUTE request from within a handler.
	// Injected by the Dispatcher at dispatch time to avoid import cycles.
	// Handlers call this to invoke other handlers, governed by capabilities and bounds.
	Execute func(ctx context.Context, uri, operation string, params entity.Entity, opts ...ExecuteOption) (*Response, error)
	// GoAsync runs fn on the dispatcher's bounded async-dispatch pool for
	// fire-and-forget work that must not block the serve loop (e.g. inbox
	// receive → continuation advance). Injected by the Dispatcher. Returns
	// false WITHOUT running fn when the pool is saturated or stopped — the
	// handler must then apply backpressure (durable-mailbox fallback / 429)
	// rather than spawn an unbounded goroutine. Nil when no dispatcher wired
	// the context (manually-built test contexts): callers fall back to a
	// plain `go fn()` so behavior is preserved off the bounded path.
	GoAsync func(fn func()) bool
	// ConnectionState holds *protocol.ConnectionState for connect handlers.
	// Typed as interface{} to avoid import cycle (handler cannot import protocol).
	ConnectionState interface{}
}

// ExtractResourcePath returns the first resource target path, or "" if none.
func (hctx *HandlerContext) ExtractResourcePath() string {
	if hctx.Resource != nil && len(hctx.Resource.Targets) > 0 {
		return hctx.Resource.Targets[0]
	}
	return ""
}

// CheckPathCapability performs a Level 2 capability check for the given
// operation and path. Returns a 403 error response if the caller's capability
// does not cover the path, or nil if the check passes (or no capability present).
func (hctx *HandlerContext) CheckPathCapability(operation, path string) *Response {
	if !hctx.CallerCapability.ContentHash.IsZero() {
		capData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
		if err == nil {
			// Cap-resource canonicalization uses the chain-root namespace which,
			// per VerifyChain Site 3, equals the local peer for any validated
			// chain (PROPOSAL §PR-8 / V7 §5.5).
			if !capability.CheckPathPermission(operation, path, capData, hctx.HandlerPattern, hctx.LocalPeerID, hctx.LocalPeerID) {
				resp, err := NewErrorResponse(403, "capability_denied",
					"insufficient capability for path: "+path)
				if err != nil {
					return &Response{Status: 403}
				}
				return resp
			}
		}
	}
	return nil
}

// TreeSet writes a hash to the location index with execution context from this
// handler context. All handler writes to the tree MUST use this method (not
// LocationIndex.Set directly) so that execution context propagates to sync
// hooks and event consumers (history, subscriptions, etc.).
//
// The capability recorded in the mutation context is selected per-write:
// if the caller's capability covers the write path, it is used (caller-authorized);
// otherwise the handler's own grant is used (handler-authorized).
// See EXPLORATION-EXECUTION-CONTEXT-AND-GRANT-AUTHORITY §4.
//
// A non-nil error means the binding did NOT commit (storage failure: SQLITE_BUSY
// past the configured timeout, disk full, corruption, etc.). Per V7 §2688 the
// caller MUST propagate the error and abort the enclosing operation — partial
// ingestion state is forbidden.
func (hctx *HandlerContext) TreeSet(path string, h hash.Hash, operation string) (*store.CascadeResult, error) {
	ctx := hctx.mutationContext(path, operation)
	var (
		cr  *store.CascadeResult
		err error
	)
	if cw, ok := hctx.LocationIndex.(store.ContextualWriter); ok {
		cr, err = cw.SetWithContext(path, h, ctx)
	} else {
		err = hctx.LocationIndex.Set(path, h)
	}
	// Observational cap-binding index: V7 v7.62 §5.1 capability_path_for
	// is populated by recording every successful tree-bind of a
	// system/capability/token entity. Lookup at is_revoked time then walks
	// hash → path → check binding (defense in depth) and feeds the marker
	// check at system/capability/revocations/{root_hash_hex}.
	if err == nil {
		hctx.recordCapBinding(path, h)
	}
	return cr, err
}

// TreeRemove removes a path from the location index with execution context.
// All handler removals from the tree MUST use this method.
func (hctx *HandlerContext) TreeRemove(path string, operation string) (hash.Hash, bool, *store.CascadeResult) {
	ctx := hctx.mutationContext(path, operation)
	var (
		h  hash.Hash
		ok bool
		cr *store.CascadeResult
	)
	if cw, ok2 := hctx.LocationIndex.(store.ContextualWriter); ok2 {
		h, ok, cr = cw.RemoveWithContext(path, ctx)
	} else {
		h, ok = hctx.LocationIndex.Remove(path)
	}
	if ok {
		hctx.forgetCapBinding(h)
	}
	return h, ok, cr
}

// recordCapBinding registers (capHash → path) in the capability index if the
// bound entity is a system/capability/token. Non-cap binds are ignored.
func (hctx *HandlerContext) recordCapBinding(path string, h hash.Hash) {
	if hctx.CapabilityIndex == nil || hctx.Store == nil {
		return
	}
	ent, ok := hctx.Store.Get(h)
	if !ok || ent.Type != types.TypeCapToken {
		return
	}
	hctx.CapabilityIndex.Record(h, path)
}

// forgetCapBinding drops the capability-index record for an unbound entity if
// it was a system/capability/token.
func (hctx *HandlerContext) forgetCapBinding(h hash.Hash) {
	if hctx.CapabilityIndex == nil || hctx.Store == nil {
		return
	}
	ent, ok := hctx.Store.Get(h)
	if !ok || ent.Type != types.TypeCapToken {
		return
	}
	hctx.CapabilityIndex.Forget(h)
}

// mutationContext builds a MutationContext for a specific tree write.
// Capability selection follows the three authorization modes:
//   - Caller-authorized: caller capability covers the write path → use it
//   - Handler-authorized: caller capability absent or doesn't cover path → handler grant
//   - Autonomous: no caller capability → handler grant
func (hctx *HandlerContext) mutationContext(writePath, operation string) *store.MutationContext {
	ctx := &store.MutationContext{
		AuthorHash:     hctx.AuthorHash,
		HandlerPattern: hctx.HandlerPattern,
		Operation:      operation,
	}
	ctx.CapabilityHash = hctx.selectCapability(writePath, operation)
	// CallerCapabilityHash is only stored when it differs from CapabilityHash
	// (W6) — i.e., handler-authorized writes within externally-triggered chains.
	// Absent when redundant (caller-authorized, where capability IS the caller's
	// grant) and absent for autonomous operations (no external caller).
	if !hctx.CallerCapability.ContentHash.IsZero() && hctx.CallerCapability.ContentHash != ctx.CapabilityHash {
		ctx.CallerCapabilityHash = hctx.CallerCapability.ContentHash
	}
	if hctx.Bounds != nil {
		ctx.ChainID = hctx.Bounds.ChainID
		ctx.ParentChainID = hctx.Bounds.ParentChainID
		ctx.CascadeDepth = hctx.Bounds.CascadeDepth
	}
	return ctx
}

// selectCapability determines which capability authorized a specific write.
// If the caller's capability covers the write path, return it (caller-authorized).
// Otherwise return the handler's own grant (handler-authorized / autonomous).
func (hctx *HandlerContext) selectCapability(writePath, operation string) hash.Hash {
	if !hctx.CallerCapability.ContentHash.IsZero() {
		// Check if the caller's capability actually covers this write path
		// for the specific operation being performed.
		capData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
		if err == nil && capability.CheckPathPermission(operation, writePath, capData, hctx.HandlerPattern, hctx.LocalPeerID, hctx.LocalPeerID) {
			return hctx.CallerCapability.ContentHash
		}
	}
	// Caller capability absent or doesn't cover this path — handler's own authority.
	return hctx.HandlerGrant.ContentHash
}
