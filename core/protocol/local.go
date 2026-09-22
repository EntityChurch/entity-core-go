package protocol

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// DispatchLocalEnvelope routes a locally-originated envelope through the dispatch pipeline.
// Unlike DispatchEnvelope (for wire-received messages), this checks if the EXECUTE targets
// a remote peer and routes through RemoteExecute if so. This is the correct entry point
// for subscription delivery and any locally-originated dispatch that may target remote peers.
func (d *Dispatcher) DispatchLocalEnvelope(ctx context.Context, env entity.Envelope) (entity.Envelope, error) {
	// Check if the envelope targets a remote peer.
	if env.Root.Type == types.TypeExecute {
		execData, err := types.ExecuteDataFromEntity(env.Root)
		if err == nil && isRemoteURI(execData.URI, d.LocalPeerID) {
			if d.RemoteExecute == nil {
				return entity.Envelope{}, fmt.Errorf("remote execute not available for URI %s", execData.URI)
			}
			// Decode params entity from the EXECUTE's raw params field.
			var params entity.Entity
			if len(execData.Params) > 0 {
				var paramsEnt entity.Entity
				if err := ecf.Decode(execData.Params, &paramsEnt); err == nil {
					params = paramsEnt
				}
			}
			// Pass deliver_to if present on the EXECUTE.
			var async []*AsyncDelivery
			if execData.DeliverTo != nil && !execData.DeliverToken.IsZero() {
				if dtEnt, ok := env.FindIncluded(execData.DeliverToken); ok {
					async = append(async, &AsyncDelivery{
						DeliverTo:    execData.DeliverTo,
						DeliverToken: dtEnt,
					})
				}
			}
			// Thread the envelope's Included through to the remote
			// dispatch. This is the request-side dual of V7 v7.49 §3.3
			// (result-side equivalence): when a locally-originated envelope
			// targets a remote peer, its Included payload (e.g. the
			// EXTENSION-SUBSCRIPTION v3.14 include_payload entity bundled
			// by the subscription engine) MUST ride to the remote side so
			// the receiver's continuation chain can resolve hash refs from
			// hctx.Included (e.g. deref_included). Without this, the
			// envelope.Included on the source dispatcher is silently
			// dropped before the wire — exactly the gap flagged in
			// DOUBTS-CONVERGENT-MIRRORING-FOR-ARCH §7.
			//
			// AsyncDelivery.Extras is the existing pipe (added for
			// cross-peer subscribe's deliver_token + signature carrying);
			// reuse it. CreateAuthenticatedExecute dedupes auth-chain
			// entries on the remote side (helpers.go:134), so over-
			// inclusion is safe.
			if len(env.Included) > 0 {
				if len(async) == 0 {
					async = append(async, &AsyncDelivery{})
				}
				if async[0].Extras == nil {
					async[0].Extras = make(map[hash.Hash]entity.Entity, len(env.Included))
				}
				for h, ent := range env.Included {
					if _, present := async[0].Extras[h]; !present {
						async[0].Extras[h] = ent
					}
				}
			}
			resp, err := d.RemoteExecute(ctx, execData.URI, execData.Operation, params, execData.Resource, async...)
			if err != nil {
				return entity.Envelope{}, fmt.Errorf("remote dispatch: %w", err)
			}
			return d.makeResponse(execData.RequestID, resp)
		}
	}
	// Local dispatch — use standard path.
	return d.DispatchEnvelope(ctx, env, nil)
}

// LocalExecuteRequest carries the parameters needed to dispatch an EXECUTE
// in-process via the V7 §6.6 tree-walk pipeline. Used by SDK executors so
// that local dispatch honors the spec's "tree is source of truth" contract
// for all handler types — language-native AND entity-native — and produces
// observably identical results to over-the-wire dispatch.
//
// Envelope-level signature verification is skipped: the caller is in-process
// and supplies its own CallerCapability. The dispatcher still performs the
// RL1 capability scope check and the V7 §6.8 handler-grant validation.
type LocalExecuteRequest struct {
	URI       string
	Operation string
	Params    entity.Entity
	Resource  *types.ResourceTarget

	// CallerCapability is the cap the dispatcher checks the operation
	// against (RL1) and propagates as chain initiator. The SDK typically
	// supplies its peer-owner self-cap minted at startup.
	CallerCapability entity.Entity

	// Author identifies the request's logical author. For SDK self-dispatch
	// this is the local peer's id / identity-hash.
	Author     crypto.PeerID
	AuthorHash hash.Hash

	// Bounds optionally constrains TTL / depth for the dispatch tree.
	Bounds *types.BoundsData

	// RequestID is the dispatch-chain identifier used by continuation /
	// history. Optional; handlers tolerate empty.
	RequestID string

	// Included carries extra entities the request needs in handler scope
	// (e.g. the subscribe deliver_token). Merged into the child hctx's
	// Included map verbatim.
	Included map[hash.Hash]entity.Entity
}

// DispatchLocalExecute performs an in-process EXECUTE through the V7 §6.6
// tree-walk dispatch pipeline. This is the entry point SDK executors call
// for local URIs to ensure they reach the same dispatch machinery a wire
// EXECUTE would — entity-native handlers included.
//
// For cross-peer URIs the call routes through RemoteExecute (same branching
// as a handler-internal sub-dispatch via hctx.Execute).
//
// Returns the unwrapped *handler.Response; non-2xx responses come back as
// status fields, not Go errors, matching the hctx.Execute contract.
func (d *Dispatcher) DispatchLocalExecute(ctx context.Context, req LocalExecuteRequest) (*handler.Response, error) {
	rootCtx := &handler.HandlerContext{
		Author:           req.Author,
		AuthorHash:       req.AuthorHash,
		LocalPeerID:      d.LocalPeerID,
		CallerCapability: req.CallerCapability,
		Resource:         req.Resource,
		Store:            d.Store,
		LocationIndex:    d.LocationIndex,
		CapabilityIndex:  d.CapabilityIndex,
		RequestID:        req.RequestID,
		Bounds:           req.Bounds,
		Included:         req.Included,
	}
	rootCtx.Execute = d.makeLocalExecute(ctx, rootCtx)
	rootCtx.GoAsync = d.submitAsync
	// Entry-point dispatch (the in-process equivalent of wire EXECUTE):
	// the caller's capability is the L1 gate, mirroring execute.go:133's
	// FindMatchingGrant check at wire entry. V7 v7.49 §6.8's "gate on the
	// handler grant, never on caller cap" applies to sub-dispatch from
	// inside a handler — this is the entry, so the explicit cap option
	// supplies the authority.
	//
	// WithResource is REQUIRED here and mirrors wire entry, where handleExecute
	// seeds hctx.Resource = normalizeResourceTargets(execData.Resource) directly
	// on the handler's context (execute.go). This entry point instead re-dispatches
	// through makeLocalExecute, whose child context takes its resource from
	// execOpts.Resource (NOT callerCtx.Resource — the §5.2 sub-dispatch rule that a
	// child inherits no parent resource). So rootCtx.Resource above never reaches the
	// handler; without passing it as the opt, every in-process ENTRY dispatch that
	// names a resource dropped it to nil — the confused inverse of the §5.2 rule,
	// applied to an entry that is NOT a sub-dispatch. (Found by workbench-go with a
	// kernel-level reproducer; the gap was invisible because
	// subdispatch_resource_dimension_test.go exercises both sub-dispatch directions
	// but never enters through DispatchLocalExecute, which is how every SDK consumer
	// dispatches.)
	return rootCtx.Execute(ctx, req.URI, req.Operation, req.Params,
		handler.WithCapability(req.CallerCapability),
		handler.WithResource(req.Resource))
}

// makeLocalExecute returns a closure that dispatches a local Execute request
// through the handler registry, inheriting capability and bounds from the
// parent context. For remote URIs it delegates to RemoteExecute.
// Supports variadic ExecuteOption for overriding resource, capability, bounds, etc.
func (d *Dispatcher) makeLocalExecute(parentCtx context.Context, callerCtx *handler.HandlerContext) func(ctx context.Context, uri, operation string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
	return func(ctx context.Context, uri, operation string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		execOpts := handler.ApplyOpts(opts)

		handlerPath := entity.ExtractHandlerPath(uri)

		// chain_depth + bounds are resolved once, ahead of the local/remote
		// split. PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §3/§4 makes chain_depth
		// a system/bounds field that MUST ride a cross-peer EXECUTE and be
		// inherited across the boundary, exactly as cascade_depth is — the same
		// value that seeds the child context on a local dispatch. Before this,
		// the remote branch dropped bounds and the counter reset every hop, so
		// nothing globally bounded a cross-peer chain.
		//
		// §3.9 chain depth: a continuation advancement passes caller+1 (the sole
		// incrementing site is ext/continuation advanceForward); every other
		// dispatch inherits unchanged. The ceiling is enforced here in the
		// dispatch layer because §3.9 puts it there — a continuation that refills
		// ttl each hop has no other structural brake, and a handler cannot be
		// trusted to bound its own recursion. Response is 429 bounds_exceeded,
		// matching how ttl/budget exhaustion already surfaces (§3.9 groups the
		// three as one class; its distinct-reason suspension handler is a MAY Go
		// does not register). Deliberately NOT the 400 chain_depth_exceeded of
		// V7 §4.10(b): that is the capability-chain counter sharing a name.
		childDepth := callerCtx.ChainDepth
		if execOpts.ChainDepth != nil {
			childDepth = *execOpts.ChainDepth
		}
		if childDepth > d.maxChainDepth() {
			resp, _ := handler.NewErrorResponse(429, "bounds_exceeded",
				fmt.Sprintf("continuation chain depth %d exceeds maximum %d (EXTENSION-CONTINUATION §3.9)",
					childDepth, d.maxChainDepth()))
			return resp, nil
		}

		// Determine bounds: explicit override from opts, or decrement parent
		// bounds; then stamp the depth in so it is inherited across the wire (§4).
		var childBounds *types.BoundsData
		if execOpts.Bounds != nil {
			childBounds = execOpts.Bounds
		} else {
			var err error
			childBounds, err = decrementBounds(callerCtx.Bounds)
			if err != nil {
				resp, _ := handler.NewErrorResponse(429, "bounds_exceeded", err.Error())
				return resp, nil
			}
		}
		childBounds = stampChainDepth(childBounds, childDepth)

		// Determine if this is a local or remote URI.
		if isRemoteURI(uri, d.LocalPeerID) {
			if d.RemoteExecute == nil {
				return nil, fmt.Errorf("remote execute not available")
			}
			// A sub-dispatch that names no resource has none — the remote child
			// MUST NOT inherit the parent's (§5.2, 0.8.2; arch ROUTING-2026-08-18-g
			// §5). The receiving peer authorizes this EXECUTE through its own
			// dispatch_request check, so the §5.2 dimension binds there; sending an
			// inherited resource would populate the remote child's context with a
			// target the caller never named. Explicit opt only, nil otherwise.
			resource := execOpts.Resource
			// Pass deliver_to for async delivery on the remote peer.
			// The deliver_token is the handler grant for the inbox handler —
			// authorizes the remote peer to deliver the result back.
			// Carry deliver_to (async result return) AND, for cross-peer
			// continuation dispatch, the scoped dispatch_capability + its
			// full authority chain (EXTENSION-CONTINUATION §4.2 case 3 /
			// §4.3 / §8.1). All ride the existing AsyncDelivery carrier;
			// nil when none apply (ordinary remote dispatch, unchanged).
			var ad *AsyncDelivery
			if execOpts.DeliverTo != nil {
				ad = &AsyncDelivery{
					DeliverTo:    execOpts.DeliverTo,
					DeliverToken: callerCtx.HandlerGrant,
				}
				// §4.2 Step 4 line 2: generate_internal_deliver_token. The
				// caller's HandlerGrant above is NOT a deliver_token — its
				// grantee is the caller, so the peer we are dispatching to
				// cannot author the delivery under it and has to improvise
				// (see mintDeliverToken for what each impl improvises, and
				// why go→go passed while go→rust did not). Mint the real
				// one: self-rooted, granted to THAT peer, scoped to this one
				// delivery.
				//
				// Fail-soft by design. A mint failure leaves the pre-existing
				// HandlerGrant in place, so this is strictly additive: the
				// paths that worked before still take exactly the route they
				// took before, and nothing new can 500 a dispatch that used
				// to succeed.
				if targetURI, uerr := entity.ParseURI(uri); execOpts.MintDeliverToken && uerr == nil {
					dtCap, dtSig, dtIdent, mintErr := d.mintDeliverToken(crypto.PeerID(targetURI.PeerID), execOpts.DeliverTo)
					if mintErr != nil {
						d.debugf("deliver_token: not minted, falling back to caller handler grant: %v", mintErr)
					} else {
						ad.DeliverToken = dtCap
						deliverTokenExtras(ad, dtCap, dtSig, dtIdent)
						d.debugf("deliver_token: minted for %s scoped to %s:%s",
							targetURI.PeerID, execOpts.DeliverTo.URI, execOpts.DeliverTo.Operation)
					}
				}
			}
			if execOpts.Capability.Type != "" || len(execOpts.IncludedChain) > 0 {
				if ad == nil {
					ad = &AsyncDelivery{}
				}
				if execOpts.Capability.Type != "" {
					capCopy := execOpts.Capability
					ad.CapabilityOverride = &capCopy
				}
				if len(execOpts.IncludedChain) > 0 {
					if ad.Extras == nil {
						ad.Extras = make(map[hash.Hash]entity.Entity, len(execOpts.IncludedChain))
					}
					for _, e := range execOpts.IncludedChain {
						ad.Extras[e.ContentHash] = e
					}
				}
			}
			// Rung 1 (PROPOSAL §3): bounds MUST ride the cross-peer EXECUTE —
			// chain_id / chain_depth / ttl / budget. This branch previously
			// dropped them, so the counter reset at the boundary and nothing
			// globally bounded a cross-peer chain. stampChainDepth left bounds
			// nil for a non-chain dispatch, so ordinary remote dispatch is
			// unchanged (no bounds invented).
			if childBounds != nil {
				if ad == nil {
					ad = &AsyncDelivery{}
				}
				ad.Bounds = childBounds
			}
			// PD-2 (0.8.2.17, §5.2): authorize this locally-originated
			// sub-dispatch BEFORE it leaves the peer. Gated on being inside an
			// executing handler (HandlerPattern set) — that is the
			// "sub-dispatch" the rule governs and the point where the ambient
			// authority is a handler grant. A top-level SELF origination
			// through DispatchLocalExecute (rootCtx has no HandlerPattern) is
			// the peer acting as itself and is authorized by the TARGET on
			// receipt, not pre-gated here (the §5.2 SELF authority case, whose
			// authority is the caller capability verified at the far end).
			//
			// D4 (0.8.2.18) scope note: caller-directed AND continuation
			// (advance/resume) originations reach this gate — both carry a
			// HandlerPattern (continuation runs via hctx.Execute, a
			// makeLocalExecute closure). Handler-AUTONOMOUS subscription
			// delivery does NOT: it originates via DispatchLocalEnvelope →
			// RemoteExecute (ext/subscription/delivery.go) and never enters this
			// closure. Its PD-2 classification is unruled and 3-way divergent —
			// see the pinned interim + spec-issue 2026-09-10-a at that call site.
			if callerCtx.HandlerPattern != "" {
				if code, msg, ok := d.authorizeOutboundSubdispatch(uri, operation, resource, execOpts.Capability, execOpts.IncludedChain, callerCtx.HandlerGrant); !ok {
					resp, _ := handler.NewErrorResponse(403, code, msg)
					return resp, nil
				}
			}
			var async []*AsyncDelivery
			if ad != nil {
				async = append(async, ad)
			}
			return d.RemoteExecute(ctx, uri, operation, params, resource, async...)
		}

		// Resolve handler from the tree (V7 §6.6).
		res, errCode, ok := d.resolveHandler(handlerPath)
		if !ok {
			switch errCode {
			case "no_impl":
				resp, _ := handler.NewErrorResponse(404, "not_found",
					"handler bound at "+handlerPath+" has neither expression_path nor compiled implementation")
				return resp, nil
			case "decode_failed":
				resp, _ := handler.NewErrorResponse(500, "internal_error", "failed to decode handler entity")
				return resp, nil
			default:
				resp, _ := handler.NewErrorResponse(404, "not_found", "no handler for path: "+handlerPath)
				return resp, nil
			}
		}
		pattern := res.pattern

		// Level 1 capability check on the child handler pattern.
		// V7 v7.49 §6.8: the dispatch decision is made on the executing
		// handler's grant, never on the propagated caller capability.
		// Order: explicit WithCapability override → parent's HandlerGrant.
		// No fallback to CallerCapability (the confused-deputy door).
		grantToCheck := execOpts.Capability
		if grantToCheck.Type == "" {
			grantToCheck = callerCtx.HandlerGrant
		}
		if grantToCheck.Type == "" {
			resp, _ := handler.NewErrorResponse(403, "missing_handler_grant",
				"sub-dispatch refused: parent has no HandlerGrant and no explicit capability was supplied")
			return resp, nil
		}
		capData, err := types.CapabilityTokenDataFromEntity(grantToCheck)
		if err != nil {
			return nil, fmt.Errorf("decode capability: %w", err)
		}
		granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, d.Store, d.LocalPeerID)
		if gerr != nil {
			resp, _ := handler.NewErrorResponse(403, "capability_denied", "granter unresolvable: "+gerr.Error())
			return resp, nil
		}
		// Determine the child's resource target BEFORE the L1 check, and hand it
		// TO the check. §5.2's Dimension 3 tests `resource_target is not null` —
		// the field, not any wire-entry door — so a sub-dispatch that computes a
		// resource, propagates it as the child's authorization target (below), and
		// yet passes the check a literal that omits it has MOVED the resource past
		// its own scope check (arch ROUTING-2026-08-18-d §2, SA-PY-9). §6.2 assigns
		// `system/handler:register`'s install-path authorization to exactly this
		// check, and register always carries a resource (the pattern).
		//
		// A sub-dispatch that names NO resource has NO resource (§5.2, normative
		// 0.8.2; arch ROUTING-2026-08-18-g §5): the child MUST NOT inherit the
		// parent's resource targets — not into this check (nil → Dimension 3
		// deferred to the handler, exactly as the wire path when resource is
		// absent) and not into the child context below. go, py and rust are
		// aligned on this after go recommended against its own prior inheritance.
		// Inheritance would manufacture a target the caller never named — a
		// confused-deputy shape reached from the fix for a confused-deputy shape.
		// Normalize entity://localPeer/path → path when a resource IS named, so
		// local-dispatch callers can pass URI-form resources (e.g. continuation
		// OnError.URI), matching the wire-entry handleExecute behavior above.
		childResource := normalizeResourceTargets(execOpts.Resource, d.LocalPeerID)
		if !capability.CheckPermission(types.ExecuteData{Operation: operation, Resource: childResource}, capData, pattern, d.LocalPeerID, granterPeerID) {
			resp, _ := handler.NewErrorResponse(403, "capability_denied", "insufficient capability for handler scope: "+pattern)
			return resp, nil
		}

		// Resolve and validate the child handler's grant — same V7 §6.2 / §6.8
		// validation as wire-entry dispatch. A handler-internal sub-dispatch
		// cannot use a foreign grant for the child handler.
		childEntityNative := res.handlerData.ExpressionPath != ""
		childHandlerGrant, gErr := d.loadValidatedGrant(pattern)
		if gErr != nil {
			if gErr.code == "missing" && !childEntityNative {
				// Compiled child handler without a seeded grant — allow.
			} else {
				resp, _ := handler.NewErrorResponse(gErr.status, gErr.code, gErr.message)
				return resp, nil
			}
		}

		// (childResource was resolved above, before the L1 resource-dimension
		// check, and is reused here as the child context's authorization target.)

		// CallerCapability is the chain initiator and propagates unchanged
		// across sub-dispatches (V7 §6.8, PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §6.2).
		// WithCapability only affects the level-1 cap check above — it must NOT
		// overwrite the propagated initiator, which history attribution relies on.
		childCallerCap := callerCtx.CallerCapability
		// EXTENSION-CONTINUATION §3.6b: a continuation advance is a new chain
		// root and re-roots the initiator at its own dispatch_capability.
		if execOpts.CallerCapabilityOverride.Type != "" {
			childCallerCap = execOpts.CallerCapabilityOverride
		}

		childCtx := &handler.HandlerContext{
			Author:           callerCtx.Author,
			AuthorHash:       callerCtx.AuthorHash,
			LocalPeerID:      callerCtx.LocalPeerID,
			CallerCapability: childCallerCap,
			HandlerGrant:     childHandlerGrant,
			Resource:         childResource,
			Store:            callerCtx.Store,
			LocationIndex:    callerCtx.LocationIndex,
			CapabilityIndex:  callerCtx.CapabilityIndex,
			HandlerPattern:   pattern,
			RequestID:        callerCtx.RequestID,
			Bounds:           childBounds,
			ChainDepth:       childDepth,
			// ReactiveTrigger is sourced per-dispatch from the option, NOT
			// inherited from callerCtx: it marks only the one advance the
			// delivery mechanism initiated (PROPOSAL-CONTINUATION-STANDING-MODEL
			// §3). Propagating it would wrongly tag the continuation's onward
			// chain dispatches as reactive too.
			ReactiveTrigger: execOpts.ReactiveTrigger,
			Included:        callerCtx.Included,
		}
		childCtx.Execute = d.makeLocalExecute(ctx, childCtx)
		childCtx.GoAsync = d.submitAsync

		req := &handler.Request{
			Path:      handlerPath,
			Operation: operation,
			Params:    params,
			Context:   childCtx,
		}

		// Build the handler invocation. Entity-native and compiled handlers
		// go through the same sync and deliver_to paths from here — the
		// dispatcher honors deliver_to uniformly regardless of handler
		// shape. The only difference is which line invokes the
		// implementation.
		var entityNativeExprPath string
		if res.handlerData.ExpressionPath != "" {
			if d.EvaluateExpression == nil {
				resp, _ := handler.NewErrorResponse(501, "unsupported_operation",
					"compute extension not wired for entity-native dispatch")
				return resp, nil
			}
			entityNativeExprPath = qualifyIfRelative(string(d.LocalPeerID), res.handlerData.ExpressionPath)
		}
		invoke := func(ctx context.Context) (*handler.Response, error) {
			// Dispatch hooks fire entry+exit around handler-from-handler
			// dispatches too (GUIDE-INSPECTABILITY v1.1 §2.1 #3). Same
			// fire-site contract as handleExecute.invoke.
			d.fireDispatchHooks(handler.DispatchEvent{
				Phase:      handler.DispatchEntry,
				TargetURI:  uri,
				Operation:  operation,
				ParamsHash: params.ContentHash,
				RequestID:  callerCtx.RequestID,
				Timestamp:  time.Now(),
			})
			var resp *handler.Response
			var err error
			if entityNativeExprPath != "" {
				resp, err = d.EvaluateExpression(ctx, entityNativeExprPath, req)
			} else {
				resp, err = res.compiled.Handle(ctx, req)
			}
			exit := handler.DispatchEvent{
				Phase:      handler.DispatchExit,
				TargetURI:  uri,
				Operation:  operation,
				ParamsHash: params.ContentHash,
				RequestID:  callerCtx.RequestID,
				Timestamp:  time.Now(),
			}
			if resp != nil {
				exit.ResponseStatus = resp.Status
				exit.ResponseHash = resp.Result.ContentHash
			}
			d.fireDispatchHooks(exit)
			return resp, err
		}

		// Async delivery for local dispatch: when deliver_to is set on
		// a handler-initiated local EXECUTE, run the handler in a
		// goroutine and route its response through deliverToInbox.
		// Mirrors the wire-entry async path and the cross-peer
		// local-execute path so all three dispatch entry points have
		// symmetric deliver_to semantics across compiled and entity-
		// native handlers.
		if execOpts.DeliverTo != nil {
			deliverTokenEntity := callerCtx.HandlerGrant
			if deliverTokenEntity.ContentHash.IsZero() {
				resp, _ := handler.NewErrorResponse(400, "missing_deliver_token",
					"deliver_to set on local execute but caller has no handler grant to use as deliver_token")
				return resp, nil
			}
			// The deliver-EXECUTE's envelope auth check (VerifyRequest)
			// requires the deliver_token cap's signature to be in
			// env.Included. Reconstruct it here and prepend to the
			// originalIncluded map deliverToInbox carries through.
			localIdentity, idErr := d.LocalKeypair.IdentityEntity()
			if idErr != nil {
				resp, _ := handler.NewErrorResponse(500, "internal_error",
					"derive local identity for deliver_token signature")
				return resp, nil
			}
			capSig := d.LocalKeypair.Sign(deliverTokenEntity.ContentHash.Bytes())
			capSigEntity, sigErr := types.SignatureData{
				Target:    deliverTokenEntity.ContentHash,
				Signer:    localIdentity.ContentHash,
				Algorithm: crypto.KeyTypeString(d.LocalKeypair.KeyType),
				Signature: capSig,
			}.ToEntity()
			if sigErr != nil {
				resp, _ := handler.NewErrorResponse(500, "internal_error",
					"build deliver_token signature entity")
				return resp, nil
			}
			extendedIncluded := make(map[hash.Hash]entity.Entity, len(callerCtx.Included)+1)
			for h, ent := range callerCtx.Included {
				extendedIncluded[h] = ent
			}
			extendedIncluded[capSigEntity.ContentHash] = capSigEntity
			synthExecData := types.ExecuteData{
				RequestID:    callerCtx.RequestID,
				URI:          handlerPath,
				Operation:    operation,
				DeliverTo:    execOpts.DeliverTo,
				DeliverToken: deliverTokenEntity.ContentHash,
			}
			// Same bounded-pool + backpressure semantics as the wire-entry
			// async path (EXTENSION-INBOX §9.1 MUST: handler-initiated
			// deliver_to sub-dispatches follow wire-entry async-spawning
			// semantics). Pool saturated → 429, not an unbounded goroutine.
			if !d.submitAsync(func() {
				resp, herr := invoke(ctx)
				if herr != nil {
					d.debugf("local async delivery: handler error: %v", herr)
					return
				}
				if resp == nil {
					return
				}
				if err := d.deliverToInbox(ctx, synthExecData, resp, deliverTokenEntity, extendedIncluded); err != nil {
					d.debugf("local async delivery: delivery failed: %v", err)
				}
			}) {
				d.debugf("local async delivery: dispatch pool saturated, returning 429")
				resp, _ := handler.NewErrorResponse(429, "async_dispatch_overflow",
					"async delivery pool saturated; retry later")
				return resp, nil
			}
			// 202 Accepted — per EXTENSION-INBOX v5.6 §4.5, async
			// acknowledgements carry no result body (result: null).
			// Matches the wire-entry path's make202Response shape
			// (response.Result is CBOR null).
			return &handler.Response{Status: 202}, nil
		}

		return invoke(ctx)
	}
}

// decrementBounds creates a copy of bounds with TTL decremented by 1.
// Returns an error if TTL is already exhausted.
