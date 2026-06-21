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
	return rootCtx.Execute(ctx, req.URI, req.Operation, req.Params,
		handler.WithCapability(req.CallerCapability))
}

// makeLocalExecute returns a closure that dispatches a local Execute request
// through the handler registry, inheriting capability and bounds from the
// parent context. For remote URIs it delegates to RemoteExecute.
// Supports variadic ExecuteOption for overriding resource, capability, bounds, etc.
func (d *Dispatcher) makeLocalExecute(parentCtx context.Context, callerCtx *handler.HandlerContext) func(ctx context.Context, uri, operation string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
	return func(ctx context.Context, uri, operation string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		execOpts := handler.ApplyOpts(opts)

		// Determine if this is a local or remote URI.
		handlerPath := entity.ExtractHandlerPath(uri)
		if isRemoteURI(uri, d.LocalPeerID) {
			if d.RemoteExecute == nil {
				return nil, fmt.Errorf("remote execute not available")
			}
			// Pass resource: prefer explicit opt, then inherited from parent.
			resource := execOpts.Resource
			if resource == nil {
				resource = callerCtx.Resource
			}
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
				resp, _ := handler.NewErrorResponse(500, "internal", "failed to decode handler entity")
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
		if !capability.CheckPermission(types.ExecuteData{Operation: operation}, capData, pattern, d.LocalPeerID, granterPeerID) {
			resp, _ := handler.NewErrorResponse(403, "capability_denied", "insufficient capability for handler scope: "+pattern)
			return resp, nil
		}

		// Determine bounds: explicit override from opts, or decrement parent bounds.
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

		// Determine resource: explicit override from opts, or inherit from parent.
		// Normalize entity://localPeer/path → path so local-dispatch callers can
		// pass URI-form resources (e.g. continuation OnError.URI), matching the
		// wire-entry handleExecute behavior at the top of this file.
		childResource := callerCtx.Resource
		if execOpts.Resource != nil {
			childResource = execOpts.Resource
		}
		childResource = normalizeResourceTargets(childResource, d.LocalPeerID)

		// CallerCapability is the chain initiator and propagates unchanged
		// across sub-dispatches (V7 §6.8, PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §6.2).
		// WithCapability only affects the level-1 cap check above — it must NOT
		// overwrite the propagated initiator, which history attribution relies on.
		childCallerCap := callerCtx.CallerCapability

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
			Included:         callerCtx.Included,
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
				resp, _ := handler.NewErrorResponse(501, "not_implemented",
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
