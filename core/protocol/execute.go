package protocol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)


// DispatchEnvelope processes an incoming wire envelope from a remote peer.
// Returns an execute response envelope, or an error.
// For locally-originated envelopes that may target remote peers, use DispatchLocalEnvelope.
func (d *Dispatcher) DispatchEnvelope(ctx context.Context, env entity.Envelope, connState *ConnectionState) (entity.Envelope, error) {
	// Validate all entity hashes.
	if err := env.ValidateAll(); err != nil {
		d.diagnoseEnvelope("incoming", env)
		return entity.Envelope{}, fmt.Errorf("validate envelope: %w", err)
	}

	root := env.Root
	d.debugf("dispatch: root_type=%s", root.Type)

	switch root.Type {
	case types.TypeExecute:
		return d.handleExecute(ctx, env, connState)
	case types.TypeExecuteResponse:
		// Responses are correlated by the caller, not dispatched.
		return entity.Envelope{}, fmt.Errorf("unexpected execute response in dispatch")
	default:
		return entity.Envelope{}, fmt.Errorf("unknown root type: %s", root.Type)
	}
}

func (d *Dispatcher) handleExecute(ctx context.Context, env entity.Envelope, connState *ConnectionState) (entity.Envelope, error) {
	execData, err := types.ExecuteDataFromEntity(env.Root)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("decode execute: %w", err)
	}

	handlerPath := entity.ExtractHandlerPath(execData.URI)
	d.debugf("execute: req=%s uri=%s op=%s", execData.RequestID, execData.URI, execData.Operation)

	// Connect path: no auth required, but only before connection is established.
	if handlerPath == connectPath || (len(handlerPath) > len(connectPath) && handlerPath[:len(connectPath)+1] == connectPath+"/") {
		if connState != nil && connState.Completed {
			return d.makeErrorResponse(execData.RequestID, 409, "connection_already_established", "connection already established")
		}
		if connState != nil {
			if err := ValidateConnectionSequence(connState, execData.Operation); err != nil {
				return d.makeErrorResponse(execData.RequestID, 409, "connection_sequence_error", err.Error())
			}
		}
		return d.dispatchToHandler(ctx, handlerPath, execData, env, connState)
	}

	// Non-connect: require auth.
	if connState != nil && !connState.Completed {
		return d.makeErrorResponse(execData.RequestID, 403, "connection_required", "connection not established")
	}

	// Verify request integrity.
	//
	// V7 v7.71 §A4-AUTHZ status+code discrimination (the AUTHZ-* matrix
	// regression pin). VerifyRequestWithBinding aggregates several distinct
	// sentinel classes; the wire surface MUST surface the domain-defined
	// code per V7 §3.3, NOT a catch-all default like
	// `authentication_failed` / `verification_failed`. The four cases:
	//
	//   - ErrUnresolvableGrantee  → 401 unresolvable_grantee (PR-3 single
	//     401 carve-out / §5.2 grantee resolution)
	//   - ErrCapabilityRevoked    → 403 capability_revoked   (RULING-CLASS-C
	//     when verifier knows revocation, preserve the
	//     `capability_revoked` semantic per v7.71 §3.3 line 900 instead of
	//     collapsing to the `capability_denied` default. The (401, X) pair
	//     is RESERVED for the actual ROLE §5.5 T_old/T_new in-flight cascade
	//     race, which we don't distinguish from non-race revocation here.)
	//   - ErrCapabilityDenied     → 403 capability_denied    (the §5.2
	//     authorization-domain default: cap structure / chain link /
	//     attenuation / granter unresolvable / expiry / etc.)
	//   - ErrAuthenticationFailed → 401 authentication_failed (auth-class
	//     failures: missing author / signer-author mismatch / signature
	//     verify fail / unsupported key_type)
	//
	// The historical 403-authentication_failed path is preserved for the
	// auth-class fallback (no matching sentinel — defensive default) so a
	// brand-new failure mode never reads as silent-pass.
	if err := VerifyRequestWithBinding(env, d.LocalPeerID, d.LocalIdentityHash, d.IdentityBindingChecker); err != nil {
		d.debugf("execute: auth failed: %s", err)
		switch {
		case errors.Is(err, ecerrors.ErrChainTooDeep):
			// V7 §4.10(b) (v7.75 §9.1 floor MUST): a chain over max depth is a
			// client-correctable structural excess, not an authz verdict.
			// Keystone analysis pinned 400 (not 403) so callers can
			// distinguish "too deep" from "you lack the capability". This
			// branch precedes ErrCapabilityDenied so the depth code wins
			// even when downstream wrapping re-asserts ErrCapabilityDenied.
			return d.makeErrorResponse(execData.RequestID, 400, "chain_depth_exceeded", err.Error())
		case errors.Is(err, ecerrors.ErrUnresolvableGrantee):
			return d.makeErrorResponse(execData.RequestID, 401, "unresolvable_grantee", err.Error())
		case errors.Is(err, ecerrors.ErrCapabilityRevoked):
			return d.makeErrorResponse(execData.RequestID, 403, "capability_revoked", err.Error())
		case errors.Is(err, ecerrors.ErrCapabilityDenied):
			return d.makeErrorResponse(execData.RequestID, 403, "capability_denied", err.Error())
		case errors.Is(err, ecerrors.ErrAuthenticationFailed):
			return d.makeErrorResponse(execData.RequestID, 401, "authentication_failed", err.Error())
		default:
			return d.makeErrorResponse(execData.RequestID, 403, "authentication_failed", err.Error())
		}
	}
	d.debugf("execute: auth ok")

	// V7 v7.62 §5.1 + RULING-CLASS-C-403-CAPABILITY-REVOKED-CORE:
	// revocation check on the presented capability. Walks the chain to its
	// root, checks the binding (via the observational capability_path_for
	// index), and checks the explicit marker at
	// system/capability/revocations/{root_hash_hex}. Wire-only caps are
	// covered by the marker check; path-bound caps get defense in depth.
	//
	// RULING-CLASS-C: when is_revoked returns true the verifier KNOWS the
	// cap is revoked — emit (403, capability_revoked), the RECOMMENDED core
	// surface that preserves the revocation semantic per v7.71 §3.3 line 900
	// ("defined code where one applies"). The (401, capability_revoked)
	// status carve-out is RESERVED for the actual ROLE §5.5 T_old/T_new
	// in-flight cascade race (fail-fast retry semantics); we don't
	// distinguish race from non-race here, so the conservative call is the
	// 403 surface that applies to both.
	if capEntity, ok := env.FindIncluded(execData.Capability); ok {
		if capability.IsRevoked(capEntity, capability.RevocationContext{
			ContentStore:    d.Store,
			LocationIndex:   d.LocationIndex,
			Included:        env.Included,
			CapabilityIndex: d.CapabilityIndex,
		}) {
			return d.makeErrorResponse(execData.RequestID, 403, "capability_revoked",
				"capability revoked")
		}
	}

	// Ingest signatures from envelope.included before handler dispatch
	// per ENTITY-CORE-PROTOCOL-V7 v7.37 §6.5. Persists system/signature
	// entities to the content store and binds them at their V7 invariant
	// pointer paths so identity / quorum / substrate validators can find
	// them regardless of whether they arrived via cross-peer sync or this
	// envelope. system/peer entities referenced by signatures are
	// also ingested so signer peer_id resolution works. Universal across
	// kernel / substrate / identity / extension ops (per SPEC-25 ruling
	// in PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md Amendment 1).
	// EXTENSION-IDENTITY v3.3 §6.2 is a one-paragraph pointer to V7 §6.5.
	if err := IngestEnvelopeSignatures(d.Store, d.LocationIndex, env.Included); err != nil {
		d.debugf("execute: signature ingestion failed: %s", err)
		return d.makeErrorResponse(execData.RequestID, 400, "signature_path_conflict", err.Error())
	}

	// V7 §6.6: tree is the source of truth for handler dispatch. Walk the tree
	// for the longest-prefix system/handler entity covering handlerPath, then
	// look up either the expression (entity-native) or compiled code by pattern.
	res, errCode, ok := d.resolveHandler(handlerPath)
	if !ok {
		switch errCode {
		case "no_impl":
			return d.makeErrorResponse(execData.RequestID, 404, "not_found",
				"handler bound at "+handlerPath+" has neither expression_path nor compiled implementation")
		case "decode_failed":
			return d.makeErrorResponse(execData.RequestID, 500, "internal", "failed to decode handler entity")
		default:
			return d.makeErrorResponse(execData.RequestID, 404, "not_found", "no handler for path: "+handlerPath)
		}
	}
	pattern := res.pattern
	h := res.compiled
	entityNative := res.handlerData.ExpressionPath != ""
	var entityNativeExprPath string
	if entityNative {
		if d.EvaluateExpression == nil {
			return d.makeErrorResponse(execData.RequestID, 501, "not_implemented",
				"compute extension not wired for entity-native dispatch")
		}
		entityNativeExprPath = qualifyIfRelative(string(d.LocalPeerID), res.handlerData.ExpressionPath)
	}
	d.debugf("execute: resolved handler=%s entity_native=%t", pattern, entityNative)

	// V7 v7.62 §6.2 status-code semantic note: 501 unsupported_operation
	// MUST distinguish from 404 handler_not_found and 403 capability_denied.
	// Per the note's literal wording — "the caller's authority is
	// irrelevant; the operation does not exist on this handler" — the op-
	// existence check fires BEFORE the cap check. Otherwise a caller whose
	// cap doesn't authorize a bogus op gets 403 (masking the fact that the
	// op doesn't exist at all). The dispatcher consults the handler's
	// manifest; if the op isn't declared, return 501. Compiled handlers
	// expose this via ManifestProvider; entity-native handlers' interface
	// is read off res.handlerData.Interface — neither path is required by
	// older handlers, so we fall through if neither source is available.
	if env501, has := d.checkOpInManifest(execData.RequestID, pattern, execData.Operation, h, res); has {
		return env501, nil
	}

	capEntity, capOk := env.FindIncluded(execData.Capability)
	if !capOk {
		return d.makeErrorResponse(execData.RequestID, 403, "capability_not_found", "capability entity not in envelope")
	}
	capData, err := types.CapabilityTokenDataFromEntity(capEntity)
	if err != nil {
		return d.makeErrorResponse(execData.RequestID, 403, "invalid_capability", err.Error())
	}

	granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, d.Store, d.LocalPeerID)
	if gerr != nil {
		// WB-27 receiver-side rejected marker per EXTENSION-CONTINUATION
		// v1.20 §3.10.3: chain-dispatches only (bindRejectedChainErrorMarker
		// no-ops when Bounds.ChainID is empty). Returns zero hash for
		// ordinary EXECUTEs; the response's RejectedMarker is then
		// omitted via omitzero.
		rejectedMarker := d.bindRejectedChainErrorMarker(
			execData, "capability_denied", execData.URI, requestingPeerIDFromExec(execData, env))
		return d.makeErrorResponseWithRejectedMarker(execData.RequestID, 403, "capability_denied",
			"granter unresolvable: "+gerr.Error(), rejectedMarker)
	}
	matchingGrant, permitted := capability.FindMatchingGrant(execData, capData, pattern, d.LocalPeerID, granterPeerID)
	if !permitted {
		rejectedMarker := d.bindRejectedChainErrorMarker(
			execData, "capability_denied", execData.URI, requestingPeerIDFromExec(execData, env))
		return d.makeErrorResponseWithRejectedMarker(execData.RequestID, 403, "capability_denied",
			"insufficient capability for handler scope", rejectedMarker)
	}

	// Build handler context.
	var authorPeerID crypto.PeerID
	if !execData.Author.IsZero() {
		authorEntity, ok := env.FindIncluded(execData.Author)
		if ok {
			var idData types.PeerData
			if err := decodeEntity(authorEntity.Data, &idData); err == nil {
				// v7.65 §1.5: peer_id derives from (public_key, key_type).
				if ktByte, ktOK := idData.KeyTypeByte(); ktOK {
					if pid, pidErr := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte); pidErr == nil {
						authorPeerID = pid
					}
				}
			}
		}
	}

	var bounds *types.BoundsData
	if execData.Bounds != nil {
		bounds = execData.Bounds
	}

	// Decode params — spec §3.4: params contains an entity (type + data + content_hash).
	var paramsEntity entity.Entity
	if len(execData.Params) > 0 {
		if err := decodeRawEntity(execData.Params, &paramsEntity); err != nil {
			return d.makeErrorResponse(execData.RequestID, 400, "invalid_params", "params is not a valid entity: "+err.Error())
		}
		if paramsEntity.Type == "" {
			return d.makeErrorResponse(execData.RequestID, 400, "invalid_params", "params entity missing type field (spec §3.4: params must be an entity)")
		}
	}

	// Resolve and validate the handler grant per V7 §6.2 / §6.8 (spec-gap-
	// handler-grant-authority §S2). The grant at system/capability/grants/
	// {pattern} MUST be issued by the local peer's authority; otherwise
	// dispatch fails closed.
	handlerGrant, gErr := d.loadValidatedGrant(pattern)
	if gErr != nil {
		// Missing grant entity. Entity-native handlers fail closed (§7.1);
		// compiled handlers can still dispatch (some bootstrap handlers
		// don't have grants seeded yet — peer-root-grant materialization
		// is deferred).
		if gErr.code == "missing" && !entityNative {
			// fall through with empty handlerGrant
		} else {
			return d.makeErrorResponse(execData.RequestID, gErr.status, gErr.code, gErr.message)
		}
	}

	// Normalize resource targets: entity://local_peer/path → path.
	// Cross-peer URIs (entity://other_peer/path) stay as-is.
	normalizedResource := normalizeResourceTargets(execData.Resource, d.LocalPeerID)

	// Validate resource target paths (R12 V1): reject reserved prefixes,
	// empty segments, and malformed peer IDs. Canonicalize to absolute form
	// first so validate_absolute_path can check the peer ID segment.
	if normalizedResource != nil {
		for _, target := range normalizedResource.Targets {
			if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
				return d.makeErrorResponse(execData.RequestID, 400, "invalid_path",
					"reserved path prefix: paths starting with ./ or ../ are not allowed")
			}
			if strings.Contains(target, "//") {
				return d.makeErrorResponse(execData.RequestID, 400, "invalid_path",
					"invalid path: contains empty segments (consecutive //)")
			}
			// Canonicalize to absolute and validate peer ID segment.
			abs := capability.Canonicalize(target, d.LocalPeerID)
			if err := store.ValidateAbsolutePath(abs); err != nil {
				return d.makeErrorResponse(execData.RequestID, 400, "invalid_path",
					"invalid resource path: "+err.Error())
			}
		}
	}

	// SessionPeerID — the authenticated wire-session peer. For direct
	// EXECUTE this equals authorPeerID; for cross-peer dispatch they
	// diverge (the relay re-issues Alice's EXECUTE on its own connection,
	// so SessionPeerID = relay while Author = Alice). See HandlerContext
	// docs + RELAY §3.2.
	var sessionPeerID crypto.PeerID
	if connState != nil {
		sessionPeerID = connState.RemotePeerID
	}
	hctx := &handler.HandlerContext{
		Author:           authorPeerID,
		AuthorHash:       execData.Author,
		SessionPeerID:    sessionPeerID,
		LocalPeerID:      d.LocalPeerID,
		CallerCapability: capEntity,
		HandlerGrant:     handlerGrant,
		MatchingGrant:    &matchingGrant,
		Resource:         normalizedResource,
		Store:            d.Store,
		LocationIndex:    d.LocationIndex,
		CapabilityIndex:  d.CapabilityIndex,
		HandlerPattern:   pattern,
		RequestID:        execData.RequestID,
		Bounds:           bounds,
		Included:         env.Included,
		ConnectionState:  connState,
	}
	hctx.Execute = d.makeLocalExecute(ctx, hctx)
	hctx.GoAsync = d.submitAsync

	req := &handler.Request{
		Path:      handlerPath,
		Operation: execData.Operation,
		Params:    paramsEntity,
		Context:   hctx,
	}

	// Durability Contract (EXTENSION-DURABILITY — exploratory extension; the
	// silent-discard rule was reverted out of V7 §3.2 along with the v7.47
	// retraction). When the request carries a durability_request, it is
	// reconciled against this peer's own policy at acceptance and answered
	// with status + the durability field. A must_have level that cannot be
	// met is refused HERE (412), before the handler runs or any async
	// delivery is spawned: refused at acceptance, no run-then-fail, no
	// double execution (EXTENSION-DURABILITY §5 invariant).
	var durResult *types.DurabilityResultData
	var durAsync bool
	if execData.DurabilityRequest != nil {
		// EXTENSION-DURABILITY §5 / §8 — duplicate (author, request_id) → 409. Idempotency
		// check fires BEFORE reconcile so a replayed durable request never
		// re-executes the handler. Author is required for durability; if zero,
		// skip the dedup index (the request couldn't be uniquely identified
		// and the reconcile will see what it sees).
		if !execData.Author.IsZero() {
			key := dedupKey(execData.Author, execData.RequestID)
			if priorHandle, ok := d.preservedRequests.Load(key); ok {
				return d.makeDurabilityDuplicate(
					execData.RequestID,
					execData.DurabilityRequest.Level,
					priorHandle.(string),
				)
			}
		}
		v := d.durabilityPolicy().Reconcile(*execData.DurabilityRequest)
		if !v.PerformOp {
			return d.makeDurabilityRefusal(execData.RequestID, v.Result)
		}
		// Preservation paths split by sync vs. async (EXTENSION-DURABILITY §6):
		//
		// - SYNC (no deliver_to): preserve right now. Handle = the path we
		//   wrote to. applied stays at its reconciled level.
		//
		// - ASYNC (deliver_to present): the inbox handler will preserve on
		//   delivery. At response time NOTHING is physically preserved yet,
		//   so applied MUST be downgraded to none (the §5 "applied =
		//   physical now" invariant), with the originally-reconciled level
		//   moved to committed and status forced to 202. Handle predicts
		//   where the inbox handler will write — `<deliver_to_path>/<rid>`.
		if v.Preserve {
			if execData.DeliverTo == nil {
				if path, ok := d.preserveDurableRequest(execData.RequestID, env.Root); ok {
					v.Result.Handle = path
					// Register the (author, request_id) → handle entry so a
					// replay returns 409 with the original handle (§9.2.4).
					if !execData.Author.IsZero() {
						d.preservedRequests.Store(dedupKey(execData.Author, execData.RequestID), path)
					}
				} else {
					v.Result.Applied = types.DurabilityNone
					v.Result.Committed = ""
					v.Result.Reason = types.ReasonNoDurableStore
					v.Async = false
				}
			} else {
				committed := v.Result.Applied
				v.Result.Applied = types.DurabilityNone
				v.Result.Committed = committed
				v.Async = true
				v.Result.Handle = predictDeliverToHandle(execData.DeliverTo, execData.RequestID)
			}
		}
		durResult = &v.Result
		durAsync = v.Async
	}

	// Build the handler invocation. Entity-native handlers (system/handler
	// with expression_path) and compiled handlers go through the same
	// dispatch flow from here — sync and deliver_to alike. The only
	// difference is which line invokes the implementation. V7 §6.6 makes
	// the tree the source of truth for what binds at a pattern; the
	// dispatcher honors deliver_to uniformly regardless of handler shape.
	//
	// Dispatch hooks fire entry+exit around the call per GUIDE-
	// INSPECTABILITY v1.1 §2.1 #3. Both inline; hot path.
	invoke := func(ctx context.Context) (*handler.Response, error) {
		d.fireDispatchHooks(handler.DispatchEvent{
			Phase:      handler.DispatchEntry,
			TargetURI:  execData.URI,
			Operation:  execData.Operation,
			ParamsHash: paramsEntity.ContentHash,
			RequestID:  execData.RequestID,
			Timestamp:  time.Now(),
		})
		var resp *handler.Response
		var err error
		if entityNativeExprPath != "" {
			resp, err = d.EvaluateExpression(ctx, entityNativeExprPath, req)
		} else {
			resp, err = h.Handle(ctx, req)
		}
		exit := handler.DispatchEvent{
			Phase:      handler.DispatchExit,
			TargetURI:  execData.URI,
			Operation:  execData.Operation,
			ParamsHash: paramsEntity.ContentHash,
			RequestID:  execData.RequestID,
			Timestamp:  time.Now(),
		}
		if resp != nil {
			exit.ResponseStatus = resp.Status
			exit.ResponseHash = resp.Result.ContentHash
		}
		d.fireDispatchHooks(exit)
		return resp, err
	}

	// Async delivery detection: if deliver_to is present, validate and handle async.
	if execData.DeliverTo != nil {
		if execData.DeliverToken.IsZero() {
			return d.makeErrorResponse(execData.RequestID, 400, "missing_deliver_token",
				"deliver_to field present but deliver_token is missing")
		}
		// Verify deliver_token entity is in included.
		deliverTokenEntity, dtOk := env.FindIncluded(execData.DeliverToken)
		if !dtOk {
			return d.makeErrorResponse(execData.RequestID, 400, "missing_deliver_token",
				"deliver_token entity not in envelope included")
		}

		// Launch async processing on the bounded pool. Pass original
		// envelope included so the delivery can include the token's
		// signature for chain verification. If the pool is saturated,
		// refuse with 429 rather than spawn an unbounded goroutine
		// (EXTENSION-INBOX §9.3 backpressure; the caller retries per §9.2).
		included := env.Included
		if !d.submitAsync(func() {
			d.processAsyncDelivery(ctx, invoke, execData, deliverTokenEntity, included)
		}) {
			d.debugf("execute: async dispatch pool saturated, returning 429")
			return d.makeErrorResponse(execData.RequestID, 429, "async_dispatch_overflow",
				"async delivery pool saturated; retry later")
		}

		// Return 202 acknowledgement. When durability was requested, the
		// verdict rides the same 202 (the existing async-ack 202 meaning,
		// reused — EXTENSION-INBOX §7.1 / EXTENSION-DURABILITY §5); `applied` still reports
		// only what is physically in place now.
		d.debugf("execute: async delivery, returning 202")
		if durResult != nil {
			return d.make202ResponseDur(execData.RequestID, durResult)
		}
		return d.make202Response(execData.RequestID)
	}

	resp, err := invoke(ctx)
	if err != nil {
		return d.makeErrorResponse(execData.RequestID, 500, "handler_error", err.Error())
	}

	d.debugf("execute: -> status=%d entity_native=%t", resp.Status, entityNativeExprPath != "")
	return d.finishExecute(execData.RequestID, resp, durResult, durAsync)
}

func (d *Dispatcher) dispatchToHandler(ctx context.Context, handlerPath string, execData types.ExecuteData, env entity.Envelope, connState *ConnectionState) (entity.Envelope, error) {
	d.debugf("connect: op=%s", execData.Operation)
	res, errCode, ok := d.resolveHandler(handlerPath)
	if !ok {
		switch errCode {
		case "no_impl":
			return d.makeErrorResponse(execData.RequestID, 404, "not_found",
				"handler bound at "+handlerPath+" has neither expression_path nor compiled implementation")
		case "decode_failed":
			return d.makeErrorResponse(execData.RequestID, 500, "internal", "failed to decode handler entity")
		default:
			return d.makeErrorResponse(execData.RequestID, 404, "not_found", "no handler for path: "+handlerPath)
		}
	}

	// Decode params — spec §3.4: params contains an entity (type + data + content_hash).
	var paramsEntity entity.Entity
	if len(execData.Params) > 0 {
		if err := decodeRawEntity(execData.Params, &paramsEntity); err != nil {
			return d.makeErrorResponse(execData.RequestID, 400, "invalid_params", "params is not a valid entity: "+err.Error())
		}
		if paramsEntity.Type == "" {
			return d.makeErrorResponse(execData.RequestID, 400, "invalid_params", "params entity missing type field (spec §3.4: params must be an entity)")
		}
	}

	var sessionPeerID crypto.PeerID
	if connState != nil {
		sessionPeerID = connState.RemotePeerID
	}
	hctx := &handler.HandlerContext{
		LocalPeerID:     d.LocalPeerID,
		SessionPeerID:   sessionPeerID,
		Store:           d.Store,
		LocationIndex:   d.LocationIndex,
		CapabilityIndex: d.CapabilityIndex,
		HandlerPattern:  res.pattern,
		RequestID:       execData.RequestID,
		Included:        env.Included,
		ConnectionState: connState,
	}
	hctx.Execute = d.makeLocalExecute(ctx, hctx)
	hctx.GoAsync = d.submitAsync

	req := &handler.Request{
		Path:      handlerPath,
		Operation: execData.Operation,
		Params:    paramsEntity,
		Context:   hctx,
	}

	if res.handlerData.ExpressionPath != "" {
		if d.EvaluateExpression == nil {
			return d.makeErrorResponse(execData.RequestID, 501, "not_implemented",
				"compute extension not wired for entity-native dispatch")
		}
		exprPath := qualifyIfRelative(string(d.LocalPeerID), res.handlerData.ExpressionPath)
		resp, err := d.EvaluateExpression(ctx, exprPath, req)
		if err != nil {
			return d.makeErrorResponse(execData.RequestID, 500, "handler_error", err.Error())
		}
		return d.makeResponse(execData.RequestID, resp)
	}

	resp, err := res.compiled.Handle(ctx, req)
	if err != nil {
		return d.makeErrorResponse(execData.RequestID, 500, "handler_error", err.Error())
	}

	return d.makeResponse(execData.RequestID, resp)
}

// grantLoadError carries the wire-level shape of a grant-load failure so
// both dispatch entry points can produce consistent error responses.
type grantLoadError struct {
	code    string // "missing" | "missing_entity" | "permission_denied"
	status  uint
	message string
}

// loadValidatedGrant reads the handler grant entity at
// system/capability/grants/{pattern} and verifies it per V7 §6.2 / §6.8 +
// spec-gap-handler-grant-authority §S2. Returns the validated grant entity,
// or a grantLoadError describing the failure shape.
//
// Both wire-entry dispatch (handleExecute) and handler-internal sub-dispatch
// (makeLocalExecute) call this — every grant-load site applies the same
// validation, so a sub-dispatch can't pull a foreign grant from a child
// pattern path.
func (d *Dispatcher) loadValidatedGrant(pattern string) (entity.Entity, *grantLoadError) {
	grantPath := "system/capability/grants/" + pattern
	grantHash, ghOk := d.LocationIndex.Get(grantPath)
	if !ghOk {
		return entity.Entity{}, &grantLoadError{
			code:    "missing",
			status:  403,
			message: "no handler grant at " + grantPath,
		}
	}
	grantEnt, geOk := d.Store.Get(grantHash)
	if !geOk {
		return entity.Entity{}, &grantLoadError{
			code:    "missing_entity",
			status:  500,
			message: "grant path bound but content store has no entity",
		}
	}
	if d.LocalIdentityHash.IsZero() {
		// No local identity wired (test contexts) — skip validation.
		return grantEnt, nil
	}
	if err := capability.VerifyHandlerGrant(grantEnt, types.LocalSignaturePath(grantEnt.ContentHash),
		d.LocalIdentityHash, d.Store, d.LocationIndex); err != nil {
		gi, _ := capability.IsGrantInvalid(err)
		msg := "handler grant invalid: " + err.Error()
		if gi != nil {
			msg = "handler grant invalid (" + gi.Code + "): " + gi.Message
		}
		d.debugf("grant validation failed pattern=%s: %s", pattern, msg)
		return entity.Entity{}, &grantLoadError{
			code:    "permission_denied",
			status:  403,
			message: msg,
		}
	}
	return grantEnt, nil
}

// SeedHandlersFromRegistry writes minimal system/handler entities into the
// location index for every pattern in the registry. V7 §6.6 makes the tree
// the source of truth for dispatch resolution; this helper bootstraps that
// state for callers that build a Dispatcher directly (tests, custom embeds).
// The peer builder seeds richer entries via its own path; this is the minimal
// dispatch-resolvable shape.
func SeedHandlersFromRegistry(cs store.ContentStore, li store.LocationIndex, reg *handler.Registry) error {
	for pattern := range reg.Handlers() {
		hd := types.HandlerData{Interface: "system/handler/" + pattern}
		ent, err := hd.ToEntity()
		if err != nil {
			return fmt.Errorf("build handler entity for %s: %w", pattern, err)
		}
		h, err := cs.Put(ent)
		if err != nil {
			return fmt.Errorf("store handler entity for %s: %w", pattern, err)
		}
		if err := li.Set(pattern, h); err != nil {
			return fmt.Errorf("bind handler entity for %s: %w", pattern, err)
		}
	}
	return nil
}

// resolution carries the result of V7 §6.6 path dispatch: the longest prefix
// at which a system/handler entity exists in the tree, plus the decoded handler
// data and the bare pattern (without the leading peer-id segment). For
// language-native handlers, compiled is the registered implementation; for
// entity-native handlers (handlerData.ExpressionPath set), compiled is nil.
type resolution struct {
	pattern     string            // bare pattern, e.g. "system/tree"
	handlerData types.HandlerData // decoded system/handler entity
	compiled    handler.Handler   // compiled implementation, or nil for entity-native
}

// resolveHandler implements V7 §6.6 path dispatch. The tree is the source of
// truth: a handler exists iff a system/handler entity is bound at a path that
// is a prefix of handlerPath. The Registry is consulted only as a code lookup
// for the resolved pattern. Returns (resolution, true) on success.
//
// Errors (non-OK) are encoded by the caller into the appropriate wire response.
// "not_found" means no system/handler entity covers handlerPath. "no_impl"
// means the tree binds a handler entity but it has neither expression_path nor
// a compiled implementation registered for that pattern — a misconfiguration.
func (d *Dispatcher) resolveHandler(handlerPath string) (resolution, string, bool) {
	qualified := store.QualifyPath(string(d.LocalPeerID), handlerPath)
	patternFull, handlerEnt, found := d.treeWalkHandler(qualified)
	if !found {
		return resolution{}, "not_found", false
	}
	var hd types.HandlerData
	if err := ecf.Decode(handlerEnt.Data, &hd); err != nil {
		return resolution{}, "decode_failed", false
	}
	pattern := strings.TrimPrefix(patternFull, "/"+string(d.LocalPeerID)+"/")

	res := resolution{pattern: pattern, handlerData: hd}
	if hd.ExpressionPath == "" {
		impl, ok := d.Registry.Lookup(pattern)
		if !ok {
			return resolution{}, "no_impl", false
		}
		res.compiled = impl
	}
	return res, "", true
}

// checkOpInManifest enforces V7 v7.62 §6.2's 501-wins-over-403 rule when
// the operation doesn't appear in the handler's manifest. Returns nil to
// pass through to the next dispatch stage; returns a 501 error response
// when the op is provably absent.
//
// The manifest is consulted in two places:
//
//  1. The compiled handler's `Manifest()` method (via the ManifestProvider
//     interface). Every system handler shipped in core + ext implements
//     this; it's the authoritative source for "what ops does this handler
//     declare."
//  2. The interface entity at `res.handlerData.Interface` — for entity-
//     native handlers (`ExpressionPath != ""`) that have no compiled code
//     to query. The interface entity carries the same operations map
//     advertised in the manifest.
//
// If neither source yields a manifest (older handlers without ops decl,
// or a misconfigured peer), we fall through — the existing cap-check path
// preserves the pre-v7.62 behavior. That preserves backward-compat for
// anything that didn't migrate to declaring its manifest.
func (d *Dispatcher) checkOpInManifest(requestID, pattern, operation string, compiled handler.Handler, res resolution) (entity.Envelope, bool) {
	if operation == "" {
		return entity.Envelope{}, false
	}
	if compiled != nil {
		if mp, ok := compiled.(handler.ManifestProvider); ok {
			m := mp.Manifest()
			if m.Operations != nil {
				if _, has := m.Operations[operation]; !has {
					env, _ := d.makeErrorResponse(requestID, 501, "unsupported_operation",
						"handler "+pattern+" does not implement operation: "+operation)
					return env, true
				}
				return entity.Envelope{}, false
			}
		}
	}
	if res.handlerData.Interface != "" {
		ifacePath := store.QualifyPath(string(d.LocalPeerID), res.handlerData.Interface)
		if h, ok := d.LocationIndex.Get(ifacePath); ok {
			if ent, ok := d.Store.Get(h); ok && ent.Type == types.TypeHandlerInterface {
				if iface, err := types.HandlerInterfaceDataFromEntity(ent); err == nil && iface.Operations != nil {
					if _, has := iface.Operations[operation]; !has {
						env, _ := d.makeErrorResponse(requestID, 501, "unsupported_operation",
							"handler "+pattern+" does not implement operation: "+operation)
						return env, true
					}
				}
			}
		}
	}
	return entity.Envelope{}, false
}

// treeWalkHandler walks backward from path through segments, checking each prefix
// for a system/handler entity (V7 §6.6).
func (d *Dispatcher) treeWalkHandler(qualifiedPath string) (string, entity.Entity, bool) {
	path := qualifiedPath
	for {
		if h, ok := d.LocationIndex.Get(path); ok {
			if ent, ok := d.Store.Get(h); ok && ent.Type == "system/handler" {
				return path, ent, true
			}
		}
		idx := strings.LastIndex(path, "/")
		if idx <= 0 {
			return "", entity.Entity{}, false
		}
		path = path[:idx]
	}
}
