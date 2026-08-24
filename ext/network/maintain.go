package network

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// handleMaintainPeer implements §4.1 maintain-peer: connect if needed, then
// install the reconnect lifecycle continuation graph and the lifecycle
// subscriptions, and return session info.
//
// Ordering nuance vs the §4.1 pseudocode (connect first, 502 with no graph
// on failure): that holds for the FIRST imperative call. On a re-entry for
// an existing session (the backoff continuation re-EXECUTing maintain-peer
// after a failed reconnect), a connect failure must NOT strand the retry
// loop — the graph is re-armed (one-shot backoff continuation re-installed,
// next delayed advance scheduled) before the 502 returns.
func (h *Handler) handleMaintainPeer(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	p := h.boundPeer()
	if p == nil {
		return handler.NewErrorResponse(500, "internal_error", "network handler not bound to a peer")
	}

	// Accept the declared §2.1 input type AND primitive/any: the backoff
	// continuation's re-EXECUTE arrives as primitive/any (continuation
	// params assembly is untyped); shape validation is the decode below.
	if req.Params.Type != types.TypeNetworkMaintainRequest && req.Params.Type != "primitive/any" {
		return handler.NewErrorResponse(400, "invalid_params",
			"maintain-peer params must be "+types.TypeNetworkMaintainRequest+", got "+req.Params.Type)
	}
	params, err := types.MaintainRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params", "decode maintain-request: "+err.Error())
	}
	if params.PeerID == "" {
		return handler.NewErrorResponse(400, "invalid_params", "maintain-request requires peer_id")
	}
	peerID := crypto.PeerID(params.PeerID)
	if peerID == p.PeerID() {
		return handler.NewErrorResponse(400, "invalid_params", "cannot maintain a relationship with self")
	}
	remoteHash, err := types.ComputePeerIdentityHashFromPeerID(peerID)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"cannot derive identity hash for peer_id (status-path key required): "+err.Error())
	}

	// Publish the dial address as a transport profile so EnsureConnected
	// (and every later redial) can resolve it.
	if params.Address != "" {
		if err := p.RegisterRemote(peerID, params.Address); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "register address: "+err.Error())
		}
	}

	sess, existed := h.getOrCreateSession(peerID, remoteHash, params)

	// 1. Connect if needed (§4.1 step 1). EnsureConnected reuses the pooled
	// binding or dials + handshakes; the establish path writes the §3.13
	// connected status and pool insert starts keepalive (§4.1 steps 2 and 5
	// are ambient in core/peer — the handler adds no second write or loop).
	if err := p.EnsureConnected(ctx, peerID); err != nil {
		if existed && sess.params.ReconnectEnabled() {
			// Re-entry from the backoff continuation: keep the retry loop
			// alive. Re-install the consumed one-shot and schedule the next
			// delayed advance.
			if aerr := h.armBackoffRetry(hctx, sess); aerr != nil {
				h.debugf("maintain-peer %s: re-arm backoff failed: %v", peerID, aerr)
			}
		} else if !existed {
			// First imperative call failed — no session, no graph (§4.1).
			h.dropSession(peerID)
		}
		return handler.NewErrorResponse(502, "connection_failed",
			fmt.Sprintf("connect to %s: %v", peerID, err))
	}
	sess.mu.Lock()
	sess.attempt = 0
	sess.params = params
	graphNeeded := !sess.graphInstalled
	sess.mu.Unlock()

	// 2–4. Install the continuation graph + lifecycle subscriptions.
	// Continuation re-puts are content-idempotent; subscriptions are created
	// once per session.
	if graphNeeded {
		if params.ReconnectEnabled() {
			if err := h.installReconnectContinuations(hctx, sess); err != nil {
				return handler.NewErrorResponse(500, "storage_error", err.Error())
			}
		}
		if params.ResubscribeEnabled() {
			if err := h.installResubscribeContinuation(hctx, sess); err != nil {
				return handler.NewErrorResponse(500, "storage_error", err.Error())
			}
		}

		var subIDs []string
		if params.ReconnectEnabled() {
			id, err := h.subscribeLifecycle(ctx, remoteHash, onDisconnectPath(peerID))
			if err != nil {
				return handler.NewErrorResponse(500, "internal_error", err.Error())
			}
			subIDs = append(subIDs, id)
		}
		if params.ResubscribeEnabled() {
			id, err := h.subscribeLifecycle(ctx, remoteHash, onReconnectPath(peerID))
			if err != nil {
				return handler.NewErrorResponse(500, "internal_error", err.Error())
			}
			subIDs = append(subIDs, id)
		}
		sess.mu.Lock()
		sess.subscriptionIDs = subIDs
		sess.graphInstalled = true
		sess.mu.Unlock()
	}

	sess.mu.Lock()
	result := types.MaintainResultData{
		PeerID:        string(peerID),
		SessionID:     sess.sessionID,
		Subscriptions: append([]string(nil), sess.subscriptionIDs...),
		ChainID:       sess.chainID,
	}
	sess.mu.Unlock()
	return handler.NewResponse(200, types.TypeNetworkMaintainResult, result)
}

// installReconnectContinuations writes the on-disconnect standing
// continuation (inbox resident — the lifecycle subscription's delivery
// target) and the one-shot backoff continuation (managed-namespace resident
// — advanced only by the handler's delayed self-advance, never via
// system/inbox/*). Writes are direct handler-authorized tree binds per §11:
// the graph lives in the handler's managed namespaces, authorized by its own
// grant, with dispatch_capability = the handler grant (the F2 pattern).
func (h *Handler) installReconnectContinuations(hctx *handler.HandlerContext, sess *session) error {
	reconnectParams, err := ecf.Encode(map[string]interface{}{
		"peer_id": string(sess.peerID),
		"address": sess.params.Address,
	})
	if err != nil {
		return fmt.Errorf("encode reconnect params: %w", err)
	}

	// Standing on-disconnect trigger (result_field null, remaining null).
	// No on_error: a failed reconnect dispatch binds the §3.10 lost-error
	// marker (no-on_error forward non-2xx), keyed by RequestID — the
	// marker-proposal surface. Retry pacing is the handler's job below.
	onDisconnect := types.ContinuationData{
		Target:             HandlerPattern,
		Operation:          "reconnect",
		Resource:           &types.ResourceTarget{Targets: []string{HandlerPattern}},
		Params:             cbor.RawMessage(reconnectParams),
		DispatchCapability: hctx.HandlerGrant.ContentHash,
	}
	if err := h.bindContinuation(hctx, onDisconnectPath(sess.peerID), onDisconnect); err != nil {
		return err
	}
	return h.installBackoffContinuation(hctx, sess)
}

// installBackoffContinuation (re-)installs the one-shot §4.1 backoff
// continuation that re-EXECUTEs maintain-peer with the session's original
// request. One-shot: each advance consumes it; maintain-peer re-entry
// re-installs it while the failure persists.
func (h *Handler) installBackoffContinuation(hctx *handler.HandlerContext, sess *session) error {
	sess.mu.Lock()
	params := sess.params
	sess.mu.Unlock()
	paramsEnt, err := params.ToEntity()
	if err != nil {
		return fmt.Errorf("encode maintain-request for backoff: %w", err)
	}
	one := uint64(1)
	backoff := types.ContinuationData{
		Target:              HandlerPattern,
		Operation:           "maintain-peer",
		Resource:            &types.ResourceTarget{Targets: []string{HandlerPattern}},
		Params:              paramsEnt.Data,
		RemainingExecutions: &one,
		DispatchCapability:  hctx.HandlerGrant.ContentHash,
	}
	return h.bindContinuation(hctx, backoffPath(sess.peerID), backoff)
}

// installResubscribeContinuation writes the standing on-reconnect
// continuation dispatching the internal restore-subscriptions operation
// (§4.1 step 3 / §7).
func (h *Handler) installResubscribeContinuation(hctx *handler.HandlerContext, sess *session) error {
	restoreParams, err := ecf.Encode(map[string]interface{}{
		"peer_id": string(sess.peerID),
	})
	if err != nil {
		return fmt.Errorf("encode restore params: %w", err)
	}
	onReconnect := types.ContinuationData{
		Target:             HandlerPattern,
		Operation:          "restore-subscriptions",
		Resource:           &types.ResourceTarget{Targets: []string{HandlerPattern}},
		Params:             cbor.RawMessage(restoreParams),
		DispatchCapability: hctx.HandlerGrant.ContentHash,
	}
	return h.bindContinuation(hctx, onReconnectPath(sess.peerID), onReconnect)
}

// bindContinuation stores a continuation entity and binds it at path via the
// handler-authorized tree write seam.
func (h *Handler) bindContinuation(hctx *handler.HandlerContext, path string, cont types.ContinuationData) error {
	ent, err := cont.ToEntity()
	if err != nil {
		return fmt.Errorf("build continuation for %s: %w", path, err)
	}
	contHash, err := hctx.Store.Put(ent)
	if err != nil {
		return fmt.Errorf("store continuation for %s: %w", path, err)
	}
	if _, err := hctx.TreeSet(path, contHash, "maintain-peer"); err != nil {
		return fmt.Errorf("bind continuation at %s: %w", path, err)
	}
	return nil
}

// armBackoffRetry re-installs the one-shot backoff continuation and
// schedules its delayed advance per the session's §2.2 backoff config.
func (h *Handler) armBackoffRetry(hctx *handler.HandlerContext, sess *session) error {
	if err := h.installBackoffContinuation(hctx, sess); err != nil {
		return err
	}
	h.scheduleBackoffAdvance(sess)
	return nil
}

// scheduleBackoffAdvance starts (or replaces) the session's retry timer: after
// the computed delay, self-advance the backoff continuation, which one-shot
// re-EXECUTEs maintain-peer. The advance is a self-authored EXECUTE — there
// is no request context alive when the timer fires.
func (h *Handler) scheduleBackoffAdvance(sess *session) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.attempt++
	delay := backoffDelay(sess.params.EffectiveBackoff(), sess.attempt)
	if sess.retryTimer != nil {
		sess.retryTimer.Stop()
	}
	peerID := sess.peerID
	attempt := sess.attempt
	h.debugf("reconnect %s: attempt %d failed, next retry in %s", peerID, attempt, delay)
	sess.retryTimer = time.AfterFunc(delay, func() {
		// Session may have been released while the timer was pending.
		if h.getSession(peerID) != sess {
			return
		}
		advReq := types.ContinuationAdvanceRequestData{}
		advEnt, err := advReq.ToEntity()
		if err != nil {
			h.debugf("reconnect %s: build advance request: %v", peerID, err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		status, result, err := h.selfExecute(ctx, "system/continuation", "advance", advEnt,
			&types.ResourceTarget{Targets: []string{backoffPath(peerID)}})
		if err != nil {
			h.debugf("reconnect %s: backoff advance dispatch: %v", peerID, err)
			return
		}
		if status != 200 {
			h.debugf("reconnect %s: backoff advance returned %d: %s", peerID, status, errorCode(result))
		}
	})
}

// handleReconnect is the internal operation the on-disconnect continuation
// dispatches. The lifecycle subscription fires on EVERY status transition
// (including the establish's own `connected` write), so the operation is
// guarded: already-connected is a 200 no-op.
func (h *Handler) handleReconnect(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	p := h.boundPeer()
	if p == nil {
		return handler.NewErrorResponse(500, "internal_error", "network handler not bound to a peer")
	}
	peerID, resp := decodePeerIDParam(req.Params)
	if resp != nil {
		return resp, nil
	}
	sess := h.getSession(peerID)
	if sess == nil {
		return handler.NewErrorResponse(404, "not_found",
			"no maintain session for peer "+string(peerID))
	}

	if status, ok := h.readPeerStatus(sess); ok && status == types.PeerStatusConnected {
		return reconnectResult("already-connected")
	}

	if err := p.EnsureConnected(ctx, peerID); err != nil {
		// Schedule the paced retry, then surface 502 — the advancing
		// continuation has no on_error, so this binds the §3.10 lost-error
		// marker (reason connection_failed) as the observability record.
		if sess.params.ReconnectEnabled() {
			if aerr := h.armBackoffRetry(hctx, sess); aerr != nil {
				h.debugf("reconnect %s: arm backoff failed: %v", peerID, aerr)
			}
		}
		return handler.NewErrorResponse(502, "connection_failed",
			fmt.Sprintf("reconnect to %s: %v", peerID, err))
	}
	sess.mu.Lock()
	sess.attempt = 0
	sess.mu.Unlock()
	return reconnectResult("reconnected")
}

// handleRestoreSubscriptions is the internal §7.2 operation the on-reconnect
// continuation dispatches. Guarded on connected (the subscription also fires
// on demotion transitions).
//
// Scope (rung 3): the §7.2 first half — re-validate the deliver tokens of
// tree-resident subscriptions whose delivery targets the reconnected peer,
// dropping dead ones (token missing or expired). Surviving subscriptions
// stay registered in the engine's in-memory index (the peer process never
// stopped — only the connection dropped), so they resume delivering with no
// re-registration. The §7.2 second half (re-subscribing on the REMOTE peer)
// requires a local record of outbound subscriptions that no impl keeps yet —
// flagged in docs/validation/spec-issues rather than papered over.
//
// Drop mechanism (convergence pass, tracker #7): a dead subscription is
// removed by a DIRECT handler-authorized tree delete — the §7.2 pseudocode's
// `entity_tree.put(sub_path, null)`, matching entity-core-py. NOT a
// self-authored `unsubscribe`: these subscriptions deliver TO the remote,
// so their `subscriber_identity` is the REMOTE, and the subscription
// handler's unsubscribe is subscriber-gated — a local-peer-authored
// unsubscribe 403s (`not_subscription_owner`). The tree write itself is not
// cap-gated (authorization is at dispatch, not at the write seam), so the
// handler-authorized delete is the correct, spec-sanctioned mechanism.
//
// Engine-index note: unlike entity-core-py, Go's subscription engine has no
// hook that drops the in-memory index when a subscription ENTITY is deleted
// (its OnTreeChange matches watched-resource patterns, not the registry
// path). The index instead self-heals on the next delivery attempt — the
// engine re-reads the deliver token, finds it gone/expired, and
// terminateSubscription clears both index and tree. Bounded staleness, no
// mis-delivery (an invalid-token attempt terminates rather than delivers).
// The immediate-drop hook parity is a convergence-pass follow-up on the
// subscription extension, not the network handler.
func (h *Handler) handleRestoreSubscriptions(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	peerID, resp := decodePeerIDParam(req.Params)
	if resp != nil {
		return resp, nil
	}
	sess := h.getSession(peerID)
	if sess == nil {
		return handler.NewErrorResponse(404, "not_found",
			"no maintain session for peer "+string(peerID))
	}
	if status, ok := h.readPeerStatus(sess); !ok || status != types.PeerStatusConnected {
		return restoreResult(0, 0, "not-connected")
	}

	retained, dropped := 0, 0
	nowMs := uint64(time.Now().UnixMilli())
	for _, entry := range hctx.LocationIndex.List("system/subscription/") {
		subEnt, ok := hctx.Store.Get(entry.Hash)
		if !ok || subEnt.Type != types.TypeSubscription {
			continue
		}
		sub, err := types.SubscriptionDataFromEntity(subEnt)
		if err != nil {
			continue
		}
		if !deliveryTargetsPeer(sub.DeliverURI, peerID) {
			continue
		}
		tokenEnt, ok := hctx.Store.Get(sub.DeliverToken)
		alive := ok
		if ok {
			if tok, terr := types.CapabilityTokenDataFromEntity(tokenEnt); terr == nil {
				if tok.ExpiresAt != nil && *tok.ExpiresAt < nowMs {
					alive = false
				}
			}
		}
		if alive {
			retained++
			continue
		}
		// Token expired or missing during the disconnect — the subscription
		// is dead (§7.2). Direct handler-authorized tree delete (the
		// pseudocode's put(sub_path, null)); NOT a subscriber-gated
		// unsubscribe (would 403 — the subscriber is the remote).
		if _, ok, _ := hctx.TreeRemove(entry.Path, "restore-subscriptions"); ok {
			dropped++
		}
	}
	h.debugf("restore-subscriptions %s: %d retained, %d dropped", peerID, retained, dropped)
	return restoreResult(retained, dropped, "restored")
}

// readPeerStatus reads the current §3.13 status value for the session's peer.
func (h *Handler) readPeerStatus(sess *session) (string, bool) {
	p := h.boundPeer()
	if p == nil {
		return "", false
	}
	path := types.PeerStatusPath(string(p.PeerID()), sess.remoteHash)
	hh, ok := p.LocationIndex().Get(path)
	if !ok {
		return "", false
	}
	ent, ok := p.Store().Get(hh)
	if !ok {
		return "", false
	}
	d, err := types.PeerStatusDataFromEntity(ent)
	if err != nil {
		return "", false
	}
	return d.Status, true
}

// deliveryTargetsPeer reports whether a subscription's deliver URI routes to
// the given remote peer (§7.2: "entity://{peer_id}/...").
func deliveryTargetsPeer(deliverURI string, peerID crypto.PeerID) bool {
	return strings.HasPrefix(deliverURI, "entity://"+string(peerID)+"/") ||
		deliverURI == "entity://"+string(peerID)
}

// decodePeerIDParam extracts peer_id from an internal operation's params.
func decodePeerIDParam(params entity.Entity) (crypto.PeerID, *handler.Response) {
	var d struct {
		PeerID string `cbor:"peer_id"`
	}
	if len(params.Data) > 0 {
		if err := ecf.Decode(params.Data, &d); err != nil {
			resp, _ := handler.NewErrorResponse(400, "invalid_params", "decode params: "+err.Error())
			return "", resp
		}
	}
	if d.PeerID == "" {
		resp, _ := handler.NewErrorResponse(400, "invalid_params", "params require peer_id")
		return "", resp
	}
	return crypto.PeerID(d.PeerID), nil
}

func reconnectResult(outcome string) (*handler.Response, error) {
	raw, _ := ecf.Encode(map[string]interface{}{"outcome": outcome})
	ent, _ := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
	return &handler.Response{Status: 200, Result: ent}, nil
}

func restoreResult(retained, dropped int, outcome string) (*handler.Response, error) {
	raw, _ := ecf.Encode(map[string]interface{}{
		"outcome":  outcome,
		"retained": retained,
		"dropped":  dropped,
	})
	ent, _ := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
	return &handler.Response{Status: 200, Result: ent}, nil
}
