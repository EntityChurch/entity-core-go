package network

import (
	"context"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// handleReleasePeer implements §4.2 release-peer: tear down the lifecycle
// graph and, on reason=shutdown, close the connection with a terminal
// disconnected write.
func (h *Handler) handleReleasePeer(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	p := h.boundPeer()
	if p == nil {
		return handler.NewErrorResponse(500, "internal_error", "network handler not bound to a peer")
	}
	if req.Params.Type != types.TypeNetworkReleaseRequest {
		return handler.NewErrorResponse(400, "invalid_params",
			"release-peer params must be "+types.TypeNetworkReleaseRequest+", got "+req.Params.Type)
	}
	var params types.ReleaseRequestData
	if err := decodeParams(req.Params, &params); err != nil {
		return handler.NewErrorResponse(400, "invalid_params", "decode release-request: "+err.Error())
	}
	if params.PeerID == "" {
		return handler.NewErrorResponse(400, "invalid_params", "release-request requires peer_id")
	}
	peerID := crypto.PeerID(params.PeerID)
	reason := params.EffectiveReason()

	// Stop the retry timer and forget the session first — a timer firing
	// mid-teardown must find no session and bail.
	sess := h.dropSession(peerID)

	// Remove the lifecycle continuations — the inbox residents and the
	// managed-namespace backoff resident. Real tree deletion (the §4.2
	// pseudocode's `put null`): TreeRemove drops the binding and leaves the
	// deletion marker the tree layer records.
	var cleanedUp []string
	for _, prefix := range []string{inboxPrefix(peerID), managedPrefix(peerID)} {
		for _, entry := range hctx.LocationIndex.List(prefix) {
			if _, ok, _ := hctx.TreeRemove(entry.Path, "release-peer"); ok {
				cleanedUp = append(cleanedUp, entry.Path)
			}
		}
	}

	// Remove the lifecycle subscriptions (self-owned — unsubscribe rides
	// the peer's own identity).
	if sess != nil {
		sess.mu.Lock()
		subIDs := append([]string(nil), sess.subscriptionIDs...)
		sess.mu.Unlock()
		for _, id := range subIDs {
			if err := h.unsubscribeLifecycle(ctx, id); err != nil {
				h.debugf("release-peer %s: unsubscribe %s: %v", peerID, id, err)
			}
		}
	}

	// Close the connection on shutdown; idle/migration leave it (and any
	// subscriptions) for potential resumption (§4.2).
	if reason == "shutdown" {
		p.EvictRemoteConnection(peerID)
		// Terminal §3.13 write: this relationship is deliberately over.
		// Eviction alone would leave the last transition value standing.
		if remoteHash, err := protocol.ResolveRemoteIdentityHash(peerID, nil); err == nil {
			if _, werr := protocol.WritePeerStatus(
				p.Store(), p.LocationIndex(), string(p.PeerID()), remoteHash,
				types.PeerStatusData{
					PeerID: string(peerID),
					Status: types.PeerStatusDisconnected,
				},
			); werr != nil {
				h.debugf("release-peer %s: terminal status write: %v", peerID, werr)
			}
			if _, cerr := protocol.MarkConnectionClosed(
				p.Store(), p.LocationIndex(), string(p.PeerID()), remoteHash,
			); cerr != nil {
				h.debugf("release-peer %s: connection-state write: %v", peerID, cerr)
			}
		}
	}

	if cleanedUp == nil {
		cleanedUp = []string{}
	}
	return handler.NewResponse(200, types.TypeNetworkReleaseResult, types.ReleaseResultData{
		PeerID:    string(peerID),
		CleanedUp: cleanedUp,
	})
}

// handleStatus implements §4.3 status: a read-model over the §3.13
// system/peer/status entities plus session bookkeeping. pending_count is
// bare zero throughout — Go ships no §8 outbox (Amendment 11: the
// bare-error terminal is conformant; rung 4 stays optional).
func (h *Handler) handleStatus(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	// Subscription counts per delivery peer, one scan.
	subCounts := make(map[string]uint64)
	for _, entry := range hctx.LocationIndex.List("system/subscription/") {
		subEnt, ok := hctx.Store.Get(entry.Hash)
		if !ok || subEnt.Type != types.TypeSubscription {
			continue
		}
		sub, err := types.SubscriptionDataFromEntity(subEnt)
		if err != nil {
			continue
		}
		if pid, ok := peerFromDeliverURI(sub.DeliverURI); ok {
			subCounts[pid]++
		}
	}

	peers := []types.NetworkPeerSummaryData{}
	for _, entry := range hctx.LocationIndex.List(types.TypePeerStatus + "/") {
		statusEnt, ok := hctx.Store.Get(entry.Hash)
		if !ok || statusEnt.Type != types.TypePeerStatus {
			continue
		}
		d, err := types.PeerStatusDataFromEntity(statusEnt)
		if err != nil {
			continue
		}
		sessionID := ""
		if sess := h.getSession(crypto.PeerID(d.PeerID)); sess != nil {
			sessionID = sess.sessionID
		}
		peers = append(peers, types.NetworkPeerSummaryData{
			PeerID:        d.PeerID,
			SessionID:     sessionID,
			Status:        d.Status,
			PendingCount:  0,
			Subscriptions: subCounts[d.PeerID],
		})
	}

	return handler.NewResponse(200, types.TypeNetworkStatus, types.NetworkStatusData{
		MaintainedPeers: peers,
		PendingCount:    0,
	})
}

// handleClose implements §4.4 close: best-effort remote notification, then
// the local §3.13 close transition. Subscription disposition follows the
// reason (§9.1): shutdown expects the remote to drop its subscriptions;
// idle/migration preserve them for resumption — locally there is nothing to
// delete on either branch (release-peer owns lifecycle teardown).
func (h *Handler) handleClose(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	p := h.boundPeer()
	if p == nil {
		return handler.NewErrorResponse(500, "internal_error", "network handler not bound to a peer")
	}
	if req.Params.Type != types.TypeNetworkCloseRequest {
		return handler.NewErrorResponse(400, "invalid_params",
			"close params must be "+types.TypeNetworkCloseRequest+", got "+req.Params.Type)
	}
	var params types.CloseRequestData
	if err := decodeParams(req.Params, &params); err != nil {
		return handler.NewErrorResponse(400, "invalid_params", "decode close-request: "+err.Error())
	}
	if params.PeerID == "" || params.Reason == "" {
		return handler.NewErrorResponse(400, "invalid_params", "close-request requires peer_id and reason")
	}
	peerID := crypto.PeerID(params.PeerID)

	// Best-effort remote close notification (§9.2). The cohort's connect
	// handlers predate a `close` operation — an unknown_operation error (or
	// a dead transport) must not block the local close.
	if p.IsConnected(peerID) {
		closeURI := fmt.Sprintf("entity://%s/system/protocol/connect", peerID)
		if _, err := p.RemoteExecute(ctx, closeURI, "close", req.Params, nil); err != nil {
			h.debugf("close %s: remote notification failed (best-effort): %v", peerID, err)
		}
	}

	// Local transition: evict the pooled binding (keepalive loop exits on
	// its next tick) and record the §3.13 close.
	p.EvictRemoteConnection(peerID)
	if remoteHash, err := protocol.ResolveRemoteIdentityHash(peerID, nil); err == nil {
		if _, cerr := protocol.MarkConnectionClosed(
			p.Store(), p.LocationIndex(), string(p.PeerID()), remoteHash,
		); cerr != nil {
			h.debugf("close %s: connection-state write: %v", peerID, cerr)
		}
	}

	raw, _ := ecf.Encode(map[string]interface{}{"closed": true, "reason": params.Reason})
	ent, _ := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
	return &handler.Response{Status: 200, Result: ent}, nil
}

// peerFromDeliverURI extracts the peer id from an entity://{peer}/... URI.
func peerFromDeliverURI(uri string) (string, bool) {
	const scheme = "entity://"
	if !strings.HasPrefix(uri, scheme) {
		return "", false
	}
	rest := uri[len(scheme):]
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i], true
	}
	if rest != "" {
		return rest, true
	}
	return "", false
}

// decodeParams ECF-decodes an entity's data into out.
func decodeParams(e entity.Entity, out interface{}) error {
	if len(e.Data) == 0 {
		return fmt.Errorf("empty params")
	}
	return ecf.Decode(e.Data, out)
}
