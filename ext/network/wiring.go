package network

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// selfExecute dispatches a self-authored local EXECUTE through the bound
// peer's dispatcher, authenticated with the network handler's own grant —
// the same pattern subscription.MakeDeliveryFunc uses for notification
// delivery. Needed where the propagated caller identity is wrong for the
// action: the lifecycle subscriptions are the PEER's (subscriber_identity
// must be the local peer so release-peer can unsubscribe them), and the
// backoff-timer advance fires outside any request context.
//
// extras ride the envelope's `included` map (deliver tokens + signatures).
// Returns the decoded EXECUTE-RESPONSE status and raw result.
// chainID, when non-empty, is carried as the EXECUTE's bounds.chain_id — the
// §3.11 coordinate every chain-error marker downstream of this dispatch is
// filed under. Pass the session's maintain chain for lifecycle dispatches: it
// is what makes maintain-result's advertised chain_id answerable, since a
// caller watching system/runtime/chain-errors/lost/{chain_id}/ only sees
// anything if the dispatches actually ran under it. Empty for dispatches that
// belong to no chain.
func (h *Handler) selfExecute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, chainID string, extras ...entity.Entity) (uint, cbor.RawMessage, error) {
	p := h.boundPeer()
	if p == nil {
		return 0, nil, fmt.Errorf("network handler not bound to a peer")
	}
	capEnt, sigEnt, err := h.handlerGrant()
	if err != nil {
		return 0, nil, err
	}
	requestID := fmt.Sprintf("network-%s-%d", operation, time.Now().UnixNano())
	var async []*protocol.AsyncDelivery
	if chainID != "" {
		async = append(async, &protocol.AsyncDelivery{
			Bounds: &types.BoundsData{ChainID: chainID},
		})
	}
	env, err := protocol.CreateAuthenticatedExecute(
		p.Keypair(), p.Identity(), capEnt, requestID, uri, operation, params, resource, async...)
	if err != nil {
		return 0, nil, fmt.Errorf("create %s execute: %w", operation, err)
	}
	env.Include(sigEnt)
	for _, e := range extras {
		env.Include(e)
	}
	respEnv, err := p.Dispatcher().DispatchLocalEnvelope(ctx, env)
	if err != nil {
		return 0, nil, err
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, nil, fmt.Errorf("decode %s response: %w", operation, err)
	}
	// The response's result field carries a full entity encoding; callers
	// want the inner data payload.
	if len(respData.Result) == 0 {
		return respData.Status, nil, nil
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		return respData.Status, nil, fmt.Errorf("decode %s result entity: %w", operation, err)
	}
	return respData.Status, resultEnt.Data, nil
}

// handlerGrant resolves the network handler's own grant (bound at
// system/capability/grants/system/network by createHandlerGrants) plus its
// reconstructed signature entity — the pair a self-authored envelope carries
// so VerifyChain resolves to the local root.
func (h *Handler) handlerGrant() (entity.Entity, entity.Entity, error) {
	p := h.boundPeer()
	if p == nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("network handler not bound to a peer")
	}
	grantPath := "system/capability/grants/" + HandlerPattern
	capHash, ok := p.LocationIndex().Get(grantPath)
	if !ok {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("handler grant not found at %s", grantPath)
	}
	capEnt, ok := p.Store().Get(capHash)
	if !ok {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("handler grant entity not in store: %s", capHash)
	}
	// Deterministic ed25519: re-signing the same hash reproduces the
	// install-time signature entity byte-for-byte.
	kp := p.Keypair()
	sig := kp.Sign(capEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    p.Identity().ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sig,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("build grant signature: %w", err)
	}
	return capEnt, sigEnt, nil
}

// mintDeliverToken creates + stores a delivery token authorizing inbox
// receive at deliverURI, self-granted under the peer's own identity (the
// self-owned-namespace pattern: granter == grantee == the local peer, root
// token, signed by the peer's keypair). No expiry — the lifecycle
// subscriptions must survive arbitrarily long disconnects; release-peer is
// the deliberate teardown.
func (h *Handler) mintDeliverToken(deliverURI string) (entity.Entity, entity.Entity, error) {
	p := h.boundPeer()
	if p == nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("network handler not bound to a peer")
	}
	identity := p.Identity()
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/inbox"}},
			Resources:  types.CapabilityScope{Include: []string{deliverURI}},
			Operations: types.CapabilityScope{Include: []string{"receive"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: uint64(time.Now().UnixMilli()),
	}
	tokenEnt, err := tokenData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("build deliver token: %w", err)
	}
	kp := p.Keypair()
	sig := kp.Sign(tokenEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    tokenEnt.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sig,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("build deliver token signature: %w", err)
	}
	if _, err := p.Store().Put(tokenEnt); err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("store deliver token: %w", err)
	}
	if _, err := p.Store().Put(sigEnt); err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("store deliver token signature: %w", err)
	}
	return tokenEnt, sigEnt, nil
}

// subscribeLifecycle creates one lifecycle subscription on the remote's
// status path delivering to deliverURI, via a self-authored subscribe.
// Returns the subscription id.
func (h *Handler) subscribeLifecycle(ctx context.Context, remoteHash hash.Hash, deliverURI string) (string, error) {
	tokenEnt, sigEnt, err := h.mintDeliverToken(deliverURI)
	if err != nil {
		return "", err
	}
	subReq := types.SubscriptionRequestData{
		// The floor's demotion/establish writes are same-path overwrites —
		// every transition surfaces as "updated" (first-ever write as
		// "created", covered too).
		Events: []string{"created", "updated"},
		DeliverTo: types.DeliverySpec{
			URI:       deliverURI,
			Operation: "receive",
		},
		DeliverToken: tokenEnt.ContentHash,
	}
	params, err := subReq.ToEntity()
	if err != nil {
		return "", fmt.Errorf("build subscribe request: %w", err)
	}
	p := h.boundPeer()
	identity := p.Identity()
	// Bare pattern — the subscribe handler qualifies it with the local
	// peer id, matching the absolute PeerStatusPath the floor writes to.
	// Hex segment is the 66-char invariant-pointer form (format byte
	// included) via Bytes(), same as PeerStatusPath.
	statusPattern := types.TypePeerStatus + "/" + hex.EncodeToString(remoteHash.Bytes())
	resource := &types.ResourceTarget{Targets: []string{statusPattern}}
	// No chain: this is imperative setup inside the maintain-peer request,
	// not a chain dispatch — a failure surfaces synchronously to the caller
	// rather than as a chain-error marker, so there is no coordinate to file
	// it under and inventing one would be the very habit being fixed.
	status, result, err := h.selfExecute(ctx, "system/subscription", "subscribe", params, resource, "",
		tokenEnt, sigEnt, identity)
	if err != nil {
		return "", fmt.Errorf("lifecycle subscribe: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("lifecycle subscribe returned %d: %s", status, errorCode(result))
	}
	var sub struct {
		SubscriptionID string `cbor:"subscription_id"`
	}
	if err := ecf.Decode(result, &sub); err != nil || sub.SubscriptionID == "" {
		return "", fmt.Errorf("lifecycle subscribe result carried no subscription_id")
	}
	return sub.SubscriptionID, nil
}

// unsubscribeLifecycle removes one lifecycle subscription by id via a
// self-authored unsubscribe (the subscriptions are peer-owned).
func (h *Handler) unsubscribeLifecycle(ctx context.Context, subscriptionID string) error {
	cancel := types.SubscriptionCancelData{SubscriptionID: subscriptionID}
	raw, err := ecf.Encode(cancel)
	if err != nil {
		return err
	}
	params, err := entity.NewEntity(types.TypeSubscriptionCancel, cbor.RawMessage(raw))
	if err != nil {
		return err
	}
	status, result, err := h.selfExecute(ctx, "system/subscription", "unsubscribe", params, nil, "")
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("unsubscribe %s returned %d: %s", subscriptionID, status, errorCode(result))
	}
	return nil
}

// errorCode extracts the error code from a raw error result, best-effort.
func errorCode(result cbor.RawMessage) string {
	if len(result) == 0 {
		return ""
	}
	var ed types.ErrorData
	if err := ecf.Decode(result, &ed); err != nil {
		return ""
	}
	return ed.Code
}
