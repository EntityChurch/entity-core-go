package protocol

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

func (d *Dispatcher) processAsyncDelivery(ctx context.Context, invoke func(context.Context) (*handler.Response, error), execData types.ExecuteData, deliverTokenEntity entity.Entity, originalIncluded map[hash.Hash]entity.Entity) {
	resp, err := invoke(ctx)
	if err != nil {
		d.debugf("async delivery: handler error: %v", err)
		return
	}

	d.debugf("async delivery: handler returned status=%d, delivering to %s", resp.Status, execData.DeliverTo.URI)

	if err := d.deliverToInbox(ctx, execData, resp, deliverTokenEntity, originalIncluded); err != nil {
		d.debugf("async delivery: delivery failed: %v", err)
	}
}

// deliverToInbox constructs and dispatches an inbox delivery EXECUTE.
func (d *Dispatcher) deliverToInbox(ctx context.Context, execData types.ExecuteData, resp *handler.Response, deliverTokenEntity entity.Entity, originalIncluded map[hash.Hash]entity.Entity) error {
	// Construct delivery params.
	resultRaw, err := encodeToRaw(resp.Result)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	delivery := types.InboxDeliveryData{
		OriginalRequestID: execData.RequestID,
		Status:            resp.Status,
		Result:            resultRaw,
	}
	deliveryEntity, err := delivery.ToEntity()
	if err != nil {
		return fmt.Errorf("create delivery entity: %w", err)
	}

	identityEntity, err := d.LocalKeypair.IdentityEntity()
	if err != nil {
		return fmt.Errorf("get identity: %w", err)
	}

	// Default operation to "receive" if empty.
	op := execData.DeliverTo.Operation
	if op == "" {
		op = "receive"
	}

	resource := &types.ResourceTarget{Targets: []string{execData.DeliverTo.URI}}

	env, err := CreateAuthenticatedExecute(
		d.LocalKeypair,
		identityEntity,
		deliverTokenEntity,
		fmt.Sprintf("dlv-%s", execData.RequestID),
		execData.DeliverTo.URI,
		op,
		deliveryEntity,
		resource,
	)
	if err != nil {
		return fmt.Errorf("create inbox execute: %w", err)
	}

	// Include entities from the original request envelope — this carries
	// the deliver_token's signature and granter identity, which are needed
	// for capability chain verification on the delivery dispatch.
	for h, ent := range originalIncluded {
		if _, exists := env.Included[h]; !exists {
			env.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
		}
	}

	// Dispatch locally or remotely.
	if isRemoteURI(execData.DeliverTo.URI, d.LocalPeerID) {
		if d.RemoteExecute == nil {
			return fmt.Errorf("remote execute not available for inbox delivery to %s", execData.DeliverTo.URI)
		}
		d.debugf("delivery: remote inbox delivery to %s", execData.DeliverTo.URI)
		// Back-direction authority, taxonomy row 2 (scoped reentry
		// delivery): the delivery EXECUTE is authorized by the
		// **deliver_token** — the cap the requester granted us for exactly
		// this delivery — never by whatever broad authority the connection
		// happens to carry. Before this, the fully-authorized `env` built
		// above was silently discarded on the remote branch and the
		// delivery rode the connection's session capability instead. On a
		// dialed connection that cap is the one the far side granted us
		// (works by accident); on the V7 §6.11 reentry path — the
		// profile-less peer we reach only by reusing the connection IT
		// opened — it is the cap WE minted for THEM, so `grantee != author`
		// at the far side and the delivery dies `401 unresolvable_grantee`.
		// Resolution is not authority: reusing an inbound connection
		// resolves the peer, it does not authorize the dispatch.
		//
		// Guarded on the token naming US as grantee, because the far side's
		// verify_request compares `grantee == author` and we are the author.
		// The local-async entry point (local.go) synthesizes a deliver_token
		// from the caller's own HandlerGrant, which is locally rooted and
		// grants us nothing at the remote — that case keeps the pre-existing
		// path rather than presenting a cap that cannot verify.
		var async []*AsyncDelivery
		if tokenGranteeIs(deliverTokenEntity, identityEntity.ContentHash) {
			tokenCap := deliverTokenEntity
			async = append(async, &AsyncDelivery{
				CapabilityOverride: &tokenCap,
				// The token's own signature + granter identity ride the
				// original request's included set; without them the far
				// side cannot walk the chain it just authorized.
				Extras: originalIncluded,
			})
		} else {
			d.debugf("delivery: deliver_token does not name us as grantee; remote delivery falls back to connection authority")
		}
		resp, err := d.RemoteExecute(ctx, execData.DeliverTo.URI, op, deliveryEntity, resource, async...)
		if err != nil {
			return fmt.Errorf("remote inbox delivery: %w", err)
		}
		if resp.Status >= 400 {
			return fmt.Errorf("remote inbox delivery returned status %d", resp.Status)
		}
		return nil
	}

	// Local dispatch.
	_, err = d.DispatchEnvelope(ctx, env, nil)
	return err
}

// tokenGranteeIs reports whether tok is a capability token whose grantee is
// exactly grantee. Used to decide whether a deliver_token can authorize an
// outbound delivery we author: V7 §5.2 requires `grantee == author` at the
// far side, so a token granted to somebody else (or an undecodable one)
// cannot carry our dispatch.
func tokenGranteeIs(tok entity.Entity, grantee hash.Hash) bool {
	if tok.Type == "" || tok.ContentHash.IsZero() || grantee.IsZero() {
		return false
	}
	data, err := types.CapabilityTokenDataFromEntity(tok)
	if err != nil {
		return false
	}
	return data.Grantee == grantee
}

// make202Response creates a 202 Accepted acknowledgement for async callbacks.
func (d *Dispatcher) make202Response(requestID string) (entity.Envelope, error) {
	respData := types.ExecuteResponseData{
		RequestID: requestID,
		Status:    202,
		Result:    []byte{0xf6}, // CBOR null
	}
	respEntity, err := respData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(respEntity, nil), nil
}

// qualifyIfRelative qualifies a peer-relative path with the local peer ID.
// Already-absolute paths (leading "/") pass through unchanged. Detection is
// HasPrefix("/"), not heuristic — see V7 §1.4 (PROPOSAL-PATH-ABSOLUTE-RELATIVE-CONVENTION).
