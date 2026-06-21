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
		resp, err := d.RemoteExecute(ctx, execData.DeliverTo.URI, op, deliveryEntity, resource)
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
