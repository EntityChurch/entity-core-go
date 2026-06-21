package subscription

import (
	"context"
	"fmt"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// MakeDeliveryFunc creates a DeliverFunc that dispatches notification
// deliveries through the given dispatcher using the peer's handler grants.
//
// For local delivery (same-peer), the server uses its own handler grant for the
// inbox handler — not the subscriber's delivery token. The subscriber's delivery
// token authorizes cross-peer delivery (verified on the subscriber's side where
// granter == local_peer). For local dispatch, the server is calling its own handler
// and needs a capability whose root granter is itself.
func MakeDeliveryFunc(
	kp crypto.Keypair,
	identity entity.Entity,
	cs store.ContentStore,
	li store.LocationIndex,
	dispatcher *protocol.Dispatcher,
) DeliverFunc {
	// Per-DeliverFunc handler-grant cache. The lookup is stable while the
	// peer's identity + handler grant for system/inbox don't rotate: the
	// grant entity is fetched by content hash, and findSignatureFor
	// reconstructs a deterministic ed25519 signature only to compute the
	// signature entity's content hash. Caching the resolved
	// (capEntity, capSigEntity) eliminates ~19.5µs/delivery of redundant
	// signing on the hot cross-peer delivery path (BUG-CLASSES H-G2 /
	// workbench-go Stage 5 F2a).
	//
	// Keyed by handler pattern (currently always "system/inbox" but kept
	// general so a future delivery path that calls a different handler
	// still benefits). Invalidated implicitly when the engine is rebuilt;
	// the underlying grant is content-addressed so rotation is observable
	// only by replacing the cap entity at the grant path, which is not
	// supported in-flight today.
	type cachedGrant struct {
		capEntity    entity.Entity
		capSigEntity entity.Entity
	}
	var grantCache sync.Map // pattern (string) -> cachedGrant

	return func(ctx context.Context, req DeliveryRequest) error {
		var capEntity, capSigEntity entity.Entity
		const handlerPattern = "system/inbox"
		if v, ok := grantCache.Load(handlerPattern); ok {
			cg := v.(cachedGrant)
			capEntity, capSigEntity = cg.capEntity, cg.capSigEntity
		} else {
			ce, se, err := lookupHandlerGrant(kp, identity, cs, li, handlerPattern)
			if err != nil {
				return fmt.Errorf("lookup inbox handler grant: %w", err)
			}
			grantCache.Store(handlerPattern, cachedGrant{capEntity: ce, capSigEntity: se})
			capEntity, capSigEntity = ce, se
		}

		// Build optional extras — bounds with cascade_depth (G-3, SUB §4.5).
		var extras *protocol.AsyncDelivery
		if req.CascadeDepth != nil || req.ChainID != "" {
			extras = &protocol.AsyncDelivery{
				Bounds: &types.BoundsData{
					CascadeDepth: req.CascadeDepth,
					ChainID:      req.ChainID,
				},
			}
		}

		resource := req.Resource
		env, err := protocol.CreateAuthenticatedExecute(
			kp,
			identity,
			capEntity,
			req.RequestID,
			req.DeliverURI,
			"receive",
			req.Params,
			resource,
			extras,
		)
		if err != nil {
			return fmt.Errorf("create notification execute: %w", err)
		}

		// Include the handler grant signature (granter = local peer, passes VerifyChain).
		env.Include(capSigEntity)

		// EXTENSION-SUBSCRIPTION v3.14 §4.2: when the subscription opted into
		// include_payload, the engine attached the changed entity in req.Included.
		// Ride it through to the receiver via the envelope's `included` map so
		// the continuation chain can extract it locally without a cross-peer GET.
		for _, ent := range req.Included {
			env.Include(ent)
		}

		_, err = dispatcher.DispatchLocalEnvelope(ctx, env)
		return err
	}
}

// lookupHandlerGrant retrieves the server's self-granted capability for a handler pattern.
func lookupHandlerGrant(kp crypto.Keypair, identity entity.Entity, cs store.ContentStore, li store.LocationIndex, pattern string) (entity.Entity, entity.Entity, error) {
	grantPath := "system/capability/grants/" + pattern
	capHash, ok := li.Get(grantPath)
	if !ok {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("handler grant not found at %s", grantPath)
	}
	capEntity, ok := cs.Get(capHash)
	if !ok {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("handler grant entity not in store: %s", capHash)
	}

	// Find the signature for this capability token.
	sigEntity, ok := findSignatureFor(kp, identity, cs, capEntity.ContentHash)
	if !ok {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("no signature found for handler grant %s", capHash)
	}

	return capEntity, sigEntity, nil
}

// findSignatureFor reconstructs and looks up the signature for the given hash.
func findSignatureFor(kp crypto.Keypair, identity entity.Entity, cs store.ContentStore, targetHash hash.Hash) (entity.Entity, bool) {
	sig := kp.Sign(targetHash.Bytes())
	sigData := types.SignatureData{
		Target:    targetHash,
		Signer:    identity.ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, false
	}
	// Verify it's in the store.
	stored, ok := cs.Get(sigEntity.ContentHash)
	if ok {
		return stored, true
	}
	return sigEntity, true // Return freshly created — same content
}
