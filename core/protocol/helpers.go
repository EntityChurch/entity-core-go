package protocol

import (
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func decodeEntity(data []byte, v interface{}) error {
	return ecf.Decode(data, v)
}

func decodeRawEntity(data []byte, e *entity.Entity) error {
	return ecf.Decode(data, e)
}

func encodeToRaw(e entity.Entity) ([]byte, error) {
	return ecf.Encode(e)
}

// CreateAuthenticatedExecute creates a fully authenticated EXECUTE envelope.
// The envelope includes the identity, capability, and signature entities needed
// for the remote peer to verify the capability chain.
// AsyncDelivery holds optional extras for the EXECUTE entity.
//
// Despite the name, this struct also carries `Extras` — additional
// entities that must land in the receiving handler's hctx.Included
// regardless of async delivery. The cross-peer subscribe path is the
// motivating case: the subscription handler reads its deliver_token
// from hctx.Included (per EXTENSION-SUBSCRIPTION.md), so any token
// referenced via subReq.DeliverToken must accompany the EXECUTE on
// the wire even though it has nothing to do with async delivery of
// this request's response. Without Extras, cross-peer subscribe
// using a params-referenced deliver_token returns
// `400 missing_deliver_token`.
//
// See the workbench review of cross-peer feedback included-extras for
// context.
type AsyncDelivery struct {
	DeliverTo    *types.DeliverySpec
	DeliverToken entity.Entity     // capability token entity (included in envelope)
	Bounds       *types.BoundsData // optional bounds (cascade_depth, chain_id, etc.)
	// Extras is a map of additional entities to include in the EXECUTE
	// envelope's Included field. Used when the receiving handler reads
	// from hctx.Included entities that are referenced via params hashes
	// (e.g. subscription.deliver_token, continuation.dispatch_capability)
	// rather than carried as auth-chain entities. Nil and empty maps
	// are equivalent.
	Extras map[hash.Hash]entity.Entity
	// CapabilityOverride, when non-nil, replaces the connection's session
	// capability as the dispatched EXECUTE's `capability`. Used for
	// cross-peer continuation dispatch so the EXECUTE is authorized by the
	// scoped dispatch_capability (B-rooted, installer in-chain) rather than
	// silently riding the broader connection authority — V7 §6.8 "no
	// silent escalation" / EXTENSION-CONTINUATION §4.2 case 3. The cap's
	// full chain MUST also be in Extras. Nil = connection default.
	CapabilityOverride *entity.Entity
	// DurabilityRequest, when non-nil, sets the optional request-side
	// durability marker on the EXECUTE (EXTENSION-DURABILITY §2 —
	// exploratory extension). Independent of DeliverTo/DeliverToken — it may
	// be set with or without async delivery.
	DurabilityRequest *types.DurabilityRequestData
}

func CreateAuthenticatedExecute(
	kp crypto.Keypair,
	identityEntity entity.Entity,
	capEntity entity.Entity,
	requestID, uri, operation string,
	params entity.Entity,
	resource *types.ResourceTarget,
	async ...*AsyncDelivery,
) (entity.Envelope, error) {
	paramsRaw, err := ecf.Encode(params)
	if err != nil {
		return entity.Envelope{}, err
	}

	execData := types.ExecuteData{
		RequestID:  requestID,
		URI:        uri,
		Operation:  operation,
		Resource:   resource,
		Params:     cbor.RawMessage(paramsRaw),
		Author:     identityEntity.ContentHash,
		Capability: capEntity.ContentHash,
	}

	// Include optional fields from AsyncDelivery.
	if len(async) > 0 && async[0] != nil {
		execData.DeliverTo = async[0].DeliverTo
		execData.DeliverToken = async[0].DeliverToken.ContentHash
		execData.Bounds = async[0].Bounds
		execData.DurabilityRequest = async[0].DurabilityRequest
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}

	sig := kp.Sign(execEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    execEntity.ContentHash,
		Signer:    identityEntity.ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}

	included := map[hash.Hash]entity.Entity{
		identityEntity.ContentHash: identityEntity,
		capEntity.ContentHash:      capEntity,
		sigEntity.ContentHash:      sigEntity,
	}

	// Include deliver_token entity in envelope if async delivery.
	if len(async) > 0 && async[0] != nil && !async[0].DeliverToken.ContentHash.IsZero() {
		included[async[0].DeliverToken.ContentHash] = async[0].DeliverToken
	}

	// Include any caller-supplied extras (e.g. cross-peer subscribe's
	// deliver_token + signature). Auth-chain entries above (identity /
	// cap / sig / deliver_token) win on hash collision.
	if len(async) > 0 && async[0] != nil {
		for h, ent := range async[0].Extras {
			if _, exists := included[h]; exists {
				continue
			}
			included[h] = ent
		}
	}

	return entity.NewEnvelope(execEntity, included), nil
}
