package peerwiring

import (
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/relay"
)

// SelfAdvertiseHandlerPattern attributes the self-advertise binding to the
// relay when the location index records mutation context (matches the shape
// publishedroot uses for its own authority writes).
const SelfAdvertiseHandlerPattern = "system/relay/self-advertise"

// PublishSelfAdvertise authors, signs, and binds the relay's OWN §4.1 advertise
// carrying its configured §8 store bounds (limits.max_retention_ms /
// max_storage_bytes).
//
// This is the "peer-builder seam" the relay handler's handleAdvertise defers to
// (relay.go: "the signature carriage + publication lives at the peer-builder
// seam (it has the keypair)"): handleAdvertise binds an INBOUND advertise and
// never signs, because the handler has no keypair. Here the peer does.
//
// §4.1 makes publishing the bound a MUST *when enforced*: a sender choosing a
// relay, and a peer choosing which relays to name in its §3.5 inbox-relay
// declaration, both depend on how long an entry is held and how full the store
// may get — a ceiling only the relay can read configures behaviour no
// counterparty can observe before depending on it. Call this when
// h.HasStoreBounds() is true.
//
// V7 §5.2: the advertise MUST be signed by relay_peer_id; the signature reaches
// at the invariant-pointer path system/signature/{hex(advertise.content_hash)}.
// The advertise binds at RelayAdvertisePath(peer_id). Both relative paths are
// bound through the peer's NAMESPACED location index, so they qualify to the
// same key space a wire tree:get reads them from (the B4 writer/reader
// one-key-space rule).
//
// Ordering is signature-before-pointer, the same discipline publishedroot and
// SUBSTITUTE §7.3 state: bind what is referenced (the signature) before the
// reference that makes the advertise reachable, so a reader that observes the
// advertise can always resolve its signature.
func PublishSelfAdvertise(p *peer.Peer, h *relay.Handler) (entity.Entity, error) {
	peerID := string(p.PeerID())

	adv := types.AdvertiseData{
		// v1 serves Mode-F (forward) + Mode-S (store-poll).
		Modes:        []string{types.RelayModeForward, types.RelayModeStorePoll},
		Endpoints:    []cbor.RawMessage{},
		Limits:       h.ConfiguredLimits(),
		CapsRequired: []string{types.CapRelayPoll},
	}
	advEnt, err := adv.ToEntity()
	if err != nil {
		return entity.Entity{}, fmt.Errorf("encode relay advertise: %w", err)
	}

	kp := p.Keypair()
	sig := kp.Sign(advEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    advEnt.ContentHash,
		Signer:    p.Identity().ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sig,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, fmt.Errorf("encode relay advertise signature: %w", err)
	}

	cs := p.Store()
	if _, err := cs.Put(advEnt); err != nil {
		return entity.Entity{}, fmt.Errorf("store relay advertise: %w", err)
	}
	if _, err := cs.Put(sigEnt); err != nil {
		return entity.Entity{}, fmt.Errorf("store relay advertise signature: %w", err)
	}

	li := p.LocationIndex()
	ctx := &store.MutationContext{
		AuthorHash:     p.Identity().ContentHash,
		HandlerPattern: SelfAdvertiseHandlerPattern,
		Operation:      relay.OpAdvertise,
	}
	// Signature first (referenced-before-reference), advertise second.
	sigPath := types.LocalSignaturePath(advEnt.ContentHash)
	if err := bind(li, sigPath, sigEnt.ContentHash, ctx); err != nil {
		return entity.Entity{}, fmt.Errorf("bind relay advertise signature at %s: %w", sigPath, err)
	}
	advPath := types.RelayAdvertisePath(peerID)
	if err := bind(li, advPath, advEnt.ContentHash, ctx); err != nil {
		return entity.Entity{}, fmt.Errorf("bind relay advertise at %s: %w", advPath, err)
	}
	return advEnt, nil
}

// bind writes path→hash through the location index, using SetWithContext when
// the index records mutation context and falling back to Set otherwise
// (the publishedroot precedent).
func bind(li store.LocationIndex, path string, h hash.Hash, ctx *store.MutationContext) error {
	if cw, ok := li.(store.ContextualWriter); ok {
		_, err := cw.SetWithContext(path, h, ctx)
		return err
	}
	return li.Set(path, h)
}
