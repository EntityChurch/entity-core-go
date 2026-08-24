package protocol

import (
	"context"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// capturedDispatch records what deliverToInbox handed RemoteExecute.
type capturedDispatch struct {
	uri   string
	async []*AsyncDelivery
}

// newDeliveryDispatcher builds a dispatcher whose RemoteExecute is a stub
// recording the outbound dispatch instead of touching a wire.
func newDeliveryDispatcher(t *testing.T, captured *capturedDispatch) (*Dispatcher, crypto.Keypair, entity.Entity) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	identity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity: %v", err)
	}
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))
	d := NewDispatcher(handler.NewRegistry(), cs, li, kp, nil)
	d.RemoteExecute = func(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, async ...*AsyncDelivery) (*handler.Response, error) {
		captured.uri = uri
		captured.async = async
		return &handler.Response{Status: 200}, nil
	}
	return d, kp, identity
}

// mintToken builds a capability token granting everything, from granter to
// grantee. Only granter/grantee matter to the authority selection under test.
func mintToken(t *testing.T, granter, grantee hash.Hash) entity.Entity {
	t.Helper()
	tok, err := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(granter),
		Grantee:   grantee,
		CreatedAt: 1,
	}.ToEntity()
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return tok
}

func remoteDeliverySpec(t *testing.T) (*types.DeliverySpec, hash.Hash) {
	t.Helper()
	remoteKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate remote keypair: %v", err)
	}
	remoteIdentity, err := remoteKP.IdentityEntity()
	if err != nil {
		t.Fatalf("remote identity: %v", err)
	}
	return &types.DeliverySpec{
		URI:       "entity://" + string(remoteKP.PeerID()) + "/system/inbox",
		Operation: "receive",
	}, remoteIdentity.ContentHash
}

func stubResponse(t *testing.T) *handler.Response {
	t.Helper()
	raw, err := ecf.Encode(map[string]any{"ok": true})
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	result, err := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("build result entity: %v", err)
	}
	return &handler.Response{Status: 200, Result: result}
}

// TestRemoteInboxDeliveryCarriesDeliverToken pins back-direction authority
// taxonomy row 2 for cross-peer async delivery: the delivery EXECUTE MUST be
// authorized by the deliver_token the requester granted us, never by whatever
// authority the underlying connection happens to carry.
//
// Regression shape: deliverToInbox built a fully-authorized envelope from the
// deliver_token and then discarded it on the remote branch, calling
// RemoteExecute with no capability override. On a dialed connection the
// session cap masked the omission; on the V7 §6.11 reentry path — the
// profile-less peer reachable only by reusing the connection IT opened — the
// session cap is the one WE minted for THEM, so `grantee != author` at the far
// side and the delivery dies 401 unresolvable_grantee. Resolution is not
// authority: reusing an inbound connection resolves the peer, it does not
// authorize the dispatch.
func TestRemoteInboxDeliveryCarriesDeliverToken(t *testing.T) {
	var captured capturedDispatch
	d, _, identity := newDeliveryDispatcher(t, &captured)

	spec, requesterHash := remoteDeliverySpec(t)
	// The requester granted US the delivery authority: granter = requester,
	// grantee = this peer. That is exactly what makes `grantee == author`
	// hold when we author the delivery.
	token := mintToken(t, requesterHash, identity.ContentHash)

	// The token's supporting chain rides the original request's included set.
	supporting, err := entity.NewEntity("primitive/any", cbor.RawMessage([]byte{0xf6}))
	if err != nil {
		t.Fatalf("build supporting entity: %v", err)
	}
	originalIncluded := map[hash.Hash]entity.Entity{supporting.ContentHash: supporting}

	execData := types.ExecuteData{RequestID: "req-1", DeliverTo: spec, DeliverToken: token.ContentHash}
	if err := d.deliverToInbox(context.Background(), execData, stubResponse(t), token, originalIncluded); err != nil {
		t.Fatalf("deliverToInbox: %v", err)
	}

	if captured.uri != spec.URI {
		t.Fatalf("delivery URI: got %q, want %q", captured.uri, spec.URI)
	}
	if len(captured.async) != 1 || captured.async[0] == nil {
		t.Fatalf("remote delivery carried no AsyncDelivery — the deliver_token was dropped and the dispatch fell back to connection authority (taxonomy row 2 violated)")
	}
	override := captured.async[0].CapabilityOverride
	if override == nil {
		t.Fatalf("CapabilityOverride is nil — the delivery would ride the connection's session capability, which on the §6.11 reentry path names the far side as grantee and fails 401")
	}
	if override.ContentHash != token.ContentHash {
		t.Fatalf("CapabilityOverride: got %s, want the deliver_token %s", override.ContentHash, token.ContentHash)
	}
	if _, ok := captured.async[0].Extras[supporting.ContentHash]; !ok {
		t.Fatalf("Extras did not carry the original included set — the far side cannot walk the chain that authorizes the delivery it just accepted")
	}
}

// TestRemoteInboxDeliveryRejectsForeignDeliverToken pins the guard: a
// deliver_token that does not name us as grantee cannot authorize a dispatch
// we author (V7 §5.2 `grantee == author`), so it MUST NOT be presented as the
// delivery's capability. The local-async entry point synthesizes a token from
// the caller's own HandlerGrant, which is locally rooted and grants us nothing
// at a remote peer — that is the case this guard keeps off the wire.
func TestRemoteInboxDeliveryRejectsForeignDeliverToken(t *testing.T) {
	var captured capturedDispatch
	d, _, _ := newDeliveryDispatcher(t, &captured)

	spec, requesterHash := remoteDeliverySpec(t)
	// Granted to a third party, not to us.
	strangerKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate stranger keypair: %v", err)
	}
	strangerIdentity, err := strangerKP.IdentityEntity()
	if err != nil {
		t.Fatalf("stranger identity: %v", err)
	}
	token := mintToken(t, requesterHash, strangerIdentity.ContentHash)

	execData := types.ExecuteData{RequestID: "req-2", DeliverTo: spec, DeliverToken: token.ContentHash}
	if err := d.deliverToInbox(context.Background(), execData, stubResponse(t), token, nil); err != nil {
		t.Fatalf("deliverToInbox: %v", err)
	}

	for _, ad := range captured.async {
		if ad != nil && ad.CapabilityOverride != nil {
			t.Fatalf("a deliver_token granted to somebody else was presented as the delivery capability — it can only fail `grantee != author` at the far side")
		}
	}
}
