package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// inboxStub is a minimal handler so Registry.Resolve has a pattern to return.
type inboxStub struct{}

func (inboxStub) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	return &handler.Response{Status: 200}, nil
}

func (inboxStub) Name() string { return "system/inbox" }

// EXTENSION-CONTINUATION §4.2 Step 4 line 2 — generate_internal_deliver_token.
//
// The property under test is the one the far side actually checks: V7 §5.2
// `grantee == author` on the delivery EXECUTE. The SERVICING peer authors that
// delivery, so the token must name the SERVICING peer as grantee. Anything
// else and the delivery is refused `403 capability_denied` — which is exactly
// what go→rust did until this mint existed.
func TestMintDeliverTokenNamesTheServicingPeerAsGrantee(t *testing.T) {
	var captured capturedDispatch
	d, _, localIdentity := newDeliveryDispatcher(t, &captured)
	d.Registry.Register("system/inbox", inboxStub{})

	targetKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate target keypair: %v", err)
	}
	targetPeerID := targetKP.PeerID()

	deliverTo := &types.DeliverySpec{
		URI:       "entity://" + string(d.LocalPeerID) + "/system/inbox/result-1",
		Operation: "receive",
	}

	capEnt, sigEnt, identEnt, err := d.mintDeliverToken(targetPeerID, deliverTo)
	if err != nil {
		t.Fatalf("mint deliver_token: %v", err)
	}

	capData, err := types.CapabilityTokenDataFromEntity(capEnt)
	if err != nil {
		t.Fatalf("decode minted cap: %v", err)
	}

	// The grantee must be the SERVICING peer's identity-entity content hash —
	// not its peer_id, and not ours. This is the whole fix.
	wantGrantee, err := ResolveRemoteIdentityHash(targetPeerID, nil)
	if err != nil {
		t.Fatalf("resolve target identity hash: %v", err)
	}
	if capData.Grantee != wantGrantee {
		t.Fatalf("deliver_token grantee = %s, want the servicing peer %s — a token granted to anyone else fails `grantee != author` at the far side",
			capData.Grantee, wantGrantee)
	}
	if capData.Grantee == localIdentity.ContentHash {
		t.Fatal("deliver_token was granted to US, the dispatching peer — that is the pre-fix shape: the servicing peer cannot author a delivery under a cap naming somebody else")
	}

	// Self-rooted at us: we are the peer whose inbox receives the delivery,
	// so we are the authority that can grant it (§4.2 authority table, the
	// "result deliver_token" row).
	if !capData.Granter.EqualsHash(localIdentity.ContentHash) {
		t.Fatalf("deliver_token granter = %s, want the local peer %s (the delivery destination roots it)", capData.Granter, localIdentity.ContentHash)
	}

	// Scoped to exactly one delivery — not a blanket grant.
	if len(capData.Grants) != 1 {
		t.Fatalf("deliver_token carries %d grants, want exactly 1 (one delivery, one grant)", len(capData.Grants))
	}
	g := capData.Grants[0]
	if len(g.Operations.Include) != 1 || g.Operations.Include[0] != "receive" {
		t.Fatalf("operations scope = %v, want exactly [receive] — a wildcard here hands the servicing peer our whole inbox", g.Operations.Include)
	}
	wantResource := "/" + string(d.LocalPeerID) + "/system/inbox/result-1"
	if len(g.Resources.Include) != 1 || g.Resources.Include[0] != wantResource {
		t.Fatalf("resources scope = %v, want exactly [%s] in absolute form", g.Resources.Include, wantResource)
	}
	// The handler dimension is compared against the RESOLVED pattern at the
	// receiving side. Granting the request path instead would produce a cap
	// that verifies nothing.
	if len(g.Handlers.Include) != 1 || g.Handlers.Include[0] != "system/inbox" {
		t.Fatalf("handlers scope = %v, want the resolved pattern [system/inbox], not the request path", g.Handlers.Include)
	}

	// The token must actually authorize the delivery it was minted for.
	exec := types.ExecuteData{
		URI:       deliverTo.URI,
		Operation: "receive",
		Resource:  &types.ResourceTarget{Targets: []string{wantResource}},
	}
	if !capability.CheckPermission(exec, capData, "system/inbox", d.LocalPeerID, d.LocalPeerID) {
		t.Fatal("the minted deliver_token does not authorize its own delivery — the scope is wrong somewhere above")
	}

	// A root cap with no signature is rejected `missing_signature` at the
	// §5.5 chain walk, so both the signature and the granter identity have to
	// travel with it.
	sigData, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		t.Fatalf("decode cap signature: %v", err)
	}
	if sigData.Target != capEnt.ContentHash {
		t.Fatalf("signature targets %s, not the cap %s", sigData.Target, capEnt.ContentHash)
	}
	if sigData.Signer != localIdentity.ContentHash {
		t.Fatalf("signature signer = %s, want the granter %s", sigData.Signer, localIdentity.ContentHash)
	}
	if identEnt.ContentHash != localIdentity.ContentHash {
		t.Fatalf("returned identity %s is not the granter identity %s the far side must resolve", identEnt.ContentHash, localIdentity.ContentHash)
	}
}

// The boundary: a peer cannot root authority over somebody else's inbox, so it
// declines to mint rather than emitting a cap that cannot verify anywhere.
// The caller keeps its pre-existing behaviour on this path — the fix is
// additive, and this test is what pins that.
func TestMintDeliverTokenRefusesAThirdPartyDeliveryTarget(t *testing.T) {
	var captured capturedDispatch
	d, _, _ := newDeliveryDispatcher(t, &captured)
	d.Registry.Register("system/inbox", inboxStub{})

	targetKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate target keypair: %v", err)
	}
	otherKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate third-party keypair: %v", err)
	}

	_, _, _, err = d.mintDeliverToken(targetKP.PeerID(), &types.DeliverySpec{
		URI:       "entity://" + string(otherKP.PeerID()) + "/system/inbox/result-1",
		Operation: "receive",
	})
	if err == nil {
		t.Fatal("minted a deliver_token for a THIRD peer's inbox — we hold no authority there, and the resulting cap would fail at whoever received it")
	}
}

// A delivery path no handler serves cannot be scoped correctly (there is no
// pattern to name), so the mint declines rather than guessing a prefix.
func TestMintDeliverTokenRefusesAnUnservedDeliveryPath(t *testing.T) {
	var captured capturedDispatch
	d, _, _ := newDeliveryDispatcher(t, &captured)

	targetKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate target keypair: %v", err)
	}

	_, _, _, err = d.mintDeliverToken(targetKP.PeerID(), &types.DeliverySpec{
		URI:       "entity://" + string(d.LocalPeerID) + "/system/nothing-here/result-1",
		Operation: "receive",
	})
	if err == nil {
		t.Fatal("minted a deliver_token naming a handler pattern that does not exist")
	}
}

// The mutation with teeth: this asserts the OLD behaviour was genuinely
// broken, so the test above cannot pass for the wrong reason. The caller's
// HandlerGrant — what the remote branch used as the deliver_token before this
// change — is granted to the CALLER. Fed through the same `grantee == author`
// comparison the far side runs, it fails. If this ever stops failing, the
// mint above is no longer load-bearing and something else is authorizing the
// delivery.
func TestCallerHandlerGrantCannotAuthorizeTheServicingPeersDelivery(t *testing.T) {
	var captured capturedDispatch
	d, _, localIdentity := newDeliveryDispatcher(t, &captured)
	d.Registry.Register("system/inbox", inboxStub{})

	targetKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate target keypair: %v", err)
	}
	targetIdentityHash, err := ResolveRemoteIdentityHash(targetKP.PeerID(), nil)
	if err != nil {
		t.Fatalf("resolve target identity hash: %v", err)
	}

	// The shape the remote branch passed before the fix: the grant the CALLER
	// holds. Granter and grantee are both local-side.
	handlerGrant := mintToken(t, localIdentity.ContentHash, localIdentity.ContentHash)

	if tokenGranteeIs(handlerGrant, targetIdentityHash) {
		t.Fatal("the caller's handler grant names the SERVICING peer as grantee — it does not, and if it did the pre-fix path would have worked and go→rust would never have failed")
	}
	// And the positive half, so this is a comparison and not a tautology.
	capEnt, _, _, err := d.mintDeliverToken(targetKP.PeerID(), &types.DeliverySpec{
		URI:       "entity://" + string(d.LocalPeerID) + "/system/inbox/result-1",
		Operation: "receive",
	})
	if err != nil {
		t.Fatalf("mint deliver_token: %v", err)
	}
	if !tokenGranteeIs(capEnt, targetIdentityHash) {
		t.Fatal("the minted deliver_token does not name the servicing peer as grantee — the far side will refuse it exactly as it refused the handler grant")
	}
}
