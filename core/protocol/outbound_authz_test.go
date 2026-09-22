package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// seedGrantWithPeers seeds a self-grant at system/capability/grants/{pattern}
// with an explicit (possibly nil) peers scope. A nil peers slice leaves the
// dimension absent — the §5.2 default {include:[local_peer_id]}.
func seedGrantWithPeers(t *testing.T, kp crypto.Keypair, cs store.ContentStore, li store.LocationIndex, ops []string, peers []string, pattern string) entity.Entity {
	t.Helper()
	identity, _ := kp.IdentityEntity()
	if _, err := cs.Put(identity); err != nil {
		t.Fatal(err)
	}
	grant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
		Operations: types.CapabilityScope{Include: ops},
	}
	if peers != nil {
		grant.Peers = &types.CapabilityScope{Include: peers}
	}
	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{grant},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(capEntity); err != nil {
		t.Fatal(err)
	}
	if err := li.Set("system/capability/grants/"+pattern, capEntity.ContentHash); err != nil {
		t.Fatal(err)
	}
	return capEntity
}

// pd2Dispatcher wires a dispatcher whose one handler sub-dispatches to remoteURI
// with ambient authority (no presented capability). RemoteExecute is stubbed to
// record whether the outbound was reached. Returns the dispatcher and a pointer
// to the "reached" flag.
func pd2Dispatcher(t *testing.T, kp crypto.Keypair, peers []string) (*Dispatcher, entity.Entity, string, *bool) {
	t.Helper()
	remoteKP, _ := crypto.Generate()
	remoteURI := "entity://" + string(remoteKP.PeerID()) + "/system/test/target"

	reg := handler.NewRegistry()
	reg.Register("system/test/relay", &fnHandler{name: "relay", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		return req.Context.Execute(ctx, remoteURI, "get", entity.Entity{})
	}})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(kp.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	callerCap := seedGrantWithPeers(t, kp, cs, li, []string{"get"}, peers, "system/test/relay")
	d := NewDispatcher(reg, cs, li, kp, nil)

	reached := false
	d.RemoteExecute = func(ctx context.Context, uri, op string, params entity.Entity, resource *types.ResourceTarget, async ...*AsyncDelivery) (*handler.Response, error) {
		reached = true
		return &handler.Response{Status: 200}, nil
	}
	return d, callerCap, remoteURI, &reached
}

// TestPD2_AmbientNoPeersScopeRefusesForeignSubdispatch pins the PD-2 negative
// arm (§5.2, 0.8.2.17): a handler whose grant carries no peers scope covering
// the target CANNOT sub-dispatch at a foreign peer. This is the enforcement
// point landing — the escalation the peers dimension exists to close.
//
// Mutation witness: removing the authorizeOutboundSubdispatch call in
// makeLocalExecute's remote branch reddens this (the foreign outbound would be
// reached and return 200).
func TestPD2_AmbientNoPeersScopeRefusesForeignSubdispatch(t *testing.T) {
	kp, _ := crypto.Generate()
	// peers=nil → absent → default {include:[local]} → foreign target refused.
	d, callerCap, _, reached := pd2Dispatcher(t, kp, nil)

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI: "system/test/relay", Operation: "get",
		Params: entity.Entity{}, CallerCapability: callerCap,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("ambient outbound to a foreign peer with no peers scope: status %d, want 403 (PD-2 negative arm)", resp.Status)
	}
	if *reached {
		t.Fatal("PD-2 failed closed: the outbound reached RemoteExecute despite the handler grant not scoping the target peer")
	}
}

// TestPD2_AmbientWithPeersScopeAllows is the control: the same outbound is
// authorized when the handler grant DOES scope the target peer (peers: ["*"]).
// Without this control the negative test above would pass on a peer that
// refuses everything — one arm alone does not discriminate.
func TestPD2_AmbientWithPeersScopeAllows(t *testing.T) {
	kp, _ := crypto.Generate()
	d, callerCap, _, reached := pd2Dispatcher(t, kp, []string{"*"})

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI: "system/test/relay", Operation: "get",
		Params: entity.Entity{}, CallerCapability: callerCap,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("ambient outbound with peers:[*] scope: status %d, want 200", resp.Status)
	}
	if !*reached {
		t.Fatal("outbound with a covering peers scope should have reached RemoteExecute")
	}
}
