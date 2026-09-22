package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
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

// mintTargetMintedCred builds a VALID target-minted credential: a single-link
// capability chain rooted at targetKP (granter = target), granted to
// granteeHash (this peer), signed by the target. It returns the cap entity and
// the included chain (target identity + signature) the presenter must carry so
// VerifyChain resolves. peers is left absent so that, evaluated in the target's
// own frame, it defaults to {include:[target]} and covers reaching the target
// (mirroring what the target computes on receipt).
func mintTargetMintedCred(t *testing.T, targetKP crypto.Keypair, granteeHash hash.Hash, ops []string) (entity.Entity, []entity.Entity) {
	t.Helper()
	targetIdent, err := targetKP.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			Operations: types.CapabilityScope{Include: ops},
		}},
		Granter:   types.SingleSigGranter(targetIdent.ContentHash),
		Grantee:   granteeHash,
		CreatedAt: 1000,
	}
	capEnt, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	sig := targetKP.Sign(capEnt.ContentHash.Bytes())
	sigEnt, err := types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    targetIdent.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return capEnt, []entity.Entity{targetIdent, sigEnt}
}

// mintMultiSigRootCred builds a credential whose chain ROOT is a K-of-2
// multi-sig granter over {target, coSigner}, threshold 2, both signing, granted
// to granteeHash. The target IS one of the two signers and does sign — so
// VerifyChain's M6 (verifyRootGranter), run with the target as the frame,
// ACCEPTS it. It is nonetheless NOT "minted BY the target peer" (D1): the
// co-signer authorized it too. E3/F66 makes the presented arm reject it
// fail-closed. Returns the cap and the included chain (both identities + both
// signatures).
func mintMultiSigRootCred(t *testing.T, targetKP, coKP crypto.Keypair, granteeHash hash.Hash, ops []string) (entity.Entity, []entity.Entity) {
	t.Helper()
	targetIdent, err := targetKP.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	coIdent, err := coKP.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			Operations: types.CapabilityScope{Include: ops},
		}},
		Granter: types.MultiSigGranter(types.MultiGranter{
			Signers:   []hash.Hash{targetIdent.ContentHash, coIdent.ContentHash},
			Threshold: 2,
		}),
		Grantee:   granteeHash,
		CreatedAt: 1000,
	}
	capEnt, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	mkSig := func(kp crypto.Keypair, ident entity.Entity) entity.Entity {
		sig := kp.Sign(capEnt.ContentHash.Bytes())
		e, serr := types.SignatureData{
			Target:    capEnt.ContentHash,
			Signer:    ident.ContentHash,
			Algorithm: "ed25519",
			Signature: sig,
		}.ToEntity()
		if serr != nil {
			t.Fatal(serr)
		}
		return e
	}
	return capEnt, []entity.Entity{targetIdent, coIdent, mkSig(targetKP, targetIdent), mkSig(coKP, coIdent)}
}

// pd2PresentedDispatcher wires a dispatcher whose one handler sub-dispatches to
// a FOREIGN target, presenting a target-minted credential (WithCapability +
// WithIncludedChain). The handler's own grant (seeded at
// system/capability/grants/system/test/relay) carries relayGrantOps / peers, so
// a test can make the handler grant NOT cover the sub-dispatch and observe
// whether the presented credential is (wrongly) treated as a standalone
// authorizer. Returns the dispatcher, the entry cap (the relay grant), the
// target keypair (to mint the credential against), the foreign target URI, and
// a pointer to a flag recording whether the outbound reached RemoteExecute.
func pd2PresentedDispatcher(t *testing.T, localKP crypto.Keypair, relayGrantOps, relayGrantPeers []string, subOp string, presented *entity.Entity, chain *[]entity.Entity) (*Dispatcher, entity.Entity, crypto.Keypair, string, *bool) {
	t.Helper()
	targetKP, _ := crypto.Generate()
	remoteURI := "entity://" + string(targetKP.PeerID()) + "/system/test/target"

	reg := handler.NewRegistry()
	reg.Register("system/test/relay", &fnHandler{name: "relay", fn: func(ctx context.Context, req *handler.Request) (*handler.Response, error) {
		return req.Context.Execute(ctx, remoteURI, subOp, entity.Entity{},
			handler.WithCapability(*presented), handler.WithIncludedChain(*chain))
	}})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	callerCap := seedGrantWithPeers(t, localKP, cs, li, relayGrantOps, relayGrantPeers, "system/test/relay")

	// With LocalIdentityHash wired (below), the child handler's grant is
	// signature-validated (§3.5 / VerifyHandlerGrant), so the seeded relay grant
	// must carry a local signature at its LocalSignaturePath — otherwise the
	// relay handler 403s at grant-load before it ever sub-dispatches (which would
	// make the confused-deputy test a false pass: refused for the wrong reason).
	localIdent, _ := localKP.IdentityEntity()
	sig := localKP.Sign(callerCap.ContentHash.Bytes())
	sigEnt, err := types.SignatureData{
		Target:    callerCap.ContentHash,
		Signer:    localIdent.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(sigEnt); err != nil {
		t.Fatal(err)
	}
	if err := li.Set(types.LocalSignaturePath(callerCap.ContentHash), sigEnt.ContentHash); err != nil {
		t.Fatal(err)
	}

	// presentedAuthorizes reads the local identity from the store at
	// LocalIdentityHash to resolve the credential's grantee during VerifyChain.
	if _, err := cs.Put(localIdent); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(reg, cs, li, localKP, nil)
	d.LocalIdentityHash = localIdent.ContentHash

	reached := false
	d.RemoteExecute = func(ctx context.Context, uri, op string, params entity.Entity, resource *types.ResourceTarget, async ...*AsyncDelivery) (*handler.Response, error) {
		reached = true
		return &handler.Response{Status: 200}, nil
	}
	return d, callerCap, targetKP, remoteURI, &reached
}

// TestPD2_ConfusedDeputy_PresentedCredentialDoesNotBypassHandlerGrant is the
// discriminator whose ABSENCE shipped F67 (cohort-wide confused-deputy bypass).
// A caller presents a VALID target-minted credential (broad: ops=["*"]) to a
// handler on this peer whose OWN grant does NOT cover the sub-dispatched
// operation. Under the 0.8.2.19 E1 rule the executing handler's grant gates all
// four dimensions and a target-minted credential relaxes ONLY Dimension 4
// (peers) — so the sub-dispatch MUST be refused: the credential answers WHERE,
// the handler's grant answers WHAT, and this handler's grant does not authorize
// this operation.
//
// Mutation witness (the F67 form): making presentedAuthorizes a standalone
// authorizer (return authorized when the credential holds, before the handler
// grant is checked) reddens this — the broad credential would authorize the
// operation the handler's own grant forbids, and the outbound would reach
// RemoteExecute with a 200.
func TestPD2_ConfusedDeputy_PresentedCredentialDoesNotBypassHandlerGrant(t *testing.T) {
	kp, _ := crypto.Generate()
	var presented entity.Entity
	var chain []entity.Entity

	// Handler grant: may run + sub-dispatch "get" only, no peers scope. It has
	// no authority to do "delete" anywhere, least of all at a foreign peer.
	d, callerCap, targetKP, _, reached := pd2PresentedDispatcher(t, kp,
		[]string{"get"}, nil, "delete", &presented, &chain)

	// The caller holds a BROAD target-minted credential (ops=["*"]) and presents
	// it, trying to steer the "get"-only handler into a "delete" at the target.
	localIdent, _ := kp.IdentityEntity()
	presented, chain = mintTargetMintedCred(t, targetKP, localIdent.ContentHash, []string{"*"})

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI: "system/test/relay", Operation: "get",
		Params: entity.Entity{}, CallerCapability: callerCap,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("confused-deputy: a valid target-minted credential steered a handler past its own grant: status %d, want 403 (E1 — the handler grant gates operations; a credential relaxes only Dimension 4)", resp.Status)
	}
	if *reached {
		t.Fatal("F67: the outbound sub-dispatch reached RemoteExecute — the presented credential was treated as a standalone authorizer, bypassing the executing handler's grant")
	}
}

// TestPD2_PresentedCredentialRelaxesPeersDimensionOnly is the positive control
// pairing the discriminator above: the SAME valid credential DOES authorize the
// sub-dispatch when the handler's grant covers the operation (WHAT) but lacks a
// peers scope reaching the target (WHERE). The credential relaxes Dimension 4
// only, and the outbound proceeds. Without this control the refusal test would
// pass on a peer that refuses every presented credential — one arm does not
// discriminate.
//
// Mutation witness: if the E1 relaxation is not wired (the credential is
// ignored for Dimension 4), this reddens — the handler grant's absent peers
// scope defaults to {local} and refuses the foreign target with a 403.
func TestPD2_PresentedCredentialRelaxesPeersDimensionOnly(t *testing.T) {
	kp, _ := crypto.Generate()
	var presented entity.Entity
	var chain []entity.Entity

	// Handler grant: covers "get" (WHAT), no peers scope (cannot reach the
	// foreign target on its own — WHERE).
	d, callerCap, targetKP, _, reached := pd2PresentedDispatcher(t, kp,
		[]string{"get"}, nil, "get", &presented, &chain)

	localIdent, _ := kp.IdentityEntity()
	presented, chain = mintTargetMintedCred(t, targetKP, localIdent.ContentHash, []string{"*"})

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI: "system/test/relay", Operation: "get",
		Params: entity.Entity{}, CallerCapability: callerCap,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("PD-2 relaxation: a valid target-minted credential should relax Dimension 4 for a handler grant that covers the operation: status %d, want 200", resp.Status)
	}
	if !*reached {
		t.Fatal("PD-2 relaxation: the outbound should have reached RemoteExecute — a valid credential relaxes the peers dimension")
	}
}

// TestPD2_E3_MultiSigRootCredentialDoesNotRelax pins E3/F66 (0.8.2.19,
// fail-closed): a credential whose chain ROOT is a K-of-2 multi-sig granter
// that merely INCLUDES the target as one signer is NOT "minted BY the target
// peer" and MUST NOT relax Dimension 4 — even though VerifyChain's M6 accepts it
// (the target is a signer and signed). This was a LIVE over-acceptance found
// cross-impl (rust + py both had it, and so did go): the presented arm ran
// VerifyChain with the target as the frame, so a K-of-N root landed in M6's
// "is the frame peer among the signers" branch and relaxed.
//
// Same shape as the relaxation control, but the credential's root is multi-sig,
// so the sub-dispatch MUST be refused (the handler grant has no peers scope).
// Mutation witness: removing the IsMulti root check in presentedAuthorizes lets
// the multi-sig root relax Dimension 4, and the outbound reaches RemoteExecute
// with a 200.
func TestPD2_E3_MultiSigRootCredentialDoesNotRelax(t *testing.T) {
	kp, _ := crypto.Generate()
	coKP, _ := crypto.Generate()
	var presented entity.Entity
	var chain []entity.Entity

	// Handler grant covers "get" (WHAT) but has no peers scope (WHERE). Only a
	// valid SINGLE-target-minted credential may relax the peers dimension.
	d, callerCap, targetKP, _, reached := pd2PresentedDispatcher(t, kp,
		[]string{"get"}, nil, "get", &presented, &chain)

	localIdent, _ := kp.IdentityEntity()
	presented, chain = mintMultiSigRootCred(t, targetKP, coKP, localIdent.ContentHash, []string{"*"})

	resp, err := d.DispatchLocalExecute(context.Background(), LocalExecuteRequest{
		URI: "system/test/relay", Operation: "get",
		Params: entity.Entity{}, CallerCapability: callerCap,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("E3: a K-of-2 multi-sig root credential (target is one signer) relaxed Dimension 4: status %d, want 403 (a multi-sig root is not 'minted BY the target peer'; fail-closed)", resp.Status)
	}
	if *reached {
		t.Fatal("E3 over-acceptance: the outbound reached RemoteExecute — a multi-sig root credential relaxed the peers dimension")
	}
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
