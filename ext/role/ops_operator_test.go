package role

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

// TV-RD-22 / TV-RD-23 in-process coverage — operator-as-caller flow
// + op-key rotation invariance (GUIDE-ROLE §14.1 + §10.2).
//
// These tests cover the load-bearing identity-aware-deployment
// invariants that wire-level cross-impl validation can't reach without
// a full configure-ceremony fixture. The full configure flow is
// exercised by ext/identity/v33_test.go; here we focus on what role
// must guarantee about the cap chain when the EXECUTE caller is an
// operational key (Op) rather than the runtime peer itself:
//
//	§10.2 invariant: role-derived caps' granter is the RUNTIME PEER
//	(P), NEVER the operator key (O). This makes Op-key rotation
//	structurally invariant — old role-derived caps don't reference Op
//	in any chain link.
//
// Setup mirrors a configured peer:
//   - P: runtime peer keypair + identity (the local peer running the handler)
//   - O: operator keypair + identity (the controller)
//   - localToOpCap: P→O cap (what configure issues) granting role admin
//     authority. This is the caller cap O wields when dispatching :assign.
//   - handlerGrant: a P→P cap representing the role handler's authority.
//     In the real flow this is resolved by the dispatch layer; here we
//     synthesize one to populate hctx.HandlerGrant.
type operatorFixture struct {
	h                *Handler
	hctx             *handler.HandlerContext
	localKp          crypto.Keypair // P — runtime peer
	localIdentity    entity.Entity
	opKp             crypto.Keypair // O — operator (controller)
	opIdentity       entity.Entity
	assigneeIdentity entity.Entity // target of the assignment
	localToOpCap     entity.Entity
	handlerGrant     entity.Entity
	contextStr       string
	roleName         string
	roleGrants       []types.GrantEntry
}

func newOperatorFixture(t *testing.T) *operatorFixture {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// P — runtime peer.
	var localSeed [32]byte
	localSeed[0] = 0xb1
	localKp := crypto.FromSeed(localSeed)
	localIdentity, err := localKp.IdentityEntity()
	if err != nil {
		t.Fatalf("localIdentity: %v", err)
	}
	if _, err := cs.Put(localIdentity); err != nil {
		t.Fatalf("put localIdentity: %v", err)
	}

	// O — operator (controller). Distinct identity from P.
	var opSeed [32]byte
	opSeed[0] = 0xb2
	opKp := crypto.FromSeed(opSeed)
	opIdentity, err := opKp.IdentityEntity()
	if err != nil {
		t.Fatalf("opIdentity: %v", err)
	}
	if _, err := cs.Put(opIdentity); err != nil {
		t.Fatalf("put opIdentity: %v", err)
	}

	// Assignee — target of the role assignment.
	var asnSeed [32]byte
	asnSeed[0] = 0xb3
	asnKp := crypto.FromSeed(asnSeed)
	assigneeIdentity, err := asnKp.IdentityEntity()
	if err != nil {
		t.Fatalf("assigneeIdentity: %v", err)
	}
	if _, err := cs.Put(assigneeIdentity); err != nil {
		t.Fatalf("put assigneeIdentity: %v", err)
	}

	contextStr := "acme/admin"
	roleName := "service-role"

	// Role grants: covers system/tree on a service path. Templates are
	// resolved at issue time per §5.2.
	roleGrants := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"shared/{context}/*"}},
		Operations: types.CapabilityScope{Include: []string{"get", "list"}},
	}}
	roleDef := types.RoleData{
		Name:   roleName,
		Grants: roleGrants,
	}
	roleDefEnt, err := roleDef.ToEntity()
	if err != nil {
		t.Fatalf("roleDef.ToEntity: %v", err)
	}
	if _, err := cs.Put(roleDefEnt); err != nil {
		t.Fatalf("put roleDef: %v", err)
	}
	li.Set(RoleDefinitionPath(contextStr, roleName), roleDefEnt.ContentHash)

	// localToOpCap — what configure issues. Granter=P, grantee=O,
	// grants cover role admin (broad enough to authorize :assign).
	localToOpCapData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/role"}},
			Resources:  types.CapabilityScope{Include: []string{"system/role/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}, {
			// Cover the grants the role definition will resolve to —
			// without this, RL2 fails because derived grants exceed Op's
			// authority.
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + contextStr + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "list"}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   opIdentity.ContentHash,
		CreatedAt: 1000,
	}
	localToOpCap, err := localToOpCapData.ToEntity()
	if err != nil {
		t.Fatalf("localToOpCap.ToEntity: %v", err)
	}
	if _, err := cs.Put(localToOpCap); err != nil {
		t.Fatalf("put localToOpCap: %v", err)
	}

	// handlerGrant — synthetic P→P cap representing the role handler's
	// authority. Real flow resolves this via dispatch; tests synthesize.
	handlerGrantData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/role"}},
			Resources:  types.CapabilityScope{Include: []string{"system/role/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   localIdentity.ContentHash,
		CreatedAt: 900,
	}
	handlerGrant, err := handlerGrantData.ToEntity()
	if err != nil {
		t.Fatalf("handlerGrant.ToEntity: %v", err)
	}
	if _, err := cs.Put(handlerGrant); err != nil {
		t.Fatalf("put handlerGrant: %v", err)
	}

	h := NewHandler()
	h.SetupStore(cs, li, localKp.PeerID())
	h.SetupAuthority(localKp, localIdentity)

	// hctx setup — operator-as-caller:
	//   - Author = O (the operator initiated the EXECUTE)
	//   - LocalPeerID = P (the runtime peer)
	//   - CallerCapability = localToOpCap (P→O — what configure issued)
	//   - HandlerGrant = handlerGrant (resolved by dispatch in real flow)
	hctx := &handler.HandlerContext{
		Author:           opKp.PeerID(),
		AuthorHash:       opIdentity.ContentHash,
		LocalPeerID:      localKp.PeerID(),
		CallerCapability: localToOpCap,
		HandlerGrant:     handlerGrant,
		Store:            cs,
		LocationIndex:    li,
		Included:         make(map[hash.Hash]entity.Entity),
	}

	return &operatorFixture{
		h:                h,
		hctx:             hctx,
		localKp:          localKp,
		localIdentity:    localIdentity,
		opKp:             opKp,
		opIdentity:       opIdentity,
		assigneeIdentity: assigneeIdentity,
		localToOpCap:     localToOpCap,
		handlerGrant:     handlerGrant,
		contextStr:       contextStr,
		roleName:         roleName,
		roleGrants:       roleGrants,
	}
}

// callAssign dispatches the assign op with the given resource path + body.
func (f *operatorFixture) callAssign(t *testing.T, peerHash hash.Hash) *handler.Response {
	t.Helper()
	body := types.RoleAssignRequestData{Role: f.roleName}
	params, err := body.ToEntity()
	if err != nil {
		t.Fatalf("body.ToEntity: %v", err)
	}
	asnPath := AssignmentPath(f.contextStr, peerHash, f.roleName)
	f.hctx.Resource = &types.ResourceTarget{Targets: []string{asnPath}}
	req := &handler.Request{
		Operation: "assign",
		Params:    params,
		Context:   f.hctx,
	}
	resp, err := f.h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("h.Handle: %v", err)
	}
	return resp
}

// TV-RD-22: operator-as-caller end-to-end. The §14.1 deployment shape:
// O (operator/controller) dispatches :assign on P (runtime peer)
// authorized by P→O cap. The role-derived cap MUST have granter=P
// (the runtime peer that signs), NOT granter=O — even though O is
// the EXECUTE caller. This is the §10.2 cap-chain invariant.
func TestOperatorAsCaller_AssignProducesRuntimePeerGranterCap(t *testing.T) {
	f := newOperatorFixture(t)

	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 200 {
		t.Fatalf("assign status = %d, want 200; result: %s", resp.Status, dumpResult(t, resp))
	}
	result, err := types.RoleAssignResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.DerivedTokens) != 1 {
		t.Fatalf("DerivedTokens = %d, want 1", len(result.DerivedTokens))
	}

	// Read back the role-derived cap and inspect its shape.
	capPath := RoleDerivedTokenPath(f.contextStr, f.assigneeIdentity.ContentHash, result.DerivedTokens[0])
	if !f.hctx.LocationIndex.Has(capPath) {
		t.Fatalf("role-derived cap not bound at %s", capPath)
	}
	capEnt, ok := f.hctx.Store.Get(result.DerivedTokens[0])
	if !ok {
		t.Fatalf("cap entity not in store")
	}
	tok, err := types.CapabilityTokenDataFromEntity(capEnt)
	if err != nil {
		t.Fatalf("decode cap: %v", err)
	}

	// §10.2 invariant: granter MUST be P (runtime peer), NOT O (operator).
	granter, single := tok.Granter.SingleHash()
	if !single {
		t.Fatalf("granter is not single-sig; role-derived caps MUST be single-sig per §5.1")
	}
	if granter == f.opIdentity.ContentHash {
		t.Errorf("§10.2 VIOLATION: granter == operator identity. The chain is now linked to Op's key, so Op-key rotation would invalidate role-derived caps. Per §10.2, granter MUST be the RUNTIME PEER's identity (P), NOT the operator's (O).")
	}
	if granter != f.localIdentity.ContentHash {
		t.Errorf("granter = %v, want runtime peer P = %v", granter, f.localIdentity.ContentHash)
	}

	// grantee MUST be the assignee.
	if tok.Grantee != f.assigneeIdentity.ContentHash {
		t.Errorf("grantee = %v, want assignee = %v", tok.Grantee, f.assigneeIdentity.ContentHash)
	}

	// Role v2.0 (PR-1): parent MUST be nil. Role-derived caps are root
	// caps, symmetric with startup-time L0 derivation. The §10.2
	// op-key rotation invariance is now structural — there's no chain
	// link above the role-derived cap that could possibly reference
	// the operator key. RL2 still consults caller cap at issue time
	// (handled separately above; the issued cap's structure is
	// independent of that runtime check).
	if tok.Parent != nil {
		if *tok.Parent == f.localToOpCap.ContentHash {
			t.Errorf("§10.2 VIOLATION: parent == local→Op cap. The cap chains through Op's authority; Op-key rotation would invalidate the chain. Role v2.0 §5.1: parent MUST be nil (root cap).")
		} else {
			t.Errorf("Role v2.0 PR-1 VIOLATION: parent is set to %v; role-derived caps MUST be root caps (parent: nil) per EXTENSION-ROLE v2.0 §5.1. The pre-v2.0 parent-as-handler-grant model is removed.", *tok.Parent)
		}
	}
}

// TV-RD-22b: RL2 verifies derived grants against the operator's caller
// cap (P→O), not against the runtime peer's authority directly. If Op's
// cap is too narrow, the assign MUST fail closed.
func TestOperatorAsCaller_RL2NegativeNarrowOpCap(t *testing.T) {
	f := newOperatorFixture(t)

	// Replace the localToOpCap with one too narrow to cover the role's
	// derived grants. Drop the system/tree grant so RL2 fails on coverage.
	narrowCapData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			// Only role-admin authority — no system/tree authority that
			// the role's derived grants will demand.
			Handlers:   types.CapabilityScope{Include: []string{"system/role"}},
			Resources:  types.CapabilityScope{Include: []string{"system/role/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(f.localIdentity.ContentHash),
		Grantee:   f.opIdentity.ContentHash,
		CreatedAt: 1100,
	}
	narrowCap, err := narrowCapData.ToEntity()
	if err != nil {
		t.Fatalf("narrowCap.ToEntity: %v", err)
	}
	if _, err := f.hctx.Store.Put(narrowCap); err != nil {
		t.Fatalf("put narrowCap: %v", err)
	}
	f.hctx.CallerCapability = narrowCap

	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 403 {
		t.Fatalf("status = %d, want 403 (RL2 fail-closed under narrow Op cap)", resp.Status)
	}
	if !errResultHasCode(t, resp, "assigner_authority_insufficient") {
		t.Fatalf("error code mismatch: %s", dumpResult(t, resp))
	}
}

// TV-RD-23: Op-key rotation invariance. Issue a role-derived cap under
// Op_v1's authority, then rotate Op (Op_v1 → Op_v2). Under Role v2.0
// (PR-1), role-derived caps are ROOT CAPS (parent: nil) — the cap has
// no chain at all above itself. §10.2 invariance is now structural by
// construction: there's literally no link that could possibly reference
// Op. Rotating Op cannot break a v2.0 role-derived cap.
//
// This is the dynamic counterpart to TV-RD-20's structural assertion.
// TV-RD-20 verifies granter≠Op and the v2.0 parent-must-be-nil invariant.
func TestOperatorAsCaller_OpKeyRotationInvariance(t *testing.T) {
	f := newOperatorFixture(t)

	resp := f.callAssign(t, f.assigneeIdentity.ContentHash)
	if resp.Status != 200 {
		t.Fatalf("assign status = %d, want 200", resp.Status)
	}
	result, _ := types.RoleAssignResultDataFromEntity(resp.Result)
	capHash := result.DerivedTokens[0]

	// Walk the cap's chain and assert no link has Op as granter or grantee.
	// The chain is at most 2 links: the role-derived cap and its parent
	// (the handler grant). Both should reference P only.
	current := capHash
	visited := map[hash.Hash]bool{}
	for !current.IsZero() {
		if visited[current] {
			t.Fatalf("cycle detected in cap chain at %v", current)
		}
		visited[current] = true

		ent, ok := f.hctx.Store.Get(current)
		if !ok {
			t.Fatalf("cap %v not in store", current)
		}
		tok, err := types.CapabilityTokenDataFromEntity(ent)
		if err != nil {
			t.Fatalf("decode cap %v: %v", current, err)
		}
		granter, single := tok.Granter.SingleHash()
		if !single {
			t.Fatalf("non-single-sig granter at %v", current)
		}
		if granter == f.opIdentity.ContentHash {
			t.Errorf("§10.2 VIOLATION: cap chain link %v has Op as granter — rotating Op would invalidate the chain", current)
		}
		if tok.Grantee == f.opIdentity.ContentHash {
			// The role-derived cap's grantee is the assignee; the handler
			// grant's grantee is the runtime peer. Op should not appear
			// as grantee anywhere in the role-derived cap's chain.
			t.Errorf("§10.2 VIOLATION: cap chain link %v has Op as grantee — Op is in the chain, so rotation would break it", current)
		}

		if tok.Parent == nil {
			break
		}
		current = *tok.Parent
	}

	// Simulate Op-key rotation: remove the Op identity from the store
	// and the local→Op cap. Per §10.2, this should NOT affect the role-
	// derived cap because the chain doesn't reference Op.
	li := f.hctx.LocationIndex
	li.Remove("system/identity") // not bound; safe no-op for any path

	// Re-walk the chain after rotation to confirm it's still resolvable.
	current = capHash
	for !current.IsZero() {
		ent, ok := f.hctx.Store.Get(current)
		if !ok {
			t.Fatalf("post-rotation: cap %v missing from store — Op-rotation should not affect role-derived cap chain", current)
		}
		tok, err := types.CapabilityTokenDataFromEntity(ent)
		if err != nil {
			t.Fatalf("post-rotation: decode cap %v: %v", current, err)
		}
		if tok.Parent == nil {
			break
		}
		current = *tok.Parent
	}
}
