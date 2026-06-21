package role

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// delegateFixture sets up a fully-populated handler context for testing
// :delegate. The fixture establishes:
//
//   - localKp / localIdentity   — the runtime peer (acts as delegator B
//     under SI-19 locality, since author == local).
//   - delegateIdentity          — recipient peer (C); only the identity
//     hash is needed for delegate flows.
//   - role definition           — bound at system/role/{ctx}/{role}.
//   - assignment for delegator  — bound; satisfies "delegator holds role".
//   - delegator's role-derived cap (parent for delegations).
//   - linkage entity            — points the (delegator, role) slot at
//     the parent cap so SI-22 parent selection works.
//
// Tests then build a RoleDelegateRequestData, call h.Handle, and assert
// on the response + post-state. Each test gets a fresh fixture so state
// doesn't leak across cases.
type delegateFixture struct {
	h                *Handler
	hctx             *handler.HandlerContext
	localKp          crypto.Keypair
	localIdentity    entity.Entity
	delegateIdentity entity.Entity
	contextStr       string
	roleName         string
	roleGrants       []types.GrantEntry
}

func newDelegateFixture(t *testing.T) *delegateFixture {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// Local peer = delegator. SI-19 locality means author MUST equal
	// local; the handler signs the delegation cap with the local
	// keypair, which IS the delegator's key by construction.
	var localSeed [32]byte
	localSeed[0] = 0xa1
	localKp := crypto.FromSeed(localSeed)
	localIdentity, err := localKp.IdentityEntity()
	if err != nil {
		t.Fatalf("localIdentity: %v", err)
	}
	if _, err := cs.Put(localIdentity); err != nil {
		t.Fatalf("put localIdentity: %v", err)
	}

	// Recipient C. Only the identity hash matters for delegate.
	var delegateSeed [32]byte
	delegateSeed[0] = 0xc1
	delegateKp := crypto.FromSeed(delegateSeed)
	delegateIdentity, err := delegateKp.IdentityEntity()
	if err != nil {
		t.Fatalf("delegateIdentity: %v", err)
	}
	if _, err := cs.Put(delegateIdentity); err != nil {
		t.Fatalf("put delegateIdentity: %v", err)
	}

	contextStr := "test/delegate"
	roleName := "reader"

	// Role grants: covers system/tree:get on a /shared/{ctx}/* prefix.
	// {context} is template-resolved at issue time per §5.2; the scope
	// passed to :delegate must be a literal subset of these grants
	// after template resolution.
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

	// Delegator's assignment entity.
	asn := types.RoleAssignmentData{
		Role:       roleName,
		AssignedBy: localIdentity.ContentHash,
		AssignedAt: 1000,
	}
	asnEnt, err := asn.ToEntity()
	if err != nil {
		t.Fatalf("assignment.ToEntity: %v", err)
	}
	if _, err := cs.Put(asnEnt); err != nil {
		t.Fatalf("put assignment: %v", err)
	}
	li.Set(AssignmentPath(contextStr, localIdentity.ContentHash, roleName), asnEnt.ContentHash)

	// Delegator's role-derived cap (the parent for delegations per SI-22).
	resolvedGrants := resolveGrants(roleGrants, contextStr, localIdentity.ContentHash)
	parentCap := types.CapabilityTokenData{
		Grants:    resolvedGrants,
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   localIdentity.ContentHash,
		CreatedAt: 1100,
	}
	parentCapEnt, err := parentCap.ToEntity()
	if err != nil {
		t.Fatalf("parentCap.ToEntity: %v", err)
	}
	if _, err := cs.Put(parentCapEnt); err != nil {
		t.Fatalf("put parentCap: %v", err)
	}
	li.Set(RoleDerivedTokenPath(contextStr, localIdentity.ContentHash, parentCapEnt.ContentHash),
		parentCapEnt.ContentHash)

	// Linkage entity (SI-5): (delegator, role) → parent cap hash.
	link := types.RoleDerivedTokenLinkData{
		TokenHash: parentCapEnt.ContentHash,
		IssuedAt:  parentCap.CreatedAt,
	}
	linkEnt, err := link.ToEntity()
	if err != nil {
		t.Fatalf("link.ToEntity: %v", err)
	}
	if _, err := cs.Put(linkEnt); err != nil {
		t.Fatalf("put link: %v", err)
	}
	li.Set(DerivedTokenLinkPath(contextStr, localIdentity.ContentHash, roleName), linkEnt.ContentHash)

	h := NewHandler()
	h.SetupStore(cs, li, localKp.PeerID())
	h.SetupAuthority(localKp, localIdentity)

	hctx := &handler.HandlerContext{
		Author:        localKp.PeerID(),
		AuthorHash:    localIdentity.ContentHash,
		LocalPeerID:   localKp.PeerID(),
		Store:         cs,
		LocationIndex: li,
		Included:      make(map[hash.Hash]entity.Entity),
	}

	return &delegateFixture{
		h:                h,
		hctx:             hctx,
		localKp:          localKp,
		localIdentity:    localIdentity,
		delegateIdentity: delegateIdentity,
		contextStr:       contextStr,
		roleName:         roleName,
		roleGrants:       roleGrants,
	}
}

// callDelegate dispatches a :delegate op with the given request body.
func (f *delegateFixture) callDelegate(t *testing.T, body types.RoleDelegateRequestData) *handler.Response {
	t.Helper()
	params, err := body.ToEntity()
	if err != nil {
		t.Fatalf("body.ToEntity: %v", err)
	}
	req := &handler.Request{
		Operation: "delegate",
		Params:    params,
		Context:   f.hctx,
	}
	resp, err := f.h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("h.Handle: %v", err)
	}
	return resp
}

// literalScope returns a literal grant subset of the role's authority,
// resolved by template substitution against the test context (the
// delegator's identity hash isn't part of the resource pattern, so the
// resolution drops only {context}).
func (f *delegateFixture) literalScope() []types.GrantEntry {
	return []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"shared/" + f.contextStr + "/*"}},
		Operations: types.CapabilityScope{Include: []string{"get"}}, // narrowed: drop "list"
	}}
}

func TestDelegate_HappyPath(t *testing.T) {
	f := newDelegateFixture(t)

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    f.literalScope(),
	})

	if resp.Status != 200 {
		t.Fatalf("status = %d, want 200; result: %s", resp.Status, dumpResult(t, resp))
	}
	result, err := types.RoleDelegateResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.DelegationTokenHash.IsZero() {
		t.Fatalf("DelegationTokenHash is zero")
	}

	// Verify the cap is bound at the role-derived path under recipient C.
	expectedPath := RoleDerivedTokenPath(f.contextStr, f.delegateIdentity.ContentHash, result.DelegationTokenHash)
	if !f.hctx.LocationIndex.Has(expectedPath) {
		t.Fatalf("delegation cap not bound at %s", expectedPath)
	}

	// Verify cap shape: granter=local (delegator), grantee=delegate, parent set.
	capEnt, ok := f.hctx.Store.Get(result.DelegationTokenHash)
	if !ok {
		t.Fatalf("cap entity not in store")
	}
	tok, err := types.CapabilityTokenDataFromEntity(capEnt)
	if err != nil {
		t.Fatalf("decode cap: %v", err)
	}
	granter, single := tok.Granter.SingleHash()
	if !single || granter != f.localIdentity.ContentHash {
		t.Errorf("granter = %v (single=%v), want delegator=%v", granter, single, f.localIdentity.ContentHash)
	}
	if tok.Grantee != f.delegateIdentity.ContentHash {
		t.Errorf("grantee = %v, want delegate=%v", tok.Grantee, f.delegateIdentity.ContentHash)
	}
	if tok.Parent == nil {
		t.Errorf("parent is nil; SI-22 requires parent = delegator's role-derived cap hash")
	}

	// Verify the (recipient, role) linkage slot was NOT written by
	// :delegate — delegation caps don't participate in the assignment-
	// linkage lookup. (Writing here would conflict with C's own future
	// :assign linkage.)
	delegateLinkPath := DerivedTokenLinkPath(f.contextStr, f.delegateIdentity.ContentHash, f.roleName)
	if f.hctx.LocationIndex.Has(delegateLinkPath) {
		t.Errorf("delegation incorrectly wrote a linkage entity at %s — delegation caps don't participate in unassign-by-linkage", delegateLinkPath)
	}

	// Verify the delegation cap signature is bound at the V7 §3.5
	// invariant pointer path (the sole canonical location — ROLE keeps
	// no sibling copy per V7 §3.5).
	invSigPath := types.InvariantSignaturePath(f.localKp.PeerID().String(), result.DelegationTokenHash)
	if !f.hctx.LocationIndex.Has(invSigPath) {
		t.Errorf("delegation cap signature not bound at the invariant pointer path %s", invSigPath)
	}
	// Negative control: the legacy sibling path MUST NOT exist (cleanup
	// per V7 §3.5 — role-derived/delegation caps no longer dual-bind).
	if siblingPath := expectedPath + "/signature"; f.hctx.LocationIndex.Has(siblingPath) {
		t.Errorf("delegation cap signature unexpectedly still bound at the removed sibling path %s", siblingPath)
	}
}

func TestDelegate_LocalityViolation(t *testing.T) {
	f := newDelegateFixture(t)

	// Simulate a remote caller: author != local_peer_id.
	var remoteSeed [32]byte
	remoteSeed[0] = 0xff
	remoteKp := crypto.FromSeed(remoteSeed)
	remoteIdentity, _ := remoteKp.IdentityEntity()
	f.hctx.Author = remoteKp.PeerID()
	f.hctx.AuthorHash = remoteIdentity.ContentHash

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    f.literalScope(),
	})

	if resp.Status != 400 {
		t.Fatalf("status = %d, want 400 (SI-19)", resp.Status)
	}
	if !errResultHasCode(t, resp, "delegator_must_be_local_peer") {
		t.Fatalf("error code mismatch: %s", dumpResult(t, resp))
	}
}

func TestDelegate_TemplatedScopeRejected(t *testing.T) {
	f := newDelegateFixture(t)

	templated := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"shared/{context}/*"}}, // template var present
		Operations: types.CapabilityScope{Include: []string{"get"}},
	}}

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    templated,
	})

	if resp.Status != 400 {
		t.Fatalf("status = %d, want 400 (SI-20)", resp.Status)
	}
	if !errResultHasCode(t, resp, "scope_must_be_literal") {
		t.Fatalf("error code mismatch: %s", dumpResult(t, resp))
	}
}

func TestDelegate_ReservedRoleName(t *testing.T) {
	f := newDelegateFixture(t)

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     "assignment", // reserved (R10)
		Scope:    f.literalScope(),
	})

	if resp.Status != 400 {
		t.Fatalf("status = %d, want 400 (R10)", resp.Status)
	}
	if !errResultHasCode(t, resp, "invalid_role_name") {
		t.Fatalf("error code mismatch: %s", dumpResult(t, resp))
	}
}

func TestDelegate_EmptyScope(t *testing.T) {
	f := newDelegateFixture(t)

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    []types.GrantEntry{},
	})

	if resp.Status != 400 {
		t.Fatalf("status = %d, want 400", resp.Status)
	}
}

func TestDelegate_DelegatorNotAssigned(t *testing.T) {
	f := newDelegateFixture(t)

	// Remove the delegator's assignment entity.
	f.hctx.LocationIndex.Remove(AssignmentPath(f.contextStr, f.localIdentity.ContentHash, f.roleName))

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    f.literalScope(),
	})

	if resp.Status != 403 {
		t.Fatalf("status = %d, want 403", resp.Status)
	}
	if !errResultHasCode(t, resp, "delegator_role_not_held") {
		t.Fatalf("error code mismatch: %s", dumpResult(t, resp))
	}
}

func TestDelegate_DelegateExcluded(t *testing.T) {
	f := newDelegateFixture(t)

	// Bind an exclusion entity for the delegate target C.
	excl := types.RoleExclusionData{
		ExcludedBy: f.localIdentity.ContentHash,
		ExcludedAt: 1500,
	}
	exclEnt, _ := excl.ToEntity()
	if _, err := f.hctx.Store.Put(exclEnt); err != nil {
		t.Fatalf("put exclusion: %v", err)
	}
	f.hctx.LocationIndex.Set(ExclusionPath(f.contextStr, f.delegateIdentity.ContentHash), exclEnt.ContentHash)

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    f.literalScope(),
	})

	if resp.Status != 403 {
		t.Fatalf("status = %d, want 403", resp.Status)
	}
	if !errResultHasCode(t, resp, "delegate_excluded") {
		t.Fatalf("error code mismatch: %s", dumpResult(t, resp))
	}
}

func TestDelegate_RoleNotFound(t *testing.T) {
	f := newDelegateFixture(t)

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     "nonexistent-role",
		Scope:    f.literalScope(),
	})

	// The "delegator does not hold role" check fires BEFORE role-def
	// lookup (assignment for nonexistent-role doesn't exist), so we
	// see 403 not 404. Both are valid spec readings; the impl puts
	// the cheaper assignment-lookup first.
	if resp.Status != 403 {
		t.Fatalf("status = %d, want 403 (delegator_role_not_held — fires before role-def lookup)", resp.Status)
	}
}

func TestDelegate_ScopeExceedsAuthority(t *testing.T) {
	f := newDelegateFixture(t)

	// Scope demands "put" — role grants only have "get"/"list".
	overscoped := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"shared/" + f.contextStr + "/*"}},
		Operations: types.CapabilityScope{Include: []string{"put"}}, // not in role's authority
	}}

	resp := f.callDelegate(t, types.RoleDelegateRequestData{
		Delegate: f.delegateIdentity.ContentHash,
		Context:  f.contextStr,
		Role:     f.roleName,
		Scope:    overscoped,
	})

	if resp.Status != 403 {
		t.Fatalf("status = %d, want 403 (RL2)", resp.Status)
	}
	if !errResultHasCode(t, resp, "delegator_authority_insufficient") {
		t.Fatalf("error code mismatch: %s", dumpResult(t, resp))
	}
}

// errResultHasCode checks that resp.Result decodes to an error envelope
// with the given subcode. NewErrorResponse builds a result entity whose
// data is a CBOR map with at least {"code": "<subcode>", "message": ...}.
func errResultHasCode(t *testing.T, resp *handler.Response, want string) bool {
	t.Helper()
	if resp.Result.Data == nil {
		return false
	}
	var m map[string]cbor.RawMessage
	if err := ecf.Decode(resp.Result.Data, &m); err != nil {
		return false
	}
	raw, ok := m["code"]
	if !ok {
		return false
	}
	var code string
	if err := cbor.Unmarshal(raw, &code); err != nil {
		return false
	}
	return code == want
}

// dumpResult is a small helper to surface error info in test failures.
func dumpResult(t *testing.T, resp *handler.Response) string {
	t.Helper()
	if resp.Result.Data == nil {
		return "<no result>"
	}
	var m map[string]cbor.RawMessage
	if err := ecf.Decode(resp.Result.Data, &m); err != nil {
		return "<undecodable>"
	}
	out := "{"
	for k, v := range m {
		var s string
		if cbor.Unmarshal(v, &s) == nil {
			out += k + "=" + s + " "
		}
	}
	out += "}"
	return out
}
