package query

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Teeth for the QUERY §5.2 step-6b authorization fix (rust routed 2026-09-12):
// checkQueryPathPermission consulted the request's resource field and returned
// true when it was ABSENT — a fail-open, since the request field is a caller
// narrowing, not a grant. Authorization is the CALLER CAPABILITY (§6.3). A cap
// scoped to /{p}/app/* must not authorize a result at /{p}/secret/* on a query
// with no resource field.
func TestCheckQueryPathPermission_ConsultsCapabilityNotRequest(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pid := kp.PeerID()
	cs := store.NewMemoryContentStore()
	identity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	cs.Put(identity) // required so ResolveGranterPeerID resolves the granter

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"app/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()

	// hctx with a caller capability and NO request resource field — the exact
	// case the old code let through (Resource == nil → allow everything).
	hctx := &handler.HandlerContext{
		LocalPeerID:      pid,
		Store:            cs,
		CallerCapability: capEntity,
		Resource:         nil,
	}

	appPath := store.QualifyPath(string(pid), "app/report")
	secretPath := store.QualifyPath(string(pid), "secret/leak")

	// Out-of-scope result MUST be denied even with no request resource field.
	if checkQueryPathPermission(secretPath, hctx) {
		t.Fatal("result outside the capability must be denied (query authz is the cap, not the request)")
	}
	// Control: an in-scope result is allowed.
	if !checkQueryPathPermission(appPath, hctx) {
		t.Fatal("in-scope result must be allowed")
	}
}
