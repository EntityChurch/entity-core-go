package role

import (
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestResolveGrants_GatingNeverEscalates is the in-process coverage the
// convergence suite could not provide. VALIDATION-PROFILE-ROLE TV-RV-2.7 /
// RA-6 asserts that a peer recognized via the initial-grant policy receives
// EXACTLY the policy's default_role grants (EXTENSION-ROLE §5.1 derive_grants:
// the connection cap carries `grants: resolved_grants`, nothing more). The
// wire check `role_stage2_recognize_on_attest_*` cannot observe this against a
// peer-manager peer, because peer-manager starts every peer with `-open-access`
// (start.go: default true — the flag EXTENSION-ROLE/entity-peer already
// deprecates in v7.74 and removes in v7.75). An open-access peer hands every
// connector `OpenAccessGrants()` via the §8 handshake floor/policy union, so
// K's cap comes back as `OpenAccessGrants() ∪ {guest}` and the gating is
// unobservable — a property of the peer's posture, NOT of this resolver.
//
// This test pins the load-bearing fact directly: PolicyResolverDeps.ResolveGrants
// returns either nil or exactly the default_role's grants — it structurally
// cannot emit a wildcard. If a future change lets it union anything onto the
// role grants, this fails.
func TestResolveGrants_GatingNeverEscalates(t *testing.T) {
	const ctxName = "test/gating"
	const guestRole = "guest"

	// The default_role's grants: deliberately narrow. Anything WIDER than
	// this coming back out of the resolver is an escalation.
	guestGrants := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
		Operations: types.CapabilityScope{Include: []string{"get"}},
	}}

	newDeps := func(policy types.RoleInitialGrantPolicyData) PolicyResolverDeps {
		cs := store.NewMemoryContentStore()
		li := store.NewMemoryLocationIndex()

		roleDef := types.RoleData{Name: guestRole, Grants: guestGrants}
		roleEnt, err := roleDef.ToEntity()
		if err != nil {
			t.Fatalf("roleDef.ToEntity: %v", err)
		}
		if _, err := cs.Put(roleEnt); err != nil {
			t.Fatalf("put roleDef: %v", err)
		}
		li.Set(RoleDefinitionPath(ctxName, guestRole), roleEnt.ContentHash)

		polEnt, err := policy.ToEntity()
		if err != nil {
			t.Fatalf("policy.ToEntity: %v", err)
		}
		if _, err := cs.Put(polEnt); err != nil {
			t.Fatalf("put policy: %v", err)
		}
		li.Set(InitialGrantPolicyPath(), polEnt.ContentHash)

		// AttestationIdx nil: identity substrate not installed, so
		// recognize-on-attestation exercises its no-recognition fallback
		// (IdentityRequired decides). The recognized-chain path itself is
		// covered end-to-end by the convergence fixture's setup; what is
		// untested and pinned HERE is that no mode returns more than the role.
		return PolicyResolverDeps{Store: cs, Locations: li, NowMillis: func() uint64 { return 1000 }}
	}

	// A connecting peer that is NOT in any exclusion subtree.
	kp := crypto.FromSeed([32]byte{0x4b})
	id, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peerID, peerHash := kp.PeerID(), id.ContentHash

	cases := []struct {
		name   string
		policy types.RoleInitialGrantPolicyData
		want   []types.GrantEntry // nil means "no cap"
	}{
		{
			name:   "deny yields no grants",
			policy: types.RoleInitialGrantPolicyData{UnknownPeer: types.InitialGrantModeDeny, DefaultRole: guestRole, DefaultContext: ctxName},
			want:   nil,
		},
		{
			name:   "allow yields exactly the default_role grants",
			policy: types.RoleInitialGrantPolicyData{UnknownPeer: types.InitialGrantModeAllow, DefaultRole: guestRole, DefaultContext: ctxName},
			want:   guestGrants,
		},
		{
			name:   "recognize + identity_required, unrecognized -> no grants (fails closed)",
			policy: types.RoleInitialGrantPolicyData{UnknownPeer: types.InitialGrantModeRecognizeOnAttest, DefaultRole: guestRole, DefaultContext: ctxName, IdentityRequired: true},
			want:   nil,
		},
		{
			name:   "recognize without identity_required falls back to exactly the default_role grants",
			policy: types.RoleInitialGrantPolicyData{UnknownPeer: types.InitialGrantModeRecognizeOnAttest, DefaultRole: guestRole, DefaultContext: ctxName, IdentityRequired: false},
			want:   guestGrants,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := newDeps(tc.policy).ResolveGrants(peerID, peerHash)

			if tc.want == nil {
				if got != nil {
					t.Fatalf("expected nil (no cap), got %d grant(s): %+v", len(got), got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("grants mismatch:\n got  = %+v\n want = %+v", got, tc.want)
			}
			// Explicit escalation guard: whatever the mode, the resolver must
			// never emit an OpenAccess-shaped wildcard grant. This is the exact
			// grant the wire check saw unioned onto K by the open-access peer,
			// and it must never originate here.
			for _, g := range got {
				if scopeHasWildcard(g.Handlers) && scopeHasWildcard(g.Operations) {
					t.Fatalf("resolver emitted a wildcard-handler+wildcard-op grant (escalation): %+v", g)
				}
			}
		})
	}
}

func scopeHasWildcard(s types.CapabilityScope) bool {
	for _, inc := range s.Include {
		if inc == "*" {
			return true
		}
	}
	return false
}
