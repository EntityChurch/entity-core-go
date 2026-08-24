package main

import (
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/registry/peerissued"
)

// Two flags that each GRANT must never combine to grant LESS than either
// alone. --open-access and --issuer-policy-mode did exactly that: the issuer's
// register-request grant is seeded at the `default` policy pattern, and a
// policy entry is a request-time CEILING (V7 v7.62 §4), so the narrow entry
// capped everything --open-access had handed out at handshake.
//
// The property, not the instance: for every grant either flag contributes
// alone, the combination still contains it. A future edit that reintroduces
// displacement — swapping the union for an assignment, or dropping one side —
// fails here rather than showing up as six unexplained 403s in a category
// nobody connected to the flag.
func TestIssuerSeedGrantsAreMonotoneUnderOpenAccess(t *testing.T) {
	issuerOnly := issuerSeedGrants(false)
	combined := issuerSeedGrants(true)

	if len(issuerOnly) == 0 {
		t.Fatal("issuerSeedGrants(false) is empty — register-request would be unreachable and this test would assert nothing")
	}

	for _, want := range issuerOnly {
		if !containsGrant(combined, want) {
			t.Errorf("--open-access DROPPED a grant that --issuer-policy-mode alone provides: %+v", want)
		}
	}
	for _, want := range peer.OpenAccessGrants() {
		if !containsGrant(combined, want) {
			t.Errorf("--issuer-policy-mode DROPPED a grant that --open-access alone provides: %+v", want)
		}
	}
}

// Without --open-access the entry stays exactly as narrow as §6a.9 asks. The
// fix must not widen the issuer-only deployment, which is the one an operator
// running a public registry actually deploys.
func TestIssuerSeedGrantsStayNarrowWithoutOpenAccess(t *testing.T) {
	got := issuerSeedGrants(false)
	want := peerissued.RequestBindingSeedGrants()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("issuerSeedGrants(false) = %+v, want exactly RequestBindingSeedGrants() %+v", got, want)
	}
	for _, g := range got {
		if containsGrant(peer.OpenAccessGrants(), g) {
			t.Errorf("issuer-only seed entry carries an open-access grant %+v — the registry deployment must not be widened by the fix for the combined one", g)
		}
	}
}

func containsGrant(set []types.GrantEntry, want types.GrantEntry) bool {
	for _, g := range set {
		if reflect.DeepEqual(g, want) {
			return true
		}
	}
	return false
}
