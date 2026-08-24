package protocol

import (
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// These tests ground WHERE a connecting peer's initial grants come from, at the
// one seam that assembles them: ConnectHandler.AssembleInboundGrants (V7 v7.62
// §8). This is the composition that leaked `OpenAccessGrants() ∪ {guest}` onto a
// recognized peer in the role_stage2_recognize_on_attest wire check — a leak that
// was invisible because every validator peer runs -open-access. The four cases
// below pin each source independently, so the next reader does not have to
// reverse-engineer the union from a wire capture.
//
// The grant resolver here is a STUB standing in for ext/role's recognize-on-attest
// resolver: it returns the guest grants for the "recognized" identity and nil for
// everyone else. The recognition PREDICATE (RecognizeIdentityCert) and the resolver
// DISPATCH (ResolveGrants) are tested in ext/role; this file tests only how their
// output composes with the floor and the policy table.

func openAccessGrant() types.GrantEntry {
	return types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*", "/*/*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}
}

func guestGrant() types.GrantEntry {
	return types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"shared/gating/*"}},
		Operations: types.CapabilityScope{Include: []string{"get"}},
	}
}

func grantsHaveWildcard(grants []types.GrantEntry) bool {
	for _, g := range grants {
		hw, ow := false, false
		for _, h := range g.Handlers.Include {
			if h == "*" {
				hw = true
			}
		}
		for _, o := range g.Operations.Include {
			if o == "*" {
				ow = true
			}
		}
		if hw && ow {
			return true
		}
	}
	return false
}

// newGatingHandler builds a ConnectHandler whose resolver returns the guest
// grants for exactly `recognized`, nil otherwise. connectionGrants is the floor.
func newGatingHandler(t *testing.T, floor []types.GrantEntry, recognized hash.Hash) *ConnectHandler {
	t.Helper()
	localKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("gen local: %v", err)
	}
	ch, err := NewConnectHandler(localKP, nil)
	if err != nil {
		t.Fatalf("NewConnectHandler: %v", err)
	}
	ch.SetConnectionGrants(floor)
	ch.SetGrantResolver(func(_ crypto.PeerID, h hash.Hash) []types.GrantEntry {
		if h == recognized {
			return []types.GrantEntry{guestGrant()}
		}
		return nil
	})
	return ch
}

func mkPeer(t *testing.T, seed byte) (crypto.PeerID, hash.Hash) {
	t.Helper()
	var s [32]byte
	s[0] = seed
	kp := crypto.FromSeed(s)
	id, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return kp.PeerID(), id.ContentHash
}

// Case 1 — the correct gating outcome. A restrictive floor (anonymous-deny =
// empty connection grants) plus a resolver that recognizes K yields EXACTLY the
// resolved guest grants. No floor, no union: the recognized peer gets its role
// and nothing else. This is what the wire check asserts and could never observe
// against an open-access peer.
func TestAssembleInboundGrants_RestrictiveFloor_RecognizedGetsExactlyGuest(t *testing.T) {
	kPeerID, kHash := mkPeer(t, 0x4b)
	ch := newGatingHandler(t, []types.GrantEntry{}, kHash)

	got := ch.AssembleInboundGrants(nil, nil, kPeerID, kHash)
	want := []types.GrantEntry{guestGrant()}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recognized peer under restrictive floor:\n got  = %+v\n want = %+v", got, want)
	}
}

// Case 2 — deny works. Restrictive floor, UNrecognized peer (resolver returns
// nil) falls through to the empty connection grants: no cap.
func TestAssembleInboundGrants_RestrictiveFloor_UnrecognizedGetsNothing(t *testing.T) {
	_, kHash := mkPeer(t, 0x4b)       // the recognized one
	mPeerID, mHash := mkPeer(t, 0x6d) // a different, unrecognized peer
	ch := newGatingHandler(t, []types.GrantEntry{}, kHash)

	got := ch.AssembleInboundGrants(nil, nil, mPeerID, mHash)
	if len(got) != 0 {
		t.Fatalf("unrecognized peer under restrictive floor must get no grants, got %d: %+v", len(got), got)
	}
}

// Case 3 — the floor does NOT leak. Even with an OPEN-ACCESS floor, a resolver
// that returns non-nil grants preempts it (connect.go: fall through to
// connectionGrants only when the resolver returns nil). So the open-access floor
// alone is not where the wire leak came from — proving that requires Case 4.
func TestAssembleInboundGrants_OpenAccessFloor_ResolverPreemptsIt(t *testing.T) {
	kPeerID, kHash := mkPeer(t, 0x4b)
	ch := newGatingHandler(t, []types.GrantEntry{openAccessGrant()}, kHash)

	got := ch.AssembleInboundGrants(nil, nil, kPeerID, kHash)
	want := []types.GrantEntry{guestGrant()}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolver must preempt the open-access floor:\n got  = %+v\n want = %+v", got, want)
	}
	if grantsHaveWildcard(got) {
		t.Fatal("open-access floor leaked a wildcard past the resolver")
	}
}

// Case 4 — THE leak, reproduced in-process. §8 unions any matching
// system/capability/policy entry onto the resolved grants. A `default`-pattern
// policy entry carrying open-access grants (the shape an -open-access /
// wide-seed-policy peer materializes) is unioned onto K's guest grant, yielding
// exactly the `guest ∪ OpenAccessGrants()` the wire check saw. This is the
// definitive grounding: the leak is the POLICY-TABLE union under a permissive
// posture, and a restrictive posture (no such entry — Cases 1/2) is what makes
// the gate observable. The union itself is spec-correct (V7 v7.62 §8).
func TestAssembleInboundGrants_DefaultPolicyEntry_UnionsOntoResolved(t *testing.T) {
	kPeerID, kHash := mkPeer(t, 0x4b)
	ch := newGatingHandler(t, []types.GrantEntry{}, kHash)

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	pol := types.CapabilityPolicyEntryData{
		PeerPattern: "default",
		Grants:      []types.GrantEntry{openAccessGrant()},
	}
	polEnt, err := pol.ToEntity()
	if err != nil {
		t.Fatalf("policy ToEntity: %v", err)
	}
	if _, err := cs.Put(polEnt); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	li.Set("system/capability/policy/default", polEnt.ContentHash)

	got := ch.AssembleInboundGrants(cs, li, kPeerID, kHash)

	// guest (resolved) followed by the default-policy open-access union.
	if len(got) != 2 {
		t.Fatalf("expected guest ∪ open-access (2 grants), got %d: %+v", len(got), got)
	}
	if !reflect.DeepEqual(got[0], guestGrant()) {
		t.Fatalf("first grant must be the resolved guest grant, got %+v", got[0])
	}
	if !grantsHaveWildcard(got) {
		t.Fatal("default-policy union should have introduced the open-access wildcard — the reproduced leak")
	}
}
