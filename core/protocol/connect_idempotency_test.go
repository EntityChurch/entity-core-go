package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestConnect_R3a_GranterIdempotency exercises the proposal §7.3 R3a gate:
// two full hello+authenticate handshakes from the same remote against the
// same granter MUST resolve to the same capability-token entity (identical
// token hash on the grant). Pre-R3a behavior minted a fresh CreatedAt-
// bearing token per handshake, churning the token entity hash and bloating
// the store.
func TestConnect_R3a_GranterIdempotency(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()

	ch, err := NewConnectHandler(localKP, nil)
	if err != nil {
		t.Fatal(err)
	}

	reg := handler.NewRegistry()
	reg.Register("system/protocol/connect", ch)

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(reg, cs, li, localKP, nil)

	doHandshake := func(kp crypto.Keypair) types.CapabilityGrantData {
		t.Helper()
		// hello
		helloEnv, _, err := CreateHelloExecute(kp, nil)
		if err != nil {
			t.Fatal(err)
		}
		cstate := NewConnectionState()
		if _, err := d.DispatchEnvelope(context.Background(), helloEnv, cstate); err != nil {
			t.Fatalf("hello dispatch: %v", err)
		}
		// authenticate — echo the nonce the *server* issued on its hello
		// response (recorded in cstate.OurNonce), per §4.6 nonce-echo. The
		// dialer's own hello nonce is not what the responder challenges with.
		authEnv, err := CreateAuthenticateExecute(kp, cstate.OurNonce)
		if err != nil {
			t.Fatal(err)
		}
		respEnv, err := d.DispatchEnvelope(context.Background(), authEnv, cstate)
		if err != nil {
			t.Fatalf("authenticate dispatch: %v", err)
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			t.Fatal(err)
		}
		if respData.Status != 200 {
			t.Fatalf("authenticate status: got %d, want 200", respData.Status)
		}
		var grantEnt entity.Entity
		if err := ecf.Decode(respData.Result, &grantEnt); err != nil {
			t.Fatalf("decode grant entity: %v", err)
		}
		var grant types.CapabilityGrantData
		if err := ecf.Decode(grantEnt.Data, &grant); err != nil {
			t.Fatalf("decode grant data: %v", err)
		}
		return grant
	}

	g1 := doHandshake(remoteKP)
	g2 := doHandshake(remoteKP)
	if g1.Token != g2.Token {
		t.Fatalf("R3a violated: two handshakes minted distinct tokens\n  first:  %s\n  second: %s", g1.Token, g2.Token)
	}

	// Cross-grantee non-collapse: a different remote MUST get a
	// distinct token, since the cache key includes the grantee
	// identity. (Catches a hypothetical key-collision regression.)
	otherKP, _ := crypto.Generate()
	g3 := doHandshake(otherKP)
	if g3.Token == g1.Token {
		t.Fatalf("R3a violated: distinct remotes collapsed onto a single token (%s)", g1.Token)
	}
}
