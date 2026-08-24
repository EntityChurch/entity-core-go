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

// TestConnect_RT6_NonceSingleUse pins RT-6 (§4.6): the issued handshake nonce
// is single-use. A SECOND authenticate on the SAME connection (same connection
// state, replaying the consumed nonce) MUST be rejected with 401 invalid_nonce.
// The mechanism is impl-defined — Go tracks post-handshake established state —
// but the status is pinned: a generic 409 connection_already_established (the
// pre-RT-6 behavior) under-signals a replay to the peer. This is the
// same-connection complement to R3a idempotency, which re-handshakes on a
// FRESH connection (fresh nonce) and legitimately returns 200.
func TestConnect_RT6_NonceSingleUse(t *testing.T) {
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

	// One connection state, reused for both authenticate legs (same nonce).
	cstate := NewConnectionState()

	helloEnv, _, err := CreateHelloExecute(remoteKP, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DispatchEnvelope(context.Background(), helloEnv, cstate); err != nil {
		t.Fatalf("hello dispatch: %v", err)
	}

	// Leg 1: valid authenticate consumes the nonce — 200.
	authEnv, err := CreateAuthenticateExecute(remoteKP, cstate.OurNonce)
	if err != nil {
		t.Fatal(err)
	}
	resp1, err := d.DispatchEnvelope(context.Background(), authEnv, cstate)
	if err != nil {
		t.Fatalf("authenticate dispatch: %v", err)
	}
	rd1, err := types.ExecuteResponseDataFromEntity(resp1.Root)
	if err != nil {
		t.Fatal(err)
	}
	if rd1.Status != 200 {
		t.Fatalf("first authenticate: got status %d, want 200", rd1.Status)
	}

	// Leg 2: replay the identical authenticate on the same connection state.
	resp2, err := d.DispatchEnvelope(context.Background(), authEnv, cstate)
	if err != nil {
		t.Fatalf("replay authenticate dispatch: %v", err)
	}
	rd2, err := types.ExecuteResponseDataFromEntity(resp2.Root)
	if err != nil {
		t.Fatal(err)
	}
	if rd2.Status != 401 {
		t.Fatalf("RT-6: replayed authenticate got status %d, want 401 invalid_nonce (a non-401 under-signals the replay)", rd2.Status)
	}
	var errEnt entity.Entity
	if err := ecf.Decode(rd2.Result, &errEnt); err != nil {
		t.Fatalf("decode replay error result entity: %v", err)
	}
	var errData types.ErrorData
	if err := ecf.Decode(errEnt.Data, &errData); err != nil {
		t.Fatalf("decode replay error data: %v", err)
	}
	if errData.Code != "invalid_nonce" {
		t.Fatalf("RT-6: replayed authenticate code %q, want invalid_nonce", errData.Code)
	}
}
