package protocol

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

// SPEC-FINDING F12 — handshake proof-of-possession.
//
// The §4.6 authenticate step must reject any authenticate that does not (a)
// echo the nonce the responder issued on hello and (b) carry a valid signature
// by the claimed key over the authenticate entity. Before the F12 fix the
// responder checked neither: the nonce was decorative and an authenticate
// forged from a peer's *public* identity (not secret) — or replayed from
// another connection — was accepted. These tests pin the rejections.

// newF12Dispatcher builds a connect-only dispatcher for handshake tests.
func newF12Dispatcher(t *testing.T, localKP crypto.Keypair) *Dispatcher {
	t.Helper()
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
	return NewDispatcher(reg, cs, li, localKP, nil)
}

// f12Hello runs the hello leg and returns the connection state, whose
// OurNonce now holds the nonce the responder issued (its challenge).
func f12Hello(t *testing.T, d *Dispatcher, dialerKP crypto.Keypair) *ConnectionState {
	t.Helper()
	helloEnv, _, err := CreateHelloExecute(dialerKP, nil)
	if err != nil {
		t.Fatal(err)
	}
	cstate := NewConnectionState()
	if _, err := d.DispatchEnvelope(context.Background(), helloEnv, cstate); err != nil {
		t.Fatalf("hello dispatch: %v", err)
	}
	return cstate
}

// authStatus dispatches an authenticate envelope and returns the response status.
func authStatus(t *testing.T, d *Dispatcher, env entity.Envelope, cstate *ConnectionState) uint {
	t.Helper()
	respEnv, err := d.DispatchEnvelope(context.Background(), env, cstate)
	if err != nil {
		t.Fatalf("authenticate dispatch: %v", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatal(err)
	}
	return respData.Status
}

// buildAuthenticate constructs an authenticate EXECUTE envelope where the
// claimed identity, the echoed nonce, and the signing key can all be chosen
// independently — so a test can forge an authenticate that claims one peer's
// public identity while signing with another's key.
func buildAuthenticate(t *testing.T, claimKP, signKP crypto.Keypair, nonce []byte, includeSig bool) entity.Envelope {
	t.Helper()
	claimIdentity, err := claimKP.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	authData := types.AuthenticateData{
		PeerID:    string(claimKP.PeerID()),
		PublicKey: claimKP.PublicKeyBytes(),
		KeyType:   "ed25519",
		Nonce:     nonce,
	}
	authEntity, err := authData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	included := map[hash.Hash]entity.Entity{claimIdentity.ContentHash: claimIdentity}
	if includeSig {
		signIdentity, err := signKP.IdentityEntity()
		if err != nil {
			t.Fatal(err)
		}
		sig := signKP.Sign(authEntity.ContentHash.Bytes())
		sigEntity, err := types.SignatureData{
			Target:    authEntity.ContentHash,
			Signer:    signIdentity.ContentHash,
			Algorithm: "ed25519",
			Signature: sig,
		}.ToEntity()
		if err != nil {
			t.Fatal(err)
		}
		included[sigEntity.ContentHash] = sigEntity
	}
	paramsRaw, err := ecf.Encode(authEntity)
	if err != nil {
		t.Fatal(err)
	}
	execEntity, err := types.ExecuteData{
		RequestID: "connect-authenticate",
		URI:       connectPath,
		Operation: "authenticate",
		Params:    cbor.RawMessage(paramsRaw),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return entity.NewEnvelope(execEntity, included)
}

func TestF12_HappyPath_Accepts(t *testing.T) {
	localKP, _ := crypto.Generate()
	dialerKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)
	cstate := f12Hello(t, d, dialerKP)

	env := buildAuthenticate(t, dialerKP, dialerKP, cstate.OurNonce, true)
	if got := authStatus(t, d, env, cstate); got != 200 {
		t.Fatalf("valid authenticate: got status %d, want 200", got)
	}
}

func TestF12_NonceMismatch_Rejected(t *testing.T) {
	localKP, _ := crypto.Generate()
	dialerKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)
	cstate := f12Hello(t, d, dialerKP)

	wrongNonce := make([]byte, len(cstate.OurNonce))
	copy(wrongNonce, cstate.OurNonce)
	wrongNonce[0] ^= 0xFF // flip a bit — no longer the issued challenge

	env := buildAuthenticate(t, dialerKP, dialerKP, wrongNonce, true)
	if got := authStatus(t, d, env, cstate); got != 401 {
		t.Fatalf("nonce mismatch: got status %d, want 401", got)
	}
}

func TestF12_MissingSignature_Rejected(t *testing.T) {
	localKP, _ := crypto.Generate()
	dialerKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)
	cstate := f12Hello(t, d, dialerKP)

	env := buildAuthenticate(t, dialerKP, dialerKP, cstate.OurNonce, false)
	if got := authStatus(t, d, env, cstate); got != 401 {
		t.Fatalf("missing signature: got status %d, want 401", got)
	}
}

// TestF12_Impersonation_Rejected is the core attack: an attacker presents the
// victim's *public* identity (peer_id + public_key, both public), echoes the
// correct issued nonce, but cannot sign as the victim. Signing with the
// attacker's own key must fail signature verification against the claimed
// (victim's) public key.
func TestF12_Impersonation_Rejected(t *testing.T) {
	localKP, _ := crypto.Generate()
	victimKP, _ := crypto.Generate()
	attackerKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)
	cstate := f12Hello(t, d, victimKP)

	// Claim victim's identity, sign with attacker's key.
	env := buildAuthenticate(t, victimKP, attackerKP, cstate.OurNonce, true)
	if got := authStatus(t, d, env, cstate); got != 401 {
		t.Fatalf("impersonation: got status %d, want 401", got)
	}
}
