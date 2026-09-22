package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Teeth for the three §4.6/§4.7 rulings arch landed 2026-09-01 (routed from go's
// spec-issues 2026-09-01-b / -c). Each is mutation-verified in the doc comment.

// dispatchStatusCode drives an envelope on the connect path and returns the
// response (status, code).
func dispatchStatusCode(t *testing.T, d *Dispatcher, env entity.Envelope, cstate *ConnectionState) (uint, string) {
	t.Helper()
	respEnv, err := d.DispatchEnvelope(context.Background(), env, cstate)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	rd, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatal(err)
	}
	if rd.Status == 200 {
		return rd.Status, ""
	}
	var errEnt entity.Entity
	if err := ecf.Decode(rd.Result, &errEnt); err != nil {
		t.Fatalf("decode error result: %v", err)
	}
	var errData types.ErrorData
	if err := ecf.Decode(errEnt.Data, &errData); err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	return rd.Status, errData.Code
}

// Row 1 (§4.5 / §4.7 incompatible_protocol): a hello whose protocols intersect
// the responder's empty MUST reject 400 incompatible_protocol — the live gap
// where go completed the handshake for a counterparty speaking no version it
// supports. Control: a common version handshakes to 200. Mutation: drop the
// len>0 && !anyInBoth guard in handleHello -> the disjoint hello reaches 200 and
// the reject row reddens.
func TestRow1_IncompatibleProtocol_Rejected(t *testing.T) {
	localKP, _ := crypto.Generate()
	dialerKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	// Disjoint: responder speaks entity-core/1.0 only.
	disjoint, _, err := CreateHelloExecute(dialerKP, []string{"entity-core/99.0"})
	if err != nil {
		t.Fatal(err)
	}
	if st, code := dispatchStatusCode(t, d, disjoint, NewConnectionState()); st != 400 || code != "incompatible_protocol" {
		t.Fatalf("disjoint protocols: got (%d, %q), want (400, incompatible_protocol)", st, code)
	}

	// Control: a common version handshakes.
	common, _, err := CreateHelloExecute(dialerKP, []string{"entity-core/1.0", "entity-core/99.0"})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := dispatchStatusCode(t, d, common, NewConnectionState()); st != 200 {
		t.Fatalf("common protocol: got status %d, want 200", st)
	}

	// A nil arg to the INITIATOR defaults to [entity-core/1.0] in
	// CreateHelloExecute, so the wire hello is non-empty and intersects -> 200.
	// This pins the initiator default, NOT the responder's absent-arm behavior;
	// a genuinely-empty wire hello is refused (FM-2e, see the next test).
	defaulted, _, err := CreateHelloExecute(dialerKP, nil) // CreateHelloExecute defaults nil -> 1.0
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := dispatchStatusCode(t, d, defaulted, NewConnectionState()); st != 200 {
		t.Fatalf("initiator-defaulted protocols: got status %d, want 200", st)
	}
}

// helloWithProtocols builds a raw hello EXECUTE envelope with EXACTLY the given
// protocols set (bypassing CreateHelloExecute's nil->[1.0] default) so a
// genuinely-empty list can reach the responder.
func helloWithProtocols(t *testing.T, kp crypto.Keypair, protocols []string) entity.Envelope {
	t.Helper()
	nonce := make([]byte, 32)
	helloEnt, err := types.HelloData{
		PeerID:      string(kp.PeerID()),
		Nonce:       nonce,
		Protocols:   protocols,
		HashFormats: DefaultAdvertisedHashFormats(),
		KeyTypes:    DefaultAdvertisedKeyTypes(),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	paramsRaw, err := ecf.Encode(helloEnt)
	if err != nil {
		t.Fatal(err)
	}
	execEnt, err := types.ExecuteData{
		RequestID: "connect-hello",
		URI:       connectPath,
		Operation: "hello",
		Params:    cbor.RawMessage(paramsRaw),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return entity.NewEnvelope(execEnt, nil)
}

// FM-2e (§4.5 SA-PY-31, folded 0.8.2.4): an ABSENT or EMPTY protocols set is a
// malformed request -> 400 invalid_request, NOT incompatible_protocol (arch
// ruled reading 2 over go's shipped reading 1). Dormant arm: no cohort peer
// emits an empty list, so nothing conformant is refused. Mutation: revert to
// reading 1 (`len(...) > 0 &&` guarding the disjoint check) -> an empty list
// falls through to 200, reddening this; a bare disjoint check (drop the empty
// guard) -> an empty list intersects to empty -> incompatible_protocol, also
// reddening this on the code.
func TestFM2e_AbsentProtocols_IsInvalidRequest(t *testing.T) {
	localKP, _ := crypto.Generate()
	dialerKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	for _, tc := range []struct {
		name      string
		protocols []string
	}{
		{"empty", []string{}},
		{"nil", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := helloWithProtocols(t, dialerKP, tc.protocols)
			if st, code := dispatchStatusCode(t, d, env, NewConnectionState()); st != 400 || code != "invalid_request" {
				t.Fatalf("%s protocols: got (%d, %q), want (400, invalid_request)", tc.name, st, code)
			}
		})
	}

	// Control: a non-empty intersecting list still handshakes to 200 — the
	// guard rejects the empty case specifically, not all hellos.
	ok := helloWithProtocols(t, dialerKP, []string{"entity-core/1.0"})
	if st, _ := dispatchStatusCode(t, d, ok, NewConnectionState()); st != 200 {
		t.Fatalf("non-empty intersecting protocols: got status %d, want 200", st)
	}
}

// Row 10 (§4.7, closes PD-1g): an UNRECOGNIZED connect operation is a malformed
// request -> 400 invalid_request, NOT the 409 state-conflict code. Mutation:
// remove the operation switch at the top of the connect branch -> an unknown op
// falls through to ValidateConnectionSequence and returns 409, reddening this.
func TestRow10_UnknownConnectOperation_IsInvalidRequest(t *testing.T) {
	localKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	execEntity, err := types.ExecuteData{
		RequestID: "connect-frobnicate",
		URI:       connectPath,
		Operation: "frobnicate", // not hello / authenticate / ping
		Params:    cbor.RawMessage(nil),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	env := entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{})
	if st, code := dispatchStatusCode(t, d, env, NewConnectionState()); st != 400 || code != "invalid_request" {
		t.Fatalf("unknown connect op: got (%d, %q), want (400, invalid_request)", st, code)
	}
}

// -c (§4.6 step ordering ruled normative): the identity binding (step 3) runs
// AFTER signature verification (step 2). An input that fails BOTH — claim kpA's
// peer_id, present kpB's public_key (step 3 fails), sign with kpA (does not
// verify against kpB's key, step 2 fails) — must report the step-2
// authentication_failed, matching rust/py's numbered order. Mutation: move the
// VerifyPublicKey check back above the signature verify -> this returns
// identity_mismatch (the pre-ruling go order) and the code assertion reddens.
func TestOrdering_Step3AfterStep2_ReportsAuthenticationFailed(t *testing.T) {
	localKP, _ := crypto.Generate()
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)
	cstate := f12Hello(t, d, kpA)

	env := buildAuthenticateMismatch(t, kpA, kpB, kpA, cstate.OurNonce)
	st, code := dispatchStatusCode(t, d, env, cstate)
	if st != 401 || code != "authentication_failed" {
		t.Fatalf("fails-both input under numbered order: got (%d, %q), want (401, authentication_failed) — "+
			"identity_mismatch means step 3 ran before step 2 (pre-ruling order)", st, code)
	}
}

// buildAuthenticateMismatch builds an authenticate whose claimed peer_id
// (peerIDKP), presented public_key (pubKeyKP), and signing key (signKP) are all
// independent — the shape buildAuthenticate cannot express because it ties
// peer_id and public_key together.
func buildAuthenticateMismatch(t *testing.T, peerIDKP, pubKeyKP, signKP crypto.Keypair, nonce []byte) entity.Envelope {
	t.Helper()
	authData := types.AuthenticateData{
		PeerID:    string(peerIDKP.PeerID()),
		PublicKey: pubKeyKP.PublicKeyBytes(),
		KeyType:   "ed25519",
		Nonce:     nonce,
	}
	authEntity, err := authData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
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
	return entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		signIdentity.ContentHash: signIdentity,
		sigEntity.ContentHash:    sigEntity,
	})
}
