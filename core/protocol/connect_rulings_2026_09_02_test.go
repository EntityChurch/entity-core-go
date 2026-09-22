package protocol

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Teeth for the three §4.6/§4.7 gaps entity-core-rust routed in
// ROUTING-2026-09-02-f, all against the folded ENTITY-CORE-PROTOCOL 0.8.2.4.

// (a) §4.6 "MUST also verify authenticate.peer_id == hello.peer_id for the same
// connection." A hello advertising kpA, then a fully-valid authenticate for kpB
// (peer_id, public_key and signature all internally consistent for B, correct
// nonce — steps 0–3 all pass) must be refused 401 identity_mismatch, because the
// claimed identity changed mid-handshake. Mutation: drop the cs.HelloPeerID
// equality check in handleAuthenticate -> the B authenticate completes at 200
// (the exact hole: one peer_id in hello, another in authenticate, no error).
func TestFold0902_AuthenticatePeerIDMustMatchHello(t *testing.T) {
	localKP, _ := crypto.Generate()
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	cstate := f12Hello(t, d, kpA) // HelloPeerID = kpA
	// A valid authenticate for kpB against the issued nonce: internally
	// consistent, so it clears steps 0–3 and only the hello-equality check fails.
	env := buildAuthenticate(t, kpB, kpB, cstate.OurNonce, true)
	if st, code := dispatchStatusCode(t, d, env, cstate); st != 401 || code != "identity_mismatch" {
		t.Fatalf("authenticate peer_id != hello peer_id: got (%d, %q), want (401, identity_mismatch)", st, code)
	}

	// Control: an authenticate for the SAME peer as the hello completes (200) —
	// the check refuses a changed identity, not every authenticate.
	ok := f12Hello(t, d, kpA)
	same := buildAuthenticate(t, kpA, kpA, ok.OurNonce, true)
	if st, _ := dispatchStatusCode(t, d, same, ok); st != 200 {
		t.Fatalf("matching peer_id authenticate: got status %d, want 200", st)
	}
}

// (b) §4.7 out-of-order row: a SECOND hello mid-handshake (after the first hello,
// before completion) → 409 connection_sequence_error, not a re-issued nonce.
// Mutation: drop the Phase=="awaiting_authenticate" guard in
// ValidateConnectionSequence -> the second hello returns nil and completes at 200.
func TestFold0902_SecondHelloMidHandshakeIsSequenceError(t *testing.T) {
	localKP, _ := crypto.Generate()
	kpA, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	cstate := f12Hello(t, d, kpA) // Phase -> awaiting_authenticate
	second, _, err := CreateHelloExecute(kpA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st, code := dispatchStatusCode(t, d, second, cstate); st != 409 || code != "connection_sequence_error" {
		t.Fatalf("second hello mid-handshake: got (%d, %q), want (409, connection_sequence_error)", st, code)
	}
}

// (c) §4.7 out-of-order row: a pre-handshake ping (ping is implemented, arriving
// before the connection is established) → 409 connection_sequence_error. The old
// code was 403 connection_required, a string in no spec. Mutation: restore the
// 403 connection_required mapping in execute.go -> code/status reddens.
func TestFold0902_PreHandshakePingIsSequenceError(t *testing.T) {
	localKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	execEnt, err := types.ExecuteData{
		RequestID: "connect-ping-prehello",
		URI:       connectPath,
		Operation: "ping",
		Params:    cbor.RawMessage(nil),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	env := entity.NewEnvelope(execEnt, nil)
	if st, code := dispatchStatusCode(t, d, env, NewConnectionState()); st != 409 || code != "connection_sequence_error" {
		t.Fatalf("pre-handshake ping: got (%d, %q), want (409, connection_sequence_error)", st, code)
	}
}

// (d) §4.7 row 10 is "in ANY state": an unknown connect operation is a malformed
// request classified by its NAME, not by the connection's state. On an ESTABLISHED
// connection a frobnicate must STILL be 400 invalid_request — not 409
// connection_already_established (which is the state-conflict answer reserved for a
// RECOGNIZED op arriving in a forbidden state, e.g. a second hello). The wire probe
// connect_unknown_operation only reaches this row pre-handshake, so this pins the
// established arm no dialing probe exercises. Mutation: move the unknown-op switch
// (execute.go, "unknown connect operation") BELOW the connState.Completed branch ->
// frobnicate on an established connection returns 409 connection_already_established
// and step 1 reddens. Control (step 2): a hello in the same state IS a recognized
// op in a forbidden state, so it MUST be 409 — proving the branch discriminates
// name from state rather than answering 400 to everything.
func TestFold0902_UnknownConnectOperationIsInvalidRequestInAnyState(t *testing.T) {
	localKP, _ := crypto.Generate()
	kpA, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	// Establish: hello + a valid authenticate → Completed.
	cstate := f12Hello(t, d, kpA)
	auth := buildAuthenticate(t, kpA, kpA, cstate.OurNonce, true)
	if st, _ := dispatchStatusCode(t, d, auth, cstate); st != 200 {
		t.Fatalf("handshake setup: authenticate got status %d, want 200", st)
	}
	if !cstate.Completed {
		t.Fatal("handshake setup: connection not marked established")
	}

	// Step 1 (input under test): unknown op on the established connection → 400.
	unknown, err := types.ExecuteData{
		RequestID: "connect-unknown-op-established",
		URI:       connectPath,
		Operation: "frobnicate",
		Params:    cbor.RawMessage(nil),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if st, code := dispatchStatusCode(t, d, entity.NewEnvelope(unknown, nil), cstate); st != 400 || code != "invalid_request" {
		t.Fatalf("unknown op on established connection: got (%d, %q), want (400, invalid_request) — row 10 is 'in any state'", st, code)
	}

	// Step 2 (control): a RECOGNIZED op in the forbidden state → 409, proving the
	// established branch discriminates operation-name from state.
	hello, _, err := CreateHelloExecute(kpA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st, code := dispatchStatusCode(t, d, hello, cstate); st != 409 || code != "connection_already_established" {
		t.Fatalf("control hello on established connection: got (%d, %q), want (409, connection_already_established)", st, code)
	}
}

// CE-1 (arch ROUTING-2026-09-02-h; ENTITY-CORE-PROTOCOL 0.8.2.5 note under §4.7,
// §4.2 third pre-authorization rule + §5.2a). A NON-connect EXECUTE arriving before
// the handshake completes carries no verified signer, so it is auth-class and MUST
// be refused 401 authentication_failed — NOT 403 (the blanket status F32 retired at
// 0.8.1, which also wrongly asserts "authenticated but not permitted"), and NOT the
// minted connection_required the 0.8.2.5 note names non-conformant. The dispatcher
// refuses at the non-connect auth gate ahead of handler resolution, so system/tree
// need not be registered. Mutation: restore (403, connection_required) at
// execute.go's non-connect branch -> this reddens.
func TestCE1_NonConnectExecuteBeforeEstablishedIs401(t *testing.T) {
	localKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	execEnt, err := types.ExecuteData{
		RequestID: "ce1-execute-before-established",
		URI:       "system/tree",
		Operation: "get",
		Params:    cbor.RawMessage(nil),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	// A fresh (un-established) connection: Completed == false.
	if st, code := dispatchStatusCode(t, d, entity.NewEnvelope(execEnt, nil), NewConnectionState()); st != 401 || code != "authentication_failed" {
		t.Fatalf("non-connect EXECUTE before establishment: got (%d, %q), want (401, authentication_failed)", st, code)
	}
}
