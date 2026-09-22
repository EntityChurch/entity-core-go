package protocol

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// FM-1 (§4.7 row 6, ruled 2026-08-30 → entity-core-protocol 804876e).
//
// An `authenticate` arriving as the FIRST frame — before any `hello` nonce has
// been issued — is the wire form of the replay attack §4.6 step 1 exists to
// stop: a captured authenticate replayed onto a fresh connection IS an
// authenticate-before-hello. It MUST be rejected with 401 invalid_nonce, the
// same status as the established-connection replay (RT-6, TestRT6_* /
// connect_idempotency). It previously mapped to 409 connection_sequence_error —
// a status in no §4.7 row for this input, and a state-conflict framing that
// under-signals the replay (§4.6 Hardening).
//
// The sequence gate fires BEFORE the handler's nonce/signature checks, so the
// bogus nonce here never reaches them; a validly-signed authenticate stands in
// for the captured frame. Teeth: reverting the fix maps this to 409
// connection_sequence_error — the CODE assertion reddens, and it is the
// load-bearing one, because a nonce-mismatch after hello is also 401 (see
// TestF12_NonceMismatch_Rejected), so status alone cannot separate the two
// paths. Both are pinned.
func TestFM1_PreHelloAuthenticate_IsInvalidNonce(t *testing.T) {
	localKP, _ := crypto.Generate()
	dialerKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	// Fresh connection, phase="init": NO hello leg. No nonce has been issued,
	// so any value stands in for a nonce captured elsewhere.
	cstate := NewConnectionState()
	env := buildAuthenticate(t, dialerKP, dialerKP, []byte("no-nonce-was-issued"), true)

	respEnv, err := d.DispatchEnvelope(context.Background(), env, cstate)
	if err != nil {
		t.Fatalf("authenticate dispatch: %v", err)
	}
	rd, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatal(err)
	}
	if rd.Status != 401 {
		t.Fatalf("pre-hello authenticate: got status %d, want 401 (FM-1); a 409 sequence/state conflict under-signals the replay", rd.Status)
	}

	var errEnt entity.Entity
	if err := ecf.Decode(rd.Result, &errEnt); err != nil {
		t.Fatalf("decode error result entity: %v", err)
	}
	var errData types.ErrorData
	if err := ecf.Decode(errEnt.Data, &errData); err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	if errData.Code != "invalid_nonce" {
		t.Fatalf("pre-hello authenticate: code %q, want invalid_nonce (FM-1)", errData.Code)
	}
}
