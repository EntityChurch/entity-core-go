package protocol

import (
	"context"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// PD-1h / §1.4 dispatch routing + §9.1 (ruled 2026-08-31 → entity-core-protocol
// ba2f5a3, 0.8.2.2).
//
// An inbound EXECUTE whose HANDLER uri names a peer_id that is not the local
// peer MUST be refused at canonicalization — 400 invalid_request — before
// handler resolution and before the connect branch. §6.5 step 3 is a GATE, not
// an ordering preference: an impl MUST NOT reach the refusal by stripping the
// peer id, resolving the local handler, and letting the §5.2 peers dimension
// decide. That strip-and-resolve path is the live escalation (P1 → 200 in the
// minority-of-6): a grant carrying a matching `peers` scope authorizes a foreign
// namespace over the wire.
//
// Teeth: the foreign-handler-uri row asserts (400, invalid_request) — reverting
// the gate maps it to a connection/auth outcome (no gate, so it falls through to
// the non-connect auth path), reddening the code assertion. The positive control
// is the discriminator: the SAME request to a LOCAL handler uri MUST NOT be
// 400 invalid_request — proving the gate keys on the handler uri's peer segment,
// not on foreign-looking input generally. The universal-address-space category
// (cmd/internal/validate/universal_address_space.go) is the wire-level companion
// control: a tree:put to entity://{local}/system/tree with a foreign RESOURCE
// target stays conformant, because the gate reads the handler uri (local there),
// never the resource path.
func TestPD1h_ForeignHandlerURI_RefusedBeforeDispatch(t *testing.T) {
	localKP, _ := crypto.Generate()
	d := newF12Dispatcher(t, localKP)

	// A syntactic-but-unowned foreign peer id (base58, ≥46 chars so every impl's
	// is_peer_id recognizes it) that is not the peer under test.
	const foreignID = "1HtVqLgPqkScVxjVN8VFGFiH7T2P3aSDwJxQ8DGEoooo2z"
	if foreignID == string(localKP.PeerID()) {
		t.Fatal("fixture foreign id collides with local peer id")
	}

	// --- The gate: a foreign HANDLER uri is refused (400, invalid_request). ---
	status, code := dispatchExecuteURI(t, d, "entity://"+foreignID+"/system/tree")
	if status != 400 || code != "invalid_request" {
		t.Fatalf("foreign handler uri: got (%d, %q), want (400, invalid_request) — the §1.4 routing gate (PD-1h) must refuse an EXECUTE naming a non-local peer BEFORE resolving locally", status, code)
	}

	// --- Positive control: a LOCAL handler uri is NOT gated. ---
	// It falls through to the normal path (here: unauthenticated → a
	// connection/auth outcome), the point being only that it is not the gate's
	// 400 invalid_request. If this ever reads (400, invalid_request), the gate
	// has stopped discriminating and is rejecting local dispatch too.
	lstatus, lcode := dispatchExecuteURI(t, d, "entity://"+string(localKP.PeerID())+"/system/tree")
	if lstatus == 400 && lcode == "invalid_request" {
		t.Fatalf("local handler uri: got (400, invalid_request) — the gate must NOT fire on the local peer's own namespace")
	}

	// --- Positive control: a peer-relative handler uri is NOT gated either. ---
	rstatus, rcode := dispatchExecuteURI(t, d, "system/tree")
	if rstatus == 400 && rcode == "invalid_request" {
		t.Fatalf("peer-relative handler uri: got (400, invalid_request) — peer-relative belongs to the local peer and must not be gated")
	}
}

// dispatchExecuteURI sends a minimal unauthenticated EXECUTE (op "get") at the
// given handler uri through the wire entry (DispatchEnvelope → handleExecute)
// with no connection state, and returns the response (status, code). The PD-1h
// gate fires ahead of the connect branch and auth, so connState=nil is enough
// to isolate it; a non-gated uri simply proceeds past the gate to whatever the
// unauthenticated path returns.
func dispatchExecuteURI(t *testing.T, d *Dispatcher, uri string) (uint, string) {
	t.Helper()
	paramsRaw, _ := ecf.Encode(map[string]string{"path": "system/tree/probe"})
	execData := types.ExecuteData{
		RequestID: "pd1h-req",
		URI:       uri,
		Operation: "get",
		Params:    cbor.RawMessage(paramsRaw),
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	env := entity.NewEnvelope(execEntity, nil)

	respEnv, err := d.DispatchEnvelope(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("dispatch %q: %v", uri, err)
	}
	rd, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatal(err)
	}
	if rd.Status >= 200 && rd.Status < 300 {
		return rd.Status, ""
	}
	var errEnt entity.Entity
	if err := ecf.Decode(rd.Result, &errEnt); err != nil {
		t.Fatalf("decode error result entity for %q: %v", uri, err)
	}
	var errData types.ErrorData
	if err := ecf.Decode(errEnt.Data, &errData); err != nil {
		t.Fatalf("decode error data for %q: %v", uri, err)
	}
	return rd.Status, errData.Code
}
