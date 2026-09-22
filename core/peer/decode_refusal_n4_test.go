package peer

import (
	"net"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/core/wire"
)

// TestServe_N4_DecodeBoundaryRefusalEmitsCodedFrameBeforeClose pins
// ENTITY-CORE-PROTOCOL 0.8.2.24 N4 (§4.9(c)/§4.10(a)): a frame refused at the
// decode boundary (validateRecv → ValidateAll: here a mis-keyed included entry,
// the §1.8 forgery vector) MUST put a coded response on the wire — correlated by
// request_id where the root still decodes — before the connection closes. A
// bare close with no coded frame (the pre-N4 behaviour) is non-conformant.
//
// This drives serve() directly with a raw dial: serve() runs validateRecv on the
// FIRST frame, ahead of the handshake dispatch, so the mis-keyed frame is refused
// there and never reaches a handler. The response's code is 400 hash_mismatch
// (F79: every ValidateAll failure is a hash-binding failure).
//
// Mutation witness: revert the N4 edit in serve() (bare `return` on the
// validateRecv failure) and the read below gets EOF instead of a coded frame.
func TestServe_N4_DecodeBoundaryRefusalEmitsCodedFrameBeforeClose(t *testing.T) {
	server := newMultiplexTestPeer(t, 0)

	raw, err := net.DialTimeout("tcp", server.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))

	// A valid EXECUTE root (so bestEffortRequestID recovers the request_id) whose
	// included map carries ONE mis-keyed entry: an entity filed under a key that
	// is not its content hash. ValidateAll's key-binding check rejects it.
	execData := types.ExecuteData{
		RequestID: "n4-teeth",
		URI:       "entity://" + string(server.PeerID()) + "/system/tree",
		Operation: "get",
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		t.Fatalf("build exec: %v", err)
	}
	otherRaw, err := ecf.Encode("x")
	if err != nil {
		t.Fatalf("encode other: %v", err)
	}
	other, err := entity.NewEntity("test/x", otherRaw)
	if err != nil {
		t.Fatalf("build other: %v", err)
	}
	// THE MIS-KEY: file `other` under execEntity's hash (guaranteed != other's).
	misKeyed := entity.Envelope{
		Root: execEntity,
		Included: map[hash.Hash]entity.Entity{
			execEntity.ContentHash: other,
		},
	}

	if err := wire.WriteEnvelope(raw, misKeyed); err != nil {
		t.Fatalf("write mis-keyed envelope: %v", err)
	}

	// N4: a coded frame MUST arrive before the close. A pre-N4 bare close yields
	// EOF here.
	respEnv, err := wire.ReadEnvelope(raw)
	if err != nil {
		t.Fatalf("expected a coded EXECUTE_RESPONSE before close, got read error (bare close is the pre-N4, non-conformant behaviour): %v", err)
	}

	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respData.Status != 400 {
		t.Fatalf("N4 coded frame: expected status 400, got %d", respData.Status)
	}
	if respData.RequestID != "n4-teeth" {
		t.Fatalf("N4 coded frame: expected request_id correlated to \"n4-teeth\", got %q", respData.RequestID)
	}

	var errEnt entity.Entity
	if err := ecf.Decode(respData.Result, &errEnt); err != nil {
		t.Fatalf("decode result entity: %v", err)
	}
	errData, err := types.ErrorDataFromEntity(errEnt)
	if err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	if errData.Code != "hash_mismatch" {
		t.Fatalf("N4 coded frame: expected code hash_mismatch (F79), got %q", errData.Code)
	}
}
