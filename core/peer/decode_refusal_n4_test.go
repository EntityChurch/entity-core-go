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

// TestServe_HashBindingRefusalEmitsCodedFrameAndContinues pins two rulings on
// the whole-decoded hash/key-binding refusal (validateRecv → ValidateAll: here a
// mis-keyed included entry, the §1.8 forgery vector):
//
//   - N4 (0.8.2.24 §4.9(c)/§4.10(a)): the refusal MUST put a coded response on
//     the wire — correlated by request_id where the root still decodes — code
//     400 hash_mismatch (F79: every ValidateAll failure is a hash-binding one).
//   - 0.8.2.29 item B (ROUTING-2026-09-16-j): the connection MUST NOT close. The
//     frame decoded WHOLE, so the stream is synchronized on the next boundary and
//     §4.9(c)/§4.10 forbid degrading service on a multiplexed link. serve()
//     CONTINUES on the hash/key-binding arm exactly as it does on the tag and
//     undecodable arms — the earlier per-cause close was a disposition inferred
//     from N4's code pin, now corrected.
//
// This drives serve() directly with a raw dial: serve() runs validateRecv on each
// frame ahead of the handshake dispatch, so the mis-keyed frame is refused there
// and never reaches a handler.
//
// Mutation witness (item B): restore the `return` on the hash/key-binding arm in
// serve() and the SECOND read below gets EOF (the connection closed) instead of a
// second coded frame. Mutation witness (N4): a bare `return` with no SendEnvelope
// gets EOF on the FIRST read.
func TestServe_HashBindingRefusalEmitsCodedFrameAndContinues(t *testing.T) {
	server := newMultiplexTestPeer(t, 0)

	raw, err := net.DialTimeout("tcp", server.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))

	// sendMisKeyed writes a valid EXECUTE root (so bestEffortRequestID recovers the
	// request_id) whose included map carries ONE mis-keyed entry — an entity filed
	// under a key that is not its content hash, which ValidateAll's key-binding
	// check rejects — then asserts the coded 400 hash_mismatch response correlated
	// to reqID.
	sendMisKeyed := func(reqID string) {
		t.Helper()
		execData := types.ExecuteData{
			RequestID: reqID,
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
			t.Fatalf("write mis-keyed envelope %q: %v", reqID, err)
		}

		respEnv, err := wire.ReadEnvelope(raw)
		if err != nil {
			t.Fatalf("%q: expected a coded EXECUTE_RESPONSE, got read error (a close here is non-conformant — N4 on the first frame, item-B on the second): %v", reqID, err)
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			t.Fatalf("%q: decode response: %v", reqID, err)
		}
		if respData.Status != 400 {
			t.Fatalf("%q: coded frame expected status 400, got %d", reqID, respData.Status)
		}
		if respData.RequestID != reqID {
			t.Fatalf("coded frame: expected request_id correlated to %q, got %q", reqID, respData.RequestID)
		}
		var errEnt entity.Entity
		if err := ecf.Decode(respData.Result, &errEnt); err != nil {
			t.Fatalf("%q: decode result entity: %v", reqID, err)
		}
		errData, err := types.ErrorDataFromEntity(errEnt)
		if err != nil {
			t.Fatalf("%q: decode error data: %v", reqID, err)
		}
		if errData.Code != "hash_mismatch" {
			t.Fatalf("%q: coded frame expected code hash_mismatch (F79), got %q", reqID, errData.Code)
		}
	}

	// First frame: the coded 400 MUST arrive (N4). A pre-N4 bare close yields EOF.
	sendMisKeyed("n4-teeth")

	// Item B (ROUTING-2026-09-16-j): the connection survived the whole-decoded
	// refusal, so a SECOND mis-keyed frame is still served with its own coded 400.
	// Under the pre-item-B `return` this read gets EOF — the discriminating teeth.
	sendMisKeyed("item-b-teeth")
}
