package signaling

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	cbor "github.com/fxamacker/cbor/v2"
)

// §7.1 dial order: class first (host → srflx → relay, via CandidatePriority),
// then address. An unknown class sorts LAST rather than being dropped. There is
// no wire priority field on system/network/candidate (§6.7.3) — try order is a
// pure function of the candidate `type`.
func TestCandidatesOrderHostThenSrflxThenRelay(t *testing.T) {
	in := []types.NetworkCandidateData{
		{Type: types.CandidateTypeRelay, Substrate: types.CandidateSubstrateTCP, Address: "r:1"},
		{Type: "mystery", Substrate: types.CandidateSubstrateTCP, Address: "u:1"},
		{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: "s:2"},
		{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: "s:1"},
		{Type: types.CandidateTypeHost, Substrate: types.CandidateSubstrateTCP, Address: "h:1"},
	}
	got := OrderForDialing(in)
	wantOrder := []string{"h:1", "s:1", "s:2", "r:1", "u:1"}
	if len(got) != len(wantOrder) {
		t.Fatalf("got %d candidates, want %d", len(got), len(wantOrder))
	}
	for i, addr := range wantOrder {
		if got[i].Address != addr {
			t.Errorf("position %d: got %q, want %q", i, got[i].Address, addr)
		}
	}
	// The unknown class survived rather than being dropped.
	if got[len(got)-1].Type != "mystery" {
		t.Errorf("unknown class did not sort last: %q", got[len(got)-1].Type)
	}
	// Input not mutated.
	if in[0].Address != "r:1" {
		t.Error("OrderForDialing mutated its input")
	}
}

// §7.2: PunchDelay never falls below the one-way carrier latency (rtt/2). Since
// d = max(rtt, floor) and d ≥ rtt implies d ≥ rtt/2, the guarantee holds for any
// rtt.
func TestPunchDelayNeverBelowOneWayLatency(t *testing.T) {
	for _, rtt := range []uint64{0, 100, 250, 300, 1000, 5000} {
		d := PunchDelay(rtt)
		if d < rtt/2 {
			t.Errorf("rtt=%d: delay %d < one-way latency %d", rtt, d, rtt/2)
		}
		if rtt <= PunchDelayFloorMs && d != PunchDelayFloorMs {
			t.Errorf("rtt=%d: delay %d, want floor %d", rtt, d, PunchDelayFloorMs)
		}
		if rtt > PunchDelayFloorMs && d != rtt {
			t.Errorf("rtt=%d: delay %d, want rtt", rtt, d)
		}
	}
}

// §4.3: fire_at encodes as a CBOR unsigned integer (major type 0), never a
// signed one. Asserted on the encoded BYTES, not through a decoder.
func TestFireAtEncodesAsCBORUint(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	e, err := types.PunchSyncData{FireAt: 250, Nonce: nonce}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	// Pull the fire_at field's raw CBOR out of the entity data.
	var fields map[string]cbor.RawMessage
	if err := ecf.Decode(e.Data, &fields); err != nil {
		t.Fatalf("decode punch-sync data map: %v", err)
	}
	raw, ok := fields["fire_at"]
	if !ok || len(raw) == 0 {
		t.Fatal("fire_at field absent")
	}
	if major := raw[0] >> 5; major != 0 {
		t.Fatalf("fire_at encoded as CBOR major type %d, want 0 (unsigned integer); bytes=%x", major, raw)
	}
}

// §4.3: a negative fire_at is refused, not clamped. A punch-sync entity carrying
// a negative fire_at fails to decode into the uint64 field, so it classifies as
// Unknown rather than a Sync with a nonsensical value.
func TestNegativeFireAtIsRefusedNotClamped(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	// Hand-build data with fire_at = -1 (CBOR major type 1).
	raw, err := ecf.Encode(map[string]interface{}{"fire_at": -1, "nonce": nonce})
	if err != nil {
		t.Fatal(err)
	}
	e, err := entity.NewEntity(types.TypeSignalingPunchSync, raw)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := ToBlob(e)
	if err != nil {
		t.Fatal(err)
	}
	if got := ClassifyBlob(blob); got.Kind != KindUnknown {
		t.Fatalf("negative fire_at classified as %v, want KindUnknown (refused, not clamped)", got.Kind)
	}
}

// §6.2: a blob round trip preserves the message TYPE. connect-request and
// connect-response differ only by a field name, so classifying by type (not by
// sniffing keys) is what keeps them apart in a mixed bucket.
func TestBlobRoundTripPreservesTheMessageType(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	cands := []types.NetworkCandidateData{
		{Type: types.CandidateTypeHost, Substrate: types.CandidateSubstrateTCP, Address: "10.0.0.1:9000"},
	}

	reqEnt, err := types.ConnectRequestData{Candidates: cands, Initiator: "peer-A", Nonce: nonce}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	respEnt, err := types.ConnectResponseData{Candidates: cands, Nonce: nonce, Responder: "peer-B"}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	reqBlob, err := ToBlob(reqEnt)
	if err != nil {
		t.Fatal(err)
	}
	respBlob, err := ToBlob(respEnt)
	if err != nil {
		t.Fatal(err)
	}

	gotReq := ClassifyBlob(reqBlob)
	if gotReq.Kind != KindConnectRequest || gotReq.Request == nil {
		t.Fatalf("request blob classified as %v, want KindConnectRequest", gotReq.Kind)
	}
	if gotReq.Request.Initiator != "peer-A" || !bytes.Equal(gotReq.Request.Nonce, nonce) {
		t.Errorf("request fields not preserved: %+v", gotReq.Request)
	}
	if len(gotReq.Request.Candidates) != 1 || gotReq.Request.Candidates[0].Address != "10.0.0.1:9000" {
		t.Errorf("request candidate not preserved: %+v", gotReq.Request.Candidates)
	}

	gotResp := ClassifyBlob(respBlob)
	if gotResp.Kind != KindConnectResponse || gotResp.Response == nil {
		t.Fatalf("response blob classified as %v, want KindConnectResponse", gotResp.Kind)
	}
	if gotResp.Response.Responder != "peer-B" {
		t.Errorf("response responder not preserved: %q", gotResp.Response.Responder)
	}
}

// §6.4: an unrecognized blob classifies as Unknown, not an error. A future
// message type this build has never seen is MUST-ignore.
func TestUnrecognizedBlobClassifiesAsUnknownNotAnError(t *testing.T) {
	raw, err := ecf.Encode(map[string]interface{}{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := entity.NewEntity("system/signaling/some-future-message", raw)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := ToBlob(e)
	if err != nil {
		t.Fatal(err)
	}
	if got := ClassifyBlob(blob); got.Kind != KindUnknown {
		t.Fatalf("unknown-type blob classified as %v, want KindUnknown", got.Kind)
	}
	// Garbage that is not even an entity is also Unknown, not a panic/error.
	if got := ClassifyBlob([]byte{0xff, 0x00, 0x13, 0x37}); got.Kind != KindUnknown {
		t.Fatalf("garbage blob classified as %v, want KindUnknown", got.Kind)
	}
}

// §6.4: FindResponse requires the nonce echo AND skips my own peer-id. A shared
// bucket holds other pairs' traffic and my own re-read offers.
func TestFindResponseRequiresNonceEchoAndSkipsSelf(t *testing.T) {
	mine, _ := GenerateNonce()
	other, _ := GenerateNonce()
	cands := []types.NetworkCandidateData{{Type: types.CandidateTypeHost, Substrate: types.CandidateSubstrateTCP, Address: "a:1"}}

	mkResp := func(responder string, nonce []byte) CollectedMessage {
		d := types.ConnectResponseData{Candidates: cands, Nonce: nonce, Responder: responder}
		return CollectedMessage{Kind: KindConnectResponse, Response: &d}
	}

	msgs := []CollectedMessage{
		mkResp("someone-else", other), // wrong nonce
		mkResp("me", mine),            // my nonce but MY id — answering myself
		mkResp("peer-B", mine),        // the real answer
	}
	got, _, ok := FindResponse(msgs, mine, "me")
	if !ok {
		t.Fatal("FindResponse found nothing, want peer-B's response")
	}
	if got.Responder != "peer-B" {
		t.Fatalf("FindResponse returned %q, want peer-B (skipped wrong-nonce and self)", got.Responder)
	}

	// No echo at all → nothing.
	if _, _, ok := FindResponse([]CollectedMessage{mkResp("peer-B", other)}, mine, "me"); ok {
		t.Fatal("FindResponse matched a response with the wrong nonce")
	}
}

// §6.4: FindRequest skips my own offers (collect is non-destructive, so I re-read
// what I wrote).
func TestFindRequestSkipsMyOwn(t *testing.T) {
	nonce, _ := GenerateNonce()
	cands := []types.NetworkCandidateData{{Type: types.CandidateTypeHost, Substrate: types.CandidateSubstrateTCP, Address: "a:1"}}
	mkReq := func(initiator string) CollectedMessage {
		d := types.ConnectRequestData{Candidates: cands, Initiator: initiator, Nonce: nonce}
		return CollectedMessage{Kind: KindConnectRequest, Request: &d}
	}
	msgs := []CollectedMessage{mkReq("me"), mkReq("peer-B")}
	got, _, ok := FindRequest(msgs, "me")
	if !ok || got.Initiator != "peer-B" {
		t.Fatalf("FindRequest returned %v/%q, want peer-B (skipped my own)", ok, initiatorOf(got))
	}
	if _, _, ok := FindRequest([]CollectedMessage{mkReq("me")}, "me"); ok {
		t.Fatal("FindRequest answered my own request")
	}
}

func initiatorOf(r *types.ConnectRequestData) string {
	if r == nil {
		return "<nil>"
	}
	return r.Initiator
}
