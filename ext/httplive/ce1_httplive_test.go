package httplive_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"

	"github.com/fxamacker/cbor/v2"
)

// CE-1 over the HTTP-live transport (arch ROUTING-2026-09-02-h; ENTITY-CORE-PROTOCOL
// 0.8.2.5 note under §4.7 — §4.2 third pre-authorization rule + §5.2a). go fronts the
// SAME Dispatcher over HTTP as over TCP (server.go: "Pass the same Dispatcher the peer
// uses for TCP"), so the pre-establishment auth gate is ONE gate, not the per-transport
// duplicates rust and py each had to fix separately. This proves the single execute.go
// fix reaches the HTTP arm: a non-connect EXECUTE as the FIRST frame of a fresh session
// (its ConnectionState is not Completed) is refused 401 authentication_failed, NOT the
// retired 403 connection_required the 0.8.2.5 note names non-conformant. py flagged the
// HTTP boundary as unreachable by any cohort wire probe, so go proves it here in-tree.
// Mutation: reverting execute.go's non-connect branch to (403, connection_required)
// reddens this exactly as it reddens the TCP-path TestCE1_... test.
func TestHTTPLive_CE1_NonConnectExecuteBeforeEstablishedIs401(t *testing.T) {
	p := startPeerForHTTPTest(t)
	srv := httplive.NewServer(p.Dispatcher())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	client := httplive.NewClient(nil, ts.URL)

	// First frame of the session: a non-connect EXECUTE, no hello — so the
	// server-side ConnectionState is fresh (Completed == false).
	execEnt, err := types.ExecuteData{
		RequestID: "ce1-httplive",
		URI:       "system/tree",
		Operation: "get",
		Params:    cbor.RawMessage(nil),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	respEnv, err := client.RoundTrip(context.Background(), entity.NewEnvelope(execEnt, nil))
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	rd, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatal(err)
	}
	var errEnt entity.Entity
	if err := ecf.Decode(rd.Result, &errEnt); err != nil {
		t.Fatalf("decode error result: %v", err)
	}
	var errData types.ErrorData
	if err := ecf.Decode(errEnt.Data, &errData); err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	if rd.Status != 401 || errData.Code != "authentication_failed" {
		t.Fatalf("pre-establishment EXECUTE over HTTP: got (%d, %q), want (401, authentication_failed)", rd.Status, errData.Code)
	}
}
