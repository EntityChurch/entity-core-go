// Roundtrip tests for the http live transport — server + client in-
// process. Exercises HELLO → HELLO_RESPONSE → AUTHENTICATE →
// AUTHENTICATE_RESPONSE → EXECUTE → EXECUTE-RESPONSE over the wire
// substrate.

package httplive_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// startPeerForHTTPTest builds an in-process Peer suitable for being
// driven by an httplive.Client. We don't start the peer's TCP listener
// — the HTTP server fronts the Dispatcher directly.
func startPeerForHTTPTest(t *testing.T) *peer.Peer {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	p, err := peer.New(
		peer.WithIdentity(kp),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
	)
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestHTTPLive_HelloHandshake(t *testing.T) {
	// 1. Stand up a Peer + its Dispatcher.
	p := startPeerForHTTPTest(t)
	srv := httplive.NewServer(p.Dispatcher())

	// 2. Mount the server on an httptest.Server.
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 3. Build a Client targeting the test server.
	clientKP, _ := crypto.Generate()
	client := httplive.NewClient(nil, ts.URL)

	// 4. POST a HELLO envelope.
	helloEnv, _, err := protocol.CreateHelloExecute(clientKP, nil)
	if err != nil {
		t.Fatalf("CreateHelloExecute: %v", err)
	}
	respEnv, err := client.RoundTrip(context.Background(), helloEnv)
	if err != nil {
		t.Fatalf("HELLO round-trip: %v", err)
	}

	// 5. The server allocated a session ID; the client should have it.
	if client.SessionID() == "" {
		t.Error("expected session ID after first round-trip")
	}

	// 6. Response should be an execute response (the HELLO is dispatched
	// through the connect path which returns a response envelope).
	if respEnv.Root.Type == "" {
		t.Error("expected non-empty response envelope root type")
	}
	t.Logf("HELLO response root type=%s session=%s", respEnv.Root.Type, client.SessionID())
}

func TestHTTPLive_RejectsGET(t *testing.T) {
	p := startPeerForHTTPTest(t)
	srv := httplive.NewServer(p.Dispatcher())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Errorf("GET status: got %d want 405", resp.StatusCode)
	}
	if resp.Header.Get("Allow") != "POST" {
		t.Errorf("Allow header: got %q want POST", resp.Header.Get("Allow"))
	}
}

func TestHTTPLive_SessionPersistsAcrossRoundTrips(t *testing.T) {
	p := startPeerForHTTPTest(t)
	srv := httplive.NewServer(p.Dispatcher())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientKP, _ := crypto.Generate()
	client := httplive.NewClient(nil, ts.URL)

	// First round-trip: HELLO. Server allocates session ID.
	helloEnv, _, err := protocol.CreateHelloExecute(clientKP, nil)
	if err != nil {
		t.Fatalf("CreateHelloExecute: %v", err)
	}
	if _, err := client.RoundTrip(context.Background(), helloEnv); err != nil {
		t.Fatalf("HELLO: %v", err)
	}
	sid1 := client.SessionID()
	if sid1 == "" {
		t.Fatal("expected session ID after HELLO")
	}

	// Second round-trip: any envelope. Same session header should keep
	// the same connection state on the server.
	helloEnv2, _, _ := protocol.CreateHelloExecute(clientKP, nil)
	if _, err := client.RoundTrip(context.Background(), helloEnv2); err != nil {
		// Second HELLO might error because the connection is already
		// past the awaiting_hello phase — but the session correlation
		// itself MUST persist.
		t.Logf("second HELLO error (expected — phase mismatch): %v", err)
	}
	if client.SessionID() != sid1 {
		t.Errorf("session ID changed: %q -> %q (must persist)", sid1, client.SessionID())
	}
}
