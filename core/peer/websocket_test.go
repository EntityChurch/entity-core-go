// WebSocket substrate test — two peers communicate over the §6.5.2b
// WS profile using the same handshake + tree:put path TCP uses. Proves
// the V7 §6.5.2c L864 framing-reuse blessing ("one §1.6 length-prefixed
// envelope per binary WS message") works end-to-end through the
// existing core/peer machinery.

package peer

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// startWSPeerForTest builds a peer that listens on a ws:// endpoint and
// returns the peer + its ws URL + a teardown.
func startWSPeerForTest(t *testing.T, name string) (*Peer, crypto.Keypair, string, func()) {
	t.Helper()

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("[%s] keypair: %v", name, err)
	}
	p, err := New(
		WithIdentity(kp),
		WithConnectionGrants(OpenAccessGrants()),
		WithHandler("system/tree", tree.NewHandler()),
	)
	if err != nil {
		t.Fatalf("[%s] peer.New: %v", name, err)
	}
	identity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("[%s] identity: %v", name, err)
	}
	if _, err := p.Store().Put(identity); err != nil {
		t.Fatalf("[%s] put identity: %v", name, err)
	}

	// Bind to an ephemeral port first so the URL is known.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("[%s] reserve port: %v", name, err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go func() {
		_ = p.ListenWebSocketReady(ctx, addr, "/ws", ready)
	}()
	<-ready
	// Small delay so the http.Server's Serve loop is actually accepting.
	time.Sleep(50 * time.Millisecond)

	url := fmt.Sprintf("ws://%s/ws", addr)
	teardown := func() {
		cancel()
		_ = p.Close()
	}
	return p, kp, url, teardown
}

// TestWebSocket_TreePutRoundTrip proves the WS substrate carries
// HELLO → AUTHENTICATE → EXECUTE end-to-end, with the result landing
// in the destination peer's tree byte-identical to TCP.
func TestWebSocket_TreePutRoundTrip(t *testing.T) {
	a, _, _, aDown := startWSPeerForTest(t, "A")
	defer aDown()
	b, bKP, bURL, bDown := startWSPeerForTest(t, "B")
	defer bDown()

	if err := a.RegisterRemoteWS(bKP.PeerID(), bURL); err != nil {
		t.Fatalf("A.RegisterRemoteWS(B): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Probe op to drive the handshake.
	probeGetReq, probeGetRes, err := tree.CreateGetRequest("system/handler/system/tree", "entity")
	if err != nil {
		t.Fatalf("CreateGetRequest: %v", err)
	}
	if _, err := a.RemoteExecute(ctx, "entity://"+string(bKP.PeerID())+"/system/tree", "get", probeGetReq, probeGetRes); err != nil {
		t.Fatalf("probe RemoteExecute over WS: %v", err)
	}

	// Issue a put with a real payload entity through the dispatcher.
	const dataTreePath = "local/ws-roundtrip/marker"
	payload, err := entity.NewEntity("test/ws-payload", []byte{0xA1, 0x01, 0x05}) // {1: 5}
	if err != nil {
		t.Fatalf("payload NewEntity: %v", err)
	}
	if _, err := a.Store().Put(payload); err != nil {
		t.Fatalf("A.Store().Put(payload): %v", err)
	}
	putReq, putRes, err := tree.CreatePutRequest(dataTreePath, &payload)
	if err != nil {
		t.Fatalf("CreatePutRequest: %v", err)
	}
	if _, err := a.RemoteExecute(ctx, "entity://"+string(bKP.PeerID())+"/system/tree", "put", putReq, putRes); err != nil {
		t.Fatalf("RemoteExecute put over WS: %v", err)
	}

	// Verify B bound the path.
	bTreePath := "/" + string(bKP.PeerID()) + "/" + dataTreePath
	bound := false
	for attempt := 0; attempt < 20; attempt++ {
		if _, ok := b.LocationIndex().Get(bTreePath); ok {
			bound = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bound {
		t.Fatalf("B's tree did not bind %s after WS RemoteExecute (substrate did not carry the EXECUTE end-to-end)", bTreePath)
	}
}

// TestWebSocket_TransportProfileRoundTrip exercises RegisterRemoteWS +
// resolveTransportTarget to confirm the WS profile is stored, decoded,
// and selected when no other transport is registered.
func TestWebSocket_TransportProfileRoundTrip(t *testing.T) {
	a, _, _, aDown := startWSPeerForTest(t, "A")
	defer aDown()
	_, bKP, bURL, bDown := startWSPeerForTest(t, "B")
	defer bDown()

	if err := a.RegisterRemoteWS(bKP.PeerID(), bURL); err != nil {
		t.Fatalf("RegisterRemoteWS: %v", err)
	}

	// Resolve should pick the WS profile.
	tgt, err := a.resolveTransportTarget(bKP.PeerID())
	if err != nil {
		t.Fatalf("resolveTransportTarget: %v", err)
	}
	if tgt.typeURI != types.TypePeerTransportWebSocket {
		t.Fatalf("resolved transport type = %q, want %q", tgt.typeURI, types.TypePeerTransportWebSocket)
	}
	if tgt.endpoint != bURL {
		t.Fatalf("resolved endpoint = %q, want %q", tgt.endpoint, bURL)
	}
}
