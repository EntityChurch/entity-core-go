package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/tree"

	"github.com/fxamacker/cbor/v2"
)

// TestWireHook_ObservesInboundAndOutbound verifies the WithWireHook surface
// per GUIDE-INSPECTABILITY v1.1 §2.1 #7. Fires once per envelope in each
// direction, carries raw frame bytes, populates direction + peer address.
func TestWireHook_ObservesInboundAndOutbound(t *testing.T) {
	var mu sync.Mutex
	var events []WireEvent

	serverKP, _ := crypto.Generate()
	server, err := New(
		WithIdentity(serverKP),
		WithListenAddr("127.0.0.1:0"),
		WithWireHook("test-recorder", func(evt WireEvent) {
			mu.Lock()
			events = append(events, evt)
			mu.Unlock()
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	raw, _ := ecf.Encode(map[string]string{"content": "wire-hook-test"})
	seeded, _ := entity.NewEntity("test/doc", cbor.RawMessage(raw))
	server.Store().Put(seeded)
	server.LocationIndex().Set("system/type/test/doc", seeded.ContentHash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready := make(chan struct{})
	go func() { server.ListenReady(ctx, ready) }()
	<-ready

	clientKP, _ := crypto.Generate()
	client, err := New(WithIdentity(clientKP))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	getReq, getResource, _ := tree.CreateGetRequest("system/type/test/doc", "entity")
	if _, err := conn.Execute(
		ctx,
		"entity://"+string(serverKP.PeerID())+"/system/tree",
		"get",
		getReq,
		getResource,
	); err != nil {
		t.Fatalf("execute: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	var inbound, outbound int
	var sawExecuteFrame bool
	for _, evt := range events {
		switch evt.Direction {
		case WireInbound:
			inbound++
		case WireOutbound:
			outbound++
		}
		if len(evt.FrameBytes) == 0 {
			t.Fatalf("wire event has empty FrameBytes: %+v", evt)
		}
		if evt.Timestamp.IsZero() {
			t.Fatalf("wire event has zero timestamp: %+v", evt)
		}
		if evt.PeerAddress == "" {
			t.Fatalf("wire event has empty PeerAddress: %+v", evt)
		}
		if evt.RootType == "system/protocol/execute" && evt.RequestID != "" {
			sawExecuteFrame = true
		}
	}
	if inbound == 0 {
		t.Fatal("expected at least one inbound wire event (server saw client frames)")
	}
	if outbound == 0 {
		t.Fatal("expected at least one outbound wire event (server wrote responses)")
	}
	if !sawExecuteFrame {
		t.Fatal("expected at least one Execute frame with extracted RequestID — best-effort decode missed it")
	}
}
