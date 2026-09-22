package peer

import (
	"context"
	"testing"
	"time"
)

// TestConnectionDirection is the teeth for workbench-go tracker row 13: a
// connection must expose whether THIS peer originated it, so an application can
// tell "connected (I can dispatch)" from "inbound only (they dialed me)".
// Connections() merges the inbound and pooled-outbound lists and loses this;
// IsConnected conflates it with a reentry binding. IsOutbound()/Direction() are
// the accessor.
//
// Mutation witness: drop the `c.outbound = true` set in PerformConnect and the
// dialer side reports inbound.
func TestConnectionDirection(t *testing.T) {
	dialer := newMultiplexTestPeer(t, 0)
	acceptor := newMultiplexTestPeer(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// The dialer's connection is OUTBOUND — this peer originated it.
	if !conn.IsOutbound() {
		t.Fatal("dialer's connection must report IsOutbound()==true")
	}
	if conn.Direction() != "outbound" {
		t.Fatalf("dialer Direction() = %q, want \"outbound\"", conn.Direction())
	}

	// The acceptor's side of the same connection is INBOUND — they did not dial.
	inbound := acceptorConnFor(t, acceptor, dialer)
	if inbound.IsOutbound() {
		t.Fatal("acceptor's connection must report IsOutbound()==false (they did not dial)")
	}
	if inbound.Direction() != "inbound" {
		t.Fatalf("acceptor Direction() = %q, want \"inbound\"", inbound.Direction())
	}
}
