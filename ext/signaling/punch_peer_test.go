package signaling

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// buildPunchPeer constructs a minimal in-process peer for the punch integration.
// No listener is started: the punch dials peer-to-peer over the punched socket,
// so the initiator drives PerformConnect and the responder ServeConn directly on
// the crossed net.Conn — the peer's own TCP listen address is never used. The
// per-connection serve context is live from peer.New (not Listen), which is why
// ServeConn works here without a listener.
func buildPunchPeer(t *testing.T, name string) *peer.Peer {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("[%s] keypair: %v", name, err)
	}
	p, err := peer.New(
		peer.WithIdentity(kp),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithStore(store.NewMemoryContentStore()),
		peer.WithLocationIndex(store.NewMemoryLocationIndex()),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
	)
	if err != nil {
		t.Fatalf("[%s] peer.New: %v", name, err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// TestPunchPeerLevelIdentityCheckAndPing completes the Stage-2 step-4 proof at
// the PEER level: after the loopback simultaneous-open, the initiator wraps its
// punched conn via ConnectVia + PerformConnect (the §7.4 identity check) and the
// responder serves its side via ServeConn. The initiator MUST end holding the
// EXPECTED peer's id (not merely "some" peer), the connection pools as an
// ordinary transport, and a ping dispatched over it returns a pong — the whole
// §7 punch reduced to a working *peer.Connection.
func TestPunchPeerLevelIdentityCheckAndPing(t *testing.T) {
	a := buildPunchPeer(t, "A")
	b := buildPunchPeer(t, "B")
	aID := a.PeerID().String()
	bID := b.PeerID().String()

	carrier := newMemCarrier()
	key := make([]byte, 33)
	aAddr := freeLoopbackPort(t)
	bAddr := freeLoopbackPort(t)

	mkParty := func(self string, local *net.TCPAddr) *PunchParty {
		return &PunchParty{
			Carrier: carrier,
			Key:     key,
			SelfID:  self,
			LocalCands: []types.NetworkCandidateData{
				{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: local.String()},
			},
			LocalAddr:       local,
			Poll:            20 * time.Millisecond,
			CrossingRetries: 40,
			DialTimeout:     300 * time.Millisecond,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Responder side runs concurrently: punch back, then serve the crossed conn
	// as a server so the initiator's PerformConnect completes.
	bErr := make(chan error, 1)
	go func() {
		raw, initiator, err := mkParty(bID, bAddr).Respond(ctx)
		if err != nil {
			bErr <- fmt.Errorf("respond: %w", err)
			return
		}
		if initiator != aID {
			bErr <- fmt.Errorf("responder saw initiator %q, want %q", initiator, aID)
			return
		}
		b.ServeConn(raw) // server-side handshake over the punched conn
		bErr <- nil
	}()

	// Initiator side: punch, wrap, handshake, identity-check.
	raw, err := mkParty(aID, aAddr).Initiate(ctx, bID)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	conn := a.ConnectVia(raw)
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("PerformConnect over punched conn: %v", err)
	}

	// §7.4: the punched path is the EXPECTED peer, proven by the handshake.
	if got := conn.Session().RemotePeerID.String(); got != bID {
		t.Fatalf("punched conn authenticated as %q, want expected peer %q", got, bID)
	}
	if err := <-bErr; err != nil {
		t.Fatalf("responder: %v", err)
	}

	// §10.3 obligation 1: pool it as an ordinary transport (also validates the
	// session is established), then dispatch a ping over the pooled connection.
	if _, err := a.AddRemoteConnection(b.PeerID(), conn); err != nil {
		t.Fatalf("pool punched conn: %v", err)
	}
	ping, err := types.PingData{Timestamp: 1709740800000, Sequence: 7}.ToEntity()
	if err != nil {
		t.Fatalf("build ping: %v", err)
	}
	resp, err := a.RemoteExecute(ctx, fmt.Sprintf("entity://%s/system/protocol/connect", bID), "ping", ping, nil)
	if err != nil {
		t.Fatalf("ping over punched conn: %v", err)
	}
	if resp.Status != 200 || resp.Result.Type != types.TypeNetworkPong {
		t.Fatalf("ping response: status=%d type=%q, want 200 / %s", resp.Status, resp.Result.Type, types.TypeNetworkPong)
	}
}
