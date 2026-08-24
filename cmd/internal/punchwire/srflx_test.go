package punchwire

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	extnetwork "go.entitychurch.org/entity-core-go/ext/network"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// TestSRFLXGathererObservesReflectorMapping is the client half of §6.7.1: the
// gatherer dials a reflector from a REUSEPORT socket, runs observe-address, and
// yields an srflx candidate naming the reflector-observed source — which on
// loopback is exactly the client's own reuseport local socket. It also proves the
// same-socket binding (§7.3): the returned local address IS the srflx address, so
// the punch will dial from the mapping the srflx names.
func TestSRFLXGathererObservesReflectorMapping(t *testing.T) {
	// Reflector: ships the §6.7.1 responder and accepts inbound connections.
	reflector := newPeer(t, "reflector",
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithHandler(extnetwork.HandlerPattern, extnetwork.NewHandler()),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	go func() { _ = reflector.ListenReady(ctx, ready) }()
	<-ready

	// Client: dials the reflector to learn its own public mapping.
	client := newPeer(t, "client")

	gather := SRFLXGatherer(client, reflector.Addr().String(), "")

	gctx, gcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer gcancel()
	local, cands, err := gather(gctx)
	if err != nil {
		if errors.Is(err, signaling.ErrReusePortUnsupported) {
			t.Skip("SO_REUSEPORT not supported on this platform")
		}
		t.Fatalf("SRFLXGatherer: %v", err)
	}

	if local == nil || local.Port == 0 {
		t.Fatalf("gatherer returned no bound local addr: %v", local)
	}

	var srflx string
	for _, c := range cands {
		if c.Type == types.CandidateTypeSrflx {
			if c.Substrate != types.CandidateSubstrateTCP {
				t.Fatalf("srflx substrate %q, want tcp", c.Substrate)
			}
			srflx = c.Address
		}
	}
	if srflx == "" {
		t.Fatalf("no srflx candidate gathered; got %+v", cands)
	}
	// The reflector observes the client's connection source; on loopback that is
	// the client's reuseport local socket, which is exactly `local` — the §7.3
	// same-socket invariant the punch depends on.
	if srflx != local.String() {
		t.Fatalf("srflx candidate %q != reflector-bound local %q (observed source must be the dial socket)", srflx, local.String())
	}
}

// TestSRFLXGathererUnreachableReflectorErrors confirms an unreachable reflector is
// a clean error (→ the §10.3 seam maps it to the relay fallback), never a panic or
// a phantom candidate.
func TestSRFLXGathererUnreachableReflectorErrors(t *testing.T) {
	client := newPeer(t, "client")
	dead := freeAddr(t) // nothing is listening here

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	local, cands, err := SRFLXGatherer(client, dead, "")(ctx)
	if err == nil {
		t.Fatalf("expected an error dialing a dead reflector, got local=%v cands=%+v", local, cands)
	}
	if errors.Is(err, signaling.ErrReusePortUnsupported) {
		t.Skip("SO_REUSEPORT not supported on this platform")
	}
	if local != nil || cands != nil {
		t.Fatalf("failed gather must return no candidates; got local=%v cands=%+v", local, cands)
	}
}

func newPeer(t *testing.T, name string, extra ...peer.Option) *peer.Peer {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("[%s] keypair: %v", name, err)
	}
	opts := append([]peer.Option{
		peer.WithIdentity(kp),
		peer.WithStore(store.NewMemoryContentStore()),
		peer.WithLocationIndex(store.NewMemoryLocationIndex()),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
	}, extra...)
	p, err := peer.New(opts...)
	if err != nil {
		t.Fatalf("[%s] peer.New: %v", name, err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// freeAddr reserves and releases a loopback port, returning an address nothing is
// listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
