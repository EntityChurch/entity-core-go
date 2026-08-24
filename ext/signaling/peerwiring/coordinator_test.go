package peerwiring

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// memCarrier is an in-memory rendezvous store (the §4 node is an opaque blob
// store); collect is non-destructive and returns every blob including the
// caller's own, matching the real node.
type memCarrier struct {
	mu      sync.Mutex
	buckets map[string][][]byte
}

func newMemCarrier() *memCarrier { return &memCarrier{buckets: make(map[string][][]byte)} }

func (m *memCarrier) Offer(_ context.Context, key, message []byte) (uint, error) {
	m.mu.Lock()
	m.buckets[string(key)] = append(m.buckets[string(key)], append([]byte(nil), message...))
	m.mu.Unlock()
	return 200, nil
}

// CollectMessagesVerified runs the real §6.4 read path over the stored bytes,
// keyed by the bucket they are filed under — the stub stores blobs and verifies
// nothing itself, exactly like the node it stands in for (§4.4).
func (m *memCarrier) CollectMessagesVerified(_ context.Context, key []byte) (uint, []signaling.CollectedMessage, []error, error) {
	m.mu.Lock()
	blobs := append([][]byte(nil), m.buckets[string(key)]...)
	m.mu.Unlock()
	msgs := make([]signaling.CollectedMessage, 0, len(blobs))
	var skipped []error
	for _, b := range blobs {
		msg, err := signaling.ClassifyCollected(b, key)
		if err != nil {
			skipped = append(skipped, err)
			continue
		}
		msgs = append(msgs, msg)
	}
	return 200, msgs, skipped, nil
}

func buildPeer(t *testing.T, name string) *peer.Peer {
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

func freePort(t *testing.T) *net.TCPAddr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	a := l.Addr().(*net.TCPAddr)
	l.Close()
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: a.Port}
}

// gatherFor returns a fixed GatherFunc advertising addr as this peer's srflx and
// binding it for the punch (loopback: no NAT, so srflx == the local bind).
func gatherFor(addr *net.TCPAddr) GatherFunc {
	return func(context.Context) (*net.TCPAddr, []types.NetworkCandidateData, error) {
		return addr, []types.NetworkCandidateData{
			{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: addr.String()},
		}, nil
	}
}

func fastOpts() []Option {
	return []Option{
		WithPoll(20 * time.Millisecond),
		WithCrossingRetries(40),
		WithDialTimeout(300 * time.Millisecond),
		WithExchangeTimeout(10 * time.Second),
	}
}

func pingURI(target *peer.Peer) string {
	return fmt.Sprintf("entity://%s/system/protocol/connect", target.PeerID())
}

func mustPing(t *testing.T) entity.Entity {
	t.Helper()
	e, err := types.PingData{Timestamp: 1709740800000, Sequence: 7}.ToEntity()
	if err != nil {
		t.Fatalf("build ping: %v", err)
	}
	return e
}

// TestCoordinatorEstablishThroughSeam is the real §10.3 integration: A holds no
// durable profile for B, so a RemoteExecute falls to the live-establishment seam,
// which runs the punch coordinator end to end — exchange over an in-memory
// carrier, direct-path establishment, PerformConnect + §7.4 identity check — and
// the dispatch lands a pong over the punched, pooled connection. B stays reachable
// via a background responder loop on the shared pair key.
func TestCoordinatorEstablishThroughSeam(t *testing.T) {
	a := buildPeer(t, "A")
	b := buildPeer(t, "B")

	carrier := newMemCarrier()
	carrierFn := func(context.Context, []byte) (signaling.Carrier, error) { return carrier, nil }

	coordA := New(a, gatherFor(freePort(t)), carrierFn, nil, fastOpts()...)
	coordB := New(b, gatherFor(freePort(t)), carrierFn, nil, fastOpts()...)

	a.SetLiveEstablish(coordA.Establish)

	// B stays reachable: loop the responder on the pair key both sides derive.
	key, err := signaling.PairKey(a.PeerID().String(), b.PeerID().String())
	if err != nil {
		t.Fatalf("pair key: %v", err)
	}
	respCtx, stopResponder := context.WithCancel(context.Background())
	defer stopResponder()
	go coordB.RunResponder(respCtx, key)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := a.RemoteExecute(ctx, pingURI(b), "ping", mustPing(t), nil)
	if err != nil {
		t.Fatalf("dispatch via punch seam: %v", err)
	}
	if resp.Status != 200 || resp.Result.Type != types.TypeNetworkPong {
		t.Fatalf("ping via punched conn: status=%d type=%q, want 200 / %s", resp.Status, resp.Result.Type, types.TypeNetworkPong)
	}

	// §10.3 obligation 1: the punched connection was pooled — a second dispatch
	// reuses it (the seam is not consulted again; the pool serves it).
	if _, err := a.RemoteExecute(ctx, pingURI(b), "ping", mustPing(t), nil); err != nil {
		t.Fatalf("second dispatch (should reuse pooled punched conn): %v", err)
	}
}

// TestEnsureConnectedPunchesUnderCallerOwnedRetry is rung 4's happy path: the §4.1
// EnsureConnected seam drives the punch with caller-owned retry (a single carrier
// exchange), and on loopback the punch lands and pools the connection — so a
// maintain-peer reconnect reaches a NAT'd peer without nesting the §7.2 exchange
// budget under §4.1's backoff.
func TestEnsureConnectedPunchesUnderCallerOwnedRetry(t *testing.T) {
	a := buildPeer(t, "A")
	b := buildPeer(t, "B")

	carrier := newMemCarrier()
	carrierFn := func(context.Context, []byte) (signaling.Carrier, error) { return carrier, nil }

	coordA := New(a, gatherFor(freePort(t)), carrierFn, nil, fastOpts()...)
	coordB := New(b, gatherFor(freePort(t)), carrierFn, nil, fastOpts()...)
	a.SetLiveEstablish(coordA.Establish)

	key, err := signaling.PairKey(a.PeerID().String(), b.PeerID().String())
	if err != nil {
		t.Fatalf("pair key: %v", err)
	}
	respCtx, stopResponder := context.WithCancel(context.Background())
	defer stopResponder()
	go coordB.RunResponder(respCtx, key)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := a.EnsureConnected(ctx, b.PeerID()); err != nil {
		t.Fatalf("EnsureConnected via the §4.1 punch seam: %v", err)
	}
	if !a.IsConnected(b.PeerID()) {
		t.Fatal("expected b pooled after the reconnect-driven punch")
	}
}

// TestEnsureConnectedFailedPunchMemoizesPreferRelay is rung 4's give-up path: a
// punch driven by EnsureConnected that cannot complete (nobody answers) runs the
// seam exactly once under caller-owned retry, then the session-local prefer-relay
// memo short-circuits the seam on the next reconnect — so the §4.1 backoff loop
// stops re-punching an untraversable peer and lets relay carry it.
func TestEnsureConnectedFailedPunchMemoizesPreferRelay(t *testing.T) {
	a := buildPeer(t, "A")
	bKP, _ := crypto.Generate()
	bID := crypto.PeerID(bKP.PeerID())

	carrier := newMemCarrier() // no responder → the punch times out
	carrierFn := func(context.Context, []byte) (signaling.Carrier, error) { return carrier, nil }
	coordA := New(a, gatherFor(freePort(t)), carrierFn, nil,
		WithPoll(20*time.Millisecond), WithCrossingRetries(3),
		WithDialTimeout(200*time.Millisecond), WithExchangeTimeout(500*time.Millisecond))

	var seamCalls int32
	var sawCallerOwned atomic.Bool
	a.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*peer.Connection, error) {
		atomic.AddInt32(&seamCalls, 1)
		sawCallerOwned.Store(peer.CallerOwnsRetry(ctx))
		return coordA.Establish(ctx, peerID)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First reconnect: the seam runs the doomed punch once, under caller-owned retry.
	if err := a.EnsureConnected(ctx, bID); err == nil {
		t.Fatal("expected failure — nobody answers the punch")
	}
	if got := atomic.LoadInt32(&seamCalls); got != 1 {
		t.Fatalf("seam consulted %d times, want 1", got)
	}
	if !sawCallerOwned.Load() {
		t.Fatal("seam did not observe caller-owned retry (§7.2 × §4.1 would nest)")
	}

	// Second reconnect: prefer-relay memo skips the seam entirely.
	if err := a.EnsureConnected(ctx, bID); err == nil {
		t.Fatal("expected failure (still unreachable)")
	}
	if got := atomic.LoadInt32(&seamCalls); got != 1 {
		t.Fatalf("seam re-consulted despite prefer-relay memo: %d, want 1", got)
	}
}

// TestCoordinatorFailedPunchFallsThroughToFallback is Stage-2 step 6: when the
// punch cannot complete (here: nobody answers on the carrier, so Initiate times
// out), Establish returns an error, which the §10.3 seam treats as "no live path"
// and the ladder falls through to §10.2 dispatch_fallback — never a hard failure.
func TestCoordinatorFailedPunchFallsThroughToFallback(t *testing.T) {
	a := buildPeer(t, "A")
	bKP, _ := crypto.Generate()
	bID := crypto.PeerID(bKP.PeerID())

	carrier := newMemCarrier() // no responder → Initiate never gets a response
	carrierFn := func(context.Context, []byte) (signaling.Carrier, error) { return carrier, nil }

	// Short exchange timeout so the doomed punch abandons quickly.
	coordA := New(a, gatherFor(freePort(t)), carrierFn, nil,
		WithPoll(20*time.Millisecond), WithCrossingRetries(3),
		WithDialTimeout(200*time.Millisecond), WithExchangeTimeout(500*time.Millisecond))
	a.SetLiveEstablish(coordA.Establish)

	var fallbackCalls int32
	a.SetDispatchFallback(func(ctx context.Context, peerID crypto.PeerID, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (*handler.Response, bool, error) {
		atomic.AddInt32(&fallbackCalls, 1)
		if peerID != bID {
			return nil, false, fmt.Errorf("unexpected peer %s", peerID)
		}
		return &handler.Response{Status: 202}, true, nil // store-and-forward stand-in
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := a.RemoteExecute(ctx, fmt.Sprintf("entity://%s/system/protocol/connect", bID), "ping", mustPing(t), nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 202 {
		t.Fatalf("expected the fallback's 202 after the punch abandoned, got %d", resp.Status)
	}
	if n := atomic.LoadInt32(&fallbackCalls); n != 1 {
		t.Fatalf("dispatch_fallback consulted %d times, want 1 (failed punch → fall through)", n)
	}
}
