package peer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/tree"
)

// EXTENSION-NETWORK §10.3 obligation 5 — single-flight establishment per peer.
//
// The obligation is the FAN-IN face of the bounded-third-party-load invariant
// obligation 4 states on the RETRY face: obligation 4 explicitly grants each
// standalone §10 dispatch its own exchange budget, so N concurrent dispatches
// are N individually-conformant establishments whose SUM is the multiplicative
// load on the shared carrier/reflector the discipline exists to prevent.
//
// Found by entity-browser-rust on the WebRTC leg (~470 deposits/side at ~29 s
// vs 4/side at ~1 s under single-flight) and folded as a general MUST every
// implementation inherits. Go's crossing is TCP simultaneous-open rather than
// ICE, but the coordination deposits the obligation counts land on the same
// shared rendezvous node either way, so the obligation binds here identically.
//
// These vectors pin the fan-in axis. The retry axis is pinned separately in
// reconnect_seam_test.go (caller-owned retry + the prefer-relay memo).

// TestEstablishmentIsSingleFlightPerPeer is the obligation-5 headline: N
// concurrent triggers to the same unpooled peer consult the live-establishment
// seam EXACTLY ONCE. Without the gate this is N coordination exchanges against
// the shared node — every one of them individually conformant, which is why
// obligation 4 never caught it.
func TestEstablishmentIsSingleFlightPerPeer(t *testing.T) {
	p := startPeer(t)

	kp, _ := crypto.Generate()
	target := crypto.PeerID(kp.PeerID()) // no transport profile → plain dial fails

	const waves = 32
	var seamCalls int32
	release := make(chan struct{})
	p.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		atomic.AddInt32(&seamCalls, 1)
		// Hold the establishment open so every caller is provably concurrent
		// with it — a serial run would trivially "coalesce" by finishing first.
		<-release
		return nil, errors.New("punch declined (test)")
	})

	var wg sync.WaitGroup
	errs := make([]error, waves)
	for i := range waves {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = p.EnsureConnected(context.Background(), target)
		}()
	}

	// Let all the callers pile in, then let the one leader finish.
	waitFor(t, func() bool { return p.dialGateDepth(target) }, "no establishment ever entered the gate")
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&seamCalls); got != 1 {
		t.Fatalf("seam consulted %d times for %d concurrent triggers, want exactly 1 (§10.3 obligation 5: concurrent triggers MUST coalesce onto the one in-flight establishment)", got, waves)
	}
	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d reported success though the establishment failed", i)
		}
	}
}

// TestSingleFlightWaitersShareTheLeadersConnection proves coalescing AWAITS THE
// RESULT rather than merely suppressing the duplicate work: every waiter comes
// back with the leader's connection, and the pool holds exactly one.
func TestSingleFlightWaitersShareTheLeadersConnection(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t) // deliberately NO WithRemotePeer: no profile, so the dial misses and the seam runs

	var seamCalls int32
	release := make(chan struct{})
	client.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		atomic.AddInt32(&seamCalls, 1)
		<-release
		// Stand in for a punched path: an ordinary connection the seam hands
		// back for the ladder to pool (§10.3 obligations 1 and 2).
		conn, err := client.Connect(ctx, server.Addr().String())
		if err != nil {
			return nil, err
		}
		if err := conn.PerformConnect(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	})

	const waves = 16
	var wg sync.WaitGroup
	errs := make([]error, waves)
	for i := range waves {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = client.EnsureConnected(context.Background(), server.PeerID())
		}()
	}
	waitFor(t, func() bool { return client.dialGateDepth(server.PeerID()) }, "no establishment ever entered the gate")
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&seamCalls); got != 1 {
		t.Fatalf("seam consulted %d times, want exactly 1", got)
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("waiter %d did not receive the leader's connection: %v", i, err)
		}
	}
	client.remote.mu.Lock()
	pooled := len(client.remote.conns)
	client.remote.mu.Unlock()
	if pooled != 1 {
		t.Fatalf("pool holds %d connections after a coalesced wave, want 1 (each waiter must reuse the leader's, never establish its own)", pooled)
	}
}

// TestSingleFlightGateClearsAfterTheWave pins the two properties a naive gate
// gets wrong: the map entry is dropped when the leader publishes (bounded
// memory — rust's DialGuard GC, which Go gets by dropping the entry and letting
// waiters hold the gate pointer), and a FAILED establishment does not wedge the
// peer — the next trigger establishes fresh rather than inheriting a stale
// error forever.
func TestSingleFlightGateClearsAfterTheWave(t *testing.T) {
	p := startPeer(t)

	kp, _ := crypto.Generate()
	target := crypto.PeerID(kp.PeerID())

	var seamCalls int32
	p.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		atomic.AddInt32(&seamCalls, 1)
		return nil, errors.New("punch declined (test)")
	})

	if err := p.EnsureConnected(context.Background(), target); err == nil {
		t.Fatal("expected an error from a declined punch")
	}
	p.remote.mu.Lock()
	inFlight := len(p.remote.dialing)
	p.remote.mu.Unlock()
	if inFlight != 0 {
		t.Fatalf("gate map holds %d entries after the establishment finished, want 0 (unbounded growth)", inFlight)
	}

	// The memo short-circuits the seam on the reconnect path, so clear it to
	// isolate what is under test here: that the GATE re-arms.
	p.clearPreferRelay(target)
	if err := p.EnsureConnected(context.Background(), target); err == nil {
		t.Fatal("expected an error on the second attempt too")
	}
	if got := atomic.LoadInt32(&seamCalls); got != 2 {
		t.Fatalf("seam consulted %d times across two sequential waves, want 2 — a failed establishment must not wedge the peer", got)
	}
}

// TestSingleFlightIsPerPeerNotGlobal guards the obvious over-correction: a
// single global dial lock would satisfy every count above and serialize the
// whole peer. Two establishments to DIFFERENT peers must be able to run at the
// same instant — the seam here refuses to return until both have arrived, so a
// global gate deadlocks and this test times out rather than passing quietly.
func TestSingleFlightIsPerPeerNotGlobal(t *testing.T) {
	p := startPeer(t)

	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	targetA := crypto.PeerID(kpA.PeerID())
	targetB := crypto.PeerID(kpB.PeerID())

	var both sync.WaitGroup
	both.Add(2)
	p.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		both.Done()
		both.Wait() // only returns once BOTH peers are in flight together
		return nil, errors.New("punch declined (test)")
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for _, target := range []crypto.PeerID{targetA, targetB} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.EnsureConnected(context.Background(), target)
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("establishments to two different peers did not overlap — the gate is global, not per-peer")
	}
}

// TestDispatchFanInCoalescesOntoOneSeamConsult runs the same fan-in through the
// path §10.3 obligation 5 actually names — "every §10-step-1 pool-miss, every
// dispatch that finds no live connection" — rather than only the §4.1
// maintain-peer entry. Both funnel through establishRemote; this pins that they
// do, so a later refactor cannot restore the seam consult to the call site.
func TestDispatchFanInCoalescesOntoOneSeamConsult(t *testing.T) {
	p := startPeer(t)

	kp, _ := crypto.Generate()
	target := crypto.PeerID(kp.PeerID())

	const waves = 16
	var seamCalls int32
	release := make(chan struct{})
	p.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		atomic.AddInt32(&seamCalls, 1)
		<-release
		return nil, errors.New("punch declined (test)")
	})

	uri := "entity://" + string(target) + "/system/tree"
	req, resource, _ := tree.CreateGetRequest("test/doc", "entity")
	var wg sync.WaitGroup
	for range waves {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.RemoteExecute(context.Background(), uri, "get", req, resource)
		}()
	}
	waitFor(t, func() bool { return p.dialGateDepth(target) }, "no dispatch ever entered the gate")
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&seamCalls); got != 1 {
		t.Fatalf("seam consulted %d times for %d concurrent dispatches, want exactly 1", got, waves)
	}
}

// TestReentryOriginationBypassesTheGate is the no-regression vector for the
// deliberate carve-out: §6.11 reentry reuse establishes nothing — it hands back
// a connection the COUNTERPART dialed — so it stays outside the gate. Inside
// it, the bounded §6.5 (b) grant wait would serialize concurrent originations
// to the same peer at N × the wait, for no third-party-load benefit at all.
func TestReentryOriginationBypassesTheGate(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t, WithRemotePeer(server.PeerID(), server.Addr().String()))

	// Drive one dispatch so the server holds an inbound connection from the
	// client and can originate back through it with no profile of its own.
	uri := "entity://" + string(server.PeerID()) + "/system/tree"
	req, resource, _ := tree.CreateGetRequest("test/doc", "entity")
	if _, err := client.RemoteExecute(context.Background(), uri, "get", req, resource); err != nil {
		t.Logf("priming dispatch returned %v (only the connection matters here)", err)
	}
	waitFor(t, func() bool { return server.inboundForReentry(client.PeerID()) != nil }, "server never registered the inbound connection for §6.11 reentry")

	// The reentry endpoint resolves without ever entering the gate.
	conn := server.reentryEndpoint(context.Background(), client.PeerID())
	if conn == nil {
		t.Fatal("reentry endpoint not resolvable")
	}
	server.remote.mu.Lock()
	inFlight := len(server.remote.dialing)
	server.remote.mu.Unlock()
	if inFlight != 0 {
		t.Fatalf("reentry reuse took the establishment gate (%d entries) — it establishes nothing and must not serialize", inFlight)
	}
}

// dialGateDepth reports whether an establishment to peerID is currently in
// flight. Test-only observation of the obligation-5 gate.
func (p *Peer) dialGateDepth(peerID crypto.PeerID) bool {
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	_, ok := p.remote.dialing[peerID]
	return ok
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}
