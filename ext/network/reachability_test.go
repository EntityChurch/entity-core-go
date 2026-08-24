package network

// Live Go↔Go vectors for EXTENSION-NETWORK §6.7 reachability facts
// (Amendment 13). observe-address / check-reachability need a REAL accepted
// connection so the responder sees the initiator's transport source — these
// drive peer A → peer B over TCP (not selfExecute), which is the whole point:
// the fact rides from the accepted connection, never the request body.
//
// The §6.7.5 gate — a real cross-NAT dial-back proving reachable=true, and a
// cross-IMPL reflect — is out of scope here (no NAT in a unit test, no sibling
// peer); these lock the wire shape, the two security MUSTs, and the §6.7.4
// grant posture. reachable=true is the cross-NAT gate by construction.

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// reachEmptyParams builds the no-input params entity observe-address /
// check-reachability take (the fact rides from the connection, not the body).
func reachEmptyParams(t *testing.T) entity.Entity {
	t.Helper()
	e, err := entity.NewEntity("primitive/any", cbor.RawMessage{0xa0}) // CBOR empty map
	if err != nil {
		t.Fatalf("build empty params: %v", err)
	}
	return e
}

// bogusAddrParams builds a params entity carrying a body-supplied address —
// the value a conformant handler MUST ignore (§6.7.1 MUST 1 / §6.7.2 MUST).
// If the handler ever echoed the body, the tests would see this address.
const bogusBodyAddr = "6.6.6.6:6666"

func bogusAddrParams(t *testing.T) entity.Entity {
	t.Helper()
	return mustEntity(t, types.ObserveAddressResultData{ObservedAddress: bogusBodyAddr})
}

// startDefaultGrantPeer builds a listening peer wired with ONLY the network
// handler and the §4.4 DefaultConnectionGrants (observe-address broad,
// check-reachability withheld) — the posture under test in §6.7.4. Lighter
// than startLifecyclePeer: the reachability ops need no reactive stack.
func startDefaultGrantPeer(t *testing.T, kp crypto.Keypair) *lifecyclePeer {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	networkH := NewHandler()
	p, err := peer.New(
		peer.WithIdentity(kp),
		peer.WithStore(cs),
		peer.WithLocationIndex(li),
		peer.WithListenAddr("127.0.0.1:0"),
		// No WithConnectionGrants → DefaultConnectionGrants() (§4.4).
		peer.WithHandler(HandlerPattern, networkH),
	)
	if err != nil {
		t.Fatal(err)
	}
	networkH.Bind(p)
	listenCtx, cancelListen := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go func() { p.ListenReady(listenCtx, ready) }()
	<-ready
	lp := &lifecyclePeer{p: p, h: networkH}
	lp.stop = func() {
		if lp.stopped {
			return
		}
		lp.stopped = true
		cancelListen()
		p.Close()
	}
	t.Cleanup(lp.stop)
	return lp
}

func networkURI(lp *lifecyclePeer) string {
	return fmt.Sprintf("entity://%s/system/network", lp.p.PeerID())
}

// dialLink registers b's TCP profile on a so a.RemoteExecute can resolve and
// dial it (the §10 profile-resolution path RemoteExecute walks). The observed
// source is still a's ephemeral client socket — registering b's profile does
// not change what b observes.
func dialLink(t *testing.T, a, b *lifecyclePeer) {
	t.Helper()
	if err := a.p.RegisterRemote(b.p.PeerID(), b.p.Addr().String()); err != nil {
		t.Fatalf("register remote profile: %v", err)
	}
}

// TestObserveAddressReflectsTransportSource: B reflects the transport source of
// A's connection — a real 127.0.0.1:<ephemeral> that is neither empty nor B's
// own listen address (§6.7.1).
func TestObserveAddressReflectsTransportSource(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startLifecyclePeer(t, kpB, "127.0.0.1:0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialLink(t, a, b)
	resp, err := a.p.RemoteExecute(ctx, networkURI(b), "observe-address", reachEmptyParams(t), nil)
	if err != nil {
		t.Fatalf("observe-address: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("observe-address status = %d, want 200", resp.Status)
	}
	if resp.Result.Type != types.TypeNetworkObserveAddressResult {
		t.Fatalf("result type = %q, want %q", resp.Result.Type, types.TypeNetworkObserveAddressResult)
	}
	res, err := types.ObserveAddressResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode observe-address-result: %v", err)
	}
	host, port, err := net.SplitHostPort(res.ObservedAddress)
	if err != nil {
		t.Fatalf("observed_address %q not host:port: %v", res.ObservedAddress, err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("observed host = %q, want 127.0.0.1", host)
	}
	if port == "" || port == "0" {
		t.Fatalf("observed port = %q, want a real ephemeral port", port)
	}
	if res.ObservedAddress == b.p.Addr().String() {
		t.Fatalf("observed_address is B's own listen addr %q — must be A's source", res.ObservedAddress)
	}
}

// TestObserveAddressIgnoresBodyAddress: a body-supplied address is never
// echoed (§6.7.1 MUST 1 — the anti-laundering seam).
func TestObserveAddressIgnoresBodyAddress(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startLifecyclePeer(t, kpB, "127.0.0.1:0", nil)
	_ = b

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialLink(t, a, b)
	resp, err := a.p.RemoteExecute(ctx, networkURI(b), "observe-address", bogusAddrParams(t), nil)
	if err != nil {
		t.Fatalf("observe-address: %v", err)
	}
	res, err := types.ObserveAddressResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.ObservedAddress == bogusBodyAddr {
		t.Fatalf("observed_address echoed the body-supplied %q — §6.7.1 MUST 1 violation", bogusBodyAddr)
	}
	if host, _, _ := net.SplitHostPort(res.ObservedAddress); host != "127.0.0.1" {
		t.Fatalf("observed host = %q, want the real transport source 127.0.0.1", host)
	}
}

// TestCheckReachabilityDialsObservedNotBody: dial-back targets A's OWN observed
// source, never a body-supplied address (§6.7.2 anti-reflector MUST). An
// ephemeral client port is not listening, so reachable is false — the honest
// local result; reachable=true is the cross-NAT §6.7.5 gate.
func TestCheckReachabilityDialsObservedNotBody(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startLifecyclePeer(t, kpB, "127.0.0.1:0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialLink(t, a, b)
	resp, err := a.p.RemoteExecute(ctx, networkURI(b), "check-reachability", bogusAddrParams(t), nil)
	if err != nil {
		t.Fatalf("check-reachability: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("check-reachability status = %d, want 200", resp.Status)
	}
	res, err := types.CheckReachabilityResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode check-reachability-result: %v", err)
	}
	if res.AddressTested == bogusBodyAddr {
		t.Fatalf("dialed the body-supplied %q — §6.7.2 anti-reflector MUST violation", bogusBodyAddr)
	}
	if host, _, err := net.SplitHostPort(res.AddressTested); err != nil || host != "127.0.0.1" {
		t.Fatalf("address_tested = %q, want A's real source 127.0.0.1:<port>", res.AddressTested)
	}
	if res.Reachable {
		t.Fatalf("reachable = true for an ephemeral non-listening client port; expected false")
	}
}

// TestReachabilityDefaultGrantPosture: under §4.4 DefaultConnectionGrants,
// observe-address is granted (network-reflect broad) and check-reachability is
// denied 403 (network-dialback restricted) — the §6.7.4 security asymmetry.
func TestReachabilityDefaultGrantPosture(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startDefaultGrantPeer(t, kpB)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// observe-address: broad default grant → 200.
	dialLink(t, a, b)
	obs, err := a.p.RemoteExecute(ctx, networkURI(b), "observe-address", reachEmptyParams(t), nil)
	if err != nil {
		t.Fatalf("observe-address: %v", err)
	}
	if obs.Status != 200 {
		t.Fatalf("observe-address under default grants = %d, want 200 (network-reflect is broad)", obs.Status)
	}

	// check-reachability: NOT in the default grant → 403.
	chk, err := a.p.RemoteExecute(ctx, networkURI(b), "check-reachability", reachEmptyParams(t), nil)
	if err != nil {
		t.Fatalf("check-reachability dispatch: %v", err)
	}
	if chk.Status != 403 {
		t.Fatalf("check-reachability under default grants = %d, want 403 (network-dialback is restricted)", chk.Status)
	}
}

// TestObservedAddressNotPersistedAsDurableAddress: the responder-side observed
// source is NEVER written to a durable per-peer address field (§6.7.1 MUST 2 —
// the trap arch flagged: system/connection.address is dialer-side dialable
// state, and an ephemeral source port written there routes nowhere yet reads as
// dialable to §10). B is the responder here; whatever B stores about A, none of
// it carries A's observed ephemeral source as an address.
func TestObservedAddressNotPersistedAsDurableAddress(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startLifecyclePeer(t, kpB, "127.0.0.1:0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialLink(t, a, b)
	resp, err := a.p.RemoteExecute(ctx, networkURI(b), "observe-address", reachEmptyParams(t), nil)
	if err != nil {
		t.Fatalf("observe-address: %v", err)
	}
	observed, err := types.ObserveAddressResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	// On B (the responder), the system/connection record for A — the entity an
	// implementer reaches for first — must not carry A's observed source as its
	// dialable Address. Absent is fine (a responder holds no dialable address
	// for the peer that dialed it); present-but-different is fine; present-and-
	// equal-to-observed is the MUST-2 violation.
	aHash, err := types.ComputePeerIdentityHashFromPeerID(a.p.PeerID())
	if err != nil {
		t.Fatalf("derive A identity hash: %v", err)
	}
	connPath := types.ConnectionPath(string(b.p.PeerID()), aHash)
	if h, ok := b.p.LocationIndex().Get(connPath); ok {
		ent, ok := b.p.Store().Get(h)
		if ok {
			cd, err := types.ConnectionDataFromEntity(ent)
			if err == nil && cd.Address == observed.ObservedAddress {
				t.Fatalf("§6.7.1 MUST 2 violation: B persisted A's observed source %q as system/connection.address", observed.ObservedAddress)
			}
		}
	}
}

// TestSortCandidatesTryOrder: §6.7.3 host → srflx → relay, stable within a type.
func TestSortCandidatesTryOrder(t *testing.T) {
	cands := []types.NetworkCandidateData{
		{Address: "relay:1", Type: types.CandidateTypeRelay},
		{Address: "host:1", Type: types.CandidateTypeHost},
		{Address: "srflx:1", Type: types.CandidateTypeSrflx},
		{Address: "host:2", Type: types.CandidateTypeHost},
	}
	SortCandidates(cands)
	wantOrder := []string{"host:1", "host:2", "srflx:1", "relay:1"}
	for i, w := range wantOrder {
		if cands[i].Address != w {
			t.Fatalf("candidate[%d] = %q, want %q (order: %+v)", i, cands[i].Address, w, cands)
		}
	}
}

// TestGatherCandidatesTypingAndOrdering: srflx and relay are typed and ordered
// (srflx before relay); any host candidates come first; all TCP-substrate.
func TestGatherCandidatesTypingAndOrdering(t *testing.T) {
	srflx := "203.0.113.7:51820"
	relay := "relay.example:3478"
	cands := GatherCandidates(9000, srflx, relay)

	var srflxIdx, relayIdx = -1, -1
	for i, c := range cands {
		if c.Substrate != types.CandidateSubstrateTCP {
			t.Fatalf("candidate %q substrate = %q, want tcp", c.Address, c.Substrate)
		}
		switch c.Type {
		case types.CandidateTypeSrflx:
			if c.Address != srflx {
				t.Fatalf("srflx address = %q, want %q", c.Address, srflx)
			}
			srflxIdx = i
		case types.CandidateTypeRelay:
			if c.Address != relay {
				t.Fatalf("relay address = %q, want %q", c.Address, relay)
			}
			relayIdx = i
		case types.CandidateTypeHost:
			// host candidates (if the box has non-loopback interfaces) must
			// precede srflx.
			if srflxIdx != -1 && i > srflxIdx {
				t.Fatalf("host candidate at %d follows srflx at %d — host must be first", i, srflxIdx)
			}
		}
	}
	if srflxIdx == -1 || relayIdx == -1 {
		t.Fatalf("expected both srflx and relay candidates, got %+v", cands)
	}
	if srflxIdx > relayIdx {
		t.Fatalf("srflx (%d) must precede relay (%d)", srflxIdx, relayIdx)
	}
}

// TestReachabilityRateLimiter: per-requester min-interval; in-process (empty
// requester) never limited (§6.7.4 rate-limiting).
func TestReachabilityRateLimiter(t *testing.T) {
	rl := newRateLimiter(50 * time.Millisecond)
	p := crypto.PeerID("peer-1")

	if !rl.allow(p) {
		t.Fatal("first call should be allowed")
	}
	if rl.allow(p) {
		t.Fatal("immediate second call should be rate-limited")
	}
	if !rl.allow("") {
		t.Fatal("empty requester (in-process) must never be rate-limited")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.allow(p) {
		t.Fatal("call after the interval should be allowed again")
	}
}
