package peer

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
)

// waitForOriginating polls the acceptor's server-side connection for the
// installed grant. The grant is fire-and-forget on the wire, so there is no
// response to synchronize on from the dialer's side.
func acceptorConnFor(t *testing.T, acceptor *Peer, dialer *Peer) *Connection {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if conn := acceptor.inboundForReentry(dialer.PeerID()); conn != nil {
			return conn
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("acceptor never registered the inbound connection for §6.11 reentry")
	return nil
}

// TestReciprocalGrantOnRendezvousEstablishment is the §6.5 (b) loop, end to
// end over a real connection: a rendezvous-classified dial mints the
// reciprocal capability at the handshake's tail, the acceptor validates and
// installs it, and the acceptor's origination path then selects it.
//
// This is the authority the two-browser rung-1 run did not have — the observed
// `no originating authority` when the answerer tried to originate back. On a
// same-implementation loopback the mechanism is visible but the *gap* is not:
// only a genuinely different-role exchange shows the acceptor failing closed,
// which is why the vector matters and why this test asserts the negative case
// too.
func TestReciprocalGrantOnRendezvousEstablishment(t *testing.T) {
	dialer := newMultiplexTestPeer(t, 0)
	acceptor := newMultiplexTestPeer(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	// Classify BEFORE the handshake — the mint fires at its tail.
	conn.MarkEstablishedViaRendezvousKey()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	inbound := acceptorConnFor(t, acceptor, dialer)
	if !inbound.AwaitOriginatingCapability(ctx, ReciprocalGrantVectorFloor) {
		t.Fatal("acceptor never received the §6.5 (b) reciprocal grant — it has no authority to originate back, which is the gap this mechanism exists to close")
	}

	cap, supporting, ok := inbound.OriginatingCapability()
	if !ok {
		t.Fatal("grant reported ready but no capability installed")
	}

	// The grant must be usable by the acceptor: granter is the DIALER (so the
	// chain roots at the peer whose handlers we are about to invoke), grantee
	// is US (so `grantee == author` holds when we author the dispatch).
	capData, err := types.CapabilityTokenDataFromEntity(cap)
	if err != nil {
		t.Fatalf("decode installed grant: %v", err)
	}
	dialerHash, err := protocol.ResolveRemoteIdentityHash(dialer.PeerID(), nil)
	if err != nil {
		t.Fatalf("resolve dialer identity hash: %v", err)
	}
	granterHash, single := capData.Granter.SingleHash()
	if !single || granterHash != dialerHash {
		t.Fatalf("grant granter = %v (single=%v), want the dialer %s — a chain rooted anywhere else cannot authorize us at the dialer", granterHash, single, dialerHash)
	}
	if capData.Grantee != acceptor.identity.ContentHash {
		t.Fatalf("grant grantee = %s, want the acceptor's identity CONTENT HASH %s — naming the peer-id here is the #67 hazard and fails grantee_mismatch",
			capData.Grantee, acceptor.identity.ContentHash)
	}

	// The supporting chain must travel: a single-sig root cap without its
	// signature is rejected `missing_signature` at the far side's §5.5 walk,
	// and the acceptor's own handshake auth_included cannot contain entities
	// the dialer authored.
	var sawSignature, sawGranterIdentity bool
	for h, ent := range supporting {
		if ent.Type == types.TypeSignature {
			sawSignature = true
		}
		if h == dialerHash {
			sawGranterIdentity = true
		}
	}
	if !sawSignature {
		t.Fatal("no cap signature in the grant's supporting set — the far side rejects a single-sig root cap missing_signature")
	}
	if !sawGranterIdentity {
		t.Fatal("no granter identity in the grant's supporting set — the far side cannot resolve the chain root")
	}

	// And the origination path must actually select it, over the durable slot.
	selected, selectedSupporting, _ := inbound.selectOutboundCapability()
	if selected.ContentHash != cap.ContentHash {
		t.Fatalf("origination selected %s, not the reciprocal grant %s", selected.ContentHash, cap.ContentHash)
	}
	if len(selectedSupporting) != len(supporting) {
		t.Fatalf("origination carried %d supporting entities, want %d", len(selectedSupporting), len(supporting))
	}
}

// TestNoReciprocalGrantOnDialByAddress is the asymmetric non-regression vector
// (§6.5 (b) conformance §8.2, and the whole point of the §7 narrowing): a peer
// reached by ordinary dial-by-address MUST NOT gain reciprocal originating
// authority. This is the vector the pre-narrowing universal build fails.
func TestNoReciprocalGrantOnDialByAddress(t *testing.T) {
	dialer := newMultiplexTestPeer(t, 0)
	acceptor := newMultiplexTestPeer(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No MarkEstablishedViaRendezvousKey — this is a plain dial.
	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	inbound := acceptorConnFor(t, acceptor, dialer)
	// A short bound: we are asserting nothing arrives, and the acceptor must
	// not block on a grant that is never coming.
	if inbound.AwaitOriginatingCapability(ctx, 300*time.Millisecond) {
		t.Fatal("a dial-by-address acceptor gained reciprocal originating authority — one party requested service, and nothing entitles the server to reach back (EXTENSION-NETWORK §6.6)")
	}
	if _, _, ok := inbound.OriginatingCapability(); ok {
		t.Fatal("originating capability installed on an asymmetric establishment")
	}
}

// TestReciprocalGrantRejectsForeignGranter pins the acceptance check: a grant
// whose granter is not the peer we authenticated on this connection is
// dropped. The frame is otherwise well-formed and correctly self-signed — the
// only thing wrong with it is who minted it.
func TestReciprocalGrantRejectsForeignGranter(t *testing.T) {
	dialer := newMultiplexTestPeer(t, 0)
	acceptor := newMultiplexTestPeer(t, 0)
	stranger := newMultiplexTestPeer(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	inbound := acceptorConnFor(t, acceptor, dialer)

	// A grant minted by a THIRD peer, sent down the dialer's connection.
	forged, err := protocol.BuildReentryGrantEnvelope(
		stranger.Keypair(),
		acceptor.identity.ContentHash,
		protocol.DefaultConnectionGrants(),
		conn.connState.ActiveHashFormat,
	)
	if err != nil {
		t.Fatalf("build foreign grant: %v", err)
	}
	if err := conn.SendEnvelope(forged); err != nil {
		t.Fatalf("send foreign grant: %v", err)
	}

	if inbound.AwaitOriginatingCapability(ctx, 500*time.Millisecond) {
		t.Fatal("installed a grant whose granter is not the authenticated peer — authority we store must be attributable to the peer we actually verified")
	}
}

// TestReciprocalGrantIsAdvertisementFiltered is Q2(a) (arch f8f736a): the §3
// advertisement discipline binds the reciprocal mint, not only the §6.6
// handshake. Both Go and Rust were skipping it there.
//
// It is inherent in the Q2 ruling rather than an extra rule — the reciprocal
// grant is "the grant an inbound dialer would receive," and an inbound dialer
// never receives an entry naming a handler this peer does not serve. Shipping
// one advertises authority whose cross-peer behavior is `404 handler_not_found`
// at the dispatch boundary: the counterpart believes it may originate, and
// discovers otherwise only at the seam where attribution is hardest.
func TestReciprocalGrantIsAdvertisementFiltered(t *testing.T) {
	const unbacked = "test/not-registered"

	// The dialer resolves a grant naming a handler it does not register,
	// alongside one it does. Only the backed entry may reach the wire.
	dialer := newFilteredGrantTestPeer(t, []types.GrantEntry{
		{
			Handlers:   types.CapabilityScope{Include: []string{unbacked}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		},
		{
			Handlers:   types.CapabilityScope{Include: []string{"test/echo"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		},
	})
	acceptor := newMultiplexTestPeer(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	conn.MarkEstablishedViaRendezvousKey()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	inbound := acceptorConnFor(t, acceptor, dialer)
	if !inbound.AwaitOriginatingCapability(ctx, ReciprocalGrantVectorFloor) {
		t.Fatal("reciprocal grant never landed")
	}

	cap, _, _ := inbound.OriginatingCapability()
	capData, err := types.CapabilityTokenDataFromEntity(cap)
	if err != nil {
		t.Fatalf("decode reciprocal grant: %v", err)
	}

	backedSeen := false
	for _, g := range capData.Grants {
		for _, pattern := range g.Handlers.Include {
			if pattern == unbacked {
				t.Fatalf("the reciprocal grant advertises %q, which the granting peer does not register — "+
					"the §3 advertisement discipline binds this mint too (Q2(a)); the counterpart would "+
					"originate against it and take a 404 at the dispatch boundary", unbacked)
			}
			if pattern == "test/echo" {
				backedSeen = true
			}
		}
	}
	if !backedSeen {
		t.Fatal("the filter removed the BACKED entry as well — an over-filtered grant fails closed " +
			"quietly, which is the same class of defect in the other direction")
	}
}

// newFilteredGrantTestPeer builds a listening peer whose connection grants are
// the caller's, so a test can put an unbacked entry in front of the
// advertisement filter. Registers test/echo as the one genuinely backed
// handler.
func newFilteredGrantTestPeer(t *testing.T, grants []types.GrantEntry) *Peer {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(
		WithIdentity(kp),
		WithListenAddr("127.0.0.1:0"),
		WithConnectionGrants(grants),
		WithHandler("test/echo", &echoHandler{payloadBytes: 16 * 1024}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		p.Close()
	})
	ready := make(chan struct{})
	go func() { p.ListenReady(ctx, ready) }()
	<-ready
	return p
}
