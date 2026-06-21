// HTTP-substrate raw-frame test — proves Peer.SendRawFrameTo over an
// HTTP-only outbound POSTs envelope bytes verbatim and the destination
// dispatches them through the SAME path TCP uses.
//
// This is the substrate that RELAY §3.1.1 terminal-hop delivery rides on
// for HTTP-live transport. RELAY itself names the semantic ("deliver the
// inner verbatim"), never the substrate — Go follows whichever §6.5
// profile resolved to. Previously this method was hard-locked to TCP
// (SendRawFrameTo rejected HTTPConnection at construction); this test
// pins the unlocked behavior.

package peer

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// startHTTPOnlyPeerForTest builds a peer wired with tree + open-access,
// mounts an httplive.Server in front of its dispatcher via httptest, and
// returns the peer + its public URL + a teardown.
func startHTTPOnlyPeerForTest(t *testing.T, name string) (*Peer, crypto.Keypair, entity.Entity, string, func()) {
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

	srv := httplive.NewServer(p.Dispatcher())
	ts := httptest.NewServer(srv)

	teardown := func() {
		ts.Close()
		_ = p.Close()
	}
	return p, kp, identity, ts.URL, teardown
}

// TestSendRawFrameTo_HTTP_VerbatimDelivery proves the substrate fix.
// Two HTTP-only peers; A authenticates with B (priming the pool +
// capturing B's session cap), then A constructs a fully-authenticated
// EXECUTE envelope (signed by A, against B's session cap, targeting
// tree:put on B), encodes it to bytes, and calls SendRawFrameTo. The
// destination MUST dispatch the EXECUTE as if it arrived on a direct
// connection (this is the RELAY §3.1.1 / §9 / §10.4 semantic — opaque
// inner, per-envelope auth, byte-identical-to-direct).
func TestSendRawFrameTo_HTTP_VerbatimDelivery(t *testing.T) {
	a, aKP, aIdentity, _, aDown := startHTTPOnlyPeerForTest(t, "A")
	defer aDown()
	b, bKP, _, bURL, bDown := startHTTPOnlyPeerForTest(t, "B")
	defer bDown()
	_ = b

	// A learns B's HTTP profile (the §6.5 transport profile A would dial).
	if err := a.RegisterRemoteHTTP(bKP.PeerID(), bURL); err != nil {
		t.Fatalf("A.RegisterRemoteHTTP(B): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Trigger the HELLO → AUTHENTICATE handshake by issuing one real
	// EXECUTE. After this, A's pool holds a post-PerformConnect
	// HTTPConnection to B, with B's session cap pinned in Session().
	probeGetReq, probeGetRes, err := tree.CreateGetRequest("system/handler/system/tree", "entity")
	if err != nil {
		t.Fatalf("CreateGetRequest: %v", err)
	}
	if _, err := a.RemoteExecute(ctx, "entity://"+string(bKP.PeerID())+"/system/tree", "get", probeGetReq, probeGetRes); err != nil {
		t.Fatalf("priming RemoteExecute (HELLO/AUTH): %v", err)
	}

	// Pull A's HTTPConnection to B out of the pool and lift the session cap
	// B conferred during AUTHENTICATE. The cap chains B-identity → A-identity
	// under B's connection grant; A authors EXECUTEs against B under it
	// exactly like a real cross-peer flow.
	a.remote.mu.Lock()
	cached, ok := a.remote.conns[bKP.PeerID()]
	a.remote.mu.Unlock()
	if !ok {
		t.Fatal("post-priming pool MUST hold an HTTPConnection to B")
	}
	httpConn, ok := cached.(*HTTPConnection)
	if !ok {
		t.Fatalf("pool entry is %T, expected *HTTPConnection (HTTP profile registered)", cached)
	}
	if httpConn.Session() == nil || httpConn.Session().Capability == nil {
		t.Fatal("session capability MUST be populated after priming RemoteExecute")
	}
	sessionCap := *httpConn.Session().Capability

	// Author A's "inner" — a fully-signed EXECUTE that does tree:put on B.
	// In a real relay scenario this is the envelope the originator hands
	// to the relay, which the relay forwards verbatim. Here we hand it to
	// SendRawFrameTo directly so the substrate proof is on the transport
	// step alone, with no relay extension in the way.
	const targetPath = "local/raw-frame-http-test/key"
	payload, err := entity.NewEntity("test/raw-frame-payload", []byte{0xA1, 0x01, 0x05}) // {1: 5}
	if err != nil {
		t.Fatalf("payload NewEntity: %v", err)
	}
	if _, err := a.Store().Put(payload); err != nil {
		t.Fatalf("A.Store().Put(payload): %v", err)
	}
	putReqEnt, putResource, err := tree.CreatePutRequest(targetPath, &payload)
	if err != nil {
		t.Fatalf("CreatePutRequest: %v", err)
	}

	innerEnv, err := protocol.CreateAuthenticatedExecute(
		aKP,
		aIdentity,
		sessionCap,
		"raw-frame-http-req",
		"entity://"+string(bKP.PeerID())+"/system/tree",
		"put",
		putReqEnt,
		putResource,
	)
	if err != nil {
		t.Fatalf("CreateAuthenticatedExecute: %v", err)
	}

	// Bundle the AUTHENTICATE-response's Included into the inner envelope's
	// Included set so B's per-envelope V7 §5.2 chain walk (granter identity
	// + cap signature) resolves standalone. Without this, B's verifier sees
	// the cap-token reference but no matching signature → capability_denied.
	// Same posture as the validator's buildInnerExecute in mp2.
	for h, ent := range httpConn.Session().Envelope.Included {
		if _, exists := innerEnv.Included[h]; exists {
			continue
		}
		innerEnv.Include(entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h})
	}

	// Encode to bytes — same shape as the .Data of a system/envelope-
	// typed inner the relay's terminal-hop carries.
	innerBytes, err := ecf.Encode(innerEnv)
	if err != nil {
		t.Fatalf("ecf.Encode envelope: %v", err)
	}

	// THE substrate operation under test.
	if err := a.SendRawFrameTo(ctx, bKP.PeerID(), innerBytes); err != nil {
		t.Fatalf("SendRawFrameTo over HTTP: %v", err)
	}

	// Verify the put landed at B. The send is fire-and-forget per §3.1.1;
	// we poll B's tree briefly to give the async dispatch time to settle.
	wantHash := payload.ContentHash
	bound := false
	bTreePath := "/" + string(bKP.PeerID()) + "/" + targetPath
	for attempt := 0; attempt < 20; attempt++ {
		if h, ok := b.LocationIndex().Get(bTreePath); ok && h == wantHash {
			bound = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bound {
		t.Fatalf("B's tree did not bind %s → %s after SendRawFrameTo (substrate did not deliver verbatim, or dispatcher did not run)", bTreePath, wantHash)
	}

	// And re-fetch through the store to confirm bytes round-trip.
	gotEnt, ok := b.Store().Get(wantHash)
	if !ok {
		t.Fatalf("B's content store missing payload hash %s after raw-frame delivery", wantHash)
	}
	if gotEnt.Type != payload.Type {
		t.Fatalf("payload type drift: want %q got %q", payload.Type, gotEnt.Type)
	}

}
