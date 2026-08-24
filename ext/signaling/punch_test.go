package signaling

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// memCarrier is a minimal in-memory rendezvous store standing in for the §4
// node — which is, by construction, an opaque blob store (§4.4). collect is
// non-destructive and returns EVERY blob at the key including the caller's own,
// exactly like the real node, which is why the punch's FindResponse/FindRequest
// filter by self and nonce (§6.4).
type memCarrier struct {
	mu      sync.Mutex
	buckets map[string][][]byte
}

func newMemCarrier() *memCarrier {
	return &memCarrier{buckets: make(map[string][][]byte)}
}

func (m *memCarrier) Offer(_ context.Context, key, message []byte) (uint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buckets[string(key)] = append(m.buckets[string(key)], append([]byte(nil), message...))
	return 200, nil
}

// CollectMessagesVerified runs the REAL §6.4 read path over the stored bytes —
// ClassifyCollected against the very key the bucket is filed under, exactly as
// the live *Client does. The stub stays a blob store and verifies nothing
// itself, so the bucket binding under test is the real one: a blob sealed for
// another key fails here for the same reason it would fail against a node.
func (m *memCarrier) CollectMessagesVerified(_ context.Context, key []byte) (uint, []CollectedMessage, []error, error) {
	m.mu.Lock()
	blobs := append([][]byte(nil), m.buckets[string(key)]...)
	m.mu.Unlock()
	msgs := make([]CollectedMessage, 0, len(blobs))
	var skipped []error
	for _, b := range blobs {
		msg, err := ClassifyCollected(b, key)
		if err != nil {
			skipped = append(skipped, err)
			continue
		}
		msgs = append(msgs, msg)
	}
	return 200, msgs, skipped, nil
}

// orderedKeypairs returns two real keypairs whose derived peer-ids sort lo < hi.
//
// The punch's tie-break and the §6.5 offerer rule are both a byte-wise sort over
// peer-ids, and the old tests spelled that with the literals "peer-A" / "peer-B".
// Those cannot survive sealed deposits: the id in `initiator` must equal the id
// the signature derives (§6.3 step 3), so a party's id is now whatever its key
// says it is. Sorting two generated keys keeps the roles deterministic — lo is
// still the impolite/lower side every assertion below means by "peer-A".
func orderedKeypairs(t *testing.T) (lo, hi crypto.Keypair) {
	t.Helper()
	a, err := crypto.Generate()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	b, err := crypto.Generate()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	if a.PeerID().String() > b.PeerID().String() {
		return b, a
	}
	return a, b
}

// freeLoopbackPort reserves a free loopback TCP port and returns its address
// with nothing listening on it — the port a punch party binds and both
// advertises as srflx and dials FROM (the §7.3 same-socket requirement, modeled
// on loopback where there is no NAT so srflx == the local bind).
func freeLoopbackPort(t *testing.T) *net.TCPAddr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close()
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.Port}
}

// TestPunchLoopbackDirectPath drives the full §7.1 exchange between two parties
// over an in-memory carrier and asserts a direct path lands on loopback: A
// offers connect-request, B answers connect-response, A measures rtt and sends
// punch-sync, and both fire at fire_at — establishing one TCP connection between
// their reflector-bound (SO_REUSEPORT) srflx ports. Proven by writing a byte
// each way. This is the Go↔Go end-to-end proof of the coordination protocol +
// the shared-port substrate; the true dual-hole crossing under real NAT is the
// separate §7.5-class gate (loopback has no NAT mapping to punch).
func TestPunchLoopbackDirectPath(t *testing.T) {
	carrier := newMemCarrier()
	key := make([]byte, 33) // opaque to the node; any fixed value works here

	aAddr := freeLoopbackPort(t)
	bAddr := freeLoopbackPort(t)

	kpA, kpB := orderedKeypairs(t)
	idA, idB := kpA.PeerID().String(), kpB.PeerID().String()
	mkParty := func(identity crypto.Keypair, local *net.TCPAddr) *PunchParty {
		return &PunchParty{
			Carrier:  carrier,
			Key:      key,
			Identity: identity,
			Trust:    VerifyTolerant,
			LocalCands: []types.NetworkCandidateData{
				{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: local.String()},
			},
			LocalAddr: local,
			// Loopback simultaneous-open can take several crossing windows; keep
			// attempts generous and spacing tight so the two connect()s overlap.
			Poll:            20 * time.Millisecond,
			CrossingRetries: 40,
			DialTimeout:     300 * time.Millisecond,
		}
	}
	aParty := mkParty(kpA, aAddr)
	bParty := mkParty(kpB, bAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type result struct {
		conn   net.Conn
		remote string
		err    error
	}
	aCh := make(chan result, 1)
	bCh := make(chan result, 1)
	go func() {
		c, err := aParty.Initiate(ctx, idB)
		aCh <- result{conn: c, err: err}
	}()
	go func() {
		c, remote, err := bParty.Respond(ctx)
		bCh <- result{conn: c, remote: remote, err: err}
	}()

	aRes := <-aCh
	bRes := <-bCh
	if aRes.err != nil {
		if aRes.conn != nil {
			aRes.conn.Close()
		}
		if bRes.conn != nil {
			bRes.conn.Close()
		}
		if errors.Is(aRes.err, ErrReusePortUnsupported) {
			t.Skip("SO_REUSEPORT not supported on this platform")
		}
		t.Fatalf("initiator: %v", aRes.err)
	}
	if bRes.err != nil {
		aRes.conn.Close()
		t.Fatalf("responder: %v", bRes.err)
	}
	defer aRes.conn.Close()
	defer bRes.conn.Close()

	// The responder learned the initiator's identity from the exchange — and now
	// from the SIGNATURE over it, not from the `initiator` field.
	if bRes.remote != idA {
		t.Errorf("responder saw initiator %q, want %q", bRes.remote, idA)
	}

	// Prove it is ONE connection: a byte written on each side arrives on the
	// other. (The real punch would now run PerformConnect/serve over this; here
	// we assert the raw transport crossed.)
	assertConnected(t, aRes.conn, bRes.conn)
	assertConnected(t, bRes.conn, aRes.conn)

	// Both legs bound the local srflx port they advertised (§7.3 same-socket).
	if got := aRes.conn.LocalAddr().(*net.TCPAddr).Port; got != aAddr.Port {
		t.Errorf("initiator bound local port %d, want advertised srflx port %d", got, aAddr.Port)
	}
	if got := bRes.conn.LocalAddr().(*net.TCPAddr).Port; got != bAddr.Port {
		t.Errorf("responder bound local port %d, want advertised srflx port %d", got, bAddr.Port)
	}
}

// recordingDial wraps dialReusePort with a flag that records whether this party
// ever fired an outbound dial. It performs the REAL dial so the punch still
// completes — the recorder is a tap, not a stub.
func recordingDial(dialed *atomic.Bool) DialFunc {
	return func(ctx context.Context, local *net.TCPAddr, remote string) (net.Conn, error) {
		dialed.Store(true)
		return dialReusePort(ctx, local, remote)
	}
}

// TestPunchBothSidesDial is G1's load-bearing assertion and its own negative
// control: under the §7.1-step-4 dual-hole fix, BOTH parties MUST fire an
// outbound dial (each side's connect opens ITS OWN NAT mapping). Loopback cannot
// observe a missing hole — a listen-only side passes an ordinary punch test
// unchanged (exactly how the retracted lower-dials/higher-listens shape slipped
// past both impls) — so the guarantee is asserted at the DialFunc seam instead.
// A sorts below B, so pre-fix B (the higher id) would listen-only and never
// dial; this test fails on that regression.
func TestPunchBothSidesDial(t *testing.T) {
	carrier := newMemCarrier()
	key := make([]byte, 33)

	aAddr := freeLoopbackPort(t)
	bAddr := freeLoopbackPort(t)

	var aDialed, bDialed atomic.Bool
	kpA, kpB := orderedKeypairs(t)
	idB := kpB.PeerID().String()
	mkParty := func(identity crypto.Keypair, local *net.TCPAddr, dialed *atomic.Bool) *PunchParty {
		return &PunchParty{
			Carrier:  carrier,
			Key:      key,
			Identity: identity,
			Trust:    VerifyTolerant,
			LocalCands: []types.NetworkCandidateData{
				{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: local.String()},
			},
			LocalAddr:       local,
			Dial:            recordingDial(dialed),
			Poll:            20 * time.Millisecond,
			CrossingRetries: 40,
			DialTimeout:     300 * time.Millisecond,
		}
	}
	aParty := mkParty(kpA, aAddr, &aDialed)
	bParty := mkParty(kpB, bAddr, &bDialed)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type result struct {
		conn net.Conn
		err  error
	}
	aCh := make(chan result, 1)
	bCh := make(chan result, 1)
	go func() {
		c, err := aParty.Initiate(ctx, idB)
		aCh <- result{conn: c, err: err}
	}()
	go func() {
		c, _, err := bParty.Respond(ctx)
		bCh <- result{conn: c, err: err}
	}()

	aRes := <-aCh
	bRes := <-bCh
	if aRes.conn != nil {
		defer aRes.conn.Close()
	}
	if bRes.conn != nil {
		defer bRes.conn.Close()
	}
	if aRes.err != nil {
		if errors.Is(aRes.err, ErrReusePortUnsupported) {
			t.Skip("SO_REUSEPORT not supported on this platform")
		}
		t.Fatalf("initiator: %v", aRes.err)
	}
	if bRes.err != nil {
		t.Fatalf("responder: %v", bRes.err)
	}

	// The whole point: neither side is listen-only. A false here is the dual-hole
	// regression — the peer's mapping never opens under real NAT.
	if !aDialed.Load() {
		t.Error("initiator (lower id) never dialed — regressed to listen-only, its NAT hole never opens")
	}
	if !bDialed.Load() {
		t.Error("responder (higher id) never dialed — regressed to listen-only, its NAT hole never opens")
	}
}

// assertConnected writes a probe byte on from and reads it on to.
func assertConnected(t *testing.T, from, to net.Conn) {
	t.Helper()
	want := []byte{0x42}
	_ = from.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := from.Write(want); err != nil {
		t.Fatalf("write on punched conn: %v", err)
	}
	_ = to.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 1)
	if _, err := to.Read(got); err != nil {
		t.Fatalf("read on punched conn: %v", err)
	}
	if got[0] != want[0] {
		t.Fatalf("punched conn delivered %#x, want %#x", got[0], want[0])
	}
}
