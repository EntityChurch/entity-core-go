package peer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// slowHandler waits delay before returning a 200 — used to verify that
// concurrent Execute calls run in parallel rather than serializing on a
// per-connection mutex.
type slowHandler struct {
	delay time.Duration
}

func (s *slowHandler) Name() string { return "test-slow" }

func (s *slowHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	raw, _ := ecf.Encode(map[string]string{"ok": "1"})
	ent, _ := entity.NewEntity("test/slow-result", cbor.RawMessage(raw))
	return &handler.Response{Status: 200, Result: ent}, nil
}

func (s *slowHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: "test/slow",
		Name:    "test-slow",
		Operations: map[string]types.HandlerOperationSpec{
			"go": {InputType: "test/slow-input", OutputType: "test/slow-result"},
		},
	}
}

// reentryHandler, when invoked, dispatches a sub-EXECUTE back to a target
// peer encoded in params. This is the WB-28 deadlock shape: a handler
// running on peer A's server side calls back to peer B via A's pooled
// outbound connection to B, while another Execute call may already be
// holding the (pre-fix) connection mutex.
type reentryHandler struct{}

func (r *reentryHandler) Name() string { return "test-reentry" }

func (r *reentryHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var params struct {
		TargetURI string `cbor:"target_uri"`
	}
	if err := ecf.Decode(req.Params.Data, &params); err != nil {
		return handler.NewErrorResponse(400, "invalid_params", err.Error())
	}
	emptyRaw, _ := ecf.Encode(map[string]string{})
	emptyEnt, _ := entity.NewEntity("test/empty", cbor.RawMessage(emptyRaw))
	resp, err := req.Context.Execute(ctx, params.TargetURI, "go", emptyEnt)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (r *reentryHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: "test/reentry",
		Name:    "test-reentry",
		Operations: map[string]types.HandlerOperationSpec{
			"go": {InputType: "test/reentry-input", OutputType: "test/slow-result"},
		},
	}
}

// newMultiplexTestPeer builds a peer with open-access grants + a slow + a
// reentry handler, ready to drive WB-28-shape probes.
func newMultiplexTestPeer(t *testing.T, slowDelay time.Duration) *Peer {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(
		WithIdentity(kp),
		WithListenAddr("127.0.0.1:0"),
		WithConnectionGrants(OpenAccessGrants()),
		WithHandler("test/slow", &slowHandler{delay: slowDelay}),
		WithHandler("test/reentry", &reentryHandler{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Listener context lives until the test finishes — the inner goroutine
	// in ListenReady closes the listener when its ctx is canceled, so the
	// ctx must outlast every Execute call we drive against this peer.
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

// connectClient performs the handshake from client→server and returns the
// established Connection. The reader goroutine starts at the end of
// PerformConnect — post-fix, the connection supports concurrent Execute.
func connectClient(t *testing.T, client, server *Peer) *Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := conn.PerformConnect(ctx); err != nil {
		conn.Close()
		t.Fatalf("handshake: %v", err)
	}
	return conn
}

// TestConnection_ConcurrentExecutesAreMultiplexed verifies the Class G fix
// (F-WB28 / Stage 4 round-1): N concurrent Execute calls on the same
// client connection run in PARALLEL via the multiplexed reader, NOT
// serialized via a per-connection mutex.
//
// Pre-fix, Connection.Execute held c.mu across send+recv — N concurrent
// callers to a slow handler took N × delay wall-clock. Post-fix, the
// reader demuxes responses by request_id; the same N concurrent callers
// complete in ~1 × delay wall-clock.
//
// The assertion uses a generous parallelism floor (must be at least 3× faster
// than fully-serialized) so it stays robust under CI scheduler noise.
func TestConnection_ConcurrentExecutesAreMultiplexed(t *testing.T) {
	const delay = 300 * time.Millisecond
	const concurrency = 8

	server := newMultiplexTestPeer(t, delay)
	client, err := New(
		WithIdentity(mustKey(t)),
		WithConnectionGrants(OpenAccessGrants()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn := connectClient(t, client, server)
	defer conn.Close()

	emptyRaw, _ := ecf.Encode(map[string]string{})
	emptyEnt, _ := entity.NewEntity("test/empty", cbor.RawMessage(emptyRaw))
	slowURI := "entity://" + string(server.PeerID()) + "/test/slow"

	var wg sync.WaitGroup
	var failures atomic.Int32

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			respEnv, err := conn.Execute(ctx, slowURI, "go", emptyEnt, nil)
			if err != nil {
				failures.Add(1)
				t.Errorf("execute %d: %v", idx, err)
				return
			}
			respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
			if err != nil || respData.Status != 200 {
				failures.Add(1)
				t.Errorf("execute %d: status=%d err=%v", idx, respData.Status, err)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	if failures.Load() != 0 {
		t.Fatalf("%d/%d executes failed", failures.Load(), concurrency)
	}

	// Serialized cost = concurrency × delay; parallel cost ≈ 1 × delay.
	// We require at least 3× speedup over serialized to confirm parallelism.
	serialized := time.Duration(concurrency) * delay
	if elapsed > serialized/3 {
		t.Fatalf("F-WB28 regression: %d concurrent Execute calls took %v; expected ≪ serialized cost %v (3× margin = %v). The per-connection write+recv mutex appears to be back — responses are not being demuxed by request_id.",
			concurrency, elapsed, serialized, serialized/3)
	}
	t.Logf("multiplexed %d concurrent executes in %v (serialized would be %v)", concurrency, elapsed, serialized)
}

// TestConnection_ReentrantCrossPeerDoesNotDeadlock is the F-WB28 pin
// test in its bidirectional-reentry shape — the canonical 2-peer
// concurrent-call deadlock the workbench reproducer surfaced.
//
// Setup: two peers A and B, pooled outbound in BOTH directions (A→B
// client conn and B→A client conn). Both register a "reentry" handler
// that synchronously dispatches a sub-EXECUTE back to a target peer
// passed in params.
//
// Probe (concurrent):
//   - From A: Execute reentry@B with target=A — drives A's outbound on
//     A→B; bob's handler then reenters via B→A back to A's slow handler.
//   - From B: Execute reentry@A with target=B — symmetric. Drives B's
//     outbound on B→A; alice's handler reenters via A→B back to B's slow.
//
// Pre-fix: A's outbound holds A→B's c.mu (single-pending); bob's reentry
// needs B→A's c.mu, which is held by B's outbound; symmetric on the
// other side — deadlock at the per-connection mutexes. Both calls
// timeout at 15s.
//
// Post-fix: each Connection's reader demuxes responses by request_id;
// the reentries proceed concurrently on the same pooled connections;
// both Executes complete within the slow-handler delay + scheduling
// overhead.
func TestConnection_ReentrantCrossPeerDoesNotDeadlock(t *testing.T) {
	const slowDelay = 100 * time.Millisecond

	alice := newMultiplexTestPeer(t, slowDelay)
	bob := newMultiplexTestPeer(t, slowDelay)

	// Pool outbound connections in both directions.
	aliceToBob := connectClient(t, alice, bob)
	defer aliceToBob.Close()
	bobToAlice := connectClient(t, bob, alice)
	defer bobToAlice.Close()

	// AddRemoteConnection makes hctx.Execute on each side find the pooled
	// connection (instead of dialing fresh, which would skip the deadlock
	// scenario entirely).
	if _, err := alice.AddRemoteConnection(bob.PeerID(), aliceToBob); err != nil {
		t.Fatalf("alice.AddRemoteConnection: %v", err)
	}
	if _, err := bob.AddRemoteConnection(alice.PeerID(), bobToAlice); err != nil {
		t.Fatalf("bob.AddRemoteConnection: %v", err)
	}

	// Register transport addresses so makeLocalExecute → remoteExecute
	// can resolve them when reentering.
	if err := alice.RegisterRemote(bob.PeerID(), bob.Addr().String()); err != nil {
		t.Fatalf("alice.RegisterRemote bob: %v", err)
	}
	if err := bob.RegisterRemote(alice.PeerID(), alice.Addr().String()); err != nil {
		t.Fatalf("bob.RegisterRemote alice: %v", err)
	}

	// Reentry params: each side's outbound targets the OTHER peer's
	// reentry handler, with a target_uri that points the reentry sub-call
	// at our OWN slow handler — completing the loop A→B→A and B→A→B.
	aliceReentryURI := "entity://" + string(bob.PeerID()) + "/test/reentry"
	bobReentryURI := "entity://" + string(alice.PeerID()) + "/test/reentry"
	aliceTargetURI := "entity://" + string(alice.PeerID()) + "/test/slow"
	bobTargetURI := "entity://" + string(bob.PeerID()) + "/test/slow"

	encodeParams := func(target string) entity.Entity {
		raw, _ := ecf.Encode(struct {
			TargetURI string `cbor:"target_uri"`
		}{TargetURI: target})
		ent, _ := entity.NewEntity("test/reentry-input", cbor.RawMessage(raw))
		return ent
	}

	// 3-second budget. Pre-fix the deadlock fires the 15s per-request
	// default deadline; we want a regression to FAIL FAST, not stall the
	// whole CI run.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)

	go func() {
		defer wg.Done()
		respEnv, err := aliceToBob.Execute(ctx, aliceReentryURI, "go", encodeParams(aliceTargetURI), nil)
		if err != nil {
			errs <- fmt.Errorf("alice→bob reentry: %w", err)
			return
		}
		respData, _ := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if respData.Status != 200 {
			errs <- fmt.Errorf("alice→bob reentry status=%d", respData.Status)
		}
	}()
	go func() {
		defer wg.Done()
		respEnv, err := bobToAlice.Execute(ctx, bobReentryURI, "go", encodeParams(bobTargetURI), nil)
		if err != nil {
			errs <- fmt.Errorf("bob→alice reentry: %w", err)
			return
		}
		respData, _ := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if respData.Status != 200 {
			errs <- fmt.Errorf("bob→alice reentry status=%d", respData.Status)
		}
	}()

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		close(errs)
		for e := range errs {
			t.Errorf("%v", e)
		}
	case <-ctx.Done():
		t.Fatalf("F-WB28 regression: bidirectional reentrant Execute deadlocked within 3s budget. The connection multiplexer has reverted to per-connection send+recv serialization. See core/peer/connection.go Execute path + Stage 4 round-1 coordination memo §4.")
	}
}

func mustKey(t *testing.T) crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// silenceUnused keeps the hash import alive even when test refactors
// drop direct references — connection tests sometimes import it via
// the helpers above.
var _ = hash.Hash{}
