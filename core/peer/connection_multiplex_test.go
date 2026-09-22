package peer

import (
	"bytes"
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
		// The reentry handler dispatches AMBIENTLY to a foreign peer, so under
		// PD-2 (§5.2, 0.8.2.17) its own grant must scope that peer — declare a
		// cross-peer internal scope. A handler that legitimately reenters a
		// foreign peer without presenting a target-minted capability must
		// declare a peers scope covering it, exactly as this does; the §6.9
		// default self-grant (peers absent → {local}) would refuse the outbound.
		InternalScope: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
			Peers:      &types.CapabilityScope{Include: []string{"*"}},
		}},
	}
}

// echoHandler returns a distinct LARGE response body derived from the
// request's "marker" param — used to drive the RT-13b (§6.11 a′) frame-write
// atomicity path: concurrent responses are large enough to span multiple
// writes and distinct enough that a write-splice (two envelopes interleaved on
// the wire) shows up as a body-byte mismatch.
type echoHandler struct{ payloadBytes int }

func (e *echoHandler) Name() string { return "test-echo" }

func (e *echoHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var params struct {
		Marker string `cbor:"marker"`
	}
	if err := ecf.Decode(req.Params.Data, &params); err != nil {
		return handler.NewErrorResponse(400, "invalid_params", err.Error())
	}
	buf := make([]byte, 0, e.payloadBytes)
	for len(buf) < e.payloadBytes {
		buf = append(buf, params.Marker...)
	}
	buf = buf[:e.payloadBytes]
	raw, _ := ecf.Encode(buf)
	ent, _ := entity.NewEntity("primitive/bytes", cbor.RawMessage(raw))
	return &handler.Response{Status: 200, Result: ent}, nil
}

func (e *echoHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: "test/echo",
		Name:    "test-echo",
		Operations: map[string]types.HandlerOperationSpec{
			"echo": {InputType: "test/echo-input", OutputType: "primitive/bytes"},
		},
	}
}

// newMultiplexTestPeer builds a peer with open-access grants + a slow + a
// reentry handler + a large-echo handler, ready to drive WB-28-shape probes
// and the RT-13b frame-write-atomicity attestation.
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
		WithHandler("test/echo", &echoHandler{payloadBytes: 16 * 1024}),
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

// TestConnection_FrameWriteAtomicity_RT13b is the RT-13b (§6.11 a′) Part-B
// peer-side atomicity attestation: on one connection carrying concurrent
// dispatch, the bytes of two distinct response frames MUST NOT interleave —
// each frame is written whole / serialized against other frame writes. Go's
// mechanism is writeMu in connection.go (SendEnvelope holds it across the whole
// envelope write); this test is the standing guarantee that the property holds
// by construction, the load-bearing half of RT-13b that a wire probe alone
// cannot certify (VECTOR-SPEC-2026-07-27-RT-13b §4).
//
// It drives M concurrent Executes that each force a distinct LARGE response
// body and asserts every response is byte-identical to its own expected body —
// a splice would mix two bodies — with none dropped. Run under `go test -race`:
// the race detector additionally flags any unsynchronized write to the shared
// connection, so removing the writeMu serialization fails both deterministically
// (byte mismatch) and under -race.
func TestConnection_FrameWriteAtomicity_RT13b(t *testing.T) {
	const concurrency = 64
	const payloadBytes = 16 * 1024

	server := newMultiplexTestPeer(t, 0)
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

	echoURI := "entity://" + string(server.PeerID()) + "/test/echo"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	expected := func(idx int) []byte {
		marker := fmt.Sprintf("rt13b-partb-%d-", idx)
		buf := make([]byte, 0, payloadBytes)
		for len(buf) < payloadBytes {
			buf = append(buf, marker...)
		}
		return buf[:payloadBytes]
	}

	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			marker := fmt.Sprintf("rt13b-partb-%d-", idx)
			paramsRaw, _ := ecf.Encode(struct {
				Marker string `cbor:"marker"`
			}{Marker: marker})
			paramsEnt, _ := entity.NewEntity("test/echo-input", cbor.RawMessage(paramsRaw))
			respEnv, err := conn.Execute(ctx, echoURI, "echo", paramsEnt, nil)
			if err != nil {
				failures.Add(1)
				t.Errorf("execute %d: %v", idx, err)
				return
			}
			respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
			if err != nil || respData.Status != 200 {
				failures.Add(1)
				t.Errorf("execute %d: status=%d err=%v", idx, respData.Status, err)
				return
			}
			var resultEnt entity.Entity
			if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
				failures.Add(1)
				t.Errorf("execute %d: decode result entity: %v", idx, err)
				return
			}
			var got []byte
			if err := ecf.Decode(resultEnt.Data, &got); err != nil {
				failures.Add(1)
				t.Errorf("execute %d: decode body bytes: %v", idx, err)
				return
			}
			if !bytes.Equal(got, expected(idx)) {
				failures.Add(1)
				t.Errorf("execute %d: response body not byte-identical (got len=%d want len=%d) — frame-write splice suspected", idx, len(got), len(expected(idx)))
			}
		}(i)
	}
	wg.Wait()

	if failures.Load() != 0 {
		t.Fatalf("RT-13b Part B: %d/%d concurrent large responses failed byte-identity/framing — the frame writer is not atomic", failures.Load(), concurrency)
	}
	t.Logf("RT-13b Part B: %d concurrent distinct %d KB responses all byte-identical on one connection (writeMu serializes whole-frame writes)", concurrency, payloadBytes/1024)
}
