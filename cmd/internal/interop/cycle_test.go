package interop

// Cross-peer subscription-cycle regression canary (SYSTEM-AUDIT
// ledger item #1 / CONCURRENCY-CONSOLIDATION-PLAN Step 2).
//
// Before this test the cross-peer subscription cycle "passed by luck": no
// mechanical test drove writes around a ring of peers each subscribing to
// the next, so every emit-pipeline change was unverified against the cycle
// topology. This test builds 4 in-process peers (A→B→C→D→A), wires the
// production cross-peer auto-sync recipe (subscription → inbox continuation
// chain → tree.put) on every ring edge, drives sustained writes at A, and
// asserts the invariants the spec already names (V7 §3.4 cascade_depth / TTL
// bounds, §2870 post-commit observability):
//
//	(i)   no deadlock          — the whole exchange finishes within the
//	                             overall deadline; a stalled emit pipeline
//	                             manifests as a timeout failure, not a hang.
//	(ii)  eventual propagation  — a write at A reaches all four peers.
//	(iii) bounded amplification — one external write produces ONE lap of
//	                             the ring and then stops. The spec's no-op
//	                             suppression (notifying.go: identical-hash
//	                             rebind skips cascade+emit, SYSTEM-
//	                             COMPOSITION 1.1) terminates the verbatim-
//	                             relay cycle; the configured cascade-depth
//	                             bound (cycleMaxDepth) is the backstop if
//	                             that regresses. The sharp signal is the
//	                             amplification FACTOR: observed writes per
//	                             peer ~= externalWrites (one lap). If no-op
//	                             suppression breaks or the pipeline
//	                             amplifies, the cycle laps until the depth
//	                             backstop instead (orders of magnitude more
//	                             observed writes) and this test fails. The
//	                             cascade-depth refusal PRIMITIVE is unit-
//	                             tested in core/tree.TestPutCascadeDepth-
//	                             Refused; this test's job is the cross-peer
//	                             TOPOLOGY staying bounded under feedback.
//	(iv)  finite drop counters  — Peer.Stats() (EventBufferDrops /
//	                             FanOutSinks) and Engine.DroppedDeliveries()
//	                             are bounded; they do not grow without bound
//	                             after the system quiesces.
//
// REGRESSION CANARY: do not make an emit-pipeline change (notifying.go,
// fanout.go, subscription engine/delivery, cascade tracker) without running
// this test. If it stops quiescing, or the amplification factor blows past
// one lap, the cross-peer cycle is no longer bounded — a correctness
// regression, not a flaky test.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/continuation"
	"go.entitychurch.org/entity-core-go/ext/inbox"
	"go.entitychurch.org/entity-core-go/ext/subscription"

	"github.com/fxamacker/cbor/v2"
)

const (
	cyclePrefix   = "system/validate/cycle/"
	cycleDocPath  = cyclePrefix + "doc"
	cyclePattern  = cyclePrefix + "*"
	cycleMaxDepth = 32 // loop backstop; healthy convergence stays far below it
)

// ringPeer is one node of the cycle: a fully-wired listening peer plus an
// observer counter of writes landing on the shared cycle prefix.
type ringPeer struct {
	name     string
	peer     *peer.Peer
	engine   *subscription.Engine
	client   *validate.PeerClient
	kp       crypto.Keypair // peer's own keypair; reused for peer-to-peer cross-peer clients
	observed *atomic.Int64  // tree events seen on cyclePrefix (quiescence signal)
}

// buildRingPeer constructs an in-process listening peer wired with the same
// subscription / inbox / continuation stack entity-peer uses, plus an
// observer sink that counts settled writes on the shared cycle prefix.
func buildRingPeer(t *testing.T, name string) *ringPeer {
	t.Helper()

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("[%s] generate keypair: %v", name, err)
	}

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	engine := subscription.NewEngine(cs, li, nil)
	engineCtx, cancelEngine := context.WithCancel(context.Background())

	// Observer sink — the "Phase 2 observer" pattern. Per-sink fan-out
	// isolation means a slow drain here cannot stall the peer; we drain
	// promptly anyway and only count events on the shared prefix.
	observerCh := make(chan store.TreeChangeEvent, 1024)
	observed := &atomic.Int64{}

	p, err := peer.New(
		peer.WithIdentity(kp),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithStore(cs),
		peer.WithLocationIndex(li),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
		peer.WithMaxCascadeDepth(cycleMaxDepth),
		peer.WithHandler("system/inbox", inbox.NewHandler()),
		peer.WithHandler("system/continuation", continuation.NewHandler()),
		peer.WithHandler("system/subscription", subscription.NewHandler(engine)),
		peer.WithNamedSyncHook("subscription/notification", engine.OnTreeChange),
		peer.WithTreeEventSink(observerCh),
		peer.WithCloseFunc(cancelEngine),
	)
	if err != nil {
		t.Fatalf("[%s] peer.New: %v", name, err)
	}

	engine.SetLocationIndex(p.LocationIndex())
	engine.Deliver = subscription.MakeDeliveryFunc(
		p.Keypair(), p.Identity(), p.Store(), p.LocationIndex(), p.Dispatcher(),
	)
	engine.Load()
	engine.StartDelivery(engineCtx)

	listenCtx, cancelListen := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go func() { _ = p.ListenReady(listenCtx, ready) }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("[%s] listener not ready in 5s", name)
	}

	stopDrain := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopDrain:
				return
			case ev := <-observerCh:
				if hasCyclePath(ev.Path) {
					observed.Add(1)
				}
			}
		}
	}()

	// Peer-to-peer model (EXTENSION-CONTINUATION v1.11 §4.2 case 3): the
	// client wields the peer's OWN keypair so cross-peer dispatch flows
	// where the dispatcher == grantee == client-identity == peer-identity
	// work end-to-end. With a random ephemeral client identity the §3.1a
	// in-chain-granter check at install rejects (writer ≠ leaf granter)
	// and the §6.8 grantee check at dispatch rejects (peer ≠ grantee).
	client, err := validate.NewPeerClientWithKeypair(p.Addr().String(), kp)
	if err != nil {
		t.Fatalf("[%s] new client: %v", name, err)
	}
	connCtx, connCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer connCancel()
	if err := client.Connect(connCtx); err != nil {
		t.Fatalf("[%s] connect: %v", name, err)
	}
	client.PerformHandshake(connCtx)
	if !client.Connected() {
		t.Fatalf("[%s] handshake failed", name)
	}

	t.Cleanup(func() {
		client.Close()
		cancelListen()
		_ = p.Close()
		close(stopDrain)
	})

	return &ringPeer{name: name, peer: p, engine: engine, client: client, observed: observed, kp: kp}
}

func hasCyclePath(path string) bool {
	// Qualified path is /{peerID}/system/validate/cycle/... — match the
	// shared segment, not a fixed peer-id prefix.
	for i := 0; i+len(cyclePrefix) <= len(path); i++ {
		if path[i:i+len(cyclePrefix)] == cyclePrefix {
			return true
		}
	}
	return false
}

func TestCrossPeerCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-peer cycle canary: skipped under -short (spins up 4 networked peers)")
	}

	// Recipe: EXTENSION-SUBSCRIPTION v3.14 include_payload + V7 v7.50
	// CAS-on-tree:put (PROPOSAL-CONVERGENT-MIRRORING). Subscription
	// notifications carry the changed entity in the envelope's `included`;
	// a single local continuation extracts (entity, expected_hash) from the
	// notification (entity = notification.hash deref'd via deref_included
	// transform_op; expected_hash = notification.previous_hash) and
	// dispatches tree:put. Stale laps fail CAS-replace (409) and die —
	// terminating the amplification the unconditional-PUT recipe produced.
	//
	// Bounded-amplification gate (convergent_mirror canonical shape,
	// PROPOSAL-CONVERGENT-MIRRORING §5): total laps observed per peer
	// MUST be ≤ 1.5 × external_writes. With writes=20 the per-peer cap
	// is 30; the unconditional-PUT regression produced ~87 laps/write.

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const n = 4
	ring := make([]*ringPeer, n)
	names := []string{"A", "B", "C", "D"}
	for i := 0; i < n; i++ {
		ring[i] = buildRingPeer(t, names[i])
	}

	// Full-mesh transport registration: any peer may need to dial any other
	// (predecessor for the fetch continuation, successor for delivery).
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			targetID := string(ring[j].client.RemotePeerID())
			// V7.64 path-encoding alignment: TCPProfileData at
			// system/peer/transport/{peer_id_hex}/primary. profile-id
			// "primary" matches the cohort default.
			targetHash, err := types.ComputePeerIdentityHashFromPeerID(ring[j].client.RemotePeerID())
			if err != nil {
				t.Fatalf("derive identity hash for %s: %v", names[j], err)
			}
			targetHashHex := types.PeerIdentityHashHex(targetHash)
			tdata, err := ecf.Encode(types.TCPProfileData{
				PeerID:        targetID,
				TransportType: "tcp",
				Endpoint:      types.TransportEndpointURL{URL: "tcp://" + ring[j].client.Addr()},
				SupportedOps:  []string{types.OpExecute},
				Freshness:     "live",
				NonceRequired: true,
				CapFlow:       "both",
			})
			if err != nil {
				t.Fatalf("encode transport %s: %v", names[j], err)
			}
			tent, err := entity.NewEntity(types.TypePeerTransportTCP, cbor.RawMessage(tdata))
			if err != nil {
				t.Fatalf("transport entity %s: %v", names[j], err)
			}
			if _, err := ring[i].client.TreePut(ctx, "system/peer/transport/"+targetHashHex+"/primary", tent); err != nil {
				t.Fatalf("register transport %s on %s: %v", names[j], names[i], err)
			}
		}
	}

	// Wire one ring edge per peer using the v3.14 recipe: a write on peer
	// i's shared prefix propagates to peer (i+1)'s shared prefix via a
	// single local continuation on succ (no cross-peer GET).
	//
	// src subscribes succ to its cyclePattern with include_payload=true.
	// Each notification's envelope carries the changed entity in `included`.
	// succ's mirror continuation runs the v3.14 recipe:
	//   - Select {entity: hash, expected_hash: previous_hash}
	//   - deref_included on the entity field (resolves hash → entity from
	//     envelope.included)
	//   - dispatch tree:put with CAS via expected_hash
	// Stale laps fail CAS-replace (409) and die.
	//
	// The continuation install is purely local on succ (dst.client both
	// sides; chain dst-rooted, grantee = dst peer = local dispatcher) —
	// no cross-peer GET client is needed because the entity arrives
	// in-band with the notification.
	for i := 0; i < n; i++ {
		succ := (i + 1) % n
		src, dst := ring[i], ring[succ]
		dstID := string(dst.client.RemotePeerID())

		mirrorInbox := "system/inbox/cycle-mirror-" + dst.name

		mirror := types.ContinuationData{
			Target:    "system/tree",
			Operation: "put",
			Resource:  &types.ResourceTarget{Targets: []string{cycleDocPath}},
			ResultTransform: &types.ContinuationTransformData{
				Select: map[string]string{
					"entity":        "hash",          // notification.hash → put.entity (as hash ref)
					"expected_hash": "previous_hash", // notification.previous_hash → put.expected_hash
				},
				TransformOps: []types.ContinuationTransformOpData{
					// Resolve the hash from envelope.included to the full
					// entity bytes (v3.14 §4.2 + DOUBTS §9b).
					{Op: "deref_included", Field: "entity"},
				},
			},
			// No Params / ResultField — pass-through: the post-transform
			// value IS the put-request params.
		}
		if err := validate.InstallCrossPeerContinuation(ctx, dst.client, dst.client, mirrorInbox, mirror); err != nil {
			t.Fatalf("edge %s→%s install mirror cont: %v", src.name, dst.name, err)
		}

		// Subscribe on peer i with include_payload=true; delivery URI is
		// dst's mirror inbox. Each notification's envelope carries the
		// changed entity inline so the local continuation can apply it
		// without a cross-peer GET.
		deliverURI := "entity://" + dstID + "/" + mirrorInbox
		token, tokenSig, err := src.client.CreateDeliveryToken(deliverURI, "receive")
		if err != nil {
			t.Fatalf("edge %s→%s delivery token: %v", src.name, dst.name, err)
		}
		subID, _, _, err := src.client.SubscribeWithPayload(ctx, cyclePattern, deliverURI, "receive",
			token, tokenSig, []string{"created", "updated"}, nil, true)
		if err != nil || subID == "" {
			t.Fatalf("edge %s→%s subscribe: %v", src.name, dst.name, err)
		}
		t.Logf("ring edge %s→%s wired (sub=%s)", src.name, dst.name, subID)
	}

	// Drive sustained writes at A.
	const writes = 20
	for w := 0; w < writes; w++ {
		ent, err := entity.NewEntity("test/cycle-doc", cbor.RawMessage(mustEnc(map[string]interface{}{
			"seq":     w,
			"content": fmt.Sprintf("cycle-write-%d", w),
		})))
		if err != nil {
			t.Fatalf("write %d build: %v", w, err)
		}
		if _, err := ring[0].client.TreePut(ctx, cycleDocPath, ent); err != nil {
			t.Fatalf("write %d on A: %v", w, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Logf("drove %d sustained writes at A", writes)

	// (ii) Eventual propagation: a write at A must reach all four peers'
	// shared prefix. Poll with a bounded deadline.
	for i := 0; i < n; i++ {
		if !waitNonEmpty(ctx, t, ring[i].client, cycleDocPath, 30*time.Second) {
			t.Fatalf("propagation: peer %s never received a write on %s", names[i], cycleDocPath)
		}
		t.Logf("propagation: peer %s has %s", names[i], cycleDocPath)
	}

	// With writes stopped, propagation must quiesce — observer counts stop
	// growing — as the verbatim-relay cycle converges via no-op suppression
	// (cascade-depth backstop behind it). If counts never stabilize the cycle
	// is unbounded (the regression this canary guards against) and the
	// surrounding context deadline turns it into a clear failure. The
	// amplification-factor assertion below is the sharp signal.
	if !waitQuiescent(ctx, t, ring, 5, 600*time.Millisecond) {
		t.Fatalf("cycle did not quiesce within deadline: the cross-peer feedback loop is not terminating (no-op suppression broken AND cascade-depth backstop not firing) — unbounded propagation")
	}

	// (iii) Bounded amplification — convergent_mirror canonical gate
	// (PROPOSAL-CONVERGENT-MIRRORING §5): total laps per peer MUST be
	// ≤ 1.5 × external_writes. With writes=20 the per-peer cap is 30.
	// The unconditional-PUT regression produced ~87 laps/write per peer.
	// CAS-on-tree:put kills the amplification: stale laps fail CAS (409)
	// and die instead of rolling state back and re-firing forward.
	maxPerPeer := int64(float64(writes) * 1.5)
	total := int64(0)
	for i := 0; i < n; i++ {
		c := ring[i].observed.Load()
		total += c
		t.Logf("peer %s observed %d settled cycle writes (%d external writes; gate ≤ %d)",
			names[i], c, writes, maxPerPeer)
		if c > maxPerPeer {
			t.Errorf("peer %s exceeded convergent_mirror gate: %d settled writes for %d external (cap = 1.5×N = %d) — CAS recipe failing to terminate stale laps",
				names[i], c, writes, maxPerPeer)
		}
	}
	t.Logf("ring quiesced; total observed = %d, amplification ~= %.2f laps/write (gate: ≤ 1.5)",
		total, float64(total)/float64(writes*n))

	// (iv) Finite drop counters: read twice across a settle window; nothing
	// may grow once the ring has quiesced.
	type snap struct {
		bufDrops    uint64
		fanOut      []uint64
		delivery    uint64
		asyncRefuse uint64
	}
	read := func() []snap {
		s := make([]snap, n)
		for i := 0; i < n; i++ {
			st := ring[i].peer.Stats()
			s[i] = snap{
				bufDrops:    st.EventBufferDrops,
				fanOut:      st.FanOutSinks,
				delivery:    ring[i].engine.DroppedDeliveries(),
				asyncRefuse: st.AsyncDispatchRefused,
			}
		}
		return s
	}
	before := read()
	time.Sleep(2 * time.Second)
	after := read()
	for i := 0; i < n; i++ {
		if after[i].bufDrops != before[i].bufDrops {
			t.Errorf("peer %s EventBufferDrops still growing after quiescence: %d → %d",
				names[i], before[i].bufDrops, after[i].bufDrops)
		}
		if after[i].delivery != before[i].delivery {
			t.Errorf("peer %s DroppedDeliveries still growing after quiescence: %d → %d",
				names[i], before[i].delivery, after[i].delivery)
		}
		if after[i].asyncRefuse != before[i].asyncRefuse {
			t.Errorf("peer %s AsyncDispatchRefused still growing after quiescence: %d → %d",
				names[i], before[i].asyncRefuse, after[i].asyncRefuse)
		}
		for s := range after[i].fanOut {
			if s < len(before[i].fanOut) && after[i].fanOut[s] != before[i].fanOut[s] {
				t.Errorf("peer %s fan-out sink[%d] still growing after quiescence: %d → %d",
					names[i], s, before[i].fanOut[s], after[i].fanOut[s])
			}
		}
		t.Logf("peer %s drop counters (steady): bufDrops=%d delivery=%d asyncRefused=%d fanOut=%v",
			names[i], after[i].bufDrops, after[i].delivery, after[i].asyncRefuse, after[i].fanOut)
	}
}

func mustEnc(v interface{}) []byte {
	b, err := ecf.Encode(v)
	if err != nil {
		panic(err)
	}
	return b
}

// waitNonEmpty polls path on the peer until it holds an entity or the
// deadline elapses.
func waitNonEmpty(ctx context.Context, t *testing.T, c *validate.PeerClient, path string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		ent, _, err := c.TreeGet(ctx, path)
		if err == nil && !ent.ContentHash.IsZero() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// waitQuiescent returns true once the summed observer count across the ring
// is unchanged for `stableSamples` consecutive samples (the cycle has
// terminated), or false if the context deadline elapses first.
func waitQuiescent(ctx context.Context, t *testing.T, ring []*ringPeer, stableSamples int, interval time.Duration) bool {
	t.Helper()
	sum := func() int64 {
		var s int64
		for _, rp := range ring {
			s += rp.observed.Load()
		}
		return s
	}
	last := int64(-1)
	stable := 0
	for {
		if ctx.Err() != nil {
			return false
		}
		cur := sum()
		if cur == last {
			stable++
			if stable >= stableSamples {
				return true
			}
		} else {
			stable = 0
			last = cur
		}
		time.Sleep(interval)
	}
}
