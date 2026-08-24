package network

// In-process two-peer vectors for the §4.1 maintain-peer reconnect
// lifecycle (EXTENSION-NETWORK Amendment 12 rung 3). These double as the Go
// shape for PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-MUST §4's reconnect-
// chain vectors — rung 3 is the proposal's named "natural test subject":
// the reconnect-failure path MUST leave lost-error markers (no-on_error
// forward non-2xx) bound under the continuation handler's own authority.

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/continuation"
	"go.entitychurch.org/entity-core-go/ext/inbox"
	"go.entitychurch.org/entity-core-go/ext/subscription"

	"github.com/fxamacker/cbor/v2"
)

// opRecorder collects dispatched operation names (entry phase).
type opRecorder struct {
	mu  sync.Mutex
	ops []string
}

func (r *opRecorder) record(evt handler.DispatchEvent) {
	if evt.Phase != handler.DispatchEntry {
		return
	}
	r.mu.Lock()
	r.ops = append(r.ops, evt.Operation)
	r.mu.Unlock()
}

func (r *opRecorder) count(op string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, o := range r.ops {
		if o == op {
			n++
		}
	}
	return n
}

// lifecyclePeer is one full-featured test peer: inbox + continuation +
// subscription (engine + delivery) + network, listening on TCP.
type lifecyclePeer struct {
	p       *peer.Peer
	h       *Handler
	rec     *opRecorder
	stopped bool
	stop    func()
}

// startLifecyclePeer builds and starts a peer with the whole reactive stack
// wired — the same composition cmd/entity-peer ships, minus the unrelated
// extensions. listenAddr may be "127.0.0.1:0" or a fixed address (restart
// vectors reuse the port and keypair).
func startLifecyclePeer(t *testing.T, kp crypto.Keypair, listenAddr string, kcfg *types.KeepaliveConfigData) *lifecyclePeer {
	t.Helper()

	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	engine := subscription.NewEngine(cs, li, nil)
	engineCtx, cancelEngine := context.WithCancel(context.Background())

	networkH := NewHandler()
	rec := &opRecorder{}

	opts := []peer.Option{
		peer.WithIdentity(kp),
		peer.WithStore(cs),
		peer.WithLocationIndex(li),
		peer.WithListenAddr(listenAddr),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
		peer.WithTreeEventBuffer(64),
		peer.WithHandler("system/inbox", inbox.NewHandler()),
		peer.WithHandler("system/continuation", continuation.NewHandler()),
		peer.WithHandler("system/subscription", subscription.NewHandler(engine)),
		peer.WithHandler(HandlerPattern, networkH),
		peer.WithNamedSyncHook("subscription/notification", engine.OnTreeChange),
		peer.WithDispatchHook("test/op-recorder", rec.record),
		peer.WithCloseFunc(cancelEngine),
	}
	if kcfg != nil {
		opts = append(opts, peer.WithKeepaliveConfig(*kcfg))
	}

	p, err := peer.New(opts...)
	if err != nil {
		t.Fatal(err)
	}

	engine.SetLocationIndex(p.LocationIndex())
	engine.Deliver = subscription.MakeDeliveryFunc(
		p.Keypair(), p.Identity(), p.Store(), p.LocationIndex(), p.Dispatcher())
	engine.StartDelivery(engineCtx)

	networkH.Bind(p)

	listenCtx, cancelListen := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go func() { p.ListenReady(listenCtx, ready) }()
	<-ready

	lp := &lifecyclePeer{p: p, h: networkH, rec: rec}
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

// execNetworkOp drives a system/network operation on lp through the full
// wire-entry dispatch path (self-authored; §3.2 admin posture).
func execNetworkOp(t *testing.T, lp *lifecyclePeer, operation string, params entity.Entity) (uint, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, result, err := lp.h.selfExecute(ctx, HandlerPattern, operation, params,
		&types.ResourceTarget{Targets: []string{HandlerPattern}})
	if err != nil {
		t.Fatalf("%s dispatch: %v", operation, err)
	}
	return status, result
}

// mustEntity converts a typed payload into its entity.
func mustEntity(t *testing.T, data interface {
	ToEntity() (entity.Entity, error)
}) entity.Entity {
	t.Helper()
	ent, err := data.ToEntity()
	if err != nil {
		t.Fatalf("build params entity: %v", err)
	}
	return ent
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// statusOf reads lp's §3.13 status entity for remote, if present.
func statusOf(t *testing.T, lp *lifecyclePeer, remote crypto.PeerID) (string, bool) {
	t.Helper()
	remoteHash, err := types.ComputePeerIdentityHashFromPeerID(remote)
	if err != nil {
		t.Fatalf("derive remote hash: %v", err)
	}
	h, ok := lp.p.LocationIndex().Get(types.PeerStatusPath(string(lp.p.PeerID()), remoteHash))
	if !ok {
		return "", false
	}
	ent, ok := lp.p.Store().Get(h)
	if !ok {
		return "", false
	}
	d, err := types.PeerStatusDataFromEntity(ent)
	if err != nil {
		return "", false
	}
	return d.Status, true
}

// freeTCPAddr reserves a port on 127.0.0.1 and releases it for reuse.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// shortKeepalive makes §5.4 failure detection land within ~1s.
func shortKeepalive() *types.KeepaliveConfigData {
	interval, timeout, missed := uint64(200), uint64(150), uint64(1)
	return &types.KeepaliveConfigData{IntervalMs: &interval, TimeoutMs: &timeout, MaxMissed: &missed}
}

// TestMaintainPeerEstablishesGraph: the §4.1 happy path — connect, install
// the three-continuation graph + two lifecycle subscriptions, return
// session info.
func TestMaintainPeerEstablishesGraph(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startLifecyclePeer(t, kpB, "127.0.0.1:0", nil)

	status, result := execNetworkOp(t, a, "maintain-peer", mustEntity(t, types.MaintainRequestData{
		PeerID:  string(b.p.PeerID()),
		Address: b.p.Addr().String(),
	}))
	if status != 200 {
		t.Fatalf("maintain-peer returned %d (%s)", status, string(result))
	}
	var res types.MaintainResultData
	if err := ecf.Decode(result, &res); err != nil {
		t.Fatalf("decode maintain-result: %v", err)
	}
	if res.PeerID != string(b.p.PeerID()) || res.SessionID == "" || res.ChainID == "" {
		t.Fatalf("maintain-result incomplete: %+v", res)
	}
	if len(res.Subscriptions) != 2 {
		t.Fatalf("expected 2 lifecycle subscriptions, got %v", res.Subscriptions)
	}
	if !strings.HasPrefix(res.ChainID, "network/maintain/") {
		t.Fatalf("chain_id %q lacks the network/maintain/ scheme", res.ChainID)
	}

	// The graph is in the tree: two inbox residents + the managed-namespace
	// backoff resident, all system/continuation entities carrying the
	// handler grant as dispatch_capability (§11 / F2 pattern).
	grantHash, ok := a.p.LocationIndex().Get("system/capability/grants/" + HandlerPattern)
	if !ok {
		t.Fatal("network handler grant not bound")
	}
	for _, path := range []string{
		onDisconnectPath(b.p.PeerID()),
		onReconnectPath(b.p.PeerID()),
		backoffPath(b.p.PeerID()),
	} {
		ch, ok := a.p.LocationIndex().Get(path)
		if !ok {
			t.Fatalf("no continuation bound at %s", path)
		}
		ent, ok := a.p.Store().Get(ch)
		if !ok || ent.Type != types.TypeContinuation {
			t.Fatalf("entity at %s is %q, want system/continuation", path, ent.Type)
		}
		cd, err := types.ContinuationDataFromEntity(ent)
		if err != nil {
			t.Fatalf("decode continuation at %s: %v", path, err)
		}
		if cd.DispatchCapability != grantHash {
			t.Fatalf("continuation at %s rides cap %s, want the handler grant %s (§11)",
				path, cd.DispatchCapability, grantHash)
		}
		if cd.OnError != nil && strings.HasPrefix(cd.OnError.URI, "system/inbox/") {
			t.Fatalf("continuation at %s routes on_error to %s — marker-proposal §5 forbids system/inbox/* targets",
				path, cd.OnError.URI)
		}
	}

	// Both ends observe connected (§A3 establish writes).
	waitFor(t, 3*time.Second, "A sees B connected", func() bool {
		s, ok := statusOf(t, a, b.p.PeerID())
		return ok && s == types.PeerStatusConnected
	})

	// Idempotent re-entry: same params, same session.
	status2, result2 := execNetworkOp(t, a, "maintain-peer", mustEntity(t, types.MaintainRequestData{
		PeerID:  string(b.p.PeerID()),
		Address: b.p.Addr().String(),
	}))
	if status2 != 200 {
		t.Fatalf("maintain-peer re-entry returned %d", status2)
	}
	var res2 types.MaintainResultData
	if err := ecf.Decode(result2, &res2); err != nil {
		t.Fatal(err)
	}
	if res2.SessionID != res.SessionID {
		t.Fatalf("re-entry minted a new session: %s → %s", res.SessionID, res2.SessionID)
	}
}

// TestRestoreSubscriptionsDropsForeignDeadToken is the convergence-pass
// regression for the §7.2 drop mechanism: a subscription DELIVERING TO the
// reconnected peer is owned by the REMOTE identity, so it must be dropped by
// a direct handler-authorized tree delete — a self-authored `unsubscribe`
// would 403 (`not_subscription_owner`). entity-core-py surfaced this; the
// original Go build's happy-path vector never seeded a foreign-subscriber
// dead-token sub, so the 403 hid.
func TestRestoreSubscriptionsDropsForeignDeadToken(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startLifecyclePeer(t, kpB, "127.0.0.1:0", nil)
	bID := b.p.PeerID()

	if status, _ := execNetworkOp(t, a, "maintain-peer", mustEntity(t, types.MaintainRequestData{
		PeerID:  string(bID),
		Address: b.p.Addr().String(),
	})); status != 200 {
		t.Fatalf("maintain-peer returned %d", status)
	}
	waitFor(t, 3*time.Second, "connected", func() bool {
		s, ok := statusOf(t, a, bID)
		return ok && s == types.PeerStatusConnected
	})

	// Seed a dead subscription owned by a FOREIGN identity (a third
	// keypair, not A), delivering to B, with a deliver_token hash that is
	// not in A's store (→ token missing → dead per §7.2).
	kpForeign, _ := crypto.Generate()
	foreignHash, err := types.ComputePeerIdentityHashFromPeerID(kpForeign.PeerID())
	if err != nil {
		t.Fatal(err)
	}
	deadTokenHash := mustEntity(t, types.MaintainRequestData{PeerID: string(bID)}).ContentHash // any hash NOT a stored token
	seeded := types.SubscriptionData{
		SubscriptionID:     "dead-foreign-sub",
		Pattern:            "/" + string(a.p.PeerID()) + "/data/*",
		Events:             []string{"updated"},
		DeliverURI:         "entity://" + string(bID) + "/system/inbox/x",
		DeliverOperation:   "receive",
		SubscriberIdentity: foreignHash,
		DeliverToken:       deadTokenHash,
	}
	seededEnt, err := seeded.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.p.Store().Put(seededEnt); err != nil {
		t.Fatal(err)
	}
	if err := a.p.LocationIndex().Set("system/subscription/dead-foreign-sub", seededEnt.ContentHash); err != nil {
		t.Fatal(err)
	}

	// Directly dispatch the internal restore-subscriptions op (the same op
	// the on-reconnect leg fires), then assert the dead foreign sub is gone.
	restoreRaw, _ := ecf.Encode(map[string]interface{}{"peer_id": string(bID)})
	restoreParams, _ := entity.NewEntity("primitive/any", cbor.RawMessage(restoreRaw))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, result, err := a.h.selfExecute(ctx, HandlerPattern, "restore-subscriptions", restoreParams,
		&types.ResourceTarget{Targets: []string{HandlerPattern}})
	if err != nil {
		t.Fatalf("restore-subscriptions dispatch: %v", err)
	}
	if status != 200 {
		t.Fatalf("restore-subscriptions returned %d (%s)", status, string(result))
	}
	var rr struct {
		Dropped int `cbor:"dropped"`
	}
	_ = ecf.Decode(result, &rr)
	if rr.Dropped < 1 {
		t.Fatalf("restore-subscriptions dropped %d, want ≥1 — the foreign-subscriber dead sub was not removed (403 regression)", rr.Dropped)
	}
	if _, ok := a.p.LocationIndex().Get("system/subscription/dead-foreign-sub"); ok {
		t.Fatal("dead foreign-owned subscription still bound after restore-subscriptions")
	}
}

// TestMaintainPeerConnectFailure: first imperative call to an unreachable
// peer → 502 connection_failed, no graph, no session (§4.1 step 1).
func TestMaintainPeerConnectFailure(t *testing.T) {
	kpA, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	kpGhost, _ := crypto.Generate()
	ghostID := kpGhost.PeerID()

	status, result := execNetworkOp(t, a, "maintain-peer", mustEntity(t, types.MaintainRequestData{
		PeerID:  string(ghostID),
		Address: freeTCPAddr(t), // nothing listens here
	}))
	if status != 502 {
		t.Fatalf("expected 502 connection_failed, got %d (%s)", status, string(result))
	}
	var ed types.ErrorData
	if err := ecf.Decode(result, &ed); err != nil || ed.Code != "connection_failed" {
		t.Fatalf("expected code connection_failed, got %q", ed.Code)
	}
	if a.h.getSession(ghostID) != nil {
		t.Fatal("failed first maintain-peer left a session behind")
	}
	if _, ok := a.p.LocationIndex().Get(onDisconnectPath(ghostID)); ok {
		t.Fatal("failed first maintain-peer installed the graph")
	}
}

// TestReconnectLifecycle is the rung-3 anchor vector: establish → kill the
// remote → the floor demotes → the graph reconnects through backoff retries
// against the restarted peer → status returns to connected and
// restore-subscriptions ran. The failed attempts MUST leave §3.10
// lost-error markers (the marker-proposal §4 reconnect-chain evidence).
func TestReconnectLifecycle(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	fixedAddr := freeTCPAddr(t)

	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", shortKeepalive())
	b := startLifecyclePeer(t, kpB, fixedAddr, nil)
	bID := b.p.PeerID()

	minMs, maxMs := uint64(100), uint64(400)
	status, _ := execNetworkOp(t, a, "maintain-peer", mustEntity(t, types.MaintainRequestData{
		PeerID:  string(bID),
		Address: fixedAddr,
		Backoff: &types.BackoffConfigData{MinMs: &minMs, MaxMs: &maxMs},
	}))
	if status != 200 {
		t.Fatalf("maintain-peer returned %d", status)
	}
	waitFor(t, 3*time.Second, "connected baseline", func() bool {
		s, ok := statusOf(t, a, bID)
		return ok && s == types.PeerStatusConnected
	})

	// Kill B. A's §5.4 keepalive (or the read-loop error) demotes; the
	// lifecycle subscription fires the on-disconnect continuation.
	b.stop()
	waitFor(t, 10*time.Second, "demotion after kill", func() bool {
		s, ok := statusOf(t, a, bID)
		return ok && s != types.PeerStatusConnected
	})

	// The graph is now retrying against a dead address: reconnect dispatches
	// happen and failures land as lost-error markers (no-on_error forward
	// non-2xx, keyed by RequestID).
	waitFor(t, 10*time.Second, "reconnect dispatch", func() bool {
		return a.rec.count("reconnect") >= 1
	})
	waitFor(t, 10*time.Second, "lost-error marker from failed reconnect", func() bool {
		return len(a.p.LocationIndex().List("system/runtime/chain-errors/lost/")) >= 1
	})

	// Restart B: same keypair, same port — the retry loop must find it and
	// re-establish without operator involvement.
	b2 := startLifecyclePeer(t, kpB, fixedAddr, nil)
	_ = b2
	waitFor(t, 15*time.Second, "re-established after restart", func() bool {
		s, ok := statusOf(t, a, bID)
		return ok && s == types.PeerStatusConnected
	})

	// The on-reconnect leg fired restore-subscriptions (§7.2), and the
	// lifecycle subscriptions survived the outage.
	waitFor(t, 10*time.Second, "restore-subscriptions dispatch", func() bool {
		return a.rec.count("restore-subscriptions") >= 1
	})
	subs := 0
	for _, entry := range a.p.LocationIndex().List("system/subscription/") {
		if ent, ok := a.p.Store().Get(entry.Hash); ok && ent.Type == types.TypeSubscription {
			subs++
		}
	}
	if subs != 2 {
		t.Fatalf("expected the 2 lifecycle subscriptions to survive, found %d", subs)
	}

	// The backoff loop settled: attempt counter reset on success.
	sess := a.h.getSession(bID)
	if sess == nil {
		t.Fatal("session lost across the outage")
	}
	sess.mu.Lock()
	attempt := sess.attempt
	sess.mu.Unlock()
	if attempt != 0 {
		t.Fatalf("attempt counter %d after successful re-establish, want 0", attempt)
	}
	// The retry re-entered maintain-peer at least once (the backoff
	// continuation's re-EXECUTE).
	if a.rec.count("maintain-peer") < 2 {
		t.Fatalf("expected backoff re-EXECUTE of maintain-peer, saw %d dispatches", a.rec.count("maintain-peer"))
	}
}

// TestReleasePeer tears down the graph: continuations deleted (real tree
// deletion), lifecycle subscriptions unsubscribed, terminal disconnected
// write on reason=shutdown (§4.2).
func TestReleasePeer(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startLifecyclePeer(t, kpB, "127.0.0.1:0", nil)
	bID := b.p.PeerID()

	if status, _ := execNetworkOp(t, a, "maintain-peer", mustEntity(t, types.MaintainRequestData{
		PeerID:  string(bID),
		Address: b.p.Addr().String(),
	})); status != 200 {
		t.Fatalf("maintain-peer returned %d", status)
	}

	status, result := execNetworkOp(t, a, "release-peer", mustEntity(t, types.ReleaseRequestData{
		PeerID: string(bID),
	}))
	if status != 200 {
		t.Fatalf("release-peer returned %d (%s)", status, string(result))
	}
	var res types.ReleaseResultData
	if err := ecf.Decode(result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.CleanedUp) != 3 {
		t.Fatalf("expected 3 cleaned-up continuation paths, got %v", res.CleanedUp)
	}
	for _, path := range []string{
		onDisconnectPath(bID), onReconnectPath(bID), backoffPath(bID),
	} {
		if _, ok := a.p.LocationIndex().Get(path); ok {
			t.Fatalf("continuation still bound at %s after release", path)
		}
	}
	for _, entry := range a.p.LocationIndex().List("system/subscription/") {
		if ent, ok := a.p.Store().Get(entry.Hash); ok && ent.Type == types.TypeSubscription {
			t.Fatalf("lifecycle subscription %s survived release", entry.Path)
		}
	}
	if a.h.getSession(bID) != nil {
		t.Fatal("session survived release")
	}
	waitFor(t, 3*time.Second, "terminal disconnected write", func() bool {
		s, ok := statusOf(t, a, bID)
		return ok && s == types.PeerStatusDisconnected
	})
}

// TestStatusOp: the §4.3 read-model over the §3.13 entities. pending_count
// is bare zero (no §8 outbox, Amendment 11).
func TestStatusOp(t *testing.T) {
	kpA, _ := crypto.Generate()
	kpB, _ := crypto.Generate()
	a := startLifecyclePeer(t, kpA, "127.0.0.1:0", nil)
	b := startLifecyclePeer(t, kpB, "127.0.0.1:0", nil)
	bID := b.p.PeerID()

	status, result := execNetworkOp(t, a, "maintain-peer", mustEntity(t, types.MaintainRequestData{
		PeerID:  string(bID),
		Address: b.p.Addr().String(),
	}))
	if status != 200 {
		t.Fatalf("maintain-peer returned %d", status)
	}
	var mres types.MaintainResultData
	if err := ecf.Decode(result, &mres); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	emptyRaw, _ := ecf.Encode(map[string]interface{}{})
	emptyParams, _ := entity.NewEntity("primitive/any", cbor.RawMessage(emptyRaw))
	sstatus, sresult, err := a.h.selfExecute(ctx, HandlerPattern, "status", emptyParams,
		&types.ResourceTarget{Targets: []string{HandlerPattern}})
	if err != nil {
		t.Fatalf("status dispatch: %v", err)
	}
	if sstatus != 200 {
		t.Fatalf("status returned %d (%s)", sstatus, string(sresult))
	}
	var sd types.NetworkStatusData
	if err := ecf.Decode(sresult, &sd); err != nil {
		t.Fatal(err)
	}
	if sd.PendingCount != 0 {
		t.Fatalf("pending_count = %d, want bare zero (no §8 outbox)", sd.PendingCount)
	}
	var row *types.NetworkPeerSummaryData
	for i := range sd.MaintainedPeers {
		if sd.MaintainedPeers[i].PeerID == string(bID) {
			row = &sd.MaintainedPeers[i]
		}
	}
	if row == nil {
		t.Fatalf("status omitted maintained peer %s: %+v", bID, sd.MaintainedPeers)
	}
	if row.SessionID != mres.SessionID {
		t.Fatalf("status session_id %q, want %q", row.SessionID, mres.SessionID)
	}
	if row.Status != types.PeerStatusConnected {
		t.Fatalf("status row shows %q, want connected", row.Status)
	}
	if row.PendingCount != 0 {
		t.Fatalf("per-peer pending_count = %d, want 0", row.PendingCount)
	}
}
