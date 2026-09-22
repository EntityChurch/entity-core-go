package peer

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// fakeEndpoint is a minimal remoteEndpoint for exercising the §A1 no-clobber
// guard without a network. It is deliberately NOT a *Connection, so the
// reentry branch of demotePeerOnTransportError is skipped and only the pooled-
// binding guard is under test.
type fakeEndpoint struct{ closed bool }

func (f *fakeEndpoint) Execute(context.Context, string, string, entity.Entity, *types.ResourceTarget, ...*protocol.AsyncDelivery) (entity.Envelope, error) {
	return entity.Envelope{}, fmt.Errorf("fake endpoint")
}
func (f *fakeEndpoint) Close() error   { f.closed = true; return nil }
func (f *fakeEndpoint) IsClosed() bool { return f.closed }

// poolBind injects a fake endpoint as the bound outbound connection for a peer.
func poolBind(p *Peer, peerID crypto.PeerID, ep remoteEndpoint) {
	p.remote.mu.Lock()
	if p.remote.conns == nil {
		p.remote.conns = map[crypto.PeerID]remoteEndpoint{}
	}
	p.remote.conns[peerID] = ep
	p.remote.mu.Unlock()
}

func poolBound(p *Peer, peerID crypto.PeerID) (remoteEndpoint, bool) {
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	ep, ok := p.remote.conns[peerID]
	return ep, ok
}

// livenessStatusOf reads the system/peer/status entity `local` holds for
// `remote`, if any. Queries the absolute path (pass-through on the namespaced
// index), mirroring WritePeerStatus's write path.
func livenessStatusOf(t *testing.T, local, remote *Peer) (types.PeerStatusData, bool) {
	t.Helper()
	remoteHash, err := types.ComputePeerIdentityHashFromPeerID(remote.PeerID())
	if err != nil {
		t.Fatalf("derive remote identity hash: %v", err)
	}
	path := types.PeerStatusPath(string(local.PeerID()), remoteHash)
	h, ok := local.LocationIndex().Get(path)
	if !ok {
		return types.PeerStatusData{}, false
	}
	ent, ok := local.Store().Get(h)
	if !ok {
		return types.PeerStatusData{}, false
	}
	d, err := types.PeerStatusDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode peer-status entity: %v", err)
	}
	return d, true
}

// waitLivenessStatus polls until `local` holds a status entity for `remote`
// with the wanted status, or fails after the deadline. Used for the responder
// side, whose write settles as it produces the AUTHENTICATE response
// (asynchronous relative to the dialer's Connect return).
func waitLivenessStatus(t *testing.T, local, remote *Peer, want string) types.PeerStatusData {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		d, ok := livenessStatusOf(t, local, remote)
		if ok && d.Status == want {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("status for %s never reached %q (last: %+v, present=%v)", remote.PeerID(), want, d, ok)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLivenessConnectedOnEstablish is the Amendment 12 §A3 baseline: a
// completed handshake (§6.2) writes system/peer/status = connected on BOTH
// ends — the dialer synchronously in Connect, the responder as it grants the
// capability. This is the connected write everything else demotes from.
func TestLivenessConnectedOnEstablish(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t)

	ctx := context.Background()
	conn, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("perform connect: %v", err)
	}

	// Dialer side: written synchronously during Connect (before startReader).
	d, ok := livenessStatusOf(t, client, server)
	if !ok {
		t.Fatalf("dialer has no status entity for server after connect")
	}
	if d.Status != types.PeerStatusConnected {
		t.Fatalf("dialer status = %q, want %q", d.Status, types.PeerStatusConnected)
	}
	if d.PeerID != string(server.PeerID()) {
		t.Fatalf("dialer status peer_id = %q, want %q", d.PeerID, server.PeerID())
	}
	if d.Reason != "" || d.LastError != "" {
		t.Fatalf("connected status carried reason/last_error: %+v", d)
	}

	// Responder side: symmetric write as the server produces the grant.
	rd := waitLivenessStatus(t, server, client, types.PeerStatusConnected)
	if rd.PeerID != string(client.PeerID()) {
		t.Fatalf("responder status peer_id = %q, want %q", rd.PeerID, client.PeerID())
	}
}

// TestLivenessSuspectOnTransportError is the Amendment 12 §A1 anchor vector:
// a live two-peer session, drop one side, and the surviving side's
// system/peer/status flips connected → suspect (reason transport-error) the
// moment a dispatch over the dead pooled connection fails — the reactive
// demotion the whole reactive half composes on. The write is a plain tree
// entity, so a subscriber would see it with no poll.
func TestLivenessSuspectOnTransportError(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("some/path", "entity")

	// First dispatch: dials + handshakes through the outbound pool, so the
	// failing conn later is the pooled binding the no-clobber guard checks.
	// A 404 is fine — we only need the transport to succeed and pool the conn.
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err != nil {
		t.Fatalf("first remote execute (establish): %v", err)
	}
	baseline := waitLivenessStatus(t, client, server, types.PeerStatusConnected)
	if baseline.Reason != "" {
		t.Fatalf("connected baseline carried reason %q", baseline.Reason)
	}

	// Drop the server. The client's pooled connection is now dead, but the
	// pool still hands it out (the "browse over a dead pool" symptom).
	server.Close()

	// Next dispatch fails at the transport → §A1 demotion fires.
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err == nil {
		t.Fatalf("expected transport error dispatching over dropped server")
	}

	// The surviving side flipped to suspect with the transport-error reason.
	d, ok := livenessStatusOf(t, client, server)
	if !ok {
		t.Fatalf("client lost status entity for server after demotion")
	}
	if d.Status != types.PeerStatusSuspect {
		t.Fatalf("status = %q, want %q", d.Status, types.PeerStatusSuspect)
	}
	if d.Reason != types.PeerStatusReasonTransportError {
		t.Fatalf("reason = %q, want %q", d.Reason, types.PeerStatusReasonTransportError)
	}
	if d.LastError == "" {
		t.Fatalf("suspect status should carry a coded last_error")
	}
	if d.PeerID != string(server.PeerID()) {
		t.Fatalf("status peer_id = %q, want %q", d.PeerID, server.PeerID())
	}
}

// remoteFixture generates a resolvable remote peer identity for guard tests.
func remoteFixture(t *testing.T) crypto.PeerID {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate remote keypair: %v", err)
	}
	return kp.PeerID()
}

// TestLivenessDemotionNoClobber pins the §A1 no-clobber MUST: a stale failed
// connection must NOT demote liveness when a different connection is currently
// bound for the peer (a concurrent re-establishment that already wrote its own
// connected). The Arc::ptr_eq precedent.
func TestLivenessDemotionNoClobber(t *testing.T) {
	p := startPeer(t)
	remotePeerID := remoteFixture(t)
	remoteHash, err := protocol.ResolveRemoteIdentityHash(remotePeerID, nil)
	if err != nil {
		t.Fatalf("resolve remote hash: %v", err)
	}

	stale := &fakeEndpoint{}
	live := &fakeEndpoint{}

	// A live re-establishment is the current binding and wrote connected.
	poolBind(p, remotePeerID, live)
	if _, err := protocol.WritePeerStatus(p.Store(), p.LocationIndex(),
		string(p.PeerID()), remoteHash,
		types.PeerStatusData{PeerID: string(remotePeerID), Status: types.PeerStatusConnected}); err != nil {
		t.Fatalf("seed connected: %v", err)
	}

	// The stale conn fails and tries to demote. Guard must skip.
	p.demotePeerOnTransportError(remotePeerID, stale, fmt.Errorf("stale write failed"))

	h, ok := p.LocationIndex().Get(types.PeerStatusPath(string(p.PeerID()), remoteHash))
	if !ok {
		t.Fatalf("status entity vanished")
	}
	ent, _ := p.Store().Get(h)
	d, _ := types.PeerStatusDataFromEntity(ent)
	if d.Status != types.PeerStatusConnected {
		t.Fatalf("stale demotion clobbered live connected: status = %q", d.Status)
	}
	// The live binding must be untouched (not closed, still pooled).
	if bound, ok := poolBound(p, remotePeerID); !ok || bound != live {
		t.Fatalf("stale demotion evicted the live binding")
	}
	if live.closed {
		t.Fatalf("stale demotion closed the live connection")
	}
}

// TestLivenessDemotionIdempotent pins idempotency under concurrent re-entry:
// many goroutines observing the SAME failed connection must produce exactly one
// demotion, no panic, ending at suspect with the failed conn evicted.
func TestLivenessDemotionIdempotent(t *testing.T) {
	p := startPeer(t)
	remotePeerID := remoteFixture(t)
	remoteHash, err := protocol.ResolveRemoteIdentityHash(remotePeerID, nil)
	if err != nil {
		t.Fatalf("resolve remote hash: %v", err)
	}

	failed := &fakeEndpoint{}
	poolBind(p, remotePeerID, failed)
	if _, err := protocol.WritePeerStatus(p.Store(), p.LocationIndex(),
		string(p.PeerID()), remoteHash,
		types.PeerStatusData{PeerID: string(remotePeerID), Status: types.PeerStatusConnected}); err != nil {
		t.Fatalf("seed connected: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.demotePeerOnTransportError(remotePeerID, failed, fmt.Errorf("concurrent transport error"))
		}()
	}
	wg.Wait()

	h, ok := p.LocationIndex().Get(types.PeerStatusPath(string(p.PeerID()), remoteHash))
	if !ok {
		t.Fatalf("status entity vanished")
	}
	ent, _ := p.Store().Get(h)
	d, _ := types.PeerStatusDataFromEntity(ent)
	if d.Status != types.PeerStatusSuspect || d.Reason != types.PeerStatusReasonTransportError {
		t.Fatalf("expected suspect/transport-error, got %q/%q", d.Status, d.Reason)
	}
	if _, ok := poolBound(p, remotePeerID); ok {
		t.Fatalf("failed conn should be evicted from the pool")
	}
}

// connectionStateOf reads the §3.13 system/connection entity `local` holds
// for `remote`, if any.
func connectionStateOf(t *testing.T, local, remote *Peer) (types.ConnectionData, bool) {
	t.Helper()
	remoteHash, err := types.ComputePeerIdentityHashFromPeerID(remote.PeerID())
	if err != nil {
		t.Fatalf("derive remote identity hash: %v", err)
	}
	h, ok := local.LocationIndex().Get(types.ConnectionPath(string(local.PeerID()), remoteHash))
	if !ok {
		return types.ConnectionData{}, false
	}
	ent, ok := local.Store().Get(h)
	if !ok {
		return types.ConnectionData{}, false
	}
	d, err := types.ConnectionDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode connection entity: %v", err)
	}
	return d, true
}

// TestConnectionStateTransitions pins the ruling-C full-conformance surface:
// establish writes system/connection = active (transport + address recorded,
// referenced from the status entity's `connection` field), and the demotion
// seam flips it to closed WITHOUT losing the attachment record — §3.13
// write-on-transition, nothing per-activity.
func TestConnectionStateTransitions(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("some/path", "entity")
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err != nil {
		t.Fatalf("first remote execute (establish): %v", err)
	}

	cd, ok := connectionStateOf(t, client, server)
	if !ok {
		t.Fatalf("no system/connection entity after establish")
	}
	if cd.Status != types.ConnectionStatusActive {
		t.Fatalf("connection status = %q, want %q", cd.Status, types.ConnectionStatusActive)
	}
	if cd.Transport != "tcp" || cd.Address == "" || cd.EstablishedAt == 0 || cd.PeerID != string(server.PeerID()) {
		t.Fatalf("connection record incomplete: %+v", cd)
	}
	// The status entity references it (§3.13 `connection` path ref).
	sd := waitLivenessStatus(t, client, server, types.PeerStatusConnected)
	remoteHash, _ := types.ComputePeerIdentityHashFromPeerID(server.PeerID())
	if want := types.ConnectionPath(string(client.PeerID()), remoteHash); sd.Connection != want {
		t.Fatalf("status connection ref = %q, want %q", sd.Connection, want)
	}

	// Failure demotion → closed, attachment record preserved.
	server.Close()
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err == nil {
		t.Fatalf("expected transport error dispatching over dropped server")
	}
	closed, ok := connectionStateOf(t, client, server)
	if !ok {
		t.Fatalf("connection entity vanished on close")
	}
	if closed.Status != types.ConnectionStatusClosed {
		t.Fatalf("connection status after failure = %q, want %q", closed.Status, types.ConnectionStatusClosed)
	}
	if closed.Transport != cd.Transport || closed.Address != cd.Address || closed.EstablishedAt != cd.EstablishedAt {
		t.Fatalf("closed transition lost the attachment record:\n active %+v\n closed %+v", cd, closed)
	}
}

// u64 builds the pointer-typed optional config fields (§2.3).
func u64(v uint64) *uint64 { return &v }

// fastKeepalive returns a test-scale §2.3 config so the §5.4 loop escalates
// within milliseconds instead of the ~100 s production envelope.
func fastKeepalive(intervalMs, timeoutMs, maxMissed uint64) types.KeepaliveConfigData {
	return types.KeepaliveConfigData{
		IntervalMs: u64(intervalMs),
		TimeoutMs:  u64(timeoutMs),
		MaxMissed:  u64(maxMissed),
	}
}

// TestKeepalivePingPong pins the §5.1 exchange shape: EXECUTE
// system/protocol/connect op "ping" over an ESTABLISHED connection returns a
// system/network/pong echoing timestamp + sequence with the responder's
// server_time stamped. This is the wire vector the cohort converges on.
func TestKeepalivePingPong(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t)

	ctx := context.Background()
	conn, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("perform connect: %v", err)
	}

	ping, err := types.PingData{Timestamp: 1709740800000, Sequence: 42}.ToEntity()
	if err != nil {
		t.Fatalf("ping ToEntity: %v", err)
	}
	uri := fmt.Sprintf("entity://%s/system/protocol/connect", server.PeerID())
	env, err := conn.Execute(ctx, uri, "ping", ping, nil)
	if err != nil {
		t.Fatalf("ping execute: %v", err)
	}
	resp, err := decodeExecuteResponse(env, nil, nil)
	if err != nil {
		t.Fatalf("decode ping response: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("ping status = %d, want 200 (result: %+v)", resp.Status, resp.Result)
	}
	if resp.Result.Type != types.TypeNetworkPong {
		t.Fatalf("ping result type = %q, want %q", resp.Result.Type, types.TypeNetworkPong)
	}
	pong, err := types.PongDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode pong: %v", err)
	}
	if pong.Timestamp != 1709740800000 || pong.Sequence != 42 {
		t.Fatalf("pong did not echo ping: %+v", pong)
	}
	if pong.ServerTime == 0 {
		t.Fatalf("pong missing server_time")
	}
}

// TestLivenessDisconnectedOnKeepaliveMiss is the rung-2 anchor vector — the
// third §A3 write that completes the liveness floor: drop the remote, let
// the §5.4 keepalive loop run, and the survivor's system/peer/status
// escalates to disconnected (reason keepalive-miss) with the dead conn
// evicted, all within the interval×max_missed+timeout envelope, no poll and
// no dispatch traffic required (that is what distinguishes it from the
// rung-1 transport-error path, which needs a failed dispatch to observe).
func TestLivenessDisconnectedOnKeepaliveMiss(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
		WithKeepaliveConfig(fastKeepalive(40, 120, 2)),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("some/path", "entity")

	// Establish: dial + handshake through the outbound pool; the pool insert
	// starts the keepalive loop.
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err != nil {
		t.Fatalf("first remote execute (establish): %v", err)
	}
	waitLivenessStatus(t, client, server, types.PeerStatusConnected)

	// Drop the server and go idle: no dispatch ever touches the dead conn.
	// Only the keepalive loop can notice.
	server.Close()

	deadline := time.Now().Add(5 * time.Second)
	var d types.PeerStatusData
	for {
		var ok bool
		d, ok = livenessStatusOf(t, client, server)
		if ok && d.Status == types.PeerStatusDisconnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never escalated to disconnected (last: %+v)", d)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d.Reason != types.PeerStatusReasonKeepaliveMiss {
		t.Fatalf("reason = %q, want %q", d.Reason, types.PeerStatusReasonKeepaliveMiss)
	}
	if d.LastError == "" {
		t.Fatalf("keepalive-miss status should carry a coded last_error")
	}
	// §A4: the demotion write snapshots last_seen — the demotion's
	// evidence (the establish dispatch recorded an exchange).
	if d.LastSeen == 0 {
		t.Fatalf("demotion write should carry the last_seen transition snapshot: %+v", d)
	}
	if _, ok := poolBound(client, server.PeerID()); ok {
		t.Fatalf("dead conn should be evicted from the pool on keepalive miss")
	}
}

// TestLivenessEscalatesAfterTransportErrorEviction is the F-1 regression: the
// §5.4 `suspect → disconnected` escalation MUST still happen when the failure
// episode began at the §A1 transport seam rather than at an idle keepalive
// miss.
//
// The defect this pins was structural, not marginal. The §A1 demotion evicts
// the pooled binding as it writes `suspect`; the keepalive loop's lifetime was
// bound to that binding, so the loop that owes the escalation exited the moment
// the demotion fired. The peer then stayed `suspect` forever — the disconnect
// subscription never fired, so §4.1 reconnect never triggered, and the
// Amendment 12 §A3 consumer latency contract ("an idle-dead connection demotes
// within the keepalive envelope") was silently unmet on every
// transport-error-first path.
//
// It surfaced as a 1-in-4 flake on the conformance suite's
// `liveness_disconnected_on_keepalive_miss` (bimodal: ~6 s when the keepalive
// loop reached max_missed first, the full deadline when the transport seam won
// the race), which is exactly how a race between two paths to the same write
// reads from outside. Before the fix this test failed 100 % of the time — the
// in-process form removes the race and makes the defect deterministic.
func TestLivenessEscalatesAfterTransportErrorEviction(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
		WithKeepaliveConfig(fastKeepalive(40, 120, 2)),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("some/path", "entity")

	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err != nil {
		t.Fatalf("first remote execute (establish): %v", err)
	}
	waitLivenessStatus(t, client, server, types.PeerStatusConnected)

	// Kill the server and dispatch once: the §A1 seam writes suspect AND
	// evicts the pooled binding, which is the precondition under test.
	server.Close()
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err == nil {
		t.Fatalf("expected transport error dispatching over dropped server")
	}
	d, ok := livenessStatusOf(t, client, server)
	if !ok || d.Status != types.PeerStatusSuspect {
		t.Fatalf("precondition: want suspect after transport error, got %+v (present=%v)", d, ok)
	}
	if _, bound := poolBound(client, server.PeerID()); bound {
		t.Fatalf("precondition: the §A1 demotion should have evicted the pooled binding")
	}

	// No further dispatch: only the §5.4 grace path can move it from here.
	// Envelope is 40ms x 2 + 120ms = 200ms; 3s is ~15x that.
	deadline := time.Now().Add(3 * time.Second)
	for {
		d, _ = livenessStatusOf(t, client, server)
		if d.Status == types.PeerStatusDisconnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never escalated past %q/%q — the §5.4 escalation is orphaned by the §A1 eviction (last: %+v)", d.Status, d.Reason, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// §5.4a [MUST]: the escalation preserves the episode's ORIGINATING reason.
	// This episode began at the §A1 seam, so it stays transport-error — it is
	// NOT re-stamped to keepalive-miss, which would assert pings that were
	// never sent (the connection was gone before the loop could send one).
	if d.Reason != types.PeerStatusReasonTransportError {
		t.Fatalf("reason = %q, want %q — §5.4a: the escalation carries the reason the demotion that OPENED the episode wrote, not the timer that confirmed it", d.Reason, types.PeerStatusReasonTransportError)
	}
	// failing_since stamps the START of the episode — the transport error —
	// and the escalation must carry it forward, not re-stamp it.
	if d.FailingSince == 0 {
		t.Fatalf("escalation write lost failing_since: %+v", d)
	}
}

// TestLivenessNoEscalationWithoutFailureEpisode is the negative half of the
// F-1 fix: the grace path escalates ONLY from `suspect`. An evicted binding
// with no demotion behind it (the §10.2 dispatch-fallback and the RELAY
// terminal hop both evict WITHOUT demoting, per the §A1 scope pin) must not
// be turned into a `disconnected` write by the keepalive loop's teardown.
// Without this the fix would manufacture demotions on paths the spec
// explicitly excludes from the demotion seam.
//
// THIS TEST IS THE SATISFACTION MODE FOR A PINNED VECTOR, NOT A UNIT TEST.
// §5.4a [corrected 2026-08-12] pins NET-LIVENESS-NO-ESCALATION-WITHOUT-EPISODE-1
// and — because the state it needs is not constructible by a conformance
// client without RELAY — states that it is satisfied in-process, PROVIDED the
// implementation records a declared exclusion naming the mutation. Ours is
// `cmd/internal/validate/exclusions.go`, printed by every validate-peer run so
// no report can read as having covered this over the wire. The mutation: drop
// the `suspect` guard from the grace path and this test MUST fail. If you
// change either side, change the other — an exclusion that names a test that
// no longer fails under its mutation is worse than no exclusion at all.
func TestLivenessNoEscalationWithoutFailureEpisode(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
		WithKeepaliveConfig(fastKeepalive(40, 120, 2)),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("some/path", "entity")
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err != nil {
		t.Fatalf("first remote execute (establish): %v", err)
	}
	waitLivenessStatus(t, client, server, types.PeerStatusConnected)

	// Evict the binding directly, writing no status — the evict-only shape.
	client.remote.mu.Lock()
	delete(client.remote.conns, server.PeerID())
	client.remote.mu.Unlock()

	// Well past grace + interval: status must still be connected.
	time.Sleep(600 * time.Millisecond)
	d, ok := livenessStatusOf(t, client, server)
	if !ok {
		t.Fatalf("status entity disappeared")
	}
	if d.Status != types.PeerStatusConnected {
		t.Fatalf("status = %q (reason %q) after an evict-only unbind, want %q — the grace path escalated without a failure episode", d.Status, d.Reason, types.PeerStatusConnected)
	}
}

// TestLivenessNoEscalationMutationHasTeeth EXECUTES the mutation the declared
// exclusion names, rather than describing it.
//
// GUIDE-CONFORMANCE §5.2b.1, sharpened 2026-08-12 (d) to core-py's stronger
// form: a declared exclusion's mutation must be executed and dated, because
// a mutation that is only written down is a claim nobody checked — py's §5.5a
// control and its mutation test both ran against a malformed probe and
// neither could have failed. Our own version named the mutation and cited a
// manual run, which is the weaker form the rule now rejects.
//
// This runs the same scenario as the test above with the scope pin removed
// and asserts the escalation DOES fire. If this ever passes with the guard
// intact, or fails with it removed, the exclusion above is worthless and the
// negative half of NET-LIVENESS-NO-ESCALATION-WITHOUT-EPISODE-1 is unguarded.
func TestLivenessNoEscalationMutationHasTeeth(t *testing.T) {
	suspectScopeGuardDisabled = true
	t.Cleanup(func() { suspectScopeGuardDisabled = false })

	server := startPeer(t)
	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
		WithKeepaliveConfig(fastKeepalive(40, 120, 2)),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("some/path", "entity")
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err != nil {
		t.Fatalf("first remote execute (establish): %v", err)
	}
	waitLivenessStatus(t, client, server, types.PeerStatusConnected)

	client.remote.mu.Lock()
	delete(client.remote.conns, server.PeerID())
	client.remote.mu.Unlock()

	time.Sleep(600 * time.Millisecond)
	d, ok := livenessStatusOf(t, client, server)
	if !ok {
		t.Fatalf("status entity disappeared")
	}
	if d.Status != types.PeerStatusDisconnected {
		t.Fatalf("with the scope guard REMOVED the evict-only unbind still did not escalate (status %q) — the guard is not what makes the negative test pass, so that test cannot fail and the declared exclusion is empty", d.Status)
	}
}

// TestKeepaliveNoCadenceWrites pins §A4 (rung-2 ruling 1) as an invariant:
// the status entity is TRANSITION-written only. Keepalive successes update
// the impl-internal freshness bookkeeping (observable in-package via
// lastPeerActivity) but MUST NOT rewrite the tree entity — no last_seen
// cadence refresh, no subscriber fan-out, no CAS accretion on an idle
// healthy connection. This is the negative test replacing the rung-2
// cadence-refresh vector after arch ruled the refresh a spec defect.
func TestKeepaliveNoCadenceWrites(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
		WithKeepaliveConfig(fastKeepalive(30, 500, 3)),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("some/path", "entity")
	if _, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource); err != nil {
		t.Fatalf("first remote execute (establish): %v", err)
	}
	baseline := waitLivenessStatus(t, client, server, types.PeerStatusConnected)
	if baseline.ConnectedAt == 0 {
		t.Fatalf("establish write missing connected_at: %+v", baseline)
	}
	if baseline.LastSeen != 0 {
		t.Fatalf("connected establish write should not carry last_seen: %+v", baseline)
	}

	remoteHash, err := types.ComputePeerIdentityHashFromPeerID(server.PeerID())
	if err != nil {
		t.Fatalf("derive remote identity hash: %v", err)
	}
	statusPath := types.PeerStatusPath(string(client.PeerID()), remoteHash)
	h0, ok := client.LocationIndex().Get(statusPath)
	if !ok {
		t.Fatalf("no status binding after establish")
	}
	activity0, ok := client.lastPeerActivity(server.PeerID())
	if !ok {
		t.Fatalf("establish dispatch did not record activity")
	}

	// Wait until the in-memory freshness advances past the establish-time
	// mark — proof at least one keepalive pong landed (the impl-internal
	// bookkeeping §A4 keeps).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a, ok := client.lastPeerActivity(server.PeerID()); ok && a.After(activity0) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("keepalive success never advanced in-memory freshness")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Let several more keepalive intervals elapse so any (forbidden)
	// cadence write would have landed.
	time.Sleep(150 * time.Millisecond)

	h1, ok := client.LocationIndex().Get(statusPath)
	if !ok {
		t.Fatalf("status binding vanished")
	}
	if h1 != h0 {
		t.Fatalf("status entity rewritten at keepalive cadence — §A4: transition writes only (baseline %s, now %s)", h0, h1)
	}
}

// TestLivenessFailingSinceStampedOnceAndPreserved pins the `failing_since`
// contract: it marks the START of a failure episode, so it is stamped at the
// first demotion out of connected and carried forward by every later demotion
// write in the same episode.
//
// The escalation (suspect → disconnected) is the case that matters. Every
// demotion is a straight overwrite of the status entity, so a writer that
// simply filled the field in from `now` would silently re-stamp it here — and
// because the §2.2 pacing is DERIVED from failing_since, that would reset the
// backoff curve to min_ms every time a failing peer failed a little harder. The
// bug has no symptom at the write site; it only shows up as a peer that never
// backs off. Hence the assertion is on the value, not just its presence.
func TestLivenessFailingSinceStampedOnceAndPreserved(t *testing.T) {
	p := startPeer(t)
	remotePeerID := remoteFixture(t)
	remoteHash, err := protocol.ResolveRemoteIdentityHash(remotePeerID, nil)
	if err != nil {
		t.Fatalf("resolve remote hash: %v", err)
	}
	readStatus := func() types.PeerStatusData {
		t.Helper()
		d, ok := protocol.ReadPeerStatus(p.Store(), p.LocationIndex(), string(p.PeerID()), remoteHash)
		if !ok {
			t.Fatalf("status entity missing")
		}
		return d
	}

	// A connected baseline: no episode is in progress.
	conn := &fakeEndpoint{}
	poolBind(p, remotePeerID, conn)
	if _, err := protocol.WritePeerStatus(p.Store(), p.LocationIndex(),
		string(p.PeerID()), remoteHash,
		types.PeerStatusData{PeerID: string(remotePeerID), Status: types.PeerStatusConnected}); err != nil {
		t.Fatalf("seed connected: %v", err)
	}
	if d := readStatus(); d.FailingSince != 0 {
		t.Fatalf("connected baseline carries failing_since %d, want unset", d.FailingSince)
	}

	// First demotion opens the episode.
	before := uint64(time.Now().UnixMilli())
	p.demotePeerOnTransportError(remotePeerID, conn, fmt.Errorf("transport died"))
	after := uint64(time.Now().UnixMilli())

	suspect := readStatus()
	if suspect.Status != types.PeerStatusSuspect {
		t.Fatalf("status = %q, want %q", suspect.Status, types.PeerStatusSuspect)
	}
	if suspect.FailingSince < before || suspect.FailingSince > after {
		t.Fatalf("failing_since %d not stamped within the demotion window [%d, %d]",
			suspect.FailingSince, before, after)
	}
	episodeStart := suspect.FailingSince

	// Escalate. Re-bind because the demotion evicted the failed endpoint, and
	// let the clock advance so a re-stamp would be visible as a NEW value.
	time.Sleep(5 * time.Millisecond)
	conn2 := &fakeEndpoint{}
	poolBind(p, remotePeerID, conn2)
	if !p.demotePeerOnKeepaliveMiss(remotePeerID, conn2, fmt.Errorf("keepalive missed")) {
		t.Fatalf("keepalive-miss demotion did not fire")
	}

	escalated := readStatus()
	if escalated.Status != types.PeerStatusDisconnected {
		t.Fatalf("status = %q, want %q", escalated.Status, types.PeerStatusDisconnected)
	}
	if escalated.Reason != types.PeerStatusReasonKeepaliveMiss {
		t.Fatalf("reason = %q, want %q", escalated.Reason, types.PeerStatusReasonKeepaliveMiss)
	}
	if escalated.FailingSince != episodeStart {
		t.Fatalf("escalation re-stamped failing_since: %d, want the episode start %d — "+
			"the derived backoff curve would restart at min_ms",
			escalated.FailingSince, episodeStart)
	}

	// Recovery ends the episode: the `connected` write omits the field.
	if _, err := protocol.WritePeerStatus(p.Store(), p.LocationIndex(),
		string(p.PeerID()), remoteHash,
		types.PeerStatusData{PeerID: string(remotePeerID), Status: types.PeerStatusConnected}); err != nil {
		t.Fatalf("re-establish connected: %v", err)
	}
	if d := readStatus(); d.FailingSince != 0 {
		t.Fatalf("failing_since %d survived recovery, want cleared", d.FailingSince)
	}
}
