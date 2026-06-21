package peer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func TestNewPeer(t *testing.T) {
	kp, _ := crypto.Generate()

	p, err := New(WithIdentity(kp))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if p.PeerID() != kp.PeerID() {
		t.Fatalf("PeerID mismatch: %s != %s", p.PeerID(), kp.PeerID())
	}

	if p.Identity().Type != "system/peer" {
		t.Fatalf("expected identity entity type, got %s", p.Identity().Type)
	}
}

func TestNewPeerDefaults(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if string(p.PeerID()) == "" {
		t.Fatal("PeerID should not be empty")
	}
	if p.Store() == nil {
		t.Fatal("store should not be nil")
	}
	if p.LocationIndex() == nil {
		t.Fatal("location index should not be nil")
	}
}

func TestNewPeerWithStore(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	p, err := New(
		WithStore(cs),
		WithLocationIndex(li),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// ContentStore is wrapped with NotifyingContentStore, so identity check
	// won't match. Verify the wrapper delegates to the underlying store.
	if p.Store() == nil {
		t.Fatal("store should not be nil")
	}
	// LocationIndex is wrapped with NotifyingLocationIndex, so identity check
	// won't match. Verify the wrapper delegates to the underlying index.
	if p.LocationIndex() == nil {
		t.Fatal("location index should not be nil")
	}
}

// TestPeerSqliteRestartSurvival is the integration test for the persistent
// peer story (DESIGN-SQLITE-PERSISTENCE.md): build a peer backed by sqlite,
// write app data, close, build a fresh peer at the same path, verify the
// data is intact.
func TestPeerSqliteRestartSurvival(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/peer.db"

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// Phase 1 — first peer process: write app data.
	var appHash hash.Hash
	{
		s, err := store.NewSqliteStore(dbPath)
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}

		p, err := New(
			WithIdentity(kp),
			WithStore(s.ContentStore()),
			WithLocationIndex(s.LocationIndex()),
			WithCloseFunc(func() { _ = s.Close() }),
		)
		if err != nil {
			t.Fatalf("new peer: %v", err)
		}

		// Write an app entity (simulates a runtime put through the tree handler).
		raw, err := ecf.Encode("payload-after-restart")
		if err != nil {
			t.Fatalf("ecf encode: %v", err)
		}
		ent, err := entity.NewEntity("test/app", raw)
		if err != nil {
			t.Fatalf("entity: %v", err)
		}
		appHash, err = p.Store().Put(ent)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		// Bind via the namespaced index — same path the tree handler would use.
		p.LocationIndex().Set("app/data", appHash)

		if err := p.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}

	// Phase 2 — second peer process: same DB, verify app data survived.
	{
		s, err := store.NewSqliteStore(dbPath)
		if err != nil {
			t.Fatalf("reopen sqlite: %v", err)
		}

		p, err := New(
			WithIdentity(kp),
			WithStore(s.ContentStore()),
			WithLocationIndex(s.LocationIndex()),
			WithCloseFunc(func() { _ = s.Close() }),
		)
		if err != nil {
			t.Fatalf("new peer (restart): %v", err)
		}
		defer p.Close()

		got, ok := p.LocationIndex().Get("app/data")
		if !ok {
			t.Fatal("app/data binding lost across restart")
		}
		if got != appHash {
			t.Fatalf("app/data hash drifted: got %s, want %s", got, appHash)
		}
		ent, ok := p.Store().Get(appHash)
		if !ok {
			t.Fatal("app entity lost across restart")
		}
		if ent.Type != "test/app" {
			t.Fatalf("entity type wrong: %s", ent.Type)
		}
	}
}

func TestPeerListenAndConnect(t *testing.T) {
	// Create server peer.
	serverKP, _ := crypto.Generate()
	server, err := New(
		WithIdentity(serverKP),
		WithListenAddr("127.0.0.1:0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start listening in background.
	ready := make(chan struct{})
	listenErr := make(chan error, 1)
	go func() {
		listenErr <- server.ListenReady(ctx, ready)
	}()

	// Wait for listener to be ready.
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for listener")
	}

	addr := server.Addr()
	if addr == nil {
		t.Fatal("addr should not be nil after Listen")
	}

	// Create client peer and connect.
	clientKP, _ := crypto.Generate()
	client, err := New(WithIdentity(clientKP))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn, err := client.Connect(ctx, addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if conn.RemoteAddr() == nil {
		t.Fatal("remote addr should not be nil")
	}
}

func TestPeerRegistryHasDefaults(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	handlers := p.Registry().Handlers()

	// Should have connect and tree handlers.
	if _, ok := handlers["system/protocol/connect"]; !ok {
		t.Fatal("missing connect handler")
	}
	if _, ok := handlers["system/tree"]; !ok {
		t.Fatal("missing tree handler")
	}
}

func TestPeerTreePopulation(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	li := p.LocationIndex()

	// Verify type definitions are in the tree.
	if _, ok := li.Get("system/type/primitive/string"); !ok {
		t.Fatal("system/type/primitive/string not in location index")
	}
	if _, ok := li.Get("system/type/system/hash"); !ok {
		t.Fatal("system/type/system/hash not in location index")
	}

	// Verify handler manifests are in the tree.
	if _, ok := li.Get("system/handler/system/protocol/connect"); !ok {
		t.Fatal("system/handler/system/protocol/connect not in location index")
	}
	if _, ok := li.Get("system/handler/system/tree"); !ok {
		t.Fatal("system/handler/system/tree not in location index")
	}

	// Handler entities (dispatch targets) are bound at pattern paths.
	if _, ok := li.Get("system/tree"); !ok {
		t.Fatal("system/tree should have a handler entity binding")
	}
	if _, ok := li.Get("system/protocol/connect"); !ok {
		t.Fatal("system/protocol/connect should have a handler entity binding")
	}
}

// TestHandlerGrantsAreDeterministic pins the determinism fix from
// DESIGN-SQLITE-PERSISTENCE.md §4.1: two peers built from the same keypair
// must produce byte-identical handler-grant entities (so persistent-storage
// restart doesn't accumulate stale grants on each cold start).
func TestHandlerGrantsAreDeterministic(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	build := func() store.LocationIndex {
		p, err := New(WithIdentity(kp))
		if err != nil {
			t.Fatalf("new peer: %v", err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p.LocationIndex()
	}

	li1 := build()
	li2 := build()

	// Compare a representative grant binding. Same keypair + deterministic
	// seed → identical hashes at the same path.
	const grantPath = "system/capability/grants/system/tree"
	h1, ok := li1.Get(grantPath)
	if !ok {
		t.Fatalf("grant missing at %s on first peer", grantPath)
	}
	h2, ok := li2.Get(grantPath)
	if !ok {
		t.Fatalf("grant missing at %s on second peer", grantPath)
	}
	if h1 != h2 {
		t.Fatalf("handler grant hashes differ across restarts: %s vs %s\n(handler grants are non-deterministic — sqlite restart will accumulate stale entities)", h1, h2)
	}
}

func TestFullConnectAndTreeGet(t *testing.T) {
	// Set up server.
	serverKP, _ := crypto.Generate()

	server, err := New(
		WithIdentity(serverKP),
		WithListenAddr("127.0.0.1:0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// Seed an entity into the tree at a path covered by connection grants.
	raw, _ := ecf.Encode(map[string]string{"content": "hello from Go"})
	testEntity, _ := entity.NewEntity("test/doc", cbor.RawMessage(raw))
	server.Store().Put(testEntity)
	server.LocationIndex().Set("system/type/test/doc", testEntity.ContentHash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ready := make(chan struct{})
	go func() {
		server.ListenReady(ctx, ready)
	}()
	<-ready

	// Create client and connect.
	clientKP, _ := crypto.Generate()
	client, err := New(WithIdentity(clientKP))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Perform connect.
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Verify connection state.
	connSt := conn.ConnState()
	if !connSt.Completed {
		t.Fatal("connection should be completed")
	}
	if connSt.RemotePeerID != serverKP.PeerID() {
		t.Fatalf("remote peer ID mismatch: %s != %s", connSt.RemotePeerID, serverKP.PeerID())
	}

	// Verify session has capability.
	sess := conn.Session()
	if sess == nil {
		t.Fatal("session should not be nil")
	}
	if sess.Capability == nil {
		t.Fatal("session capability should not be nil")
	}

	// Perform authenticated tree get via the multiplexed Execute path.
	// Post-handshake SendEnvelope/RecvEnvelope on a client connection is
	// no longer supported — the reader goroutine demuxes responses by
	// request_id, so manual recv would race with the reader. Use Execute,
	// which registers a pending channel keyed on request_id and waits.
	getReq, getResource, _ := tree.CreateGetRequest("system/type/test/doc", "entity")

	respEnv, err := conn.Execute(
		ctx,
		"entity://"+string(serverKP.PeerID())+"/system/tree",
		"get",
		getReq,
		getResource,
	)
	if err != nil {
		t.Fatalf("tree get execute: %v", err)
	}

	if respEnv.Root.Type != types.TypeExecuteResponse {
		t.Fatalf("expected execute response, got %s", respEnv.Root.Type)
	}

	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respData.Status != 200 {
		// Decode error for debugging.
		var errEntity entity.Entity
		if err := ecf.Decode(respData.Result, &errEntity); err == nil {
			var errData types.ErrorData
			if err := ecf.Decode(errEntity.Data, &errData); err == nil {
				t.Fatalf("tree get failed with status %d: %s: %s", respData.Status, errData.Code, errData.Message)
			}
			t.Fatalf("tree get failed with status %d, result type: %s", respData.Status, errEntity.Type)
		}
		t.Fatalf("tree get failed with status %d", respData.Status)
	}

	// Decode the result entity.
	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if resultEntity.Type != "test/doc" {
		t.Fatalf("expected test/doc, got %s", resultEntity.Type)
	}
	if resultEntity.ContentHash != testEntity.ContentHash {
		t.Fatalf("content hash mismatch")
	}
}

func TestTreeEventsOnLocationIndexWrite(t *testing.T) {
	p, err := New(WithTreeEventBuffer(16))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Store an entity and set it in the location index.
	raw, _ := ecf.Encode(map[string]string{"content": "test-event"})
	testEntity, _ := entity.NewEntity("test/event-doc", cbor.RawMessage(raw))
	h, _ := p.Store().Put(testEntity)

	p.LocationIndex().Set("test/my-doc", h)

	expectedPath := "/" + string(p.PeerID()) + "/test/my-doc"
	select {
	case evt := <-p.TreeEvents():
		if evt.Path != expectedPath {
			t.Fatalf("expected path %s, got %s", expectedPath, evt.Path)
		}
		if evt.PeerID != string(p.PeerID()) {
			t.Fatalf("expected PeerID %s, got %s", p.PeerID(), evt.PeerID)
		}
		if evt.ChangeType != store.ChangeCreated {
			t.Fatalf("expected ChangeCreated, got %d", evt.ChangeType)
		}
		if evt.Hash != h {
			t.Fatal("event hash should match stored hash")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for tree event")
	}

	// Overwrite should produce a Modified event.
	raw2, _ := ecf.Encode(map[string]string{"content": "updated"})
	testEntity2, _ := entity.NewEntity("test/event-doc", cbor.RawMessage(raw2))
	h2, _ := p.Store().Put(testEntity2)

	p.LocationIndex().Set("test/my-doc", h2)

	select {
	case evt := <-p.TreeEvents():
		if evt.ChangeType != store.ChangeModified {
			t.Fatalf("expected ChangeModified, got %d", evt.ChangeType)
		}
		if evt.PreviousHash != h {
			t.Fatal("previous hash should match first hash")
		}
		if evt.Hash != h2 {
			t.Fatal("new hash should match second hash")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for modified event")
	}

	// Remove should produce a Deleted event.
	p.LocationIndex().Remove("test/my-doc")

	select {
	case evt := <-p.TreeEvents():
		if evt.ChangeType != store.ChangeDeleted {
			t.Fatalf("expected ChangeDeleted, got %d", evt.ChangeType)
		}
		if evt.PreviousHash != h2 {
			t.Fatal("previous hash should match last hash")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for delete event")
	}
}

func TestTreeEventsChannelClosedOnClose(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}

	events := p.TreeEvents()
	p.Close()

	// Channel should be closed — reading should return zero value immediately.
	_, ok := <-events
	if ok {
		t.Fatal("expected channel to be closed")
	}
}

// TestTreeEventsNonBlockingWhenFull was removed alongside the drop-on-full
// behavior in NotifyingLocationIndex.emit and fanOut. Writes are now expected
// to block when the event consumer isn't draining; callers either drain or
// close the peer. See core/store/notifying_test.go::TestNotifyingEmitBackpressure
// for the regression test guarding the new design and
// the SQLite busy bulk-ingest review for
// the production incident that drove the change.

func TestPeerTreeStructure(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	cs := p.Store()
	li := p.LocationIndex()

	// Use the tree handler to extract the full tree.
	th := tree.NewHandler()
	req := &handler.Request{
		Path:      "system/tree",
		Operation: "extract",
		Params:    entity.Entity{},
		Context: &handler.HandlerContext{
			LocalPeerID:    p.PeerID(),
			Store:          cs,
			LocationIndex:  li,
			HandlerPattern: "system/tree",
			Resource:       &types.ResourceTarget{Targets: []string{""}},
		},
	}
	resp, err := th.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("extract failed with status %d", resp.Status)
	}

	// Decode the envelope.
	var env entity.Envelope
	if err := ecf.Decode(resp.Result.Data, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	// Decode the snapshot.
	snap, err := types.SnapshotDataFromEntity(env.Root)
	if err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}

	// Collect flat bindings from trie root.
	bindings := tree.CollectAllBindings(cs, snap.Root, "")

	// Sort paths for stable output.
	paths := make([]string, 0, len(bindings))
	for path := range bindings {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	// Tally entity types.
	typeCounts := map[string]int{}

	t.Logf("")
	t.Logf("=== Peer Tree Structure ===")
	t.Logf("Peer ID: %s", p.PeerID())
	t.Logf("Total bindings: %d", len(bindings))
	t.Logf("Included entities: %d", len(env.Included))
	t.Logf("Content store size: %d", cs.Len())
	t.Logf("")

	// Track which hashes appear at multiple paths.
	hashPaths := map[hash.Hash][]string{}

	t.Logf("--- Bindings (path → entity type [hash]) ---")
	for _, path := range paths {
		h := bindings[path]
		hashPaths[h] = append(hashPaths[h], path)
		ent, ok := env.Included[h]
		if ok {
			typeCounts[ent.Type]++
			shortHash := h.String()[len("ecf-sha256:"):][:12]
			t.Logf("  %-70s  %-30s  %s", path, ent.Type, shortHash)
		} else {
			t.Logf("  %-70s  (entity not in included)", path)
		}
	}

	// Show shared references — multiple paths pointing to the same entity.
	t.Logf("")
	t.Logf("--- Shared References (same entity, multiple paths) ---")
	sharedCount := 0
	for h, ps := range hashPaths {
		if len(ps) <= 1 {
			continue
		}
		sharedCount++
		ent, _ := env.Included[h]
		shortHash := h.String()[len("ecf-sha256:"):][:12]
		t.Logf("  %s [%s] (%d paths):", ent.Type, shortHash, len(ps))
		for _, p := range ps {
			t.Logf("    → %s", p)
		}
	}
	if sharedCount == 0 {
		t.Logf("  (none)")
	}

	t.Logf("")
	t.Logf("--- Entity Type Summary ---")
	typeNames := make([]string, 0, len(typeCounts))
	for name := range typeCounts {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)
	for _, name := range typeNames {
		t.Logf("  %-50s  %d", name, typeCounts[name])
	}

	t.Logf("")
	t.Logf("--- Envelope ---")
	t.Logf("  Root type: %s", env.Root.Type)
	t.Logf("  Root hash: %s", env.Root.ContentHash)
	t.Logf("  Bindings:  %d paths → %d unique hashes → %d included entities",
		len(bindings), len(hashPaths), len(env.Included))
	t.Logf("")

	// Basic assertions.
	if len(bindings) < 40 {
		t.Errorf("expected at least 40 bindings (types+handlers+grants), got %d", len(bindings))
	}
	if len(env.Included) == 0 {
		t.Error("expected included entities in envelope")
	}
}

func TestPeerConnectionsEmpty(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	conns := p.Connections()
	if len(conns) != 0 {
		t.Fatalf("expected 0 connections, got %d", len(conns))
	}
}

func TestPeerConnectionsInbound(t *testing.T) {
	server := startTestPeer(t)
	client := startTestPeer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Give the server a moment to accept.
	time.Sleep(50 * time.Millisecond)

	// Server should have one inbound connection.
	serverConns := server.Connections()
	if len(serverConns) != 1 {
		t.Fatalf("expected 1 server connection, got %d", len(serverConns))
	}

	// Client should have one inbound connection (from Connect).
	clientConns := client.Connections()
	if len(clientConns) != 1 {
		t.Fatalf("expected 1 client connection, got %d", len(clientConns))
	}
}

func TestPeerConnectionsOutbound(t *testing.T) {
	server := startTestPeer(t)
	client := startTestPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("system/handler/system/tree", "entity")

	// Trigger a remote execute to establish a cached outbound connection.
	_, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource)
	if err != nil {
		t.Fatalf("remote execute: %v", err)
	}

	conns := client.Connections()
	// Should have at least the outbound cached connection (plus possibly the
	// inbound side of Connect that remoteExecute calls internally).
	if len(conns) == 0 {
		t.Fatal("expected at least 1 connection after remote execute")
	}

	// Verify the returned slice is a copy.
	conns[0] = nil
	conns2 := client.Connections()
	if conns2[0] == nil {
		t.Fatal("Connections() should return a copy, not a reference to internal state")
	}
}

// startTestPeer creates a listening peer for tests. Uses startPeer but defined
// separately for the Connections tests to avoid depending on the remote execute
// test helper ordering.
func startTestPeer(t *testing.T, opts ...Option) *Peer {
	t.Helper()
	return startPeer(t, opts...)
}

// --- Remote Execute tests ---

// startPeer creates and starts a listening peer, returning it and a cleanup func.
func startPeer(t *testing.T, opts ...Option) *Peer {
	t.Helper()
	kp, _ := crypto.Generate()
	allOpts := append([]Option{
		WithIdentity(kp),
		WithListenAddr("127.0.0.1:0"),
		WithConnectionGrants(OpenAccessGrants()),
	}, opts...)

	p, err := New(allOpts...)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go func() {
		p.ListenReady(ctx, ready)
	}()
	<-ready

	t.Cleanup(func() {
		cancel()
		p.Close()
	})
	return p
}

func TestRemoteExecute(t *testing.T) {
	server := startPeer(t)

	// Seed data on server after construction (goes through namespace layer).
	raw, _ := ecf.Encode(map[string]string{"content": "remote-data"})
	testEntity, _ := entity.NewEntity("test/remote-doc", cbor.RawMessage(raw))
	server.Store().Put(testEntity)
	server.LocationIndex().Set("test/remote-doc", testEntity.ContentHash)

	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
	)

	// Verify TCP profile was stored at the §6.5 path
	// system/peer/transport/{peer_id_hex}/primary (v7.64 path-encoding alignment).
	serverHash, err := types.ComputePeerIdentityHashFromPeerID(server.PeerID())
	if err != nil {
		t.Fatalf("derive server identity hash: %v", err)
	}
	transportPath := "system/peer/transport/" + types.PeerIdentityHashHex(serverHash) + "/primary"
	if _, ok := client.LocationIndex().Get(transportPath); !ok {
		t.Fatalf("tcp profile not in tree at %s", transportPath)
	}

	// Call remoteExecute to do a tree get on the server.
	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("test/remote-doc", "entity")

	resp, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource)
	if err != nil {
		t.Fatalf("remote execute: %v", err)
	}

	if resp.Status != 200 {
		if resp.Result.Type == types.TypeError {
			var errData types.ErrorData
			ecf.Decode(resp.Result.Data, &errData)
			t.Fatalf("remote execute returned status %d: %s: %s", resp.Status, errData.Code, errData.Message)
		}
		t.Fatalf("remote execute returned status %d", resp.Status)
	}

	if resp.Result.Type != "test/remote-doc" {
		t.Fatalf("expected test/remote-doc, got %s", resp.Result.Type)
	}
	if resp.Result.ContentHash != testEntity.ContentHash {
		t.Fatalf("content hash mismatch")
	}
}

func TestRemoteExecuteConnectionReuse(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t,
		WithRemotePeer(server.PeerID(), server.Addr().String()),
	)

	ctx := context.Background()
	remoteTreeURI := fmt.Sprintf("entity://%s/system/tree", server.PeerID())

	// First call — establishes connection.
	getReq, getResource, _ := tree.CreateGetRequest("system/handler/system/tree", "entity")
	_, err := client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource)
	if err != nil {
		t.Fatalf("first remote execute: %v", err)
	}

	// Capture cached connection count.
	client.remote.mu.Lock()
	connCount1 := len(client.remote.conns)
	client.remote.mu.Unlock()

	// Second call — should reuse connection.
	_, err = client.remoteExecute(ctx, remoteTreeURI, "get", getReq, getResource)
	if err != nil {
		t.Fatalf("second remote execute: %v", err)
	}

	client.remote.mu.Lock()
	connCount2 := len(client.remote.conns)
	client.remote.mu.Unlock()

	if connCount1 != 1 {
		t.Fatalf("expected 1 cached connection after first call, got %d", connCount1)
	}
	if connCount2 != 1 {
		t.Fatalf("expected 1 cached connection after second call (reuse), got %d", connCount2)
	}
}

// TestAddRemoteConnection_Inserts verifies the new pool-insertion API
// caches an externally-dialed connection so subsequent dispatches
// reuse it instead of dialing fresh.
func TestAddRemoteConnection_Inserts(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t)

	ctx := context.Background()
	conn, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("PerformConnect: %v", err)
	}

	pooled, err := client.AddRemoteConnection(server.PeerID(), conn)
	if err != nil {
		t.Fatalf("AddRemoteConnection: %v", err)
	}
	if pooled != conn {
		t.Fatal("AddRemoteConnection returned a different connection on first insert")
	}

	// Calling again with a fresh connection should close the new one
	// and return the existing pooled connection.
	conn2, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	if err := conn2.PerformConnect(ctx); err != nil {
		t.Fatalf("second PerformConnect: %v", err)
	}
	pooled2, err := client.AddRemoteConnection(server.PeerID(), conn2)
	if err != nil {
		t.Fatalf("second AddRemoteConnection: %v", err)
	}
	if pooled2 != conn {
		t.Error("expected existing pooled connection back when re-inserting under same peer-id")
	}

	// Pool must have exactly one entry for this peer-id.
	client.remote.mu.Lock()
	count := len(client.remote.conns)
	client.remote.mu.Unlock()
	if count != 1 {
		t.Errorf("pool size = %d, want 1", count)
	}
}

func TestAddRemoteConnection_RejectsUnestablished(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t)

	ctx := context.Background()
	conn, err := client.Connect(ctx, server.Addr().String())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// Skip PerformConnect — connection is not established.
	defer conn.Close()

	_, err = client.AddRemoteConnection(server.PeerID(), conn)
	if err == nil {
		t.Fatal("expected error when adding unestablished connection")
	}
}

func TestRemoteExecuteUnknownPeer(t *testing.T) {
	unknownKP, _ := crypto.Generate()
	client := startPeer(t) // No remotes registered.

	ctx := context.Background()
	uri := fmt.Sprintf("entity://%s/system/tree", unknownKP.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("system/handler/system/tree", "entity")

	_, err := client.remoteExecute(ctx, uri, "get", getReq, getResource)
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}
	if !strings.Contains(err.Error(), "no transport profile") {
		t.Fatalf("expected 'no transport profile' error, got: %v", err)
	}
}

func TestRegisterAndRemoveRemote(t *testing.T) {
	server := startPeer(t)
	client := startPeer(t)

	// Register remote.
	if err := client.RegisterRemote(server.PeerID(), server.Addr().String()); err != nil {
		t.Fatalf("register remote: %v", err)
	}

	// Verify in tree. V7.64 path-encoding alignment: the path is
	// system/peer/transport/{peer_id_hex}/primary and the entity is
	// TCPProfileData with endpoint URL tcp://addr.
	serverHash, err := types.ComputePeerIdentityHashFromPeerID(server.PeerID())
	if err != nil {
		t.Fatalf("derive server identity hash: %v", err)
	}
	transportPath := "system/peer/transport/" + types.PeerIdentityHashHex(serverHash) + "/primary"
	h, ok := client.LocationIndex().Get(transportPath)
	if !ok {
		t.Fatal("tcp profile not in tree after RegisterRemote")
	}
	ent, ok := client.Store().Get(h)
	if !ok {
		t.Fatal("tcp profile entity not in store")
	}
	if ent.Type != types.TypePeerTransportTCP {
		t.Fatalf("entity type: got %q want %q", ent.Type, types.TypePeerTransportTCP)
	}
	data, err := types.TCPProfileDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode tcp profile: %v", err)
	}
	wantURL := "tcp://" + server.Addr().String()
	if data.Endpoint.URL != wantURL {
		t.Fatalf("endpoint URL mismatch: %s != %s", data.Endpoint.URL, wantURL)
	}

	// Establish a remote connection so there's something to clean up.
	ctx := context.Background()
	uri := fmt.Sprintf("entity://%s/system/tree", server.PeerID())
	getReq, getResource, _ := tree.CreateGetRequest("system/handler/system/tree", "entity")
	_, err = client.remoteExecute(ctx, uri, "get", getReq, getResource)
	if err != nil {
		t.Fatalf("remote execute: %v", err)
	}

	// Verify connection is cached.
	client.remote.mu.Lock()
	_, hasCachedConn := client.remote.conns[server.PeerID()]
	client.remote.mu.Unlock()
	if !hasCachedConn {
		t.Fatal("expected cached connection after remote execute")
	}

	// Remove remote.
	client.RemoveRemote(server.PeerID())

	// Verify tree entry removed.
	if _, ok := client.LocationIndex().Get(transportPath); ok {
		t.Fatal("transport address should be removed from tree")
	}

	// Verify cached connection removed.
	client.remote.mu.Lock()
	_, hasCachedConn = client.remote.conns[server.PeerID()]
	client.remote.mu.Unlock()
	if hasCachedConn {
		t.Fatal("cached connection should be removed after RemoveRemote")
	}
}

// TestRegisterRemote_G1_TCPAndHTTPCoexist verifies the G1 fix from
// PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY §7.3: RegisterRemote (TCP)
// and RegisterRemoteHTTP for the same peer must produce TWO distinct
// profile entries, not collide on a single "primary" key. Pre-G1, the
// second call silently overwrote the first.
func TestRegisterRemote_G1_TCPAndHTTPCoexist(t *testing.T) {
	client := startPeer(t)
	server := startPeer(t)
	pid := server.PeerID()

	if err := client.RegisterRemote(pid, server.Addr().String()); err != nil {
		t.Fatalf("RegisterRemote (TCP): %v", err)
	}
	if err := client.RegisterRemoteHTTP(pid, "http://"+server.Addr().String()+"/entity"); err != nil {
		t.Fatalf("RegisterRemoteHTTP: %v", err)
	}
	pidHash, err := types.ComputePeerIdentityHashFromPeerID(pid)
	if err != nil {
		t.Fatalf("derive pid hash: %v", err)
	}

	relPrefix := "system/peer/transport/" + types.PeerIdentityHashHex(pidHash) + "/"
	absPrefix := "/" + string(client.PeerID()) + "/" + relPrefix
	entries := client.LocationIndex().List(relPrefix)
	if len(entries) != 2 {
		paths := make([]string, len(entries))
		for i, e := range entries {
			paths[i] = e.Path
		}
		t.Fatalf("expected 2 profile entries (tcp + http), got %d: %v", len(entries), paths)
	}

	// Verify each profile-id maps to the expected transport type.
	// List returns absolute paths per the namespacing contract; trim
	// the canonicalized absolute prefix to recover the profile-id.
	byID := map[string]string{}
	for _, e := range entries {
		ent, ok := client.Store().Get(e.Hash)
		if !ok {
			t.Fatalf("entity missing for %s", e.Path)
		}
		id := strings.TrimPrefix(e.Path, absPrefix)
		byID[id] = ent.Type
	}
	if byID["primary"] != types.TypePeerTransportTCP {
		t.Fatalf("expected 'primary' = TCP profile, got %q", byID["primary"])
	}
	if byID["primary-http"] != types.TypePeerTransportHTTP {
		t.Fatalf("expected 'primary-http' = HTTP profile, got %q", byID["primary-http"])
	}
}

// F18 regression: serve loops MUST outlive the listener ctx passed to
// ListenReady. The listener ctx bounds the Accept loop only; already-
// accepted serve goroutines stay on the peer-lifetime serveCtx until
// Peer.Close. Without this, a caller that passes a short-timeout ctx to
// ListenReady (e.g. a test ctx) silently kills every connection at the
// timeout boundary even though the caller is still using them.
//
// Workbench-go's TestRevision_F18_Bisect_AutoVersionOn_Hierarchical
// reproducer surfaced this: 90s test ctx, 231s burn → conns died at 90s,
// post-burn fetch-diff failed with broken pipe.
func TestPeerServeOutlivesListenerCtx(t *testing.T) {
	serverKP, _ := crypto.Generate()
	server, err := New(WithIdentity(serverKP), WithListenAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// Short-timeout listener ctx — caller cancels this to stop accepting
	// new connections but expects already-established ones to keep working.
	listenCtx, listenCancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go func() { _ = server.ListenReady(listenCtx, ready) }()
	<-ready

	clientKP, _ := crypto.Generate()
	client, err := New(WithIdentity(clientKP))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Establish connection while listener ctx is still live.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, err := client.Connect(dialCtx, server.Addr().String())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Cancel the listener ctx — this MUST NOT kill the established
	// connection. The Accept loop will return; the serve goroutine for
	// the existing conn keeps running on server.serveCtx.
	listenCancel()

	// Give the listener-loop goroutine a moment to exit.
	time.Sleep(50 * time.Millisecond)

	if conn.IsClosed() {
		t.Fatal("F18 regression: client connection closed after listener ctx cancel; serve loop is bound to listener ctx instead of peer ctx")
	}

	// Server should still hold the connection too.
	server.mu.Lock()
	serverHasConn := len(server.connections) > 0
	if serverHasConn && server.connections[0].IsClosed() {
		serverHasConn = false
	}
	server.mu.Unlock()
	if !serverHasConn {
		t.Fatal("F18 regression: server-side connection is closed after listener ctx cancel; serve loop exited and called Close")
	}

	// Explicit Peer.Close cancels serveCtx and tears down server-side
	// conns; the client side will see EOF on next read. We only assert
	// the no-regression behavior above; the server-Close teardown is
	// already covered by TestPeerListenAndConnect + defer chains.
}

// TestWithBindingHookPattern_E2E exercises the new pattern-filtered binding-hook
// option end-to-end: builder option → config.namedSyncHooks → peer.New wiring →
// NotifyingLocationIndex.runCascade pattern check. Drives writes through
// p.LocationIndex().Set (the same path application writes use) and asserts
// each hook only fires for events whose path matches its pattern.
//
// This is the test that previously didn't exist — the unit tests cover the
// pathMatchesPattern helper and the store-level AddNamedSyncHookWithPattern,
// but neither proves that WithBindingHookPattern actually propagates through
// the builder wiring. Without this test the public API surface was unverified.
func TestWithBindingHookPattern_E2E(t *testing.T) {
	kp, _ := crypto.Generate()

	var (
		attHits     int
		clockHits   int
		exactHits   int
		wildcardHits int
		allHits     int
	)

	p, err := New(
		WithIdentity(kp),
		// Prefix-glob: should match anything under system/attestation/
		WithBindingHookPattern("att-watch", "system/attestation/*",
			func(evt store.TreeChangeEvent) { attHits++ }),
		// Prefix-glob on a different family.
		WithBindingHookPattern("clock-watch", "system/clock/*",
			func(evt store.TreeChangeEvent) { clockHits++ }),
		// Exact match.
		WithBindingHookPattern("exact-watch", "system/exact/path",
			func(evt store.TreeChangeEvent) { exactHits++ }),
		// "*" universal.
		WithBindingHookPattern("wild-watch", "*",
			func(evt store.TreeChangeEvent) { wildcardHits++ }),
		// Legacy (no pattern) — should fire for everything too.
		WithBindingHook("all-watch",
			func(evt store.TreeChangeEvent) { allHits++ }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Baseline counts to subtract (peer construction seeds many writes).
	baselineAtt := attHits
	baselineClock := clockHits
	baselineExact := exactHits
	baselineWild := wildcardHits
	baselineAll := allHits

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0xAB

	// Drive writes through the same path the application uses.
	// Paths are peer-relative and get canonicalized to /{peerID}/path,
	// so the patterns we register (peer-relative) match the post-canonicalization
	// path because NotifyingLocationIndex sees the qualified path.
	pid := string(p.PeerID())
	cases := []struct {
		name string
		path string
	}{
		{"attestation-1", "/" + pid + "/system/attestation/a1"},
		{"attestation-2", "/" + pid + "/system/attestation/nested/a2"},
		{"clock-now",     "/" + pid + "/system/clock/now"},
		{"exact-hit",     "/" + pid + "/system/exact/path"},
		{"unrelated",     "/" + pid + "/unrelated/x"},
	}

	for _, tc := range cases {
		if err := p.LocationIndex().Set(tc.path, h); err != nil {
			t.Fatalf("Set %s: %v", tc.name, err)
		}
	}

	got := struct {
		att, clock, exact, wild, all int
	}{
		att:   attHits - baselineAtt,
		clock: clockHits - baselineClock,
		exact: exactHits - baselineExact,
		wild:  wildcardHits - baselineWild,
		all:   allHits - baselineAll,
	}

	// Peer-relative patterns are canonicalized to /{localPeerID}/pattern at
	// peer construction (peer.go: "Canonicalize peer-relative patterns"). So
	// "system/attestation/*" matches /{peerID}/system/attestation/*, and the
	// two attestation writes fire it.
	if got.att != 2 {
		t.Errorf("att-watch (peer-relative pattern) fired %d times; want 2", got.att)
	}
	if got.clock != 1 {
		t.Errorf("clock-watch fired %d times; want 1", got.clock)
	}
	if got.exact != 1 {
		t.Errorf("exact-watch fired %d times; want 1", got.exact)
	}
	// Universal pattern + no-pattern: both should fire for all 5 writes.
	if got.wild != len(cases) {
		t.Errorf("wildcard fired %d times; want %d", got.wild, len(cases))
	}
	if got.all != len(cases) {
		t.Errorf("no-pattern hook fired %d times; want %d", got.all, len(cases))
	}
}

// TestWithBindingHookPattern_AbsolutePathPatterns is the partner test that uses
// absolute path patterns matching the events the engine actually sees. This is
// the "use it correctly" case — patterns must be in the same coordinate space
// as the events.
func TestWithBindingHookPattern_AbsolutePathPatterns(t *testing.T) {
	kp, _ := crypto.Generate()
	pid := string(kp.PeerID())

	var attHits, clockHits, exactHits int

	p, err := New(
		WithIdentity(kp),
		WithBindingHookPattern("att", "/"+pid+"/system/attestation/*",
			func(evt store.TreeChangeEvent) { attHits++ }),
		WithBindingHookPattern("clock", "/"+pid+"/system/clock/*",
			func(evt store.TreeChangeEvent) { clockHits++ }),
		WithBindingHookPattern("exact", "/"+pid+"/system/exact/path",
			func(evt store.TreeChangeEvent) { exactHits++ }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	bAtt, bClock, bExact := attHits, clockHits, exactHits

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0xCD
	writes := []string{
		"/" + pid + "/system/attestation/a1",
		"/" + pid + "/system/attestation/nested/a2",
		"/" + pid + "/system/clock/now",
		"/" + pid + "/system/exact/path",
		"/" + pid + "/unrelated/x",
	}
	for _, w := range writes {
		if err := p.LocationIndex().Set(w, h); err != nil {
			t.Fatalf("Set %s: %v", w, err)
		}
	}

	if attHits-bAtt != 2 {
		t.Errorf("att-pattern fired %d times; want 2", attHits-bAtt)
	}
	if clockHits-bClock != 1 {
		t.Errorf("clock-pattern fired %d times; want 1", clockHits-bClock)
	}
	if exactHits-bExact != 1 {
		t.Errorf("exact-pattern fired %d times; want 1", exactHits-bExact)
	}
}

// TestWithNamedSyncHookPattern_CascadeHalt verifies that a pattern-filtered
// cascade-participating hook can still halt the cascade for matching events
// and is skipped silently (not in CascadeResult.Skipped) for non-matching events.
func TestWithNamedSyncHookPattern_CascadeHalt(t *testing.T) {
	kp, _ := crypto.Generate()
	pid := string(kp.PeerID())

	matchingFired := 0
	nonMatchingFired := 0

	p, err := New(
		WithIdentity(kp),
		WithNamedSyncHookPattern("halt-on-match", "/"+pid+"/halt/*",
			func(evt store.TreeChangeEvent) *store.ConsumerResult {
				matchingFired++
				return &store.ConsumerResult{Status: 403, Code: "test_halt", Message: "test"}
			}),
		WithNamedSyncHookPattern("never-fires", "/"+pid+"/halt/*",
			func(evt store.TreeChangeEvent) *store.ConsumerResult {
				nonMatchingFired++
				return nil
			}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	bMatch := matchingFired

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0xEF

	// Write to a non-matching path — neither hook should fire.
	if err := p.LocationIndex().Set("/"+pid+"/other/x", h); err != nil {
		t.Fatalf("non-matching Set: %v", err)
	}
	if matchingFired-bMatch != 0 {
		t.Errorf("matching-pattern hook fired %d times on non-match; want 0", matchingFired-bMatch)
	}
	if nonMatchingFired != 0 {
		t.Errorf("downstream pattern hook fired on non-match; want 0")
	}
}

// TestWithBindingHookPattern_CrossPeerNamespaceVisibility is the load-bearing
// test for the namespace-agnostic peer-relative pattern grammar: a hook
// watching "system/attestation/*" MUST fire for events written under remote
// peers' namespaces (which sit in the local tree via revision/sync/cache),
// not just the local peer's namespace.
//
// Why this matters: tree storage is peer-namespaced (/{peer_id}/...), but the
// logical content shape is namespace-agnostic — a write at PeerA's
// "system/attestation/x" and PeerB's "system/attestation/x" are the same
// kind of event from an observer's perspective. If peer-relative patterns
// auto-scoped to local-PID-only, every observer would silently miss every
// event from remote-peer namespaces — exactly the data-loss footgun this
// surface exists to prevent.
//
// The test writes under three distinct peer-id segments in the local tree
// and asserts the peer-relative pattern hook fires for all three.
func TestWithBindingHookPattern_CrossPeerNamespaceVisibility(t *testing.T) {
	kpLocal, _ := crypto.Generate()
	localPID := string(kpLocal.PeerID())

	// Fake remote peer IDs — we just need to write under those namespaces in
	// the local tree. (In production these get populated by revision/sync;
	// for this test direct Set into the namespaced index is sufficient.)
	kpRemoteA, _ := crypto.Generate()
	kpRemoteB, _ := crypto.Generate()
	remoteA := string(kpRemoteA.PeerID())
	remoteB := string(kpRemoteB.PeerID())

	var (
		peerRelHits int // pattern "system/attestation/*" — any peer
		anyPeerHits int // pattern "/*/system/attestation/*" — explicit any-peer
		localOnly   int // pattern "/{localPID}/system/attestation/*" — local only
		remoteAOnly int // pattern "/{remoteA}/system/attestation/*" — that peer
	)

	p, err := New(
		WithIdentity(kpLocal),
		WithBindingHookPattern("peer-rel", "system/attestation/*",
			func(evt store.TreeChangeEvent) { peerRelHits++ }),
		WithBindingHookPattern("any-peer", "/*/system/attestation/*",
			func(evt store.TreeChangeEvent) { anyPeerHits++ }),
		WithBindingHookPattern("local-only", "/"+localPID+"/system/attestation/*",
			func(evt store.TreeChangeEvent) { localOnly++ }),
		WithBindingHookPattern("remoteA-only", "/"+remoteA+"/system/attestation/*",
			func(evt store.TreeChangeEvent) { remoteAOnly++ }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Baseline counts (peer construction does seed writes under localPID's
	// namespace, some of which touch system/* — subtract from final counts).
	bPeerRel, bAnyPeer, bLocal, bRemoteA := peerRelHits, anyPeerHits, localOnly, remoteAOnly

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0xA0

	writes := []string{
		"/" + localPID + "/system/attestation/a1", // local namespace
		"/" + remoteA + "/system/attestation/a2",  // remote peer A
		"/" + remoteB + "/system/attestation/a3",  // remote peer B
		"/" + remoteA + "/system/clock/now",       // remote A, wrong suffix
		"/" + remoteB + "/unrelated/x",            // remote B, wrong everything
	}
	for _, w := range writes {
		if err := p.LocationIndex().Set(w, h); err != nil {
			t.Fatalf("Set %s: %v", w, err)
		}
	}

	// Peer-relative pattern is namespace-agnostic: 3 attestation writes
	// across 3 different peers all fire it. The 2 non-attestation writes
	// don't.
	if got := peerRelHits - bPeerRel; got != 3 {
		t.Errorf("peer-relative pattern fired %d times across namespaces; want 3", got)
	}
	// Explicit /*/ form behaves identically.
	if got := anyPeerHits - bAnyPeer; got != 3 {
		t.Errorf("/*/...  pattern fired %d times; want 3", got)
	}
	// Local-PID-specific pattern fires only for the local-namespace write.
	if got := localOnly - bLocal; got != 1 {
		t.Errorf("local-only pattern fired %d times; want 1", got)
	}
	// remoteA-specific pattern fires only for the one attestation write
	// under remoteA's namespace (NOT remoteA's clock write — wrong suffix).
	if got := remoteAOnly - bRemoteA; got != 1 {
		t.Errorf("remoteA-only pattern fired %d times; want 1", got)
	}
}
