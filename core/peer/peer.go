package peer

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	coderws "github.com/coder/websocket"
)

// Peer is the top-level construct that ties together identity, handlers,
// storage, and network connections.
type Peer struct {
	keypair         crypto.Keypair
	peerID          crypto.PeerID
	identity        entity.Entity
	store           store.ContentStore
	locationIndex   store.LocationIndex
	namespacedIndex *store.NamespacedIndex
	registry        *handler.Registry
	dispatcher      *protocol.Dispatcher
	connectHandler  *protocol.ConnectHandler // exposed via SetGrantResolver for post-construction policy wiring
	debugLog        *log.Logger

	contextFields *store.ContextFieldRegistry

	treeEvents     chan store.TreeChangeEvent
	treeEventsDone chan struct{}
	fanOutStats    *FanOutStats
	notifyingIndex *store.NotifyingLocationIndex // direct ref for observability

	listenAddr string
	listener   net.Listener

	remote remoteState // connection pool for remote peers

	closeFuncs  []func()
	mu          sync.Mutex
	connections []*Connection
	closed      bool

	// serveCtx scopes the lifetime of spawned per-connection serve()
	// goroutines. Created at peer construction time, cancelled only by
	// Peer.Close. Deliberately independent of the ctx passed to
	// ListenReady — the listener ctx bounds the Accept loop (callers
	// expect cancellation to stop accepting new connections), but
	// already-accepted serve loops MUST outlive the listener ctx so
	// short-timeout test contexts don't silently kill connections
	// the test is still using. F18 root cause (HANDOFF-STAGE-6-2026-
	// 05-31): the prior `go c.serve(ctx)` passed the listener ctx
	// straight through; workbench-go's reproducer used a 90s test
	// ctx for a 231s burn, which killed every conn at 90s and made
	// post-burn fetch-diff fail with EPIPE.
	serveCtx    context.Context
	serveCancel context.CancelFunc

	// wireHooks fire on every envelope crossing the network boundary, per
	// GUIDE-INSPECTABILITY v1.1 §2.1 #7. Registered at peer construction;
	// readers are inline on the wire hot path with no lock — append after
	// Build is unsafe.
	wireHooks []NamedWireHook

	// dispatchFallback is the NETWORK §10 step-4 sender-side seam per
	// PROPOSAL-DISPATCH-FALLBACK-SEAM-SENDER-SIDE-STORE-AND-FORWARD
	// (DRAFT — Tier 2 / v1.x). Consulted by remoteExecute
	// when getRemoteConnection fails (no live session, no transport
	// profile, dial failed), AFTER the §6.11 reentry fallback and
	// BEFORE returning the unreachable error. RELAY plugs the inbox-
	// relay-resolve + Mode-S/Mode-F policy in behind this field;
	// non-RELAY peers leave it nil and behave byte-identical to v1.
	dispatchFallback DispatchFallbackFunc
}

// New creates a new Peer with the given options.
func New(opts ...Option) (*Peer, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Keypair is required.
	if cfg.keypair == nil {
		kp, err := crypto.Generate()
		if err != nil {
			return nil, fmt.Errorf("generate keypair: %w", err)
		}
		cfg.keypair = &kp
	}

	kp := *cfg.keypair
	identity, err := kp.IdentityEntity()
	if err != nil {
		return nil, err
	}

	// Default store.
	rawCS := cfg.store
	if rawCS == nil {
		rawCS = store.NewMemoryContentStore()
	}
	// Wrap content store with NotifyingContentStore for content-store events.
	// Wrapping order: MemoryCS → NotifyingCS → all callers (handlers, seed, etc.)
	// Content-store events fire when a new hash enters the store (SYSTEM-COMPOSITION
	// v1.2 section 1.1). Hooks registered via WithNamedContentHook are wired here.
	notifyingCS := store.NewNotifyingContentStore(rawCS)
	for _, hook := range cfg.namedContentHooks {
		notifyingCS.AddNamedContentHook(hook.Name, hook.Fn)
	}
	var cs store.ContentStore = notifyingCS

	li := cfg.locationIndex
	if li == nil {
		li = store.NewMemoryLocationIndex()
	}

	// Create tree event channels and wrap location index.
	// Wrapping order: MemoryLI → NotifyingLI → NamespacedIndex → handlers
	// Events carry fully qualified paths ({peerID}/path) — the canonical form.
	// NS writes (SetNS) also fire events since they pass through NotifyingLI.
	eventBufSize := cfg.treeEventBuffer
	if eventBufSize == 0 {
		eventBufSize = 256
	}
	treeEvents := make(chan store.TreeChangeEvent, eventBufSize)
	treeEventsDone := make(chan struct{})

	notifyingLI := store.NewNotifyingLocationIndex(li, treeEvents, treeEventsDone)
	// Suppress emit during the seed phase. Construction does hundreds of
	// seed writes (type entities, handler entities, handler grants) before
	// any consumer of the events channel is wired. Emitting those would
	// either fill the channel (with nobody draining) or return
	// ErrEventBufferFull (failing the constructor under tight buffers).
	// Neither is correct — seed writes are not application events. Cleared
	// below before fanOut takes over.
	notifyingLI.SetEmitSuppressed(true)
	if cfg.debugLog != nil {
		notifyingLI.SetDebugLog(cfg.debugLog)
	}
	if cfg.maxCascadeDepth != nil {
		notifyingLI.SetMaxCascadeDepth(*cfg.maxCascadeDepth)
	}
	for _, hook := range cfg.namedSyncHooks {
		if hook.Pattern == "" {
			notifyingLI.AddNamedSyncHook(hook.Name, hook.Fn)
		} else {
			// Patterns pass through verbatim. Coordinate-space semantics
			// are decided in pathMatchesPattern:
			//   peer-relative ("system/foo/*")  → suffix match across ANY
			//                                     peer namespace (default
			//                                     gives full visibility)
			//   "/PID/foo/*"                    → that specific peer only
			//   "/*/foo/*"                      → explicit any-peer (same
			//                                     effect as peer-relative)
			// Observation defaults to namespace-agnostic so a watcher does
			// not silently miss events from non-local peer namespaces that
			// sync/revision/cache populated in the local tree.
			notifyingLI.AddNamedSyncHookWithPattern(hook.Name, hook.Pattern, hook.Fn)
		}
	}
	namespacedLI := store.NewNamespacedIndex(notifyingLI, string(kp.PeerID()))

	// Create type registry and register core types.
	typeReg := types.NewTypeRegistry()
	types.RegisterCoreTypes(typeReg)

	reg := handler.NewRegistry()

	// Register connect handler.
	ch, err := protocol.NewConnectHandler(kp, cfg.protocols)
	if err != nil {
		return nil, err
	}
	if cfg.connectionGrants != nil {
		ch.SetConnectionGrants(cfg.connectionGrants)
	}
	if cfg.grantResolver != nil {
		ch.SetGrantResolver(cfg.grantResolver)
	}
	// V7 v7.62 §3 advertisement discipline: connect handler filters
	// advertised grants against the registry's installed handlers at
	// authenticate-time. The closure binds `reg` so registrations that
	// land later in the builder (extension handlers below) are visible.
	ch.SetHandlerRegisteredFn(func(pattern string) bool {
		_, _, ok := reg.Resolve(pattern)
		return ok
	})
	registerHandler(reg, typeReg, "system/protocol/connect", ch)

	// Register tree handler.
	th := tree.NewHandler()
	if cfg.rootTracker != nil {
		th.SetRootTracker(cfg.rootTracker)
	}
	registerHandler(reg, typeReg, "system/tree", th)

	// Register custom handlers (includes extension handlers like
	// system/callback). Iteration is in insertion order — extension types
	// reflect via cross-package struct fields and the registration depends
	// on prior types being known. See handlerEntry doc in builder.go.
	for _, e := range cfg.handlers {
		registerHandler(reg, typeReg, e.pattern, e.h)
	}

	// Populate tree from registries (uses namespaced index — events fire during seed).
	if err := seedFromRegistries(typeReg, reg, cs, namespacedLI); err != nil {
		return nil, fmt.Errorf("seed system tree: %w", err)
	}

	// Create handler grants for each registered handler.
	if err := createHandlerGrants(reg, kp, identity, cs, namespacedLI); err != nil {
		return nil, fmt.Errorf("create handler grants: %w", err)
	}

	// V7 v7.74 Phase 2 §6.9a: materialize the principal-level self-owner
	// seed entry (and any operator-declared seed policy) at L0. Coexists
	// with per-handler self-grants above per §6.9a.4. The owner identity
	// defaults to the peer's own identity hash; WithOwnerIdentity overrides
	// for multi-key / operator models.
	ownerHash := identity.ContentHash
	if cfg.ownerIdentityHash != nil {
		ownerHash = *cfg.ownerIdentityHash
	}
	if err := createSeedPolicyEntries(ownerHash, cfg.seedPolicy, cs, namespacedLI); err != nil {
		return nil, fmt.Errorf("create seed policy entries: %w", err)
	}

	// Advertise supported durability levels (EXTENSION-DURABILITY §3 — MAY,
	// discovery only; absence does not change the §5 response contract).
	// EXTENSION-DURABILITY is exploratory/optional; this seed runs
	// unconditionally as part of the Go reference implementation.
	// Seeded within the suppression window so it does not emit a startup
	// event. Reflects the dispatcher's default policy; a custom policy is
	// authoritative via the response verdict regardless.
	if adEnt, err := protocol.DefaultDurabilityPolicy().Advertisement().ToEntity(); err == nil {
		if h, err := cs.Put(adEnt); err == nil {
			_ = namespacedLI.Set(types.DurabilityAdvertisementPath, h)
		}
	}

	// Initialize context field registry (SYSTEM-COMPOSITION §1.5).
	contextFields := store.NewContextFieldRegistry()
	for _, reg := range cfg.contextFields {
		if err := contextFields.Register(reg); err != nil {
			return nil, fmt.Errorf("register context field: %w", err)
		}
	}

	// End the seed-suppression window. From here on, emit fires events
	// normally; fanOut takes over the channel below. No straggler events
	// to discard (suppression means none were emitted to the channel).
	notifyingLI.SetEmitSuppressed(false)

	dispatcher := protocol.NewDispatcher(reg, cs, namespacedLI, kp, cfg.debugLog)
	dispatcher.CapabilityIndex = capability.NewMemoryCapabilityIndex()
	if cfg.identityBindingChecker != nil {
		dispatcher.IdentityBindingChecker = cfg.identityBindingChecker
	}
	if len(cfg.dispatchHooks) > 0 {
		dispatcher.SetDispatchHooks(cfg.dispatchHooks)
	}
	// Wire hooks are owned by the peer (passed to each Connection at construction).
	wireHooks := cfg.wireHooks

	// Set up event routing. Each sink runs with per-sink isolation: a slow or
	// un-drained sink fills its OWN buffer and drops with metric, without
	// stalling other sinks (per the event-delivery-backpressure design). The internal `externalEvents` channel is always
	// created so peer.TreeEvents() works; if no caller drains it, it fills
	// and drops with its drop count visible via fanOutStats.
	externalEvents := make(chan store.TreeChangeEvent, eventBufSize)
	allSinks := make([]chan<- store.TreeChangeEvent, 0, len(cfg.treeEventSinks)+1)
	sinkNames := make([]string, 0, len(cfg.treeEventSinks)+1)
	allSinks = append(allSinks, cfg.treeEventSinks...)
	for i := range cfg.treeEventSinks {
		sinkNames = append(sinkNames, fmt.Sprintf("user-sink[%d]", i))
	}
	allSinks = append(allSinks, externalEvents)
	sinkNames = append(sinkNames, "peer.TreeEvents()")
	fanOutStats := fanOut(treeEvents, treeEventsDone, allSinks...)
	fanOutStats.SetSinkNames(sinkNames)
	if cfg.debugLog != nil {
		fanOutStats.SetLogger(cfg.debugLog)
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	p := &Peer{
		keypair:         kp,
		peerID:          kp.PeerID(),
		identity:        identity,
		store:           cs,
		locationIndex:   namespacedLI,
		namespacedIndex: namespacedLI,
		registry:        reg,
		dispatcher:      dispatcher,
		connectHandler:  ch,
		debugLog:        cfg.debugLog,
		contextFields:   contextFields,
		treeEvents:      externalEvents,
		treeEventsDone:  treeEventsDone,
		fanOutStats:     fanOutStats,
		notifyingIndex:  notifyingLI,
		listenAddr:      cfg.listenAddr,
		closeFuncs:      cfg.closeFuncs,
		remote:          remoteState{conns: make(map[crypto.PeerID]remoteEndpoint)},
		serveCtx:        serveCtx,
		serveCancel:     serveCancel,
		wireHooks:       wireHooks,
	}

	// Wire remote execute.
	dispatcher.RemoteExecute = p.remoteExecute

	// Register configured remote peers (seeds transport addresses in tree).
	for _, r := range cfg.remotes {
		if err := p.RegisterRemote(r.peerID, r.addr); err != nil {
			return nil, fmt.Errorf("register remote %s: %w", r.peerID, err)
		}
	}

	return p, nil
}

// PeerID returns the peer's identifier.
func (p *Peer) PeerID() crypto.PeerID {
	return p.peerID
}

// Keypair returns the peer's keypair.
func (p *Peer) Keypair() crypto.Keypair {
	return p.keypair
}

// Identity returns the peer's identity entity.
func (p *Peer) Identity() entity.Entity {
	return p.identity
}

// Store returns the peer's content store.
func (p *Peer) Store() store.ContentStore {
	return p.store
}

// LocationIndex returns the peer's location index.
func (p *Peer) LocationIndex() store.LocationIndex {
	return p.locationIndex
}

// NamespacedIndex returns the peer's namespace-aware location index.
// Use this for explicit namespace operations (remote peer data).
func (p *Peer) NamespacedIndex() *store.NamespacedIndex {
	return p.namespacedIndex
}

// Registry returns the peer's handler registry.
func (p *Peer) Registry() *handler.Registry {
	return p.registry
}

// Dispatcher returns the peer's protocol dispatcher.
// SetGrantResolver sets (or replaces) the dynamic grant resolver consulted
// by the connect handler at AUTHENTICATE time. Used to compose the role-
// extension's policy resolver (which needs post-construction access to the
// peer's store + attestation index) with any static resolver wired via
// WithGrantResolver. See ext/role/policy.go for the role-aware resolver
// and cmd/entity-peer for the typical wiring sequence.
func (p *Peer) SetGrantResolver(r protocol.GrantResolver) {
	if p.connectHandler != nil {
		p.connectHandler.SetGrantResolver(r)
	}
}

func (p *Peer) Dispatcher() *protocol.Dispatcher {
	return p.dispatcher
}

// ContextFields returns the peer's extension-contributed context field registry.
func (p *Peer) ContextFields() *store.ContextFieldRegistry {
	return p.contextFields
}

// Connections returns a snapshot of active connections (inbound + outbound).
// The returned slice is a copy — mutating it does not affect the peer's state.
//
// A pooled outbound connection sits in both p.connections (added at dial time)
// and p.remote.conns (added when promoted to the per-peer-id pool); we dedupe
// by pointer so each connection appears at most once.
func (p *Peer) Connections() []*Connection {
	p.mu.Lock()
	inbound := make([]*Connection, len(p.connections))
	copy(inbound, p.connections)
	p.mu.Unlock()

	p.remote.mu.Lock()
	pooled := make([]*Connection, 0, len(p.remote.conns))
	for _, c := range p.remote.conns {
		// Connections() exposes only TCP *Connection objects — that has
		// always been its contract (per-connection state, wire framing,
		// multiplexed reader, etc.). HTTP endpoints in the pool have no
		// equivalent surface and are skipped here; callers that need
		// HTTP-substrate observability go through a separate path.
		if tcp, ok := c.(*Connection); ok {
			pooled = append(pooled, tcp)
		}
	}
	p.remote.mu.Unlock()

	seen := make(map[*Connection]struct{}, len(inbound)+len(pooled))
	out := make([]*Connection, 0, len(inbound)+len(pooled))
	for _, c := range inbound {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	for _, c := range pooled {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// Listen starts accepting connections on the configured address.
// The ready channel, if non-nil, is closed once the listener is active.
func (p *Peer) Listen(ctx context.Context) error {
	return p.ListenReady(ctx, nil)
}

// ListenReady starts accepting connections. If ready is non-nil, it is closed
// once the listener is bound and accepting.
func (p *Peer) ListenReady(ctx context.Context, ready chan struct{}) error {
	if p.listenAddr == "" {
		return fmt.Errorf("no listen address configured")
	}

	ln, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	p.mu.Lock()
	p.listener = ln
	p.mu.Unlock()

	if ready != nil {
		close(ready)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.isClosed() {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				continue
			}
		}
		p.debugf("accepted connection from %s", conn.RemoteAddr())
		c := newConnection(p, conn)
		p.addConnection(c)
		// Per-connection serve uses the peer-lifetime ctx, NOT the
		// caller's listener ctx — see Peer.serveCtx doc. The listener
		// ctx still bounds the Accept loop (above); only spawned
		// serves are decoupled. F18 fix.
		go c.serve(p.serveCtx)
	}
}

// Addr returns the listener address, or nil if not listening.
func (p *Peer) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return nil
	}
	return p.listener.Addr()
}

// Connect dials a remote peer.
func (p *Peer) Connect(ctx context.Context, addr string) (*Connection, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	c := newConnection(p, conn)
	p.addConnection(c)
	return c, nil
}

// ListenWebSocketReady starts an HTTP listener bound to addr that
// upgrades incoming requests at urlPath to WebSocket (V7 §6.5.2b) and
// hands each accepted connection to the same newConnection().serve()
// flow TCP uses. The wire codec is byte-identical to TCP — one
// length-prefixed ECF envelope per binary WS message per §6.5.2c L864.
//
// If ready is non-nil, it is closed once the HTTP listener is bound.
// Returns when ctx is cancelled or the listener exits.
//
// AcceptOptions sets InsecureSkipVerify=true so browser dev tooling and
// LAN demos do not need Origin negotiation; production wss://
// deployments are expected to terminate TLS at a reverse proxy that
// gates Origin upstream.
func (p *Peer) ListenWebSocketReady(ctx context.Context, addr, urlPath string, ready chan struct{}) error {
	if addr == "" {
		return fmt.Errorf("websocket listen: empty address")
	}
	if urlPath == "" {
		urlPath = "/ws"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("websocket listen: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(urlPath, func(w http.ResponseWriter, r *http.Request) {
		c, err := coderws.Accept(w, r, &coderws.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			p.debugf("ws: accept failed: %v", err)
			return
		}
		// Connection lifetime is bounded by the peer-lifetime serveCtx,
		// NOT the http.Request ctx (which expires after this handler
		// returns — see http.Hijacker note in coder/websocket docs).
		local := wsAddr{url: "ws://" + ln.Addr().String() + urlPath}
		remote := wsAddr{url: "ws://" + r.RemoteAddr + urlPath}
		wConn := newWSConn(p.serveCtx, c, local, remote)
		p.debugf("ws: accepted connection from %s", r.RemoteAddr)
		conn := newConnection(p, wConn)
		p.addConnection(conn)
		// Block until the connection's serve loop returns. http.Server
		// would otherwise close the underlying TCP socket as soon as
		// this handler returns, which collapses the WS session.
		conn.serve(p.serveCtx)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if ready != nil {
		close(ready)
	}

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
		_ = ln.Close()
	}()

	err = srv.Serve(ln)
	if err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
		return fmt.Errorf("websocket serve: %w", err)
	}
	return nil
}

// ConnectWebSocket dials a remote peer over WebSocket and returns a
// *Connection that drives the same handshake + Execute paths TCP uses.
// The wire codec is byte-identical (V7 §6.5.2c L864 framing reuse).
func (p *Peer) ConnectWebSocket(ctx context.Context, url string) (*Connection, error) {
	c, _, err := coderws.Dial(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", url, err)
	}
	local := wsAddr{url: "ws://local"}
	remote := wsAddr{url: url}
	wConn := newWSConn(p.serveCtx, c, local, remote)
	conn := newConnection(p, wConn)
	p.addConnection(conn)
	return conn, nil
}

// Close shuts down the peer and all connections.
func (p *Peer) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := p.connections
	p.connections = nil
	p.mu.Unlock()

	// Cancel the peer-lifetime serve ctx so any blocked or about-to-loop
	// serve goroutines exit promptly. The actual conn teardown happens
	// below via c.Close(); cancelling here is the signal for the select
	// branches inside serve() that watch ctx.Done(). F18 fix companion.
	if p.serveCancel != nil {
		p.serveCancel()
	}

	// Run registered close funcs (extension cleanup, engine cancellation, etc.).
	for _, fn := range p.closeFuncs {
		fn()
	}

	// Stop the bounded async-dispatch pool and join in-flight jobs (bounded)
	// before tearing down connections so in-flight deliveries can finish
	// cleanly. Refuses any further submissions.
	if p.dispatcher != nil {
		p.dispatcher.StopAsyncPool()
	}

	// Close cached remote connections.
	p.closeRemoteConnections()

	// Stop event emission first, then close the raw events channel.
	// treeEventsDone signals the notifying index to stop, and also stops the fan-out.
	close(p.treeEventsDone)

	for _, c := range conns {
		c.Close()
	}

	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// TreeEvents returns a read-only channel that emits tree change events.
// The channel is closed when the Peer is closed.
//
// **Backpressure contract.** This sink has per-sink isolation: if the
// caller doesn't drain, this sink's buffer fills and starts dropping
// events FOR THIS SINK ONLY. Other sinks and the rest of the peer
// continue uninterrupted. To detect drops, monitor PeerStats().FanOut
// — the last entry is this channel's drop count. A non-zero count
// means events were lost for callers of TreeEvents() because the
// caller wasn't draining fast enough.
//
// **Recommended usage**: spawn a goroutine that drains this channel,
// even if you discard the events (no-op drainer pattern). If you
// don't, you accept silent loss for this sink.
func (p *Peer) TreeEvents() <-chan store.TreeChangeEvent {
	return p.treeEvents
}

// PeerStats is a snapshot of internal queue and saturation counters.
// Use for observability dashboards and health probes.
type PeerStats struct {
	// EventBufferDrops counts tree events dropped because the events
	// channel (the head of the fan-out pipeline) was full when emit
	// fired. A non-zero count means callers of Set saw ErrEventBufferFull.
	EventBufferDrops uint64

	// FanOutSinks reports per-sink drop counts (in registration order:
	// user-registered sinks first via WithTreeEventSink, then peer.TreeEvents()
	// last). Each is the count of events dropped because that specific sink's
	// buffer was full while fanOut was distributing.
	FanOutSinks []uint64

	// AsyncDispatchRefused counts fire-and-forget async dispatch jobs
	// (continuation-advance + deliver_to delivery) rejected because the
	// bounded async-dispatch pool was saturated or stopped. A growing value
	// means the peer is shedding async load (callers got 429 / messages
	// retained in the durable mailbox) rather than spawning unbounded
	// goroutines — see CONCURRENCY-BACKPRESSURE-REVIEW §7.5.
	AsyncDispatchRefused uint64
}

// Stats returns a snapshot of the peer's observability counters.
// Intended for ops dashboards, health probes, and saturation alerts.
// All counters are monotonic and atomic — safe to call concurrently.
func (p *Peer) Stats() PeerStats {
	stats := PeerStats{}
	if p.notifyingIndex != nil {
		stats.EventBufferDrops = p.notifyingIndex.DroppedEvents()
	}
	if p.fanOutStats != nil {
		stats.FanOutSinks = p.fanOutStats.AllDrops()
	}
	if p.dispatcher != nil {
		stats.AsyncDispatchRefused = p.dispatcher.AsyncDispatchRefused()
	}
	return stats
}

// drainEvents reads and discards all pending events from a channel.
func drainEvents(ch <-chan store.TreeChangeEvent) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func (p *Peer) addConnection(c *Connection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connections = append(p.connections, c)
}

func (p *Peer) removeConnection(c *Connection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, conn := range p.connections {
		if conn == c {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			return
		}
	}
}

func (p *Peer) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *Peer) debugf(format string, args ...any) {
	if p.debugLog != nil {
		p.debugLog.Printf(format, args...)
	}
}

// registerHandler registers a handler and has it contribute types.
func registerHandler(reg *handler.Registry, typeReg *types.TypeRegistry, pattern string, h handler.Handler) {
	reg.Register(pattern, h)
	if tp, ok := h.(handler.TypeProvider); ok {
		tp.RegisterTypes(typeReg)
	}
}

// createHandlerGrants creates a self-granted capability token for each handler
// and stores it at system/capability/grants/{pattern} in the tree.
//
// Per spec-gap-handler-grant-authority §S2, dispatch-time grant validation
// resolves the granter's identity entity from the content store to verify
// the signature. We pre-populate the local peer's identity entity here so
// validation can find it for any handler grant we just signed.
func createHandlerGrants(reg *handler.Registry, kp crypto.Keypair, identity entity.Entity, cs store.ContentStore, li store.LocationIndex) error {
	if _, err := cs.Put(identity); err != nil {
		return fmt.Errorf("store local identity entity: %w", err)
	}
	for pattern, h := range reg.Handlers() {
		mp, ok := h.(handler.ManifestProvider)
		if !ok {
			continue
		}
		manifest := mp.Manifest()

		// Skip if the grant already exists at the canonical path. Handler
		// grants are Class I (install-once) per
		// docs/architecture/proposals/active/DEFERRED-PERSISTENCE-FOLLOWUPS.md
		// and entity-core-architecture .../guides/GUIDE-RESTART-AND-PERSISTENCE.md
		// §2.2 — the install-time value is canonical for the peer's lifetime
		// under this identity. Re-minting would either churn (with a real
		// timestamp) or duplicate work (with deterministic content). Persistent
		// stores skip the mint entirely; memory stores have nothing at the
		// path so always mint.
		grantPath := "system/capability/grants/" + pattern
		if _, exists := li.Get(grantPath); exists {
			continue
		}

		// Determine internal scope from manifest, or default to full access.
		scope := manifest.InternalScope
		if len(scope) == 0 {
			scope = []types.GrantEntry{
				{
					Handlers:   types.CapabilityScope{Include: []string{"*"}},
					Resources:  types.CapabilityScope{Include: []string{"*"}},
					Operations: types.CapabilityScope{Include: []string{"*"}},
				},
			}
		}

		// CreatedAt fixed at zero. Handler grants have no TTL — they live for
		// the peer's identity lifetime and are not consulted for time-based
		// validation. Zero keeps content deterministic so the skip-if-exists
		// path above produces stable hashes if it ever races (defense in
		// depth — the existence check is the primary mechanism).
		capData := types.CapabilityTokenData{
			Grants:    scope,
			Granter:   types.SingleSigGranter(identity.ContentHash),
			Grantee:   identity.ContentHash,
			CreatedAt: 0,
		}
		capEntity, err := capData.ToEntity()
		if err != nil {
			return fmt.Errorf("create handler grant for %s: %w", manifest.Name, err)
		}

		sig := kp.Sign(capEntity.ContentHash.Bytes())
		sigData := types.SignatureData{
			Target:    capEntity.ContentHash,
			Signer:    identity.ContentHash,
			Algorithm: crypto.KeyTypeString(kp.KeyType),
			Signature: sig,
		}
		sigEntity, err := sigData.ToEntity()
		if err != nil {
			return fmt.Errorf("create handler grant signature for %s: %w", manifest.Name, err)
		}

		capHash, err := cs.Put(capEntity)
		if err != nil {
			return fmt.Errorf("store handler grant for %s: %w", manifest.Name, err)
		}
		sigHash, err := cs.Put(sigEntity)
		if err != nil {
			return fmt.Errorf("store handler grant sig for %s: %w", manifest.Name, err)
		}

		if err := li.Set(grantPath, capHash); err != nil {
			return fmt.Errorf("bind handler grant for %s: %w", manifest.Name, err)
		}
		// v7.74 v0.4 §3.4: bind the signature at the invariant-pointer path
		// system/signature/{grant_hash} (the same convention as every other
		// signature in the address space). Dispatch-time grant validation
		// resolves the path from the grant's content_hash.
		if err := li.Set(types.LocalSignaturePath(capEntity.ContentHash), sigHash); err != nil {
			return fmt.Errorf("bind handler grant sig for %s: %w", manifest.Name, err)
		}
	}
	return nil
}

// SeedPolicyEntry declares a startup-time capability policy entry per
// V7 v7.74 Phase 2 §6.9a. Each entry materializes at L0 as a
// system/capability/policy-entry stored at
// system/capability/policy/{Pattern} per v7.64 dual-form discipline.
//
// Use SeedPolicyForIdentity (hex form, canonical), SeedPolicyForPeerID
// (Base58 form, pre-contact affordance), or SeedPolicyDefault for the
// fallback entry.
type SeedPolicyEntry struct {
	Pattern string
	Grants  []types.GrantEntry
	TTLMs   *uint64
	Notes   string
}

// SeedPolicyForIdentity builds a v7.64 hex-form seed policy entry keyed
// by the grantee's system/peer entity content_hash.
func SeedPolicyForIdentity(identityHash hash.Hash, grants []types.GrantEntry) SeedPolicyEntry {
	return SeedPolicyEntry{
		Pattern: hex.EncodeToString(identityHash.Bytes()),
		Grants:  grants,
	}
}

// SeedPolicyForPeerID builds a v7.64 Base58-form seed policy entry keyed
// by the grantee's Base58 PeerID. The connect handler canonicalizes
// Base58→hex on first cap-match per v7.64 §2.3.
func SeedPolicyForPeerID(peerID crypto.PeerID, grants []types.GrantEntry) SeedPolicyEntry {
	return SeedPolicyEntry{
		Pattern: string(peerID),
		Grants:  grants,
	}
}

// SeedPolicyDefault builds the fallback seed policy entry at the literal
// "default" segment per v7.64 §2.1.
func SeedPolicyDefault(grants []types.GrantEntry) SeedPolicyEntry {
	return SeedPolicyEntry{
		Pattern: "default",
		Grants:  grants,
	}
}

// createSeedPolicyEntries writes declared seed policy entries at L0 per
// V7 v7.74 Phase 2 §6.9a. Each entry binds a system/capability/policy-entry
// at system/capability/policy/{Pattern} that the connect handler reads
// at authenticate-time via the existing v7.62 §8 union/subset substrate.
//
// The self-owner seed entry (grantee = ownerIdentityHash; scope = full
// over the local namespace) is materialized first per §6.9a A1 (the
// key-holder is owner by construction). Additional declared entries are
// written in order. Coexists with createHandlerGrants per §6.9a.4 — the
// per-handler self-grants stay in place.
func createSeedPolicyEntries(
	ownerIdentityHash hash.Hash,
	extraEntries []SeedPolicyEntry,
	cs store.ContentStore,
	li store.LocationIndex,
) error {
	selfEntry := SeedPolicyForIdentity(ownerIdentityHash, []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*", "/*/*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}})
	selfEntry.Notes = "v7.74 §6.9a self-owner seed entry"

	entries := append([]SeedPolicyEntry{selfEntry}, extraEntries...)
	for _, e := range entries {
		if e.Pattern == "" {
			return fmt.Errorf("seed policy entry has empty pattern")
		}
		path := "system/capability/policy/" + e.Pattern
		if _, exists := li.Get(path); exists {
			// Class I (install-once): if an entry already exists at this
			// path (operator-supplied policy table from a prior run, or
			// a runtime-configured entry persisted across restart), do
			// not clobber it. The self-owner seed is the floor; operator
			// edits via system/capability:configure take precedence.
			continue
		}
		pe := types.CapabilityPolicyEntryData{
			PeerPattern: e.Pattern,
			Grants:      e.Grants,
			TTLMs:       e.TTLMs,
			Notes:       e.Notes,
		}
		ent, err := pe.ToEntity()
		if err != nil {
			return fmt.Errorf("build seed policy entry %s: %w", e.Pattern, err)
		}
		h, err := cs.Put(ent)
		if err != nil {
			return fmt.Errorf("store seed policy entry %s: %w", e.Pattern, err)
		}
		if err := li.Set(path, h); err != nil {
			return fmt.Errorf("bind seed policy entry %s: %w", e.Pattern, err)
		}
	}
	return nil
}

// seedFromRegistries populates the tree from the type registry and handler manifests.
func seedFromRegistries(typeReg *types.TypeRegistry, reg *handler.Registry, cs store.ContentStore, li store.LocationIndex) error {
	// Type definitions → system/type/*
	for _, td := range typeReg.All() {
		ent, err := td.ToEntity()
		if err != nil {
			return fmt.Errorf("create type entity %s: %w", td.Name, err)
		}
		h, err := cs.Put(ent)
		if err != nil {
			return fmt.Errorf("store type entity %s: %w", td.Name, err)
		}
		if err := li.Set(td.TreePath(), h); err != nil {
			return fmt.Errorf("bind type entity %s: %w", td.Name, err)
		}
	}

	// For each handler, store two entities per N5 (handler normalization):
	//   1. system/handler/interface at system/handler/{pattern} — public contract
	//   2. system/handler at {pattern} — dispatch target with interface path ref
	for pattern, h := range reg.Handlers() {
		mp, ok := h.(handler.ManifestProvider)
		if !ok {
			// Compiled handler without a manifest (typical for
			// peer.WithHandler custom handlers). Seed a minimal
			// system/handler entity so V7 §6.6 tree-walk dispatch
			// can resolve it — without this, the handler is reachable
			// only through the in-memory registry, breaking any caller
			// that honors "tree is the source of truth." No grant is
			// emitted; loadValidatedGrant allows the missing-grant
			// fall-through for compiled handlers (dispatch.go:341).
			hd := types.HandlerData{Interface: "system/handler/" + pattern}
			ent, err := hd.ToEntity()
			if err != nil {
				return fmt.Errorf("create minimal handler entity %s: %w", pattern, err)
			}
			hh, err := cs.Put(ent)
			if err != nil {
				return fmt.Errorf("store minimal handler entity %s: %w", pattern, err)
			}
			if err := li.Set(pattern, hh); err != nil {
				return fmt.Errorf("bind minimal handler entity %s: %w", pattern, err)
			}
			continue
		}
		manifest := mp.Manifest()

		// Interface entity (public contract: pattern, name, operations).
		ifacePath := "system/handler/" + pattern
		ifaceEnt, err := manifest.InterfaceData().ToEntity()
		if err != nil {
			return fmt.Errorf("create handler interface %s: %w", manifest.Name, err)
		}
		ifaceHash, err := cs.Put(ifaceEnt)
		if err != nil {
			return fmt.Errorf("store handler interface %s: %w", manifest.Name, err)
		}
		if err := li.Set(ifacePath, ifaceHash); err != nil {
			return fmt.Errorf("bind handler interface %s: %w", manifest.Name, err)
		}

		// Handler entity (dispatch target: interface ref + scope).
		handlerData := types.HandlerData{
			Interface:      ifacePath,
			MaxScope:       manifest.MaxScope,
			InternalScope:  manifest.InternalScope,
			ExpressionPath: manifest.ExpressionPath,
		}
		handlerEnt, err := handlerData.ToEntity()
		if err != nil {
			return fmt.Errorf("create handler entity %s: %w", manifest.Name, err)
		}
		handlerHash, err := cs.Put(handlerEnt)
		if err != nil {
			return fmt.Errorf("store handler entity %s: %w", manifest.Name, err)
		}
		if err := li.Set(pattern, handlerHash); err != nil {
			return fmt.Errorf("bind handler entity %s: %w", manifest.Name, err)
		}
	}

	return nil
}
