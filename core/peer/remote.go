package peer

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// defaultTCPProfileID is the profile-id Go assigns when RegisterRemote
// stores a peer's TCP profile entity at
// system/peer/transport/{peer_id}/{profile-id}. Per EXTENSION-NETWORK
// §6.5 a peer MAY publish multiple profiles of the same transport-type
// (primary, cdn-mirror, backup-relay); the SELECTION RULE among them
// is undefined — flagged for arch as E1 in CROSS-IMPL-HANDOFF §10.
// "primary" matches the cohort default while arch pins a stable rule.
const defaultTCPProfileID = "primary"

// defaultHTTPProfileID is the profile-id Go assigns when
// RegisterRemoteHTTP stores a peer's HTTP profile entity. Per PROPOSAL-
// TRANSPORT-FAMILY-LIVE-REACHABILITY-AND-SESSION-LIFECYCLE §7.3 (G1),
// HTTP MUST NOT collide with the TCP default "primary" — registering
// both transports on the same peer must produce two distinct profile
// entries, not a silent overwrite. Lex-sorts after "primary" under D-1
// so TCP remains the first-tried transport when both are published.
const defaultHTTPProfileID = "primary-http"

// defaultWSProfileID is the profile-id Go assigns when RegisterRemoteWS
// stores a peer's WebSocket profile entity. Distinct from the TCP
// "primary" and HTTP "primary-http" defaults so a single peer can
// advertise all three transports concurrently per G1 (one profile-id
// per published transport, no silent overwrite). Lex-sorts after both,
// so TCP and HTTP are tried first when multiple substrates coexist.
const defaultWSProfileID = "primary-ws"

// transportProfilePrefix returns the location-index prefix under which
// {peerID}'s transport profile entries live: system/peer/transport/{peer_id_hex}/
// Per EXTENSION-NETWORK §6.5 + v7.64 path-encoding alignment.
//
// V7.64: the path segment is the canonical content_hash hex of the peer's
// `system/peer` entity (not the Base58 PeerID). For identity-form PeerIDs
// (v7.64 default) this is a pure local computation; for SHA-256-form
// PeerIDs the helper falls back to an empty string and callers must
// route through a public_key-aware variant.
func transportProfilePrefix(peerID crypto.PeerID) string {
	h, err := types.ComputePeerIdentityHashFromPeerID(peerID)
	if err != nil {
		return ""
	}
	return "system/peer/transport/" + types.PeerIdentityHashHex(h) + "/"
}

// transportProfilePrefixForHash is the canonical form taking the already-
// derived identity hash. Use this when the caller already holds the hash
// (e.g. handshake-time from remote_identity_hash).
func transportProfilePrefixForHash(peerHash hash.Hash) string {
	return "system/peer/transport/" + types.PeerIdentityHashHex(peerHash) + "/"
}

// remoteState holds the connection pool for outbound remote-peer
// endpoints. Values are remoteEndpoint — concretely *Connection for TCP
// or *HTTPConnection for HTTP. The pool is transport-agnostic; the
// transport-specific dial path runs inside getRemoteConnection.
type remoteState struct {
	mu    sync.Mutex
	conns map[crypto.PeerID]remoteEndpoint
	// inboundConns is the V7 §6.11 reentry fallback pool: server-side
	// connections registered at handshake completion so an inbound
	// handler can originate outbound EXECUTE to the remote peer reusing
	// the SAME connection. Consulted by getRemoteConnection only when
	// transport-profile resolution fails — the dialed pool above wins
	// when both are available. See registerInboundForReentry.
	inboundConns map[crypto.PeerID]*Connection
	// preferRelay is the session-local, NEVER-published prefer-relay memo
	// (NETWORK §10.3 obligation 4 / SIGNALING §7.2): a peer whose direct-path
	// traversal failed under a §4.1 reconnect is marked here so later reconnects
	// skip the live-establishment seam and let the relay path carry it. Cleared
	// once the peer is reachable again. Local optimization only — it is a MAY and
	// affects nothing on the wire.
	preferRelay map[crypto.PeerID]bool
}

// transportTarget is the resolution result for a remote peer's
// transport profile. typeURI is the entity type URI of the chosen
// profile (TypePeerTransportTCP or TypePeerTransportHTTP); endpoint
// is the host:port (tcp) or full URL (http) extracted from the profile.
type transportTarget struct {
	typeURI  string
	endpoint string
}

// DispatchFallbackFunc is the NETWORK §10 step-4 sender-side store-and-
// forward seam per PROPOSAL-DISPATCH-FALLBACK-SEAM-SENDER-SIDE-STORE-AND-
// FORWARD (DRAFT). Consulted by remoteExecute / RemoteExecute
// / RemoteExecuteWithIncluded when getRemoteConnection fails — no live
// session, no transport profile, dial refused — AFTER the §6.11 reentry
// fallback and BEFORE returning the unreachable error.
//
// Return contract:
//
//   - (resp, true,  nil) — fallback handled the dispatch. resp surfaces
//     to the caller as the synthetic Response (typically a relay-style
//     queued-fallback status with the inner stored_at namespace).
//   - (nil,  false, nil) — fallback declined (e.g. no inbox-relay
//     declaration known, no usable home relay). Caller falls through to
//     today's local-queue/502 path; behavior is byte-identical to v1.
//   - (nil,  true,  err) — fallback attempted but failed. NETWORK never
//     silent-drops (§4.3 fail-closed); the error wraps the cause.
//
// RELAY (or any other extension) registers a fallback via
// (*Peer).SetDispatchFallback at peer-builder time. Layer-honest by
// construction: NETWORK consults a function value, never reaches into
// RELAY semantics.
type DispatchFallbackFunc func(ctx context.Context, peerID crypto.PeerID,
	uri, operation string, params entity.Entity,
	resource *types.ResourceTarget) (*handler.Response, bool, error)

// SetDispatchFallback installs the NETWORK §10 step-4 fallback seam.
// Pass nil to disable. Non-RELAY peers leave it unset and the dispatch
// ladder behaves exactly as v1 (queue/502 on unreachable).
func (p *Peer) SetDispatchFallback(fn DispatchFallbackFunc) {
	p.dispatchFallback = fn
}

// LiveEstablishFunc is the NETWORK §10.3 step-3b live-establishment seam
// (Amendment 14). Consulted by remoteExecute / RemoteExecuteWithIncluded when
// getRemoteConnection fails (no durable profile connected) and BEFORE
// dispatchFallback (§10.2 — the normative "live first, store-and-forward last"
// ordering). A traversal extension (EXTENSION-SIGNALING §7's hole punch)
// registers the policy behind this seam; peers with none leave it nil and the
// ladder is byte-identical to the pre-seam behavior.
//
// It carries a context (the §10.3 review delta this impl fed back to arch: a
// traversal "takes seconds" and a caller with no deadline is a hang — so the
// seam MUST be cancellable). It returns a CONNECTION, not a delivered result:
// on a non-nil return the ladder re-enters ordinary dispatch and the
// connection is pooled (AddRemoteConnection), so every later dispatch to that
// peer reuses it and it runs §5 keepalive — §10.3 obligations 1 and 2.
//
// Return contract:
//   - (conn, nil)  — traversal established a live transport; the ladder pools
//     and sends through it.
//   - (nil,  nil)  — no traversal path (symmetric NAT / CGNAT / not eligible);
//     the ladder falls through to dispatchFallback, then the terminal.
//   - (nil,  err)  — traversal attempted and failed; treated as (nil, nil) for
//     dispatch (fall through) — the error is for the seam's own observability.
type LiveEstablishFunc func(ctx context.Context, peerID crypto.PeerID) (*Connection, error)

// SetLiveEstablish installs the NETWORK §10.3 step-3b live-establishment seam.
// Pass nil to disable. Peers with no traversal extension leave it unset and the
// dispatch ladder behaves exactly as pre-Amendment-14 (fall straight to §10.2 /
// the terminal on a NAT'd target with no durable profile).
func (p *Peer) SetLiveEstablish(fn LiveEstablishFunc) {
	p.establishLive = fn
}

// tryEstablishLive consults the §10.3 seam and, on a live connection, pools it
// (which also begins §5 keepalive — §10.3 obligation 2) so the ladder re-enters
// ordinary dispatch and later calls reuse it. Returns nil when no seam is
// registered, the seam declines, or pooling fails — every one of which is a
// "fall through to §10.2" signal, never a hard error (traversal is best-effort;
// correctness is preserved by the store-and-forward fallback below it).
func (p *Peer) tryEstablishLive(ctx context.Context, peerID crypto.PeerID) remoteEndpoint {
	seam := p.establishLive
	if seam == nil {
		return nil
	}
	conn, err := seam(ctx, peerID)
	if err != nil || conn == nil {
		// THE OUTCOME IS UNCHANGED — still nil, still a fall-through to §10.2.
		// What changes is that the REASON is no longer discarded.
		//
		// Every live-establishment failure used to arrive here and vanish: not
		// logged, not counted, not distinguishable. That is fine while every
		// failure really is "no direct path" — and stops being fine the moment
		// a §6.3 collect policy can refuse a counterpart, because a policy
		// refusal then presents to an operator as a NAT problem and gets
		// diagnosed as one. entity-core-rust hit exactly this on their own
		// policy raise (their refusal logged at debug alongside every traversal
		// failure, driver reporting "no direct path within the deadline") and
		// fixed it; ours is currently worse, because there is no log at all.
		//
		// It is LATENT here rather than live: Go's production posture is
		// tolerant (peerwiring.DefaultTrust), so no refusal can reach this line
		// yet. It arms itself the moment that constant flips to Require, which
		// is the next step of the §6.1 flag day — so this lands before the flip
		// rather than after it.
		//
		// core/peer cannot name the §6.3 sentinel: the DAG forbids core from
		// importing ext, and ext/signaling is where that error lives. It does
		// not need to — the error's own text says which check refused, so the
		// reason travels without this layer knowing the taxonomy.
		if err != nil {
			p.debugf("live-establishment seam declined for %s: %v", peerID, err)
		}
		return nil
	}
	// Pool it as an ordinary transport (§10.3 obligation 1) and start keepalive
	// (obligation 2). AddRemoteConnection resolves the race if a connection for
	// peerID already landed, returning whichever is now pooled.
	pooled, aerr := p.AddRemoteConnection(peerID, conn)
	if aerr != nil {
		conn.Close()
		return nil
	}
	return pooled
}

// callerOwnedRetryKey marks a live-establishment consultation whose retry is owned
// by the CALLER — a §4.1 maintain-peer/reconnect continuation whose own backoff is
// the retry authority. A seam implementation reads it (CallerOwnsRetry) and makes
// exactly ONE attempt, per NETWORK §10.3 obligation 4 / SIGNALING §7.2: the punch
// attempt budget and the reconnection backoff MUST NOT nest — nesting multiplies
// load onto third-party carrier and reflector peers, which the buggy peer never
// sees locally.
type callerOwnedRetryKey struct{}

// WithCallerOwnedRetry marks ctx so a live-establishment seam consulted under it
// makes a single attempt (the caller's own loop owns retry). The §4.1 reconnect
// path (EnsureConnected) sets this; a §10 dispatch does NOT, so it spends the full
// §7.2 budget.
func WithCallerOwnedRetry(ctx context.Context) context.Context {
	return context.WithValue(ctx, callerOwnedRetryKey{}, true)
}

// CallerOwnsRetry reports whether ctx was marked by WithCallerOwnedRetry. A live-
// establishment seam implementation reads it to cap itself at one attempt.
func CallerOwnsRetry(ctx context.Context) bool {
	v, _ := ctx.Value(callerOwnedRetryKey{}).(bool)
	return v
}

// markPreferRelay records (session-local, never published) that direct-path
// traversal to peerID failed, so a later §4.1 reconnect skips the seam.
func (p *Peer) markPreferRelay(peerID crypto.PeerID) {
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	if p.remote.preferRelay == nil {
		p.remote.preferRelay = make(map[crypto.PeerID]bool)
	}
	p.remote.preferRelay[peerID] = true
}

// clearPreferRelay drops any prefer-relay memo for peerID — called when the peer
// is reachable again, so a future disconnect re-attempts the punch.
func (p *Peer) clearPreferRelay(peerID crypto.PeerID) {
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	delete(p.remote.preferRelay, peerID)
}

// prefersRelay reports whether peerID carries a prefer-relay memo this session.
func (p *Peer) prefersRelay(peerID crypto.PeerID) bool {
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	return p.remote.preferRelay[peerID]
}

// RegisterRemote registers a remote peer's transport address in the
// tree as a TCPProfileData entity at
// system/peer/transport/{peer_id}/{profile-id}, per EXTENSION-NETWORK
// §6.5 v1.4 Amendment 2. The Go default profile-id is "primary" (see
// defaultTCPProfileID). The endpoint URL is `tcp://addr` per the
// §4.1 / D-14 single-{url} endpoint shape.
//
// addr SHOULD be a `host:port` string (e.g. "10.0.0.1:9002"). The
// scheme is prepended automatically — passing a pre-schemed value
// like "tcp://x:9002" is rejected because the cohort wire shape pins
// the scheme position.
func (p *Peer) RegisterRemote(peerID crypto.PeerID, addr string) error {
	if strings.Contains(addr, "://") {
		return fmt.Errorf("RegisterRemote: addr %q already carries a scheme; pass host:port only", addr)
	}
	data := types.TCPProfileData{
		PeerID:        string(peerID),
		TransportType: "tcp",
		Endpoint:      types.TransportEndpointURL{URL: "tcp://" + addr},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
	}
	ent, err := data.ToEntity()
	if err != nil {
		return fmt.Errorf("create tcp profile entity: %w", err)
	}
	h, err := p.store.Put(ent)
	if err != nil {
		return fmt.Errorf("store tcp profile entity: %w", err)
	}
	if err := p.locationIndex.Set(transportProfilePrefix(peerID)+defaultTCPProfileID, h); err != nil {
		return fmt.Errorf("bind tcp profile: %w", err)
	}
	return nil
}

// RegisterRemoteHTTP registers a remote peer's HTTP-live transport
// profile per EXTENSION-NETWORK §6.5 Amendment 3. url MUST carry an
// http:// or https:// scheme and the full POST target path (e.g.
// "https://peer.example:9003/entity"). Lives at the same
// system/peer/transport/{peer_id}/{profile-id} prefix as the TCP
// profile; profile-id defaults to "primary-http" (see
// defaultHTTPProfileID). A distinct default from the TCP "primary"
// closes the G1 collision flagged in PROPOSAL-TRANSPORT-FAMILY-LIVE-
// REACHABILITY §7.3 — both transports can coexist on the same peer.
//
// Callers that need additional profiles (cdn-mirror, backup-relay)
// can drive p.LocationIndex().Set() directly with any unique profile-
// id; per D-1 "primary" is tried first, then remaining profile-ids in
// lexicographic order — "primary-http" therefore sits after "primary"
// but before "z*".
func (p *Peer) RegisterRemoteHTTP(peerID crypto.PeerID, url string) error {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("RegisterRemoteHTTP: url %q missing http(s):// scheme", url)
	}
	data := types.HTTPProfileData{
		PeerID:        string(peerID),
		TransportType: "http",
		Endpoint:      types.TransportEndpointURL{URL: url},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
	}
	ent, err := data.ToEntity()
	if err != nil {
		return fmt.Errorf("create http profile entity: %w", err)
	}
	h, err := p.store.Put(ent)
	if err != nil {
		return fmt.Errorf("store http profile entity: %w", err)
	}
	if err := p.locationIndex.Set(transportProfilePrefix(peerID)+defaultHTTPProfileID, h); err != nil {
		return fmt.Errorf("bind http profile: %w", err)
	}
	return nil
}

// RegisterRemoteWS registers a remote peer's WebSocket-live transport
// profile per EXTENSION-NETWORK §6.5.2b. url MUST carry a ws:// or
// wss:// scheme (e.g. "ws://peer.example:9004/ws"). Lives at the
// same system/peer/transport/{peer_id}/{profile-id} prefix as the TCP
// and HTTP profiles; profile-id defaults to "primary-ws".
func (p *Peer) RegisterRemoteWS(peerID crypto.PeerID, url string) error {
	if !strings.HasPrefix(url, "ws://") && !strings.HasPrefix(url, "wss://") {
		return fmt.Errorf("RegisterRemoteWS: url %q missing ws(s):// scheme", url)
	}
	data := types.WebSocketProfileData{
		PeerID:        string(peerID),
		TransportType: "websocket",
		Endpoint:      types.TransportEndpointURL{URL: url},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
	}
	ent, err := data.ToEntity()
	if err != nil {
		return fmt.Errorf("create ws profile entity: %w", err)
	}
	h, err := p.store.Put(ent)
	if err != nil {
		return fmt.Errorf("store ws profile entity: %w", err)
	}
	if err := p.locationIndex.Set(transportProfilePrefix(peerID)+defaultWSProfileID, h); err != nil {
		return fmt.Errorf("bind ws profile: %w", err)
	}
	return nil
}

// RemoveRemote unregisters a remote peer and closes any cached
// connection. Removes all profile entries under the per-peer
// prefix (system/peer/transport/{peer_id}/*) so secondary profiles
// (cdn-mirror, backup-relay, etc.) don't linger.
func (p *Peer) RemoveRemote(peerID crypto.PeerID) {
	p.remote.mu.Lock()
	if conn, ok := p.remote.conns[peerID]; ok {
		conn.Close()
		delete(p.remote.conns, peerID)
	}
	p.remote.mu.Unlock()

	prefix := transportProfilePrefix(peerID)
	for _, e := range p.locationIndex.List(prefix) {
		p.locationIndex.Remove(e.Path)
	}
}

// AddRemoteConnection caches an established outbound connection in the
// remote pool keyed by remote peer-id. Subsequent EXECUTEs whose URI
// targets peerID reuse this connection rather than dialing fresh.
//
// Behavior follows getRemoteConnection's race-resolution pattern: if
// the pool already holds a connection for peerID, the supplied conn is
// closed and the existing one returned. The returned Connection is
// the one currently in the pool (usually conn unless a race resolved
// in favor of an existing entry).
//
// The connection must have completed PerformConnect — that is, its
// session and capability must be set. Otherwise an error is returned
// and the supplied conn is left untouched.
func (p *Peer) AddRemoteConnection(peerID crypto.PeerID, conn *Connection) (*Connection, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil connection")
	}
	if conn.session == nil || conn.session.Capability == nil {
		return nil, fmt.Errorf("connection not established (PerformConnect not completed)")
	}

	p.remote.mu.Lock()
	if existing, ok := p.remote.conns[peerID]; ok {
		p.remote.mu.Unlock()
		conn.Close()
		// The pool stores remoteEndpoints polymorphically. AddRemoteConnection
		// is the TCP-specific entry point — callers expect a *Connection back.
		// If the existing entry is non-TCP (e.g. an HTTPConnection was
		// pooled first), surface that rather than silently lying about the
		// type.
		existingTCP, ok := existing.(*Connection)
		if !ok {
			return nil, fmt.Errorf("existing pool entry for %s is not *Connection (mixed transports)", peerID)
		}
		return existingTCP, nil
	}
	p.remote.conns[peerID] = conn
	p.remote.mu.Unlock()

	// Pool insert = liveness tracking begins (§5 keepalive, Amendment 12
	// rung 2). Outside the pool lock — startKeepalive takes keepalive.mu.
	p.startKeepalive(peerID)
	return conn, nil
}

// reciprocalGrantWait bounds how long an acceptor waits for the §6.5 (b)
// reciprocal grant before originating anyway (and failing closed). Sized to
// cover the ≈1-round-trip delivery window on a real link with slack, and
// deliberately short: the cost of waiting too long is a stalled dispatch, the
// cost of not waiting is a spurious 401 on an establishment that was about to
// work.
//
// This value is IMPLEMENTATION-LOCAL and stays that way (§11.4). The spec pins
// no bound; what it pins is a conformance-vector FLOOR — see
// ReciprocalGrantVectorFloor.
const reciprocalGrantWait = 2 * time.Second

// ReciprocalGrantVectorFloor is the minimum a §6.5 (b) conformance vector must
// allow the peer under test before declaring the reciprocal grant absent
// (arch f8f736a, Q3 ruling 2026-08-05).
//
// The distinction matters and is easy to collapse. Go's own 2s above is a
// production timeout, free to change. The floor is a property of the VECTOR:
// a vector that waits only as long as the fast implementation that wrote it
// fails a slower-but-correct peer, and reports it as a conformance failure of
// the peer rather than of the harness. So the floor is what a vector waits, and
// a vector MUST NOT tighten it to its author's own bound. Two seconds happens
// to be both here; they are not the same number and must not be merged.
const ReciprocalGrantVectorFloor = 2 * time.Second

// registerInboundForReentry caches a server-side connection in a
// secondary map keyed by remote peer-id so a handler invoked over it
// can originate outbound EXECUTEs to the remote peer reusing the SAME
// connection (V7 §6.11 reentry seam; GUIDE-CONFORMANCE §7a.2a — the
// substantive surface §10.2 verifies). Called from
// Connection.initServerSessionLocked once the server-side handshake
// completes.
//
// The registration is in a SEPARATE map (p.remote.inboundConns), NOT
// the main outbound pool (p.remote.conns). Rationale:
//   - The main pool is preferred for outbound dispatch (a real dialed
//     connection with a tree-resolved transport profile is the
//     canonical endpoint).
//   - The inbound map is the §6.11 fallback: only consulted by
//     getRemoteConnection when transport-profile resolution fails
//     (no published profile entry for the remote — the validator-as-B
//     case, where the validator has no listener).
//   - Without the split, an inbound registration would race the
//     outbound AddRemoteConnection on bidirectional peer setups
//     (TestConnection_ReentrantCrossPeerDoesNotDeadlock pre-fix) and
//     cause the second AddRemoteConnection to close its own conn
//     because the inbound already claimed the pool slot.
//
// Best-effort: a nil peer-id (handshake didn't populate one) is a
// no-op. Multiple inbound connections from the same peer overwrite —
// the newest wins, since the older inbound's serve loop will close
// the conn shortly after.
func (p *Peer) registerInboundForReentry(peerID crypto.PeerID, conn *Connection) {
	if conn == nil || peerID == "" {
		return
	}
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	if p.remote.inboundConns == nil {
		p.remote.inboundConns = make(map[crypto.PeerID]*Connection)
	}
	p.remote.inboundConns[peerID] = conn
	p.debugf("remote: registered inbound connection from %s for §6.11 reentry reuse", peerID)
}

// inboundForReentry returns a server-side connection from the same
// remote peer-id, if one is registered. Used by getRemoteConnection as
// the §6.11 reentry fallback when transport-profile resolution misses.
func (p *Peer) inboundForReentry(peerID crypto.PeerID) *Connection {
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	if p.remote.inboundConns == nil {
		return nil
	}
	return p.remote.inboundConns[peerID]
}

// unregisterInboundForReentry removes the inbound reentry registration
// for a server-side connection (called from the serve loop's deferred
// teardown). Only deletes when the registered entry is exactly conn —
// a newer inbound from the same peer-id may have already overwritten
// us, in which case the new entry must stay.
func (p *Peer) unregisterInboundForReentry(peerID crypto.PeerID, conn *Connection) {
	if conn == nil || peerID == "" {
		return
	}
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	if p.remote.inboundConns == nil {
		return
	}
	if existing, ok := p.remote.inboundConns[peerID]; ok && existing == conn {
		delete(p.remote.inboundConns, peerID)
	}
}

// remoteExecute dispatches an EXECUTE to a remote peer. Resolves the
// peer's transport profile (TCP or HTTP) from the tree, gets or creates
// a pooled outbound endpoint, and sends the request through whichever
// substrate the resolution selected.
func (p *Peer) remoteExecute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, async ...*protocol.AsyncDelivery) (*handler.Response, error) {
	parsed, err := entity.ParseURI(uri)
	if err != nil {
		return nil, fmt.Errorf("parse remote URI: %w", err)
	}
	peerID := crypto.PeerID(parsed.PeerID)

	conn, err := p.getRemoteConnection(ctx, peerID)
	if err != nil {
		// §10.3 step 3b — live-establishment seam, consulted BEFORE §10.2's
		// dispatch_fallback (the normative "live first, store-and-forward last"
		// ordering). On success the connection is pooled and the ladder
		// re-enters ordinary dispatch through it.
		if live := p.tryEstablishLive(ctx, peerID); live != nil {
			conn, err = live, nil
		}
	}
	if err != nil {
		if p.dispatchFallback != nil {
			if resp, ok, ferr := p.dispatchFallback(ctx, peerID, uri, operation, params, resource); ok {
				if ferr != nil {
					return nil, fmt.Errorf("dispatch_fallback for %s: %w", peerID, ferr)
				}
				return resp, nil
			}
		}
		return nil, fmt.Errorf("remote connection to %s: %w", peerID, err)
	}

	respEnv, err := conn.Execute(ctx, uri, operation, params, resource, async...)
	if err != nil {
		// Transport error on a connection we believed active (§10 step 1):
		// evict the dead conn from the pool AND demote peer liveness to
		// suspect (Amendment 12 §A1), idempotently under the no-clobber
		// guard. Also clears the §6.11 reentry entry so the next call redials
		// rather than reusing the broken conn.
		p.demotePeerOnTransportError(peerID, conn, err)
		return nil, fmt.Errorf("remote execute to %s: %w", peerID, err)
	}
	// §5.4 adaptive suppression: a successful exchange counts as liveness,
	// so the keepalive loop skips its next idle ping.
	p.markPeerActivity(peerID)

	return decodeExecuteResponse(respEnv)
}

// SendRawFrameTo writes pre-encoded envelope bytes verbatim onto the outbound
// connection to peerID, dialing the pool if necessary. Used by the RELAY
// production dispatcher at the terminal hop (§3.1.1 / §9 / §10.4): the inner
// envelope bytes are forwarded opaquely — the relay MUST NOT decode or
// re-encode them. Returns an error wrapping "transport profile" / "dial" /
// connection-refused when the destination is unreachable; isUnreachable in
// the dispatcher translates that to relay.ErrDestinationUnreachable so the
// handler fires §6.2.1 Mode-S fallback.
//
// Transport-agnostic: TCP writes the bytes as a length-prefixed wire frame;
// HTTP-live POSTs them verbatim as the request body (the destination's
// HTTP server decodes the body as a bare ECF envelope per Amendment 3 and
// dispatches through the same path TCP uses). RELAY §3.1.1 names the
// semantic ("deliver verbatim"), never the substrate — Go follows whichever
// transport the destination's published §6.5 profile resolved to.
func (p *Peer) SendRawFrameTo(ctx context.Context, peerID crypto.PeerID, frame []byte) error {
	conn, err := p.getRemoteConnection(ctx, peerID)
	if err != nil {
		return fmt.Errorf("remote connection to %s: %w", peerID, err)
	}
	switch c := conn.(type) {
	case *Connection:
		if err := c.SendRawFrame(frame); err != nil {
			p.removeRemoteConnection(peerID)
			return fmt.Errorf("raw-frame send to %s (tcp): %w", peerID, err)
		}
		return nil
	case *HTTPConnection:
		if err := c.SendRawFrame(ctx, frame); err != nil {
			p.removeRemoteConnection(peerID)
			return fmt.Errorf("raw-frame send to %s (http): %w", peerID, err)
		}
		return nil
	default:
		return fmt.Errorf("raw-frame send to %s: unsupported transport type %T", peerID, conn)
	}
}

// RemoteExecute is the public counterpart of remoteExecute. RELAY
// production dispatcher uses it to deliver inner envelopes (§3.1.1
// terminal hop) without reaching into peer internals.
func (p *Peer) RemoteExecute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (*handler.Response, error) {
	return p.remoteExecute(ctx, uri, operation, params, resource)
}

// RemoteExecuteWithIncluded is RemoteExecute plus an extra included set.
// RELAY production dispatcher uses it to ride the opaque inner envelope
// (§9) on a forward-request to an intermediate hop — the inner entity
// keyed by its content hash MUST be included so the next relay's
// `lookupIncluded` resolves it.
func (p *Peer) RemoteExecuteWithIncluded(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget, extras map[hash.Hash]entity.Entity) (*handler.Response, error) {
	parsed, err := entity.ParseURI(uri)
	if err != nil {
		return nil, fmt.Errorf("parse remote URI: %w", err)
	}
	peerID := crypto.PeerID(parsed.PeerID)

	conn, err := p.getRemoteConnection(ctx, peerID)
	if err != nil {
		// §10.3 step 3b — live-establishment BEFORE §10.2 dispatch_fallback.
		if live := p.tryEstablishLive(ctx, peerID); live != nil {
			conn, err = live, nil
		}
	}
	if err != nil {
		if p.dispatchFallback != nil {
			if resp, ok, ferr := p.dispatchFallback(ctx, peerID, uri, operation, params, resource); ok {
				if ferr != nil {
					return nil, fmt.Errorf("dispatch_fallback for %s: %w", peerID, ferr)
				}
				return resp, nil
			}
		}
		return nil, fmt.Errorf("remote connection to %s: %w", peerID, err)
	}

	switch c := conn.(type) {
	case *Connection:
		respEnv, err := c.ExecuteWithIncluded(ctx, uri, operation, params, resource, extras)
		if err != nil {
			p.demotePeerOnTransportError(peerID, c, err)
			return nil, fmt.Errorf("remote execute with included to %s (tcp): %w", peerID, err)
		}
		p.markPeerActivity(peerID)
		return decodeExecuteResponse(respEnv)
	case *HTTPConnection:
		respEnv, err := c.ExecuteWithIncluded(ctx, uri, operation, params, resource, extras)
		if err != nil {
			p.demotePeerOnTransportError(peerID, c, err)
			return nil, fmt.Errorf("remote execute with included to %s (http): %w", peerID, err)
		}
		p.markPeerActivity(peerID)
		return decodeExecuteResponse(respEnv)
	default:
		return nil, fmt.Errorf("remote execute with included to %s: unsupported transport type %T", peerID, conn)
	}
}

// getRemoteConnection returns a cached outbound endpoint or creates one.
// Branches on the resolved transport type — TCP dials a net.Conn through
// p.Connect; HTTP builds an HTTPConnection bound to the profile's URL.
// Both paths run the same HELLO/AUTHENTICATE handshake; the only
// difference is the substrate.
func (p *Peer) getRemoteConnection(ctx context.Context, peerID crypto.PeerID) (remoteEndpoint, error) {
	p.remote.mu.Lock()
	if conn, ok := p.remote.conns[peerID]; ok {
		p.remote.mu.Unlock()
		return conn, nil
	}
	p.remote.mu.Unlock()

	target, err := p.resolveTransportTarget(peerID)
	if err != nil {
		// V7 §6.11 reentry fallback (GUIDE-CONFORMANCE §7a.2a): when
		// transport-profile resolution misses, check whether a server-
		// side connection from the same peer-id is registered. If so,
		// reuse it for outbound dispatch — the inbound conn IS the
		// outbound seam (the validator-as-B / no-listener case §10.2
		// verifies).
		if inbound := p.inboundForReentry(peerID); inbound != nil {
			p.debugf("remote: §6.11 reentry to %s reuses inbound connection (no published transport profile)", peerID)
			// EXTENSION-SIGNALING §6.5 (b) "Delivery + timing": on a symmetric
			// rendezvous establishment our originating authority is the
			// reciprocal grant, and it lands ≈1 round trip after the channel
			// opens. Originating in that window would dispatch under the cap
			// we minted for THEM — `grantee != author`, a guaranteed 401. So
			// gate on grant-received, bounded: on expiry we fall through and
			// let the dispatch fail closed rather than block. A counterpart
			// that never adopts the grant therefore degrades to
			// one-directional, not to a hang.
			//
			// Only on a rendezvous establishment: an ordinary dial-by-address
			// acceptor is asymmetric, expects no grant, and must not pay the
			// wait.
			if inbound.EstablishedViaRendezvousKey() {
				if !inbound.AwaitOriginatingCapability(ctx, reciprocalGrantWait) {
					p.debugf("remote: §6.5 (b) reciprocal grant from %s not in hand within %s — originating fails closed", peerID, reciprocalGrantWait)
				}
			}
			return inbound, nil
		}
		return nil, err
	}

	var endpoint remoteEndpoint
	switch target.typeURI {
	case types.TypePeerTransportTCP:
		tcpConn, err := p.Connect(ctx, target.endpoint)
		if err != nil {
			return nil, fmt.Errorf("dial %s at %s: %w", peerID, target.endpoint, err)
		}
		if err := tcpConn.PerformConnect(ctx); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("handshake with %s: %w", peerID, err)
		}
		endpoint = tcpConn
	case types.TypePeerTransportHTTP:
		httpConn := newHTTPConnection(p, target.endpoint)
		if err := httpConn.PerformConnect(ctx); err != nil {
			httpConn.Close()
			return nil, fmt.Errorf("http-handshake with %s: %w", peerID, err)
		}
		endpoint = httpConn
	case types.TypePeerTransportWebSocket:
		wsConn, err := p.ConnectWebSocket(ctx, target.endpoint)
		if err != nil {
			return nil, fmt.Errorf("ws-dial %s at %s: %w", peerID, target.endpoint, err)
		}
		if err := wsConn.PerformConnect(ctx); err != nil {
			wsConn.Close()
			return nil, fmt.Errorf("ws-handshake with %s: %w", peerID, err)
		}
		endpoint = wsConn
	default:
		return nil, fmt.Errorf("unknown transport type %q for peer %s", target.typeURI, peerID)
	}

	p.debugf("remote: connected to %s via %s at %s", peerID, target.typeURI, target.endpoint)

	// Cache the endpoint. Resolve a race with another goroutine that may
	// have completed its own dial in the meantime.
	p.remote.mu.Lock()
	if existing, ok := p.remote.conns[peerID]; ok {
		p.remote.mu.Unlock()
		endpoint.Close()
		return existing, nil
	}
	p.remote.conns[peerID] = endpoint
	p.remote.mu.Unlock()

	// Pool insert = liveness tracking begins: start the §5 keepalive loop
	// (Amendment 12 rung 2). Idempotent — a running loop for this peer
	// simply keeps watching the new binding.
	p.startKeepalive(peerID)

	return endpoint, nil
}

// removeRemoteConnection removes and closes a cached connection.
func (p *Peer) removeRemoteConnection(peerID crypto.PeerID) {
	p.remote.mu.Lock()
	if conn, ok := p.remote.conns[peerID]; ok {
		conn.Close()
		delete(p.remote.conns, peerID)
	}
	p.remote.mu.Unlock()
}

// EnsureConnected establishes (or reuses) the pooled outbound connection to
// peerID: pool hit returns immediately; otherwise transport-profile
// resolution → dial → §6.2 handshake → pool insert, which writes the §3.13
// connected status and starts the §5 keepalive loop. This is the
// EXTENSION-NETWORK §4.1 "connect if needed" seam the system/network
// handler's maintain-peer/reconnect operations compose on — the connect
// path is exactly the one ordinary dispatch takes, so the handler adds no
// second establish flow (§A4 discipline).
//
// When the ordinary profile-dial fails, EnsureConnected consults the §10.3
// live-establishment seam (step 3b) so a NAT'd peer can still be reached by a
// punch — marked CALLER-OWNED (WithCallerOwnedRetry). EnsureConnected is only
// reached from the §4.1 maintain-peer/reconnect continuations, whose backoff owns
// the retry loop; the seam runs a single carrier exchange per consult (SIGNALING
// §7.2 / §10.3 obligation 4 — the exchange budget and the reconnect backoff MUST
// NOT nest), and the marker carries that boundary to the seam. A session-local
// prefer-relay memo short-circuits the seam for a peer whose traversal already
// failed this session, so the loop stops re-punching an untraversable (e.g.
// symmetric-NAT) peer and lets relay carry it; the memo clears the moment the
// peer is reachable again.
func (p *Peer) EnsureConnected(ctx context.Context, peerID crypto.PeerID) error {
	_, err := p.getRemoteConnection(ctx, peerID)
	if err == nil {
		p.clearPreferRelay(peerID)
		return nil
	}
	// No live-establishment seam registered, or this peer is memoed prefer-relay:
	// preserve the plain-dial error and fall through to the caller's backoff.
	if p.establishLive == nil || p.prefersRelay(peerID) {
		return err
	}
	if live := p.tryEstablishLive(WithCallerOwnedRetry(ctx), peerID); live != nil {
		p.clearPreferRelay(peerID)
		return nil
	}
	// One punch attempt failed; §4.1's backoff owns the next try. Memo prefer-relay
	// so subsequent reconnects skip a punch that just proved untraversable.
	p.markPreferRelay(peerID)
	return err
}

// IsConnected reports whether an outbound pooled connection (or a §6.11
// inbound-reentry binding) currently exists for peerID. Observational only —
// liveness truth is the system/peer/status entity.
func (p *Peer) IsConnected(peerID crypto.PeerID) bool {
	p.remote.mu.Lock()
	_, pooled := p.remote.conns[peerID]
	p.remote.mu.Unlock()
	if pooled {
		return true
	}
	return p.inboundForReentry(peerID) != nil
}

// EvictRemoteConnection drops any cached outbound connection to peerID
// and forces a fresh transport-profile resolution + dial on the next
// remote call. It is a no-op when no cached connection exists.
//
// This is impl-internal API — connection pooling is not protocol-
// normative (see ARCH-RESPONSE-RELAY-PRE-RELEASE-BATCHED-HANDOFF
// Item 2). It exists so test rigs and operators can force
// re-resolution after rotating a peer's transport profile (the
// mp2-over-HTTP fixture's primary use case).
func (p *Peer) EvictRemoteConnection(peerID crypto.PeerID) {
	p.removeRemoteConnection(peerID)
}

// closeRemoteConnections closes all cached remote connections.
func (p *Peer) closeRemoteConnections() {
	p.remote.mu.Lock()
	for id, conn := range p.remote.conns {
		conn.Close()
		delete(p.remote.conns, id)
	}
	// The inbound reentry map holds references to server-accepted
	// connections owned by the serve loop; their lifecycle is driven by
	// the listener teardown path (peer.Close cancels serveCtx) and the
	// connection's own deferred close, not by us. Drop the map entries
	// so a stopped peer doesn't keep stale references; the underlying
	// conns will be closed by the serve-loop teardown.
	for id := range p.remote.inboundConns {
		delete(p.remote.inboundConns, id)
	}
	p.remote.mu.Unlock()
}

// resolveTransportTarget walks the §6.5 transport-profile prefix for
// the given peer (system/peer/transport/{peer_id}/*) and returns the
// first usable target — TCP or HTTP — for outbound dispatch.
//
// Per D-1 of PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS the
// selection rule is a deterministic ordered candidate list:
//
//  1. the reserved profile-id "primary" first (if present);
//  2. then the remaining profiles sorted lexicographically by profile-id;
//  3. each attempted in order until one returns a usable target.
//
// advertised_at is NOT a selection key (D-3 informational only).
// Lexicographic profile-id is stable across every location-index
// backend. Self-publication is SHOULD (D-1); consumers MUST NOT assume
// the path exists. Legacy flat-shape entries at the old
// system/network/transport-address path are silently invisible — no
// migration shim (D-6).
//
// Both TypePeerTransportTCP and TypePeerTransportHTTP entries are
// candidates; ordering is by profile-id only (not by transport type).
// Selection-among-types under a single profile-id is forbidden by the
// store/index shape — each profile-id binds one entity. When a peer
// needs to advertise both substrates, they live under different
// profile-ids (e.g. "primary" + "secondary"). The choice of which
// transport-type maps to which profile-id is operator policy; arch's
// D-1 ruling pins lex-order, not type-precedence.
func (p *Peer) resolveTransportTarget(peerID crypto.PeerID) (transportTarget, error) {
	prefix := transportProfilePrefix(peerID)
	entries := p.locationIndex.List(prefix)
	if len(entries) == 0 {
		return transportTarget{}, fmt.Errorf("no transport profile for peer %s (checked %s*)", peerID, prefix)
	}

	// Q1 / arch §8.9 selection: sort by (effective priority asc,
	// profile-id lex). Effective priority comes from the loaded
	// entity's data.priority (when present) or the default rule
	// (profile-id "primary" → 0; others → 100). Loading happens
	// here so the priority field is observable during sort.
	candidates := p.collectProfileCandidates(entries)

	for _, c := range candidates {
		switch c.ent.Type {
		case types.TypePeerTransportTCP:
			data, err := types.TCPProfileDataFromEntity(c.ent)
			if err != nil {
				p.debugf("remote: %s decode failed: %v, skipping", c.entry.Path, err)
				continue
			}
			host, err := parseTCPEndpointURL(data.Endpoint.URL)
			if err != nil {
				p.debugf("remote: %s endpoint %q: %v, skipping", c.entry.Path, data.Endpoint.URL, err)
				continue
			}
			return transportTarget{typeURI: types.TypePeerTransportTCP, endpoint: host}, nil
		case types.TypePeerTransportHTTP:
			data, err := types.HTTPProfileDataFromEntity(c.ent)
			if err != nil {
				p.debugf("remote: %s decode failed: %v, skipping", c.entry.Path, err)
				continue
			}
			if data.Endpoint.URL == "" {
				p.debugf("remote: %s empty http endpoint url, skipping", c.entry.Path)
				continue
			}
			if !strings.HasPrefix(data.Endpoint.URL, "http://") && !strings.HasPrefix(data.Endpoint.URL, "https://") {
				p.debugf("remote: %s endpoint %q missing http(s):// scheme, skipping", c.entry.Path, data.Endpoint.URL)
				continue
			}
			return transportTarget{typeURI: types.TypePeerTransportHTTP, endpoint: data.Endpoint.URL}, nil
		case types.TypePeerTransportWebSocket:
			data, err := types.WebSocketProfileDataFromEntity(c.ent)
			if err != nil {
				p.debugf("remote: %s decode failed: %v, skipping", c.entry.Path, err)
				continue
			}
			if data.Endpoint.URL == "" {
				p.debugf("remote: %s empty ws endpoint url, skipping", c.entry.Path)
				continue
			}
			if !strings.HasPrefix(data.Endpoint.URL, "ws://") && !strings.HasPrefix(data.Endpoint.URL, "wss://") {
				p.debugf("remote: %s endpoint %q missing ws(s):// scheme, skipping", c.entry.Path, data.Endpoint.URL)
				continue
			}
			return transportTarget{typeURI: types.TypePeerTransportWebSocket, endpoint: data.Endpoint.URL}, nil
		default:
			p.debugf("remote: %s has unsupported transport type %q, skipping", c.entry.Path, c.ent.Type)
			continue
		}
	}
	return transportTarget{}, fmt.Errorf("no usable transport profile for peer %s under %s* (TCP or HTTP)", peerID, prefix)
}

// profileCandidate bundles a LocationEntry with the loaded entity and
// the effective priority used for Q1 selection ordering.
type profileCandidate struct {
	entry             store.LocationEntry
	ent               entity.Entity
	profileID         string
	effectivePriority uint64
}

// collectProfileCandidates loads each entry's entity from the store,
// extracts the priority field, applies the Q1 default rule, and
// returns the candidates sorted by (effectivePriority asc, profileID
// lex). Entities missing from the store are silently skipped (logged
// in debug).
func (p *Peer) collectProfileCandidates(entries []store.LocationEntry) []profileCandidate {
	out := make([]profileCandidate, 0, len(entries))
	for _, e := range entries {
		ent, ok := p.store.Get(e.Hash)
		if !ok {
			p.debugf("remote: %s entity missing in store, skipping", e.Path)
			continue
		}
		profileID := path.Base(e.Path)
		prio := effectiveProfilePriority(ent, profileID)
		out = append(out, profileCandidate{
			entry:             e,
			ent:               ent,
			profileID:         profileID,
			effectivePriority: prio,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].effectivePriority != out[j].effectivePriority {
			return out[i].effectivePriority < out[j].effectivePriority
		}
		return out[i].profileID < out[j].profileID
	})
	return out
}

// effectiveProfilePriority returns the value used to order profile
// candidates per arch §8.9 / Q1:
//
//   - If the entity carries an explicit priority field, that value
//     wins (including explicit 0).
//   - If priority is omitted and profileID == "primary", the default
//     is 0 (reserved-name back-compat with the pre-Q1 "primary first"
//     rule).
//   - If priority is omitted and profileID is anything else, the
//     default is 100 (DNS-SRV-style "ordinary" priority).
//
// Unsupported entity types fall through to 100 (they will be skipped
// at the dispatch loop's type switch; the priority value chosen for
// them does not change selection outcomes among usable profiles).
func effectiveProfilePriority(ent entity.Entity, profileID string) uint64 {
	const (
		defaultPrimary = uint64(0)
		defaultOther   = uint64(100)
	)
	defaulted := defaultOther
	if profileID == defaultTCPProfileID {
		defaulted = defaultPrimary
	}
	switch ent.Type {
	case types.TypePeerTransportTCP:
		data, err := types.TCPProfileDataFromEntity(ent)
		if err == nil && data.Priority != nil {
			return *data.Priority
		}
	case types.TypePeerTransportHTTP:
		data, err := types.HTTPProfileDataFromEntity(ent)
		if err == nil && data.Priority != nil {
			return *data.Priority
		}
	case types.TypePeerTransportWebSocket:
		data, err := types.WebSocketProfileDataFromEntity(ent)
		if err == nil && data.Priority != nil {
			return *data.Priority
		}
	case types.TypePeerTransportHTTPPoll:
		data, err := types.HTTPPollProfileDataFromEntity(ent)
		if err == nil && data.Priority != nil {
			return *data.Priority
		}
	}
	return defaulted
}

// sortProfileEntriesD1 orders LocationEntry under the per-peer profile
// prefix per D-1: profile-id "primary" first, then remaining profile-ids
// in lexicographic order.
//
// Per arch's Q2 ruling (TRANSPORT-FAMILY-OPEN-QUESTIONS) the
// profile-id is **the final path segment**, not "the suffix after the
// caller's prefix string." The previous TrimPrefix shape was a path-
// resolution bug: callers pass a relative prefix
// (system/peer/transport/{peer_id}/) but LocationIndex.List returns
// absolute paths (/{local_peer_id}/system/peer/transport/{peer_id}/{id})
// per the namespacing contract — so the trim never matched and the
// "primary" special case never fired. Using path.Base derives the
// profile-id directly from the path's final segment, which is the same
// answer regardless of whether the caller's prefix is relative or
// absolute. The prefix argument is retained for API compatibility (and
// for future selection-priority work — Q1).
func sortProfileEntriesD1(entries []store.LocationEntry, prefix string) {
	_ = prefix // intentionally unused after the Q2 ruling; see comment above.
	sort.SliceStable(entries, func(i, j int) bool {
		idI := path.Base(entries[i].Path)
		idJ := path.Base(entries[j].Path)
		if idI == defaultTCPProfileID && idJ != defaultTCPProfileID {
			return true
		}
		if idJ == defaultTCPProfileID && idI != defaultTCPProfileID {
			return false
		}
		return idI < idJ
	})
}

// parseTCPEndpointURL extracts host:port from a `tcp://host:port`
// endpoint URL per §4.1 / D-14 endpoint shape. Returns an error if
// the scheme isn't tcp or the host part is empty.
func parseTCPEndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "tcp" {
		return "", fmt.Errorf("expected scheme tcp, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("empty host")
	}
	return u.Host, nil
}

// decodeExecuteResponse converts a wire EXECUTE_RESPONSE envelope into a
// handler.Response.
func decodeExecuteResponse(env entity.Envelope) (*handler.Response, error) {
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return nil, fmt.Errorf("decode execute response: %w", err)
	}

	var resultEntity entity.Entity
	if len(respData.Result) > 0 {
		if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
			return nil, fmt.Errorf("decode result entity: %w", err)
		}
	}

	// Convert included map from envelope format.
	included := make(map[hash.Hash]entity.Entity, len(env.Included))
	for h, ent := range env.Included {
		included[h] = ent
	}

	return &handler.Response{
		Status:   respData.Status,
		Result:   resultEntity,
		Included: included,
	}, nil
}
