// Package relay implements EXTENSION-RELAY v1.0 — the four-mode relay
// substrate per
// `../entity-core-architecture/.../EXTENSION-RELAY.md` v1.0 (post-Go-pre-impl-
// review at arch 54e5373 + 15b30d0).
//
// v1 ships Mode F (forward) + Mode S (store-and-poll). Mode A (aggregate)
// and Mode C (circuit) entity types are named for forward-compat (core/types)
// but the normative spec text is deferred (§11.1 / §11.1a).
//
// Four handler ops at pattern `system/relay`:
//
//   - `:forward(forward-request)` → `forward-result` — Mode F: accept relay
//     envelope, decrement ttl_hops, dispatch.
//   - `:put(store-entry)` → `put-result` — Mode S: store an entry at a
//     namespace; on a wire :put the relay MUST verify put_by == authenticated
//     caller (R3 scope).
//   - `:poll(poll-request)` → `poll-result` — Mode S: enumerate stored
//     entries past the relay-owned cursor; empty namespace returns
//     {entries: [], has_more: false} at 200 (§4.2 + landing-pass finding #1).
//   - `:advertise(advertise)` → 200 — write/refresh the relay's advertise
//     entity at `system/relay/advertise/{relay_peer_id}`.
//
// R2 scope (this file): substrate + in-memory Mode-S store + relay-owned
// cursor + advertise bind + basic :forward shape (TTL decrement + envelope
// opacity gates). R3 adds:
//
//  1. §3.1.1 intermediate-vs-terminal dispatch shape — terminal hop unwraps
//     and dispatches the bare inner envelope.
//  2. §3.2 put_by == authenticated caller verification (put_by_mismatch/400).
//  3. §5.5 self-poll default grant install (peer-builder seed policy).
//  4. §6.2.1 Mode-F → Mode-S fallback path on unreachable destinations.
//
// The Mode-S store is in-memory in v1 (per cohort handoff open-TBD #2:
// "in-memory is the v1 floor; persistent store is operator choice"). Cursor
// format is impl choice (cohort R8 does NOT byte-compare cursors); we use
// a big-endian uint64 of the relay-owned monotonic sequence.
package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// HandlerPattern is the substrate pattern path.
const HandlerPattern = "system/relay"

// Op identifiers.
const (
	OpForward   = "forward"
	OpPut       = "put"
	OpPoll      = "poll"
	OpAdvertise = "advertise"
)

// DefaultPollLimit caps an unspecified :poll request. Operators tune via
// SetDefaultPollLimit; callers may pass a smaller limit per request (the
// relay applies min(request_limit, default_limit)).
const DefaultPollLimit = 100

// MaxPollLimit caps the relay's absolute response size regardless of
// requested limit — guards against pathological clients asking for the
// universe in one round trip. Operator-tunable.
const MaxPollLimit = 1000

// Clock is the seam time.Now() reads through — lets tests freeze time for
// expires_at handling without monkeypatching. Production wires
// time.Now().UnixMilli().
type Clock func() uint64

// SystemClock returns the current Unix-ms timestamp.
func SystemClock() uint64 { return uint64(time.Now().UnixMilli()) }

// ErrDestinationUnreachable is returned by an OutboundDispatcher when the
// destination peer has no live session and the dispatcher cannot deliver
// directly. The §6.2.1 fallback path catches this and queues at Mode-S.
var ErrDestinationUnreachable = errors.New("relay: destination unreachable (no live session)")

// InboxRelayResolver is the seam for §3.5 inbox-relay declaration lookup.
// Given a destination peer-id, returns the parsed InboxRelayData if a
// declaration is known (REGISTRY-served declaration, cached relationship
// declaration, etc.) — false otherwise.
//
// Resolvers MUST V7 §5.2 signature-verify the declaration against the
// destination peer-id before returning it (forged-redirection defense).
// A resolver that returns an unverified declaration is non-conformant.
//
// Default impl: NopInboxRelayResolver always returns false → §6.2.1
// fallback uses the default convention (store on the forwarding relay
// itself at namespace = destination peer_id). Production wiring would
// inject a resolver that consults the local REGISTRY index for the
// destination's published inbox-relay binding.
type InboxRelayResolver interface {
	// Resolve looks up the destination's inbox-relay declaration. Returns
	// (decl, true) if a verified declaration is available, (_, false) if
	// none is known.
	Resolve(destinationPeerID string) (types.InboxRelayData, bool)
}

// NopInboxRelayResolver returns "no declaration known" for every peer —
// the conservative default that lets §6.2.1 fallback use the default
// convention.
type NopInboxRelayResolver struct{}

func (NopInboxRelayResolver) Resolve(string) (types.InboxRelayData, bool) {
	return types.InboxRelayData{}, false
}

// OutboundDispatcher is the seam the relay handler uses to send wire-level
// traffic. The peer-builder injects an impl that bridges to core/peer's
// connection pool; tests inject mocks (relay_test.go has a FakeDispatcher
// that exercises both happy path and unreachable path).
//
// Per §3.1.1 the relay distinguishes two hop kinds:
//
//   - INTERMEDIATE: re-wrap a forward-request with TTLHops-1 and send it
//     to next_hop as a `system/relay:forward` EXECUTE. The next relay
//     repeats the routing decision.
//   - TERMINAL: deliver the bare inner envelope to the destination as a
//     normal inbound EXECUTE. The destination needs no RELAY extension to
//     receive (§5.1 cap-chain ruling — Bob's relay wrapper is consumed at
//     the terminal hop and not delivered onward).
//
// §9 envelope opacity holds across both: the inner envelope is carried as
// the original entity bytes; the dispatcher MUST NOT decode or re-encode
// it on the way out.
//
// When the destination has no live session, DeliverInner returns
// ErrDestinationUnreachable. The handler then applies the §6.2.1 fallback:
// store the inner envelope at namespace = destination peer_id under the
// forwarding relay's own relay-forward grant. The caller observes this as
// forward-result{status: queued-fallback, stored_at: ...}.
type OutboundDispatcher interface {
	// ForwardToNextHop sends a `system/relay:forward` EXECUTE to nextHopPeerID
	// carrying the (TTL-decremented) forward-request + the same inner envelope.
	// Used on intermediate hops.
	ForwardToNextHop(ctx context.Context, nextHopPeerID string, req types.ForwardRequestData, inner entity.Entity) (*handler.Response, error)
	// DeliverInner sends the inner envelope to destinationPeerID as a normal
	// inbound EXECUTE — byte-identical to direct delivery (§3.1.1 + §9).
	// Returns ErrDestinationUnreachable when there's no live session.
	DeliverInner(ctx context.Context, destinationPeerID string, inner entity.Entity) (*handler.Response, error)
}

// noopDispatcher returns ErrDestinationUnreachable for every outbound
// attempt. It's the default when SetDispatcher hasn't been called — this
// is the conservative posture (no silent forwarding) and naturally
// exercises the §6.2.1 fallback path until production wiring lands.
type noopDispatcher struct{}

func (noopDispatcher) ForwardToNextHop(_ context.Context, _ string, _ types.ForwardRequestData, _ entity.Entity) (*handler.Response, error) {
	return nil, ErrDestinationUnreachable
}
func (noopDispatcher) DeliverInner(_ context.Context, _ string, _ entity.Entity) (*handler.Response, error) {
	return nil, ErrDestinationUnreachable
}

// storedEntry holds a single Mode-S entry plus the relay-owned sequence
// number and the inner-envelope entity referenced by the store-entry.
type storedEntry struct {
	Entry     types.StoreEntryData
	EntryEnt  entity.Entity // full store-entry entity (for fetch + integrity)
	EntryHash hash.Hash
	Inner     entity.Entity // opaque inner envelope per §9 — never decoded
	Seq       uint64
	ExpiresAt uint64 // 0 == no expiry
}

// namespaceStore partitions Mode-S entries per namespace. Insertion order
// is the only order we expose; the cursor is a monotonic uint64 over the
// per-namespace seq counter.
type namespaceStore struct {
	mu      sync.Mutex
	nextSeq uint64
	entries []*storedEntry
	byHash  map[hash.Hash]*storedEntry
}

func newNamespaceStore() *namespaceStore {
	return &namespaceStore{byHash: make(map[hash.Hash]*storedEntry)}
}

// put inserts (or replaces by hash) a stored entry; returns its seq.
func (ns *namespaceStore) put(e *storedEntry) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if existing, ok := ns.byHash[e.EntryHash]; ok {
		// Dedup by content_hash — same store-entry put twice is idempotent;
		// the existing seq is preserved so pollers don't see it as a "new"
		// entry on a later poll. The inner envelope bytes are byte-identical
		// for hash-equal entries (V7 §1.5 + ECF determinism), so no rewrite
		// is needed.
		_ = existing
		return
	}
	ns.nextSeq++
	e.Seq = ns.nextSeq
	ns.entries = append(ns.entries, e)
	ns.byHash[e.EntryHash] = e
}

// gc removes entries whose ExpiresAt has passed; called on each :poll and
// :put for the touched namespace. Bounded by entry count, not time —
// keeps the GC posture per §8 (transient; honor expires_at).
func (ns *namespaceStore) gc(now uint64) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if len(ns.entries) == 0 {
		return
	}
	kept := ns.entries[:0]
	for _, e := range ns.entries {
		if e.ExpiresAt != 0 && e.ExpiresAt <= now {
			delete(ns.byHash, e.EntryHash)
			continue
		}
		kept = append(kept, e)
	}
	ns.entries = kept
}

// poll returns up to `limit` entries with seq > sinceSeq, plus the next
// cursor (the max seq returned, or sinceSeq if none) and has_more.
func (ns *namespaceStore) poll(sinceSeq uint64, limit int) (out []*storedEntry, newCursor uint64, hasMore bool) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	newCursor = sinceSeq
	for i, e := range ns.entries {
		if e.Seq <= sinceSeq {
			continue
		}
		if len(out) >= limit {
			hasMore = true
			break
		}
		out = append(out, e)
		newCursor = e.Seq
		_ = i
	}
	return out, newCursor, hasMore
}

// pollFiltered returns up to `limit` entries with seq > sinceSeq whose
// EntryHash is ALSO in the `allowed` set. The set comes from a tree-subtree
// listing under `system/relay/store/{ns}/*` (excluding `inner/*`) per
// RULING-RELAY-RECEIVE-SIDE-FETCH-SURFACE — the tree is the
// authoritative source of what the relay holds; namespaceStore owns the
// seq cursor and ExpiresAt bookkeeping. When `allowed` is nil the filter
// is bypassed (tree introspection unavailable — fall back to the in-memory
// store; v1's in-memory floor keeps them strictly in sync at put time).
func (ns *namespaceStore) pollFiltered(sinceSeq uint64, limit int, allowed map[hash.Hash]struct{}) (out []*storedEntry, newCursor uint64, hasMore bool) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	newCursor = sinceSeq
	for i, e := range ns.entries {
		if e.Seq <= sinceSeq {
			continue
		}
		if allowed != nil {
			if _, ok := allowed[e.EntryHash]; !ok {
				continue
			}
		}
		if len(out) >= limit {
			hasMore = true
			break
		}
		out = append(out, e)
		newCursor = e.Seq
		_ = i
	}
	return out, newCursor, hasMore
}

// Handler implements the system/relay substrate.
type Handler struct {
	mu                sync.RWMutex
	stores            map[string]*namespaceStore // namespace path → store
	clock             Clock
	defaultPollLimit  int
	maxPollLimit      int
	ready             bool
	localPeerIDBase58 string             // captured at SetupStore for advertise placement
	dispatcher        OutboundDispatcher // §3.1.1 outbound seam; defaults to noop
	resolver          InboxRelayResolver // §3.5 declaration resolver; defaults to nop
	disableDefaultFallback bool          // when true + no declared inbox-relay → no_inbox_relay/502
}

// NewHandler returns a substrate with empty Mode-S store + default clock /
// limits + a noop dispatcher (always returns ErrDestinationUnreachable so
// every :forward exercises the §6.2.1 fallback path until SetDispatcher is
// called) + a nop inbox-relay resolver (no destination has a declared
// inbox-relay; fallback uses the default convention). Wire authority via
// SetupStore.
func NewHandler() *Handler {
	return &Handler{
		stores:           make(map[string]*namespaceStore),
		clock:            SystemClock,
		defaultPollLimit: DefaultPollLimit,
		maxPollLimit:     MaxPollLimit,
		dispatcher:       noopDispatcher{},
		resolver:         NopInboxRelayResolver{},
	}
}

// Name implements handler.Handler.
func (h *Handler) Name() string { return "relay" }

// SetClock overrides the time source. Test-only.
func (h *Handler) SetClock(c Clock) {
	if c == nil {
		c = SystemClock
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clock = c
}

// SetDefaultPollLimit overrides the per-request default cap.
func (h *Handler) SetDefaultPollLimit(n int) {
	if n < 1 {
		n = DefaultPollLimit
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.defaultPollLimit = n
}

// SetMaxPollLimit overrides the absolute per-response cap.
func (h *Handler) SetMaxPollLimit(n int) {
	if n < 1 {
		n = MaxPollLimit
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.maxPollLimit = n
}

// SetupStore marks the substrate ready. localPeerIDBase58 is the local
// peer's Base58 peer-id (used as the advertise-entity-path segment per
// §4.1, and as the "self" peer identity in §6.2.1 fallback decisions).
// The handler does NOT directly hold a store/index — those come from the
// per-request hctx (registry/publishedroot pattern: hctx.Store +
// hctx.LocationIndex).
func (h *Handler) SetupStore(localPeerIDBase58 string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.localPeerIDBase58 = localPeerIDBase58
	h.ready = true
}

// SetDispatcher installs the outbound seam for §3.1.1 dispatch. Passing
// nil resets to the noop dispatcher (every :forward → §6.2.1 fallback).
// Production wiring is peer-builder-injected; tests inject fakes.
func (h *Handler) SetDispatcher(d OutboundDispatcher) {
	if d == nil {
		d = noopDispatcher{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dispatcher = d
}

// SetInboxRelayResolver installs the §3.5 declaration resolver. Passing
// nil resets to the nop resolver. Production wiring would inject a
// resolver that consults the local REGISTRY index for each destination's
// published inbox-relay binding (REGISTRY is the primary always-on
// holder per §3.5).
func (h *Handler) SetInboxRelayResolver(r InboxRelayResolver) {
	if r == nil {
		r = NopInboxRelayResolver{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.resolver = r
}

// SetDisableDefaultFallback flips the default-convention store off so the
// §6.2.1 path surfaces no_inbox_relay/502 when no declared inbox-relay
// is available. The conformant default is FALSE (default convention is
// usable — store on the forwarding relay itself). Used by test scenarios
// + deployments that explicitly want "MX-required" semantics (no implicit
// store-on-the-forwarding-relay).
func (h *Handler) SetDisableDefaultFallback(off bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disableDefaultFallback = off
}

// Manifest declares the four ops + internal-scope per §5.2.
//
// The four per-mode caps (relay-forward / relay-put / relay-poll /
// relay-advertise) are user-facing and granted via the peer-builder's
// seed-policy — not by the manifest's InternalScope (which governs
// handler-internal dispatch authority, not user grant). R3 wires the
// self-poll default grant for §5.5.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: HandlerPattern,
		Name:    "relay",
		Operations: map[string]types.HandlerOperationSpec{
			OpForward: {
				InputType:  types.TypeRelayForwardRequest,
				OutputType: types.TypeRelayForwardResult,
			},
			OpPut: {
				InputType:  types.TypeRelayStoreEntry,
				OutputType: types.TypeRelayPutResult,
			},
			OpPoll: {
				InputType:  types.TypeRelayPollRequest,
				OutputType: types.TypeRelayPollResult,
			},
			OpAdvertise: {
				InputType: types.TypeRelayAdvertise,
			},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{HandlerPattern}},
				Resources:  types.CapabilityScope{Include: []string{HandlerPattern, HandlerPattern + "/*"}},
				Operations: types.CapabilityScope{Include: []string{OpForward, OpPut, OpPoll, OpAdvertise}},
			},
		},
	}
}

// RegisterTypes is a no-op — relay types register centrally in
// core/types.RegisterCoreTypes (R1).
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches to the four ops.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	h.mu.RLock()
	ready := h.ready
	h.mu.RUnlock()
	if !ready {
		return handler.NewErrorResponse(503, "authority_not_ready",
			"relay substrate not yet wired (SetupStore pending)")
	}
	switch req.Operation {
	case OpForward:
		return h.handleForward(ctx, req)
	case OpPut:
		return h.handlePut(ctx, req)
	case OpPoll:
		return h.handlePoll(ctx, req)
	case OpAdvertise:
		return h.handleAdvertise(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			HandlerPattern+" does not support operation: "+req.Operation)
	}
}

// -----------------------------------------------------------------------
// :forward (§3.1.1 dispatch shape + §6.2.1 fallback)
// -----------------------------------------------------------------------

func (h *Handler) handleForward(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	rd, err := types.ForwardRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode forward-request: "+err.Error())
	}
	if rd.Destination == "" {
		return handler.NewErrorResponse(400, "invalid_request",
			"forward-request.destination MUST be set")
	}
	// §3.1 + §4.3: ttl_hops at 0 on receipt rejects fail-closed.
	if rd.TTLHops == 0 {
		return handler.NewErrorResponse(400, types.RelayErrTTLExhausted,
			"ttl_hops reached 0 on receipt")
	}
	// §9 envelope opacity: the inner envelope MUST ride in the V7 envelope's
	// included set, keyed by EnvelopeInner. Resolve once here — the dispatch
	// path threads the entity through; we never decode it.
	innerEnt, ok := lookupIncluded(req, rd.EnvelopeInner)
	if !ok {
		return handler.NewErrorResponse(400, "invalid_request",
			"forward-request.envelope_inner not present in included set "+
				"(inner envelope must ride as opaque included entity per §9)")
	}
	// PROPOSAL-RELAY-SOURCE-ROUTED-MULTIHOP §2.2 + PROPOSAL-EXTENSION-ROUTE
	// §3 — per-hop algorithm. Precedence:
	//   1. Route present and non-empty → next = Route[0]
	//   2. else NextHop set → next = NextHop
	//   3. else consult local route table (EXTENSION-ROUTE §3 match) →
	//      exact destination or `*` default, lowest metric, expiry-skip
	//   4. else no_route/502 (v1 floor — direct-or-no_route resolver)
	// When both Route and NextHop are set, NextHop MUST equal Route[0]
	// (proposal §2.1 cross-field invariant — invalid_request/400 otherwise).
	var next string
	var remaining []string
	switch {
	case len(rd.Route) > 0:
		next = rd.Route[0]
		remaining = rd.Route[1:]
		if rd.NextHop != "" && rd.NextHop != next {
			return handler.NewErrorResponse(400, "invalid_request",
				"forward-request.next_hop ("+rd.NextHop+") MUST equal route[0] ("+next+") when both are set (proposal §2.1)")
		}
	case rd.NextHop != "":
		next = rd.NextHop
		remaining = nil
	default:
		// EXTENSION-ROUTE §3 table read. No source route, no explicit
		// next-hop — consult the local route table. The match is:
		// exact > `*` default; lowest metric wins; expired skipped;
		// no-match → fall through to no_route/502.
		tableNext, hit := h.resolveFromTable(req, rd.Destination)
		if hit {
			next = tableNext
			remaining = nil
		} else {
			return handler.NewErrorResponse(502, types.RelayErrNoRoute,
				"forward-request needs route, next_hop, or a matching system/route entry (no source route + empty next_hop + no table match); §6.2.1 fallback only fires after a dispatch attempt fails")
		}
	}

	h.mu.RLock()
	dispatcher := h.dispatcher
	localPeerID := h.localPeerIDBase58
	h.mu.RUnlock()

	// §3.1.1: terminal hop iff `next == destination`. Source-routing collapses
	// to terminal naturally when route=[D] (proposal §4 SRCROUTE-TERMINAL-
	// EQUIV-1). Smarter routing tables are Phase 2 / EXTENSION-ROUTE.
	isTerminal := next == rd.Destination

	if isTerminal {
		// §3.1.1 terminal: unwrap and dispatch the bare inner envelope to
		// the destination. The destination needs no RELAY extension
		// installed to receive — the inner envelope is what would have
		// arrived on a direct connection (byte-identical per §9).
		_, err := dispatcher.DeliverInner(ctx, rd.Destination, innerEnt)
		if err == nil {
			return handler.NewResponse(200, types.TypeRelayForwardResult,
				types.ForwardResultData{
					Status:  types.ForwardStatusForwarded,
					NextHop: next,
				})
		}
		if errors.Is(err, ErrDestinationUnreachable) {
			// §6.2.1 fallback — destination offline. §3.5 resolution:
			// look up the declared inbox-relay; honor it if we serve
			// the destination; else use the default convention; else
			// surface no_inbox_relay/502 (never a silent drop).
			storedAt, code, ferr := h.queueFallback(req, rd, innerEnt, localPeerID)
			if ferr != nil {
				return handler.NewErrorResponse(500, "internal",
					"§6.2.1 fallback store failed: "+ferr.Error())
			}
			if code != "" {
				return handler.NewErrorResponse(502, code,
					"destination "+rd.Destination+" unreachable and no usable inbox-relay (no declaration, default convention disabled per §3.5)")
			}
			return handler.NewResponse(200, types.TypeRelayForwardResult,
				types.ForwardResultData{
					Status:   types.ForwardStatusQueuedFallback,
					StoredAt: storedAt,
				})
		}
		// Any other dispatcher error surfaces as a hard fail — relay
		// MUST NOT silently drop (consistent with v7.75 substrate-
		// resilience posture; §4.3 fail-closed).
		return handler.NewErrorResponse(500, "dispatch_failed",
			"terminal deliver to "+rd.Destination+" failed: "+err.Error())
	}

	// §3.1.1 intermediate: forward to `next` relay with TTL-1. Pop the head
	// of Route — the next relay chooses *its* next hop from the remaining
	// path (proposal §2.2). Single-hop callers (NextHop only, no Route)
	// preserve their pre-proposal shape: `remaining` is nil, route field
	// drops via omitempty, NextHop forwards verbatim with ttl-1 (same wire
	// as v1.0).
	var nextHopForRelayed string
	if len(remaining) > 0 {
		nextHopForRelayed = remaining[0]
	}
	relayed := types.ForwardRequestData{
		Destination:   rd.Destination,
		Route:         remaining,
		NextHop:       nextHopForRelayed,
		TTLHops:       rd.TTLHops - 1,
		EnvelopeInner: rd.EnvelopeInner,
	}
	_, err = dispatcher.ForwardToNextHop(ctx, next, relayed, innerEnt)
	if err == nil {
		return handler.NewResponse(200, types.TypeRelayForwardResult,
			types.ForwardResultData{
				Status:  types.ForwardStatusForwarded,
				NextHop: next,
			})
	}
	if errors.Is(err, ErrDestinationUnreachable) {
		// Intermediate-hop unreachable next also falls back per §6.2.1
		// + §3.5 — declaration lookup; default convention; or
		// no_inbox_relay/502.
		storedAt, code, ferr := h.queueFallback(req, rd, innerEnt, localPeerID)
		if ferr != nil {
			return handler.NewErrorResponse(500, "internal",
				"§6.2.1 fallback store failed: "+ferr.Error())
		}
		if code != "" {
			return handler.NewErrorResponse(502, code,
				"next hop "+next+" unreachable and no usable inbox-relay for destination "+rd.Destination)
		}
		return handler.NewResponse(200, types.TypeRelayForwardResult,
			types.ForwardResultData{
				Status:   types.ForwardStatusQueuedFallback,
				StoredAt: storedAt,
			})
	}
	return handler.NewErrorResponse(500, "dispatch_failed",
		"forward to next hop "+next+" failed: "+err.Error())
}

// resolveFromTable applies the EXTENSION-ROUTE §3 match against the local
// `system/route` subtree to pick a next-hop when the forward-request
// carries neither a source route nor an explicit next_hop. Behavior:
//
//  1. Enumerate route entities under RoutePrefix via the request's
//     LocationIndex; decode each via Store.Get.
//  2. Filter to routes whose Match is exactly `destinationPeerID` or the
//     `*` default-route token, and whose ExpiresAt is null or in the
//     future.
//  3. Pick the winner: lowest Metric (treating 0 as "lowest"); on ties,
//     exact-Match outranks the `*` default (longest-match-wins,
//     degenerate over a non-hierarchical peer-id space).
//  4. Action="deliver" → return destinationPeerID (handleForward then
//     detects `next == destination` → terminal hop, delivers locally).
//     Action="forward" → return Via (next intermediate hop).
//
// Returns ok=false when the request has no LocationIndex / Store (test
// contexts), or when the table is empty / fully expired / has no match —
// caller falls through to no_route/502.
//
// ROUTE §5: reads need no extra caller cap; this is relay's internal
// read of substrate state. Writes are guarded by `route-configure` at
// the standard tree-handler path, off-band from this function.
func (h *Handler) resolveFromTable(req *handler.Request, destinationPeerID string) (string, bool) {
	if req == nil || req.Context == nil || req.Context.LocationIndex == nil || req.Context.Store == nil {
		return "", false
	}
	li := req.Context.LocationIndex
	cs := req.Context.Store
	now := h.now()

	// Enumerate the local route subtree. List returns absolute paths;
	// only the bound hash matters here (we decode each route entity).
	listed := li.List(types.RoutePrefix)
	if len(listed) == 0 {
		return "", false
	}

	// Best candidate so far: lower Metric beats higher; on ties, exact
	// Match beats `*` default.
	var best types.RouteData
	bestSet := false
	bestExact := false

	for _, e := range listed {
		ent, ok := cs.Get(e.Hash)
		if !ok || ent.Type != types.TypeRoute {
			continue
		}
		rd, err := types.RouteDataFromEntity(ent)
		if err != nil {
			continue
		}
		// Filter by match: exact destination or default-route token.
		exact := rd.Match == destinationPeerID
		dflt := rd.Match == types.RouteMatchDefault
		if !exact && !dflt {
			continue
		}
		// Filter expired routes (0 == null per ECF omitempty).
		if rd.ExpiresAt != 0 && rd.ExpiresAt <= now {
			continue
		}
		// Cross-field invariant: forward action requires Via.
		if rd.Action == types.RouteActionForward && rd.Via == "" {
			continue
		}
		// Tie-break: prefer (exact, lower metric).
		if !bestSet {
			best = rd
			bestSet = true
			bestExact = exact
			continue
		}
		if exact && !bestExact {
			best = rd
			bestExact = true
			continue
		}
		if exact == bestExact && rd.Metric < best.Metric {
			best = rd
		}
	}

	if !bestSet {
		return "", false
	}
	switch best.Action {
	case types.RouteActionDeliver:
		// Terminal — handleForward detects `next == destination`.
		return destinationPeerID, true
	case types.RouteActionForward:
		return best.Via, true
	default:
		// Unknown action — skip.
		return "", false
	}
}

// resolveFallbackTarget applies §3.5 + §6.2.1 resolution:
//
//  1. Look up the destination's published inbox-relay declaration via the
//     installed resolver. If present, try its entries in ascending priority
//     order; the first whose `relay` field equals our local peer-id wins
//     (we'd be the one serving this entry). Use that entry's namespace.
//  2. If no declaration was found (or none of the declared relays target
//     us), AND the default-fallback is enabled (default), fall back to
//     the §6.2.1 default convention: namespace = destination peer_id on
//     this relay.
//  3. Otherwise (no declaration AND default disabled) surface
//     no_inbox_relay/502 to the caller — never a silent drop.
//
// Cross-relay store (declared relay != us) would require a remote :put
// via the OutboundDispatcher seam — deferred per v1 cohort scope. v1
// Go falls through to default-or-no-inbox-relay when the declared
// relay is someone else; future work wires the cross-relay store.
func (h *Handler) resolveFallbackTarget(destinationPeerID, localPeerID string) (namespace string, code string) {
	h.mu.RLock()
	resolver := h.resolver
	disableDefault := h.disableDefaultFallback
	h.mu.RUnlock()

	if decl, ok := resolver.Resolve(destinationPeerID); ok {
		// Try declared entries in ascending priority order.
		entries := append([]types.InboxRelayEntry(nil), decl.Relays...)
		sortByPriority(entries)
		for _, e := range entries {
			if e.Relay == localPeerID {
				// We're a declared inbox-relay for this destination —
				// honor the declaration's namespace (which the
				// destination chose; default convention when empty).
				ns := e.Namespace
				if ns == "" {
					ns = destinationPeerID
				}
				return ns, ""
			}
		}
		// Declared, but no entry targets us. Cross-relay store is v1-
		// deferred; if default convention is allowed, use it; else
		// surface no_inbox_relay.
		if disableDefault {
			return "", types.RelayErrNoInboxRelay
		}
		return destinationPeerID, ""
	}

	// No declaration. Default convention or no_inbox_relay.
	if disableDefault {
		return "", types.RelayErrNoInboxRelay
	}
	return destinationPeerID, ""
}

// sortByPriority sorts inbox-relay entries by ascending Priority. v1 keeps
// it simple — bubble-style on the small slice (typically 1-3 entries).
func sortByPriority(es []types.InboxRelayEntry) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j].Priority < es[j-1].Priority; j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
}

// queueFallback applies §6.2.1: store the inner envelope at the resolved
// fallback target under the relay's own authority. PutBy == the relay's
// local peer-id (NOT the caller's) — this is the case where PutBy
// diverges from authorship by design.
//
// Returns the FALLBACK NAMESPACE (= the resolved target, not the full
// store path). §4.2 forward-result.stored_at spec comment: "namespace,
// if queued-fallback" (Rust R6 catch). The destination uses the namespace
// to invoke `:poll`; the specific entry hash is discovered via poll
// cursor advance. (put-result.stored_at, in contrast, IS the full path
// including hash.)
//
// The second return value is the error code to surface to the caller
// (empty on success, RelayErrNoInboxRelay when neither declaration nor
// default-convention yields a usable target).
func (h *Handler) queueFallback(req *handler.Request, rd types.ForwardRequestData, innerEnt entity.Entity, localPeerID string) (string, string, error) {
	if localPeerID == "" {
		return "", "", errors.New("relay local peer-id not configured (SetupStore not called)")
	}
	namespace, code := h.resolveFallbackTarget(rd.Destination, localPeerID)
	if code != "" {
		return "", code, nil // §3.5 + §6.2.1 fail-closed surface (no silent drop)
	}
	now := h.now()
	se := types.StoreEntryData{
		Namespace:     namespace,   // §6.2.1: resolved target (declared or default)
		PutBy:         localPeerID, // relay placing on origin's behalf
		EnvelopeInner: rd.EnvelopeInner,
		// ExpiresAt: 0 — operator may set a default retention later (§8);
		// for v1 the fallback queue holds until polled.
	}
	entryEnt, err := se.ToEntity()
	if err != nil {
		return "", "", err
	}
	entry := &storedEntry{
		Entry:     se,
		EntryEnt:  entryEnt,
		EntryHash: entryEnt.ContentHash,
		Inner:     innerEnt,
		ExpiresAt: 0,
	}
	ns := h.namespaceFor(namespace)
	ns.gc(now)
	ns.put(entry)

	// Tree-bind both the store-entry and the inner envelope under the
	// namespace subtree per EXTENSION-RELAY §3.2 + RULING-RELAY-RECEIVE-
	// SIDE-FETCH-SURFACE. Receiver fetches both via tree:get;
	// the namespace-scoped tree-read cap governs the reads. §9 opacity
	// holds — the .Data bytes round-trip as cbor.RawMessage; nothing is
	// decoded.
	if req != nil && req.Context != nil && req.Context.Store != nil && req.Context.LocationIndex != nil {
		if _, err := req.Context.Store.Put(entryEnt); err != nil {
			return "", "", err
		}
		if _, err := req.Context.Store.Put(innerEnt); err != nil {
			return "", "", err
		}
		storedAt := types.RelayStorePath(namespace, entryEnt.ContentHash)
		if _, err := req.Context.TreeSet(storedAt, entryEnt.ContentHash, OpPut); err != nil {
			return "", "", err
		}
		innerPath := types.RelayInnerPath(namespace, innerEnt.ContentHash)
		if _, err := req.Context.TreeSet(innerPath, innerEnt.ContentHash, OpPut); err != nil {
			return "", "", err
		}
	}
	return namespace, "", nil
}

// -----------------------------------------------------------------------
// :put (R2 — accept + store; put_by check is R3)
// -----------------------------------------------------------------------

func (h *Handler) handlePut(_ context.Context, req *handler.Request) (*handler.Response, error) {
	rd, err := types.StoreEntryDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode store-entry: "+err.Error())
	}
	if rd.Namespace == "" {
		return handler.NewErrorResponse(400, types.RelayErrNamespaceInvalid,
			"store-entry.namespace MUST be set")
	}
	if rd.PutBy == "" {
		return handler.NewErrorResponse(400, "invalid_request",
			"store-entry.put_by MUST be set (Base58 peer_id per §3.0)")
	}
	now := h.now()
	if rd.ExpiresAt != 0 && rd.ExpiresAt <= now {
		return handler.NewErrorResponse(400, types.RelayErrExpiredOnArrival,
			"store-entry.expires_at already past at put time")
	}
	// §9: inner envelope MUST ride in included set, keyed by EnvelopeInner.
	innerEnt, ok := lookupIncluded(req, rd.EnvelopeInner)
	if !ok {
		return handler.NewErrorResponse(400, "invalid_request",
			"store-entry.envelope_inner not present in included set "+
				"(inner envelope must ride as opaque included entity per §9)")
	}
	// §3.2 (cohort R6/R7 ratification): the authenticated caller is the
	// SESSION/CONNECTION peer (hctx.SessionPeerID), NOT the wire-EXECUTE
	// author (hctx.Author). They agree on direct :put; they diverge on
	// cross-peer dispatch (Bob's relay re-issues Alice's EXECUTE to
	// Charlie's relay — wire-author is Alice but the session peer on
	// Charlie's relay is Bob). put_by is *placement-identity* (who placed
	// this on my relay = who connected and put it); that semantic maps to
	// session-peer, not wire-author.
	//
	// Authorship of the carried message lives in the INNER envelope's V7
	// §5.2 signature (which the relay never reads — §9 opacity). Pollers
	// MUST verify authorship from there, never from put_by. The §6.2.1
	// fallback path is the proof the two are distinct: the relay places
	// on origin's behalf, so put_by == relay (the session peer's identity
	// on the internal fallback), authorship stays Alice.
	//
	// When hctx.SessionPeerID is empty (in-process tests, or the §6.2.1
	// fallback path's queueFallback which writes directly with no wire
	// session), the check skips. Production wire always populates it.
	if sessionPeerID := string(req.Context.SessionPeerID); sessionPeerID != "" {
		if rd.PutBy != sessionPeerID {
			return handler.NewErrorResponse(400, types.RelayErrPutByMismatch,
				"store-entry.put_by ("+rd.PutBy+") does not match authenticated session peer ("+sessionPeerID+")")
		}
	}

	// Build the store-entry entity for hash/canonical storage.
	entryEnt, err := rd.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"materialize store-entry: "+err.Error())
	}
	storedAt := types.RelayStorePath(rd.Namespace, entryEnt.ContentHash)
	se := &storedEntry{
		Entry:     rd,
		EntryEnt:  entryEnt,
		EntryHash: entryEnt.ContentHash,
		Inner:     innerEnt,
		ExpiresAt: rd.ExpiresAt,
	}
	ns := h.namespaceFor(rd.Namespace)
	ns.gc(now)
	ns.put(se)

	// Per EXTENSION-RELAY §3.2 + RULING-RELAY-RECEIVE-SIDE-FETCH-SURFACE:
	// both the store-entry and the inner envelope MUST be
	// tree-bound under the namespace subtree so the receiver fetches them
	// via `tree:get` (NOT `system/content:get`) and the namespace-scoped
	// tree-read cap governs both reads. Content-store puts persist the
	// bytes (path→hash→bytes; tree bind = path→hash, content store = hash→
	// bytes). §9 opacity holds — the .Data bytes round-trip as
	// cbor.RawMessage; nothing is decoded.
	if hctx := req.Context; hctx != nil && hctx.Store != nil && hctx.LocationIndex != nil {
		if _, err := hctx.Store.Put(entryEnt); err != nil {
			return handler.NewErrorResponse(500, "internal",
				"store store-entry bytes: "+err.Error())
		}
		if _, err := hctx.Store.Put(innerEnt); err != nil {
			return handler.NewErrorResponse(500, "internal",
				"store inner envelope bytes: "+err.Error())
		}
		if _, err := hctx.TreeSet(storedAt, entryEnt.ContentHash, OpPut); err != nil {
			return handler.NewErrorResponse(500, "internal",
				"tree-bind store-entry at "+storedAt+": "+err.Error())
		}
		innerPath := types.RelayInnerPath(rd.Namespace, innerEnt.ContentHash)
		if _, err := hctx.TreeSet(innerPath, innerEnt.ContentHash, OpPut); err != nil {
			return handler.NewErrorResponse(500, "internal",
				"tree-bind inner envelope at "+innerPath+": "+err.Error())
		}
	}

	return handler.NewResponse(200, types.TypeRelayPutResult,
		types.PutResultData{
			Status:    types.PutStatusStored,
			StoredAt:  storedAt,
			EntryHash: entryEnt.ContentHash,
			ExpiresAt: rd.ExpiresAt,
		})
}

// -----------------------------------------------------------------------
// :poll (R2)
// -----------------------------------------------------------------------

func (h *Handler) handlePoll(_ context.Context, req *handler.Request) (*handler.Response, error) {
	rd, err := types.PollRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode poll-request: "+err.Error())
	}
	if rd.Namespace == "" {
		return handler.NewErrorResponse(400, types.RelayErrNamespaceInvalid,
			"poll-request.namespace MUST be set")
	}

	sinceSeq, err := decodeCursor(rd.Since)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"poll-request.since: "+err.Error())
	}

	h.mu.RLock()
	defLim := h.defaultPollLimit
	maxLim := h.maxPollLimit
	h.mu.RUnlock()

	limit := defLim
	if rd.Limit > 0 {
		limit = int(rd.Limit)
	}
	if limit > maxLim {
		limit = maxLim
	}

	// §4.2 + landing-pass finding #1: a poll against a namespace the caller
	// is authorized to read that holds no entries MUST return
	// {entries: [], has_more: false} at 200 — NOT namespace_not_found/404.
	// We treat *every* poll against a never-touched namespace as empty-
	// authorized in v1 (the R3 cap-check pre-screens for authorization;
	// here we just return the empty set).
	ns := h.namespaceForExisting(rd.Namespace)
	if ns == nil {
		return handler.NewResponse(200, types.TypeRelayPollResult,
			types.PollResultData{
				Entries: []hash.Hash{},
				Cursor:  encodeCursor(sinceSeq),
				HasMore: false,
			})
	}
	ns.gc(h.now())

	// RULING-RELAY-RECEIVE-SIDE-FETCH-SURFACE §6.1.1: enumerate
	// via tree-subtree listing under RelayStorePrefix(namespace) (the
	// authoritative source of what the relay holds-and-serves), NOT the
	// internal namespaceStore map. Both are written in lockstep at
	// handlePut/queueFallback; the tree is canonical so cross-impl cap
	// scoping flows through the standard tree-handler path.
	//
	// Filter the inner/{...} subtree — those leaves are reachable via
	// store-entry.envelope_inner and tree:get, not via poll (§3.2).
	treeEntries := allowedEntryHashes(req, h.localPeerIDBase58, rd.Namespace)

	// namespaceStore continues to own (a) the relay-owned seq cursor and
	// (b) per-entry expires_at GC bookkeeping. Cross-reference: only emit
	// entries that are BOTH tree-bound (treeEntries) AND seq-stamped
	// (namespaceStore). v1's in-memory floor keeps them strictly in sync
	// (cohort handoff TBD #2).
	out, newCursor, hasMore := ns.pollFiltered(sinceSeq, limit, treeEntries)

	entries := make([]hash.Hash, 0, len(out))
	for _, e := range out {
		entries = append(entries, e.EntryHash)
	}
	return handler.NewResponse(200, types.TypeRelayPollResult,
		types.PollResultData{
			Entries: entries,
			Cursor:  encodeCursor(newCursor),
			HasMore: hasMore,
		})
}

// -----------------------------------------------------------------------
// :advertise (R2)
// -----------------------------------------------------------------------

func (h *Handler) handleAdvertise(_ context.Context, req *handler.Request) (*handler.Response, error) {
	rd, err := types.AdvertiseDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode advertise: "+err.Error())
	}
	if len(rd.Modes) == 0 {
		return handler.NewErrorResponse(400, "invalid_request",
			"advertise.modes MUST list at least one mode")
	}
	// V7 §5.2: advertise MUST be signed by relay_peer_id; signature reaches
	// at system/signature/{hex(advertise.content_hash)}. R2 binds the
	// advertise entity at its canonical path; the signature carriage +
	// publication lives at the peer-builder seam (it has the keypair).
	advertiseEnt, err := rd.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"materialize advertise: "+err.Error())
	}
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal",
			"missing store / location index")
	}
	h.mu.RLock()
	localPeerID := h.localPeerIDBase58
	h.mu.RUnlock()
	if localPeerID == "" {
		return handler.NewErrorResponse(500, "internal",
			"advertise without local peer-id: SetupStore not called or local_peer_id empty")
	}
	// Put the entity content; bind at the canonical advertise path.
	if _, err := hctx.Store.Put(advertiseEnt); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"store advertise entity: "+err.Error())
	}
	path := types.RelayAdvertisePath(localPeerID)
	if _, err := hctx.TreeSet(path, advertiseEnt.ContentHash, OpAdvertise); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"bind advertise at "+path+": "+err.Error())
	}
	return &handler.Response{Status: 200}, nil
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

func (h *Handler) now() uint64 {
	h.mu.RLock()
	c := h.clock
	h.mu.RUnlock()
	return c()
}

// namespaceFor returns (or creates) the namespace store for `ns`.
func (h *Handler) namespaceFor(ns string) *namespaceStore {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.stores[ns]
	if !ok {
		st = newNamespaceStore()
		h.stores[ns] = st
	}
	return st
}

// namespaceForExisting returns the namespace store for `ns` without
// creating one — used by :poll, which MUST return empty rather than
// namespace_not_found for un-provisioned namespaces in v1.
func (h *Handler) namespaceForExisting(ns string) *namespaceStore {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stores[ns]
}

// EntryByHash returns the stored entry + inner envelope for the given
// store-entry content_hash, if present. Exposed so the post-poll fetch
// path (R4 validate-peer + R8 cross-impl tests) can resolve the two-hop
// pointer discipline (NETWORK §6.5.3.1).
func (h *Handler) EntryByHash(namespace string, entryHash hash.Hash) (entity.Entity, entity.Entity, bool) {
	ns := h.namespaceForExisting(namespace)
	if ns == nil {
		return entity.Entity{}, entity.Entity{}, false
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if e, ok := ns.byHash[entryHash]; ok {
		return e.EntryEnt, e.Inner, true
	}
	return entity.Entity{}, entity.Entity{}, false
}

// lookupIncluded resolves a hash via the request's included map. Required
// for envelope_inner (§9 opacity) — the inner envelope rides in the V7
// envelope's `included` set per the cohort's V7 §5.2 refless target-
// matching pattern.
func lookupIncluded(req *handler.Request, h hash.Hash) (entity.Entity, bool) {
	if req == nil || req.Context == nil || req.Context.Included == nil {
		return entity.Entity{}, false
	}
	ent, ok := req.Context.Included[h]
	return ent, ok
}

// allowedEntryHashes lists tree-bound store-entry paths under
// `system/relay/store/{namespace}/*` and returns the set of their bound
// hashes. The `inner/*` subtree is filtered (those leaves are reachable
// via store-entry.envelope_inner + tree:get, NOT via poll — §3.2).
//
// Returns nil when the request has no LocationIndex (manually-built test
// contexts) — callers MUST treat nil as "filter unavailable; fall back to
// the in-memory store" (which is what `pollFiltered(allowed=nil)` does).
//
// The listed paths are absolute (`/{localPeer}/system/relay/store/{ns}/...`);
// the InnerPrefix filter uses the same canonicalization the listing did.
func allowedEntryHashes(req *handler.Request, localPeerID, namespace string) map[hash.Hash]struct{} {
	if req == nil || req.Context == nil || req.Context.LocationIndex == nil || localPeerID == "" {
		return nil
	}
	li := req.Context.LocationIndex
	listed := li.List(types.RelayStorePrefix(namespace))
	absInnerPrefix := "/" + localPeerID + "/" + types.RelayInnerPrefix(namespace)
	out := make(map[hash.Hash]struct{}, len(listed))
	for _, e := range listed {
		if strings.HasPrefix(e.Path, absInnerPrefix) {
			continue
		}
		out[e.Hash] = struct{}{}
	}
	return out
}

// encodeCursor serializes the relay-owned seq as a CBOR-encoded 8-byte
// big-endian byte string. Go's cursor wire shape is a CBOR bstr; cohort
// R6/R7 agreement is "cursor is opaque, relay-owned" — Rust uses the same
// bstr shape; Python uses a CBOR text string (lex-by-path). On receive,
// PollRequestData.Since is cbor.RawMessage so any shape round-trips.
func encodeCursor(seq uint64) cbor.RawMessage {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, seq)
	cborBytes, err := ecf.Encode(out)
	if err != nil {
		// Encoding a fixed 8-byte slice via ECF never fails in practice;
		// fall back to the raw bytes wrapped as a bstr header by hand.
		return cbor.RawMessage(append([]byte{0x48}, out...)) // 0x48 = bstr(8)
	}
	return cbor.RawMessage(cborBytes)
}

// decodeCursor parses a Go-emitted cursor back to seq. Accepts: nil
// (fresh start), CBOR null, CBOR bstr of 8 bytes (Go's own format).
// Other shapes (CBOR text strings from Python, etc.) we accept the bytes
// but cannot map to a Go seq — those cursors are pass-through only and
// only Go's own emit can be decoded to advance our store. (Cross-impl
// polls that round-trip through Go's namespace store use the namespace
// store's own emitted cursor on the second poll.)
func decodeCursor(raw cbor.RawMessage) (uint64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	// Probe the CBOR major type. 0x40-0x5F is byte string; 0xF6 is null.
	first := raw[0]
	if first == 0xF6 { // CBOR null
		return 0, nil
	}
	if first >= 0x40 && first <= 0x5F {
		// Byte string — decode and check length.
		var b []byte
		if err := ecf.Decode(raw, &b); err != nil {
			return 0, fmt.Errorf("malformed cursor bstr: %w", err)
		}
		if len(b) == 0 {
			return 0, nil
		}
		if len(b) != 8 {
			return 0, fmt.Errorf("malformed cursor (expected 8-byte BE uint64, got %d bytes)", len(b))
		}
		return binary.BigEndian.Uint64(b), nil
	}
	// Any other shape (text string from a foreign impl, etc.) — treat as
	// fresh start. The store-write path emits Go-shape cursors going
	// forward, so a subsequent :poll will round-trip correctly.
	return 0, nil
}

// -----------------------------------------------------------------------
// §5.5 default-grant helpers (peer-builder seed-policy)
// -----------------------------------------------------------------------

// SelfPollSeedGrants returns the per-peer GrantEntry slice for §5.5: a
// grant authorizing the holder to relay-poll over namespace = `peerID`
// (their own peer-id). The peer-builder calls this via
// core/peer.SeedPolicyForPeerID(peerID, SelfPollSeedGrants(peerID)) to
// install the §5.5 default for each peer that needs fallback-inbox
// retrieval.
//
// Spec mapping (§5.5):
//
//	"a peer running Mode S SHOULD install a default grant authorizing
//	 every requesting peer P to relay-poll at namespace = P's own peer_id"
//
// Per-peer install is the v1 mechanism — the §5.4 CapabilityScope does
// not have a "{caller_peer_id}" template, so we materialize one grant
// per known peer-id with a concrete-path Resources scope. Operators
// wanting "any peer P → namespace P" with no per-peer install need
// either scope templating (V7 follow-on) OR a wildcard relay-poll grant
// they accept-the-tradeoff of (which widens read access — exactly what
// §5.5 says not to do).
//
// Note narrow scope (operations: relay-poll only): this MUST NOT include
// relay-put / relay-forward / relay-advertise — those need explicit
// operator grant.
func SelfPollSeedGrants(peerID crypto.PeerID) []types.GrantEntry {
	pid := string(peerID)
	return []types.GrantEntry{
		{
			Handlers:   types.CapabilityScope{Include: []string{HandlerPattern}},
			Resources:  types.CapabilityScope{Include: []string{types.RelayStorePrefix(pid) + "*"}},
			Operations: types.CapabilityScope{Include: []string{OpPoll}},
		},
	}
}

// Compile-time interface checks.
var _ handler.Handler = (*Handler)(nil)
var _ handler.ManifestProvider = (*Handler)(nil)
var _ handler.TypeProvider = (*Handler)(nil)

// silence unused-import: ecf is reserved for future direct use.
var _ = ecf.Encode
