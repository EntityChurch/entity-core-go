// Package network implements the system/network handler per
// EXTENSION-NETWORK.md §3–§4 (Amendment 12 rung 3): the maintain-peer /
// release-peer / status / close operations and the §4.1 reconnect lifecycle
// continuation graph, composed on the §A3 liveness floor that core/peer
// already provides (status transition writes + §5.4 keepalive).
//
// Division of labor (§A4 discipline — the handler double-builds nothing):
//
//   - core/peer owns the imperative substrate: establish writes `connected`,
//     the §A1 dispatch seam writes `suspect`, the §5.4 keepalive loop writes
//     `disconnected` and starts at every outbound pool insert.
//   - this handler owns the REACTIVE half: it installs the continuation
//     graph that watches those writes and dials back.
//
// The §4.1 graph as built here (see docs/validation/spec-issues for the
// deliberate divergences from the §4.1 pseudocode):
//
//   - system/inbox/network/{peer}/on-disconnect — standing continuation,
//     advanced by a lifecycle subscription on system/peer/status/{hex};
//     dispatches the internal `reconnect` operation (Go's connect-if-needed
//     seam; the pseudocode's `system/protocol/connect hello` target is the
//     responder side of the handshake in Go and cannot dial).
//   - system/network/peers/{peer}/on-reconnect-backoff — one-shot
//     continuation re-EXECUTing maintain-peer; advanced by the handler
//     after the computed §2.2 backoff delay. Lives in the §11 managed
//     namespace, NOT under system/inbox/* — the marker-proposal §5
//     discipline (on_error/error routing MUST NOT target system/inbox/*).
//   - system/inbox/network/{peer}/on-reconnect — standing continuation,
//     advanced by a second lifecycle subscription on the same status path;
//     dispatches the internal `restore-subscriptions` operation (§7.2).
//
// Failed reconnect dispatches deliberately carry NO on_error: a forward
// non-2xx with no on_error binds the §3.10 lost-error marker under the
// continuation handler's own authority, keyed by RequestID — the
// PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-MUST observability surface this
// rung is the named test subject for.
package network

import (
	"context"
	"log"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
)

// HandlerPattern is the handler's registration pattern (§3.1).
const HandlerPattern = "system/network"

// Handler implements the system/network handler.
type Handler struct {
	mu sync.Mutex
	// p is the bound local peer — the imperative connect/evict seam.
	// Set by Bind after peer construction (same post-construction wiring
	// as clock.SetupAdvancement); operations 500 until bound.
	p *peer.Peer
	// sessions tracks live maintain-peer sessions keyed by remote peer id.
	// In-memory per §12.4 (session bookkeeping is implementation-defined);
	// the continuation graph itself lives in the tree.
	sessions map[crypto.PeerID]*session
	// reflectLimiter / dialbackLimiter are the §6.7.4 per-requester rate
	// limits for observe-address / check-reachability (both "always
	// rate-limited"; dial-back the more tightly).
	reflectLimiter  *rateLimiter
	dialbackLimiter *rateLimiter
	debugLog        *log.Logger
}

// NewHandler creates a new network handler. Call Bind after the peer is
// constructed to wire the imperative seams.
func NewHandler() *Handler {
	return &Handler{
		sessions:        make(map[crypto.PeerID]*session),
		reflectLimiter:  newRateLimiter(reflectMinInterval),
		dialbackLimiter: newRateLimiter(dialbackMinInterval),
	}
}

// Bind wires the handler to its local peer. Must be called once after
// peer.New — the handler needs the peer's keypair/identity (to self-author
// lifecycle subscribe/advance EXECUTEs), its dispatcher, and the
// EnsureConnected/EvictRemoteConnection connection-pool seams.
func (h *Handler) Bind(p *peer.Peer) {
	h.mu.Lock()
	h.p = p
	h.mu.Unlock()
}

// SetDebugLog enables debug logging.
func (h *Handler) SetDebugLog(l *log.Logger) { h.debugLog = l }

func (h *Handler) debugf(format string, args ...any) {
	if h.debugLog != nil {
		h.debugLog.Printf("network: "+format, args...)
	}
}

func (h *Handler) Name() string { return "network" }

// Manifest returns the handler's self-description (§3.1).
//
// Beyond the four §3.1 operations it advertises the internal operations the
// §4.1 graph dispatches (`reconnect`, `restore-subscriptions`) — §A5:
// advertise what you dispatch. `restore-subscriptions` is dispatched by the
// spec's own pseudocode yet missing from the spec's §3.1 manifest (flagged
// in docs/validation/spec-issues).
//
// The internal_scope extends the §3.1 block with the handler's own pattern
// and the continuation surface: the §4.1 graph's dispatch_capability is this
// handler's grant (§11), so the grant must authorize the EXECUTEs the graph
// performs at advance time (system/network reconnect / maintain-peer /
// restore-subscriptions) and the handler's own backoff-timer advances. The
// spec's §3.1 scope block cannot authorize the §4.1 graph it specifies —
// also flagged in spec-issues.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: HandlerPattern,
		Name:    "network",
		Operations: map[string]types.HandlerOperationSpec{
			"maintain-peer": {
				InputType:  types.TypeNetworkMaintainRequest,
				OutputType: types.TypeNetworkMaintainResult,
			},
			"release-peer": {
				InputType:  types.TypeNetworkReleaseRequest,
				OutputType: types.TypeNetworkReleaseResult,
			},
			"status": {
				OutputType: types.TypeNetworkStatus,
			},
			"close": {
				InputType: types.TypeNetworkCloseRequest,
			},
			// §6.7 reachability facts (Amendment 13). Both take no input (the
			// fact rides from the accepted connection, never the body);
			// observe-address is in the broad default connection grant
			// (§6.7.4 network-reflect), check-reachability is restricted
			// (§6.7.4 network-dialback).
			"observe-address": {
				OutputType: types.TypeNetworkObserveAddressResult,
			},
			"check-reachability": {
				OutputType: types.TypeNetworkCheckReachabilityResult,
			},
			// Internal — dispatched by the §4.1 lifecycle continuations,
			// advertised per §A5.
			"reconnect": {
				InputType: types.TypeNetworkMaintainRequest,
			},
			"restore-subscriptions": {
				InputType: "primitive/any",
			},
		},
		InternalScope: []types.GrantEntry{
			// §3.1 block.
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/*"}},
				Operations: types.CapabilityScope{Include: []string{"get", "put"}},
			},
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/subscription"}},
				Resources:  types.CapabilityScope{Include: []string{"system/*"}},
				Operations: types.CapabilityScope{Include: []string{"subscribe", "unsubscribe"}},
			},
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/protocol/connect"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"hello", "authenticate"}},
			},
			// Go additions (spec-issue: §3.1's block cannot authorize the
			// §4.1 graph's own advance-time dispatches).
			{
				Handlers: types.CapabilityScope{Include: []string{HandlerPattern}},
				// The lifecycle ops target the BARE handler path (maintain.go's
				// Resource: {Targets: ["system/network"]}), so the bare path is
				// listed explicitly alongside the subtree. §5.4 `system/network/*`
				// does NOT self-match `system/network` (ROUTING-2026-08-18-o §4);
				// this grant relied on go's removed permissive self-match and is now
				// explicit — the same shape rust/py already carry.
				Resources: types.CapabilityScope{Include: []string{"system/network", "system/network/*", "system/inbox/network/*"}},
				Operations: types.CapabilityScope{Include: []string{
					"maintain-peer", "release-peer", "status", "close",
					"reconnect", "restore-subscriptions",
				}},
			},
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/continuation"}},
				Resources:  types.CapabilityScope{Include: []string{"system/network", "system/network/*", "system/inbox/network/*"}},
				Operations: types.CapabilityScope{Include: []string{"advance"}},
			},
		},
	}
}

// RegisterTypes is a no-op — the §2 types are registered in RegisterCoreTypes.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "maintain-peer":
		return h.handleMaintainPeer(ctx, req)
	case "release-peer":
		return h.handleReleasePeer(ctx, req)
	case "status":
		return h.handleStatus(ctx, req)
	case "close":
		return h.handleClose(ctx, req)
	case "observe-address":
		return h.handleObserveAddress(ctx, req)
	case "check-reachability":
		return h.handleCheckReachability(ctx, req)
	case "reconnect":
		return h.handleReconnect(ctx, req)
	case "restore-subscriptions":
		return h.handleRestoreSubscriptions(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"network handler does not support operation: "+req.Operation)
	}
}

// boundPeer returns the bound peer or nil.
func (h *Handler) boundPeer() *peer.Peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.p
}
