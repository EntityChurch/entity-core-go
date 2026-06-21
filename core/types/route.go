package types

// EXTENSION-ROUTE v1 — the routing-table storage plane per
// `PROPOSAL-EXTENSION-ROUTE.md` (arch DRAFT; reframed as
// user-confirmed — storage plane only, no producer).
//
// ROUTE stores routes; RELAY reads them when no source route is given;
// the peer / DISCOVERY / GOSSIP produce them. ROUTE itself owns no
// resolver registry and computes nothing — it is the table-shaped
// storage that downstream layers plug into.
//
// v1 conformance floor (proposal §7):
//   1. The system/route entity (§2) — shape, tree-bound at
//      `system/route/{content_hash_hex}`, signature, `route-configure`
//      cap.
//   2. The documented match relay applies (§3) — exact + `*` default,
//      lowest metric, expiry-skip, no-match → no_route/502.
//
// Deferred: route *production* (gossip-learned, DHT, link-state); the
// `resolve_next_hop` computed-routing seam (§4); prefix/topological
// aggregation; rich metric semantics.

import (
	"encoding/hex"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// TypeRoute is the entity type slug for a single routing-table entry.
const TypeRoute = "system/route"

// RouteAction is the per-route disposition relay applies when a route
// matches the destination.
const (
	RouteActionDeliver = "deliver" // terminal hop — deliver locally
	RouteActionForward = "forward" // forward one hop to `via`
)

// RouteMatchDefault is the `*`-form match expressing the default route
// (lowest-precedence catch-all). Per proposal §3, exact match outranks
// the default-route token on ties (longest-match-wins, degenerate over a
// non-hierarchical peer-id space).
const RouteMatchDefault = "*"

// RouteData is the data payload for a `system/route` entity per
// PROPOSAL-EXTENSION-ROUTE §2.
//
//   - Match: the destination this route covers — a Base58 peer-id, or
//     `*` for the default route.
//   - Action: `"deliver"` (terminal — deliver locally) or `"forward"`
//     (one-hop intermediate — forward to Via).
//   - Via: REQUIRED iff Action == "forward"; the next-hop peer-id. Empty
//     string == null; omitempty drops it.
//   - Metric: lower wins on ties when multiple routes match the same
//     destination. 0 == null/unspecified (proposal §2 "null = 0").
//   - ExpiresAt: ms since epoch; 0 == null (until superseded). A route
//     whose ExpiresAt is already past at match-time MUST be skipped
//     (proposal §3 — expired routes are silently filtered, not surfaced
//     as no_route).
//
// Cross-field invariant (relay or producer enforced at write time):
//   - Action == "deliver" → Via MUST be empty (the local relay IS the
//     terminal).
//   - Action == "forward" → Via MUST be non-empty (there's nowhere to
//     forward to).
//
// The peer-id-shape override for Match/Via is registered centrally so
// the EntityNative type system surfaces them as system/peer-id (same
// Ruling-1 pattern as REGISTRY target_peer_id + RELAY destination).
type RouteData struct {
	Match     string `cbor:"match"`
	Action    string `cbor:"action"`
	Via       string `cbor:"via,omitempty"`
	Metric    uint32 `cbor:"metric,omitempty"`
	ExpiresAt uint64 `cbor:"expires_at,omitempty"`
}

// ToEntity ECF-encodes the route data into a system/route entity.
func (d RouteData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoute, cbor.RawMessage(raw))
}

// RouteDataFromEntity decodes a system/route entity's data field.
func RouteDataFromEntity(e entity.Entity) (RouteData, error) {
	var d RouteData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RouteData{}, err
	}
	return d, nil
}

// RoutePath returns the canonical tree path for a route entity per
// PROPOSAL-EXTENSION-ROUTE §2: `system/route/{content_hash_hex}`. The id
// segment is the lowercase hex of the route entity's canonical hash
// bytes (algorithm byte + effective digest length), same shape as
// RelayStorePath / PeerIdentityHashHex. Operators publishing the same
// logical route twice dedupe at the path level.
//
// Use `routeHash.Bytes()` not `routeHash.Digest[:]` — the latter is
// padded to MaxDigestSize and would produce a non-canonical 130-char
// path with trailing zeros under SHA-256 (cross-impl trap #1 noted in
// the SRCROUTE/ROUTE cohort handoff).
func RoutePath(routeHash hash.Hash) string {
	return TypeRoute + "/" + hex.EncodeToString(routeHash.Bytes())
}

// RoutePrefix is the listing prefix for the route subtree (used by
// RELAY's table-read resolver to enumerate the local route table).
// Trailing slash is intentional — matches LocationIndex.List semantics
// (returns every leaf under the prefix).
const RoutePrefix = TypeRoute + "/"

// RELAY-domain error codes for ROUTE config writes (proposal §5).
const (
	// RouteErrInvalidAction is returned by a config write that violates
	// the action/via cross-field invariant (deliver-with-via, or
	// forward-without-via). 400.
	RouteErrInvalidAction = "invalid_route_action"
)

// Capability-pattern slug. `route-configure` guards writes to the
// system/route subtree (proposal §5). Reads need no extra caller cap —
// relay's local read of substrate state is internal.
const CapabilityRouteConfigure = "route-configure"
