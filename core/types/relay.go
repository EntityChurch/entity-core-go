package types

// EXTENSION-RELAY v1.0 entity types per §3, §4.1, §4.2 (post Go pre-impl review;
// arch `54e5373` + `15b30d0`).
//
// Discipline carryover from REGISTRY + DISCOVERY cycles:
//
//  1. Base58 peer_id everywhere (V7 §1.5 multikey form, Ruling-1 generalizes).
//     `forward-request.destination` + `next_hop`, `store-entry.put_by`,
//     `forward-result.next_hop`, and the `{relay_peer_id}` path segment in
//     §4.1 advertise all carry Base58 strings. The reflected `string`
//     fields get `system/peer-id` overrides in core.go.
//  2. The `envelope_inner` ref (§3.1, §3.2) is carried IN the data field as
//     a bare system/hash, NOT as a separate refs block. The §3.1 / §3.2
//     `refs:` notation maps to V7 §5.2 / §975 refless target-matching in
//     this cohort — same pattern REGISTRY (binding signature target),
//     DISCOVERY (decision.grant), and PUBLISHED-ROOT all use. The actual
//     inner-envelope ENTITY rides in the V7 envelope's `included` set
//     keyed by EnvelopeInner; the handler resolves it via
//     hctx.Included[EnvelopeInner]. (Cohort byte-equality at R5: pin
//     `envelope_inner` as a top-level data field name.) Signatures stay
//     refless via V7 §5.2 invariant-pointer (§3.0).
//  3. Flat result envelopes per cohort discipline #3 — `forward-result` /
//     `put-result` / `poll-result` are flat entity types, NOT wrapped under
//     `system/protocol/status` (Ruling-3 generalizes). All three slugs pinned
//     here at R1 to head off Rust + Py picking three different names.
//  4. Default-grant the self-poll cap on first install per §5.5 +
//     [[feedback_dont_drop_default_grants_implement_them]] — wired at peer-
//     builder seed-policy time (R3 scope), constant CapRelayPoll defined
//     here.
//  5. Mode A + Mode C entity types are NOT defined here — §3.3 / §3.4 named
//     them for forward-compat but the normative spec text is deferred
//     (§11.1, §11.1a). Adding empty types now would silently make Mode-A/C
//     wire claims appear, which the cohort discipline forbids — leave them
//     out until the deferral lifts.
//
// R2 wires the handler (`:forward`, `:put`, `:poll`, `:advertise`).
// R3 wires the §3.1.1 terminal-vs-intermediate dispatch shape, §3.2 put_by
// authentication check, §5.5 self-poll default grant install, and §6.2.1
// Mode-F → Mode-S fallback path.

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// -----------------------------------------------------------------------
// Entity type slugs (§3 + §4.2) — pinned at R1.
// -----------------------------------------------------------------------

const (
	TypeRelayForwardRequest = "system/relay/forward-request"
	TypeRelayStoreEntry     = "system/relay/store-entry"
	TypeRelayAdvertise      = "system/relay/advertise"

	TypeRelayForwardResult = "system/relay/forward-result"
	TypeRelayPutResult     = "system/relay/put-result"
	TypeRelayPollRequest   = "system/relay/poll-request"
	TypeRelayPollResult    = "system/relay/poll-result"

	// TypeRelayAdvertiseLimits is the slug for the §4.1 advertise.limits
	// sub-map. Named so the type registry can resolve AdvertiseLimits when
	// reflecting AdvertiseData (same pattern as system/capability/path-scope
	// for nested CapabilityScope). Wire shape is unchanged — still a plain
	// CBOR map under `limits`.
	TypeRelayAdvertiseLimits = "system/relay/advertise-limits"

	// TypePeerInboxRelay is the §3.5 MX-equivalent declaration (folded into
	// RELAY v1.0 with the R6/R7 cohort findings at arch faf3fa9). Authored
	// and signed by the declaring peer; served always-on by REGISTRY (and
	// secondary holders); MUST be V7 §5.2 signature-verified against the
	// resolved peer-id by any resolver. Closes the v1.0 Q2 gap (which-
	// relay-holds-my-mail).
	TypePeerInboxRelay = "system/peer/inbox-relay"

	// TypeInboxRelayEntry is the slug for a single (relay, namespace,
	// priority) row inside InboxRelayData.Relays — needed so reflection
	// can resolve the nested InboxRelayEntry struct (same pattern as
	// AdvertiseLimits → TypeRelayAdvertiseLimits).
	TypeInboxRelayEntry = "system/peer/inbox-relay-entry"
)

// -----------------------------------------------------------------------
// Mode identifiers (§1, §4.1) — v1 implements F + S; A + C named for
// forward-compat but their entity types are NOT defined (§11.1, §11.1a).
// -----------------------------------------------------------------------

const (
	RelayModeForward   = "F"
	RelayModeStorePoll = "S"
	// RelayModeAggregate / RelayModeCircuit deferred — DO NOT add string
	// constants until the modes land normatively (would create the appearance
	// of cohort agreement on a name the spec hasn't ratified).
)

// -----------------------------------------------------------------------
// Operation result status values (§4.2).
// -----------------------------------------------------------------------

const (
	// ForwardResult.Status values (§4.2 forward-result).
	ForwardStatusForwarded      = "forwarded"
	ForwardStatusQueuedFallback = "queued-fallback"
	ForwardStatusRejected       = "rejected"

	// PutResult.Status value (§4.2 put-result) — always "stored" in v1.
	PutStatusStored = "stored"
)

// -----------------------------------------------------------------------
// Per-mode caps (§5.2) — names pinned for cohort grant-config byte-equality.
// -----------------------------------------------------------------------

const (
	CapRelayForward   = "system/capability/relay-forward"
	CapRelayPut       = "system/capability/relay-put"
	CapRelayPoll      = "system/capability/relay-poll"
	CapRelayAdvertise = "system/capability/relay-advertise"
	// CapRelaySubscribe deferred with Mode A — see §5.2.
)

// -----------------------------------------------------------------------
// RELAY-domain error codes (§4.3) — V7 floor codes (capability_denied/403,
// payload_too_large/413) are reused, NOT redefined here. Relay-owned codes
// are domain-scoped per V7 §3.3 (same posture as DISCOVERY-owned
// discovery_scan_overflow).
// -----------------------------------------------------------------------

const (
	RelayErrTTLExhausted      = "ttl_exhausted"       // 400, forward
	RelayErrNoRoute           = "no_route"            // 502, forward
	RelayErrRateLimited       = "rate_limited"        // 429, forward
	RelayErrNamespaceInvalid  = "namespace_invalid"   // 400, put + poll
	RelayErrNamespaceNotFound = "namespace_not_found" // 404, poll (provisioning-required deployments only; empty != not-found per §4.2)
	RelayErrStorageFull       = "storage_full"        // 507, put
	RelayErrExpiredOnArrival  = "expired_on_arrival"  // 400, put (creation-side dead-on-arrival per §4.3 — NOT a 410 Gone)
	RelayErrPutByMismatch     = "put_by_mismatch"     // 400, put — new in post-Go-review absorption; see §3.2 + §4.3
	RelayErrNoInboxRelay      = "no_inbox_relay"      // 502, forward — §3.5 + §6.2.1 (R6/R7 cohort fold at arch faf3fa9): destination unreachable AND declared no inbox-relay AND default convention not usable; never a silent drop.
)

// -----------------------------------------------------------------------
// §3.1 — system/relay/forward-request
// -----------------------------------------------------------------------

// ForwardRequestData is the data payload for system/relay/forward-request
// per §3.1.
//
//   - Destination: terminal recipient (Base58 peer_id per §3.0).
//   - Route: optional source-routed path (PROPOSAL-RELAY-SOURCE-ROUTED-
//     MULTIHOP §2.1). When present and non-empty, lists the remaining
//     relay hops in order, ending at Destination — the originator's
//     forward path. Empty/nil == single-hop (use NextHop). At each hop
//     the relay pops Route[0] as the next hop and forwards Route[1:]
//     with ttl-1. omitempty drops it when nil to preserve byte-equality
//     with single-hop senders.
//   - NextHop: single-hop shorthand / resolver output (Base58 peer_id).
//     When Route is present and non-empty, NextHop MUST equal Route[0]
//     (proposal §2.1); when Route is absent, NextHop alone names the
//     single hop. Empty string == null; omitempty drops it.
//   - TTLHops: relay-transport hop budget; decremented per hop; reject
//     (fail-closed) at 0 on receipt (§3.1 + §4.2 + §4.3). TTL is the
//     loop bound — MUST be ≥ len(Route) for the route to complete.
//   - EnvelopeInner: bare system/hash of the inner envelope (V7 §5.2
//     refless target-matching). The §3.1 spec shows this under a `refs:`
//     block, but the Go codebase + the REGISTRY/DISCOVERY/PUBLISHED-ROOT
//     pattern carry such pointers IN the data field as bare hashes — the
//     "refs:" notation maps to V7 §5.2 target-matching in this cohort.
//     The actual inner-envelope ENTITY rides in the V7 envelope's
//     `included` set keyed by EnvelopeInner; the handler resolves it via
//     hctx.Included[EnvelopeInner].
type ForwardRequestData struct {
	Destination   string    `cbor:"destination"`
	Route         []string  `cbor:"route,omitempty"`
	NextHop       string    `cbor:"next_hop,omitempty"`
	TTLHops       uint32    `cbor:"ttl_hops"`
	EnvelopeInner hash.Hash `cbor:"envelope_inner"`
}

func (d ForwardRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRelayForwardRequest, cbor.RawMessage(raw))
}

func ForwardRequestDataFromEntity(e entity.Entity) (ForwardRequestData, error) {
	var d ForwardRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ForwardRequestData{}, err
	}
	return d, nil
}

// -----------------------------------------------------------------------
// §3.2 — system/relay/store-entry
// -----------------------------------------------------------------------

// StoreEntryData is the data payload for system/relay/store-entry per §3.2.
//
//   - Namespace: where the receiver polls — peer-local path string. The §6.2.1
//     fallback convention pins Namespace == destination peer_id (the Mode-F →
//     Mode-S fallback rendezvous; always, no per-relay override in v1 post-Go-
//     review).
//   - ExpiresAt: integer ms since epoch; 0 == null (omitempty drops). On :put
//     a past ExpiresAt MUST be rejected with `expired_on_arrival`/400 (§4.3).
//   - PutBy: Base58 peer_id of the peer that placed this entry. On a wire
//     :put, the relay MUST verify PutBy == authenticated caller and reject
//     mismatches with `put_by_mismatch`/400 (§3.2 + §4.3). PutBy is
//     placement-identity, NOT authorship — the §6.2.1 fallback path is the
//     proof: there PutBy == forwarding relay, but authorship is the origin's
//     inner-envelope V7 §5.2 signature. Pollers MUST verify authorship from
//     the inner envelope, never from PutBy.
//
// EnvelopeInner is the bare system/hash of the inner envelope; same V7 §5.2
// refless target-matching pattern as ForwardRequestData (see that struct's
// doc for the reasoning). The inner envelope ENTITY rides in the V7
// envelope's `included` set keyed by this hash.
type StoreEntryData struct {
	Namespace     string    `cbor:"namespace"`
	ExpiresAt     uint64    `cbor:"expires_at,omitempty"`
	PutBy         string    `cbor:"put_by"`
	EnvelopeInner hash.Hash `cbor:"envelope_inner"`
}

func (d StoreEntryData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRelayStoreEntry, cbor.RawMessage(raw))
}

func StoreEntryDataFromEntity(e entity.Entity) (StoreEntryData, error) {
	var d StoreEntryData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return StoreEntryData{}, err
	}
	return d, nil
}

// -----------------------------------------------------------------------
// §4.1 — system/relay/advertise
// -----------------------------------------------------------------------

// AdvertiseLimits is the §4.1 limits sub-map. All fields optional (omitempty
// drops zero values); when all are zero, encodes as an empty CBOR map. The
// advertise entity MUST carry a `limits` field — its sub-fields are the
// optional bits.
type AdvertiseLimits struct {
	MaxEnvelopeSize  uint64 `cbor:"max_envelope_size,omitempty"`
	MaxStorageBytes  uint64 `cbor:"max_storage_bytes,omitempty"`
	ForwardRateLimit uint32 `cbor:"forward_rate_limit,omitempty"`
}

// AdvertiseData is the data payload for system/relay/advertise per §4.1
// (post-Go-review: inbox_namespace dropped — Q2 in the absorption).
//
//   - Modes: ["F"|"S"]; future-compat "A"/"C" when those modes land.
//   - Endpoints: opaque per-entry — "dial-able endpoint per NETWORK §6.5".
//     Modeled as []cbor.RawMessage so backends can carry whatever transport-
//     profile shape NETWORK §6.5 specifies for the chosen wire (tcp / ws /
//     http-poll / etc.) without RELAY mandating a single envelope.
//   - Limits: §4.1 limits sub-map (all sub-fields optional).
//   - CapsRequired: cap paths the caller must hold (e.g. CapRelayForward,
//     CapRelayPut, etc.). Spec types this as `<cap_path>` strings.
//   - ExpiresAt: integer ms since epoch; 0 == null (omitempty drops).
//
// Stored at RelayAdvertisePath(relay_peer_id); signed by relay_peer_id per
// V7 §5.2 (invariant-pointer reachable at system/signature/{hex(hash)}); NO
// refs:{signature} block (§4.1 last paragraph + §3.0).
type AdvertiseData struct {
	Modes        []string          `cbor:"modes"`
	Endpoints    []cbor.RawMessage `cbor:"endpoints"`
	Limits       AdvertiseLimits   `cbor:"limits"`
	CapsRequired []string          `cbor:"caps_required"`
	ExpiresAt    uint64            `cbor:"expires_at,omitempty"`
}

func (d AdvertiseData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRelayAdvertise, cbor.RawMessage(raw))
}

func AdvertiseDataFromEntity(e entity.Entity) (AdvertiseData, error) {
	var d AdvertiseData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AdvertiseData{}, err
	}
	return d, nil
}

// -----------------------------------------------------------------------
// §4.2 — flat result envelopes
// -----------------------------------------------------------------------

// ForwardResultData is the flat result entity for system/relay:forward
// (§4.2). Flat per cohort discipline #3 — NOT wrapped in
// system/protocol/status.
//
//   - Status: one of ForwardStatusForwarded / ForwardStatusQueuedFallback /
//     ForwardStatusRejected.
//   - NextHop: hop actually used when Status == forwarded (Base58 peer_id).
//     Empty == null (omitempty); applies to queued-fallback / rejected.
//   - StoredAt: namespace path when Status == queued-fallback (§6.2.1 — the
//     fallback rendezvous is always RelayStorePath(destination_peer_id, ...)
//     in v1, no per-relay override). Empty == null on forwarded / rejected.
type ForwardResultData struct {
	Status   string `cbor:"status"`
	NextHop  string `cbor:"next_hop,omitempty"`
	StoredAt string `cbor:"stored_at,omitempty"`
}

func (d ForwardResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRelayForwardResult, cbor.RawMessage(raw))
}

func ForwardResultDataFromEntity(e entity.Entity) (ForwardResultData, error) {
	var d ForwardResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ForwardResultData{}, err
	}
	return d, nil
}

// PutResultData is the flat result entity for system/relay:put (§4.2).
//
//   - Status: always PutStatusStored ("stored") in v1.
//   - StoredAt: the canonical path RelayStorePath(namespace, EntryHash).
//   - EntryHash: hash of the stored store-entry entity.
//   - ExpiresAt: integer ms since epoch; 0 == null (omitempty drops).
type PutResultData struct {
	Status    string    `cbor:"status"`
	StoredAt  string    `cbor:"stored_at"`
	EntryHash hash.Hash `cbor:"entry_hash"`
	ExpiresAt uint64    `cbor:"expires_at,omitempty"`
}

func (d PutResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRelayPutResult, cbor.RawMessage(raw))
}

func PutResultDataFromEntity(e entity.Entity) (PutResultData, error) {
	var d PutResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PutResultData{}, err
	}
	return d, nil
}

// PollRequestData is the request entity for system/relay:poll (§4.2).
//
//   - Namespace: the namespace path the caller is polling.
//   - Since: opaque relay-owned cursor; nil/absent == fresh start (omitempty
//     drops). On the first poll the caller passes Since=nil; on subsequent
//     polls the caller passes back the cursor from the prior PollResult
//     verbatim. Typed cbor.RawMessage so cross-impl interop works
//     regardless of the relay's cursor encoding (Go: bstr seq; Rust: same;
//     Python: text path).
//   - Limit: optional cap on entries returned; 0 == null (omitempty); the
//     relay applies a backend default on absence.
type PollRequestData struct {
	Namespace string          `cbor:"namespace"`
	Since     cbor.RawMessage `cbor:"since,omitempty"`
	Limit     uint64          `cbor:"limit,omitempty"`
}

func (d PollRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRelayPollRequest, cbor.RawMessage(raw))
}

func PollRequestDataFromEntity(e entity.Entity) (PollRequestData, error) {
	var d PollRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PollRequestData{}, err
	}
	return d, nil
}

// PollResultData is the flat result entity for system/relay:poll (§4.2).
//
//   - Entries: hashes of stored store-entry entities (POINTERS, not inline
//     bytes — the §4.2 two-hop pointer discipline + NETWORK §6.5.3.1). An
//     empty list is the canonical "authorized but empty" shape (§4.2 +
//     post-landing finding #1: namespace_not_found/404 NOT applicable to
//     authorized-but-empty pollers).
//   - Cursor: opaque relay-owned token. Typed cbor.RawMessage on this side
//     because each cohort impl picks its own representation — Go emits an
//     8-byte BE byte string (monotonic seq); Rust the same; Python emits a
//     CBOR text string keyed on tree path. The cohort agreement (R6/R7
//     ratification) is "cursor is opaque; pass back verbatim on the next
//     :poll." cbor.RawMessage preserves whatever CBOR shape the relay
//     emitted; PollRequestData.Since re-emits it verbatim — true cross-
//     impl interop without forcing all impls onto one wire shape.
//   - HasMore: true when more entries are available past Cursor.
type PollResultData struct {
	Entries []hash.Hash     `cbor:"entries"`
	Cursor  cbor.RawMessage `cbor:"cursor"`
	HasMore bool            `cbor:"has_more"`
}

func (d PollResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRelayPollResult, cbor.RawMessage(raw))
}

func PollResultDataFromEntity(e entity.Entity) (PollResultData, error) {
	var d PollResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PollResultData{}, err
	}
	return d, nil
}

// -----------------------------------------------------------------------
// Storage paths (§3.2, §4.1).
// -----------------------------------------------------------------------

// RelayStorePath returns the canonical Mode-S storage path per §3.2:
//
//	system/relay/store/{namespace}/{entry_hash_hex}
//
// `entry_hash_hex` is the lowercase-hex content_hash of the store-entry
// entity (per the standard {hash_hex} convention used by REGISTRY /
// DISCOVERY). Consumers poll system/relay:poll {namespace}; the relay
// returns enumerated entry hashes and the consumer fetches each by hash.
func RelayStorePath(namespace string, entryHash hash.Hash) string {
	return "system/relay/store/" + namespace + "/" + PeerIdentityHashHex(entryHash)
}

// RelayStorePrefix returns the per-namespace Mode-S prefix per §3.2:
//
//	system/relay/store/{namespace}/
//
// The relay handler's :poll enumerates entries under this prefix.
func RelayStorePrefix(namespace string) string {
	return "system/relay/store/" + namespace + "/"
}

// RelayInnerPath returns the canonical Mode-S inner-envelope tree path per
// §3.2 + RULING-RELAY-RECEIVE-SIDE-FETCH-SURFACE:
//
//	system/relay/store/{namespace}/inner/{inner_hash_hex}
//
// Nested under the same namespace subtree as the store-entry so a single
// namespace-scoped tree-read cap covers both fetches. Tree-binding is
// path→hash (PRIMER #1); the inner's bytes still live once in the content
// store, so dedup is preserved across namespaces.
func RelayInnerPath(namespace string, innerHash hash.Hash) string {
	return "system/relay/store/" + namespace + "/inner/" + PeerIdentityHashHex(innerHash)
}

// RelayInnerPrefix returns the per-namespace inner-envelope subtree prefix:
//
//	system/relay/store/{namespace}/inner/
//
// Used by handlePoll's listing filter — paths under this prefix are inner
// envelopes (reachable via store-entry envelope_inner), NOT polled entries.
func RelayInnerPrefix(namespace string) string {
	return "system/relay/store/" + namespace + "/inner/"
}

// RelayAdvertisePath returns the canonical §4.1 advertise entity path:
//
//	system/relay/advertise/{relay_peer_id}
//
// The advertise entity at this path MUST be signed by relay_peer_id per
// V7 §5.2 (reachable at system/signature/{hex(content_hash)}). NO
// refs:{signature} block.
func RelayAdvertisePath(relayPeerID string) string {
	return "system/relay/advertise/" + relayPeerID
}

// -----------------------------------------------------------------------
// §3.5 — system/peer/inbox-relay (MX-equivalent declaration)
// -----------------------------------------------------------------------

// InboxRelayEntry is one row in InboxRelayData.Relays — a single
// (relay, namespace, priority) tuple. Lower priority is preferred
// (MX-priority convention; backups higher).
type InboxRelayEntry struct {
	Relay     string `cbor:"relay"`
	Namespace string `cbor:"namespace"`
	Priority  uint32 `cbor:"priority"`
}

// InboxRelayData is the data payload for system/peer/inbox-relay per
// §3.5 (MX-equivalent declaration; cohort R6/R7 fold at arch faf3fa9).
//
// A peer publishes a signed declaration of WHERE its mail is stored when
// it is unreachable — the DNS-MX analog. This gives §6.2.1 Mode-S
// fallback a resolvable, self-certifying target, closing v1.0 Q2.
//
//   - Relays: list of (relay, namespace, priority). Resolvers MUST try
//     in ascending priority order.
//   - ExpiresAt: integer ms since epoch; 0 == null (omitempty); null
//     means until superseded.
//
// AUTHORED + SIGNED by the declaring peer per V7 §5.2 — signature
// reachable at system/signature/{hex(content_hash)}. NO refs:{signature}
// block (§3.0 discipline). SERVED always-on by REGISTRY (primary holder
// per §3.5); secondary holders may serve too. A resolver MUST verify the
// signature against the resolved peer_id and reject (fail-closed) on
// mismatch — the forged-redirection defense.
type InboxRelayData struct {
	Relays    []InboxRelayEntry `cbor:"relays"`
	ExpiresAt uint64            `cbor:"expires_at,omitempty"`
}

func (d InboxRelayData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeerInboxRelay, cbor.RawMessage(raw))
}

func InboxRelayDataFromEntity(e entity.Entity) (InboxRelayData, error) {
	var d InboxRelayData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return InboxRelayData{}, err
	}
	return d, nil
}

// InboxRelayStoragePath returns the canonical local storage path for a
// peer's published inbox-relay declaration:
//
//	system/peer/inbox-relay/{peer_id}
//
// Authoritative origin = peer's own tree; primary serving home = REGISTRY
// (§3.5). The peer's own tree is NOT the fallback-path source (it's
// offline exactly when needed).
func InboxRelayStoragePath(peerID string) string {
	return "system/peer/inbox-relay/" + peerID
}
