package types

import (
	"fmt"
	"math"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

// Network extension types — minimal subset for remote execute infrastructure.
// Full network handler types will be added when ext/network/ is implemented.

const (
	// TypePeerTransportHTTPPoll is the §6.5.3 / §6 discoverable profile
	// for the http-poll passive-lookup transport.
	TypePeerTransportHTTPPoll = "system/peer/transport/http-poll"
	// TypePeerTransportTCP is the §4.1 discoverable profile for TCP —
	// the real default live transport across all three impls. Replaced
	// the legacy flat system/network/transport-address shape in the
	// Chunk C unison cutover. No migration shim.
	TypePeerTransportTCP = "system/peer/transport/tcp"
	// TypePeerTransportHTTP is the §5 / §4.x discoverable profile for
	// the http live transport (POST EXECUTE over HTTP). Half-duplex,
	// no server-push. Endpoint URL pins the full POST target.
	// Per Chunk D.
	TypePeerTransportHTTP = "system/peer/transport/http"
	// TypePeerTransportWebSocket is the §6.5.2b discoverable profile
	// for the WebSocket live transport. Full-duplex, server-push
	// capable per §6.5.1b. Reuses the V7 §1.6 4-byte length prefix
	// per binary WS message (§6.5.2c L864 — the explicit V7 v7.13
	// blessing for this profile; opposite of http-live which forbids
	// the prefix because HTTP frames the body natively). Endpoint
	// URL pins the ws:// or wss:// target.
	TypePeerTransportWebSocket = "system/peer/transport/websocket"
)

// supported_ops vocabulary per EXTENSION-NETWORK §6.5 D-13 (closed enum).
// Values pin distinct verification anchors: EXECUTE = live request/response;
// TREE_GET = hash-chain-from-root binding lookup; CONTENT_GET = content-
// addressed byte lookup (hash); MANIFEST_GET = signed-pointer/manifest
// lookup (signature). Reserved: SUBSCRIBE (push-capability is currently
// implicit in transport duplexity; reserved for future field-level
// discrimination). Live profiles advertise [OpExecute]; http-poll
// advertises any non-empty subset of {TREE_GET, CONTENT_GET, MANIFEST_GET}.
// Descriptive only — MUST NOT be derived to grant authority (§7).
const (
	OpExecute     = "EXECUTE"
	OpTreeGet     = "TREE_GET"
	OpContentGet  = "CONTENT_GET"
	OpManifestGet = "MANIFEST_GET"
	OpSubscribe   = "SUBSCRIBE" // reserved, deferred
)

// HTTPPollProfileData is the data payload for system/peer/transport/http-poll
// per EXTENSION-NETWORK §6.5.3. A publisher peer using this profile has
// published its tree + content to a static HTTP origin; consumers fetch
// inline (Mechanism A — bytes-on-wire ARE entity-encoded, hash-verified
// directly, NO BRIDGE-HTTP involvement).
//
// Profile entities live at system/peer/transport/{peer_id}/{profile-id};
// a peer MAY publish multiple http-poll profiles (e.g., primary + cdn-mirror).
//
// The Endpoint block matches the shared TransportEndpoint shape — same four
// fields the CDN snapshot manifest carries — so a consumer reaches for the
// same URL-construction helpers (BuildContentURL / BuildTreeLeafURL)
// regardless of which surface advertised the prefix.
type HTTPPollProfileData struct {
	PeerID         string            `cbor:"peer_id"`
	TransportType  string            `cbor:"transport_type"` // always "http-poll"
	Endpoint       TransportEndpoint `cbor:"endpoint"`
	SupportedOps   []string          `cbor:"supported_ops"` // non-empty subset of {OpTreeGet, OpContentGet, OpManifestGet} per D-13
	Freshness      string            `cbor:"freshness,omitempty"`
	NonceRequired  bool              `cbor:"nonce_required"`
	CapFlow        string            `cbor:"cap_flow,omitempty"`         // typically "egress"
	PollIntervalMs uint64            `cbor:"poll_interval_ms,omitempty"` // informative
	SignedPointer  string            `cbor:"signed_pointer,omitempty"`   // canonical signed root path
	AdvertisedAt   uint64            `cbor:"advertised_at,omitempty"`    // wall-clock epoch ms (PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS D-3 — informational, NOT a selection key)
	Priority       *uint64           `cbor:"priority,omitempty"`         // Q1 (arch §8.9 / Round 3): DNS-SRV semantics — lower = preferred. Pointer-typed so nil (omitted on wire) is distinguishable from explicit 0. Defaults applied at sort time: nil + profile-id "primary" → 0, nil + others → 100.
}

func (d HTTPPollProfileData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeerTransportHTTPPoll, cbor.RawMessage(raw))
}

// HTTPPollProfileDataFromEntity decodes a system/peer/transport/http-poll
// entity. Per D-5 in PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS
// the data.transport_type MUST match the entity-type suffix ("http-poll");
// decoders MUST reject mismatch (fail closed).
func HTTPPollProfileDataFromEntity(e entity.Entity) (HTTPPollProfileData, error) {
	var d HTTPPollProfileData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HTTPPollProfileData{}, err
	}
	if d.TransportType != "http-poll" {
		return HTTPPollProfileData{}, fmt.Errorf(
			"transport_type mismatch: entity type %q carries data.transport_type %q (D-5)",
			e.Type, d.TransportType)
	}
	return d, nil
}

// TransportEndpointURL is the §4.1/§4.2/§5 endpoint shape for live
// transports — a single `url` field encoding scheme + host + port
// (e.g. `tcp://host:port`, `wss://host/ws`, `https://host/entity`).
// Per D-14 (cohort feedback absorbed into the proposal):
// live profiles use this single-field shape; http-poll keeps its
// prefix-based TransportEndpoint above.
type TransportEndpointURL struct {
	URL string `cbor:"url"`
}

// TCPProfileData is the §4.1 discoverable profile for the default live
// TCP transport. Documents what all three impls already do (every peer
// listens TCP); the profile entity makes the listener address
// discoverable per the published-tree pattern + closes EXTENSION-NETWORK
// §6.5's TCP-omission gap.
//
// Lives at system/peer/transport/{peer_id}/{profile-id}.
type TCPProfileData struct {
	PeerID        string               `cbor:"peer_id"`
	TransportType string               `cbor:"transport_type"` // always "tcp"
	Endpoint      TransportEndpointURL `cbor:"endpoint"`
	SupportedOps  []string             `cbor:"supported_ops"` // typically [OpExecute]
	Freshness     string               `cbor:"freshness,omitempty"`
	NonceRequired bool                 `cbor:"nonce_required"`
	CapFlow       string               `cbor:"cap_flow,omitempty"`      // typically "both"
	AdvertisedAt  uint64               `cbor:"advertised_at,omitempty"` // wall-clock epoch ms (D-3)
	Priority      *uint64              `cbor:"priority,omitempty"`      // Q1 / arch §8.9 — DNS-SRV semantics; see HTTPPollProfileData.Priority.
}

// ToEntity creates a system/peer/transport/tcp entity.
func (d TCPProfileData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeerTransportTCP, cbor.RawMessage(raw))
}

// HTTPProfileData is the §5 / §4.x discoverable profile for the http
// live transport. Connector POSTs an EXECUTE envelope to endpoint.url;
// response body is the EXECUTE-RESPONSE envelope. Half-duplex, no
// server-push.
//
// Per the cohort handoff §10 (G1) the endpoint URL is the operator's
// choice — the profile carries the full URL the connector POSTs to,
// no path is reserved spec-side. supported_ops is [OpExecute] for the
// live transport per the D-13 split.
//
// Lives at system/peer/transport/{peer_id}/{profile-id}.
type HTTPProfileData struct {
	PeerID        string               `cbor:"peer_id"`
	TransportType string               `cbor:"transport_type"` // always "http"
	Endpoint      TransportEndpointURL `cbor:"endpoint"`       // url: "https://host:port/path"
	SupportedOps  []string             `cbor:"supported_ops"`  // [OpExecute]
	Freshness     string               `cbor:"freshness,omitempty"`
	NonceRequired bool                 `cbor:"nonce_required"`
	CapFlow       string               `cbor:"cap_flow,omitempty"`      // typically "both"
	AdvertisedAt  uint64               `cbor:"advertised_at,omitempty"` // wall-clock epoch ms (D-3)
	Priority      *uint64              `cbor:"priority,omitempty"`      // Q1 / arch §8.9 — DNS-SRV semantics; see HTTPPollProfileData.Priority.
}

// ToEntity creates a system/peer/transport/http entity.
func (d HTTPProfileData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeerTransportHTTP, cbor.RawMessage(raw))
}

// HTTPProfileDataFromEntity decodes a system/peer/transport/http entity.
// Per D-5 the data.transport_type MUST match the entity-type suffix
// ("http"); decoders MUST reject mismatch (fail closed).
func HTTPProfileDataFromEntity(e entity.Entity) (HTTPProfileData, error) {
	var d HTTPProfileData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HTTPProfileData{}, err
	}
	if d.TransportType != "http" {
		return HTTPProfileData{}, fmt.Errorf(
			"transport_type mismatch: entity type %q carries data.transport_type %q (D-5)",
			e.Type, d.TransportType)
	}
	return d, nil
}

// WebSocketProfileData is the §6.5.2b discoverable profile for the
// WebSocket live transport. Connector dials endpoint.url; after the
// HTTP Upgrade completes, the connection is a full-duplex stream of
// length-prefixed binary WS messages — one V7 §1.6 length-prefixed ECF
// envelope per binary message (§6.5.2c L864 blessing).
//
// Lives at system/peer/transport/{peer_id}/{profile-id}.
type WebSocketProfileData struct {
	PeerID        string               `cbor:"peer_id"`
	TransportType string               `cbor:"transport_type"` // always "websocket"
	Endpoint      TransportEndpointURL `cbor:"endpoint"`       // url: "ws://host:port/path" or "wss://..."
	SupportedOps  []string             `cbor:"supported_ops"`  // [OpExecute]
	Freshness     string               `cbor:"freshness,omitempty"`
	NonceRequired bool                 `cbor:"nonce_required"`
	CapFlow       string               `cbor:"cap_flow,omitempty"`      // typically "both"
	AdvertisedAt  uint64               `cbor:"advertised_at,omitempty"` // wall-clock epoch ms (D-3)
	Priority      *uint64              `cbor:"priority,omitempty"`      // Q1 / arch §8.9 — DNS-SRV semantics; see HTTPPollProfileData.Priority.
}

// ToEntity creates a system/peer/transport/websocket entity.
func (d WebSocketProfileData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeerTransportWebSocket, cbor.RawMessage(raw))
}

// WebSocketProfileDataFromEntity decodes a system/peer/transport/websocket
// entity. Per D-5 the data.transport_type MUST match the entity-type
// suffix ("websocket"); decoders MUST reject mismatch (fail closed).
func WebSocketProfileDataFromEntity(e entity.Entity) (WebSocketProfileData, error) {
	var d WebSocketProfileData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return WebSocketProfileData{}, err
	}
	if d.TransportType != "websocket" {
		return WebSocketProfileData{}, fmt.Errorf(
			"transport_type mismatch: entity type %q carries data.transport_type %q (D-5)",
			e.Type, d.TransportType)
	}
	return d, nil
}

// Keepalive / reconnect types — EXTENSION-NETWORK §2.2, §2.3, §5.2, §5.3
// (Amendment 12 rung 2: the suspect → disconnected escalation the §A3
// liveness floor requires; §12.1 makes the ping/pong exchange MUST).

const (
	// TypeNetworkKeepaliveConfig is the §2.3 keepalive parameter block.
	TypeNetworkKeepaliveConfig = "system/network/keepalive-config"
	// TypeNetworkBackoffConfig is the §2.2 reconnection backoff parameter
	// block. Consumed by the rung-3 maintain-peer reconnect lifecycle;
	// landed with rung 2 because the type shape is spec-pinned and cheap.
	TypeNetworkBackoffConfig = "system/network/backoff-config"
	// TypeNetworkPing is the §5.2 keepalive ping payload, sent as
	// EXECUTE system/protocol/connect operation "ping" (§5.1).
	TypeNetworkPing = "system/network/ping"
	// TypeNetworkPong is the §5.3 keepalive pong payload, returned in the
	// EXECUTE_RESPONSE to a ping.
	TypeNetworkPong = "system/network/pong"
)

// Keepalive defaults per §2.3 / §5.4 (exact values impl-defined per §12.4;
// Go ships the spec's documented defaults). The §B consumer latency envelope
// is interval_ms × max_missed + timeout_ms ≈ 100 s at these values.
const (
	DefaultKeepaliveIntervalMs uint64 = 30000
	DefaultKeepaliveTimeoutMs  uint64 = 10000
	DefaultKeepaliveMaxMissed  uint64 = 3
)

// Backoff defaults per §2.2.
const (
	DefaultBackoffMinMs    uint64 = 1000
	DefaultBackoffMaxMs    uint64 = 60000
	DefaultBackoffStrategy        = "exponential"
)

// KeepaliveConfigData is the system/network/keepalive-config payload (§2.3).
// All fields optional — pointer-typed so an absent field (nil, omitted on
// wire) is distinguishable from an explicit value; defaults apply at use
// time via the Effective* helpers.
type KeepaliveConfigData struct {
	// IntervalMs is the ping interval (default 30000).
	IntervalMs *uint64 `cbor:"interval_ms,omitempty"`
	// TimeoutMs is the pong timeout (default 10000).
	TimeoutMs *uint64 `cbor:"timeout_ms,omitempty"`
	// MaxMissed is the missed-pong count before failure (default 3).
	MaxMissed *uint64 `cbor:"max_missed,omitempty"`
}

// EffectiveIntervalMs returns interval_ms with the §2.3 default applied.
func (d KeepaliveConfigData) EffectiveIntervalMs() uint64 {
	if d.IntervalMs != nil {
		return *d.IntervalMs
	}
	return DefaultKeepaliveIntervalMs
}

// EffectiveTimeoutMs returns timeout_ms with the §2.3 default applied.
func (d KeepaliveConfigData) EffectiveTimeoutMs() uint64 {
	if d.TimeoutMs != nil {
		return *d.TimeoutMs
	}
	return DefaultKeepaliveTimeoutMs
}

// EffectiveMaxMissed returns max_missed with the §2.3 default applied.
func (d KeepaliveConfigData) EffectiveMaxMissed() uint64 {
	if d.MaxMissed != nil {
		return *d.MaxMissed
	}
	return DefaultKeepaliveMaxMissed
}

// ToEntity creates a system/network/keepalive-config entity.
func (d KeepaliveConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkKeepaliveConfig, cbor.RawMessage(raw))
}

// BackoffConfigData is the system/network/backoff-config payload (§2.2).
type BackoffConfigData struct {
	// MinMs is the minimum delay between reconnection attempts (default 1000).
	MinMs *uint64 `cbor:"min_ms,omitempty"`
	// MaxMs is the maximum delay (default 60000).
	MaxMs *uint64 `cbor:"max_ms,omitempty"`
	// Strategy is "exponential" (default), "linear", or "constant".
	Strategy string `cbor:"strategy,omitempty"`
	// MaxAttempts optionally bounds the retry loop by count: once this many
	// retries have FIRED, the relationship is abandoned. Unset ⇒ no bound.
	MaxAttempts *uint64 `cbor:"max_attempts,omitempty"`
	// MaxElapsedMs optionally bounds the retry loop by wall-clock: once this
	// long has passed since failing_since, the relationship is abandoned.
	// Unset ⇒ no bound.
	//
	// Both bounds are OPTIONAL and default to UNSET, which is retry-forever —
	// the normative behaviour, because a peer offline for a week and coming
	// back is the P2P norm and "give up after N" imports a client-server
	// assumption that does not hold here. They exist for callers who genuinely
	// know a relationship is disposable; they are not a recommended default.
	//
	// Exhaustion is NOT a fourth status: it terminates at `disconnected` with
	// reason `retry-exhausted` (the §3.13 enum is three-state, and `reason` is
	// the field that says why).
	MaxElapsedMs *uint64 `cbor:"max_elapsed_ms,omitempty"`
}

// EffectiveMinMs returns min_ms with the §2.2 default applied.
func (d BackoffConfigData) EffectiveMinMs() uint64 {
	if d.MinMs != nil {
		return *d.MinMs
	}
	return DefaultBackoffMinMs
}

// EffectiveMaxMs returns max_ms with the §2.2 default applied.
func (d BackoffConfigData) EffectiveMaxMs() uint64 {
	if d.MaxMs != nil {
		return *d.MaxMs
	}
	return DefaultBackoffMaxMs
}

// EffectiveStrategy returns strategy with the §2.2 default applied.
func (d BackoffConfigData) EffectiveStrategy() string {
	if d.Strategy != "" {
		return d.Strategy
	}
	return DefaultBackoffStrategy
}

// ToEntity creates a system/network/backoff-config entity.
func (d BackoffConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkBackoffConfig, cbor.RawMessage(raw))
}

// DelayMs returns the §2.2 delay before retry k, where k is 1-INDEXED: k=1 is
// the first retry after the failure, and DelayMs(0) is 0 (no retry, no wait).
//
//	constant     min
//	linear       min · k
//	exponential  min · 2^(k-1)
//
// all clamped to max (and max is raised to min when a config inverts them, so
// the returned delay is never below min). Arithmetic saturates rather than
// wrapping: a config with an absurd min cannot make a huge k produce a tiny
// delay.
func (d BackoffConfigData) DelayMs(k uint64) uint64 {
	if k == 0 {
		return 0
	}
	minMs := d.EffectiveMinMs()
	maxMs := d.EffectiveMaxMs()
	if maxMs < minMs {
		maxMs = minMs
	}
	var ms uint64
	switch d.EffectiveStrategy() {
	case "constant":
		ms = minMs
	case "linear":
		ms = saturatingMulU64(minMs, k)
	default: // "exponential"
		ms = minMs
		for i := uint64(1); i < k; i++ {
			if ms >= maxMs {
				break
			}
			ms = saturatingMulU64(ms, 2)
		}
	}
	if ms > maxMs {
		ms = maxMs
	}
	return ms
}

// RetryState is the §2.2 retry pacing for one failure episode, DERIVED from
// (failing_since, backoff config, now) — never stored. See DeriveRetryState.
type RetryState struct {
	// Attempt is how many retries have already FIRED this episode: 0 in the
	// interval between the failure and the first retry coming due.
	Attempt uint64
	// NextAttemptAt is when the next retry comes due, ms since epoch. Zero
	// when Exhausted — there is no next attempt.
	NextAttemptAt uint64
	// Exhausted reports that an OPTIONAL §2.2 bound (max_attempts /
	// max_elapsed_ms) has been reached and the relationship is abandoned.
	// Always false under the default config, which is retry-forever.
	//
	// Derived like everything else here, so "have we given up?" is a question
	// about elapsed time rather than a state someone has to remember to write.
	Exhausted bool
}

// DeriveRetryState computes the retry pacing for the failure episode that began
// at failingSince (ms since epoch), as of nowMs.
//
// This is the whole of the retry state machine, as one pure function. Nothing
// counts attempts, and nothing is written per attempt (§A4): the k-th retry is
// due at a fixed offset from failing_since, so "which retry are we on" is a
// question about elapsed time, answerable from a stamp the tree already holds.
// Two things fall out of that. Restart-hammering dies — a process that restarts
// beside a peer dead for a month re-derives a large Attempt and a max-length
// wait, where an in-memory counter would reset to 0 and redial in min_ms. And
// pacing converges: two peers reading the same failing_since agree on the
// schedule without exchanging retry state.
//
// The schedule, with elapsed = nowMs - failingSince:
//
//	elapsed_to(0) = 0
//	elapsed_to(k) = elapsed_to(k-1) + DelayMs(k)
//	Attempt       = max{ k : elapsed_to(k) <= elapsed }
//	NextAttemptAt = failingSince + elapsed_to(Attempt+1)
//
// The boundary is INCLUSIVE: at exactly elapsed_to(k) the k-th retry has fired.
//
// Worked example — the §2.2 defaults (exponential, min 1s, max 60s). Delays run
// 1s, 2s, 4s, 8s…; elapsed_to runs 1s, 3s, 7s, 15s…. At elapsed = 5s: two
// retries have fired (elapsed_to(2) = 3s <= 5s, elapsed_to(3) = 7s > 5s), so
// Attempt = 2 and the third comes due at failingSince + 7s.
//
// No jitter in v1 — the schedule is a deterministic function of its inputs,
// which is what makes it testable as a vector table and comparable across
// impls. Jitter, if it lands, is a later opt-in that perturbs the output here.
//
// failingSince == 0 means no episode (the `connected` write clears the stamp),
// and returns the zero RetryState. A degenerate config whose delay works out to
// 0 also returns Attempt 0 with NextAttemptAt == failingSince — always due,
// never counted — rather than looping forever counting instantaneous retries.
func (d BackoffConfigData) DeriveRetryState(failingSince, nowMs uint64) RetryState {
	if failingSince == 0 {
		return RetryState{}
	}
	var elapsed uint64
	if nowMs > failingSince {
		elapsed = nowMs - failingSince
	}
	st := d.derivePacing(failingSince, elapsed)

	// The OPTIONAL §2.2 bounds. Unset ⇒ retry-forever, so the default config
	// never takes this branch.
	if d.MaxAttempts != nil && st.Attempt >= *d.MaxAttempts {
		return RetryState{Attempt: st.Attempt, Exhausted: true}
	}
	if d.MaxElapsedMs != nil && elapsed >= *d.MaxElapsedMs {
		return RetryState{Attempt: st.Attempt, Exhausted: true}
	}
	return st
}

// derivePacing walks the schedule; see DeriveRetryState for the semantics.
func (d BackoffConfigData) derivePacing(failingSince, elapsed uint64) RetryState {

	// Walk the schedule. The delay sequence is non-decreasing and every
	// strategy plateaus (constant from k=1; linear and exponential once they
	// clamp at max), so as soon as two consecutive delays match, the rest of
	// the schedule is arithmetic and the tail closes in one step. Without that,
	// a peer dead for a month at a 60s cap would cost ~43k iterations here.
	var (
		attempt   uint64 // retries fired so far
		cum       uint64 // elapsed_to(attempt)
		prevDelay uint64
	)
	for k := uint64(1); ; k++ {
		delay := d.DelayMs(k)
		if delay == 0 {
			return RetryState{Attempt: attempt, NextAttemptAt: failingSince + cum}
		}
		if k > 1 && delay == prevDelay {
			// Plateaued: every remaining retry costs exactly `delay`, and
			// cum <= elapsed still holds (we would have returned otherwise).
			extra := (elapsed - cum) / delay
			attempt += extra
			cum = saturatingAddU64(cum, saturatingMulU64(extra, delay))
			return RetryState{
				Attempt:       attempt,
				NextAttemptAt: saturatingAddU64(failingSince, saturatingAddU64(cum, delay)),
			}
		}
		next := saturatingAddU64(cum, delay)
		if next > elapsed {
			return RetryState{
				Attempt:       attempt,
				NextAttemptAt: saturatingAddU64(failingSince, next),
			}
		}
		cum = next
		attempt = k
		prevDelay = delay
	}
}

func saturatingMulU64(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxUint64/b {
		return math.MaxUint64
	}
	return a * b
}

func saturatingAddU64(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// PingData is the system/network/ping payload (§5.2) — the params entity of
// the §5.1 keepalive EXECUTE (system/protocol/connect, operation "ping").
type PingData struct {
	// Timestamp is the sender's clock, ms since epoch.
	Timestamp uint64 `cbor:"timestamp"`
	// Sequence is the sender's monotonic ping sequence number.
	Sequence uint64 `cbor:"sequence"`
}

// ToEntity creates a system/network/ping entity.
func (d PingData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkPing, cbor.RawMessage(raw))
}

// PongData is the system/network/pong payload (§5.3) — the result entity of
// a keepalive ping. Timestamp and Sequence echo the ping; ServerTime is the
// responder's clock.
type PongData struct {
	Timestamp  uint64 `cbor:"timestamp"`
	Sequence   uint64 `cbor:"sequence"`
	ServerTime uint64 `cbor:"server_time"`
}

// ToEntity creates a system/network/pong entity.
func (d PongData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkPong, cbor.RawMessage(raw))
}

// PongDataFromEntity decodes a system/network/pong entity's data.
func PongDataFromEntity(e entity.Entity) (PongData, error) {
	var d PongData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PongData{}, err
	}
	return d, nil
}

// Network handler operation types — EXTENSION-NETWORK §2.1, §2.4–§2.9
// (Amendment 12 rung 3: the maintain-peer / release-peer / status / close
// surface the §4 operations exchange; §13 Types Installed).

const (
	// TypeNetworkMaintainRequest is the §2.1 maintain-peer input.
	TypeNetworkMaintainRequest = "system/network/maintain-request"
	// TypeNetworkMaintainResult is the §2.4 maintain-peer output.
	TypeNetworkMaintainResult = "system/network/maintain-result"
	// TypeNetworkReleaseRequest is the §2.5 release-peer input.
	TypeNetworkReleaseRequest = "system/network/release-request"
	// TypeNetworkReleaseResult is the §2.6 release-peer output.
	TypeNetworkReleaseResult = "system/network/release-result"
	// TypeNetworkStatus is the §2.7 status-operation output.
	TypeNetworkStatus = "system/network/status"
	// TypeNetworkPeerSummary is the §2.8 per-peer row inside §2.7 status.
	TypeNetworkPeerSummary = "system/network/peer-summary"
	// TypeNetworkCloseRequest is the §2.9 close input.
	TypeNetworkCloseRequest = "system/network/close-request"
)

// MaintainRequestData is the system/network/maintain-request payload (§2.1).
// reconnect and resubscribe are pointer-typed so an absent field (default
// true per spec) is distinguishable from an explicit false.
type MaintainRequestData struct {
	// PeerID is the remote peer to maintain a relationship with (Base58).
	PeerID string `cbor:"peer_id"`
	// Address is the optional initial dial address (e.g. "host:port").
	Address string `cbor:"address,omitempty"`
	// Reconnect enables auto-reconnect on disconnect (default true).
	Reconnect *bool `cbor:"reconnect,omitempty"`
	// Resubscribe enables subscription restoration on reconnect (default true).
	Resubscribe *bool `cbor:"resubscribe,omitempty"`
	// Keepalive overrides the §2.3 keepalive defaults.
	Keepalive *KeepaliveConfigData `cbor:"keepalive,omitempty"`
	// Backoff overrides the §2.2 reconnection backoff defaults.
	Backoff *BackoffConfigData `cbor:"backoff,omitempty"`
}

// ReconnectEnabled returns reconnect with the §2.1 default (true) applied.
func (d MaintainRequestData) ReconnectEnabled() bool {
	return d.Reconnect == nil || *d.Reconnect
}

// ResubscribeEnabled returns resubscribe with the §2.1 default (true) applied.
func (d MaintainRequestData) ResubscribeEnabled() bool {
	return d.Resubscribe == nil || *d.Resubscribe
}

// EffectiveBackoff returns the backoff config with §2.2 defaults for an
// absent block.
func (d MaintainRequestData) EffectiveBackoff() BackoffConfigData {
	if d.Backoff != nil {
		return *d.Backoff
	}
	return BackoffConfigData{}
}

// ToEntity creates a system/network/maintain-request entity.
func (d MaintainRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkMaintainRequest, cbor.RawMessage(raw))
}

// MaintainRequestDataFromEntity decodes a maintain-request entity's data.
func MaintainRequestDataFromEntity(e entity.Entity) (MaintainRequestData, error) {
	var d MaintainRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return MaintainRequestData{}, err
	}
	return d, nil
}

// MaintainResultData is the system/network/maintain-result payload (§2.4).
type MaintainResultData struct {
	PeerID string `cbor:"peer_id"`
	// SessionID identifies the maintenance session.
	SessionID string `cbor:"session_id"`
	// Subscriptions are the lifecycle-monitoring subscription IDs created.
	Subscriptions []string `cbor:"subscriptions,omitempty"`
	// ChainID is the process chain_id for the lifecycle continuation graph.
	ChainID string `cbor:"chain_id"`
}

// ToEntity creates a system/network/maintain-result entity.
func (d MaintainResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkMaintainResult, cbor.RawMessage(raw))
}

// MaintainResultDataFromEntity decodes a maintain-result entity's data.
func MaintainResultDataFromEntity(e entity.Entity) (MaintainResultData, error) {
	var d MaintainResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return MaintainResultData{}, err
	}
	return d, nil
}

// ReleaseRequestData is the system/network/release-request payload (§2.5).
type ReleaseRequestData struct {
	PeerID string `cbor:"peer_id"`
	// Reason is "shutdown" (default), "idle", or "migration".
	Reason string `cbor:"reason,omitempty"`
}

// EffectiveReason returns reason with the §2.5 default applied.
func (d ReleaseRequestData) EffectiveReason() string {
	if d.Reason != "" {
		return d.Reason
	}
	return "shutdown"
}

// ToEntity creates a system/network/release-request entity.
func (d ReleaseRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkReleaseRequest, cbor.RawMessage(raw))
}

// ReleaseResultData is the system/network/release-result payload (§2.6).
type ReleaseResultData struct {
	PeerID string `cbor:"peer_id"`
	// CleanedUp lists the tree paths removed during cleanup.
	CleanedUp []string `cbor:"cleaned_up"`
}

// ToEntity creates a system/network/release-result entity.
func (d ReleaseResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkReleaseResult, cbor.RawMessage(raw))
}

// ReleaseResultDataFromEntity decodes a release-result entity's data.
func ReleaseResultDataFromEntity(e entity.Entity) (ReleaseResultData, error) {
	var d ReleaseResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ReleaseResultData{}, err
	}
	return d, nil
}

// NetworkPeerSummaryData is the system/network/peer-summary payload (§2.8).
type NetworkPeerSummaryData struct {
	PeerID    string `cbor:"peer_id"`
	SessionID string `cbor:"session_id"`
	// Status is "connected", "disconnected", "reconnecting" (§2.8; Go also
	// surfaces the §3.13 "suspect" transition state the floor writes).
	Status string `cbor:"status"`
	// PendingCount is the queued outbound message count for this peer.
	// Go ships no §8 outbox — bare zero is the conformant value
	// (Amendment 11).
	PendingCount uint64 `cbor:"pending_count"`
	// Subscriptions is the active subscription count on this peer.
	Subscriptions uint64 `cbor:"subscriptions"`
}

// NetworkStatusData is the system/network/status payload (§2.7).
type NetworkStatusData struct {
	MaintainedPeers []NetworkPeerSummaryData `cbor:"maintained_peers"`
	// PendingCount is the total queued outbound message count (zero — no
	// §8 outbox, Amendment 11).
	PendingCount uint64 `cbor:"pending_count"`
}

// ToEntity creates a system/network/status entity.
func (d NetworkStatusData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkStatus, cbor.RawMessage(raw))
}

// NetworkStatusDataFromEntity decodes a network status entity's data.
func NetworkStatusDataFromEntity(e entity.Entity) (NetworkStatusData, error) {
	var d NetworkStatusData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return NetworkStatusData{}, err
	}
	return d, nil
}

// CloseRequestData is the system/network/close-request payload (§2.9).
type CloseRequestData struct {
	PeerID string `cbor:"peer_id"`
	// Reason is "shutdown", "idle", "error", or "migration" (§9.1).
	Reason string `cbor:"reason"`
}

// ToEntity creates a system/network/close-request entity.
func (d CloseRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkCloseRequest, cbor.RawMessage(raw))
}

// TCPProfileDataFromEntity decodes a system/peer/transport/tcp entity.
// Per D-5 in PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS the
// data.transport_type MUST match the entity-type suffix; decoders MUST
// reject mismatch (fail closed). A `system/peer/transport/tcp` entity
// carrying `transport_type: "websocket"` (or anything other than "tcp")
// is invalid.
func TCPProfileDataFromEntity(e entity.Entity) (TCPProfileData, error) {
	var d TCPProfileData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return TCPProfileData{}, err
	}
	if d.TransportType != "tcp" {
		return TCPProfileData{}, fmt.Errorf(
			"transport_type mismatch: entity type %q carries data.transport_type %q (D-5)",
			e.Type, d.TransportType)
	}
	return d, nil
}
