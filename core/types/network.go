package types

import (
	"fmt"

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
	CapFlow        string            `cbor:"cap_flow,omitempty"`        // typically "egress"
	PollIntervalMs uint64            `cbor:"poll_interval_ms,omitempty"` // informative
	SignedPointer  string            `cbor:"signed_pointer,omitempty"`   // canonical signed root path
	AdvertisedAt   uint64            `cbor:"advertised_at,omitempty"` // wall-clock epoch ms (PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS D-3 — informational, NOT a selection key)
	Priority       *uint64           `cbor:"priority,omitempty"`      // Q1 (arch §8.9 / Round 3): DNS-SRV semantics — lower = preferred. Pointer-typed so nil (omitted on wire) is distinguishable from explicit 0. Defaults applied at sort time: nil + profile-id "primary" → 0, nil + others → 100.
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
	CapFlow       string               `cbor:"cap_flow,omitempty"` // typically "both"
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
	CapFlow       string               `cbor:"cap_flow,omitempty"` // typically "both"
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
	CapFlow       string               `cbor:"cap_flow,omitempty"` // typically "both"
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
