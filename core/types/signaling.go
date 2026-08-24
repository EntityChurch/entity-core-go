package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

// Signaling extension wire types — the rendezvous/NAT-introduction surface of
// the committed EXTENSION-SIGNALING.md (§4 handler/operations, §6 coordination
// messages, §7 the punch).
//
// These structs are the shared codec for BOTH roles: the client (ext/signaling)
// and the Go node (ext/signaling/node) marshal through them, as does the Rust
// node, and the validate harness builds them inline the same way it builds
// network/relay types. Absent optional fields stay absent (pointer + omitempty),
// never null.
//
// SOURCE OF TRUTH NOTE: reconciled against the committed EXTENSION-SIGNALING.md
// (2026-07-31 re-diff). The §6.1 coordination messages carry candidates of type
// system/network/candidate (EXTENSION-NETWORK §6.7.3 — NetworkCandidateData),
// NOT a signaling-private candidate struct; the pre-v1.0 rust→cohort brief's
// NATCandidateData (which carried an out-of-spec `priority` field) is retired.
// Namespace: the §6.1 coordination messages are system/signaling/* as of the
// §3.1 flag-day rename (arch 2026-08-02), which also RESOLVED §13 Open Item #1 —
// the namespace question the rename answers. The former system/nat/* names are
// gone, not aliased: the §3.1 rendezvous-key derivation feeds its type string
// into the content hash, so a peer on the old name derives a different key and
// simply never meets one on the new name. There is no shape to fall back to.

const (
	// TypeSignalingOfferRequest is the offer input (§4.1).
	TypeSignalingOfferRequest = "system/signaling/offer-request"
	// TypeSignalingOfferResult is the offer output (§4.1).
	TypeSignalingOfferResult = "system/signaling/offer-result"
	// TypeSignalingCollectRequest is the collect input (§4.1).
	TypeSignalingCollectRequest = "system/signaling/collect-request"
	// TypeSignalingCollectResult is the collect output (§4.1).
	TypeSignalingCollectResult = "system/signaling/collect-result"
	// TypeSignalingAdvertiseResult is the advertise output (§4.5, §12).
	TypeSignalingAdvertiseResult = "system/signaling/advertise-result"
	// TypeSignalingLimits is the published bucket/TTL limits block (§4.5, §12).
	TypeSignalingLimits = "system/signaling/limits"

	// TypeSignalingConnectRequest is the §6 initiator coordination message (§6.1).
	TypeSignalingConnectRequest = "system/signaling/connect-request"
	// TypeSignalingConnectResponse is the §6 responder coordination message (§6.1).
	TypeSignalingConnectResponse = "system/signaling/connect-response"
	// TypeSignalingPunchSync is the §6 fire-time coordination message (§6.1, §7.2).
	TypeSignalingPunchSync = "system/signaling/punch-sync"

	// The §6.5 WebRTC-substrate coordination messages (folded 2026-08-02). The
	// §6.1 shapes above cannot carry an SDP/ICE exchange — they hold a candidates
	// array and no SDP — so the substrate defines three of its own. They ride the
	// carrier under §6.2 (blob framing), §6.3 (self-contained signature) and §6.4
	// (bucket read) UNCHANGED; only the payload differs.

	// TypeSignalingWebRTCOffer is the SDP offer (§6.5). Which peer sends it is
	// decided by perfect negotiation, not by a fixed role — see ext/signaling's
	// ResolveGlare.
	TypeSignalingWebRTCOffer = "system/signaling/webrtc/offer"
	// TypeSignalingWebRTCAnswer is the responder's SDP answer (§6.5).
	TypeSignalingWebRTCAnswer = "system/signaling/webrtc/answer"
	// TypeSignalingWebRTCCandidate is one trickled ICE candidate, either
	// direction, post-offer/answer (§6.5, RFC 8838).
	TypeSignalingWebRTCCandidate = "system/signaling/webrtc/candidate"

	// WebRTCSignalingSchema is the §6.5 schema version — the identifier a
	// system/peer/transport/webrtc profile pins in its signaling_schema field
	// (EXTENSION-NETWORK §6.5.2d). Declared here so the profile and the messages
	// it describes name the same constant.
	WebRTCSignalingSchema = "webrtc-sdp-ice/1"
)

// OfferRequestData is the system/signaling/offer-request payload (§4.1).
//
// RendezvousKey is a plain 33-byte CBOR bstr (algorithm‖digest, the derived key
// passed straight through) — NOT a system/hash field: to the node it is opaque
// bytes. Message is the §6.2 blob (a canonical V7 entity wire encoding).
type OfferRequestData struct {
	RendezvousKey []byte `cbor:"rendezvous_key"`
	Message       []byte `cbor:"message"`
}

// OfferResultData is the system/signaling/offer-result payload (§4.1). Ok is
// always true — a duplicate offer is idempotent and indistinguishable (§5 pin 1).
type OfferResultData struct {
	Ok bool `cbor:"ok"`
}

// CollectRequestData is the system/signaling/collect-request payload (§4.1).
type CollectRequestData struct {
	RendezvousKey []byte `cbor:"rendezvous_key"`
}

// CollectResultData is the system/signaling/collect-result payload (§4.1, §4.4).
// Messages carries the blobs THEMSELVES, not hashes; an unknown key yields an
// empty list and a 200, never a 404 (§4.4, §5 pin 1).
type CollectResultData struct {
	Messages [][]byte `cbor:"messages"`
}

// SignalingLimitsData is the system/signaling/limits block inside an
// advertise-result (§4.5). Field names, units, and defaults are the committed
// wire contract: max_blob_bytes (default 8192), max_bucket_blobs (default 32),
// ttl_seconds (default 60, SECONDS not ms). LobbyConstant is the optional
// `lobby` override — present only if the deployment overrides lobby:default;
// bytes (primitive/bytes), absent (nil) stays absent via omitempty.
type SignalingLimitsData struct {
	MaxBlobBytes   uint64 `cbor:"max_blob_bytes"`
	MaxBucketBlobs uint64 `cbor:"max_bucket_blobs"`
	TTLSeconds     uint64 `cbor:"ttl_seconds"`
	LobbyConstant  []byte `cbor:"lobby_constant,omitempty"`
}

// AdvertiseResultData is the system/signaling/advertise-result payload (§4.5).
// The `lobby` override lives inside Limits.LobbyConstant (§4.5), not as a
// top-level field. Clients read these limits rather than assuming them — a
// limit the client does not know is a cross-implementation reject boundary
// (§4.5).
type AdvertiseResultData struct {
	Endpoint string              `cbor:"endpoint"`
	Limits   SignalingLimitsData `cbor:"limits"`
}

// ConnectRequestData is the system/signaling/connect-request payload (§6.1).
// Candidates are system/network/candidate (EXTENSION-NETWORK §6.7.3) — the
// same type reachability gathering produces; try order derives from the
// candidate `type` (host→srflx→relay), not a wire priority field.
type ConnectRequestData struct {
	Candidates []NetworkCandidateData `cbor:"candidates"`
	Initiator  string                 `cbor:"initiator"`
	Nonce      []byte                 `cbor:"nonce"`
}

// ConnectResponseData is the system/signaling/connect-response payload (§6.1). Nonce
// is echoed from the request (§6.4 correlation).
type ConnectResponseData struct {
	Candidates []NetworkCandidateData `cbor:"candidates"`
	Nonce      []byte                 `cbor:"nonce"`
	Responder  string                 `cbor:"responder"`
}

// PunchSyncData is the system/signaling/punch-sync payload (§6.1). FireAt is an
// UNSIGNED integer of milliseconds from the receiving peer's moment of receipt
// — never a wall-clock instant. uint64 (not int64) is load-bearing: it must
// encode as CBOR major 0, and a negative value is refused, not clamped (§7.2).
type PunchSyncData struct {
	FireAt uint64 `cbor:"fire_at"`
	Nonce  []byte `cbor:"nonce"`
}

// WebRTCOfferData is the system/signaling/webrtc/offer payload (§6.5).
//
// SDP is OPAQUE on purpose and is fed VERBATIM to setRemoteDescription — it is
// RFC 8866 text produced by the browser's own stack, so structuring it here
// would be wrong (contrast Candidate below, which must be structured). It is
// also why this type must never be built by decoding and re-encoding a received
// offer: §6.2 embeds data verbatim because a re-encode round trip silently
// invalidates the §6.3 signature.
//
// SessionID correlates this pairing within one rendezvous key and MUST be
// freshly random and ≥16 bytes — see signaling.GenerateSessionID. A weak or
// colliding session_id splices two concurrent pairings' offer/answer/candidates
// together, which is a silent cross-handshake rather than a visible failure.
type WebRTCOfferData struct {
	SDP       string `cbor:"sdp"`
	SessionID []byte `cbor:"session_id"`
}

// WebRTCAnswerData is the system/signaling/webrtc/answer payload (§6.5). Same
// shape as the offer; the TYPE is what distinguishes them on the wire, which is
// the §6.2 reason the type travels with the blob.
type WebRTCAnswerData struct {
	SDP       string `cbor:"sdp"`
	SessionID []byte `cbor:"session_id"`
}

// WebRTCCandidateData is the system/signaling/webrtc/candidate payload (§6.5) —
// one trickled ICE candidate (RFC 8838).
//
// STRUCTURED, not a bare line, and NOT system/network/candidate. Two distinct
// reasons, both load-bearing:
//
//   - RTCPeerConnection.addIceCandidate() requires sdp_mid and sdp_mline_index
//     alongside the line and rejects a bare line, so they are distinct REQUIRED
//     fields (an S4-implementer finding, not a stylistic choice).
//   - This is the BROWSER's ICE format, produced and consumed by the browser's
//     own ICE stack and carried verbatim. It MUST NOT be translated to or from
//     NetworkCandidateData (EXTENSION-NETWORK §6.7.3), which is entity-core's own
//     reachability fact — the same non-collapse §9.3 draws for reflection. The
//     browser's srflx comes from its own STUN, never from observe-address.
//
// UsernameFragment is OPTIONAL: pointer + omitempty so an absent value stays
// absent rather than encoding as an empty string, which addIceCandidate would
// read as a real (wrong) ufrag.
type WebRTCCandidateData struct {
	Candidate        string  `cbor:"candidate"`
	SDPMid           string  `cbor:"sdp_mid"`
	SDPMLineIndex    uint64  `cbor:"sdp_mline_index"`
	SessionID        []byte  `cbor:"session_id"`
	UsernameFragment *string `cbor:"username_fragment,omitempty"`
}

// ToEntity encodes an offer-request as a system/signaling/offer-request entity.
func (d OfferRequestData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingOfferRequest, d)
}

// ToEntity encodes an offer-result entity.
func (d OfferResultData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingOfferResult, d)
}

// ToEntity encodes a collect-request entity.
func (d CollectRequestData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingCollectRequest, d)
}

// ToEntity encodes a collect-result entity.
func (d CollectResultData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingCollectResult, d)
}

// ToEntity encodes an advertise-result entity.
func (d AdvertiseResultData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingAdvertiseResult, d)
}

// ToEntity encodes a connect-request entity.
func (d ConnectRequestData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingConnectRequest, d)
}

// ToEntity encodes a connect-response entity.
func (d ConnectResponseData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingConnectResponse, d)
}

// ToEntity encodes a punch-sync entity.
func (d PunchSyncData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingPunchSync, d)
}

// ToEntity encodes a webrtc/offer entity.
func (d WebRTCOfferData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingWebRTCOffer, d)
}

// ToEntity encodes a webrtc/answer entity.
func (d WebRTCAnswerData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingWebRTCAnswer, d)
}

// ToEntity encodes a webrtc/candidate entity.
func (d WebRTCCandidateData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingWebRTCCandidate, d)
}

func toSignalingEntity(entityType string, d any) (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(entityType, cbor.RawMessage(raw))
}

// OfferRequestDataFromEntity decodes an offer-request entity's data.
func OfferRequestDataFromEntity(e entity.Entity) (OfferRequestData, error) {
	var d OfferRequestData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// CollectRequestDataFromEntity decodes a collect-request entity's data — the
// node/server side of §4.1 (the client builds the request; the node reads it).
func CollectRequestDataFromEntity(e entity.Entity) (CollectRequestData, error) {
	var d CollectRequestData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// CollectResultDataFromEntity decodes a collect-result entity's data.
func CollectResultDataFromEntity(e entity.Entity) (CollectResultData, error) {
	var d CollectResultData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// AdvertiseResultDataFromEntity decodes an advertise-result entity's data.
func AdvertiseResultDataFromEntity(e entity.Entity) (AdvertiseResultData, error) {
	var d AdvertiseResultData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// ConnectRequestDataFromEntity decodes a connect-request entity's data.
func ConnectRequestDataFromEntity(e entity.Entity) (ConnectRequestData, error) {
	var d ConnectRequestData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// ConnectResponseDataFromEntity decodes a connect-response entity's data.
func ConnectResponseDataFromEntity(e entity.Entity) (ConnectResponseData, error) {
	var d ConnectResponseData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// PunchSyncDataFromEntity decodes a punch-sync entity's data.
func PunchSyncDataFromEntity(e entity.Entity) (PunchSyncData, error) {
	var d PunchSyncData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// WebRTCOfferDataFromEntity decodes a webrtc/offer entity's data.
func WebRTCOfferDataFromEntity(e entity.Entity) (WebRTCOfferData, error) {
	var d WebRTCOfferData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// WebRTCAnswerDataFromEntity decodes a webrtc/answer entity's data.
func WebRTCAnswerDataFromEntity(e entity.Entity) (WebRTCAnswerData, error) {
	var d WebRTCAnswerData
	err := ecf.Decode(e.Data, &d)
	return d, err
}

// WebRTCCandidateDataFromEntity decodes a webrtc/candidate entity's data.
func WebRTCCandidateDataFromEntity(e entity.Entity) (WebRTCCandidateData, error) {
	var d WebRTCCandidateData
	err := ecf.Decode(e.Data, &d)
	return d, err
}
