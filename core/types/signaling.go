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
// entity-core-go builds the CLIENT of this surface; the server/node role is
// Rust's (see docs and the rust→cohort brief). These structs are the shared
// codec: a future Go handler and the client both marshal through them, and the
// validate harness builds them inline the same way it builds network/relay
// types. Absent optional fields stay absent (pointer + omitempty), never null.
//
// SOURCE OF TRUTH NOTE: reconciled against the committed EXTENSION-SIGNALING.md
// (2026-07-31 re-diff). The §6.1 coordination messages carry candidates of type
// system/network/candidate (EXTENSION-NETWORK §6.7.3 — NetworkCandidateData),
// NOT a signaling-private candidate struct; the pre-v1.0 rust→cohort brief's
// NATCandidateData (which carried an out-of-spec `priority` field) is retired.
// Message type names system/nat/* are retained per §6.1/§12 (Open Item #1 defers
// any system/signaling/* rename to a cohort call).

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

	// TypeNATConnectRequest is the §6 initiator coordination message (§6.1).
	TypeNATConnectRequest = "system/nat/connect-request"
	// TypeNATConnectResponse is the §6 responder coordination message (§6.1).
	TypeNATConnectResponse = "system/nat/connect-response"
	// TypeNATPunchSync is the §6 fire-time coordination message (§6.1, §7.2).
	TypeNATPunchSync = "system/nat/punch-sync"
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

// ConnectRequestData is the system/nat/connect-request payload (§6.1).
// Candidates are system/network/candidate (EXTENSION-NETWORK §6.7.3) — the
// same type reachability gathering produces; try order derives from the
// candidate `type` (host→srflx→relay), not a wire priority field.
type ConnectRequestData struct {
	Candidates []NetworkCandidateData `cbor:"candidates"`
	Initiator  string                 `cbor:"initiator"`
	Nonce      []byte                 `cbor:"nonce"`
}

// ConnectResponseData is the system/nat/connect-response payload (§6.1). Nonce
// is echoed from the request (§6.4 correlation).
type ConnectResponseData struct {
	Candidates []NetworkCandidateData `cbor:"candidates"`
	Nonce      []byte                 `cbor:"nonce"`
	Responder  string                 `cbor:"responder"`
}

// PunchSyncData is the system/nat/punch-sync payload (§6.1). FireAt is an
// UNSIGNED integer of milliseconds from the receiving peer's moment of receipt
// — never a wall-clock instant. uint64 (not int64) is load-bearing: it must
// encode as CBOR major 0, and a negative value is refused, not clamped (§7.2).
type PunchSyncData struct {
	FireAt uint64 `cbor:"fire_at"`
	Nonce  []byte `cbor:"nonce"`
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
	return toSignalingEntity(TypeNATConnectRequest, d)
}

// ToEntity encodes a connect-response entity.
func (d ConnectResponseData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeNATConnectResponse, d)
}

// ToEntity encodes a punch-sync entity.
func (d PunchSyncData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeNATPunchSync, d)
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
