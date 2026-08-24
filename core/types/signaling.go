package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

// Signaling extension wire types — the rendezvous/NAT-introduction surface of
// PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH (§2.2/§3) and PROPOSAL-CONNECTION-NODE.
//
// entity-core-go builds the CLIENT of this surface; the server/node role is
// Rust's (see docs and the rust→cohort brief). These structs are the shared
// codec: a future Go handler and the client both marshal through them, and the
// validate harness builds them inline the same way it builds network/relay
// types. Absent optional fields stay absent (pointer + omitempty), never null.
//
// SOURCE OF TRUTH NOTE: the arch signaling corpus is not yet committed upstream
// (see docs/status). These shapes trace to the rust→cohort build brief's §5
// wire table; re-diff against the committed spec once it lands.

const (
	// TypeSignalingOfferRequest is the offer input (§5.1).
	TypeSignalingOfferRequest = "system/signaling/offer-request"
	// TypeSignalingOfferResult is the offer output (§5.1).
	TypeSignalingOfferResult = "system/signaling/offer-result"
	// TypeSignalingCollectRequest is the collect input (§5.1).
	TypeSignalingCollectRequest = "system/signaling/collect-request"
	// TypeSignalingCollectResult is the collect output (§5.1).
	TypeSignalingCollectResult = "system/signaling/collect-result"
	// TypeSignalingAdvertisement is the advertise output (§5.1).
	TypeSignalingAdvertisement = "system/signaling/advertisement"

	// TypeNATConnectRequest is the §3 initiator coordination message (§5.4).
	TypeNATConnectRequest = "system/nat/connect-request"
	// TypeNATConnectResponse is the §3 responder coordination message (§5.4).
	TypeNATConnectResponse = "system/nat/connect-response"
	// TypeNATPunchSync is the §3 fire-time coordination message (§5.4).
	TypeNATPunchSync = "system/nat/punch-sync"
)

// OfferRequestData is the system/signaling/offer-request payload (§5.1).
//
// RendezvousKey is a plain 33-byte CBOR bstr (algorithm‖digest, the derived key
// passed straight through) — NOT a system/hash field: to the node it is opaque
// bytes. Message is the §4.4 blob (a canonical V7 entity wire encoding).
type OfferRequestData struct {
	RendezvousKey []byte `cbor:"rendezvous_key"`
	Message       []byte `cbor:"message"`
}

// OfferResultData is the system/signaling/offer-result payload (§5.1). Ok is
// always true — a duplicate offer is idempotent and indistinguishable (§5.2).
type OfferResultData struct {
	Ok bool `cbor:"ok"`
}

// CollectRequestData is the system/signaling/collect-request payload (§5.1).
type CollectRequestData struct {
	RendezvousKey []byte `cbor:"rendezvous_key"`
}

// CollectResultData is the system/signaling/collect-result payload (§5.1).
// Messages carries the blobs THEMSELVES, not hashes (arch ruling 1); an unknown
// key yields an empty list and a 200, never a 404 (§5.2).
type CollectResultData struct {
	Messages [][]byte `cbor:"messages"`
}

// SignalingLimitsData is the bare-map limits block inside an advertisement
// (§5.1) — a struct field, not a core/entity wrapper.
type SignalingLimitsData struct {
	BucketTTLMs       uint64 `cbor:"bucket_ttl_ms"`
	MaxKeys           uint64 `cbor:"max_keys"`
	MaxMessageBytes   uint64 `cbor:"max_message_bytes"`
	MaxMessagesPerKey uint64 `cbor:"max_messages_per_key"`
}

// AdvertisementData is the system/signaling/advertisement payload (§5.1).
// Lobby is absent unless the node published an override — pointer + omitempty
// so absent stays absent (§5.1).
type AdvertisementData struct {
	Endpoint string              `cbor:"endpoint"`
	Limits   SignalingLimitsData `cbor:"limits"`
	Lobby    *string             `cbor:"lobby,omitempty"`
}

// NATCandidateData is one §3 dial candidate — a bare map. Address is opaque at the
// entity layer (the layer never interprets IP:port). Priority is lower-tried-
// first. Substrate is tcp|quic|webrtc (only tcp ships v1). Type is
// host|srflx|relay; an unknown class sorts last, never dropped (§5.4).
type NATCandidateData struct {
	Address   string `cbor:"address"`
	Priority  uint64 `cbor:"priority"`
	Substrate string `cbor:"substrate"`
	Type      string `cbor:"type"`
}

// ConnectRequestData is the system/nat/connect-request payload (§5.4).
type ConnectRequestData struct {
	Candidates []NATCandidateData `cbor:"candidates"`
	Initiator  string          `cbor:"initiator"`
	Nonce      []byte          `cbor:"nonce"`
}

// ConnectResponseData is the system/nat/connect-response payload (§5.4). Nonce
// is echoed from the request (§4.5 correlation).
type ConnectResponseData struct {
	Candidates []NATCandidateData `cbor:"candidates"`
	Nonce      []byte          `cbor:"nonce"`
	Responder  string          `cbor:"responder"`
}

// PunchSyncData is the system/nat/punch-sync payload (§5.4). FireAt is an
// UNSIGNED integer of milliseconds from the receiving peer's moment of receipt
// — never a wall-clock instant. uint64 (not int64) is load-bearing: it must
// encode as CBOR major 0, and a negative value is refused, not clamped (§4.3).
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

// ToEntity encodes an advertisement entity.
func (d AdvertisementData) ToEntity() (entity.Entity, error) {
	return toSignalingEntity(TypeSignalingAdvertisement, d)
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

// AdvertisementDataFromEntity decodes an advertisement entity's data.
func AdvertisementDataFromEntity(e entity.Entity) (AdvertisementData, error) {
	var d AdvertisementData
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
