package signaling

import (
	"bytes"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §4.4 blob framing + §4.5 bucket-read rules.
//
// The blob an offer carries is the canonical V7 entity wire encoding of the
// coordination entity — {type, data, content_hash} — with data embedded
// verbatim, never decoded and re-encoded. Byte fidelity matters beyond the usual
// reason: a decode+re-encode round trip through the carrier would invalidate the
// §3.3 signature these blobs will eventually carry. The TYPE must travel with
// the blob: a bucket is a mixed set, and connect-request / connect-response
// differ by a single field NAME, so a reader handed bare data is reduced to
// sniffing map keys.
//
// In Go, ecf.Encode(entity.Entity) IS that canonical encoding — Data is a
// cbor.RawMessage embedded verbatim — and ecf.Decode reverses it.

// MessageKind tags a classified bucket blob.
type MessageKind int

const (
	// KindUnknown is an undecodable or unrecognized blob — a NORMAL outcome in a
	// shared bucket, never an error. Kept countable rather than dropped silently.
	KindUnknown MessageKind = iota
	KindConnectRequest
	KindConnectResponse
	KindPunchSync
	// The §6.5 WebRTC-substrate payloads. They share this bucket with the §6.1
	// native ones by design — same carrier, same framing, same read rules — so a
	// native peer polling a mixed bucket classifies a webrtc/offer rather than
	// choking on it, and vice versa.
	KindWebRTCOffer
	KindWebRTCAnswer
	KindWebRTCCandidate
)

// CollectedMessage is one blob collected from a bucket, classified by which
// message it is. Exactly one payload pointer is non-nil, and only when Kind
// matches; Kind == KindUnknown leaves them all nil.
type CollectedMessage struct {
	Kind     MessageKind
	Request  *types.ConnectRequestData
	Response *types.ConnectResponseData
	Sync     *types.PunchSyncData

	// The §6.5 payloads. Offer/Answer deliberately expose no accessor that
	// hands out SDP unguarded — see AcceptRemoteDescription, which is the only
	// way §6.5's channel-identity MUST can be discharged.
	WebRTCOffer     *types.WebRTCOfferData
	WebRTCAnswer    *types.WebRTCAnswerData
	WebRTCCandidate *types.WebRTCCandidateData
}

// ToBlob serializes a coordination entity into the opaque blob the node stores
// (§4.4) — the canonical {type, data, content_hash} encoding, so the message
// type travels with it.
func ToBlob(e entity.Entity) ([]byte, error) {
	return ecf.Encode(e)
}

// ClassifyBlob decodes and classifies one blob collected from a bucket. An
// undecodable blob is KindUnknown, not an error (§4.5): a shared lobby bucket
// may legitimately hold anything, including a future message type this build has
// never heard of, and MUST-ignore says skip it rather than fail the poll.
func ClassifyBlob(blob []byte) CollectedMessage {
	var e entity.Entity
	if err := ecf.Decode(blob, &e); err != nil {
		return CollectedMessage{Kind: KindUnknown}
	}
	return Classify(e)
}

// Classify dispatches on the entity TYPE rather than sniffing the map, because
// two of the three coordination messages have identical field sets apart from
// initiator/responder. A type-string match whose data fails to decode (e.g. a
// negative fire_at, which will not fit uint64) is KindUnknown, not an error.
func Classify(e entity.Entity) CollectedMessage {
	switch e.Type {
	case types.TypeSignalingConnectRequest:
		d, err := types.ConnectRequestDataFromEntity(e)
		if err != nil {
			return CollectedMessage{Kind: KindUnknown}
		}
		return CollectedMessage{Kind: KindConnectRequest, Request: &d}
	case types.TypeSignalingConnectResponse:
		d, err := types.ConnectResponseDataFromEntity(e)
		if err != nil {
			return CollectedMessage{Kind: KindUnknown}
		}
		return CollectedMessage{Kind: KindConnectResponse, Response: &d}
	case types.TypeSignalingPunchSync:
		d, err := types.PunchSyncDataFromEntity(e)
		if err != nil {
			return CollectedMessage{Kind: KindUnknown}
		}
		return CollectedMessage{Kind: KindPunchSync, Sync: &d}
	case types.TypeSignalingWebRTCOffer:
		d, err := types.WebRTCOfferDataFromEntity(e)
		if err != nil || ValidateSessionID(d.SessionID) != nil {
			// A short or absent session_id is a §6.5 MUST violation, and the
			// §6.4 disposition for a message that fails a check is SKIP — the
			// same treatment as undecodable, never an error. Enforced at
			// classification so no caller can act on one by forgetting to look.
			return CollectedMessage{Kind: KindUnknown}
		}
		return CollectedMessage{Kind: KindWebRTCOffer, WebRTCOffer: &d}
	case types.TypeSignalingWebRTCAnswer:
		d, err := types.WebRTCAnswerDataFromEntity(e)
		if err != nil || ValidateSessionID(d.SessionID) != nil {
			return CollectedMessage{Kind: KindUnknown}
		}
		return CollectedMessage{Kind: KindWebRTCAnswer, WebRTCAnswer: &d}
	case types.TypeSignalingWebRTCCandidate:
		d, err := types.WebRTCCandidateDataFromEntity(e)
		if err != nil || ValidateSessionID(d.SessionID) != nil {
			return CollectedMessage{Kind: KindUnknown}
		}
		return CollectedMessage{Kind: KindWebRTCCandidate, WebRTCCandidate: &d}
	default:
		return CollectedMessage{Kind: KindUnknown}
	}
}

// FindResponse finds the response to MY exchange in a collected bucket (§4.5),
// applying two MUSTs: nonce echo (in lobby/tag the bucket is shared, so someone
// else's response is not mine, and a fresh answer is not one processed two polls
// ago) AND not-my-own-peer-id (a peer that answered its own request would
// "succeed" at meeting itself — miserable to diagnose, every step reports
// success). Returns the first match in bucket order (deposit order, oldest
// first).
func FindResponse(messages []CollectedMessage, myNonce []byte, myPeerID string) (*types.ConnectResponseData, bool) {
	for _, m := range messages {
		if m.Kind == KindConnectResponse &&
			bytes.Equal(m.Response.Nonce, myNonce) &&
			m.Response.Responder != myPeerID {
			return m.Response, true
		}
	}
	return nil, false
}

// FindRequest finds a request addressed at this rendezvous that I should answer
// — anyone's but my own (§4.5). Returns the first match in bucket order; a lobby
// bucket may hold several, and which to answer is peer policy this layer does
// not decide.
func FindRequest(messages []CollectedMessage, myPeerID string) (*types.ConnectRequestData, bool) {
	for _, m := range messages {
		if m.Kind == KindConnectRequest && m.Request.Initiator != myPeerID {
			return m.Request, true
		}
	}
	return nil, false
}
