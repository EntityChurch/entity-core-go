package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

// Durability types — reference implementation of EXTENSION-DURABILITY v0.1
// (`core-protocol-domain/specs/extensions/standard-peer-extensions/
// EXTENSION-DURABILITY.md`). Per PROPOSAL-DELIVERY-AND-DURABILITY (Status:
// RETRACTED) the durability contract was extracted from
// EXTENSION-INBOX §10 into a standalone exploratory/optional extension; the
// wire surface is preserved verbatim. V7 v7.46 has no durability material in
// core (the v7.47 reservation of 412 / 202 in §3.3 was reverted with the
// extraction); §3.3 status codes 412 and 202 are reintroduced only within
// EXTENSION-DURABILITY's own surface. No deployment depends on this; this
// impl tracks the reference design for cross-impl validation.
const (
	TypeDurabilityRequest       = "system/durability-request"
	TypeDurabilityResult        = "system/durability-result"
	TypeDurabilityAdvertisement = "system/durability-advertisement"
)

// DurabilityAdvertisementPath is the tree path at which a peer publishes the
// durability levels it supports (EXTENSION-DURABILITY §3 — discovery, MAY-tier
// after Amendment 1 demoted SHOULD→MAY). Absence does NOT change the response
// contract (§5); the path and shape are NOT spec-pinned — this is the Go
// convention. Any path containing a `system/durability-advertisement` entity
// is conformant.
const DurabilityAdvertisementPath = "system/durability"

// DurabilityAdvertisementData is the data payload for
// system/durability-advertisement (EXTENSION-DURABILITY §3). Discovery only —
// the authoritative answer is always the response verdict (§5).
type DurabilityAdvertisementData struct {
	// Levels are the durability levels this peer supports (vocabulary
	// illustrative per §7), weakest to strongest.
	Levels []string `cbor:"levels"`
	// MaxSelfDeterminable is the strongest level the peer guarantees
	// synchronously at acceptance.
	MaxSelfDeterminable string `cbor:"max_self_determinable"`
}

// ToEntity creates a system/durability-advertisement entity.
func (d DurabilityAdvertisementData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDurabilityAdvertisement, cbor.RawMessage(raw))
}

// DurabilityAdvertisementDataFromEntity decodes an advertisement entity.
func DurabilityAdvertisementDataFromEntity(e entity.Entity) (DurabilityAdvertisementData, error) {
	var d DurabilityAdvertisementData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return DurabilityAdvertisementData{}, err
	}
	return d, nil
}

// Durability strength vocabulary. Per EXTENSION-DURABILITY §7 these values
// are illustrative, NOT a ratified enum — the field shape is pinned for
// cross-impl determinism; the level strings are this implementation's pinned
// vocabulary.
const (
	// DurabilityNone — no durable storage in place.
	DurabilityNone = "none"
	// DurabilityStored — write-ahead persisted to this peer's store + tree,
	// findable again via the handle the response returns. Self-determinable
	// at acceptance.
	DurabilityStored = "stored"
	// DurabilityReplicated — replicated to another peer via its later sync.
	// Replication-class: NOT self-certifiable at acceptance
	// (EXTENSION-DURABILITY §5 row 5).
	DurabilityReplicated = "replicated"
)

// Durability reason codes. EXTENSION-DURABILITY §7 pins the spellings for
// spec-enumerated cases (additional impl-specific diagnostic strings remain
// implementation-defined).
const (
	// ReasonNoDurableStore — the receiver has no durable store; the request
	// was handled normally but not preserved (200, applied: none).
	ReasonNoDurableStore = "no_durable_store"
	// ReasonRequiredUnmet — a must_have durability level could not be met;
	// the operation was refused at acceptance (412).
	ReasonRequiredUnmet = "durability_required_unmet"
	// ReasonUnknownLevel — the requested level is not in the receiver's
	// recognized vocabulary; fail-closed per EXTENSION-DURABILITY §5 / §8:
	// must_have:true → 412, must_have:false → 200 with applied:none.
	ReasonUnknownLevel = "unknown_level"
	// ReasonDuplicateRequestID — a durable request's (author, request_id)
	// matches a previously preserved entry; receiver returns 409 per
	// EXTENSION-DURABILITY §5 / §8. 409 is already in V7 §3.3's reserved
	// set; this extension pins it for the durability MUST.
	ReasonDuplicateRequestID = "duplicate_request_id"
)

// DurabilityRequestData is the data payload for system/durability-request —
// the optional request-side durability marker on EXECUTE
// (EXTENSION-DURABILITY §2). Independent of deliver_to/deliver_token.
type DurabilityRequestData struct {
	// Level is the requested durability level (vocabulary illustrative, §7).
	Level string `cbor:"level"`
	// MustHave: false (default/absent) = best-effort (take less, observably);
	// true = required (refuse with 412 if unmet, §5).
	MustHave bool `cbor:"must_have,omitempty"`
}

// ToEntity creates a system/durability-request entity.
func (d DurabilityRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDurabilityRequest, cbor.RawMessage(raw))
}

// DurabilityRequestDataFromEntity decodes a durability-request entity's data.
func DurabilityRequestDataFromEntity(e entity.Entity) (DurabilityRequestData, error) {
	var d DurabilityRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return DurabilityRequestData{}, err
	}
	return d, nil
}

// DurabilityResultData is the data payload for system/durability-result —
// the pinned response durability verdict (EXTENSION-DURABILITY §5). One
// distinct meaning per status: 200 = outcome final · 202 = accepted,
// Committed completes asynchronously · 412 = required durability unmet,
// operation NOT performed · 409 = duplicate (author, request_id), operation
// NOT performed.
type DurabilityResultData struct {
	// Requested is the level the sender asked for.
	Requested string `cbor:"requested"`
	// Applied is the durability PHYSICALLY IN PLACE at the moment of this
	// response (or "none"). ONE meaning in every row — it never names a
	// promise. Invariant: no response claims a durability it does not yet
	// have (EXTENSION-DURABILITY §5).
	Applied string `cbor:"applied"`
	// Committed is a strength committed to a pathway that completes
	// ASYNCHRONOUSLY. Present ONLY with status 202.
	Committed string `cbor:"committed,omitempty"`
	// MaxAvailable is the best the receiver could offer. Present ONLY with
	// status 412.
	MaxAvailable string `cbor:"max_available,omitempty"`
	// Reason is an optional code string. Spec-enumerated cases use the pinned
	// spellings in §7; other diagnostic strings are implementation-defined.
	Reason string `cbor:"reason,omitempty"`
	// Handle is the absolute tree path where the durable entry can be read.
	// Present when applied != none; on 202, names where the committed entry
	// will land (may resolve to 404 until commit completes). The receiver
	// chooses the storage layout; the sender follows the handle via
	// tree:get / sync / subscription. EXTENSION-DURABILITY §6.
	Handle string `cbor:"handle,omitempty"`
}

// ToEntity creates a system/durability-result entity.
func (d DurabilityResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDurabilityResult, cbor.RawMessage(raw))
}

// DurabilityResultDataFromEntity decodes a durability-result entity's data.
func DurabilityResultDataFromEntity(e entity.Entity) (DurabilityResultData, error) {
	var d DurabilityResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return DurabilityResultData{}, err
	}
	return d, nil
}
