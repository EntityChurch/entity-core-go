package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// EXTENSION-ATTESTATION v1.0 type constants. The substrate primitive defines
// one entity type — system/attestation — plus four handler request/result
// types for the :create, :supersede, :revoke, :verify operations.
const (
	// Entity type.
	TypeAttestation = "system/attestation"

	// Handler request/result types.
	TypeAttestationCreateRequest    = "system/attestation/create-request"
	TypeAttestationCreateResult     = "system/attestation/create-result"
	TypeAttestationSupersedeRequest = "system/attestation/supersede-request"
	TypeAttestationSupersedeResult  = "system/attestation/supersede-result"
	TypeAttestationRevokeRequest    = "system/attestation/revoke-request"
	TypeAttestationRevokeResult     = "system/attestation/revoke-result"
	TypeAttestationVerifyRequest    = "system/attestation/verify-request"
	TypeAttestationVerifyResult     = "system/attestation/verify-result"
)

// KindRevocation is the universal properties.kind value owned by
// EXTENSION-ATTESTATION (§3.3). All other kinds belong to consumer extensions.
const KindRevocation = "revocation"

// AttestationData is the data payload for system/attestation (§3.1).
// The signed-claim entity — the edge in the system's signed graph.
//
// Attesting is who's making the claim (peer hash; or quorum hash for K-of-N
// attestations — the consumer applies the K-of-N rule). Attested is what's
// being claimed about (any hash-addressable entity). Properties carries
// kind-specific extra fields per the consumer's convention; the attestation
// primitive itself only interprets properties.kind == "revocation".
type AttestationData struct {
	Attesting  hash.Hash                  `cbor:"attesting"`
	Attested   hash.Hash                  `cbor:"attested"`
	Properties map[string]cbor.RawMessage `cbor:"properties,omitempty"`
	Supersedes *hash.Hash                 `cbor:"supersedes,omitempty"`
	NotBefore  *uint64                    `cbor:"not_before,omitempty"`
	ExpiresAt  *uint64                    `cbor:"expires_at,omitempty"`
}

// ToEntity creates a system/attestation entity.
func (d AttestationData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestation, cbor.RawMessage(raw))
}

// AttestationDataFromEntity decodes a system/attestation entity's data.
func AttestationDataFromEntity(e entity.Entity) (AttestationData, error) {
	var d AttestationData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationData{}, err
	}
	return d, nil
}

// Kind returns the value of properties.kind, decoded as a string. Returns the
// empty string if no kind key is present or if the value is not a string.
func (d AttestationData) Kind() string {
	raw, ok := d.Properties["kind"]
	if !ok {
		return ""
	}
	var s string
	if err := ecf.Decode(raw, &s); err != nil {
		return ""
	}
	return s
}

// EncodeProperties encodes a typed property struct into the
// map[string]cbor.RawMessage shape carried by AttestationData.Properties.
// Returns an empty map if p is nil.
func EncodeProperties(p any) (map[string]cbor.RawMessage, error) {
	if p == nil {
		return nil, nil
	}
	raw, err := ecf.Encode(p)
	if err != nil {
		return nil, err
	}
	var m map[string]cbor.RawMessage
	if err := ecf.Decode(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// DecodeProperties decodes the map[string]cbor.RawMessage Properties of an
// attestation into a typed struct. The caller selects the correct type for
// the attestation's kind.
func DecodeProperties(props map[string]cbor.RawMessage, out any) error {
	if props == nil {
		return nil
	}
	raw, err := ecf.Encode(props)
	if err != nil {
		return err
	}
	return ecf.Decode(raw, out)
}

// MergeProperties returns a new properties map with extras merged into base.
// Keys in extras override keys in base. Used by consumer extensions to attach
// kind-specific keys on top of a partial properties map.
func MergeProperties(base map[string]cbor.RawMessage, extras map[string]cbor.RawMessage) map[string]cbor.RawMessage {
	if len(base) == 0 && len(extras) == 0 {
		return nil
	}
	out := make(map[string]cbor.RawMessage, len(base)+len(extras))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extras {
		out[k] = v
	}
	return out
}

// RevocationProperties is the typed properties shape for kind="revocation"
// (§3.3). Reason is informational; the primitive does not interpret it.
type RevocationProperties struct {
	Kind   string `cbor:"kind"`
	Reason string `cbor:"reason,omitempty"`
}

// --- Handler request/result types ---

// AttestationCreateRequestData is the data payload for
// system/attestation/create-request (§6.1). Signature gathering is the
// caller's responsibility per V7 patterns; the handler does not validate
// signatures — that's verify_attestation_signature.
//
// Wire shape per EXTENSION-ATTESTATION §6.1:
// `{attesting, attested, properties, supersedes?, not_before?, expires_at?}`.
// The flat shape comes from embedding AttestationData directly so its
// fields surface at the request-data top level (CBOR map merge).
type AttestationCreateRequestData struct {
	AttestationData
}

func (d AttestationCreateRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestationCreateRequest, cbor.RawMessage(raw))
}

func AttestationCreateRequestDataFromEntity(e entity.Entity) (AttestationCreateRequestData, error) {
	var d AttestationCreateRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationCreateRequestData{}, err
	}
	return d, nil
}

// AttestationCreateResultData carries the hash of the newly-bound attestation.
type AttestationCreateResultData struct {
	AttestationHash hash.Hash `cbor:"attestation_hash"`
}

func (d AttestationCreateResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestationCreateResult, cbor.RawMessage(raw))
}

func AttestationCreateResultDataFromEntity(e entity.Entity) (AttestationCreateResultData, error) {
	var d AttestationCreateResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationCreateResultData{}, err
	}
	return d, nil
}

// AttestationSupersedeRequestData is the data payload for
// system/attestation/supersede-request (§6.2). The previous attestation's
// attesting/attested fields are copied into the new attestation; properties
// and expires_at come from the request.
type AttestationSupersedeRequestData struct {
	PreviousHash hash.Hash                  `cbor:"previous_hash"`
	Properties   map[string]cbor.RawMessage `cbor:"properties,omitempty"`
	NotBefore    *uint64                    `cbor:"not_before,omitempty"`
	ExpiresAt    *uint64                    `cbor:"expires_at,omitempty"`
}

func (d AttestationSupersedeRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestationSupersedeRequest, cbor.RawMessage(raw))
}

func AttestationSupersedeRequestDataFromEntity(e entity.Entity) (AttestationSupersedeRequestData, error) {
	var d AttestationSupersedeRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationSupersedeRequestData{}, err
	}
	return d, nil
}

// AttestationSupersedeResultData carries the hash of the new (successor)
// attestation.
type AttestationSupersedeResultData struct {
	AttestationHash hash.Hash `cbor:"attestation_hash"`
}

func (d AttestationSupersedeResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestationSupersedeResult, cbor.RawMessage(raw))
}

func AttestationSupersedeResultDataFromEntity(e entity.Entity) (AttestationSupersedeResultData, error) {
	var d AttestationSupersedeResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationSupersedeResultData{}, err
	}
	return d, nil
}

// AttestationRevokeRequestData is the data payload for
// system/attestation/revoke-request (§6.3). The handler creates a revocation
// attestation with kind="revocation" and the given reason; equivalent to
// :create with the revocation properties shape.
type AttestationRevokeRequestData struct {
	TargetHash hash.Hash `cbor:"target_hash"`
	Attesting  hash.Hash `cbor:"attesting"`
	Reason     string    `cbor:"reason,omitempty"`
}

func (d AttestationRevokeRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestationRevokeRequest, cbor.RawMessage(raw))
}

func AttestationRevokeRequestDataFromEntity(e entity.Entity) (AttestationRevokeRequestData, error) {
	var d AttestationRevokeRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationRevokeRequestData{}, err
	}
	return d, nil
}

// AttestationRevokeResultData carries the hash of the revocation attestation.
type AttestationRevokeResultData struct {
	RevocationHash hash.Hash `cbor:"revocation_hash"`
}

func (d AttestationRevokeResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestationRevokeResult, cbor.RawMessage(raw))
}

func AttestationRevokeResultDataFromEntity(e entity.Entity) (AttestationRevokeResultData, error) {
	var d AttestationRevokeResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationRevokeResultData{}, err
	}
	return d, nil
}

// AttestationVerifyRequestData is the data payload for
// system/attestation/verify-request (§6.4). Wraps signature + liveness
// checks. AsOf, when set, enables time-traveling validation against
// historical state per §4.3.
type AttestationVerifyRequestData struct {
	AttestationHash hash.Hash `cbor:"attestation_hash"`
	AsOf            *uint64   `cbor:"as_of,omitempty"`
}

func (d AttestationVerifyRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestationVerifyRequest, cbor.RawMessage(raw))
}

func AttestationVerifyRequestDataFromEntity(e entity.Entity) (AttestationVerifyRequestData, error) {
	var d AttestationVerifyRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationVerifyRequestData{}, err
	}
	return d, nil
}

// AttestationVerifyResultData is the result of :verify. Reason is set when
// Valid is false to identify the failing predicate (invalid_signature,
// expired, superseded, self_revoked, etc.). Consumer-specific authority
// rules are NOT checked here — see consumer extensions.
type AttestationVerifyResultData struct {
	Valid  bool   `cbor:"valid"`
	Reason string `cbor:"reason,omitempty"`
}

func (d AttestationVerifyResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAttestationVerifyResult, cbor.RawMessage(raw))
}

func AttestationVerifyResultDataFromEntity(e entity.Entity) (AttestationVerifyResultData, error) {
	var d AttestationVerifyResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AttestationVerifyResultData{}, err
	}
	return d, nil
}
