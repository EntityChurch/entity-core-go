package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// EXTENSION-QUORUM v1.0 type constants. The K-of-N node primitive defines one
// entity type — system/quorum — plus four handler request/result types for
// the :create, :update, :publish, :verify operations.
//
// quorum-update and quorum-publish are NOT separate entity types — they are
// system/attestation entities (per EXTENSION-ATTESTATION) discriminated by
// properties.kind per §3.2 / §3.3.
const (
	// Entity type.
	TypeQuorum = "system/quorum"

	// Handler request/result types.
	TypeQuorumCreateRequest  = "system/quorum/create-request"
	TypeQuorumCreateResult   = "system/quorum/create-result"
	TypeQuorumUpdateRequest  = "system/quorum/update-request"
	TypeQuorumUpdateResult   = "system/quorum/update-result"
	TypeQuorumPublishRequest = "system/quorum/publish-request"
	TypeQuorumPublishResult  = "system/quorum/publish-result"
	TypeQuorumVerifyRequest  = "system/quorum/verify-request"
	TypeQuorumVerifyResult   = "system/quorum/verify-result"
)

// Quorum self-event properties.kind values owned by EXTENSION-QUORUM (§3.2,
// §3.3). Both are kinds on system/attestation entities — not separate types.
const (
	KindQuorumUpdate  = "quorum-update"
	KindQuorumPublish = "quorum-publish"
)

// Signer-resolution modes (§5). "concrete" is built into EXTENSION-QUORUM;
// other modes are registered at runtime via the resolver hook (§5.2).
// EXTENSION-IDENTITY v3.3 registers "identity-resolved" against this hook
// at configure-time.
const (
	SignerResolutionConcrete         = "concrete"
	SignerResolutionIdentityResolved = "identity-resolved"
)

// QuorumData is the data payload for system/quorum (§3.1). The K-of-N signing
// node entity. Signers is the constituent peer-identity hash list (or, in
// identity-resolved mode, references to public identities). Threshold is K.
//
// The quorum entity is structural and is not itself signed — authorization
// for the quorum's role flows from its constituents collectively K-of-N
// signing other entities (top-level certs, quorum-update / quorum-publish
// attestations, cluster votes, etc.).
type QuorumData struct {
	Signers          []hash.Hash     `cbor:"signers"`
	Threshold        uint64          `cbor:"threshold"`
	SignerResolution string          `cbor:"signer_resolution,omitempty"`
	Name             string          `cbor:"name,omitempty"`
	Metadata         cbor.RawMessage `cbor:"metadata,omitempty"`
}

func (d QuorumData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorum, cbor.RawMessage(raw))
}

func QuorumDataFromEntity(e entity.Entity) (QuorumData, error) {
	var d QuorumData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumData{}, err
	}
	return d, nil
}

// QuorumUpdateProperties is the typed properties shape for kind="quorum-update"
// (§3.2). The kind value MUST be set explicitly; "Kind" is a struct field so
// EncodeProperties round-trips through the property map.
type QuorumUpdateProperties struct {
	Kind         string      `cbor:"kind"`
	NewSigners   []hash.Hash `cbor:"new_signers"`
	NewThreshold uint64      `cbor:"new_threshold"`
}

// QuorumPublishProperties is the typed properties shape for kind="quorum-publish"
// (§3.3). PublishedHandle is an optional consumer hook (e.g., identity sets it
// to the controller's or identifier's key as the contact-side handle).
// Additional consumer-specific keys may be merged via MergeProperties.
type QuorumPublishProperties struct {
	Kind            string      `cbor:"kind"`
	Signers         []hash.Hash `cbor:"signers"`
	Threshold       uint64      `cbor:"threshold"`
	PublishedHandle *hash.Hash  `cbor:"published_handle,omitempty"`
}

// --- Handler request/result types ---

// QuorumCreateRequestData is the data payload for system/quorum/create-request
// (§6.1). Instantiates the quorum entity at system/quorum/{quorum_id_hex}.
//
// Wire shape per EXTENSION-QUORUM §6.1:
// `{signers, threshold, signer_resolution?, name?, metadata?}`. Embeds
// QuorumData so its fields surface at the request-data top level.
type QuorumCreateRequestData struct {
	QuorumData
}

func (d QuorumCreateRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorumCreateRequest, cbor.RawMessage(raw))
}

func QuorumCreateRequestDataFromEntity(e entity.Entity) (QuorumCreateRequestData, error) {
	var d QuorumCreateRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumCreateRequestData{}, err
	}
	return d, nil
}

type QuorumCreateResultData struct {
	QuorumID hash.Hash `cbor:"quorum_id"`
}

func (d QuorumCreateResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorumCreateResult, cbor.RawMessage(raw))
}

func QuorumCreateResultDataFromEntity(e entity.Entity) (QuorumCreateResultData, error) {
	var d QuorumCreateResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumCreateResultData{}, err
	}
	return d, nil
}

// QuorumUpdateRequestData is the data payload for system/quorum/update-request
// (§6.2). Produces a quorum-update attestation per §3.2. Signature gathering
// (K-of-N from the current signer set) is the caller's responsibility.
type QuorumUpdateRequestData struct {
	QuorumID     hash.Hash   `cbor:"quorum_id"`
	NewSigners   []hash.Hash `cbor:"new_signers"`
	NewThreshold uint64      `cbor:"new_threshold"`
	Supersedes   *hash.Hash  `cbor:"supersedes,omitempty"`
}

func (d QuorumUpdateRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorumUpdateRequest, cbor.RawMessage(raw))
}

func QuorumUpdateRequestDataFromEntity(e entity.Entity) (QuorumUpdateRequestData, error) {
	var d QuorumUpdateRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumUpdateRequestData{}, err
	}
	return d, nil
}

type QuorumUpdateResultData struct {
	UpdateHash hash.Hash `cbor:"update_hash"`
}

func (d QuorumUpdateResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorumUpdateResult, cbor.RawMessage(raw))
}

func QuorumUpdateResultDataFromEntity(e entity.Entity) (QuorumUpdateResultData, error) {
	var d QuorumUpdateResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumUpdateResultData{}, err
	}
	return d, nil
}

// QuorumPublishRequestData is the data payload for system/quorum/publish-request
// (§6.3). Signers/Threshold MUST match current_signer_set on the initial
// publish; subsequent publishes are signed by the previous quorum (the
// supersedes-chain key for compromise-recovery cryptographic continuity per
// §3.3).
type QuorumPublishRequestData struct {
	QuorumID        hash.Hash                  `cbor:"quorum_id"`
	Signers         []hash.Hash                `cbor:"signers"`
	Threshold       uint64                     `cbor:"threshold"`
	PublishedHandle *hash.Hash                 `cbor:"published_handle,omitempty"`
	ExtraProperties map[string]cbor.RawMessage `cbor:"extra_properties,omitempty"`
	Supersedes      *hash.Hash                 `cbor:"supersedes,omitempty"`
}

func (d QuorumPublishRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorumPublishRequest, cbor.RawMessage(raw))
}

func QuorumPublishRequestDataFromEntity(e entity.Entity) (QuorumPublishRequestData, error) {
	var d QuorumPublishRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumPublishRequestData{}, err
	}
	return d, nil
}

type QuorumPublishResultData struct {
	PublishHash hash.Hash `cbor:"publish_hash"`
}

func (d QuorumPublishResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorumPublishResult, cbor.RawMessage(raw))
}

func QuorumPublishResultDataFromEntity(e entity.Entity) (QuorumPublishResultData, error) {
	var d QuorumPublishResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumPublishResultData{}, err
	}
	return d, nil
}

// QuorumVerifyRequestData is the data payload for system/quorum/verify-request
// (§6.4). Wraps current_signer_set + verify_k_of_n_signatures.
type QuorumVerifyRequestData struct {
	EntityHash hash.Hash `cbor:"entity_hash"`
	QuorumID   hash.Hash `cbor:"quorum_id"`
}

func (d QuorumVerifyRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorumVerifyRequest, cbor.RawMessage(raw))
}

func QuorumVerifyRequestDataFromEntity(e entity.Entity) (QuorumVerifyRequestData, error) {
	var d QuorumVerifyRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumVerifyRequestData{}, err
	}
	return d, nil
}

// QuorumVerifyResultData reports the K-of-N validation result. SignedBy is the
// set of constituents whose signatures were verified — useful diagnostically
// when valid is false (shows which constituents failed to sign).
type QuorumVerifyResultData struct {
	Valid    bool        `cbor:"valid"`
	SignedBy []hash.Hash `cbor:"signed_by,omitempty"`
}

func (d QuorumVerifyResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQuorumVerifyResult, cbor.RawMessage(raw))
}

func QuorumVerifyResultDataFromEntity(e entity.Entity) (QuorumVerifyResultData, error) {
	var d QuorumVerifyResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QuorumVerifyResultData{}, err
	}
	return d, nil
}
