package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// EXTENSION-IDENTITY v3.3 type constants. The substrate-extraction rewrite
// reduces identity to a convention layer over EXTENSION-ATTESTATION
// (system/attestation) and EXTENSION-QUORUM (system/quorum). Identity owns
// only one entity type — system/identity/peer-config — plus one helper
// inner type — system/identity/identity-binding. Identity certs / lifecycle
// events / revocations are system/attestation entities discriminated by
// properties.kind values that identity registers (per
// EXTENSION-ATTESTATION.md §3.2 kind-ownership table).
//
// The bare "system/identity" type name is the identity-record type
// (declared in core/types/crypto.go); the extension types live as siblings
// under the system/identity/ namespace prefix.
const (
	// Entity types (1 primary + 1 helper + 1 controller-events).
	TypeIdentityPeerConfig = "system/identity/peer-config"
	TypeIdentityBinding    = "system/identity/identity-binding"
	// TypeIdentityEvent names the controller-events stream entity per
	// PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-5 (Rev 3). Emitted by
	// :process_attestation phase 3 on phase-2 handler failure; v2 ships
	// FAILURE-only with normative event_subkind ("recovery_signal" |
	// "failure_observation").
	TypeIdentityEvent = "system/identity/event"

	// Handler request/result types.
	TypeIdentityConfigureRequest            = "system/identity/configure-request"
	TypeIdentityConfigureResult             = "system/identity/configure-result"
	TypeIdentityCreateQuorumRequest         = "system/identity/create-quorum-request"
	TypeIdentityCreateQuorumResult          = "system/identity/create-quorum-result"
	TypeIdentityCreateAttestationRequest    = "system/identity/create-attestation-request"
	TypeIdentityCreateAttestationResult     = "system/identity/create-attestation-result"
	TypeIdentitySupersedeAttestationRequest = "system/identity/supersede-attestation-request"
	TypeIdentitySupersedeAttestationResult  = "system/identity/supersede-attestation-result"
	TypeIdentityRevokeAttestationRequest    = "system/identity/revoke-attestation-request"
	TypeIdentityRevokeAttestationResult     = "system/identity/revoke-attestation-result"
	TypeIdentityPublishAttestationRequest   = "system/identity/publish-attestation-request"
	TypeIdentityPublishAttestationResult    = "system/identity/publish-attestation-result"
)

// Identity-context properties.kind values per EXTENSION-IDENTITY v3.3 §4.1.
// Registered in the EXTENSION-ATTESTATION §3.2 kind-ownership table.
// The "revocation" kind is owned by EXTENSION-ATTESTATION (universal
// mechanism); identity applies its authority-revocation rules per §3.6.
const (
	KindIdentityCert             = "identity-cert"
	KindIdentityRotationHandoff  = "identity-rotation-handoff"
	KindIdentityRotationRecovery = "identity-rotation-recovery"
	KindIdentityRetirement       = "identity-retirement"
)

// Standard cert function values per §4.2 (REQUIRED on identity-cert
// attestations; properties.function). App-defined function values are
// allowed (per §4.2 row 5); apps document their own function strings.
const (
	FunctionController = "controller"
	FunctionAgent      = "agent"
	FunctionIdentifier = "identifier"
)

// Publication modes for identity-cert attestations per §4.2 (REQUIRED on
// ALL identity-certs; properties.mode). Mode is fixed at create-time per
// §4.2 — eliminates the in-flight rotation race that a runtime shape
// lookup would create.
const (
	ModeInternal        = "internal"
	ModePublic          = "public"
	ModePerRelationship = "per-relationship"
	ModeEmbedded        = "embedded"
)

// Controller-event subkinds per PI-5 (Rev 3). Recovery-signal events are
// retention-pinned (MUST NOT prune until cleared); failure-observation
// events are impl-defined retention. v2.x may add `informational`.
const (
	EventSubkindRecoverySignal     = "recovery_signal"
	EventSubkindFailureObservation = "failure_observation"
)

// --- Entity types ---

// IdentityBindingData is the helper inner type used in peer-config.bindings
// per §3.4. Records this agent peer's role in one identity. A field-only
// inner type — lives inside peer-config.bindings, not stored as an
// independent entity. Both fields are content hashes of system/attestation
// entities at identity's storage paths.
//
// In the three-key default (handle_cert is the controller cert), the
// agent cert is also signed by the controller. In the four-key advanced
// shape (handle_cert is the identifier cert), the agent cert is signed by
// the identifier instead.
type IdentityBindingData struct {
	HandleCert hash.Hash       `cbor:"handle_cert"`
	AgentCert  hash.Hash       `cbor:"agent_cert"`
	Label      string          `cbor:"label,omitempty"`
	Metadata   cbor.RawMessage `cbor:"metadata,omitempty"`
}

func (d IdentityBindingData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityBinding, cbor.RawMessage(raw))
}

func IdentityBindingDataFromEntity(e entity.Entity) (IdentityBindingData, error) {
	var d IdentityBindingData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityBindingData{}, err
	}
	return d, nil
}

// IdentityPeerConfigData is the data payload for system/identity/peer-config
// per §3.2. Per-agent local config; not propagated. A host machine may
// operate as multiple agents (one per identity it serves); each agent has
// its own peer-config in its own namespace; peer-configs MUST NOT share
// state across identities.
//
// ControllerGrants applies to the top-level controller cert only per the
// §3.2 resolution rule (sub-controllers are managed via their own V7 caps,
// not via this field).
type IdentityPeerConfigData struct {
	TrustsQuorum     hash.Hash             `cbor:"trusts_quorum"`
	ControllerGrants []GrantEntry          `cbor:"controller_grants"`
	Bindings         []IdentityBindingData `cbor:"bindings,omitempty"`
	Metadata         cbor.RawMessage       `cbor:"metadata,omitempty"`
}

func (d IdentityPeerConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityPeerConfig, cbor.RawMessage(raw))
}

func IdentityPeerConfigDataFromEntity(e entity.Entity) (IdentityPeerConfigData, error) {
	var d IdentityPeerConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityPeerConfigData{}, err
	}
	return d, nil
}

// --- Per-kind property structs (§4) ---

// IdentityCertProperties is the typed properties shape for
// kind="identity-cert" per §4.2. Function is REQUIRED ("controller" |
// "agent" | "identifier" | <app-defined>). Mode is REQUIRED on all certs
// ("internal" | "public" | "per-relationship" | "embedded"). ContactID is
// REQUIRED iff Mode=="per-relationship", forbidden otherwise.
type IdentityCertProperties struct {
	Kind      string     `cbor:"kind"`
	Function  string     `cbor:"function"`
	Mode      string     `cbor:"mode"`
	ContactID *hash.Hash `cbor:"contact_id,omitempty"`
}

// IdentityRotationHandoffProperties is the typed properties shape for
// kind="identity-rotation-handoff" per §4.3. TargetCert references the
// cert being rotated. OldHandle is informational on handoff (handle is
// already known via target_cert chain).
type IdentityRotationHandoffProperties struct {
	Kind       string     `cbor:"kind"`
	TargetCert hash.Hash  `cbor:"target_cert"`
	OldHandle  *hash.Hash `cbor:"old_handle,omitempty"`
}

// IdentityRotationRecoveryProperties is the typed properties shape for
// kind="identity-rotation-recovery" per §4.4. OldHandle is REQUIRED for
// handle-bearing target certs (per §9.4 fail-closed validation);
// implementations cache the prior published_handle under
// system/identity/contacts/{old_handle_hex}/quorum-publish.
type IdentityRotationRecoveryProperties struct {
	Kind       string     `cbor:"kind"`
	TargetCert hash.Hash  `cbor:"target_cert"`
	OldHandle  *hash.Hash `cbor:"old_handle,omitempty"`
}

// IdentityRetirementProperties is the typed properties shape for
// kind="identity-retirement" per §4.5. FinalSupersedes optionally
// references the last live cert in the supersedes chain.
type IdentityRetirementProperties struct {
	Kind            string     `cbor:"kind"`
	TargetCert      hash.Hash  `cbor:"target_cert"`
	FinalSupersedes *hash.Hash `cbor:"final_supersedes,omitempty"`
}

// --- Handler request/result types ---

// IdentityConfigureRequestData is the data payload for
// system/identity/configure-request per §6.1. PublishContactQuorum (as
// quorum-publish attestation) defaults to true; set to false for privacy
// opt-out (compromise-recovery falls back to out-of-band re-establishment).
type IdentityConfigureRequestData struct {
	TrustsQuorum         hash.Hash             `cbor:"trusts_quorum"`
	ControllerGrants     []GrantEntry          `cbor:"controller_grants"`
	Bindings             []IdentityBindingData `cbor:"bindings,omitempty"`
	PublishContactQuorum *bool                 `cbor:"publish_contact_quorum,omitempty"`
}

func (d IdentityConfigureRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityConfigureRequest, cbor.RawMessage(raw))
}

func IdentityConfigureRequestDataFromEntity(e entity.Entity) (IdentityConfigureRequestData, error) {
	var d IdentityConfigureRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityConfigureRequestData{}, err
	}
	return d, nil
}

// IdentityConfigureResultData is the data payload for
// system/identity/configure-result per §6.1.
// LocalPeerToControllerCaps holds one issued cap per live controller under
// the trusted quorum (multi-controller deployments produce multiple per
// §11.6).
type IdentityConfigureResultData struct {
	PeerConfigPath            string      `cbor:"peer_config_path"`
	LocalPeerToControllerCaps []hash.Hash `cbor:"local_peer_to_controller_caps"`
}

func (d IdentityConfigureResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityConfigureResult, cbor.RawMessage(raw))
}

func IdentityConfigureResultDataFromEntity(e entity.Entity) (IdentityConfigureResultData, error) {
	var d IdentityConfigureResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityConfigureResultData{}, err
	}
	return d, nil
}

// IdentityCreateQuorumRequestData is the data payload for
// system/identity/create-quorum-request per §6. Delegates to
// EXTENSION-QUORUM's :create operation; identity additionally records
// the resulting quorum_id in its own peer-config (separate configure call).
//
// Wire shape mirrors EXTENSION-QUORUM §6.1:
// `{signers, threshold, signer_resolution?, name?, metadata?}` (flat).
type IdentityCreateQuorumRequestData struct {
	QuorumData
}

func (d IdentityCreateQuorumRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityCreateQuorumRequest, cbor.RawMessage(raw))
}

func IdentityCreateQuorumRequestDataFromEntity(e entity.Entity) (IdentityCreateQuorumRequestData, error) {
	var d IdentityCreateQuorumRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityCreateQuorumRequestData{}, err
	}
	return d, nil
}

type IdentityCreateQuorumResultData struct {
	QuorumID hash.Hash `cbor:"quorum_id"`
}

func (d IdentityCreateQuorumResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityCreateQuorumResult, cbor.RawMessage(raw))
}

func IdentityCreateQuorumResultDataFromEntity(e entity.Entity) (IdentityCreateQuorumResultData, error) {
	var d IdentityCreateQuorumResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityCreateQuorumResultData{}, err
	}
	return d, nil
}

// IdentityCreateAttestationRequestData is the primary write op for any
// identity-context attestation kind (§6, "create_attestation"). The handler
// dispatches per kind/function/mode (§5.3) to derive the canonical storage
// path, then delegates to ATTESTATION:create. Signatures live in
// envelope.included per V7's signature target-matching pattern.
//
// Wire shape mirrors EXTENSION-ATTESTATION §6.1:
// `{attesting, attested, properties, supersedes?, not_before?, expires_at?}`.
type IdentityCreateAttestationRequestData struct {
	AttestationData
}

func (d IdentityCreateAttestationRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityCreateAttestationRequest, cbor.RawMessage(raw))
}

func IdentityCreateAttestationRequestDataFromEntity(e entity.Entity) (IdentityCreateAttestationRequestData, error) {
	var d IdentityCreateAttestationRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityCreateAttestationRequestData{}, err
	}
	return d, nil
}

// IdentityCreateAttestationResultData is the data payload returned from
// create_attestation. EmbeddedAttestation is set for kind=identity-cert
// mode=embedded (no tree write performed; entity returned for caller-side
// embedding into a cap envelope). Unset for all other modes —
// AttestationHash carries the bound entity's content hash.
type IdentityCreateAttestationResultData struct {
	AttestationHash     hash.Hash        `cbor:"attestation_hash,omitempty"`
	EmbeddedAttestation *AttestationData `cbor:"embedded_attestation,omitempty"`
}

func (d IdentityCreateAttestationResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityCreateAttestationResult, cbor.RawMessage(raw))
}

func IdentityCreateAttestationResultDataFromEntity(e entity.Entity) (IdentityCreateAttestationResultData, error) {
	var d IdentityCreateAttestationResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityCreateAttestationResultData{}, err
	}
	return d, nil
}

// IdentitySupersedeAttestationRequestData is the data payload for
// supersede_attestation per §6. The new attestation's Supersedes field
// references the live attestation it replaces; the handler validates the
// supersedes-chain key per kind.
//
// Wire shape mirrors EXTENSION-ATTESTATION §6.1 (flat):
// `{attesting, attested, properties, supersedes, not_before?, expires_at?}`.
// `supersedes` MUST be set on the request (it's what makes this op a
// supersede vs a fresh create).
type IdentitySupersedeAttestationRequestData struct {
	AttestationData
}

func (d IdentitySupersedeAttestationRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentitySupersedeAttestationRequest, cbor.RawMessage(raw))
}

func IdentitySupersedeAttestationRequestDataFromEntity(e entity.Entity) (IdentitySupersedeAttestationRequestData, error) {
	var d IdentitySupersedeAttestationRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentitySupersedeAttestationRequestData{}, err
	}
	return d, nil
}

type IdentitySupersedeAttestationResultData struct {
	AttestationHash hash.Hash `cbor:"attestation_hash"`
}

func (d IdentitySupersedeAttestationResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentitySupersedeAttestationResult, cbor.RawMessage(raw))
}

func IdentitySupersedeAttestationResultDataFromEntity(e entity.Entity) (IdentitySupersedeAttestationResultData, error) {
	var d IdentitySupersedeAttestationResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentitySupersedeAttestationResultData{}, err
	}
	return d, nil
}

// IdentityRevokeAttestationRequestData is the data payload for
// revoke_attestation per §6. Identity applies its authority-revocation
// rules (only the quorum at the chain root may revoke) — see
// identity_is_authorized_revoker. The revocation itself is a generic
// system/attestation entity with kind="revocation".
type IdentityRevokeAttestationRequestData struct {
	TargetHash hash.Hash `cbor:"target_hash"`
	Reason     string    `cbor:"reason,omitempty"`
}

func (d IdentityRevokeAttestationRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityRevokeAttestationRequest, cbor.RawMessage(raw))
}

func IdentityRevokeAttestationRequestDataFromEntity(e entity.Entity) (IdentityRevokeAttestationRequestData, error) {
	var d IdentityRevokeAttestationRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityRevokeAttestationRequestData{}, err
	}
	return d, nil
}

type IdentityRevokeAttestationResultData struct {
	RevocationHash hash.Hash `cbor:"revocation_hash"`
}

func (d IdentityRevokeAttestationResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityRevokeAttestationResult, cbor.RawMessage(raw))
}

func IdentityRevokeAttestationResultDataFromEntity(e entity.Entity) (IdentityRevokeAttestationResultData, error) {
	var d IdentityRevokeAttestationResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityRevokeAttestationResultData{}, err
	}
	return d, nil
}

// IdentityPublishAttestationRequestData is the data payload for
// publish_attestation per §6. Promotes/demotes a kind=identity-cert
// function=agent attestation across publication modes (§4.2a). ContactID
// is REQUIRED when NewMode == "per-relationship".
type IdentityPublishAttestationRequestData struct {
	AttestationHash hash.Hash  `cbor:"attestation_hash"`
	NewMode         string     `cbor:"new_mode"`
	ContactID       *hash.Hash `cbor:"contact_id,omitempty"`
}

func (d IdentityPublishAttestationRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityPublishAttestationRequest, cbor.RawMessage(raw))
}

func IdentityPublishAttestationRequestDataFromEntity(e entity.Entity) (IdentityPublishAttestationRequestData, error) {
	var d IdentityPublishAttestationRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityPublishAttestationRequestData{}, err
	}
	return d, nil
}

type IdentityPublishAttestationResultData struct {
	NewPath string `cbor:"new_path"`
}

func IdentityPublishAttestationResultDataFromEntity(e entity.Entity) (IdentityPublishAttestationResultData, error) {
	var d IdentityPublishAttestationResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityPublishAttestationResultData{}, err
	}
	return d, nil
}

func (d IdentityPublishAttestationResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityPublishAttestationResult, cbor.RawMessage(raw))
}

// IdentityEventData is the controller-events stream payload per PI-5
// (Rev 3). Emitted on phase-2 handler failure during :process_attestation
// and on partial-failure recovery sites in PI-3 / PI-13. EventSubkind is
// REQUIRED — recovery_signal events are retention-pinned, failure_observation
// events are impl-defined retention.
type IdentityEventData struct {
	EventSubkind    string    `cbor:"event_subkind"`
	HandlerID       string    `cbor:"handler_id"`
	AttestationHash hash.Hash `cbor:"attestation_hash"`
	AttestationKind string    `cbor:"attestation_kind"`
	ErrorCode       string    `cbor:"error_code"`
	ErrorDetail     string    `cbor:"error_detail,omitempty"`
	TimestampMs     uint64    `cbor:"timestamp_ms"`
}

func (d IdentityEventData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeIdentityEvent, cbor.RawMessage(raw))
}

func IdentityEventDataFromEntity(e entity.Entity) (IdentityEventData, error) {
	var d IdentityEventData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityEventData{}, err
	}
	return d, nil
}
