package types

// EXTENSION-REGISTRY §6a.9 — peer-issued backend live-registration surface.
//
// Curated registration (§6a.8) has the operator sign by hand; live
// registration lets a publisher self-register against a registry that
// runs the `register-request` handler. This file defines the wire entity
// types (request, policy, revoke/renew op inputs) and the capability /
// path constants. The handler itself lives in ext/registry/peerissued.
//
// Domain-control mode (§6a.9.1) is DEFERRED to the web-native domain-proof
// co-design — modes implemented here are open / allowlist / manual.

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Entity type constants per §6a.9.
const (
	TypeRegistryRegisterRequest = "system/registry/register-request"
	TypeRegistryIssuerPolicy    = "system/registry/issuer-policy"
	TypeRegistryRevokeRequest   = "system/registry/revoke-request"
	TypeRegistryRenewRequest    = "system/registry/renew-request"
)

// Issuer-policy mode values per §6a.9.1.
const (
	IssuerPolicyModeOpen           = "open"
	IssuerPolicyModeAllowlist      = "allowlist"
	IssuerPolicyModeManual         = "manual"
	IssuerPolicyModeDomainControl  = "domain-control" // DEFERRED — v1 rejects
)

// Capability constants per §6a.9 closing paragraph.
//
//   - registry-issue-binding         — internal sign+publish act; held by
//                                      the policy logic / operator only.
//   - registry-request-binding       — external surface for publishers
//                                      (open: granted broadly; allowlist: narrow).
//   - registry-manage-issuer-policy  — gates editing the policy.
const (
	CapRegistryIssueBinding        = "system/capability/registry-issue-binding"
	CapRegistryRequestBinding      = "system/capability/registry-request-binding"
	CapRegistryManageIssuerPolicy  = "system/capability/registry-manage-issuer-policy"
)

// REGISTRY-domain error codes per §6a.9 step 4 (V7 §3.3 routing).
//
//   - name_taken:        the requested name already resolves to a binding
//                        in the registry's by-name index.
//   - not_entitled:      layer-2 rejected the request (allowlist miss,
//                        name_constraints miss).
//   - policy_rejected:   manual mode queued, or policy explicitly denied.
//   - replay_detected:   the (target, nonce) pair was already used inside
//                        the issued_at window.
//   - signature_invalid: layer-1 ownership-proof failed (signature not by
//                        target_peer_id, or signature missing).
const (
	RegistryErrNameTaken        = "name_taken"        // 409
	RegistryErrNotEntitled      = "not_entitled"      // 403
	RegistryErrPolicyRejected   = "policy_rejected"   // 403
	RegistryErrReplayDetected   = "replay_detected"   // 409
	RegistryErrSignatureInvalid = "signature_invalid" // 401
)

// IssuerPolicyStoragePath is the canonical path for the singleton
// issuer-policy entity per §6a.9.1 (registry-local config; not synced).
const IssuerPolicyStoragePath = "system/registry/issuer-policy"

// RegistryRegisterRequestData is the data payload for
// system/registry/register-request per §6a.9.
//
// Wire fields:
//   - name:           the requested name (name-path safety per §6.3).
//   - target_peer_id: Base58 peer-id (V7 §1.5) the name resolves to.
//   - transports:     bare hash refs to system/transport entities (same
//                     convention as BindingData.Transports).
//   - requested_ttl:  publisher-suggested binding TTL, ms; policy MAY
//                     clamp to default_ttl.
//   - nonce:          anti-replay; the registry MUST reject a (target, nonce)
//                     pair seen within the issued_at window.
//   - issued_at:      ms-since-epoch; bounds the replay window.
//
// Ownership-proof (Layer 1, §6a.9): the request MUST be accompanied by a
// system/signature whose signer is the system/peer entity for
// target_peer_id, signed over the request's content_hash, at the
// invariant-pointer path system/signature/{hex(request.content_hash)}.
type RegistryRegisterRequestData struct {
	Name         string      `cbor:"name"`
	TargetPeerID string      `cbor:"target_peer_id"`
	Transports   []hash.Hash `cbor:"transports,omitempty"`
	RequestedTTL *uint64     `cbor:"requested_ttl,omitempty"`
	Nonce        []byte      `cbor:"nonce"`
	IssuedAt     uint64      `cbor:"issued_at"`
}

func (d RegistryRegisterRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryRegisterRequest, cbor.RawMessage(raw))
}

func RegistryRegisterRequestDataFromEntity(e entity.Entity) (RegistryRegisterRequestData, error) {
	var d RegistryRegisterRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RegistryRegisterRequestData{}, err
	}
	return d, nil
}

// IssuerPolicyData is the data payload for system/registry/issuer-policy
// per §6a.9.1. Registry-local config — a knob the operator sets, not a
// substrate-wide mandate.
//
//   - mode:             "open" | "allowlist" | "manual" | "domain-control".
//                       v1 rejects "domain-control" (deferred to the
//                       web-native domain-proof co-design).
//   - allowlist:        target_peer_ids permitted when mode == allowlist.
//                       Nil + allowlist mode → all requests fail not_entitled.
//   - name_constraints: optional glob narrowing which names this registry
//                       will issue (e.g. "*.lab"). Nil = no constraint.
//   - default_ttl:      the binding TTL the registry signs when the
//                       request omits requested_ttl, ms. Nil = no expiry.
type IssuerPolicyData struct {
	Mode             string   `cbor:"mode"`
	Allowlist        []string `cbor:"allowlist,omitempty"`
	NameConstraints  *string  `cbor:"name_constraints,omitempty"`
	DefaultTTL       *uint64  `cbor:"default_ttl,omitempty"`
}

func (d IssuerPolicyData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryIssuerPolicy, cbor.RawMessage(raw))
}

func IssuerPolicyDataFromEntity(e entity.Entity) (IssuerPolicyData, error) {
	var d IssuerPolicyData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IssuerPolicyData{}, err
	}
	return d, nil
}

// RegistryRevokeRequestData is the data payload for
// system/registry:revoke-request(binding_hash, reason) per §6a.9 (follow-on
// op). MAY be submitted by the registrant (signed by the binding's
// target_peer_id) or by the operator (signed by the registry).
type RegistryRevokeRequestData struct {
	BindingHash hash.Hash `cbor:"binding_hash"`
	Reason      *string   `cbor:"reason,omitempty"`
}

func (d RegistryRevokeRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryRevokeRequest, cbor.RawMessage(raw))
}

func RegistryRevokeRequestDataFromEntity(e entity.Entity) (RegistryRevokeRequestData, error) {
	var d RegistryRevokeRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RegistryRevokeRequestData{}, err
	}
	return d, nil
}

// RegistryRenewRequestData is the data payload for
// system/registry:renew-request(binding_hash, ttl) per §6a.9 (follow-on op).
// Produces a new binding with supersedes = prior binding_hash and the new ttl.
//
// Replay defense — EXTENSION-REGISTRY v1.2 §6a.9.1 ruling: renew has a
// non-idempotent state effect (replay extends expiry past intended lapse),
// so nonce + issued_at are carried and enforced. revoke is monotonic +
// content-addressed and is NOT defended this way.
//
// Wire fields:
//   - binding_hash: the binding being renewed.
//   - ttl:          new TTL (ms). Optional — nil means "use the registry's
//                   default" (issuer-policy default_ttl, or no expiry).
//   - nonce:        per-request opaque bytes; (target_peer_id, nonce) MUST
//                   be unique inside the registry's issued_at window.
//   - issued_at:    ms-since-epoch when the requester produced the request.
type RegistryRenewRequestData struct {
	BindingHash hash.Hash `cbor:"binding_hash"`
	TTL         *uint64   `cbor:"ttl,omitempty"`
	Nonce       []byte    `cbor:"nonce"`
	IssuedAt    uint64    `cbor:"issued_at"`
}

func (d RegistryRenewRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryRenewRequest, cbor.RawMessage(raw))
}

func RegistryRenewRequestDataFromEntity(e entity.Entity) (RegistryRenewRequestData, error) {
	var d RegistryRenewRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RegistryRenewRequestData{}, err
	}
	return d, nil
}
