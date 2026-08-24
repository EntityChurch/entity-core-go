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
	TypeRegistryRegisterResult  = "system/registry/register-result"

	// TypeRegistryPendingRegistration is the entity `pending_hash` names.
	//
	// PROVISIONAL, and said so at the point of invention. Arch ruled
	// 2026-08-12 (d) that pending_hash MUST name "the stored pending entity,
	// not the request" — because a handle the client can already compute is
	// not a handle, and nothing is fetchable at the request's own hash. What
	// arch did NOT specify, and named as owed in the same ruling, is
	// §6a.9.3's approval protocol: there is no spec text for what a queued
	// request looks like at rest, what an operator does to it, or how the
	// requester polls. This type is the minimum that makes the ruled handle
	// real, and it is expected to be replaced — not extended — when §6a.9.3
	// lands.
	TypeRegistryPendingRegistration = "system/registry/pending-registration"
	TypeRegistryIssuerPolicy        = "system/registry/issuer-policy"
	TypeRegistryRevokeRequest       = "system/registry/revoke-request"
	TypeRegistryRenewRequest        = "system/registry/renew-request"
)

// RegisterResult status values — the field that discriminates the outcomes
// §6a.9 pins for register-request. `registered` is the signed-and-published
// answer (200); `pending_review` is manual mode's queued answer (202).
const (
	RegisterStatusRegistered    = "registered"
	RegisterStatusPendingReview = "pending_review"
)

// RegistryRegisterResultData is register-request's OWN result — one entity type for
// the operation, with `status` discriminating the outcome and the hash field
// that matches it.
//
// WHY THIS TYPE EXISTS (2026-08-12 c). register-request had no result type of
// its own here: the 200 borrowed `system/registry/local-name-bind-result` from
// a DIFFERENT operation (the in-source comment said "reuses {binding_hash}
// shape"), and the 202 answered with a system/protocol/error carrying
// `code: pending_review` — an ERROR entity on a SUCCESS status. Measured
// against entity-core-py 2c1aa1b, which answers both statuses with this
// shape: `{status: "registered", binding_hash}` / `{status: "pending_review",
// pending_hash}`. That is the better design and go converged onto it rather
// than the other way round — a client decodes one type per operation and
// branches on a field, instead of decoding a foreign result type on one status
// and an error entity on another.
//
// §6a.9's status table lists `pending_review` under a column headed **Code**,
// which is what produced our error-entity reading. Its own pseudocode says
// `on queue: status "pending_review"`, and no implementation in the cohort
// emits it as an error code any more. Reported to arch as a correction, not
// asked as a question.
type RegistryRegisterResultData struct {
	// Status is `registered` or `pending_review`.
	Status string `cbor:"status"`

	// BindingHash is set iff Status == registered — the published binding.
	BindingHash *hash.Hash `cbor:"binding_hash,omitempty"`

	// PendingHash is set iff Status == pending_review — the handle the
	// operator reviews and the requester polls. Present in py's shape and
	// adopted with it: a queued request a client cannot name again is a
	// dead end, which is the practical argument for the field carrier over
	// an error code.
	PendingHash *hash.Hash `cbor:"pending_hash,omitempty"`
}

// ToEntity encodes the result as a system/registry/register-result entity.
func (d RegistryRegisterResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryRegisterResult, cbor.RawMessage(raw))
}

// RegistryRegisterResultDataFromEntity decodes a register-result entity.
func RegistryRegisterResultDataFromEntity(e entity.Entity) (RegistryRegisterResultData, error) {
	var d RegistryRegisterResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RegistryRegisterResultData{}, err
	}
	return d, nil
}

// Issuer-policy mode values per §6a.9.1.
const (
	IssuerPolicyModeOpen          = "open"
	IssuerPolicyModeAllowlist     = "allowlist"
	IssuerPolicyModeManual        = "manual"
	IssuerPolicyModeDomainControl = "domain-control" // DEFERRED — v1 rejects
)

// Capability constants per §6a.9 closing paragraph.
//
//   - registry-issue-binding         — internal sign+publish act; held by
//     the policy logic / operator only.
//   - registry-request-binding       — external surface for publishers
//     (open: granted broadly; allowlist: narrow).
//   - registry-manage-issuer-policy  — gates editing the policy.
const (
	CapRegistryIssueBinding       = "system/capability/registry-issue-binding"
	CapRegistryRequestBinding     = "system/capability/registry-request-binding"
	CapRegistryManageIssuerPolicy = "system/capability/registry-manage-issuer-policy"
)

// REGISTRY-domain error codes per §6a.9 step 4 (V7 §3.3 routing).
//
//   - name_taken:        the requested name already resolves to a binding
//     in the registry's by-name index.
//   - not_entitled:      layer-2 rejected the request (allowlist miss,
//     name_constraints miss).
//   - policy_rejected:   manual mode queued, or policy explicitly denied.
//   - replay_detected:   the (target, nonce) pair was already used inside
//     the issued_at window.
//   - signature_invalid: layer-1 ownership-proof failed (signature not by
//     target_peer_id, or signature missing).
//   - unsupported_mode:  set-issuer-policy was handed a mode this
//     implementation cannot enforce (§6a.9.2 — today only
//     the deferred `domain-control`). Distinct from the
//     501 the register path returns for an already-stored
//     domain-control policy: this one refuses to store it.
//   - not_found:         get-issuer-policy with no policy entity stored.
//     "Unset is not a mode" (§6a.9.2) — the registry is
//     curated-only, and a synthesized `open` default here
//     would silently make it first-come-first-serve.
const (
	RegistryErrNameTaken        = "name_taken"        // 409
	RegistryErrNotEntitled      = "not_entitled"      // 403
	RegistryErrPolicyRejected   = "policy_rejected"   // 403
	RegistryErrReplayDetected   = "replay_detected"   // 409
	RegistryErrSignatureInvalid = "signature_invalid" // 401
	RegistryErrUnsupportedMode  = "unsupported_mode"  // 400
	RegistryErrNotFound         = "not_found"         // 404
)

// PendingRegistrationData is a register-request held for operator review.
//
// It carries the request BY HASH rather than inlining it: the request entity
// is already stored and already signed at its invariant pointer, and copying
// its fields would create a second place for them to be wrong.
type PendingRegistrationData struct {
	// Request is the content_hash of the register-request entity.
	Request hash.Hash `cbor:"request"`

	// Name and TargetPeerID are denormalized so an operator listing the queue
	// can read it without fetching every request.
	Name         string `cbor:"name"`
	TargetPeerID string `cbor:"target_peer_id"`

	// ReceivedAt is when the registry queued it (ms since epoch).
	ReceivedAt uint64 `cbor:"received_at"`

	// Status is `pending_review` — the only value §6a.9 defines for a queued
	// request. Present so the entity is self-describing when fetched.
	Status string `cbor:"status"`
}

// ToEntity encodes the pending registration.
func (d PendingRegistrationData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryPendingRegistration, cbor.RawMessage(raw))
}

// PendingRegistrationDataFromEntity decodes a pending registration.
func PendingRegistrationDataFromEntity(e entity.Entity) (PendingRegistrationData, error) {
	var d PendingRegistrationData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PendingRegistrationData{}, err
	}
	return d, nil
}

// PendingRegistrationPath is where a queued request is published so the
// handle in `pending_hash` resolves to something. Provisional with the type
// above — §6a.9.3 owns this once it exists.
func PendingRegistrationPath(h hash.Hash) string {
	return "system/registry/pending/" + PeerIdentityHashHex(h)
}

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
//     convention as BindingData.Transports).
//   - requested_ttl:  publisher-suggested binding TTL, ms; policy MAY
//     clamp to default_ttl.
//   - nonce:          anti-replay; the registry MUST reject a (target, nonce)
//     pair seen within the issued_at window.
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
//     v1 rejects "domain-control" (deferred to the
//     web-native domain-proof co-design).
//   - allowlist:        target_peer_ids permitted when mode == allowlist.
//     Nil + allowlist mode → all requests fail not_entitled.
//   - name_constraints: optional glob narrowing which names this registry
//     will issue (e.g. "*.lab"). Nil = no constraint.
//   - default_ttl:      the binding TTL the registry signs when the
//     request omits requested_ttl, ms. Nil = no expiry.
type IssuerPolicyData struct {
	Mode            string   `cbor:"mode"`
	Allowlist       []string `cbor:"allowlist,omitempty"`
	NameConstraints *string  `cbor:"name_constraints,omitempty"`
	DefaultTTL      *uint64  `cbor:"default_ttl,omitempty"`
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
//     default" (issuer-policy default_ttl, or no expiry).
//   - nonce:        per-request opaque bytes; (target_peer_id, nonce) MUST
//     be unique inside the registry's issued_at window.
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
