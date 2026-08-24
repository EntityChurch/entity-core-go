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

	// TypeRegistryPendingBinding is the entity `pending_hash` names —
	// RULED 2026-08-13, EXTENSION-REGISTRY v1.3 §6a.9.3 (arch `f162953`).
	//
	// This replaces `system/registry/pending-registration`, which this file
	// invented on 2026-08-12 and flagged PROVISIONAL at the point of
	// invention. The history is worth keeping because it is the cleanest
	// example in this repo of a spec defect the cohort could not resolve by
	// building harder: the 08-12 ruling made `pending_hash` a MUST and
	// pointed it at an entity whose schema was a reserved heading, so all
	// three seats were simultaneously correct and mutually incompatible —
	// rust withheld the value (you cannot hash an unspecified shape), py
	// invented `system/registry/register-pending` plus an approve op, go
	// invented this type, and go's own oracle FAILed rust for the omission.
	// Arch's rule out of it: a MUST may not name a referent the corpus does
	// not define; if the referent waits, the MUST waits with it.
	//
	// Clean break, no alias for the old name (pre-1.0, AGENTS.md "no
	// backward-compat shims"). py `d6cfbda` still ships `register-pending`
	// and says in-source that "this type renames with it" — expected, and
	// tracked as a cohort delta rather than a py defect.
	TypeRegistryPendingBinding = "system/registry/pending-binding"
	TypeRegistryIssuerPolicy   = "system/registry/issuer-policy"
	TypeRegistryRevokeRequest  = "system/registry/revoke-request"
	TypeRegistryRenewRequest   = "system/registry/renew-request"

	// §6a.9.3 operator-decision inputs. The section's table gives their input
	// as a bare `{pending_hash}` / `{pending_hash, reason?}` shape and names
	// no entity type — py declares no `input_type` for `approve-request`
	// either (`manifest.py`, py `d6cfbda`). These names are ours, and the
	// handler decodes by SHAPE rather than asserting the type, so a peer
	// sending a differently-typed params entity still interoperates. Routed
	// as a spec ambiguity: §6a.9 already recorded that an operation whose
	// declared surface omits a branch is "an interop bug already in flight,"
	// and an unnamed input type is the same hole one field up.
	TypeRegistryApproveRequest = "system/registry/approve-request"
	TypeRegistryDenyRequest    = "system/registry/deny-request"
)

// Pending-binding decision states per §6a.9.3.
//
// `denied` is a STATE, not a deletion: "a denied request MUST leave a
// `status: "denied"` head reachable through the by-request pointer; the
// registry MUST NOT simply remove the entry." A requester polling a vanished
// pointer cannot tell *denied* from *never received*, which is a silent drop.
const (
	PendingStatusPendingReview = "pending_review"
	PendingStatusApproved      = "approved"
	PendingStatusDenied        = "denied"
)

// RegisterResult status values — the field that discriminates the outcomes
// §6a.9 pins for register-request. `bound` is the signed-and-published answer
// (200); `pending_review` is manual mode's queued answer (202).
//
// CORRECTED 2026-08-13: this was `registered`, and §6a.9 pins **`bound`**
// (EXTENSION-REGISTRY, the ruled signature at arch `81e73ae`:
// `return 200 register-result { status: "bound", binding_hash }`).
//
// It was a live cross-peer MUST divergence on the discriminator field itself,
// and the comment above it claimed to implement §6a.9 the whole time. **Nothing
// caught it because nothing asserted it** — no check in `registry_issuer`
// looked at the 200's `status` value at all, so the wrong string passed every
// gate in every run. Found by `entity-core-rust` while applying the same
// ruling, not by us.
//
// That is exactly the class our own conformance-register census is for, one
// level down: the citation resolved, the surface was green, and the assertion
// simply did not exist. `registry_issuer.register_result_status_bound` now
// asserts it (added in the same change), so the value cannot drift again
// unobserved.
//
// `denied` is the THIRD value, added 2026-08-13 by §6a.9.3's operations
// table (`deny-request` → `register-result {status: "denied"}`).
//
// CLOSED 2026-08-14 by REGISTRY v1.4. v1.3 introduced a branch its own
// declared return type did not enumerate — §6a.9 read `"bound" |
// "pending_review"`, two values — which is precisely the defect §6a.9
// recorded about ITSELF one screen up, recurring one subsection later. All
// three implementations emitted `"denied"` as the table said and all three
// routed the enumeration gap; v1.4 adds the value to the declaration and
// pins that **both `binding_hash` and `pending_hash` are absent on
// `"denied"`** — the request is decided and nothing was issued. We already
// emit exactly that (`RegistryRegisterResultData{Status: denied}`, no hash
// fields; ext/registry/peerissued/register.go).
//
// This comment previously ended "and route the declaration gap" and would
// have read as an open item indefinitely. A citation is a build-state claim
// about a document and decays the same way.
const (
	RegisterStatusBound         = "bound"
	RegisterStatusPendingReview = "pending_review"
	RegisterStatusDenied        = "denied"
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

	// RegistryErrAlreadyDecided — §6a.9.3, 409. A second approve/deny on a
	// pending head that already carries a decision. Approve and deny are not
	// idempotent-by-replay: re-approving would mint a SECOND binding for one
	// request, so the safe-looking "just return the first outcome again"
	// reading is the unsafe one.
	RegistryErrAlreadyDecided = "already_decided" // 409
)

// PendingBindingData is a register-request held for operator review, per
// §6a.9.3's schema. Adopted verbatim from py's worked shape, which arch
// ratified rather than replaced — the field set below is field-for-field
// what `registry.py:1188` writes (py `d6cfbda`), plus the two decision-
// carrying optionals the ruling adds.
//
// The prior go shape carried the request BY HASH (`request`, `received_at`)
// and denormalized only name + target. That is NOT what the ruling adopted:
// a pending head must be self-sufficient for the operator's decision, so the
// terms being approved — transports and requested_ttl — are inlined rather
// than reachable only through a second fetch of the request entity.
type PendingBindingData struct {
	// Name is NFC-normalized and name-path-safe per §6.3.
	Name string `cbor:"name"`

	// TargetPeerID is the Base58 peer-id (V7 §1.5) the name would resolve to.
	TargetPeerID string `cbor:"target_peer_id"`

	// Transports are the endpoint refs the binding would carry (same bare-
	// hash-ref convention as BindingData.Transports).
	Transports []hash.Hash `cbor:"transports,omitempty"`

	// RequestedTTL is the publisher-suggested TTL in ms, already clamped to
	// the policy default when the request omitted one — so an approval that
	// happens weeks later issues the terms the operator reviewed, not the
	// terms the policy holds at approval time.
	RequestedTTL *uint64 `cbor:"requested_ttl,omitempty"`

	// QueuedAt is when the registry queued it (ms since epoch).
	//
	// This is a LOCAL wall-clock reading and it is deliberately part of the
	// hashed body. §6a.9.3 rules explicitly that pending_hash "is registry-
	// local and MUST NOT be gated on cross-peer reproducibility": no second
	// registry stores a pending, §8 aggregators republish bindings and not
	// pendings, and the only obligation is that the hash resolves at the
	// registry that minted it. Stated here because every OTHER content-hash
	// ruling in the corpus runs the opposite way (EXTENSION-COMPUTE §2.4
	// materialized errors must agree byte-for-byte), so an implementer
	// generalizing from those would strip this field chasing a determinism
	// this surface does not require.
	QueuedAt uint64 `cbor:"queued_at"`

	// Status is one of the three PendingStatus* values.
	Status string `cbor:"status"`

	// BindingHash is REQUIRED on `approved`, absent otherwise — the binding
	// the approval issued.
	BindingHash *hash.Hash `cbor:"binding_hash,omitempty"`

	// Reason is OPTIONAL on `denied`. Operator-supplied and NEVER parsed:
	// no conformance check may assert on it (§6a.9's "error strings are
	// free; codes are the contract" applied to the decision surface).
	Reason *string `cbor:"reason,omitempty"`
}

// ToEntity encodes the pending binding.
func (d PendingBindingData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryPendingBinding, cbor.RawMessage(raw))
}

// PendingBindingDataFromEntity decodes a pending binding.
func PendingBindingDataFromEntity(e entity.Entity) (PendingBindingData, error) {
	var d PendingBindingData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PendingBindingData{}, err
	}
	return d, nil
}

// Decided reports whether this head already carries an operator decision.
// §6a.9.3: a second decision on either outcome returns 409 already_decided,
// because approve and deny are not idempotent-by-replay and re-approving
// would mint a second binding for one request.
func (d PendingBindingData) Decided() bool {
	return d.Status == PendingStatusApproved || d.Status == PendingStatusDenied
}

// PendingBindingPath is the immutable content-addressed body path per
// §6a.9.3:
//
//	system/registry/pending/{pending_hash}
//
// Same 66-char hex form (format byte included) as BindingStoragePath —
// §3's universal `binding/{binding_hash}` rule, which this mirrors.
func PendingBindingPath(h hash.Hash) string {
	return PendingBindingPrefix + PeerIdentityHashHex(h)
}

// PendingBindingPrefix is the body prefix.
const PendingBindingPrefix = "system/registry/pending/"

// PendingBindingByRequestPath is the mutable pointer to the CURRENT HEAD for
// one (target_peer_id, name) pair per §6a.9.3:
//
//	system/registry/pending/by-request/{target_peer_id}/{name}
//
// **The segment order is normative and it is not the obvious one.** A
// target_peer_id is a single Base58 segment; a `name` is name-path-safe but
// NOT guaranteed single-segment (§6.3 pathes names directly, and
// `binding/local-name/{name}` already relies on that). Putting the
// variable-depth value LAST is what keeps the prefix parseable and keeps
// `pending/by-request/{peer}/` enumerable at a fixed depth. The same defect
// was corrected in EXTENSION-NETWORK §4.1 the same day; do not "tidy" this
// into name-first.
//
// `name` MUST already be NFC-normalized — the path embeds it verbatim.
func PendingBindingByRequestPath(targetPeerID, normalizedName string) string {
	return PendingBindingByRequestPrefix + targetPeerID + "/" + normalizedName
}

// PendingBindingByRequestPrefix is what an operator walks to enumerate the
// review queue. §6a.9.3 defines NO `list-pending` operation on purpose: a
// tree walk over this prefix already answers it, and adding an op for a list
// a tree walk answers is the live-registry cost the coral-reef posture (§7.4)
// exists to avoid.
const PendingBindingByRequestPrefix = "system/registry/pending/by-request/"

// PendingBindingByPeerPrefix returns the enumerable per-peer prefix — the
// thing the segment order above buys.
func PendingBindingByPeerPrefix(targetPeerID string) string {
	return PendingBindingByRequestPrefix + targetPeerID + "/"
}

// RegistryDecisionRequestData is the input shape shared by `approve-request`
// and `deny-request` per §6a.9.3's operations table. `reason` is meaningful
// only on deny.
//
// Decoded by shape, not by entity type — see TypeRegistryApproveRequest.
type RegistryDecisionRequestData struct {
	PendingHash hash.Hash `cbor:"pending_hash"`
	Reason      *string   `cbor:"reason,omitempty"`
}

// ToApproveEntity / ToDenyEntity are separate constructors on purpose. An
// earlier draft picked the type from `Reason != nil`, which silently
// mistypes a deny that carries no reason — and `reason` is OPTIONAL on deny,
// so that is the ordinary case, not the edge one.
func (d RegistryDecisionRequestData) ToApproveEntity() (entity.Entity, error) {
	return d.toEntity(TypeRegistryApproveRequest)
}

func (d RegistryDecisionRequestData) ToDenyEntity() (entity.Entity, error) {
	return d.toEntity(TypeRegistryDenyRequest)
}

func (d RegistryDecisionRequestData) toEntity(t string) (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(t, cbor.RawMessage(raw))
}

func RegistryDecisionRequestDataFromEntity(e entity.Entity) (RegistryDecisionRequestData, error) {
	var d RegistryDecisionRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RegistryDecisionRequestData{}, err
	}
	return d, nil
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
