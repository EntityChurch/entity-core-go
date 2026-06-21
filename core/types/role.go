package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// EXTENSION-ROLE v1.6 type constants. The role extension defines four
// entity types — system/role (definition), system/role/assignment,
// system/role/exclusion, and system/role/derived-token-link — plus the
// request/result types for the seven handler operations: define, assign,
// unassign, exclude, unexclude, re-derive, delegate.
//
// Spec: ../entity-core-architecture/docs/architecture/v7.0-core-revision/
// core-protocol-domain/specs/extensions/EXTENSION-ROLE.md (v1.6 —
// landing per PROPOSAL-ROLE-V1.5-SPEC-FIXES).
const (
	// Entity types (§2).
	TypeRole                 = "system/role"
	TypeRoleAssignment       = "system/role/assignment"
	TypeRoleExclusion        = "system/role/exclusion"
	TypeRoleDerivedTokenLink = "system/role/derived-token-link"

	// Initial-grant policy (§4.7 / SI-28). Stored at the singleton path
	// system/role/initial-grant-policy. Configures how unknown peers
	// (peers with no explicit role assignment) are treated at AUTHENTICATE
	// time. Three modes: anonymous-deny (default), anonymous-allow,
	// recognize-on-attestation.
	TypeRoleInitialGrantPolicy = "system/role/initial-grant-policy"

	// Initial-grant policy mode constants (§4.7).
	InitialGrantModeDeny              = "anonymous-deny"
	InitialGrantModeAllow             = "anonymous-allow"
	InitialGrantModeRecognizeOnAttest = "recognize-on-attestation"

	// Handler request/result types (§4.2).
	TypeRoleDefineRequest   = "system/role/define-request"
	TypeRoleDefineResult    = "system/role/define-result"
	TypeRoleAssignRequest   = "system/role/assign-request"
	TypeRoleAssignResult    = "system/role/assign-result"
	TypeRoleUnassignResult  = "system/role/unassign-result"
	TypeRoleExcludeResult   = "system/role/exclude-result"
	TypeRoleUnexcludeResult = "system/role/unexclude-result"
	TypeRoleReDeriveRequest = "system/role/re-derive-request"
	TypeRoleReDeriveResult  = "system/role/re-derive-result"
	TypeRoleDelegateRequest = "system/role/delegate-request"
	TypeRoleDelegateResult  = "system/role/delegate-result"
)

// RoleData is the data payload for system/role (§2.1). A role is a named
// bundle of capability grant entries that the role handler issues as
// capability tokens when a peer is assigned to the role within a context.
//
// Grants is the same five-dimensional grant-entry shape used in capability
// tokens (core §3.6); template variables {context} and {peer_id} in path
// values are resolved at grant-issuance time per §5.2. Metadata is an
// optional extension point for domain-specific fields (e.g., ttl).
type RoleData struct {
	Name     string          `cbor:"name"`
	Grants   []GrantEntry    `cbor:"grants"`
	Metadata cbor.RawMessage `cbor:"metadata,omitempty"`
}

func (d RoleData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRole, cbor.RawMessage(raw))
}

func RoleDataFromEntity(e entity.Entity) (RoleData, error) {
	var d RoleData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleData{}, err
	}
	return d, nil
}

// RoleAssignmentData is the data payload for system/role/assignment (§2.2).
// Stored at system/role/{context}/assignment/{peer_id}/{role_name}; binds a
// peer identity to a role within a context. The {role_name} final segment
// supports multi-role per (peer, context) per R6.
type RoleAssignmentData struct {
	Role       string          `cbor:"role"`
	AssignedBy hash.Hash       `cbor:"assigned_by"`
	AssignedAt uint64          `cbor:"assigned_at"`
	Metadata   cbor.RawMessage `cbor:"metadata,omitempty"`
}

func (d RoleAssignmentData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleAssignment, cbor.RawMessage(raw))
}

func RoleAssignmentDataFromEntity(e entity.Entity) (RoleAssignmentData, error) {
	var d RoleAssignmentData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleAssignmentData{}, err
	}
	return d, nil
}

// RoleExclusionData is the data payload for system/role/exclusion (§2.3,
// v1.6). Stored at system/role/{context}/excluded/{peer_id_hex} where
// {peer_id_hex} is lowercase hex of the excluded peer's system/peer
// content_hash (§3.1). Denies the peer all role-derived access within
// the context; takes precedence over an active assignment.
//
// v1.6 SI-3 change: the body peer_id field was removed (redundant with
// the path segment, which carries the same value). Earlier impls had
// invented divergent encodings for the body field while the path was
// Base58 — both sources of drift are closed in v1.6 (the path is hex of
// system/hash, and the body field is gone).
type RoleExclusionData struct {
	ExcludedBy hash.Hash `cbor:"excluded_by"`
	ExcludedAt uint64    `cbor:"excluded_at"`
	Reason     string    `cbor:"reason,omitempty"`
}

func (d RoleExclusionData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleExclusion, cbor.RawMessage(raw))
}

func RoleExclusionDataFromEntity(e entity.Entity) (RoleExclusionData, error) {
	var d RoleExclusionData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleExclusionData{}, err
	}
	return d, nil
}

// RoleDerivedTokenLinkData is the data payload for
// system/role/derived-token-link (§2.4, v1.6 SI-5). Stored at
// system/role/{context}/derived-tokens/{peer_id_hex}/{role_name} —
// sibling subtree alongside assignment/ and excluded/ (NOT nested under
// the assignment entity).
//
// One linkage entity per (peer, role, context) tuple maps the assignment
// to the role-derived capability token issued for it. Re-derive may
// briefly leave multiple linkage entities during overlap; the handler
// iterates all and tie-breaks by IssuedAt descending. Used by:
//   - unassign / exclude — to find role-derived caps to revoke (§6.4.1)
//   - re-derive — to identify T_old before issuing T_new (§5.5)
//   - delegate — to identify the parent cap when delegator holds the role
//     (§5.6 / SI-22)
type RoleDerivedTokenLinkData struct {
	TokenHash hash.Hash `cbor:"token_hash"`
	IssuedAt  uint64    `cbor:"issued_at"`
}

func (d RoleDerivedTokenLinkData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleDerivedTokenLink, cbor.RawMessage(raw))
}

func RoleDerivedTokenLinkDataFromEntity(e entity.Entity) (RoleDerivedTokenLinkData, error) {
	var d RoleDerivedTokenLinkData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleDerivedTokenLinkData{}, err
	}
	return d, nil
}

// RoleInitialGrantPolicyData is the data payload for the singleton entity
// at system/role/initial-grant-policy (§4.7 / RA-6). Configures how
// unknown peers (peers with no explicit role assignment in the relevant
// context) are treated at AUTHENTICATE-time grant resolution.
//
// Modes:
//
//   - "anonymous-deny" (default): unknown peers receive no role-derived
//     grants on their connection cap. Connection authenticates but caller
//     has only whatever the connection handler ships by default
//     (typically nothing in production).
//
//   - "anonymous-allow": unknown peers receive a connection cap whose
//     grants come from the named DefaultRole in DefaultContext. Public-
//     facing deployments (open-source projects, public blogs).
//
//   - "recognize-on-attestation": unknown KEYPAIR but presents an agent-
//     cert chain to a controller cert that the local peer recognizes
//     (signed by peer-config.trusts_quorum, OR TOFU-cached). Recognized
//     peers receive the DefaultRole grants; unrecognized peers fall back
//     to anonymous-deny (or anonymous-allow if IdentityRequired=false).
//
// IdentityRequired only meaningful in recognize-on-attestation mode:
// when true (recommended for closed networks), unrecognized peers are
// rejected; when false, unrecognized peers fall back to anonymous-allow.
//
// Layer-2 exclusion (per §6.1) takes precedence over the policy: an
// excluded peer is rejected regardless of mode.
type RoleInitialGrantPolicyData struct {
	UnknownPeer      string `cbor:"unknown_peer"`
	DefaultRole      string `cbor:"default_role,omitempty"`
	DefaultContext   string `cbor:"default_context,omitempty"`
	IdentityRequired bool   `cbor:"identity_required,omitempty"`
}

func (d RoleInitialGrantPolicyData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleInitialGrantPolicy, cbor.RawMessage(raw))
}

func RoleInitialGrantPolicyDataFromEntity(e entity.Entity) (RoleInitialGrantPolicyData, error) {
	var d RoleInitialGrantPolicyData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleInitialGrantPolicyData{}, err
	}
	return d, nil
}

// --- Handler request/result types (§4.2) ---

// RoleDefineRequestData is the data payload for system/role/define-request
// (§4.2, IA11). The handler validates the proposed grants against the
// caller's capability (RL2 at definition-write time, §9.6) and triggers
// re-derive cascade per §5.5. Resource path in EXECUTE.resource is the
// role-definition path (system/role/{context}/{role_name}).
type RoleDefineRequestData struct {
	Grants   []GrantEntry    `cbor:"grants"`
	Metadata cbor.RawMessage `cbor:"metadata,omitempty"`
}

func (d RoleDefineRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleDefineRequest, cbor.RawMessage(raw))
}

func RoleDefineRequestDataFromEntity(e entity.Entity) (RoleDefineRequestData, error) {
	var d RoleDefineRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleDefineRequestData{}, err
	}
	return d, nil
}

// RoleDefineResultData is the result of system/role:define. ReDerivedCount
// reflects re-derive cascade triggered by definition mutation (§5.5); zero
// on first definition.
type RoleDefineResultData struct {
	RolePath       string `cbor:"role_path"`
	ReDerivedCount uint64 `cbor:"re_derived_count,omitempty"`
}

func (d RoleDefineResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleDefineResult, cbor.RawMessage(raw))
}

func RoleDefineResultDataFromEntity(e entity.Entity) (RoleDefineResultData, error) {
	var d RoleDefineResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleDefineResultData{}, err
	}
	return d, nil
}

// RoleAssignRequestData is the data payload for system/role/assign-request
// (§4.2). The role-name selector; the assignment path (with context and
// assignee peer-id) is in EXECUTE.resource per V7 §3.2.
type RoleAssignRequestData struct {
	Role string `cbor:"role"`
}

func (d RoleAssignRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleAssignRequest, cbor.RawMessage(raw))
}

func RoleAssignRequestDataFromEntity(e entity.Entity) (RoleAssignRequestData, error) {
	var d RoleAssignRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleAssignRequestData{}, err
	}
	return d, nil
}

// RoleAssignResultData is the result of system/role:assign. DerivedTokens
// are the hashes of the capability tokens issued to the assignee per §5.1.
type RoleAssignResultData struct {
	AssignmentPath string      `cbor:"assignment_path"`
	DerivedTokens  []hash.Hash `cbor:"derived_tokens,omitempty"`
}

func (d RoleAssignResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleAssignResult, cbor.RawMessage(raw))
}

func RoleAssignResultDataFromEntity(e entity.Entity) (RoleAssignResultData, error) {
	var d RoleAssignResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleAssignResultData{}, err
	}
	return d, nil
}

// RoleUnassignResultData carries the path of the removed assignment and the
// hashes of any role-derived tokens revoked per §4.4 IA12 (the three-step
// flow: remove assignment, locate role-derived tokens, mark revoked).
type RoleUnassignResultData struct {
	AssignmentPath     string      `cbor:"assignment_path"`
	RevokedTokenHashes []hash.Hash `cbor:"revoked_token_hashes,omitempty"`
}

func (d RoleUnassignResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleUnassignResult, cbor.RawMessage(raw))
}

func RoleUnassignResultDataFromEntity(e entity.Entity) (RoleUnassignResultData, error) {
	var d RoleUnassignResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleUnassignResultData{}, err
	}
	return d, nil
}

// RoleExcludeResultData carries the exclusion path and the hashes of any
// role-derived tokens revoked by the layer-1 sweep per §6.1.
//
// Spec ambiguity: §4.1 declares exclude's output_type as
// system/role/exclude-result but does not specify its fields. We mirror
// re-derive's shape — path + revoked-hashes list — as the natural fit
// given §6.1's layer-1 sweep semantics. Flagged for spec follow-up.
type RoleExcludeResultData struct {
	ExclusionPath      string      `cbor:"exclusion_path"`
	RevokedTokenHashes []hash.Hash `cbor:"revoked_token_hashes,omitempty"`
}

func (d RoleExcludeResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleExcludeResult, cbor.RawMessage(raw))
}

func RoleExcludeResultDataFromEntity(e entity.Entity) (RoleExcludeResultData, error) {
	var d RoleExcludeResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleExcludeResultData{}, err
	}
	return d, nil
}

// RoleUnexcludeResultData carries the path of the removed exclusion entity.
// Removing the exclusion does NOT auto-restore role-derived tokens — those
// are gone from the layer-1 sweep; re-assignment is required (§6.4).
type RoleUnexcludeResultData struct {
	ExclusionPath string `cbor:"exclusion_path"`
}

func (d RoleUnexcludeResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleUnexcludeResult, cbor.RawMessage(raw))
}

func RoleUnexcludeResultDataFromEntity(e entity.Entity) (RoleUnexcludeResultData, error) {
	var d RoleUnexcludeResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleUnexcludeResultData{}, err
	}
	return d, nil
}

// RoleReDeriveRequestData is the data payload for system/role/re-derive-request
// (§4.2 R5). Re-issues role-derived tokens for all assignees of a context
// after a role-definition mutation. Resource path in EXECUTE.resource is
// the role-definition path; Role selector identifies which role.
type RoleReDeriveRequestData struct {
	Role string `cbor:"role"`
}

func (d RoleReDeriveRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleReDeriveRequest, cbor.RawMessage(raw))
}

func RoleReDeriveRequestDataFromEntity(e entity.Entity) (RoleReDeriveRequestData, error) {
	var d RoleReDeriveRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleReDeriveRequestData{}, err
	}
	return d, nil
}

// RoleReDeriveResultData is the result of system/role:re-derive. Per §5.5
// IA9, the cascade issues T_new before revoking T_old per assignee; the
// result reports counts and hash lists for both legs. Per v1.6 SI-15,
// SkippedGrantees lists assignees skipped due to RL2 failure mid-cascade
// (they retain T_old). Each grantee is the system/hash of the assignee's
// identity entity — same form as the cap's grantee field, same form as
// the {peer_id_hex} path segment expressed as raw bytes. Type uniformity
// with RevokedTokenHashes / NewTokenHashes (all are array_of system/hash).
type RoleReDeriveResultData struct {
	ReDerivedCount     uint64      `cbor:"re_derived_count"`
	RevokedTokenHashes []hash.Hash `cbor:"revoked_token_hashes,omitempty"`
	NewTokenHashes     []hash.Hash `cbor:"new_token_hashes,omitempty"`
	SkippedGrantees    []hash.Hash `cbor:"skipped_grantees,omitempty"`
}

func (d RoleReDeriveResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleReDeriveResult, cbor.RawMessage(raw))
}

func RoleReDeriveResultDataFromEntity(e entity.Entity) (RoleReDeriveResultData, error) {
	var d RoleReDeriveResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleReDeriveResultData{}, err
	}
	return d, nil
}

// RoleDelegateRequestData is the data payload for system/role/delegate-request
// (§4.2 / §5.6, v1.6). The delegator delegates a role they hold (or a
// subset of its grants via Scope attenuation) to another peer. The derived
// cap is rooted at the delegator's runtime peer; standard role machinery
// handles revocation and exclusion.
//
// v1.6 changes (SI-4 + SI-21):
//   - Delegator field removed: `ctx.execute.data.author` is authoritative;
//     :delegate MUST run on the delegator's own peer per the SI-19
//     locality invariant (`ctx.local_peer_id == ctx.execute.data.author`).
//   - Context and Role typed as primitive/string (not system/hash) —
//     matches assign-request.role; resolves the schema-vs-§5.6-path-string
//     contradiction in v1.5.
//   - Scope MUST be literal (no template variables); handler rejects
//     with 400 scope_must_be_literal per §5.6 SI-20.
type RoleDelegateRequestData struct {
	Delegate  hash.Hash    `cbor:"delegate"`
	Context   string       `cbor:"context"`
	Role      string       `cbor:"role"`
	Scope     []GrantEntry `cbor:"scope"`
	ExpiresAt *uint64      `cbor:"expires_at,omitempty"`
}

func (d RoleDelegateRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleDelegateRequest, cbor.RawMessage(raw))
}

func RoleDelegateRequestDataFromEntity(e entity.Entity) (RoleDelegateRequestData, error) {
	var d RoleDelegateRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleDelegateRequestData{}, err
	}
	return d, nil
}

// RoleDelegateResultData carries the hash of the issued delegation cap.
type RoleDelegateResultData struct {
	DelegationTokenHash hash.Hash `cbor:"delegation_token_hash"`
}

func (d RoleDelegateResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRoleDelegateResult, cbor.RawMessage(raw))
}

func RoleDelegateResultDataFromEntity(e entity.Entity) (RoleDelegateResultData, error) {
	var d RoleDelegateResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RoleDelegateResultData{}, err
	}
	return d, nil
}
