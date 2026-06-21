package types

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// System type constants.
const (
	// TypeCoreEntity is the type_ref marker for "this slot holds a
	// materialized entity {type, data, content_hash}." See TYPE-SYSTEM §8.1
	// and PROPOSAL-TYPE-NAMESPACE-CONVENTIONS. Bare "entity" (the abstract
	// structural root, 2 fields) has no Go constant — nothing references it
	// by name.
	TypeCoreEntity    = "core/entity"
	TypeBounds        = "system/bounds"
	TypeHandler       = "system/handler"
	TypeCapToken      = "system/capability/token"
	TypeCapGrant      = "system/capability/grant"
	TypeCapGrantEntry = "system/capability/grant-entry"
	TypeCapDelegation = "system/capability/delegation-caveats"
	TypeCapPathScope  = "system/capability/path-scope"
	TypeCapIDScope    = "system/capability/id-scope"
	TypeCapRequest         = "system/capability/request"
	TypeCapRevocation      = "system/capability/revocation"
	TypeCapRevokeRequest   = "system/capability/revoke-request"
	TypeCapDelegateRequest = "system/capability/delegate-request"
	TypeCapPolicyEntry     = "system/capability/policy-entry"
	TypeValidateReq   = "system/type/validate-request"
	TypeValidateRes   = "system/type/validate-result"

	TypeHandlerManifest    = "system/handler/manifest"
	TypeHandlerRegisterReq = "system/handler/register-request"
	TypeHandlerRegisterRes = "system/handler/register-result"
	// Unregister takes no params (pattern moved to EXECUTE.resource per V7
	// §3.2 path-as-resource convention; uses empty primitive/any per the
	// empty-params wire shape).

	TypeEnvelope         = "system/envelope"
	TypeTreePath         = "system/tree/path"
	TypeTypeName         = "system/type/name"
	TypePeerID           = "system/peer-id"
	TypeHandlerInterface = "system/handler/interface"
	TypeTreeListingEntry = "system/tree/listing-entry"
)

// BoundsData is the data payload for system/bounds.
type BoundsData struct {
	TTL           *uint64  `cbor:"ttl,omitempty"`
	Budget        *uint64  `cbor:"budget,omitempty"`
	CascadeDepth  *uint64  `cbor:"cascade_depth,omitempty"` // Current cascade depth in emit pathway (G-3, V7 §3.11)
	ChainID       string   `cbor:"chain_id,omitempty"`
	ParentChainID string   `cbor:"parent_chain_id,omitempty"` // Parent chain's chain_id; set when continuation dispatches sub-chain (G-7, V7 §3.11)
	Visited       []string `cbor:"visited,omitempty"`
}

// ToEntity creates a system/bounds entity.
func (d BoundsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeBounds, cbor.RawMessage(raw))
}

// BoundsDataFromEntity decodes a bounds entity's data.
func BoundsDataFromEntity(e entity.Entity) (BoundsData, error) {
	var d BoundsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return BoundsData{}, err
	}
	return d, nil
}

// HandlerManifestData is the data payload for system/handler/manifest.
// This is the registration input — what handler code provides via Manifest().
// The peer builder decomposes it into a handler entity + interface entity.
type HandlerManifestData struct {
	Pattern        string                          `cbor:"pattern"`
	Name           string                          `cbor:"name"`
	Operations     map[string]HandlerOperationSpec `cbor:"operations"`
	MaxScope       []GrantEntry                    `cbor:"max_scope,omitempty"`
	InternalScope  []GrantEntry                    `cbor:"internal_scope,omitempty"`
	ExpressionPath string                          `cbor:"expression_path,omitempty"`
}

// ToEntity creates a system/handler/manifest entity.
func (d HandlerManifestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHandlerManifest, cbor.RawMessage(raw))
}

// HandlerManifestDataFromEntity decodes a handler manifest entity's data.
func HandlerManifestDataFromEntity(e entity.Entity) (HandlerManifestData, error) {
	var d HandlerManifestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HandlerManifestData{}, err
	}
	return d, nil
}

// HandlerData is the data payload for system/handler.
// This is the dispatch target stored at the pattern path. It references the
// interface entity by path and holds private configuration (scope, expression).
type HandlerData struct {
	Interface      string       `cbor:"interface"`
	MaxScope       []GrantEntry `cbor:"max_scope,omitempty"`
	InternalScope  []GrantEntry `cbor:"internal_scope,omitempty"`
	ExpressionPath string       `cbor:"expression_path,omitempty"`
}

// ToEntity creates a system/handler entity.
func (d HandlerData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHandler, cbor.RawMessage(raw))
}

// HandlerDataFromEntity decodes a handler entity's data.
func HandlerDataFromEntity(e entity.Entity) (HandlerData, error) {
	var d HandlerData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HandlerData{}, err
	}
	return d, nil
}

// HandlerInterfaceData is the data payload for system/handler/interface.
// This is the public-facing subset of HandlerData — pattern, name, operations
// only. No scope fields. Used for handler index entries in the tree.
type HandlerInterfaceData struct {
	Pattern    string                          `cbor:"pattern"`
	Name       string                          `cbor:"name"`
	Operations map[string]HandlerOperationSpec `cbor:"operations"`
}

// ToEntity creates a system/handler/interface entity.
func (d HandlerInterfaceData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHandlerInterface, cbor.RawMessage(raw))
}

// HandlerInterfaceDataFromEntity decodes a handler/interface entity's data.
func HandlerInterfaceDataFromEntity(e entity.Entity) (HandlerInterfaceData, error) {
	var d HandlerInterfaceData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HandlerInterfaceData{}, err
	}
	return d, nil
}

// InterfaceData returns the public-facing subset of this handler manifest.
func (d HandlerManifestData) InterfaceData() HandlerInterfaceData {
	return HandlerInterfaceData{
		Pattern:    d.Pattern,
		Name:       d.Name,
		Operations: d.Operations,
	}
}

// HandlerOperationSpec is the data for system/handler/operation-spec.
type HandlerOperationSpec struct {
	InputType  string `cbor:"input_type,omitempty"`
	OutputType string `cbor:"output_type,omitempty"`
}

// CapabilityTokenData is the data payload for system/capability/token.
//
// The Granter field is polymorphic per PROPOSAL-MULTISIG-CORE-PRIMITIVE M1:
// it is either a single identity hash (single-sig) or a MultiGranter struct
// (multi-sig, root-only per M3). The two shapes are distinguished on the wire
// by CBOR major type — see core/types/granter.go.
type CapabilityTokenData struct {
	Grants            []GrantEntry       `cbor:"grants"`
	Granter           Granter            `cbor:"granter"`
	Grantee           hash.Hash          `cbor:"grantee"`
	Parent            *hash.Hash         `cbor:"parent,omitempty"`
	CreatedAt         uint64             `cbor:"created_at"`
	ExpiresAt         *uint64            `cbor:"expires_at,omitempty"`
	NotBefore         *uint64            `cbor:"not_before,omitempty"`
	DelegationCaveats *DelegationCaveats `cbor:"delegation_caveats,omitempty"`
}

// ValidateStructure enforces structural constraints on the token:
//
//   - M3 granter shape (K, N, dedupe via Granter.Validate).
//   - M3 multi-sig root-only rule: multi-sig granter ⇒ parent: null.
//   - SEC-18 zero-grantee rejection (defense-in-depth, fail-fast at
//     issuance — V7 v7.39 PR-3 already rejects unresolvable grantees
//     at chain-walk via `unresolvable_grantee 401`; this check fails
//     a never-resolvable cap at mint time so it doesn't sit in the
//     tree as a confusing audit-trail artifact). Per PLAN-LIFECYCLE-
//     INTEGRATION-VALIDATION.md docket §4.1 option (a). The zero hash
//     cannot correspond to any real `system/peer` entity (no keypair
//     hashes to all-zeros), so a cap with `grantee: zero-hash` is
//     unusable by construction; rejecting at structure-check surfaces
//     the error to the issuer instead of leaving a dud cap bound.
//
// MUST run at chain-walk entry per PROPOSAL-MULTISIG-CORE-PRIMITIVE
// §3.3; SHOULD run at content-store insertion.
func (d CapabilityTokenData) ValidateStructure() error {
	if err := d.Granter.Validate(); err != nil {
		return err
	}
	if d.Granter.IsMulti() && d.Parent != nil {
		return fmt.Errorf("multi-sig capability MUST have parent: null (M3)")
	}
	if d.Grantee.IsZero() {
		// Wrap ErrUnresolvableGrantee so the chain-walk error contract
		// (V7 v7.39 §3.6 / PR-3) holds uniformly whether rejection
		// fires here at structure-check or at the per-link grantee
		// resolution in delegation.go's VerifyChain.
		return fmt.Errorf("%w: capability grantee MUST be a non-zero hash (SEC-18 / V7 v7.39 PR-3 — zero-hash never resolves to a system/peer entity)", ecerrors.ErrUnresolvableGrantee)
	}
	return nil
}

// ToEntity creates a system/capability/token entity.
func (d CapabilityTokenData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeCapToken, cbor.RawMessage(raw))
}

// CapabilityTokenDataFromEntity decodes a capability token entity's data.
func CapabilityTokenDataFromEntity(e entity.Entity) (CapabilityTokenData, error) {
	var d CapabilityTokenData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return CapabilityTokenData{}, err
	}
	return d, nil
}

// CapabilityScope defines include/exclude lists for a single capability dimension.
type CapabilityScope struct {
	Include []string `cbor:"include"`
	Exclude []string `cbor:"exclude,omitempty"`
}

// MarshalCBOR encodes the scope so an unset Include serializes as an empty
// array (`0x80`), not CBOR null (`0xf6`). `include` is typed `list_of(pattern)`
// per V7 §3.6; the ECF corpus pins `[]` and `null` as DISTINCT canonical
// forms (ecf-conformance/conformance-vectors-v1.diag length.1 vs primitive.1)
// and null is not a valid value of a `list_of` field. Without this method,
// fxamacker/cbor encodes a Go nil slice as CBOR null and produces
// cross-impl divergence with Rust + Python (both of which always emit `[]`
// for an empty include list — surfaced by the v7.67 Phase-2 byte-pin
// cohort round-trip).
func (s CapabilityScope) MarshalCBOR() ([]byte, error) {
	include := s.Include
	if include == nil {
		include = []string{}
	}
	type onWire struct {
		Include []string `cbor:"include"`
		Exclude []string `cbor:"exclude,omitempty"`
	}
	return ecf.Encode(onWire{Include: include, Exclude: s.Exclude})
}

// GrantEntry is the data for system/capability/grant-entry.
type GrantEntry struct {
	Handlers    CapabilityScope  `cbor:"handlers"`
	Resources   CapabilityScope  `cbor:"resources"`
	Operations  CapabilityScope  `cbor:"operations"`
	Peers       *CapabilityScope `cbor:"peers,omitempty"`
	Constraints cbor.RawMessage  `cbor:"constraints,omitempty"` // primitive/map — narrowing fields
	Allowances  cbor.RawMessage  `cbor:"allowances,omitempty"`  // primitive/map — expanding fields
}

// CapabilityGrantData is the data payload for system/capability/grant.
type CapabilityGrantData struct {
	Token hash.Hash `cbor:"token"`
}

// ToEntity creates a system/capability/grant entity.
func (d CapabilityGrantData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeCapGrant, cbor.RawMessage(raw))
}

// DelegationCaveats is the data for system/capability/delegation-caveats.
type DelegationCaveats struct {
	NoDelegation       *bool   `cbor:"no_delegation,omitempty"`
	MaxDelegationDepth *uint64 `cbor:"max_delegation_depth,omitempty"`
	MaxDelegationTTL   *uint64 `cbor:"max_delegation_ttl,omitempty"`
}

// CapabilityRequestData is the data payload for system/capability/request.
type CapabilityRequestData struct {
	Grants []GrantEntry `cbor:"grants"`
	TTLMs  *uint64      `cbor:"ttl_ms,omitempty"`
}

// ToEntity creates a system/capability/request entity.
func (d CapabilityRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeCapRequest, cbor.RawMessage(raw))
}

// CapabilityRevocationData is the data payload for system/capability/revocation
// — the persisted revocation MARKER bound at system/capability/revocations/{cap_hash_hex}.
// Per V7 v7.62 §6.2 + §2a, `revoked_at` is handler-set wall-clock millis since
// Unix epoch and caller-supplied values are ignored at the input boundary
// (replay-surface defense). The input type for the revoke op is
// CapabilityRevokeRequestData, not this.
type CapabilityRevocationData struct {
	Token     hash.Hash `cbor:"token"`
	Reason    string    `cbor:"reason,omitempty"`
	RevokedAt uint64    `cbor:"revoked_at"`
}

// ToEntity creates a system/capability/revocation entity.
func (d CapabilityRevocationData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeCapRevocation, cbor.RawMessage(raw))
}

// CapabilityRevokeRequestData is the input type for system/capability:revoke.
// Per V7 v7.62 §10. Same shape as CapabilityRevocationData minus revoked_at,
// which the handler sets from server wall-clock at marker construction.
type CapabilityRevokeRequestData struct {
	Token  hash.Hash `cbor:"token"`
	Reason string    `cbor:"reason,omitempty"`
}

// ToEntity creates a system/capability/revoke-request entity.
func (d CapabilityRevokeRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeCapRevokeRequest, cbor.RawMessage(raw))
}

// CapabilityDelegateRequestData is the input type for system/capability:delegate.
// Per V7 v7.62 §9. Self-attenuation only in v1 — the handler enforces
// `parent.grantee == caller's authenticated identity` (direct-hold). No
// `grantee` field; future amendment may introduce third-party delegation
// with explicit auth rules.
type CapabilityDelegateRequestData struct {
	Parent hash.Hash    `cbor:"parent"`
	Grants []GrantEntry `cbor:"grants"`
	TTLMs  *uint64      `cbor:"ttl_ms,omitempty"`
}

// ToEntity creates a system/capability/delegate-request entity.
func (d CapabilityDelegateRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeCapDelegateRequest, cbor.RawMessage(raw))
}

// CapabilityPolicyEntryData is the data payload for system/capability/policy-entry,
// also the input type for system/capability:configure. Per V7 v7.62 §4.
//
// PeerPattern is one of exactly two forms:
//   - A specific peer identity hash in V7 §3.5 invariant-pointer hex form
//     (66 hex chars including format-code byte): e.g., "00abc123...".
//   - The literal wildcard "*" (default-for-unknown-peers).
//
// Partial-prefix patterns are NOT valid and MUST be rejected. The path the
// entry is bound at is system/capability/policy/{peer_pattern}.
type CapabilityPolicyEntryData struct {
	PeerPattern string       `cbor:"peer_pattern"`
	Grants      []GrantEntry `cbor:"grants"`
	TTLMs       *uint64      `cbor:"ttl_ms,omitempty"`
	Notes       string       `cbor:"notes,omitempty"`
}

// ToEntity creates a system/capability/policy-entry entity.
func (d CapabilityPolicyEntryData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeCapPolicyEntry, cbor.RawMessage(raw))
}

// CapabilityPolicyEntryDataFromEntity decodes a policy-entry entity's data.
func CapabilityPolicyEntryDataFromEntity(e entity.Entity) (CapabilityPolicyEntryData, error) {
	var d CapabilityPolicyEntryData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return CapabilityPolicyEntryData{}, err
	}
	return d, nil
}

// ValidateRequestData is the data payload for system/type/validate-request.
// Per EXTENSION-TYPE v1.1 §8.3.
type ValidateRequestData struct {
	Entity   cbor.RawMessage `cbor:"entity"`
	TypePath string          `cbor:"type_path,omitempty"`
}

// ToEntity creates a system/type/validate-request entity.
func (d ValidateRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeValidateReq, cbor.RawMessage(raw))
}

// ValidateResultData is the data payload for system/type/validate-result.
// Per EXTENSION-TYPE v1.1 §8.4: violations carry kind ∈ {structural,
// constraint, unknown_constraint}; unevaluated_fields lists open-type
// extension fields the validator detected but could not interpret.
type ValidateResultData struct {
	Valid             bool        `cbor:"valid"`
	Violations        []Violation `cbor:"violations,omitempty"`
	UnevaluatedFields []string    `cbor:"unevaluated_fields,omitempty"`
}

// ToEntity creates a system/type/validate-result entity.
func (d ValidateResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeValidateRes, cbor.RawMessage(raw))
}

// RegisterRequestData is the data payload for system/handler/register-request.
// V7 §3.12: register-request carries a manifest (system/handler/manifest)
// rather than inline name/pattern/operations fields.
type RegisterRequestData struct {
	Manifest       HandlerManifestData       `cbor:"manifest"`
	Types          map[string]TypeDefinition `cbor:"types,omitempty"`
	RequestedScope []GrantEntry              `cbor:"requested_scope,omitempty"`
}

// ToEntity creates a system/handler/register-request entity.
func (d RegisterRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHandlerRegisterReq, cbor.RawMessage(raw))
}

// RegisterResultData is the data payload for system/handler/register-result.
// V7 §3.12: result carries the confirmed pattern and the handler's capability token.
type RegisterResultData struct {
	Pattern string              `cbor:"pattern"`
	Grant   CapabilityTokenData `cbor:"grant"`
}

// ToEntity creates a system/handler/register-result entity.
func (d RegisterResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHandlerRegisterRes, cbor.RawMessage(raw))
}
