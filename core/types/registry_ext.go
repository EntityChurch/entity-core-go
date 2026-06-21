package types

// EXTENSION-REGISTRY v1.0 entity types + handler request/result types.
//
// This file is named registry_ext.go rather than registry.go because Go's
// `core/types/registry.go` already defines the TypeRegistry runtime
// (type-system bookkeeping). The names collide; the on-disk file split is
// the only side effect. The wire-type names below — system/registry/* —
// follow the spec verbatim.

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Entity type constants per EXTENSION-REGISTRY §3, §3.1, §4, §6.4, §11.2.
//
// Erratum (Ruling-4 — `petname` → `local-name`): the §6 backend
// renamed from `petname` to `local-name` after the user-directed naming
// review. Substrate unchanged; identifying strings only.
const (
	TypeRegistryBinding         = "system/registry/binding"
	TypeRegistryRevocation      = "system/registry/revocation"
	TypeRegistryResolverConfig  = "system/registry/resolver-config"
	TypeRegistryLocalNameConfig = "system/registry/local-name-config"
	TypeRegistryResolutionLog   = "system/registry/resolution-log"

	// Handler request / result types.
	TypeRegistryResolveRequest = "system/registry/resolve-request"
	// TypeRegistryResolveResult: wire entity type for ResolutionResult per
	// EXTENSION-REGISTRY §2.1 (Ruling-3, cross-impl-run absorption).
	// MUST be system/registry/resolution-result on the wire with flat data
	// fields — MUST NOT wrap under system/protocol/status. The Go const name
	// is retained as ResolveResult for source-compat; the wire string moved.
	TypeRegistryResolveResult            = "system/registry/resolution-result"
	TypeRegistryInvalidateCacheRequest   = "system/registry/invalidate-cache-request"
	TypeRegistryLocalNameBindRequest     = "system/registry/local-name/bind-request"
	TypeRegistryLocalNameBindResult      = "system/registry/local-name/bind-result"
	TypeRegistryLocalNameUnbindRequest   = "system/registry/local-name/unbind-request"
	TypeRegistryLocalNameListRequest     = "system/registry/local-name/list-request"
	TypeRegistryLocalNameListResult      = "system/registry/local-name/list-result"
	TypeRegistryLocalNameUpdateTransports = "system/registry/local-name/update-transports-request"
	TypeRegistryLocalNameListEntry       = "system/registry/local-name/list-entry"
	TypeRegistryPinnedEntry              = "system/registry/pinned-entry"
	TypeRegistryDispatchEntry            = "system/registry/dispatch-entry"
	TypeRegistryResolverChainEntry       = "system/registry/resolver-chain-entry"
)

// Binding kind values per §3 / §2.4.1 vocabulary mapping (NORMATIVE
// hyphenated spelling — cross-impl convergence pin).
const (
	BindingKindSelfCertifying    = "self-certifying"
	BindingKindLocalName         = "local-name"
	BindingKindDNSTXT            = "dns-txt"
	BindingKindWellKnownURL      = "well-known-url"
	BindingKindDIDWeb            = "did-web"
	BindingKindPeerIssued        = "peer-issued"
	BindingKindOutOfBand         = "out-of-band"
	BindingKindConsensusAnchored = "consensus-anchored"
)

// backend_kind enum values (resolver-config.resolver_chain[].backend_kind).
// Per Ruling-4: the §6 backend identifier and binding kind are
// now both `local-name` — the prior `petname` / `local-petname` asymmetry
// the §2.4.1 vocab table called out is GONE; both axes use the same string.
const (
	BackendKindSelfCertifying    = "self-certifying"
	BackendKindLocalName         = "local-name"
	BackendKindDNSTXT            = "dns-txt"
	BackendKindWellKnownURL      = "well-known-url"
	BackendKindDIDWeb            = "did-web"
	BackendKindPeerIssued        = "peer-issued"
	BackendKindOutOfBand         = "out-of-band"
	BackendKindConsensusAnchored = "consensus-anchored"
)

// ResolutionStatus values per §2.1 ResolutionResult.status enum.
const (
	ResolutionStatusResolved        = "resolved"
	ResolutionStatusNotFound        = "not_found"
	ResolutionStatusChainExhausted  = "chain_exhausted"
)

// TrustAnchor wire-form values per §2.4. NORMATIVE (underscored — §2.4.1
// notes these are discriminator strings, distinct from the hyphenated
// kind/backend_kind enums).
const (
	TrustAnchorSelfCertifying = "self_certifying"
	TrustAnchorLocalName      = "local_name"
	TrustAnchorOutOfBand      = "out_of_band"
	// `dns_txt:{zone}[:dnssec]`, `well_known_url:{domain}`, `did_web:{domain}`,
	// `peer_issued:{registry_peer_id}`, `consensus_anchored:{chain}:{block}`
	// are constructed at runtime — backend-qualified strings.
)

// CaseNormalization values per §6.4 local-name-config.
const (
	CaseNormalizationNone  = "none"
	CaseNormalizationLower = "lower"
)

// REGISTRY-domain error codes per §6.5 + V7 §3.3 routing.
const (
	RegistryErrBindInvalidName    = "bind_invalid_name"    // 400
	RegistryErrBindAlreadyExists  = "bind_already_exists"  // 409
)

// REGISTRY default-grant cap names per §5.2 (NORMATIVE: bootstrap seed
// policy grants the local peer all seven on first install per
// `[[feedback_dont_drop_default_grants_implement_them]]`).
const (
	CapRegistryResolve        = "system/capability/registry-resolve"
	CapRegistryConfigure      = "system/capability/registry-configure"
	CapRegistryPin            = "system/capability/registry-pin"
	CapRegistryCacheControl   = "system/capability/registry-cache-control"
	CapRegistryLocalNameBind  = "system/capability/registry-local-name-bind"
	CapRegistryLocalNameUnbind = "system/capability/registry-local-name-unbind"
	CapRegistryLocalNameList  = "system/capability/registry-local-name-list"
)

// -----------------------------------------------------------------------
// §3 — system/registry/binding
// -----------------------------------------------------------------------

// BindingData is the data payload for system/registry/binding per §3.
//
// `target_peer_id` is the BASE58 peer-id (V7 §1.5 multikey form), NOT a
// content-hash. Self-certifying naming uses this string directly; other
// kinds rely on the registry/authority signature for trust.
//
// Bare-hash field shape: Supersedes and IssuerAttestation are bare
// system/hash values (33 bytes, `0x00`+digest), NOT wrapped in any
// envelope. Same convention as ATTESTATION supersedes.
//
// Signatures (for non-self-certifying, non-local-name kinds) live separately
// at the V7 §5.2/§975 invariant pointer `system/signature/{hex(binding.
// content_hash)}` per §3 — NOT in a refs: block. LocalNames and self-
// certifying bindings carry no signature (per the §3 + §6.3 carve-outs).
type BindingData struct {
	Name              string                     `cbor:"name"`
	Kind              string                     `cbor:"kind"`
	TargetPeerID      string                     `cbor:"target_peer_id"`
	Transports        []hash.Hash                `cbor:"transports,omitempty"`
	IssuedAt          uint64                     `cbor:"issued_at"`
	TTL               *uint64                    `cbor:"ttl,omitempty"`
	Supersedes        *hash.Hash                 `cbor:"supersedes,omitempty"`
	IssuerAttestation *hash.Hash                 `cbor:"issuer_attestation,omitempty"`
	Metadata          map[string]cbor.RawMessage `cbor:"metadata,omitempty"`
}

// ToEntity creates a system/registry/binding entity.
func (d BindingData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryBinding, cbor.RawMessage(raw))
}

// BindingDataFromEntity decodes a system/registry/binding entity's data.
func BindingDataFromEntity(e entity.Entity) (BindingData, error) {
	var d BindingData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return BindingData{}, err
	}
	return d, nil
}

// BindingStoragePath returns the universal storage path per §3:
//   system/registry/binding/{binding_hash_hex}
// LocalName bindings ADDITIONALLY have a tree pointer at the name-keyed
// path returned by LocalNamePointerPath.
func BindingStoragePath(h hash.Hash) string {
	return "system/registry/binding/" + PeerIdentityHashHex(h)
}

// LocalNamePointerPath returns the §6.3 tree-pointer storage path for a
// local-name binding:
//   system/registry/binding/local-name/{name}
// `name` MUST be NFC-normalized and case-folded per local-name-config before
// being passed here; the path embeds the normalized string verbatim.
func LocalNamePointerPath(normalizedName string) string {
	return "system/registry/binding/local-name/" + normalizedName
}

// PeerIssuedByNamePath returns the peer-issued backend's name-keyed tree
// pointer path per PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2.2:
//   system/registry/binding/by-name/{nfc(name)}
// Direct analog of LocalNamePointerPath, different prefix. `name` MUST be
// NFC-normalized before being passed; the path embeds the normalized string
// verbatim. Name-path safety per §6.3 applies (no `/`, no control chars);
// dots are allowed so `billslab.com` is a valid name.
func PeerIssuedByNamePath(normalizedName string) string {
	return "system/registry/binding/by-name/" + normalizedName
}

// PeerIssuedByNamePrefix is the prefix the peer-issued backend lists when
// enumerating cached / locally-published bindings by name.
const PeerIssuedByNamePrefix = "system/registry/binding/by-name/"

// PeerIssuedRevocationByTargetPath returns the v1 cohort revocation index
// path the peer-issued backend reads to check whether a given binding has
// been revoked: `system/registry/revocation/by-target/{hex33(bindingHash)}`.
// One round-trip vs. scanning the whole revocation prefix. The path is the
// peer-issued backend's read-side convention; revocation entities still
// live at the §3.1 universal location and carry the same signature shape.
func PeerIssuedRevocationByTargetPath(bindingHash hash.Hash) string {
	return "system/registry/revocation/by-target/" + PeerIdentityHashHex(bindingHash)
}

// PeerIssuedTrustAnchor returns the `peer_issued:{registry_id}` trust-anchor
// string per §2.4 / §2.1 step 3. Used both in resolver-config.accepted_
// trust_anchors and in surfaced ResolutionResult.trust_anchor.
func PeerIssuedTrustAnchor(registryPeerID string) string {
	return "peer_issued:" + registryPeerID
}

// -----------------------------------------------------------------------
// §3.1 — system/registry/revocation
// -----------------------------------------------------------------------

// RevocationData is the data payload for system/registry/revocation per §3.1.
// Authenticating signature lives at the invariant-pointer path
// `system/signature/{hex(revocation.content_hash)}` signed by the same
// authority that signed the revoked binding.
type RevocationData struct {
	Revokes   hash.Hash `cbor:"revokes"`
	RevokedAt uint64    `cbor:"revoked_at"`
	Reason    *string   `cbor:"reason,omitempty"`
}

func (d RevocationData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryRevocation, cbor.RawMessage(raw))
}

func RevocationDataFromEntity(e entity.Entity) (RevocationData, error) {
	var d RevocationData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevocationData{}, err
	}
	return d, nil
}

// RevocationStoragePath returns the canonical path
// `system/registry/revocation/{revocation_hash_hex}`.
func RevocationStoragePath(h hash.Hash) string {
	return "system/registry/revocation/" + PeerIdentityHashHex(h)
}

// -----------------------------------------------------------------------
// §4 — system/registry/resolver-config
// -----------------------------------------------------------------------

// ResolverChainEntry — one backend in the resolver chain per §4.
type ResolverChainEntry struct {
	BackendKind          string                     `cbor:"backend_kind"`
	BackendID            string                     `cbor:"backend_id"`
	Priority             uint32                     `cbor:"priority"`
	AcceptedTrustAnchors []string                   `cbor:"accepted_trust_anchors,omitempty"`
	Hints                map[string]cbor.RawMessage `cbor:"hints,omitempty"`
}

// PinnedEntry — one entry in resolver-config.pinned_bindings per §4.
type PinnedEntry struct {
	Name         string  `cbor:"name"`
	TargetPeerID string  `cbor:"target_peer_id"`
	Reason       *string `cbor:"reason,omitempty"`
}

// DispatchEntry — one entry in resolver-config.name_format_dispatch per
// §4. `Pattern` is a POSIX shell-glob matched against the queried name.
type DispatchEntry struct {
	Pattern      string   `cbor:"pattern"`
	BackendKinds []string `cbor:"backend_kinds"`
}

// ResolverConfigData is the data payload for system/registry/resolver-
// config per §4. Two operator-side knobs from the absorption §5.3 land on
// this type rather than local-name-config so they govern the whole resolver
// chain (not just the local-name backend): LogCacheHits + ResolutionLogCapacity.
type ResolverConfigData struct {
	ResolverChain         []ResolverChainEntry `cbor:"resolver_chain"`
	PinnedBindings        []PinnedEntry        `cbor:"pinned_bindings,omitempty"`
	NameFormatDispatch    []DispatchEntry      `cbor:"name_format_dispatch,omitempty"`
	LogCacheHits          bool                 `cbor:"log_cache_hits,omitempty"`
	ResolutionLogCapacity uint32               `cbor:"resolution_log_capacity,omitempty"`
}

func (d ResolverConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryResolverConfig, cbor.RawMessage(raw))
}

func ResolverConfigDataFromEntity(e entity.Entity) (ResolverConfigData, error) {
	var d ResolverConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ResolverConfigData{}, err
	}
	return d, nil
}

// ResolverConfigStoragePath is the canonical path for the singleton
// resolver-config entity (per §4 — "peer-local; not synced").
const ResolverConfigStoragePath = "system/registry/resolver-config"

// -----------------------------------------------------------------------
// §6.4 — system/registry/local-name-config
// -----------------------------------------------------------------------

// LocalNameConfigData is the data payload for system/registry/local-name-
// config per §6.4.
type LocalNameConfigData struct {
	DefaultPinned     bool   `cbor:"default_pinned"`
	AllowSupersede    bool   `cbor:"allow_supersede"`
	CaseNormalization string `cbor:"case_normalization"`
}

func (d LocalNameConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryLocalNameConfig, cbor.RawMessage(raw))
}

func LocalNameConfigDataFromEntity(e entity.Entity) (LocalNameConfigData, error) {
	var d LocalNameConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return LocalNameConfigData{}, err
	}
	return d, nil
}

// LocalNameConfigStoragePath is the canonical path for the singleton
// local-name-config entity (per §6.4).
const LocalNameConfigStoragePath = "system/registry/local-name-config"

// -----------------------------------------------------------------------
// §11.2 — system/registry/resolution-log (SHOULD)
// -----------------------------------------------------------------------

// ResolutionLogData is the data payload for system/registry/resolution-
// log per §11.2. One entry per top-level meta_resolve invocation; cache
// hits MAY be elided per resolver-config.log_cache_hits.
//
// Wire fields per §11.2:
//   - seq:                   per-peer monotonic, persistent across restart
//   - name:                  queried name
//   - backend_id:            which backend answered (null if chain_exhausted)
//   - status:                resolved | not_found | chain_exhausted
//   - reason:                e.g. "signature_failed", "policy_rejected",
//                            "pin_short_circuit" — null on normal-path resolve
//   - binding:               resolved binding hash, null otherwise
//   - attempted_at:          ms-since-epoch
//   - is_fallback_reresolve: true if invoked from §2.3 transport-fallback loop
type ResolutionLogData struct {
	Seq                 uint64     `cbor:"seq"`
	Name                string     `cbor:"name"`
	BackendID           *string    `cbor:"backend_id,omitempty"`
	Status              string     `cbor:"status"`
	Reason              *string    `cbor:"reason,omitempty"`
	Binding             *hash.Hash `cbor:"binding,omitempty"`
	AttemptedAt         uint64     `cbor:"attempted_at"`
	IsFallbackReresolve bool       `cbor:"is_fallback_reresolve,omitempty"`
}

func (d ResolutionLogData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryResolutionLog, cbor.RawMessage(raw))
}

func ResolutionLogDataFromEntity(e entity.Entity) (ResolutionLogData, error) {
	var d ResolutionLogData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ResolutionLogData{}, err
	}
	return d, nil
}

// ResolutionLogPrefix is the storage-path prefix for per-seq resolution
// log entries per §11.2: `system/registry/resolution-log/`. Per-peer
// monotonic seq is recovered on startup by walking this prefix and
// taking max+1.
const ResolutionLogPrefix = "system/registry/resolution-log/"

// ResolutionLogPath returns the per-seq path under ResolutionLogPrefix.
// The seq segment is written as decimal (matches the §11.2 "{seq}" form;
// zero-padding is implementation-defined and not part of the spec).
func ResolutionLogPath(seq uint64) string {
	return ResolutionLogPrefix + decimalUint(seq)
}

// decimalUint renders a uint64 as decimal — small helper to avoid pulling
// `strconv` for a single call site.
func decimalUint(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = '0' + byte(n%10)
		n /= 10
	}
	return string(buf[i:])
}

// -----------------------------------------------------------------------
// Handler request / result types
// -----------------------------------------------------------------------

// ResolveRequestData is the data payload for system/registry:resolve.
type ResolveRequestData struct {
	Name  string                     `cbor:"name"`
	Hints map[string]cbor.RawMessage `cbor:"hints,omitempty"`
}

func (d ResolveRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryResolveRequest, cbor.RawMessage(raw))
}

func ResolveRequestDataFromEntity(e entity.Entity) (ResolveRequestData, error) {
	var d ResolveRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ResolveRequestData{}, err
	}
	return d, nil
}

// ResolveResultData is the ResolutionResult shape per §2.1.
// Status determines which other fields are meaningful:
//   - resolved:        binding + peer_id + transports + trust_anchor + backend_id
//   - not_found:       neg_ttl, backend_id (the backend that said not_found)
//   - chain_exhausted: nothing else (no backend produced a result)
type ResolveResultData struct {
	Status       string      `cbor:"status"`
	Binding      *hash.Hash  `cbor:"binding,omitempty"`
	PeerID       string      `cbor:"peer_id,omitempty"`
	Transports   []hash.Hash `cbor:"transports,omitempty"`
	Attestations []hash.Hash `cbor:"attestations,omitempty"`
	TrustAnchor  string      `cbor:"trust_anchor,omitempty"`
	TTL          *uint64     `cbor:"ttl,omitempty"`
	NegTTL       *uint64     `cbor:"neg_ttl,omitempty"`
	BackendID    string      `cbor:"backend_id,omitempty"`
}

func (d ResolveResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryResolveResult, cbor.RawMessage(raw))
}

func ResolveResultDataFromEntity(e entity.Entity) (ResolveResultData, error) {
	var d ResolveResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ResolveResultData{}, err
	}
	return d, nil
}

// InvalidateCacheRequestData — system/registry:invalidate-cache(name | null).
// Nil Name means "flush all" per §2.1.
type InvalidateCacheRequestData struct {
	Name *string `cbor:"name,omitempty"`
}

func (d InvalidateCacheRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryInvalidateCacheRequest, cbor.RawMessage(raw))
}

func InvalidateCacheRequestDataFromEntity(e entity.Entity) (InvalidateCacheRequestData, error) {
	var d InvalidateCacheRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return InvalidateCacheRequestData{}, err
	}
	return d, nil
}

// LocalNameBindRequestData — system/registry/local-name:bind per §6.5.
type LocalNameBindRequestData struct {
	Name         string      `cbor:"name"`
	TargetPeerID string      `cbor:"target_peer_id"`
	Transports   []hash.Hash `cbor:"transports,omitempty"`
	Notes        *string     `cbor:"notes,omitempty"`
}

func (d LocalNameBindRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryLocalNameBindRequest, cbor.RawMessage(raw))
}

func LocalNameBindRequestDataFromEntity(e entity.Entity) (LocalNameBindRequestData, error) {
	var d LocalNameBindRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return LocalNameBindRequestData{}, err
	}
	return d, nil
}

// LocalNameBindResultData carries the bound binding's content_hash.
type LocalNameBindResultData struct {
	BindingHash hash.Hash `cbor:"binding_hash"`
}

func (d LocalNameBindResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryLocalNameBindResult, cbor.RawMessage(raw))
}

func LocalNameBindResultDataFromEntity(e entity.Entity) (LocalNameBindResultData, error) {
	var d LocalNameBindResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return LocalNameBindResultData{}, err
	}
	return d, nil
}

// LocalNameUnbindRequestData — system/registry/local-name:unbind(name).
type LocalNameUnbindRequestData struct {
	Name string `cbor:"name"`
}

func (d LocalNameUnbindRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryLocalNameUnbindRequest, cbor.RawMessage(raw))
}

func LocalNameUnbindRequestDataFromEntity(e entity.Entity) (LocalNameUnbindRequestData, error) {
	var d LocalNameUnbindRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return LocalNameUnbindRequestData{}, err
	}
	return d, nil
}

// LocalNameListRequestData — system/registry/local-name:list(filter?).
// Filter shape is unspecified in v1 (opaque per §6.5); reserved for
// future use.
type LocalNameListRequestData struct {
	Filter map[string]cbor.RawMessage `cbor:"filter,omitempty"`
}

func (d LocalNameListRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryLocalNameListRequest, cbor.RawMessage(raw))
}

func LocalNameListRequestDataFromEntity(e entity.Entity) (LocalNameListRequestData, error) {
	var d LocalNameListRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return LocalNameListRequestData{}, err
	}
	return d, nil
}

// LocalNameListEntry — one entry returned by :list per §6.5.
type LocalNameListEntry struct {
	Name         string    `cbor:"name"`
	Hash         hash.Hash `cbor:"hash"`
	TargetPeerID string    `cbor:"target_peer_id"`
	Notes        *string   `cbor:"notes,omitempty"`
	Pinned       bool      `cbor:"pinned"`
}

// LocalNameListResultData wraps the entries returned by :list.
type LocalNameListResultData struct {
	Entries []LocalNameListEntry `cbor:"entries"`
}

func (d LocalNameListResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryLocalNameListResult, cbor.RawMessage(raw))
}

func LocalNameListResultDataFromEntity(e entity.Entity) (LocalNameListResultData, error) {
	var d LocalNameListResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return LocalNameListResultData{}, err
	}
	return d, nil
}

// LocalNameUpdateTransportsRequestData — system/registry/local-name:update-
// transports(name, transports) per §6.5. Issues a new binding with
// supersedes = existing.hash and the new transports.
type LocalNameUpdateTransportsRequestData struct {
	Name       string      `cbor:"name"`
	Transports []hash.Hash `cbor:"transports"`
}

func (d LocalNameUpdateTransportsRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryLocalNameUpdateTransports, cbor.RawMessage(raw))
}

func LocalNameUpdateTransportsRequestDataFromEntity(e entity.Entity) (LocalNameUpdateTransportsRequestData, error) {
	var d LocalNameUpdateTransportsRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return LocalNameUpdateTransportsRequestData{}, err
	}
	return d, nil
}
