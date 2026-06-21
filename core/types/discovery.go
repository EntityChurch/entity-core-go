package types

// EXTENSION-DISCOVERY v1.0 entity types per §2.1, §2.2.1, §3 ScanResult.
//
// Discipline carryover from the P + R cohort cycle:
//
//   1. Base58 peer_id everywhere (V7 §1.5 multikey form, Ruling-1 generalizes).
//      `candidate.peer_id` is Base58 (nullable until IDENTIFY); `identity-claim.
//      peer_id` is Base58 (always present — it is the identity claim).
//   2. No `refs:` blocks. `decision.grant` is a bare `system/hash` referencing
//      a `system/capability/grant` entity (V7 §6.2). `candidate.identity_hint`
//      / `supersedes` / `decision.candidate` are bare `system/hash` per V7 §975
//      target-matching.
//   3. Flat result envelopes. `ScanResult` is a flat entity (slug pinned here
//      as `system/discovery/scan-result`); NOT wrapped under
//      `system/protocol/status` (Ruling-3 generalizes).
//   4. Default-grant the 2 caps to the local peer per §4.1 +
//      [[feedback_dont_drop_default_grants_implement_them]] — wired at peer-
//      builder seed-policy time (D3 scope), constants defined here.
//
// D2 handles the mDNS DNS-SD wire pin (§3.2) and the candidate-storage-prefix
// reap rule (§3.0.1). D3 wires the substrate handlers (`:scan`, `:announce`,
// `:announce-stop`) + IDENTIFY hook for the successor-candidate pattern (§2.2).

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Entity type constants per §2.1, §2.2.1, §3.
const (
	TypeDiscoveryCandidate     = "system/discovery/candidate"
	TypeDiscoveryDecision      = "system/discovery/decision"
	TypeDiscoveryIdentityClaim = "system/discovery/identity-claim"
	// TypeDiscoveryScanResult — flat entity type for the §3 ScanResult shape.
	// Slug pinned at D1 per cohort discipline #3 (flat result envelopes,
	// Ruling-3 generalizes — head off Rust + Py picking three different slugs).
	TypeDiscoveryScanResult = "system/discovery/scan-result"

	// Handler request types per §3.
	TypeDiscoveryScanRequest          = "system/discovery/scan-request"
	TypeDiscoveryAnnounceRequest      = "system/discovery/announce-request"
	TypeDiscoveryAnnounceStopRequest  = "system/discovery/announce-stop-request"
)

// Backend identifiers (§3 / §6 — only mdns is v1-normative; qr / registry-
// assisted / gossip / DHT are §6 staged growth).
const (
	DiscoveryBackendMDNS = "mdns"
)

// Decision outcome values per §2.1. NORMATIVE hyphenated spelling.
const (
	DiscoveryOutcomeIgnore        = "ignore"
	DiscoveryOutcomeTrack         = "track"
	DiscoveryOutcomeGrantLimited  = "grant-limited"
	DiscoveryOutcomeGrantMore     = "grant-more"
)

// DISCOVERY-domain error codes per §3.1 + V7 §3.3 routing.
//
//   - DiscoveryErrScanOverflow → 503 (DISCOVERY-owned per V7 §3.3 — NOT a
//     V7 §4.10 floor code; per-scan-count ceilings are application-layer).
//   - V7 §4.10(a) `413 payload_too_large` covers oversized per-candidate
//     records; reused, not redefined.
const (
	DiscoveryErrScanOverflow = "discovery_scan_overflow"
)

// Default-grant cap names per §4.1 (seed-policy bootstrap grants the local
// peer both caps on first install per
// [[feedback_dont_drop_default_grants_implement_them]]).
const (
	CapDiscoveryScan     = "system/capability/discovery-scan"
	CapDiscoveryAnnounce = "system/capability/discovery-announce"
)

// -----------------------------------------------------------------------
// §2.1 — system/discovery/candidate
// -----------------------------------------------------------------------

// CandidateData is the data payload for system/discovery/candidate per §2.1.
//
// `PeerID` is the Base58 peer-id per V7 §1.5 (nullable until IDENTIFY
// completes — empty string serializes as omitempty so a missing peer-id is
// distinguishable on the wire from one present-but-empty). The successor
// pattern (§2.2) creates a new candidate with PeerID populated and
// Supersedes set to the prior candidate's content_hash; original candidates
// are immutable.
//
// `EndpointHint` is opaque per §2.1 — backend-specific (e.g. LAN address +
// port for mDNS, QR payload for qr). Modeled as cbor.RawMessage so backends
// can pop in whatever structured shape they need without DISCOVERY mandating
// a single envelope.
//
// `IdentityHint` per §2.2.1:
//   - nil → TOFU (the candidate's backend made no identity claim).
//   - non-nil → bare system/hash of an IdentityClaim entity. Post-IDENTIFY,
//     the receiver constructs an IdentityClaim from the actual IDENTIFY
//     result and compares its content_hash; mismatch MUST fail-closed.
type CandidateData struct {
	PeerID       string          `cbor:"peer_id,omitempty"`
	Backend      string          `cbor:"backend"`
	ObservedAt   uint64          `cbor:"observed_at"`
	EndpointHint cbor.RawMessage `cbor:"endpoint_hint,omitempty"`
	IdentityHint *hash.Hash      `cbor:"identity_hint,omitempty"`
	Supersedes   *hash.Hash      `cbor:"supersedes,omitempty"`
}

func (d CandidateData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDiscoveryCandidate, cbor.RawMessage(raw))
}

func CandidateDataFromEntity(e entity.Entity) (CandidateData, error) {
	var d CandidateData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return CandidateData{}, err
	}
	return d, nil
}

// CandidateStoragePath returns the canonical watchable-prefix storage path
// per §3.0:
//
//	system/discovery/candidate/{backend}/{candidate_id}
//
// `candidate_id` is the lowercase-hex content_hash of the candidate entity
// (per the standard {hash_hex} convention used by BindingStoragePath +
// RevocationStoragePath). Live consumers subscribe to
// `system/discovery/candidate/{backend}/*` and react to add/remove per
// §3.0.1 reap rules.
func CandidateStoragePath(backend string, candidateHash hash.Hash) string {
	return "system/discovery/candidate/" + backend + "/" + PeerIdentityHashHex(candidateHash)
}

// CandidatePrefix returns the per-backend watchable prefix per §3.0:
//
//	system/discovery/candidate/{backend}/
//
// Subscription consumers (§2 grant-prompt UI, reactive browsers) listen on
// this prefix. Trailing slash ensures prefix-match excludes other backend
// names that share a common prefix.
func CandidatePrefix(backend string) string {
	return "system/discovery/candidate/" + backend + "/"
}

// -----------------------------------------------------------------------
// §2.1 — system/discovery/decision
// -----------------------------------------------------------------------

// DecisionData is the data payload for system/discovery/decision per §2.1.
//
// `Candidate` references the *head of the candidate chain* per §2.2 — for
// a candidate that has gone through the IDENTIFY successor pattern, this
// is the post-IDENTIFY candidate (with PeerID populated), not the original
// observation.
//
// `Grant` is a bare system/hash to a system/capability/grant entity per
// V7 §6.2 — refless target-matching (V7 §975), NOT a refs: block (§8.4
// MUST NOT). Nil for `ignore` / `track` outcomes; non-nil for `grant-
// limited` / `grant-more`.
type DecisionData struct {
	Candidate hash.Hash  `cbor:"candidate"`
	Outcome   string     `cbor:"outcome"`
	Grant     *hash.Hash `cbor:"grant,omitempty"`
	DecidedAt uint64     `cbor:"decided_at"`
}

func (d DecisionData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDiscoveryDecision, cbor.RawMessage(raw))
}

func DecisionDataFromEntity(e entity.Entity) (DecisionData, error) {
	var d DecisionData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return DecisionData{}, err
	}
	return d, nil
}

// -----------------------------------------------------------------------
// §2.2.1 — system/discovery/identity-claim
// -----------------------------------------------------------------------

// IdentityClaimData is the data payload for system/discovery/identity-claim
// per §2.2.1.
//
// The candidate's `IdentityHint` is the bare content_hash of an
// IdentityClaim with these fields populated from the claimed peer's V7 §1.5
// multikey. Post-IDENTIFY, the receiver reconstructs an IdentityClaim from
// the *actual* IDENTIFY result and computes its content_hash; equality with
// the candidate's hint is required for admission. Mismatch → MUST fail
// closed (§8.4).
//
// `PublicKeyDigest` is the raw V7 §1.5 public-key digest bytes — NOT a
// system/hash (no format-code prefix). The triple {KeyType, HashType,
// PublicKeyDigest} together with PeerID reproduces the multikey-canonical
// form a verifier reconstructs at IDENTIFY-complete time.
type IdentityClaimData struct {
	PeerID          string `cbor:"peer_id"`
	KeyType         uint64 `cbor:"key_type"`
	HashType        uint64 `cbor:"hash_type"`
	PublicKeyDigest []byte `cbor:"public_key_digest"`
}

func (d IdentityClaimData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDiscoveryIdentityClaim, cbor.RawMessage(raw))
}

func IdentityClaimDataFromEntity(e entity.Entity) (IdentityClaimData, error) {
	var d IdentityClaimData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return IdentityClaimData{}, err
	}
	return d, nil
}

// -----------------------------------------------------------------------
// §3 — system/discovery/scan-result (flat entity, slug pinned at D1)
// -----------------------------------------------------------------------

// ScanResultData is the data payload for system/discovery/scan-result per §3.
//
// Flat shape per cohort discipline #3 — Ruling-3 generalizes. NOT wrapped
// under system/protocol/status.
//
//   - Candidates: bare system/hash list (BARE per §3 — they reference
//     CandidateData entities living under CandidatePrefix(backend)).
//   - Truncated: true when per-scan candidate-count ceiling was exceeded.
//   - Code: nil normally; "discovery_scan_overflow" when truncated, per
//     §3.1 (DISCOVERY-owned 503; NOT silent truncation per §8.4 MUST NOT).
type ScanResultData struct {
	Candidates []hash.Hash `cbor:"candidates"`
	Truncated  bool        `cbor:"truncated"`
	Code       *string     `cbor:"code,omitempty"`
}

func (d ScanResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDiscoveryScanResult, cbor.RawMessage(raw))
}

func ScanResultDataFromEntity(e entity.Entity) (ScanResultData, error) {
	var d ScanResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ScanResultData{}, err
	}
	return d, nil
}

// -----------------------------------------------------------------------
// §3 — handler request types
// -----------------------------------------------------------------------

// ScanRequestData — system/discovery:scan(backend, filter?). Filter is
// opaque + backend-MAY-ignore per §3.3.
type ScanRequestData struct {
	Backend string                     `cbor:"backend"`
	Filter  map[string]cbor.RawMessage `cbor:"filter,omitempty"`
}

func (d ScanRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDiscoveryScanRequest, cbor.RawMessage(raw))
}

func ScanRequestDataFromEntity(e entity.Entity) (ScanRequestData, error) {
	var d ScanRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ScanRequestData{}, err
	}
	return d, nil
}

// AnnounceRequestData — system/discovery:announce(backend, profile_ref).
// `ProfileRef` is the transport-profile path-segment per NETWORK §6.5
// (e.g. an http-poll / tcp / webrtc profile id under
// `system/peer/transport/{peer}/{profile-id}`).
type AnnounceRequestData struct {
	Backend    string `cbor:"backend"`
	ProfileRef string `cbor:"profile_ref"`
}

func (d AnnounceRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDiscoveryAnnounceRequest, cbor.RawMessage(raw))
}

func AnnounceRequestDataFromEntity(e entity.Entity) (AnnounceRequestData, error) {
	var d AnnounceRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AnnounceRequestData{}, err
	}
	return d, nil
}

// AnnounceStopRequestData — system/discovery:announce-stop(backend, profile_ref).
type AnnounceStopRequestData struct {
	Backend    string `cbor:"backend"`
	ProfileRef string `cbor:"profile_ref"`
}

func (d AnnounceStopRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDiscoveryAnnounceStopRequest, cbor.RawMessage(raw))
}

func AnnounceStopRequestDataFromEntity(e entity.Entity) (AnnounceStopRequestData, error) {
	var d AnnounceStopRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AnnounceStopRequestData{}, err
	}
	return d, nil
}
