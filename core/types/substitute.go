package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// EXTENSION-SUBSTITUTE v1.0 §2.1 — substrate types for the substitute-source
// extension. A substitute source is an ordered, signed authority claim that
// peer P endorses some intermediary as a legitimate place to fetch content
// originally authored by P. The chain-consultation hook (CONTENT v3.7
// miss-hook companion, §5) walks these entries on a local content miss and
// dispatches each to its convention-extension handler
// (system/substitute/<type>:try). EXTENSION-SUBSTITUTE consolidates the
// prior PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-{SOURCES,HTTP} proposals
// (landed) — substrate §1–§6/§8–§10 + HTTP convention as §7.
const (
	TypeSubstituteSource     = "system/substitute/source"
	TypeSubstituteTryRequest = "system/substitute/try-request"
)

// OpSubstituteTry is the operation name registered by every substitute
// convention handler (e.g. ext/storagesubstitutehttp registers
// "system/substitute/http" with op "try"). The chain orchestrator
// invokes <handler-uri>:try with a TypeSubstituteTryRequest entity.
const OpSubstituteTry = "try"

// Standard substitute_type values per §2.3. Convention extensions register
// a handler at system/substitute/<type>:try; the consultation algorithm
// finds it via normal handler dispatch (no in-process type registry).
//
// For substitute_type = "http", the endpoint shape is the shared
// TransportEndpoint (matches NETWORK §6.5.3 http-poll profile). The value
// "http" (not the prior "static-cdn") is pinned per the
// storage-substitute cross-impl rulings §3.2 — it's
// HTTP transport; we don't know what's behind the origin (bucket, nginx,
// python3 -m http.server).
const (
	SubstituteTypeHTTP       = "http"
	SubstituteTypePeerToPeer = "peer-to-peer" // future
	SubstituteTypeNixCache   = "nix-cache"    // future
)

// Capability paths per §2.5.
//
//   - CapContentSubstituteConsult — pre-flight gate on whether the chain is
//     consulted at all (this extension; cheap; fails fast).
//   - CapStorageSubstituteHTTPFetch — the outbound HTTP fetch performed by
//     the convention extension (Mechanism A — inline HTTP GET +
//     hash-verify, NOT BRIDGE-HTTP which is Mechanism B per Round-6 #3 +
//     GUIDE-EXTENSION-DEVELOPMENT §3.7). §2.5's "bridge-http-fetch (or
//     sibling)" wording leaves latitude; we name the Mechanism-A-specific
//     cap to avoid implying any BRIDGE-HTTP coupling.
//   - system/content:ingest (CONTENT) — lands successfully-fetched bytes.
const (
	CapContentSubstituteConsult   = "system/capability/content-substitute-consult"
	CapStorageSubstituteHTTPFetch = "system/capability/storage-substitute-http-fetch"
)

// SubstituteSourcePathPrefix is where substitute-source entities live in the
// tree per §2.1 (peer-relative; NOT under system/content/* — clean
// namespace separation from CONTENT). Entries bind at
// SubstituteSourcePathPrefix + {substitute_hash}.
const SubstituteSourcePathPrefix = "system/substitute/sources/"

// SubstituteSourceData is the data payload for system/substitute/source per
// §2.1 (v3-post-Round-6 shape — endpoint structured object preferred,
// fetch_template legacy fallback).
//
// Endpoint is opaque CBOR — its shape varies by SubstituteType. For
// "http" the encoded shape is TransportEndpoint; convention extensions
// for other types may use different shapes. Consumers decode Endpoint
// per the SubstituteType they handle (see HTTPEndpoint helper).
//
// Per §2.4 trust contract, signature MUST be present (carried in envelope
// refs, not data). The signature is over the entry's content hash and MUST
// be by SourcePeerID's identity key. Unsigned entries are rejected at
// consultation time.
type SubstituteSourceData struct {
	Name           string          `cbor:"name"`
	SubstituteType string          `cbor:"substitute_type"`
	SourcePeerID   hash.Hash       `cbor:"source_peer_id"`
	Endpoint       cbor.RawMessage `cbor:"endpoint,omitempty"`
	FetchTemplate  string          `cbor:"fetch_template,omitempty"` // legacy; deprecated for new entries
	Priority       int64           `cbor:"priority"`
	Enabled        bool            `cbor:"enabled"`
	ExpiresAt      uint64          `cbor:"expires_at,omitempty"`
	Supersedes     *hash.Hash      `cbor:"supersedes,omitempty"`
}

// ToEntity creates a system/substitute/source entity.
func (d SubstituteSourceData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeSubstituteSource, cbor.RawMessage(raw))
}

// SubstituteSourceDataFromEntity decodes a substitute-source entity.
func SubstituteSourceDataFromEntity(e entity.Entity) (SubstituteSourceData, error) {
	var d SubstituteSourceData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SubstituteSourceData{}, err
	}
	return d, nil
}

// HTTPEndpoint decodes the SubstituteSourceData's opaque Endpoint payload
// as a TransportEndpoint — valid when SubstituteType is "http" per §2.1
// endpoint-shape-per-substitute_type note. Returns the zero value and
// false if Endpoint is empty (legacy entries using FetchTemplate instead).
func (d SubstituteSourceData) HTTPEndpoint() (TransportEndpoint, bool, error) {
	if len(d.Endpoint) == 0 {
		return TransportEndpoint{}, false, nil
	}
	var ep TransportEndpoint
	if err := ecf.Decode(d.Endpoint, &ep); err != nil {
		return TransportEndpoint{}, false, err
	}
	return ep, true, nil
}

// NewHTTPSource is a convenience constructor for the most common case —
// an http substitute entry advertising a TransportEndpoint. It encodes
// the endpoint and returns the data ready for ToEntity (callers wire the
// signature via the envelope refs at publish time).
func NewHTTPSource(name string, sourcePeerID hash.Hash, endpoint TransportEndpoint, priority int64) (SubstituteSourceData, error) {
	encEndpoint, err := ecf.Encode(endpoint)
	if err != nil {
		return SubstituteSourceData{}, err
	}
	return SubstituteSourceData{
		Name:           name,
		SubstituteType: SubstituteTypeHTTP,
		SourcePeerID:   sourcePeerID,
		Endpoint:       cbor.RawMessage(encEndpoint),
		Priority:       priority,
		Enabled:        true,
	}, nil
}

// SubstituteTryRequestData is the data payload for system/substitute/try-request
// per Ruling 2. The chain orchestrator constructs one of these per
// substitute entry and dispatches it to system/substitute/<type>:try.
//
// Entry carries the FULL system/substitute/source entity (not its hash) —
// the convention handler needs the source's endpoint + substitute_type
// to perform the fetch, and a hash would force a re-lookup the handler
// shouldn't need (Ruling 2 reasoning).
//
// Hash is the content hash the handler is being asked to fetch. The
// handler returns the fetched entity directly (raw, no wrapper) on
// success per Ruling 3; not_found / error responses use the standard
// handler-result error mechanism.
type SubstituteTryRequestData struct {
	Entry entity.Entity `cbor:"entry"`
	Hash  hash.Hash     `cbor:"hash"`
}

// ToEntity creates a system/substitute/try-request entity.
func (d SubstituteTryRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeSubstituteTryRequest, cbor.RawMessage(raw))
}

// SubstituteTryRequestDataFromEntity decodes a try-request entity.
func SubstituteTryRequestDataFromEntity(e entity.Entity) (SubstituteTryRequestData, error) {
	var d SubstituteTryRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SubstituteTryRequestData{}, err
	}
	return d, nil
}
