package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Content handler type constants.
const (
	TypeContentGetRequest    = "system/content/get-request"
	TypeContentGetResponse   = "system/content/content-response"
	TypeContentIngestRequest = "system/content/ingest-request"
	TypeContentIngestResult  = "system/content/ingest-result"

	// EXTENSION-CONTENT v3.6 §2 entity types.
	TypeContentBlob       = "system/content/blob"
	TypeContentChunk      = "system/content/chunk"
	TypeContentDescriptor = "system/content/descriptor"

	// STORAGE-SUBSTITUTE-HTTP §3-RES.2 snapshot-manifest entity type.
	// Pinned under system/substitute/* per the storage-substitute
	// cross-impl rulings §3.2 —
	// it's a tree-path index (path→hash) + content commitment, storage-
	// level not content-namespaced; coheres with the rest of the
	// substitute wire types. An OPTIONAL publisher commitment that
	// exposes path-to-hash discovery for consumers that don't already
	// have a root hash. The bare-hash fetch path (Mechanism A) works
	// without a manifest. Manifest processing itself is DEFERRED to v1.1
	// across all three impls per Ruling 5 — the type is reachable on the
	// wire today; no impl validates signatures or freshness on the v1.0
	// conformance path.
	TypeSubstituteSnapshotManifest = "system/substitute/snapshot-manifest"
)

// Chunking algorithm identifiers per §2.1.
const (
	ChunkingFixed   uint64 = 0 // §3.2 fixed-size
	ChunkingFastCDC uint64 = 1 // §3.6 FastCDC/NC2
)

// Protocol-level chunk-size constants per §10.1.
//
// DefaultChunkSize is 1 MiB per CONTENT v3.6 §3.5 (A2 cutover). The §5.5
// chunk_size MUST prerequisite is satisfied (Amendment 3 fix landed in
// de743ec) — incoming blobs encode their chunk_size and the stat-cache
// keys on it, so existing 4 MiB blobs remain valid.
const (
	DefaultChunkSize uint64 = 1 * 1024 * 1024 // 1 MiB target (CONTENT v3.6 §3.5)
	MinChunkSize     uint64 = 64 * 1024       // 64 KiB — also the §4.3 inline-include threshold
	MaxChunkSize     uint64 = 8 * 1024 * 1024 // 8 MiB
)

// ContentBlobData is the data payload for system/content/blob (§2.1).
// All four fields are structural and deterministic for given content and
// chunking parameters. The blob carries no semantic metadata.
type ContentBlobData struct {
	TotalSize uint64      `cbor:"total_size"`
	ChunkSize uint64      `cbor:"chunk_size"`
	Chunking  uint64      `cbor:"chunking"`
	Chunks    []hash.Hash `cbor:"chunks"`
}

// ToEntity creates a system/content/blob entity.
func (d ContentBlobData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContentBlob, cbor.RawMessage(raw))
}

// ContentChunkData is the data payload for system/content/chunk (§2.2).
type ContentChunkData struct {
	Payload []byte `cbor:"payload"`
}

// ToEntity creates a system/content/chunk entity.
func (d ContentChunkData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContentChunk, cbor.RawMessage(raw))
}

// ContentDescriptorData is the data payload for system/content/descriptor (§2.4).
// At least one of MediaType or TypeRef MUST be present (§2.4 presence rule);
// enforced at the publish surface, not by the type system.
type ContentDescriptorData struct {
	Content   hash.Hash        `cbor:"content"`
	MediaType *string          `cbor:"media_type,omitempty"`
	TypeRef   *hash.Hash       `cbor:"type_ref,omitempty"`
	Name      *string          `cbor:"name,omitempty"`
	Metadata  *cbor.RawMessage `cbor:"metadata,omitempty"`
}

// ToEntity creates a system/content/descriptor entity.
func (d ContentDescriptorData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContentDescriptor, cbor.RawMessage(raw))
}

// ContentGetRequestData is the data payload for system/content/get-request.
type ContentGetRequestData struct {
	Hashes []hash.Hash `cbor:"hashes"`
}

// ToEntity creates a system/content/get-request entity.
func (d ContentGetRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContentGetRequest, cbor.RawMessage(raw))
}

// ContentGetResponseData is the data payload for system/content/content-response.
//
// Per CONTENT v3.6 §6.2: Found and Missing are explicit arrays of hashes
// (informative — len(Found) gives the count); fetched entities are
// delivered via the response envelope's Included map (outer wire
// envelope), not inline in this data body. The entity-delivery channel
// is canonical per V7 §3.3 v7.51 envelope-included preservation.
//
// Migration from v3.5: Found/Missing were uint64 counters in Go's
// implementation; v3.6 §6.2 (F4 audit branch) pins arrays of hashes
// matching Rust + Python. Per v3.6 aggregation §3.3.
type ContentGetResponseData struct {
	Found   []hash.Hash `cbor:"found"`
	Missing []hash.Hash `cbor:"missing"`
}

// ToEntity creates a system/content/content-response entity.
func (d ContentGetResponseData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContentGetResponse, cbor.RawMessage(raw))
}

// ContentGetResponseDataFromEntity decodes a content-response entity.
func ContentGetResponseDataFromEntity(e entity.Entity) (ContentGetResponseData, error) {
	var d ContentGetResponseData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContentGetResponseData{}, err
	}
	return d, nil
}

// ContentIngestRequestData is the data payload for system/content/ingest-request.
type ContentIngestRequestData struct {
	Envelope *cbor.RawMessage `cbor:"envelope,omitempty"`
	Entity   *cbor.RawMessage `cbor:"entity,omitempty"`
}

// ToEntity creates a system/content/ingest-request entity.
func (d ContentIngestRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContentIngestRequest, cbor.RawMessage(raw))
}

// ContentIngestResultData is the data payload for system/content/ingest-result.
//
// Per EXTENSION-CONTENT v3.4 §6.3 (PROPOSAL-CONTENT-INGEST-PASS-THROUGH,
// implemented), envelope mode populates Root with the
// original envelope.root entity inlined as a value. This enables
// downstream continuation chain steps to navigate into the wrapper's
// fields (e.g., `extract: "data.root.data.head"`) without dereferencing
// the content store. Absent in entity mode (no envelope wrapper).
type ContentIngestResultData struct {
	Root          *entity.Entity `cbor:"root,omitempty"`
	RootHash      hash.Hash      `cbor:"root_hash"`
	IngestedCount uint64         `cbor:"ingested_count"`
}

// ToEntity creates a system/content/ingest-result entity.
func (d ContentIngestResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContentIngestResult, cbor.RawMessage(raw))
}

// SubstituteSnapshotManifestData is the data payload for the OPTIONAL
// storage-substitute snapshot manifest per STORAGE-SUBSTITUTE-HTTP §3-RES.2
// (v3 — endpoint block replaces the older flat base_url + layout fields).
//
// The manifest exposes path-to-hash discovery for consumers that don't
// already have a root hash. The bare-hash fetch path works without it
// (Mechanism A is self-sufficient via content-trust). A publisher MAY
// ship v1 with no manifest at all; impl teams MAY defer manifest
// consumption.
//
// Manifest processing — signature verify + freshness gate (Ed25519 over
// content_hash, monotonic seq) — is DEFERRED ACROSS ALL THREE IMPLS for
// v1.0 per the storage-substitute cross-impl rulings,
// Ruling 5. The type lands now so it's wire-reachable; no impl validates
// signature/freshness on the v1.0 conformance path. v1.1 lands processing
// in lock-step across Go + Rust + Py (avoids a Python-only conformance
// edge). When v1.1 ships: §13.4 MUST signature; consumer rejects unsigned
// or fails-the-freshness-gate manifests.
type SubstituteSnapshotManifestData struct {
	SourcePeerID hash.Hash            `cbor:"source_peer_id"`
	SnapshotAt   uint64               `cbor:"snapshot_at"`
	Seq          uint64               `cbor:"seq"`
	Endpoint     TransportEndpoint    `cbor:"endpoint"`
	PathIndex    map[string]hash.Hash `cbor:"path_index"`
	ContentCount uint64               `cbor:"content_count"`
	RootHashes   []hash.Hash          `cbor:"root_hashes"`
	Predecessor  *hash.Hash           `cbor:"predecessor,omitempty"`
}

// ToEntity creates a system/substitute/snapshot-manifest entity.
func (d SubstituteSnapshotManifestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeSubstituteSnapshotManifest, cbor.RawMessage(raw))
}

// SubstituteSnapshotManifestDataFromEntity decodes a snapshot-manifest entity.
func SubstituteSnapshotManifestDataFromEntity(e entity.Entity) (SubstituteSnapshotManifestData, error) {
	var d SubstituteSnapshotManifestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SubstituteSnapshotManifestData{}, err
	}
	return d, nil
}
