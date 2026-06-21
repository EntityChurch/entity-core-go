package types

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Tree type constants.
const (
	TypeTreeGetRequest = "system/tree/get-request"
	TypeTreePutRequest = "system/tree/put-request"
	TypeTreeListing    = "system/tree/listing"

	TypeTreeTrackingConfig = "system/tree/tracking-config"

	TypeTreeSnapshot        = "system/tree/snapshot"
	TypeTreeSnapshotNode    = "system/tree/snapshot/node"
	TypeTreeSnapshotRequest = "system/tree/snapshot-request"
	TypeTreeDiff            = "system/tree/diff"
	TypeTreeDiffChange      = "system/tree/diff/change"
	TypeTreeDiffRequest     = "system/tree/diff-request"
	TypeTreeMergeResult     = "system/tree/merge-result"
	TypeTreeMergeConflict   = "system/tree/merge-result/conflict"
	TypeTreeMergeRequest    = "system/tree/merge-request"
	TypeTreeExtractRequest  = "system/tree/extract-request"
	TypeTreePartialResult   = "system/tree/partial-result"
)

// GetRequestData is the data payload for system/tree/get-request.
type GetRequestData struct {
	TreeID string  `cbor:"tree_id,omitempty"`
	Mode   string  `cbor:"mode,omitempty"`
	Limit  *uint64 `cbor:"limit,omitempty"`
	Offset *uint64 `cbor:"offset,omitempty"`
}

// ToEntity creates a system/tree/get-request entity.
func (d GetRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeGetRequest, cbor.RawMessage(raw))
}

// GetRequestDataFromEntity decodes a get-request entity's data.
func GetRequestDataFromEntity(e entity.Entity) (GetRequestData, error) {
	var d GetRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return GetRequestData{}, err
	}
	return d, nil
}

// PutRequestData is the data payload for system/tree/put-request.
// ExpectedHash enables CAS per V7 §3.9 (v7.22 + v7.50 CAS-create variant):
//   - absent (nil):           unconditional put.
//   - present, non-zero hash: succeed iff current binding equals it; else 409 hash_mismatch.
//   - present, zero hash:     CAS-create — succeed iff path is unbound; else 409 hash_mismatch.
//
// The zero-hash case lets a caller thread a prior-state hash uniformly: a
// known prior hash gates replace; the zero hash gates create. The
// EXTENSION-SUBSCRIPTION include_payload mirror recipe uses this for the
// bootstrap write (created event ⇒ notification.previous_hash zero ⇒
// expected_hash zero ⇒ clean CAS-create instead of unconditional overwrite).
type PutRequestData struct {
	Entity       cbor.RawMessage `cbor:"entity,omitempty"`
	ExpectedHash *hash.Hash      `cbor:"expected_hash,omitempty"`
	TreeID       string          `cbor:"tree_id,omitempty"`
}

// ToEntity creates a system/tree/put-request entity.
func (d PutRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreePutRequest, cbor.RawMessage(raw))
}

// PutRequestDataFromEntity decodes a put-request entity's data.
func PutRequestDataFromEntity(e entity.Entity) (PutRequestData, error) {
	var d PutRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PutRequestData{}, err
	}
	return d, nil
}

// ListingData is the data payload for system/tree/listing.
//
// NextPage (V7 §3.9 / 7.57 — EXTENSION-NETWORK Amendment 5) is the
// content hash of the next listing page when a listing is paginated
// across a next_page chain. Absent on the last/only page. The head
// page is served at the tree route (`{path}.list`); subsequent pages
// are content-addressed `system/tree/listing` entities fetched via
// `/content/{hex33(H)}`. The publish pipeline MUST bind each chain
// page into the served content namespace (§6.4.2) or it 404s.
type ListingData struct {
	Path     string                 `cbor:"path"`
	Entries  map[string]interface{} `cbor:"entries"`
	Count    uint64                 `cbor:"count"`
	Offset   uint64                 `cbor:"offset"`
	NextPage *hash.Hash             `cbor:"next_page,omitempty"`
}

// ToEntity creates a system/tree/listing entity.
func (d ListingData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeListing, cbor.RawMessage(raw))
}

// ListingDataFromEntity decodes a listing entity's data.
func ListingDataFromEntity(e entity.Entity) (ListingData, error) {
	var d ListingData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ListingData{}, err
	}
	return d, nil
}

// SnapshotData is the data payload for system/tree/snapshot.
// Per EXTENSION-TREE v3.5 (I3): {root} where root is the hash of the trie root node.
type SnapshotData struct {
	Root hash.Hash `cbor:"root"`
}

// ToEntity creates a system/tree/snapshot entity.
func (d SnapshotData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeSnapshot, cbor.RawMessage(raw))
}

// SnapshotDataFromEntity decodes a snapshot entity's data.
func SnapshotDataFromEntity(e entity.Entity) (SnapshotData, error) {
	var d SnapshotData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SnapshotData{}, err
	}
	return d, nil
}

// SnapshotNodeData is the data payload for system/tree/snapshot/node.
// IPLD HashMap (HAMT + CHAMP) node per EXTENSION-TREE v4.0 §3.1.
//
//	{
//	  map:  bytes(4),   ; 32-bit bitmap of occupied positions (K=32);
//	                    ; position p is bit p of the integer (LSB-indexed),
//	                    ; serialized big-endian (MSB byte first).
//	  data: [Entry, ...] ; dense array of entries; length == popcount(map);
//	                    ; Entry is bucket (CBOR array) or link (33-byte hash).
//	}
//
// Parameters (pinned per spec, not on wire): bitWidth=5, bucketSize=3,
// hash = SHA-256(UTF-8(canonical-normalize(relative_key))). No `binding`
// field — every key lives in a leaf bucket.
type SnapshotNodeData struct {
	Map  []byte      `cbor:"map"`
	Data []NodeEntry `cbor:"data"`
}

// BucketTuple is one [key, value_hash] entry inside a bucket.
// Encoded as a 2-element CBOR array. Bucket tuples MUST be sorted lex by
// key (UTF-8) within a bucket per the canonical-form rule.
type BucketTuple struct {
	Key       string
	ValueHash hash.Hash
}

// MarshalCBOR encodes the tuple as a 2-element CBOR array.
func (t BucketTuple) MarshalCBOR() ([]byte, error) {
	return ecf.Encode([]interface{}{t.Key, t.ValueHash})
}

// UnmarshalCBOR decodes a 2-element CBOR array into the tuple.
func (t *BucketTuple) UnmarshalCBOR(data []byte) error {
	var raw []cbor.RawMessage
	if err := ecf.Decode(data, &raw); err != nil {
		return fmt.Errorf("bucket tuple: %w", err)
	}
	if len(raw) != 2 {
		return fmt.Errorf("bucket tuple: expected 2 elements, got %d", len(raw))
	}
	if err := ecf.Decode(raw[0], &t.Key); err != nil {
		return fmt.Errorf("bucket tuple key: %w", err)
	}
	if err := t.ValueHash.UnmarshalCBOR(raw[1]); err != nil {
		return fmt.Errorf("bucket tuple value_hash: %w", err)
	}
	return nil
}

// NodeEntry is either a Bucket (leaf-level storage of up to bucketSize=3
// [key, value_hash] tuples) or a Link (33-byte system/hash to a sub-node).
// The two variants are discriminated by CBOR major type at decode time:
//
//	major type 4 (array)        → Bucket
//	major type 2 (byte string)  → Link
//
// Exactly one of Bucket / Link is set at any time. Bucket length MUST be
// in [1, 3]; tuples MUST be sorted lex by Key.
type NodeEntry struct {
	Bucket []BucketTuple
	Link   *hash.Hash
}

// IsLink reports whether this entry is a link to a sub-node.
func (e NodeEntry) IsLink() bool { return e.Link != nil }

// IsBucket reports whether this entry is a leaf bucket.
func (e NodeEntry) IsBucket() bool { return e.Link == nil }

// MarshalCBOR emits the entry as either an array (bucket) or byte string
// (link). Bucket arrays are ECF-deterministic; the hash byte string is
// already canonical (33-byte system/hash).
func (e NodeEntry) MarshalCBOR() ([]byte, error) {
	if e.Link != nil {
		return e.Link.MarshalCBOR()
	}
	return ecf.Encode(e.Bucket)
}

// UnmarshalCBOR dispatches on the leading CBOR initial byte's major type.
// Major 2 (byte string, 0b010xxxxx) → link; major 4 (array, 0b100xxxxx)
// → bucket. Anything else is non-conformant per §3.1.
func (e *NodeEntry) UnmarshalCBOR(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("node entry: empty cbor")
	}
	major := data[0] >> 5
	switch major {
	case 2: // byte string → link
		var h hash.Hash
		if err := h.UnmarshalCBOR(data); err != nil {
			return fmt.Errorf("node entry link: %w", err)
		}
		e.Link = &h
		e.Bucket = nil
		return nil
	case 4: // array → bucket
		var bucket []BucketTuple
		if err := ecf.Decode(data, &bucket); err != nil {
			return fmt.Errorf("node entry bucket: %w", err)
		}
		e.Bucket = bucket
		e.Link = nil
		return nil
	default:
		return fmt.Errorf("node entry: unexpected CBOR major type %d", major)
	}
}

// ToEntity creates a system/tree/snapshot/node entity.
func (d SnapshotNodeData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeSnapshotNode, cbor.RawMessage(raw))
}

// SnapshotNodeDataFromEntity decodes a snapshot/node entity's data.
func SnapshotNodeDataFromEntity(e entity.Entity) (SnapshotNodeData, error) {
	var d SnapshotNodeData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SnapshotNodeData{}, err
	}
	return d, nil
}

// SnapshotRequestData is the data payload for system/tree/snapshot-request.
type SnapshotRequestData struct {
	Prefix string `cbor:"prefix,omitempty"`
	TreeID string `cbor:"tree_id,omitempty"`
}

// ToEntity creates a system/tree/snapshot-request entity.
func (d SnapshotRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeSnapshotRequest, cbor.RawMessage(raw))
}

// SnapshotRequestDataFromEntity decodes a snapshot-request entity's data.
func SnapshotRequestDataFromEntity(e entity.Entity) (SnapshotRequestData, error) {
	var d SnapshotRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SnapshotRequestData{}, err
	}
	return d, nil
}

// DiffData is the data payload for system/tree/diff.
type DiffData struct {
	Base      hash.Hash                 `cbor:"base"`
	Target    hash.Hash                 `cbor:"target"`
	Added     map[string]hash.Hash      `cbor:"added"`
	Removed   map[string]hash.Hash      `cbor:"removed"`
	Changed   map[string]DiffChangeData `cbor:"changed"`
	Unchanged uint64                    `cbor:"unchanged"`
}

// ToEntity creates a system/tree/diff entity.
func (d DiffData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeDiff, cbor.RawMessage(raw))
}

// DiffDataFromEntity decodes a diff entity's data.
func DiffDataFromEntity(e entity.Entity) (DiffData, error) {
	var d DiffData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return DiffData{}, err
	}
	return d, nil
}

// DiffChangeData is the data payload for system/tree/diff/change.
type DiffChangeData struct {
	BaseHash   hash.Hash `cbor:"base_hash"`
	TargetHash hash.Hash `cbor:"target_hash"`
}

// DiffRequestData is the data payload for system/tree/diff-request.
type DiffRequestData struct {
	Base   hash.Hash `cbor:"base"`
	Target hash.Hash `cbor:"target"`
}

// ToEntity creates a system/tree/diff-request entity.
func (d DiffRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeDiffRequest, cbor.RawMessage(raw))
}

// DiffRequestDataFromEntity decodes a diff-request entity's data.
func DiffRequestDataFromEntity(e entity.Entity) (DiffRequestData, error) {
	var d DiffRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return DiffRequestData{}, err
	}
	return d, nil
}

// MergeResultData is the data payload for system/tree/merge-result.
type MergeResultData struct {
	Applied   uint64                       `cbor:"applied"`
	Skipped   uint64                       `cbor:"skipped"`
	Conflicts map[string]MergeConflictData `cbor:"conflicts"`
	Strategy  string                       `cbor:"strategy"`
}

// ToEntity creates a system/tree/merge-result entity.
func (d MergeResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeMergeResult, cbor.RawMessage(raw))
}

// MergeResultDataFromEntity decodes a merge-result entity's data.
func MergeResultDataFromEntity(e entity.Entity) (MergeResultData, error) {
	var d MergeResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return MergeResultData{}, err
	}
	return d, nil
}

// MergeConflictData is the data payload for system/tree/merge-result/conflict.
type MergeConflictData struct {
	ExistingHash hash.Hash `cbor:"existing_hash"`
	IncomingHash hash.Hash `cbor:"incoming_hash"`
	Resolution   string    `cbor:"resolution"`
}

// MergeRequestData is the data payload for system/tree/merge-request.
type MergeRequestData struct {
	Source         hash.Hash       `cbor:"source,omitzero"`
	SourceEnvelope cbor.RawMessage `cbor:"source_envelope,omitempty"` // Extract envelope — ingested before merge
	TargetTree     string          `cbor:"target_tree,omitempty"`
	Strategy       string          `cbor:"strategy,omitempty"`
	SourcePrefix   string          `cbor:"source_prefix,omitempty"`
	TargetPrefix   string          `cbor:"target_prefix,omitempty"`
	DryRun         *bool           `cbor:"dry_run,omitempty"`
}

// ToEntity creates a system/tree/merge-request entity.
func (d MergeRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeMergeRequest, cbor.RawMessage(raw))
}

// MergeRequestDataFromEntity decodes a merge-request entity's data.
func MergeRequestDataFromEntity(e entity.Entity) (MergeRequestData, error) {
	var d MergeRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return MergeRequestData{}, err
	}
	return d, nil
}

// ExtractRequestData is the data payload for system/tree/extract-request.
//
// `Since` (proposed, OPEN per PROPOSAL-TREE-EXTRACT-SINCE.md):
// trie root hash the caller already has; when set, the extracted envelope
// includes only paths whose bindings differ from `since`. Mutually
// exclusive with `Paths` (impl MUST reject with 400 conflicting_filters
// if both are set).
type ExtractRequestData struct {
	Prefix string    `cbor:"prefix"`
	TreeID string    `cbor:"tree_id,omitempty"`
	Paths  []string  `cbor:"paths,omitempty"`
	Since  hash.Hash `cbor:"since,omitzero"`
}

// ToEntity creates a system/tree/extract-request entity.
func (d ExtractRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeExtractRequest, cbor.RawMessage(raw))
}

// ExtractRequestDataFromEntity decodes an extract-request entity's data.
func ExtractRequestDataFromEntity(e entity.Entity) (ExtractRequestData, error) {
	var d ExtractRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ExtractRequestData{}, err
	}
	return d, nil
}

// TrackingConfigData is the data payload for system/tree/tracking-config.
// Per EXTENSION-TREE v3.8 §3.4.1a: declares a prefix for incremental trie root maintenance.
// Stored at system/tree/tracking-config/{name}.
type TrackingConfigData struct {
	Prefix  string `cbor:"prefix"`
	Enabled bool   `cbor:"enabled"`
}

// ToEntity creates a system/tree/tracking-config entity.
func (d TrackingConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreeTrackingConfig, cbor.RawMessage(raw))
}

// TrackingConfigDataFromEntity decodes a tracking-config entity's data.
func TrackingConfigDataFromEntity(e entity.Entity) (TrackingConfigData, error) {
	var d TrackingConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return TrackingConfigData{}, err
	}
	return d, nil
}

// PartialResultHaltEntry identifies a consumer that halted the cascade.
type PartialResultHaltEntry struct {
	Name  string             `cbor:"name"`
	Error PartialResultError `cbor:"error"`
}

// PartialResultError is the error detail within a cascade halt entry.
// Mirrors system/protocol/error fields.
type PartialResultError struct {
	Code    string `cbor:"code"`
	Message string `cbor:"message,omitempty"`
}

// PartialResultData is the data payload for system/tree/partial-result.
// Returned as the result of a 207 (Multi-Status) tree.put response when
// the binding landed but the emit cascade did not complete.
// Per PROPOSAL-CASCADE-SEMANTICS §4.4.
type PartialResultData struct {
	BindingCommitted   bool                     `cbor:"binding_committed"`
	ConsumersCompleted []string                 `cbor:"consumers_completed"`
	ConsumersHalted    []PartialResultHaltEntry `cbor:"consumers_halted,omitempty"`
	ConsumersErrored   []PartialResultHaltEntry `cbor:"consumers_errored,omitempty"`
	ConsumersSkipped   []string                 `cbor:"consumers_skipped,omitempty"`
	NestedCascadeIDs   []hash.Hash              `cbor:"nested_cascade_ids,omitempty"`
	CascadeDepth       uint64                   `cbor:"cascade_depth"`
}

// ToEntity creates a system/tree/partial-result entity.
func (d PartialResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeTreePartialResult, cbor.RawMessage(raw))
}

// PartialResultDataFromEntity decodes a partial-result entity's data.
func PartialResultDataFromEntity(e entity.Entity) (PartialResultData, error) {
	var d PartialResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PartialResultData{}, err
	}
	return d, nil
}
