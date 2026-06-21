package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Revision type constants — per EXTENSION-REVISION.md v2.1.
const (
	// Entity types (5).
	TypeRevisionEntry       = "system/revision/entry"
	TypeRevisionConflict    = "system/revision/conflict"
	TypeRevisionMergeConfig = "system/revision/merge-config"
	TypeRevisionConfig      = "system/revision/config"
	TypeRevisionStatus      = "system/revision/status"

	// Param types (15).
	TypeRevisionCommitParams        = "system/revision/commit-params"
	TypeRevisionLogParams           = "system/revision/log-params"
	TypeRevisionStatusParams        = "system/revision/status-params"
	TypeRevisionMergeParams         = "system/revision/merge-params"
	TypeRevisionResolveParams       = "system/revision/resolve-params"
	TypeRevisionFetchParams         = "system/revision/fetch-params"
	TypeRevisionFetchEntitiesParams = "system/revision/fetch-entities-params"
	TypeRevisionPushParams          = "system/revision/push-params"
	TypeRevisionAncestorParams      = "system/revision/ancestor-params"
	TypeRevisionBranchParams        = "system/revision/branch-params"
	TypeRevisionCheckoutParams      = "system/revision/checkout-params"
	TypeRevisionTagParams           = "system/revision/tag-params"
	TypeRevisionDiffParams          = "system/revision/diff-params"
	TypeRevisionFetchDiffParams     = "system/revision/fetch-diff-params"
	TypeRevisionCherryPickParams    = "system/revision/cherry-pick-params"
	TypeRevisionRevertParams        = "system/revision/revert-params"
	TypeRevisionConfigParams        = "system/revision/config-params"
	TypeRevisionCascadeWarning      = "system/revision/cascade-warning"

	// Result types (14).
	TypeRevisionCommitResult        = "system/revision/commit-result"
	TypeRevisionLogResult           = "system/revision/log-result"
	TypeRevisionMergeResult         = "system/revision/merge-result"
	TypeRevisionResolveResult       = "system/revision/resolve-result"
	TypeRevisionFetchResult         = "system/revision/fetch-result"
	TypeRevisionFetchEntitiesResult = "system/revision/fetch-entities-result"
	TypeRevisionPushResult          = "system/revision/push-result"
	TypeRevisionAncestorResult      = "system/revision/ancestor-result"
	TypeRevisionBranchResult        = "system/revision/branch-result"
	TypeRevisionCheckoutResult      = "system/revision/checkout-result"
	TypeRevisionTagResult           = "system/revision/tag-result"
	TypeRevisionCherryPickResult    = "system/revision/cherry-pick-result"
	TypeRevisionRevertResult        = "system/revision/revert-result"
	TypeRevisionConfigResult        = "system/revision/config-result"

	// Merge delegation types (2).
	TypeRevisionMergeRequest  = "system/revision/merge-request"
	TypeRevisionMergeResponse = "system/revision/merge-response"
)

// --- Entity types ---

// RevisionEntryData is the data payload for system/revision/entry.
// Structural only: root trie hash + sorted parent hashes. No metadata.
type RevisionEntryData struct {
	Root    hash.Hash   `cbor:"root"`
	Parents []hash.Hash `cbor:"parents"`
}

func (d RevisionEntryData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionEntry, cbor.RawMessage(raw))
}

func RevisionEntryDataFromEntity(e entity.Entity) (RevisionEntryData, error) {
	var d RevisionEntryData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionEntryData{}, err
	}
	return d, nil
}

// RevisionConflictData is the data payload for system/revision/conflict.
type RevisionConflictData struct {
	Path          string    `cbor:"path"`
	Base          hash.Hash `cbor:"base,omitzero"`
	Local         hash.Hash `cbor:"local,omitzero"`
	Remote        hash.Hash `cbor:"remote,omitzero"`
	Strategy      string    `cbor:"strategy"`
	VersionLocal  hash.Hash `cbor:"version_local"`
	VersionRemote hash.Hash `cbor:"version_remote"`
	Supersedes    hash.Hash `cbor:"supersedes,omitzero"`
}

func (d RevisionConflictData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionConflict, cbor.RawMessage(raw))
}

func RevisionConflictDataFromEntity(e entity.Entity) (RevisionConflictData, error) {
	var d RevisionConflictData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionConflictData{}, err
	}
	return d, nil
}

// RevisionMergeConfigData is the data payload for system/revision/merge-config.
//
// Strategy is the entity-vs-entity merge strategy (source-wins, target-wins,
// three-way, deterministic, keep-both, manual).
//
// DeletionResolution is the strategy for deletion-vs-entity divergent merges
// per PROPOSAL-DELETION-MARKERS A.8 Amendment 4. Empty string → spec default
// (`deletion-wins`). Values: deletion-wins | lww | deterministic | keep-both
// | custom-handler. See `applyDeletionResolution` for semantics.
type RevisionMergeConfigData struct {
	Pattern            string `cbor:"pattern"`
	Strategy           string `cbor:"strategy"`
	DeletionResolution string `cbor:"deletion_resolution,omitempty"`
	Handler            string `cbor:"handler,omitempty"`
}

func (d RevisionMergeConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionMergeConfig, cbor.RawMessage(raw))
}

func RevisionMergeConfigDataFromEntity(e entity.Entity) (RevisionMergeConfigData, error) {
	var d RevisionMergeConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionMergeConfigData{}, err
	}
	return d, nil
}

// TypeRevisionMergeConfigParams is the input type for system/revision:merge-config
// (EXTENSION-REVISION v3.3 §4.4.18).
const TypeRevisionMergeConfigParams = "system/revision/merge-config-params"

// TypeRevisionMergeConfigResult is the output type for system/revision:merge-config.
const TypeRevisionMergeConfigResult = "system/revision/merge-config-result"

// RevisionMergeConfigParamsData is the params payload for the merge-config op.
// Per EXTENSION-REVISION v3.3 §4.4.18. The op is the canonical write path for
// the handler-owned merge-config namespace (§2.3); it enforces the §2.3
// strategy-rejection contract (lww / keep-both → 400 invalid_strategy) and a
// CAS guard.
type RevisionMergeConfigParamsData struct {
	Scope        string                   `cbor:"scope"`                    // "path" | "type"
	Name         string                   `cbor:"name"`                     // pattern (scope=path) or type name (scope=type)
	Action       string                   `cbor:"action"`                   // "set" | "delete"
	Config       *RevisionMergeConfigData `cbor:"config,omitempty"`         // required when action=set
	ExpectedHash *hash.Hash               `cbor:"expected_hash,omitempty"`  // optional CAS guard
}

func (d RevisionMergeConfigParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionMergeConfigParams, cbor.RawMessage(raw))
}

func RevisionMergeConfigParamsDataFromEntity(e entity.Entity) (RevisionMergeConfigParamsData, error) {
	var d RevisionMergeConfigParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionMergeConfigParamsData{}, err
	}
	return d, nil
}

// RevisionMergeConfigResultData is the result payload for the merge-config op.
type RevisionMergeConfigResultData struct {
	Path   string    `cbor:"path"`             // binding path written or deleted
	Hash   hash.Hash `cbor:"hash,omitzero"`    // new entity hash (action=set); zero on delete
	Status string    `cbor:"status"`           // "set" | "deleted" | "no_change"
}

func (d RevisionMergeConfigResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionMergeConfigResult, cbor.RawMessage(raw))
}

// RevisionConfigData is the data payload for system/revision/config.
type RevisionConfigData struct {
	Prefix           string   `cbor:"prefix"`
	Exclude          []string `cbor:"exclude,omitempty"`
	ExcludeTypes     []string `cbor:"exclude_types,omitempty"`
	AutoVersion      *bool    `cbor:"auto_version,omitempty"`
	MergeOrder       string   `cbor:"merge_order,omitempty"`
	OscillationDepth *uint64  `cbor:"oscillation_depth,omitempty"`
}

func (d RevisionConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionConfig, cbor.RawMessage(raw))
}

func RevisionConfigDataFromEntity(e entity.Entity) (RevisionConfigData, error) {
	var d RevisionConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionConfigData{}, err
	}
	return d, nil
}

// RevisionConfigParamsData is the data payload for system/revision/config-params.
// Per PROPOSAL-REVISION-CONFIG-OPERATION §3.1.
type RevisionConfigParamsData struct {
	Name         string              `cbor:"name"`
	Action       string              `cbor:"action"`
	Config       *RevisionConfigData `cbor:"config,omitempty"`
	ExpectedHash *hash.Hash          `cbor:"expected_hash,omitempty"`
}

func (d RevisionConfigParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionConfigParams, cbor.RawMessage(raw))
}

func RevisionConfigParamsDataFromEntity(e entity.Entity) (RevisionConfigParamsData, error) {
	var d RevisionConfigParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionConfigParamsData{}, err
	}
	return d, nil
}

// RevisionConfigResultData is the result of a successful config operation.
// Per PROPOSAL-REVISION-CONFIG-OPERATION §3.1.
type RevisionConfigResultData struct {
	ConfigPath           string    `cbor:"config_path"`
	ConfigHash           hash.Hash `cbor:"config_hash,omitzero"`
	PreviousHash         hash.Hash `cbor:"previous_hash,omitzero"`
	TrackingConfigPath   string    `cbor:"tracking_config_path,omitempty"`
	TrackingConfigAction string    `cbor:"tracking_config_action,omitempty"`
}

func (d RevisionConfigResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionConfigResult, cbor.RawMessage(raw))
}

// RevisionCascadeWarningData represents a path whose tree.put returned 207
// (cascade halted). Used in merge/checkout/cherry-pick/revert results.
type RevisionCascadeWarningData struct {
	Path           string `cbor:"path"`
	ConsumerHalted string `cbor:"consumer_halted"`
	ErrorCode      string `cbor:"error_code"`
}

func (d RevisionCascadeWarningData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionCascadeWarning, cbor.RawMessage(raw))
}

// RevisionStatusData is the data payload for system/revision/status.
type RevisionStatusData struct {
	Prefix        string               `cbor:"prefix"`
	Head          hash.Hash            `cbor:"head,omitzero"`
	Remotes       map[string]hash.Hash `cbor:"remotes,omitempty"`
	Conflicts     uint64               `cbor:"conflicts"`
	Pending       uint64               `cbor:"pending"`
	KeepBothPaths []string             `cbor:"keep_both_paths,omitempty"`
}

func (d RevisionStatusData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionStatus, cbor.RawMessage(raw))
}

func RevisionStatusDataFromEntity(e entity.Entity) (RevisionStatusData, error) {
	var d RevisionStatusData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionStatusData{}, err
	}
	return d, nil
}

// --- Param types ---

// RevisionCommitParamsData is the data payload for system/revision/commit-params.
type RevisionCommitParamsData struct {
	Prefix  string  `cbor:"prefix"`
	Message *string `cbor:"message,omitempty"`
}

func (d RevisionCommitParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionCommitParams, cbor.RawMessage(raw))
}

func RevisionCommitParamsDataFromEntity(e entity.Entity) (RevisionCommitParamsData, error) {
	var d RevisionCommitParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionCommitParamsData{}, err
	}
	return d, nil
}

// RevisionLogParamsData is the data payload for system/revision/log-params.
type RevisionLogParamsData struct {
	Prefix string    `cbor:"prefix"`
	Limit  *uint64   `cbor:"limit,omitempty"`
	Since  hash.Hash `cbor:"since,omitzero"`
}

func (d RevisionLogParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionLogParams, cbor.RawMessage(raw))
}

func RevisionLogParamsDataFromEntity(e entity.Entity) (RevisionLogParamsData, error) {
	var d RevisionLogParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionLogParamsData{}, err
	}
	return d, nil
}

// RevisionStatusParamsData is the data payload for system/revision/status-params.
type RevisionStatusParamsData struct {
	Prefix string `cbor:"prefix"`
}

func (d RevisionStatusParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionStatusParams, cbor.RawMessage(raw))
}

func RevisionStatusParamsDataFromEntity(e entity.Entity) (RevisionStatusParamsData, error) {
	var d RevisionStatusParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionStatusParamsData{}, err
	}
	return d, nil
}

// RevisionMergeParamsData is the data payload for system/revision/merge-params.
//
// Either RemoteVersion or SourceEnvelope must be set. SourceEnvelope
// is the chain-composition path: it carries an encoded entity wrapping
// a system/envelope (typically the result of system/revision:fetch),
// and the merge handler ingests envelope.Included into the local
// content store before walking the version DAG. Parity with
// tree/merge's source_envelope (core/tree/operations.go:213-244).
type RevisionMergeParamsData struct {
	Prefix         string          `cbor:"prefix"`
	RemoteVersion  hash.Hash       `cbor:"remote_version,omitzero"`
	SourceEnvelope cbor.RawMessage `cbor:"source_envelope,omitempty"`
	Strategy       string          `cbor:"strategy,omitempty"`
	DryRun         *bool           `cbor:"dry_run,omitempty"`
}

func (d RevisionMergeParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionMergeParams, cbor.RawMessage(raw))
}

func RevisionMergeParamsDataFromEntity(e entity.Entity) (RevisionMergeParamsData, error) {
	var d RevisionMergeParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionMergeParamsData{}, err
	}
	return d, nil
}

// RevisionResolveParamsData is the data payload for system/revision/resolve-params.
type RevisionResolveParamsData struct {
	Prefix   string     `cbor:"prefix"`
	Path     string     `cbor:"path"`
	Resolved *hash.Hash `cbor:"resolved"`
}

func (d RevisionResolveParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionResolveParams, cbor.RawMessage(raw))
}

func RevisionResolveParamsDataFromEntity(e entity.Entity) (RevisionResolveParamsData, error) {
	var d RevisionResolveParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionResolveParamsData{}, err
	}
	return d, nil
}

// RevisionFetchParamsData is the data payload for system/revision/fetch-params.
//
// Per EXTENSION-REVISION §4.1, `pull` reuses this input type (spec line
// 558). The `Remote` field is consumed by `pull` (§4.4.8) to identify
// the peer to fetch from; `fetch` itself ignores it (the remote is
// implicit in the EXECUTE target URI for plain fetch).
type RevisionFetchParamsData struct {
	Prefix       string    `cbor:"prefix"`
	RemotePrefix string    `cbor:"remote_prefix,omitempty"`
	Remote       string    `cbor:"remote,omitempty"`
	Since        hash.Hash `cbor:"since,omitzero"`
	Depth        *uint64   `cbor:"depth,omitempty"`
}

func (d RevisionFetchParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionFetchParams, cbor.RawMessage(raw))
}

func RevisionFetchParamsDataFromEntity(e entity.Entity) (RevisionFetchParamsData, error) {
	var d RevisionFetchParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionFetchParamsData{}, err
	}
	return d, nil
}

// RevisionFetchEntitiesParamsData is the data payload for system/revision/fetch-entities-params.
type RevisionFetchEntitiesParamsData struct {
	Prefix   string      `cbor:"prefix"`
	Snapshot hash.Hash   `cbor:"snapshot"`
	Hashes   []hash.Hash `cbor:"hashes"`
}

func (d RevisionFetchEntitiesParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionFetchEntitiesParams, cbor.RawMessage(raw))
}

func RevisionFetchEntitiesParamsDataFromEntity(e entity.Entity) (RevisionFetchEntitiesParamsData, error) {
	var d RevisionFetchEntitiesParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionFetchEntitiesParamsData{}, err
	}
	return d, nil
}

// RevisionAncestorParamsData is the data payload for system/revision/ancestor-params.
type RevisionAncestorParamsData struct {
	VersionA hash.Hash `cbor:"version_a"`
	VersionB hash.Hash `cbor:"version_b"`
}

func (d RevisionAncestorParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionAncestorParams, cbor.RawMessage(raw))
}

func RevisionAncestorParamsDataFromEntity(e entity.Entity) (RevisionAncestorParamsData, error) {
	var d RevisionAncestorParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionAncestorParamsData{}, err
	}
	return d, nil
}

// RevisionBranchParamsData is the data payload for system/revision/branch-params.
type RevisionBranchParamsData struct {
	Prefix string    `cbor:"prefix"`
	Action string    `cbor:"action"`
	Name   string    `cbor:"name,omitempty"`
	From   hash.Hash `cbor:"from,omitzero"`
}

func (d RevisionBranchParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionBranchParams, cbor.RawMessage(raw))
}

func RevisionBranchParamsDataFromEntity(e entity.Entity) (RevisionBranchParamsData, error) {
	var d RevisionBranchParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionBranchParamsData{}, err
	}
	return d, nil
}

// RevisionCheckoutParamsData is the data payload for system/revision/checkout-params.
type RevisionCheckoutParamsData struct {
	Prefix  string    `cbor:"prefix"`
	Branch  string    `cbor:"branch,omitempty"`
	Version hash.Hash `cbor:"version,omitzero"`
}

func (d RevisionCheckoutParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionCheckoutParams, cbor.RawMessage(raw))
}

func RevisionCheckoutParamsDataFromEntity(e entity.Entity) (RevisionCheckoutParamsData, error) {
	var d RevisionCheckoutParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionCheckoutParamsData{}, err
	}
	return d, nil
}

// RevisionTagParamsData is the data payload for system/revision/tag-params.
type RevisionTagParamsData struct {
	Prefix  string    `cbor:"prefix"`
	Action  string    `cbor:"action"`
	Name    string    `cbor:"name,omitempty"`
	Version hash.Hash `cbor:"version,omitzero"`
}

func (d RevisionTagParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionTagParams, cbor.RawMessage(raw))
}

func RevisionTagParamsDataFromEntity(e entity.Entity) (RevisionTagParamsData, error) {
	var d RevisionTagParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionTagParamsData{}, err
	}
	return d, nil
}

// RevisionDiffParamsData is the data payload for system/revision/diff-params.
type RevisionDiffParamsData struct {
	Prefix string    `cbor:"prefix"`
	Base   hash.Hash `cbor:"base"`
	Target hash.Hash `cbor:"target"`
}

func (d RevisionDiffParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionDiffParams, cbor.RawMessage(raw))
}

func RevisionDiffParamsDataFromEntity(e entity.Entity) (RevisionDiffParamsData, error) {
	var d RevisionDiffParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionDiffParamsData{}, err
	}
	return d, nil
}

// RevisionFetchDiffParamsData is the data payload for system/revision/fetch-diff-params
// (PROPOSAL-TREE-EXTRACT-SINCE Amendment 1 / Option E).
//
// Standalone op that returns an incremental envelope of trie nodes +
// leaf entities differing between Base.Root and the executing peer's
// current head for Prefix. Target is implicit (executing peer's local
// head); only Base is supplied by the caller. This single-dynamic-field
// shape is the one chain-expressible variant — continuation inject-mode
// supports exactly one dynamic field, so the chain author wires
// base=$notification.previous_hash, prefix is static.
//
// Wire-compatible envelope output matches tree:extract's result shape so
// downstream tree:merge ingests it identically.
type RevisionFetchDiffParamsData struct {
	Prefix string    `cbor:"prefix"`
	Base   hash.Hash `cbor:"base,omitzero"`
}

func (d RevisionFetchDiffParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionFetchDiffParams, cbor.RawMessage(raw))
}

func RevisionFetchDiffParamsDataFromEntity(e entity.Entity) (RevisionFetchDiffParamsData, error) {
	var d RevisionFetchDiffParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionFetchDiffParamsData{}, err
	}
	return d, nil
}

// RevisionCherryPickParamsData is the data payload for system/revision/cherry-pick-params.
type RevisionCherryPickParamsData struct {
	Prefix  string    `cbor:"prefix"`
	Version hash.Hash `cbor:"version"`
	Parent  hash.Hash `cbor:"parent,omitzero"`
}

func (d RevisionCherryPickParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionCherryPickParams, cbor.RawMessage(raw))
}

func RevisionCherryPickParamsDataFromEntity(e entity.Entity) (RevisionCherryPickParamsData, error) {
	var d RevisionCherryPickParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionCherryPickParamsData{}, err
	}
	return d, nil
}

// RevisionRevertParamsData is the data payload for system/revision/revert-params.
type RevisionRevertParamsData struct {
	Prefix  string    `cbor:"prefix"`
	Version hash.Hash `cbor:"version"`
	Parent  hash.Hash `cbor:"parent,omitzero"`
}

func (d RevisionRevertParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionRevertParams, cbor.RawMessage(raw))
}

func RevisionRevertParamsDataFromEntity(e entity.Entity) (RevisionRevertParamsData, error) {
	var d RevisionRevertParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionRevertParamsData{}, err
	}
	return d, nil
}

// RevisionPushParamsData is the data payload for system/revision/push-params.
type RevisionPushParamsData struct {
	Remote       string      `cbor:"remote"`
	Prefix       string      `cbor:"prefix"`
	RemotePrefix string      `cbor:"remote_prefix,omitempty"`
	Versions     []hash.Hash `cbor:"versions,omitempty"`
}

func (d RevisionPushParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionPushParams, cbor.RawMessage(raw))
}

func RevisionPushParamsDataFromEntity(e entity.Entity) (RevisionPushParamsData, error) {
	var d RevisionPushParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionPushParamsData{}, err
	}
	return d, nil
}

// --- Result types ---

// RevisionCommitResultData is the data payload for system/revision/commit-result.
type RevisionCommitResultData struct {
	Version hash.Hash `cbor:"version"`
	Root    hash.Hash `cbor:"root"`
}

func (d RevisionCommitResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionCommitResult, cbor.RawMessage(raw))
}

func RevisionCommitResultDataFromEntity(e entity.Entity) (RevisionCommitResultData, error) {
	var d RevisionCommitResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionCommitResultData{}, err
	}
	return d, nil
}

// RevisionLogResultData is the data payload for system/revision/log-result.
type RevisionLogResultData struct {
	Prefix   string      `cbor:"prefix"`
	Versions []hash.Hash `cbor:"versions"`
	HasMore  bool        `cbor:"has_more"`
}

func (d RevisionLogResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionLogResult, cbor.RawMessage(raw))
}

func RevisionLogResultDataFromEntity(e entity.Entity) (RevisionLogResultData, error) {
	var d RevisionLogResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionLogResultData{}, err
	}
	return d, nil
}

// RevisionMergeResultData is the data payload for system/revision/merge-result.
type RevisionMergeResultData struct {
	Status          string                       `cbor:"status"`
	Version         hash.Hash                    `cbor:"version,omitzero"`
	Conflicts       []string                     `cbor:"conflicts,omitempty"`
	MergedCount     *uint64                      `cbor:"merged_count,omitempty"`
	DeletedCount    *uint64                      `cbor:"deleted_count,omitempty"`
	CascadeWarnings []RevisionCascadeWarningData `cbor:"cascade_warnings,omitempty"`
}

func (d RevisionMergeResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionMergeResult, cbor.RawMessage(raw))
}

func RevisionMergeResultDataFromEntity(e entity.Entity) (RevisionMergeResultData, error) {
	var d RevisionMergeResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionMergeResultData{}, err
	}
	return d, nil
}

// RevisionResolveResultData is the data payload for system/revision/resolve-result.
type RevisionResolveResultData struct {
	Path               string     `cbor:"path"`
	Resolved           *hash.Hash `cbor:"resolved"`
	RemainingConflicts uint64     `cbor:"remaining_conflicts"`
}

func (d RevisionResolveResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionResolveResult, cbor.RawMessage(raw))
}

func RevisionResolveResultDataFromEntity(e entity.Entity) (RevisionResolveResultData, error) {
	var d RevisionResolveResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionResolveResultData{}, err
	}
	return d, nil
}

// RevisionFetchResultData is the data payload for system/revision/fetch-result.
type RevisionFetchResultData struct {
	Head     hash.Hash   `cbor:"head,omitzero"`
	Versions []hash.Hash `cbor:"versions,omitempty"`
	HasMore  *bool       `cbor:"has_more,omitempty"`
}

func (d RevisionFetchResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionFetchResult, cbor.RawMessage(raw))
}

func RevisionFetchResultDataFromEntity(e entity.Entity) (RevisionFetchResultData, error) {
	var d RevisionFetchResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionFetchResultData{}, err
	}
	return d, nil
}

// RevisionFetchEntitiesResultData is the data payload for system/revision/fetch-entities-result.
type RevisionFetchEntitiesResultData struct {
	Found   []hash.Hash `cbor:"found"`
	Missing []hash.Hash `cbor:"missing,omitempty"`
}

func (d RevisionFetchEntitiesResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionFetchEntitiesResult, cbor.RawMessage(raw))
}

func RevisionFetchEntitiesResultDataFromEntity(e entity.Entity) (RevisionFetchEntitiesResultData, error) {
	var d RevisionFetchEntitiesResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionFetchEntitiesResultData{}, err
	}
	return d, nil
}

// RevisionPushResultData is the data payload for system/revision/push-result.
type RevisionPushResultData struct {
	Status   string  `cbor:"status"`
	Versions *uint64 `cbor:"versions,omitempty"`
	Message  string  `cbor:"message,omitempty"`
}

func (d RevisionPushResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionPushResult, cbor.RawMessage(raw))
}

func RevisionPushResultDataFromEntity(e entity.Entity) (RevisionPushResultData, error) {
	var d RevisionPushResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionPushResultData{}, err
	}
	return d, nil
}

// RevisionAncestorResultData is the data payload for system/revision/ancestor-result.
type RevisionAncestorResultData struct {
	Ancestor hash.Hash `cbor:"ancestor,omitzero"`
}

func (d RevisionAncestorResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionAncestorResult, cbor.RawMessage(raw))
}

func RevisionAncestorResultDataFromEntity(e entity.Entity) (RevisionAncestorResultData, error) {
	var d RevisionAncestorResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionAncestorResultData{}, err
	}
	return d, nil
}

// RevisionBranchResultData is the data payload for system/revision/branch-result.
type RevisionBranchResultData struct {
	Status   string               `cbor:"status,omitempty"`
	Branch   string               `cbor:"branch,omitempty"`
	Version  hash.Hash            `cbor:"version,omitzero"`
	Branches map[string]hash.Hash `cbor:"branches,omitempty"`
	Active   string               `cbor:"active,omitempty"`
}

func (d RevisionBranchResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionBranchResult, cbor.RawMessage(raw))
}

func RevisionBranchResultDataFromEntity(e entity.Entity) (RevisionBranchResultData, error) {
	var d RevisionBranchResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionBranchResultData{}, err
	}
	return d, nil
}

// RevisionCheckoutResultData is the data payload for system/revision/checkout-result.
type RevisionCheckoutResultData struct {
	Status          string                       `cbor:"status"`
	Version         hash.Hash                    `cbor:"version"`
	Branch          string                       `cbor:"branch,omitempty"`
	CascadeWarnings []RevisionCascadeWarningData `cbor:"cascade_warnings,omitempty"`
}

func (d RevisionCheckoutResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionCheckoutResult, cbor.RawMessage(raw))
}

func RevisionCheckoutResultDataFromEntity(e entity.Entity) (RevisionCheckoutResultData, error) {
	var d RevisionCheckoutResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionCheckoutResultData{}, err
	}
	return d, nil
}

// RevisionTagResultData is the data payload for system/revision/tag-result.
type RevisionTagResultData struct {
	Status  string               `cbor:"status,omitempty"`
	Tag     string               `cbor:"tag,omitempty"`
	Version hash.Hash            `cbor:"version,omitzero"`
	Tags    map[string]hash.Hash `cbor:"tags,omitempty"`
}

func (d RevisionTagResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionTagResult, cbor.RawMessage(raw))
}

func RevisionTagResultDataFromEntity(e entity.Entity) (RevisionTagResultData, error) {
	var d RevisionTagResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionTagResultData{}, err
	}
	return d, nil
}

// RevisionCherryPickResultData is the data payload for system/revision/cherry-pick-result.
type RevisionCherryPickResultData struct {
	Status          string                       `cbor:"status"`
	Version         hash.Hash                    `cbor:"version"`
	Source          hash.Hash                    `cbor:"source"`
	Conflicts       []string                     `cbor:"conflicts,omitempty"`
	CascadeWarnings []RevisionCascadeWarningData `cbor:"cascade_warnings,omitempty"`
}

func (d RevisionCherryPickResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionCherryPickResult, cbor.RawMessage(raw))
}

func RevisionCherryPickResultDataFromEntity(e entity.Entity) (RevisionCherryPickResultData, error) {
	var d RevisionCherryPickResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionCherryPickResultData{}, err
	}
	return d, nil
}

// RevisionRevertResultData is the data payload for system/revision/revert-result.
type RevisionRevertResultData struct {
	Status          string                       `cbor:"status"`
	Version         hash.Hash                    `cbor:"version"`
	Reverted        hash.Hash                    `cbor:"reverted"`
	Conflicts       []string                     `cbor:"conflicts,omitempty"`
	CascadeWarnings []RevisionCascadeWarningData `cbor:"cascade_warnings,omitempty"`
}

func (d RevisionRevertResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionRevertResult, cbor.RawMessage(raw))
}

func RevisionRevertResultDataFromEntity(e entity.Entity) (RevisionRevertResultData, error) {
	var d RevisionRevertResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionRevertResultData{}, err
	}
	return d, nil
}

// --- Merge delegation types ---

// RevisionMergeRequestData is the data payload for system/revision/merge-request.
type RevisionMergeRequestData struct {
	Base   hash.Hash `cbor:"base,omitzero"`
	Local  hash.Hash `cbor:"local"`
	Remote hash.Hash `cbor:"remote"`
}

func (d RevisionMergeRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionMergeRequest, cbor.RawMessage(raw))
}

func RevisionMergeRequestDataFromEntity(e entity.Entity) (RevisionMergeRequestData, error) {
	var d RevisionMergeRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionMergeRequestData{}, err
	}
	return d, nil
}

// RevisionMergeResponseData is the data payload for system/revision/merge-response.
type RevisionMergeResponseData struct {
	Resolved bool      `cbor:"resolved"`
	Entity   hash.Hash `cbor:"entity,omitzero"`
	Reason   string    `cbor:"reason,omitempty"`
}

func (d RevisionMergeResponseData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRevisionMergeResponse, cbor.RawMessage(raw))
}

func RevisionMergeResponseDataFromEntity(e entity.Entity) (RevisionMergeResponseData, error) {
	var d RevisionMergeResponseData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RevisionMergeResponseData{}, err
	}
	return d, nil
}
