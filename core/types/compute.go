package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Compute extension type names (EXTENSION-COMPUTE v3.7).
const (
	// Core expression types (§2.1).
	TypeComputeLiteral     = "compute/literal"
	TypeComputeLookupScope = "compute/lookup/scope"
	TypeComputeLookupTree  = "compute/lookup/tree"
	TypeComputeLookupHash  = "compute/lookup/hash"
	TypeComputeApply       = "compute/apply"
	TypeComputeIf          = "compute/if"
	TypeComputeLet         = "compute/let"
	TypeComputeLambda      = "compute/lambda"

	// Inline expression types (§2.2).
	TypeComputeArithmetic  = "compute/arithmetic"
	TypeComputeCompare     = "compute/compare"
	TypeComputeLogic       = "compute/logic"
	TypeComputeField       = "compute/field"
	TypeComputeConstruct   = "compute/construct"
	TypeComputeIndex       = "compute/index"
	TypeComputeLength      = "compute/length"
	TypeComputeNumericCast = "compute/numeric-cast"

	// Value types (§2.3).
	TypeComputeClosure = "compute/closure"
	TypeComputeScope   = "compute/scope"

	// Result and error types (§2.4).
	TypeComputeResult = "compute/result"
	TypeComputeError  = "compute/error"

	// Subgraph metadata (§2.5).
	TypeComputeSubgraph = "system/compute/subgraph"

	// Install request and response types (§2.6).
	// Uninstall takes no params (path moved to EXECUTE.resource per V7 §3.2
	// path-as-resource convention; uses empty primitive/any per the
	// empty-params wire shape).
	TypeComputeInstallRequest = "system/compute/install-request"
	TypeComputeInstallResult  = "system/compute/install-result"

	// Builtin args types (§3.5).
	TypeComputeStoreArgs  = "system/compute/store-args"
	TypeComputeMapArgs    = "system/compute/map-args"
	TypeComputeFilterArgs = "system/compute/filter-args"
	TypeComputeFoldArgs   = "system/compute/fold-args"

	// v3.19b §2.3: kind-tagged scope binding value model.
	TypeComputeScopeBinding = "system/compute/scope-binding"
)

// --- Core expression types (§2.1) ---

type ComputeLiteralData struct {
	Value interface{} `cbor:"value"`
}

func (d ComputeLiteralData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeLiteral, cbor.RawMessage(raw))
}

type ComputeLookupScopeData struct {
	Name string `cbor:"name"`
}

func (d ComputeLookupScopeData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeLookupScope, cbor.RawMessage(raw))
}

type ComputeLookupTreeData struct {
	Path     string `cbor:"path"`
	Relative bool   `cbor:"relative,omitempty"`
}

func (d ComputeLookupTreeData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeLookupTree, cbor.RawMessage(raw))
}

type ComputeLookupHashData struct {
	Hash     hash.Hash `cbor:"hash"`
	Path     string    `cbor:"path,omitempty"`
	Relative bool      `cbor:"relative,omitempty"`
}

func (d ComputeLookupHashData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeLookupHash, cbor.RawMessage(raw))
}

type ComputeApplyData struct {
	Path       string               `cbor:"path,omitempty"`
	Operation  string               `cbor:"operation,omitempty"`
	Resource   hash.Hash            `cbor:"resource,omitzero"`
	Fn         hash.Hash            `cbor:"fn,omitzero"`
	Args       map[string]hash.Hash `cbor:"args,omitempty"`
	Capability hash.Hash            `cbor:"capability,omitzero"`
}

func (d ComputeApplyData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeApply, cbor.RawMessage(raw))
}

type ComputeIfData struct {
	Condition hash.Hash  `cbor:"condition"`
	Then      hash.Hash  `cbor:"then"`
	Else      *hash.Hash `cbor:"else,omitempty"`
}

func (d ComputeIfData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeIf, cbor.RawMessage(raw))
}

type ComputeLetBinding struct {
	Name  string    `cbor:"name"`
	Value hash.Hash `cbor:"value"`
}

type ComputeLetData struct {
	Bindings []ComputeLetBinding `cbor:"bindings"`
	Body     hash.Hash           `cbor:"body"`
}

func (d ComputeLetData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeLet, cbor.RawMessage(raw))
}

type ComputeLambdaData struct {
	Params []string  `cbor:"params"`
	Body   hash.Hash `cbor:"body"`
}

func (d ComputeLambdaData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeLambda, cbor.RawMessage(raw))
}

// --- Inline expression types (§2.2) ---

type ComputeArithmeticData struct {
	Op    string    `cbor:"op"`
	Left  hash.Hash `cbor:"left"`
	Right hash.Hash `cbor:"right"`
}

func (d ComputeArithmeticData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeArithmetic, cbor.RawMessage(raw))
}

type ComputeCompareData struct {
	Op    string    `cbor:"op"`
	Left  hash.Hash `cbor:"left"`
	Right hash.Hash `cbor:"right"`
}

func (d ComputeCompareData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeCompare, cbor.RawMessage(raw))
}

type ComputeLogicData struct {
	Op    string     `cbor:"op"`
	Left  hash.Hash  `cbor:"left"`
	Right *hash.Hash `cbor:"right,omitempty"`
}

func (d ComputeLogicData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeLogic, cbor.RawMessage(raw))
}

type ComputeFieldData struct {
	Name   string    `cbor:"name"`
	Entity hash.Hash `cbor:"entity"`
}

func (d ComputeFieldData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeField, cbor.RawMessage(raw))
}

type ComputeConstructData struct {
	EntityType string               `cbor:"entity_type"`
	Fields     map[string]hash.Hash `cbor:"fields"`
}

func (d ComputeConstructData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeConstruct, cbor.RawMessage(raw))
}

type ComputeIndexData struct {
	Array hash.Hash `cbor:"array"`
	Index hash.Hash `cbor:"index"`
}

func (d ComputeIndexData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeIndex, cbor.RawMessage(raw))
}

type ComputeLengthData struct {
	Array hash.Hash `cbor:"array"`
}

func (d ComputeLengthData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeLength, cbor.RawMessage(raw))
}

type ComputeNumericCastData struct {
	Value  hash.Hash `cbor:"value"`
	ToType string    `cbor:"to_type"`
}

func (d ComputeNumericCastData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeNumericCast, cbor.RawMessage(raw))
}

// --- Value types (§2.3) ---

type ComputeClosureData struct {
	Params []string   `cbor:"params"`
	Body   hash.Hash  `cbor:"body"`
	Env    *hash.Hash `cbor:"env,omitempty"`
}

func (d ComputeClosureData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeClosure, cbor.RawMessage(raw))
}

// ComputeScopeBinding is a kind-tagged scope binding per EXTENSION-COMPUTE v3.19b
// §2.3 (N1/N3). Mutually exclusive: kind="entity" has EntityHash set; kind="value"
// has Value set. ECF canonical: within a binding, keys sort `kind` (4) before
// `entity_hash` (11) or `value` (5). The kind tag disambiguates an entity hash-ref
// from a 33-byte value by construction (no shape ambiguity per N3).
type ComputeScopeBinding struct {
	Kind       string      `cbor:"kind"`                   // "entity" | "value"
	EntityHash *hash.Hash  `cbor:"entity_hash,omitempty"`  // present iff kind == "entity"
	Value      interface{} `cbor:"value,omitempty"`        // present iff kind == "value"
}

const (
	ScopeBindingKindEntity = "entity"
	ScopeBindingKindValue  = "value"
)

type ComputeScopeData struct {
	Bindings map[string]ComputeScopeBinding `cbor:"bindings"`
}

func (d ComputeScopeData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeScope, cbor.RawMessage(raw))
}

// --- Result and error types (§2.4) ---

type ComputeResultData struct {
	Value      interface{} `cbor:"value"`
	Expression hash.Hash   `cbor:"expression"`
}

func (d ComputeResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeResult, cbor.RawMessage(raw))
}

type ComputeErrorData struct {
	Code       string     `cbor:"code"`
	Message    string     `cbor:"message"`
	At         string     `cbor:"at,omitempty"`
	Expression *hash.Hash `cbor:"expression,omitempty"`
}

func (d ComputeErrorData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeError, cbor.RawMessage(raw))
}

// ComputeErrorDataFromEntity decodes a compute/error entity's data.
func ComputeErrorDataFromEntity(e entity.Entity) (ComputeErrorData, error) {
	var d ComputeErrorData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ComputeErrorData{}, err
	}
	return d, nil
}

// --- Subgraph metadata (§2.5) ---

type ComputeSubgraphData struct {
	RootExpressionPath   string      `cbor:"root_expression_path"`
	RootExpression       hash.Hash   `cbor:"root_expression"`
	InstallationGrant    hash.Hash   `cbor:"installation_grant"`
	InstalledBy          hash.Hash   `cbor:"installed_by"`
	ResultPath           string      `cbor:"result_path"`
	Status               string      `cbor:"status"`
	AuthorizedDataHashes []hash.Hash `cbor:"authorized_data_hashes,omitempty"`
}

func (d ComputeSubgraphData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeSubgraph, cbor.RawMessage(raw))
}

// ComputeSubgraphDataFromEntity decodes a system/compute/subgraph entity's data.
func ComputeSubgraphDataFromEntity(e entity.Entity) (ComputeSubgraphData, error) {
	var d ComputeSubgraphData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ComputeSubgraphData{}, err
	}
	return d, nil
}

// --- Install/uninstall request and response types (§2.6) ---

type ComputeInstallRequestData struct {
	ResultPath string `cbor:"result_path,omitempty"`
}

func (d ComputeInstallRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeInstallRequest, cbor.RawMessage(raw))
}

// ComputeInstallRequestDataFromEntity decodes a system/compute/install-request entity's data.
func ComputeInstallRequestDataFromEntity(e entity.Entity) (ComputeInstallRequestData, error) {
	var d ComputeInstallRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ComputeInstallRequestData{}, err
	}
	return d, nil
}

type ComputeInstallResultData struct {
	SubgraphPath     string      `cbor:"subgraph_path"`
	ImpureOperations interface{} `cbor:"impure_operations"`
	ResultPath       string      `cbor:"result_path"`
}

func (d ComputeInstallResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeInstallResult, cbor.RawMessage(raw))
}

// --- Builtin args types (§3.5) ---

type ComputeStoreArgsData struct {
	Path  string    `cbor:"path"`
	Value hash.Hash `cbor:"value"`
}

func (d ComputeStoreArgsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeStoreArgs, cbor.RawMessage(raw))
}

type ComputeMapArgsData struct {
	Collection hash.Hash `cbor:"collection"`
	Fn         hash.Hash `cbor:"fn"`
}

func (d ComputeMapArgsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeMapArgs, cbor.RawMessage(raw))
}

type ComputeFilterArgsData struct {
	Collection hash.Hash `cbor:"collection"`
	Fn         hash.Hash `cbor:"fn"`
}

func (d ComputeFilterArgsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeFilterArgs, cbor.RawMessage(raw))
}

type ComputeFoldArgsData struct {
	Collection hash.Hash `cbor:"collection"`
	Fn         hash.Hash `cbor:"fn"`
	Initial    hash.Hash `cbor:"initial"`
}

func (d ComputeFoldArgsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeComputeFoldArgs, cbor.RawMessage(raw))
}
