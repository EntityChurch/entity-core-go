package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Query extension type constants (EXTENSION-QUERY.md v1.0).
const (
	TypeQueryExpression     = "system/query/expression"
	TypeQueryFieldPredicate = "system/query/field-predicate"
	TypeQueryResult         = "system/query/result"
	TypeQueryMatch          = "system/query/match"
	TypeQueryConstraints    = "system/query/constraints"
	TypeQueryAllowances     = "system/query/allowances"
	TypeQueryIndexConfig    = "system/query/index-config"
)

// QueryExpressionData is the data payload for system/query/expression.
type QueryExpressionData struct {
	TypeFilter      string                    `cbor:"type_filter,omitempty"`
	FieldFilters    []QueryFieldPredicateData `cbor:"field_filters,omitempty"`
	RefFilter       *hash.Hash                `cbor:"ref_filter,omitempty"`
	PathFilter      string                    `cbor:"path_filter,omitempty"`
	PathPrefix      string                    `cbor:"path_prefix,omitempty"`
	Limit           *uint64                   `cbor:"limit,omitempty"`
	Cursor          string                    `cbor:"cursor,omitempty"`
	OrderBy         string                    `cbor:"order_by,omitempty"`
	Descending      *bool                     `cbor:"descending,omitempty"`
	IncludeEntities *bool                     `cbor:"include_entities,omitempty"`
}

// ToEntity creates a system/query/expression entity.
func (d QueryExpressionData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQueryExpression, cbor.RawMessage(raw))
}

// QueryExpressionDataFromEntity decodes a query expression entity's data.
func QueryExpressionDataFromEntity(e entity.Entity) (QueryExpressionData, error) {
	var d QueryExpressionData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QueryExpressionData{}, err
	}
	return d, nil
}

// QueryFieldPredicateData is the data payload for system/query/field-predicate.
type QueryFieldPredicateData struct {
	Field    string          `cbor:"field"`
	Operator string          `cbor:"operator"`
	Value    cbor.RawMessage `cbor:"value,omitempty"`
}

// ToEntity creates a system/query/field-predicate entity.
func (d QueryFieldPredicateData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQueryFieldPredicate, cbor.RawMessage(raw))
}

// QueryFieldPredicateDataFromEntity decodes a field predicate entity's data.
func QueryFieldPredicateDataFromEntity(e entity.Entity) (QueryFieldPredicateData, error) {
	var d QueryFieldPredicateData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QueryFieldPredicateData{}, err
	}
	return d, nil
}

// QueryResultData is the data payload for system/query/result.
type QueryResultData struct {
	Matches []QueryMatchData `cbor:"matches"`
	Total   uint64           `cbor:"total"`
	HasMore bool             `cbor:"has_more"`
	Cursor  string           `cbor:"cursor,omitempty"`
}

// ToEntity creates a system/query/result entity.
func (d QueryResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQueryResult, cbor.RawMessage(raw))
}

// QueryResultDataFromEntity decodes a query result entity's data.
func QueryResultDataFromEntity(e entity.Entity) (QueryResultData, error) {
	var d QueryResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QueryResultData{}, err
	}
	return d, nil
}

// QueryMatchData is the data payload for system/query/match.
type QueryMatchData struct {
	Path string    `cbor:"path,omitempty"`
	Hash hash.Hash `cbor:"hash"`
	Type string    `cbor:"type"`
}

// ToEntity creates a system/query/match entity.
func (d QueryMatchData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQueryMatch, cbor.RawMessage(raw))
}

// QueryConstraintsData is the data payload for system/query/constraints.
// These are narrowing fields — absent means unconstrained.
type QueryConstraintsData struct {
	MaxResults *uint64          `cbor:"max_results,omitempty"`
	TypeScope  *CapabilityScope `cbor:"type_scope,omitempty"`
}

// QueryAllowancesData is the data payload for system/query/allowances.
// These are expanding fields — absent means most restricted (tree scope only).
type QueryAllowancesData struct {
	Scope string `cbor:"scope,omitempty"` // "content_store" expands access; absent = tree scope
}

// ToEntity creates a system/query/constraints entity.
func (d QueryConstraintsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeQueryConstraints, cbor.RawMessage(raw))
}

// QueryConstraintsDataFromEntity decodes a query constraints entity's data.
func QueryConstraintsDataFromEntity(e entity.Entity) (QueryConstraintsData, error) {
	var d QueryConstraintsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return QueryConstraintsData{}, err
	}
	return d, nil
}

// QueryIndexConfigData is the data payload for system/query/index-config.
type QueryIndexConfigData struct {
	TypeName string   `cbor:"type_name"`
	Fields   []string `cbor:"fields"`
}
