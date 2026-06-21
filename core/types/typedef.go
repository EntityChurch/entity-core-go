package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

// TypeType is the entity type for all type definition entities.
const TypeType = "system/type"

// TypeDefinition represents the data payload of a system/type entity.
type TypeDefinition struct {
	Name       string               `cbor:"name"`
	Extends    string               `cbor:"extends,omitempty"`
	Fields     map[string]FieldSpec `cbor:"fields,omitempty"`
	Layout     []string             `cbor:"layout,omitempty"`
	TypeParams []string             `cbor:"type_params,omitempty"`
	TypeArgs   map[string]string    `cbor:"type_args,omitempty"`
}

// FieldSpec represents a system/type/field-spec value.
// Exactly one of TypeRef, ArrayOf, MapOf, or UnionOf must be set.
type FieldSpec struct {
	TypeRef   string            `cbor:"type_ref,omitempty"`
	Optional  bool              `cbor:"optional,omitempty"`
	ArrayOf   *FieldSpec        `cbor:"array_of,omitempty"`
	MapOf     *FieldSpec        `cbor:"map_of,omitempty"`
	UnionOf   []FieldSpec       `cbor:"union_of,omitempty"`
	TypeParam string            `cbor:"type_param,omitempty"`
	TypeArgs  map[string]string `cbor:"type_args,omitempty"`
	Default   interface{}       `cbor:"default,omitempty"`
	KeyType   string            `cbor:"key_type,omitempty"`
	ByteSize  *uint64           `cbor:"byte_size,omitempty"`
	// Constraints carries the open-type extension field defined by
	// EXTENSION-TYPE v1.1 §3.3. Each constraint is a core/entity
	// {type, data, content_hash}. Peers without the type extension
	// preserve this without interpretation; peers at Level 2+ with the
	// type extension dispatch each constraint at validate time.
	Constraints []entity.Entity `cbor:"constraints,omitempty"`
}

// ToEntity creates a system/type entity from this definition.
func (d TypeDefinition) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeType, cbor.RawMessage(raw))
}

// TreePath returns the location index path for this type definition.
func (d TypeDefinition) TreePath() string {
	return "system/type/" + d.Name
}

func uintPtr(v uint64) *uint64 { return &v }
