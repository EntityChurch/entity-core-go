package types

import (
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

func TestReflectPrimitiveFields(t *testing.T) {
	type sample struct {
		S string `cbor:"s"`
		B []byte `cbor:"b"`
		U uint64 `cbor:"u"`
		I int64  `cbor:"i"`
		F bool   `cbor:"f"`
	}

	r := NewTypeRegistry()
	def, err := r.ReflectType("test/sample", reflect.TypeOf(sample{}))
	if err != nil {
		t.Fatal(err)
	}

	expects := map[string]string{
		"s": "primitive/string",
		"b": "primitive/bytes",
		"u": "primitive/uint",
		"i": "primitive/int",
		"f": "primitive/bool",
	}

	for field, typeRef := range expects {
		fs, ok := def.Fields[field]
		if !ok {
			t.Fatalf("missing field %q", field)
		}
		if fs.TypeRef != typeRef {
			t.Errorf("field %q: expected type_ref %q, got %q", field, typeRef, fs.TypeRef)
		}
		if fs.Optional {
			t.Errorf("field %q: should not be optional", field)
		}
	}
}

func TestReflectOptionalFields(t *testing.T) {
	type sample struct {
		Ptr       *string `cbor:"ptr"`
		OmitEmpty string  `cbor:"omit,omitempty"`
	}

	r := NewTypeRegistry()
	def, err := r.ReflectType("test/opt", reflect.TypeOf(sample{}))
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"ptr", "omit"} {
		fs, ok := def.Fields[field]
		if !ok {
			t.Fatalf("missing field %q", field)
		}
		if !fs.Optional {
			t.Errorf("field %q: should be optional", field)
		}
	}
}

func TestReflectRawMessage(t *testing.T) {
	type sample struct {
		Data cbor.RawMessage `cbor:"data"`
	}

	r := NewTypeRegistry()
	def, err := r.ReflectType("test/raw", reflect.TypeOf(sample{}))
	if err != nil {
		t.Fatal(err)
	}

	fs := def.Fields["data"]
	if fs.TypeRef != "primitive/any" {
		t.Fatalf("expected primitive/any, got %q", fs.TypeRef)
	}
}

func TestReflectHashField(t *testing.T) {
	type sample struct {
		H hash.Hash `cbor:"h"`
	}

	r := NewTypeRegistry()
	r.RegisterGoType(reflect.TypeOf(hash.Hash{}), "system/hash")

	def, err := r.ReflectType("test/hash", reflect.TypeOf(sample{}))
	if err != nil {
		t.Fatal(err)
	}

	fs := def.Fields["h"]
	if fs.TypeRef != "system/hash" {
		t.Fatalf("expected system/hash, got %q", fs.TypeRef)
	}
}

func TestReflectNestedStruct(t *testing.T) {
	type Inner struct {
		X string `cbor:"x"`
	}
	type Outer struct {
		I *Inner `cbor:"i,omitempty"`
	}

	r := NewTypeRegistry()
	r.ReflectType("test/inner", reflect.TypeOf(Inner{}))

	def, err := r.ReflectType("test/outer", reflect.TypeOf(Outer{}))
	if err != nil {
		t.Fatal(err)
	}

	fs := def.Fields["i"]
	if fs.TypeRef != "test/inner" {
		t.Fatalf("expected test/inner, got %q", fs.TypeRef)
	}
	if !fs.Optional {
		t.Fatal("expected optional")
	}
}

func TestReflectSliceAndMap(t *testing.T) {
	type sample struct {
		Arr []string          `cbor:"arr"`
		M   map[string]uint64 `cbor:"m"`
	}

	r := NewTypeRegistry()
	def, err := r.ReflectType("test/collections", reflect.TypeOf(sample{}))
	if err != nil {
		t.Fatal(err)
	}

	// Array
	fs := def.Fields["arr"]
	if fs.ArrayOf == nil {
		t.Fatal("expected array_of")
	}
	if fs.ArrayOf.TypeRef != "primitive/string" {
		t.Fatalf("expected array_of primitive/string, got %q", fs.ArrayOf.TypeRef)
	}

	// Map
	fs = def.Fields["m"]
	if fs.MapOf == nil {
		t.Fatal("expected map_of")
	}
	if fs.MapOf.TypeRef != "primitive/uint" {
		t.Fatalf("expected map_of primitive/uint, got %q", fs.MapOf.TypeRef)
	}
}

func TestReflectSelfReference(t *testing.T) {
	// FieldSpec contains *FieldSpec via ArrayOf and MapOf, and []entity.Entity
	// via Constraints (EXTENSION-TYPE v1.1 §3.3).
	r := NewTypeRegistry()
	r.RegisterGoType(reflect.TypeOf(entity.Entity{}), TypeCoreEntity)
	def, err := r.ReflectType("system/type/field-spec", reflect.TypeOf(FieldSpec{}))
	if err != nil {
		t.Fatal(err)
	}

	fs := def.Fields["array_of"]
	if !fs.Optional {
		t.Fatal("array_of should be optional")
	}
	if fs.TypeRef != "system/type/field-spec" {
		t.Fatalf("expected self-reference, got %q", fs.TypeRef)
	}
}

func TestReflectUnregisteredStruct(t *testing.T) {
	type Unknown struct {
		X string `cbor:"x"`
	}
	type Outer struct {
		U Unknown `cbor:"u"`
	}

	r := NewTypeRegistry()
	_, err := r.ReflectType("test/outer", reflect.TypeOf(Outer{}))
	if err == nil {
		t.Fatal("expected error for unregistered struct")
	}
}
