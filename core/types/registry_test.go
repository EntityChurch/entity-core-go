package types

import (
	"testing"
)

func TestRegistryAll(t *testing.T) {
	r := NewTypeRegistry()
	r.RegisterPrimitive("z/last")
	r.RegisterPrimitive("a/first")
	r.RegisterPrimitive("m/middle")

	all := r.All()
	if len(all) != 3 {
		t.Fatalf("expected 3, got %d", len(all))
	}
	if all[0].Name != "a/first" || all[1].Name != "m/middle" || all[2].Name != "z/last" {
		t.Fatalf("not sorted: %v", []string{all[0].Name, all[1].Name, all[2].Name})
	}
}

// TestSetResolverConfigRequestConfigFieldIsPrecise pins §4.3's own table: the
// `config` field of set-resolver-config-request MUST reflect to the precise
// system/registry/resolver-config, NOT the looser core/entity the Go struct
// field (entity.Entity) reflects to by default. Without the OverrideField in
// RegisterCoreTypes this reads core/entity, which erases the config's own
// fields from the type checker and FAILs py's cross-impl type_system check
// (RULINGS-STORAGE-SUBSTITUTE-CROSS-IMPL Ruling 2, applied here). Teeth: this
// goes RED the moment the override is dropped or clobbered.
func TestSetResolverConfigRequestConfigFieldIsPrecise(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)

	def, ok := r.Get(TypeRegistrySetResolverConfigRequest)
	if !ok {
		t.Fatalf("%s not registered", TypeRegistrySetResolverConfigRequest)
	}
	spec, ok := def.Fields["config"]
	if !ok {
		t.Fatal("config field absent from published descriptor")
	}
	if spec.TypeRef != TypeRegistryResolverConfig {
		t.Fatalf("config type_ref: got %q want %q (§4.3 table — the precise token, not core/entity)",
			spec.TypeRef, TypeRegistryResolverConfig)
	}
}

func TestRegistryOverrideField(t *testing.T) {
	r := NewTypeRegistry()
	r.RegisterManual(TypeDefinition{
		Name: "test/type",
		Fields: map[string]FieldSpec{
			"field1": {TypeRef: "primitive/string"},
		},
	})

	err := r.OverrideField("test/type", "field1", FieldSpec{TypeRef: "primitive/uint"})
	if err != nil {
		t.Fatal(err)
	}

	def, ok := r.Get("test/type")
	if !ok {
		t.Fatal("type not found")
	}
	if def.Fields["field1"].TypeRef != "primitive/uint" {
		t.Fatalf("expected primitive/uint, got %s", def.Fields["field1"].TypeRef)
	}
}

func TestRegistryAddField(t *testing.T) {
	r := NewTypeRegistry()
	r.RegisterManual(TypeDefinition{
		Name: "test/type",
		Fields: map[string]FieldSpec{
			"field1": {TypeRef: "primitive/string"},
		},
	})

	err := r.AddField("test/type", "field2", FieldSpec{TypeRef: "primitive/uint"})
	if err != nil {
		t.Fatal(err)
	}

	def, _ := r.Get("test/type")
	if _, ok := def.Fields["field2"]; !ok {
		t.Fatal("field2 not added")
	}

	// Adding duplicate should fail.
	err = r.AddField("test/type", "field2", FieldSpec{TypeRef: "primitive/bool"})
	if err == nil {
		t.Fatal("expected error for duplicate field")
	}
}

func TestRegistryOverrideNonexistent(t *testing.T) {
	r := NewTypeRegistry()
	err := r.OverrideField("nonexistent", "field", FieldSpec{TypeRef: "primitive/string"})
	if err == nil {
		t.Fatal("expected error for nonexistent type")
	}
}
