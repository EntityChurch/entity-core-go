package types

import (
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
)

// TestConstraintTypesRegistered verifies every EXTENSION-TYPE v1.1 §4
// constraint type + the §5.2/§5.3 dispatch envelope types are present in
// the core registry with the spec-mandated field layout.
func TestConstraintTypesRegistered(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)

	cases := []struct {
		name   string
		fields map[string]string // field name → expected type_ref (primitive scalar fields only)
	}{
		{TypeConstraintMin, map[string]string{"min": "primitive/float"}},
		{TypeConstraintMax, map[string]string{"max": "primitive/float"}},
		{TypeConstraintMinLength, map[string]string{"min_length": "primitive/uint"}},
		{TypeConstraintMaxLength, map[string]string{"max_length": "primitive/uint"}},
		{TypeConstraintMinCount, map[string]string{"min_count": "primitive/uint"}},
		{TypeConstraintMaxCount, map[string]string{"max_count": "primitive/uint"}},
		{TypeConstraintPattern, map[string]string{"pattern": "primitive/string"}},
		{TypeConstraintFormat, map[string]string{"format": "primitive/string"}},
		{TypeConstraintTypePattern, map[string]string{"pattern": "primitive/string"}},
	}

	for _, tc := range cases {
		def, ok := r.Get(tc.name)
		if !ok {
			t.Errorf("constraint type %q not registered", tc.name)
			continue
		}
		for fname, expected := range tc.fields {
			fs, ok := def.Fields[fname]
			if !ok {
				t.Errorf("%s: missing field %q", tc.name, fname)
				continue
			}
			if fs.TypeRef != expected {
				t.Errorf("%s.%s: type_ref %q, want %q", tc.name, fname, fs.TypeRef, expected)
			}
		}
	}

	// one_of / not_one_of: values is array_of primitive/any.
	for _, name := range []string{TypeConstraintOneOf, TypeConstraintNotOneOf} {
		def, ok := r.Get(name)
		if !ok {
			t.Errorf("constraint type %q not registered", name)
			continue
		}
		fs := def.Fields["values"]
		if fs.ArrayOf == nil {
			t.Errorf("%s.values: expected array_of, got %+v", name, fs)
			continue
		}
		if fs.ArrayOf.TypeRef != "primitive/any" {
			t.Errorf("%s.values element: type_ref %q, want primitive/any",
				name, fs.ArrayOf.TypeRef)
		}
	}

	// Envelope types (§5.2 / §5.3).
	envReq, ok := r.Get(TypeConstraintValidateReq)
	if !ok {
		t.Fatalf("%s not registered", TypeConstraintValidateReq)
	}
	if envReq.Fields["constraint_type"].TypeRef != TypeTypeName {
		t.Errorf("%s.constraint_type: want %s, got %+v",
			TypeConstraintValidateReq, TypeTypeName, envReq.Fields["constraint_type"])
	}
	envRes, ok := r.Get(TypeConstraintValidateResult)
	if !ok {
		t.Fatalf("%s not registered", TypeConstraintValidateResult)
	}
	if envRes.Fields["valid"].TypeRef != "primitive/bool" {
		t.Errorf("%s.valid: want primitive/bool, got %+v",
			TypeConstraintValidateResult, envRes.Fields["valid"])
	}
	if reasonFS := envRes.Fields["reason"]; !reasonFS.Optional {
		t.Errorf("%s.reason: should be optional", TypeConstraintValidateResult)
	}
}

// TestValidateResultV1Schema asserts the v1.1 §8.4 schema — violations[] and
// unevaluated_fields[] — replaced the legacy errors []string surface.
func TestValidateResultV1Schema(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)

	def, ok := r.Get(TypeValidateRes)
	if !ok {
		t.Fatalf("%s not registered", TypeValidateRes)
	}
	if _, present := def.Fields["errors"]; present {
		t.Error("validate-result still carries legacy 'errors' field")
	}
	vfs, ok := def.Fields["violations"]
	if !ok {
		t.Fatal("validate-result missing 'violations' field")
	}
	if vfs.ArrayOf == nil || vfs.ArrayOf.TypeRef != TypeTypeViolation {
		t.Errorf("violations: want array_of %s, got %+v", TypeTypeViolation, vfs)
	}
	if !vfs.Optional {
		t.Error("violations should be optional (§8.4 — absent when valid is true)")
	}
	ufs, ok := def.Fields["unevaluated_fields"]
	if !ok {
		t.Fatal("validate-result missing 'unevaluated_fields' field")
	}
	if ufs.ArrayOf == nil || ufs.ArrayOf.TypeRef != "primitive/string" {
		t.Errorf("unevaluated_fields: want array_of primitive/string, got %+v", ufs)
	}

	req, ok := r.Get(TypeValidateReq)
	if !ok {
		t.Fatalf("%s not registered", TypeValidateReq)
	}
	tp, ok := req.Fields["type_path"]
	if !ok {
		t.Fatal("validate-request missing 'type_path' field")
	}
	if !tp.Optional {
		t.Error("type_path should be optional per §8.3")
	}
	if _, present := req.Fields["type_name"]; present {
		t.Error("validate-request still carries legacy 'type_name' field")
	}
}

// TestFieldSpecCarriesConstraints verifies the open-type constraints field
// from §3.3 is recognized on system/type/field-spec.
func TestFieldSpecCarriesConstraints(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)

	def, ok := r.Get("system/type/field-spec")
	if !ok {
		t.Fatal("system/type/field-spec not registered")
	}
	fs, ok := def.Fields["constraints"]
	if !ok {
		t.Fatal("field-spec missing 'constraints' field")
	}
	if fs.ArrayOf == nil {
		t.Fatalf("constraints: expected array_of, got %+v", fs)
	}
	if fs.ArrayOf.TypeRef != TypeCoreEntity {
		t.Errorf("constraints element: want %s, got %q", TypeCoreEntity, fs.ArrayOf.TypeRef)
	}
	if !fs.Optional {
		t.Error("constraints should be optional (§3.3)")
	}
}

// TestConstraintDataRoundtrip exercises ECF encode/decode for each
// constraint data struct. This is the bedrock invariant — if a struct
// can't roundtrip through ECF, every downstream cross-impl comparison
// fails closed.
func TestConstraintDataRoundtrip(t *testing.T) {
	type tcase struct {
		name string
		val  interface{}
	}
	cases := []tcase{
		{TypeConstraintMin, ConstraintMinData{Min: 1.5}},
		{TypeConstraintMax, ConstraintMaxData{Max: 100.0}},
		{TypeConstraintMinLength, ConstraintMinLengthData{MinLength: 1}},
		{TypeConstraintMaxLength, ConstraintMaxLengthData{MaxLength: 255}},
		{TypeConstraintMinCount, ConstraintMinCountData{MinCount: 1}},
		{TypeConstraintMaxCount, ConstraintMaxCountData{MaxCount: 10}},
		{TypeConstraintPattern, ConstraintPatternData{Pattern: "^[a-z]+$"}},
		{TypeConstraintFormat, ConstraintFormatData{Format: FormatURI}},
		{TypeConstraintTypePattern, ConstraintTypePatternData{Pattern: "app/*"}},
	}
	for _, tc := range cases {
		raw, err := ecf.Encode(tc.val)
		if err != nil {
			t.Errorf("%s: encode: %v", tc.name, err)
			continue
		}
		out := reflect.New(reflect.TypeOf(tc.val)).Interface()
		if err := ecf.Decode(raw, out); err != nil {
			t.Errorf("%s: decode: %v", tc.name, err)
			continue
		}
		decoded := reflect.ValueOf(out).Elem().Interface()
		if !reflect.DeepEqual(decoded, tc.val) {
			t.Errorf("%s roundtrip mismatch: got %#v, want %#v", tc.name, decoded, tc.val)
		}
	}
}
