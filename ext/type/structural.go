package typeext

import (
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// structuralCheck implements the Phase 1 (structural) half of §2.3: field
// presence, basic type alignment, no extra-field rejection (open-type
// extension is the v7 default).
//
// Note: this is intentionally minimal. Full structural validation (union
// matching, generic resolution, recursive type_ref descent) is a Layer 1
// concern per §2.1 — when the core type system grows a dedicated
// structural validator, this function should delegate to it instead. For
// v1.1 the constraint-dispatch surface is what's new; structural needs
// only catch obvious shape mismatches.
func structuralCheck(def types.TypeDefinition, fields map[string]cbor.RawMessage) []types.Violation {
	var violations []types.Violation

	names := make([]string, 0, len(def.Fields))
	for n := range def.Fields {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, fname := range names {
		spec := def.Fields[fname]
		raw, present := fields[fname]
		if !present {
			if !spec.Optional {
				violations = append(violations, types.Violation{
					Field:  fname,
					Kind:   types.ViolationKindStructural,
					Reason: "required field is absent",
				})
			}
			continue
		}
		if v := checkFieldType(fname, raw, spec); v != nil {
			violations = append(violations, *v)
		}
	}

	return violations
}

// checkFieldType verifies that raw CBOR for a field decodes into a value
// consistent with the field spec's declared shape. Returns nil on match.
//
// The check is intentionally permissive — it catches obvious mismatches
// (e.g., "field declared array_of, got a string") without trying to
// recursively descend type_refs. That's the job of a full structural
// validator (see structuralCheck comment).
func checkFieldType(fname string, raw cbor.RawMessage, spec types.FieldSpec) *types.Violation {
	switch {
	case spec.ArrayOf != nil:
		var arr []cbor.RawMessage
		if err := ecf.Decode(raw, &arr); err != nil {
			return &types.Violation{
				Field:  fname,
				Kind:   types.ViolationKindStructural,
				Reason: "field declared array but got non-array value",
			}
		}
	case spec.MapOf != nil:
		// Map keys can be strings or hashes; just verify the value is a map.
		var m map[interface{}]cbor.RawMessage
		if err := ecf.Decode(raw, &m); err != nil {
			return &types.Violation{
				Field:  fname,
				Kind:   types.ViolationKindStructural,
				Reason: "field declared map but got non-map value",
			}
		}
	case spec.TypeRef != "":
		return checkPrimitiveType(fname, raw, spec.TypeRef)
	}
	return nil
}

// checkPrimitiveType validates raw CBOR against a primitive type_ref. The
// universe is small: primitive/string, primitive/bytes, primitive/uint,
// primitive/int, primitive/float, primitive/bool, primitive/null,
// primitive/any. Non-primitive type_refs (e.g., user-defined types) pass
// without descent — full graph walking is deferred.
func checkPrimitiveType(fname string, raw cbor.RawMessage, ref string) *types.Violation {
	switch ref {
	case "primitive/string":
		var s string
		if err := ecf.Decode(raw, &s); err != nil {
			return &types.Violation{
				Field:  fname,
				Kind:   types.ViolationKindStructural,
				Reason: "field declared primitive/string but value is not a string",
			}
		}
	case "primitive/bytes":
		var b []byte
		if err := ecf.Decode(raw, &b); err != nil {
			return &types.Violation{
				Field:  fname,
				Kind:   types.ViolationKindStructural,
				Reason: "field declared primitive/bytes but value is not bytes",
			}
		}
	case "primitive/uint":
		var u uint64
		if err := ecf.Decode(raw, &u); err != nil {
			return &types.Violation{
				Field:  fname,
				Kind:   types.ViolationKindStructural,
				Reason: "field declared primitive/uint but value is not an unsigned integer",
			}
		}
	case "primitive/int":
		var i int64
		if err := ecf.Decode(raw, &i); err != nil {
			return &types.Violation{
				Field:  fname,
				Kind:   types.ViolationKindStructural,
				Reason: "field declared primitive/int but value is not an integer",
			}
		}
	case "primitive/float":
		var f float64
		if err := ecf.Decode(raw, &f); err != nil {
			return &types.Violation{
				Field:  fname,
				Kind:   types.ViolationKindStructural,
				Reason: "field declared primitive/float but value is not a float",
			}
		}
	case "primitive/bool":
		var b bool
		if err := ecf.Decode(raw, &b); err != nil {
			return &types.Violation{
				Field:  fname,
				Kind:   types.ViolationKindStructural,
				Reason: "field declared primitive/bool but value is not a bool",
			}
		}
	case "primitive/any", "primitive/null":
		// primitive/any accepts anything by definition; primitive/null
		// would need a dedicated null check (RFC 8949 major type 7 ub 22)
		// — left permissive for now.
	default:
		// Non-primitive type_ref — defer to graph-walking validator.
	}
	return nil
}
