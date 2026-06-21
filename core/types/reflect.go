package types

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Sentinel types checked by name before the Kind switch.
var (
	cborRawMessageType = reflect.TypeOf(cbor.RawMessage{})
	emptyInterfaceType = reflect.TypeOf((*interface{})(nil)).Elem()
)

// parseCBORTag extracts the CBOR field name and omitempty flag from a struct tag.
// Returns skip=true if the field has no cbor tag or is explicitly "-".
func parseCBORTag(sf reflect.StructField) (name string, omitempty bool, skip bool) {
	tag := sf.Tag.Get("cbor")
	if tag == "" || tag == "-" {
		return "", false, true
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" || name == "-" {
		return "", false, true
	}
	for _, p := range parts[1:] {
		if p == "omitempty" || p == "omitzero" {
			omitempty = true
		}
	}
	return name, omitempty, false
}

// resolveFieldSpec converts a Go type into a FieldSpec.
// knownTypes maps Go types to spec names for struct resolution.
func resolveFieldSpec(t reflect.Type, optional bool, knownTypes map[reflect.Type]string) (FieldSpec, error) {
	fs := FieldSpec{Optional: optional}

	// Check named types BEFORE Kind switch.
	// cbor.RawMessage is type RawMessage []byte — must catch before slice branch.
	if t == cborRawMessageType {
		fs.TypeRef = "primitive/any"
		return fs, nil
	}

	// Check known Go type mappings (e.g. hash.Hash → system/hash).
	if specName, ok := knownTypes[t]; ok {
		fs.TypeRef = specName
		return fs, nil
	}

	// interface{} → primitive/any
	if t == emptyInterfaceType {
		fs.TypeRef = "primitive/any"
		return fs, nil
	}

	// Kind-based resolution.
	switch t.Kind() {
	case reflect.String:
		fs.TypeRef = "primitive/string"
	case reflect.Bool:
		fs.TypeRef = "primitive/bool"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		fs.TypeRef = "primitive/uint"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fs.TypeRef = "primitive/int"
	case reflect.Float32, reflect.Float64:
		fs.TypeRef = "primitive/float"

	case reflect.Slice:
		// []byte → primitive/bytes
		if t.Elem().Kind() == reflect.Uint8 {
			fs.TypeRef = "primitive/bytes"
			return fs, nil
		}
		// []T → array_of
		elemType := t.Elem()
		if elemType.Kind() == reflect.Ptr {
			elemType = elemType.Elem()
		}
		inner, err := resolveFieldSpec(elemType, false, knownTypes)
		if err != nil {
			return FieldSpec{}, fmt.Errorf("array element: %w", err)
		}
		fs.ArrayOf = &inner
		return fs, nil

	case reflect.Map:
		// map[K]V → map_of
		keyType := t.Key()
		valType := t.Elem()

		inner, err := resolveFieldSpec(valType, false, knownTypes)
		if err != nil {
			return FieldSpec{}, fmt.Errorf("map value: %w", err)
		}
		fs.MapOf = &inner

		// Non-string keys get key_type.
		if keyType != reflect.TypeOf("") {
			if keySpecName, ok := knownTypes[keyType]; ok {
				fs.KeyType = keySpecName
			} else {
				keyInner, err := resolveFieldSpec(keyType, false, knownTypes)
				if err != nil {
					return FieldSpec{}, fmt.Errorf("map key: %w", err)
				}
				fs.KeyType = keyInner.TypeRef
			}
		}
		return fs, nil

	case reflect.Struct:
		// Look up in known types.
		if specName, ok := knownTypes[t]; ok {
			fs.TypeRef = specName
			return fs, nil
		}
		return FieldSpec{}, fmt.Errorf("unregistered struct type: %s", t)

	case reflect.Interface:
		fs.TypeRef = "primitive/any"
		return fs, nil

	case reflect.Ptr:
		// Should have been dereferenced by caller, but handle gracefully.
		return resolveFieldSpec(t.Elem(), optional, knownTypes)

	default:
		return FieldSpec{}, fmt.Errorf("unsupported Go type: %s (kind: %s)", t, t.Kind())
	}

	return fs, nil
}
