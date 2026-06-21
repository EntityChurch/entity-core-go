package query

import (
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// hashRef is a hash reference found in entity data.
type hashRef struct {
	Hash      hash.Hash
	FieldName string // top-level field containing this reference
}

// extractHashRefs walks CBOR-encoded entity data and extracts all values that
// look like content hashes (33-byte byte strings with algorithm byte 0x00).
//
// The data is a CBOR map. Top-level field names are tracked so the reverse
// index knows which field contains each reference. For nested references, the
// top-level field name is used (not the full path).
func extractHashRefs(data cbor.RawMessage) []hashRef {
	if len(data) == 0 {
		return nil
	}

	// Decode data as map[string]cbor.RawMessage to get field names.
	var fields map[string]cbor.RawMessage
	if err := cbor.Unmarshal(data, &fields); err != nil {
		// Not a map — walk raw CBOR without field names.
		var refs []hashRef
		walkCBOR(data, "", func(h hash.Hash, field string) {
			refs = append(refs, hashRef{Hash: h, FieldName: field})
		})
		return refs
	}

	var refs []hashRef
	for fieldName, raw := range fields {
		walkCBOR(raw, fieldName, func(h hash.Hash, field string) {
			refs = append(refs, hashRef{Hash: h, FieldName: field})
		})
	}
	return refs
}

// walkCBOR recursively walks a CBOR value looking for byte strings that match
// the hash format (33 bytes, algorithm 0x00). Each found hash is reported with
// the given field name.
func walkCBOR(raw cbor.RawMessage, fieldName string, fn func(hash.Hash, string)) {
	if len(raw) == 0 {
		return
	}

	// Try as byte string first — this is the hash case.
	var bs []byte
	if err := cbor.Unmarshal(raw, &bs); err == nil {
		if h, err := hash.FromBytes(bs); err == nil && !h.IsZero() {
			fn(h, fieldName)
		}
		return
	}

	// Try as array.
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &arr); err == nil {
		for _, elem := range arr {
			walkCBOR(elem, fieldName, fn)
		}
		return
	}

	// Try as map (string keys — the common case for entity data).
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &m); err == nil {
		for _, v := range m {
			walkCBOR(v, fieldName, fn)
		}
		return
	}

	// Primitive (string, int, bool, null) — no hashes here.
}

// pathRef is a path reference found in entity data.
type pathRef struct {
	Path      string
	FieldName string
}

// extractPathRefs extracts string values from known path-typed fields in entity
// data. Since identifying path fields requires type definitions, this function
// takes a set of field names known to contain system/tree/path values.
//
// For system types with well-known path fields, the caller provides the field
// names. For unknown types, this returns nil (no path indexing).
func extractPathRefs(data cbor.RawMessage, pathFields map[string]bool) []pathRef {
	if len(data) == 0 || len(pathFields) == 0 {
		return nil
	}

	var fields map[string]cbor.RawMessage
	if err := cbor.Unmarshal(data, &fields); err != nil {
		return nil
	}

	var refs []pathRef
	for fieldName, raw := range fields {
		if !pathFields[fieldName] {
			continue
		}
		// Try as single string.
		var s string
		if err := cbor.Unmarshal(raw, &s); err == nil {
			if s != "" {
				refs = append(refs, pathRef{Path: s, FieldName: fieldName})
			}
			continue
		}
		// Try as array of strings.
		var arr []string
		if err := cbor.Unmarshal(raw, &arr); err == nil {
			for _, p := range arr {
				if p != "" {
					refs = append(refs, pathRef{Path: p, FieldName: fieldName})
				}
			}
		}
	}
	return refs
}

// knownPathFields maps entity types to their fields that contain
// system/tree/path values. These are derived from the type definitions
// in the spec. For types not in this map, no path link indexing is done.
var knownPathFields = map[string]map[string]bool{
	"system/protocol/execute":            {"uri": true},
	"system/delivery-spec":               {"uri": true},
	"system/handler":                     {"interface": true, "expression_path": true},
	"system/handler/manifest":            {"pattern": true},
	"system/handler/interface":           {"pattern": true},
	"system/handler/register-result":     {"pattern": true},
	"system/subscription":                {"pattern": true, "deliver_uri": true},
	"system/continuation":                {"target": true},
	"system/continuation/join":           {"target": true},
	"system/continuation/suspended":      {"target": true},
	"system/protocol/inbox/notification": {"uri": true},
}
