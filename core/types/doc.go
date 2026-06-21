// Package types defines entity type structures for protocol, system, and
// crypto entity types.
//
// Each entity type is a Go struct with CBOR tags matching the wire format.
// Type constants (e.g., TypeHello = "system/protocol/connect/hello") name each
// type. Conversion helpers marshal/unmarshal between typed structs and
// cbor.RawMessage for the entity data field.
//
// Dependencies: hash, entity, ecf
package types
