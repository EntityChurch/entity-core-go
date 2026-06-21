// Package ecf implements Entity Canonical Form encoding — deterministic CBOR
// per RFC 8949 §4.2.
//
// ECF is the canonical serialization used for content hashing. It uses
// fxamacker/cbor/v2 with CoreDetEncOptions() to produce deterministic output:
//   - Map keys sorted in bytewise lexicographic order
//   - Minimal-length integer encoding
//   - No indefinite-length items
//
// Dependencies: fxamacker/cbor/v2 (external)
package ecf
