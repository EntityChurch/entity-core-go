// Package hash defines the content hash type used for entity addressing.
//
// A Hash is a struct with an Algorithm byte (the `content_hash_format` code
// per V7 §1.2 + v7.67 §4) and a fixed-capacity Digest array. The effective
// digest length is implied by the Algorithm byte; trailing bytes are zero.
// Since the struct contains only comparable fields, Hash is directly usable
// as a Go map key without conversion.
//
// Currently allocated formats (v7.67 Phase 1):
//
//	0x00 ECFv1-SHA-256 — 32-byte digest, 33-byte wire (production since v7.0)
//	0x01 ECFv1-SHA-384 — 48-byte digest, 49-byte wire (v7.67 Phase 1)
//
// Reserved-for-validation (v7.67 Phase 3a):
//
//	0x03 ECFv1-BLAKE3-256 — 32-byte digest
//
// On the wire (CBOR), a hash is a single byte string (algorithm || digest),
// NOT a CBOR map. This is critical for interop with Python and Rust peers.
//
//	wire:      bytes(format-code || H(ECF({type, data})))
//	in-memory: Hash{ Algorithm: 0x00, Digest: [64]byte{…} }
//
// Dependencies: ecf
package hash
