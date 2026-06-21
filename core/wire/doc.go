// Package wire implements the network framing and envelope codec.
//
// Frames use a 4-byte big-endian length prefix followed by the CBOR payload:
//
//	[4 bytes: length] [length bytes: CBOR envelope]
//
// The envelope codec handles serialization and deserialization of Envelope
// structures (root entity + included entities) for wire transmission.
//
// Dependencies: entity, hash
package wire
