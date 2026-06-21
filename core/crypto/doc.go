// Package crypto provides Ed25519 key management, PeerID derivation, and
// sign/verify operations.
//
// PeerID is derived from the public key:
//
//	PeerID = Base58(0x01 || 0x01 || SHA256(pubkey))
//
// where 0x01 is the Ed25519 key type and 0x01 is the SHA256 hash type.
//
// Dependencies: hash
package crypto
