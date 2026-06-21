package crypto

import (
	"github.com/cloudflare/circl/sign/ed448"
)

// V7.67 Phase 1 / §3 — Ed448 allocation.
//
// `key_type=0x02` Ed448 is the second classical signature algorithm allocated
// for the V7 protocol. Public-key length 57 bytes; signature length 114 bytes.
// Canonical-form pair is (0x02, 0x01) — SHA-256-form, forced by the 57-byte
// raw segment exceeding the v7.65 §10 informative substrate floor.
//
// Library: github.com/cloudflare/circl/sign/ed448 (Cloudflare-maintained,
// audited as a unit per v7.67 §8.2 Go-impl pin).
//
// EdDSA Ed448 follows RFC 8032 with Ed448ph available via separate API.
// V7 Ed448 signatures use the pure variant (Sign / Verify, NOT SignPh).
//
// V7.67 Phase 2 unification: Ed448 keypairs share the algorithm-agnostic
// crypto.Keypair value type with Ed25519. Sign/Verify/PeerID dispatch on
// KeyType internally; this file holds the Ed448-specific constants and
// the Ed448FromSeed helper that produces a unified Keypair.
const (
	// Ed448PublicKeyLen is the byte length of an Ed448 public key.
	Ed448PublicKeyLen = ed448.PublicKeySize

	// Ed448PrivateKeyLen is the byte length of an Ed448 private key.
	Ed448PrivateKeyLen = ed448.PrivateKeySize

	// Ed448SignatureLen is the byte length of an Ed448 signature.
	Ed448SignatureLen = ed448.SignatureSize

	// Ed448SeedLen is the byte length of an Ed448 secret seed (RFC 8032).
	Ed448SeedLen = ed448.SeedSize
)

// Ed448FromSeed creates a deterministic Ed448 keypair from a 57-byte seed
// (RFC 8032). Returns a unified crypto.Keypair with KeyType=KeyTypeEd448.
func Ed448FromSeed(seed [Ed448SeedLen]byte) Keypair {
	priv := ed448.NewKeyFromSeed(seed[:])
	pub := make(ed448.PublicKey, Ed448PublicKeyLen)
	copy(pub, priv[Ed448SeedLen:])
	return Keypair{
		KeyType:    KeyTypeEd448,
		PrivateKey: []byte(priv),
		PublicKey:  []byte(pub),
	}
}
