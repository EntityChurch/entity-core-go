// Package encryption implements EXTENSION-ENCRYPTION v1.0 — per-entity
// stateless encryption (self / peer / group) on V7.
//
// Spec: ../entity-core-architecture/docs/architecture/v7.0-core-revision/
// core-protocol-domain/specs/extensions/network-peer-extensions/
// EXTENSION-ENCRYPTION.md (LANDED).
//
// Three modes:
//
//   - self  (§6, PRIMARY) — Argon2id passphrase → HKDF → XChaCha20-Poly1305
//     for at-rest storage. 8-key AAD (§5.2) binds mode, suite bytes,
//     nonce, kdf_salt, kdf_params, recipient_key=∅, enc_key_type=0.
//
//   - peer  (§7, PRIMARY) — X25519 ECDH + HKDF + XChaCha20-Poly1305 for
//     single-shot hybrid send. 7-key AAD binds mode, suite, nonce,
//     recipient_pubkey_hash (F-GO-1 uniform across tiers), ephemeral_key.
//     Sender-auth via system/signature at the V7 invariant pointer
//     system/signature/{hex(content_hash)} (§7.4 / F-GO-3).
//
//   - group (§8, best-effort) — random group_aead_key wrapped per-member
//     in peer-mode-shaped wraps (§5.2 "group-wrap" AAD label, F2-2 domain
//     separation), outer ciphertext AAD-bound with
//     commitment = SHA-256(group_aead_key) (F2-1 key-commitment closes the
//     invisible-salamanders class).
//
// Layout:
//
//	ext/encryption/registry.go    — algorithm-byte name maps + cipher-suite intersection
//	ext/encryption/aad.go         — §5.2 ECF AAD builders (4 shapes)
//	ext/encryption/aead/          — XChaCha20-Poly1305 thin adapter
//	ext/encryption/kdf/           — Argon2id + HKDF thin adapters
//	ext/encryption/self/          — mode=self encrypt/decrypt
//	ext/encryption/peer/          — mode=peer encrypt/decrypt + sender-auth
//	ext/encryption/group/         — mode=group encrypt/decrypt + commitment
//
// Conformance gate: §16 byte-pin lock (§16.5) — Go authors reference hex
// against the v2.4 post-fold AAD shapes; Rust + Python + Keystone match.
//
// Key separation (R6, MUST, §2/§9.4). The encryption keypair
// (X25519 / enc_key_type=0x01) MUST be generated independently of the
// identity signing keypair (Ed25519 / key_type=0x01). An impl MUST NOT
// use the identity key material as the encryption key, AND MUST NOT
// derive the encryption key from the identity key by any deterministic
// transform — including the birational Ed25519→X25519 map (the
// age / libsodium crypto_sign_ed25519_*_to_curve25519 pattern). Any
// such derivation re-couples the two keys, so compromise of the
// identity key compromises all encrypted content. Gated by
// ENC-KEY-SEPARATION-1 (§16) — a BLOCK-1 validation-round vector against
// real key generation; the pinned-seed KATs use independent seeds by
// construction and cannot observe this property. See
// ext/encryption/separation.go for ValidateKeySeparation +
// BirationalEdToX25519 helpers.
package encryption
