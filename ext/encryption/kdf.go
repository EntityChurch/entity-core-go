package encryption

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"go.entitychurch.org/entity-core-go/core/types"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// §6.2 Argon2id baseline parameters (pinned by spec; configurable per
// impl via stored kdf_params for portability).
const (
	Argon2idBaselineMemoryCost  uint32 = 65536 // 64 MiB (KiB units per RFC 9106 §3.1)
	Argon2idBaselineTimeCost    uint32 = 3
	Argon2idBaselineParallelism uint8  = 1
	Argon2idBaselineOutputLen   uint32 = 32

	// KDFSaltMinBytes is the §6.1 minimum random salt length.
	KDFSaltMinBytes = 16
)

// DefaultKDFParams returns the §6.2 baseline parameter struct (pinned for
// v1, matches golang.org/x/crypto/argon2 + Rust + Python library defaults).
func DefaultKDFParams() types.KDFParams {
	return types.KDFParams{
		Argon2Version: types.Argon2idVersion,
		MemoryCost:    uint(Argon2idBaselineMemoryCost),
		TimeCost:      uint(Argon2idBaselineTimeCost),
		Parallelism:   uint(Argon2idBaselineParallelism),
		OutputLen:     uint(Argon2idBaselineOutputLen),
	}
}

// Argon2idKey derives a key from passphrase + salt per §6.2 / §9.2.
// Version pin: 0x13 / v19; golang.org/x/crypto/argon2 currently exposes
// only v1.3 so this is what we get. The argon2_version field in
// kdf_params is asserted to match 0x13 to fail-loudly if a backup is
// authored under a different version.
func Argon2idKey(passphrase []byte, salt []byte, params types.KDFParams) ([]byte, error) {
	if params.Argon2Version != types.Argon2idVersion {
		return nil, fmt.Errorf("%s: argon2_version 0x%02x != pinned 0x%02x",
			types.EncryptionErrUnsupportedSuite, params.Argon2Version, types.Argon2idVersion)
	}
	if len(salt) < KDFSaltMinBytes {
		return nil, fmt.Errorf("%s: kdf_salt %d bytes < %d minimum",
			types.EncryptionErrInvalidWrapper, len(salt), KDFSaltMinBytes)
	}
	if params.OutputLen == 0 {
		return nil, fmt.Errorf("%s: kdf_params.output_len must be > 0",
			types.EncryptionErrInvalidWrapper)
	}
	if params.Parallelism == 0 {
		return nil, fmt.Errorf("%s: kdf_params.parallelism must be > 0",
			types.EncryptionErrInvalidWrapper)
	}
	return argon2.IDKey(
		passphrase,
		salt,
		uint32(params.TimeCost),
		uint32(params.MemoryCost),
		uint8(params.Parallelism),
		uint32(params.OutputLen),
	), nil
}

// HKDFSHA256 derives `length` bytes per RFC 5869 (kdf_id 0x01, v1 floor).
// salt is the per-message salt (§6.2 self uses the AEAD nonce; §7.3 peer
// uses the AEAD nonce); info is the domain-separated ASCII prefix
// concatenated with any bound context bytes (no separator, no NUL per
// F-GO-9).
func HKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("HKDF length must be positive, got %d", length)
	}
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("HKDF-SHA-256 expand: %w", err)
	}
	return out, nil
}

// RandomSalt returns KDFSaltMinBytes cryptographically random bytes —
// the spec floor for a fresh kdf_salt. Callers wanting larger salts pass
// their own size.
func RandomSalt() ([]byte, error) {
	return RandomSaltN(KDFSaltMinBytes)
}

// RandomSaltN returns n cryptographically random bytes for a kdf_salt.
func RandomSaltN(n int) ([]byte, error) {
	if n < KDFSaltMinBytes {
		return nil, fmt.Errorf("kdf_salt size %d < %d minimum", n, KDFSaltMinBytes)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random salt: %w", err)
	}
	return b, nil
}
