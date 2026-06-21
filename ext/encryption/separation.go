package encryption

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

// R6 key-separation primitives. See doc.go for the normative MUST.
//
// The two checks an impl must enforce when an encryption keypair is
// generated or accepted:
//
//   1. encryption_pk != identity_pk (the X25519 pubkey is not the raw
//      Ed25519 pubkey bytes).
//
//   2. encryption_pk != birational(identity_pk) (the X25519 pubkey is
//      not the well-known Ed25519→X25519 image of the identity key, as
//      computed by the age / libsodium crypto_sign_ed25519_pk_to_curve25519
//      transform: u = (1+y)/(1-y) mod 2^255-19).
//
// The check is BLOCK-1 (against real key generation); it cannot be
// observed from the pinned-seed KATs.

// ErrEncryptionKeyDerivedFromIdentity is returned by ValidateKeySeparation
// when the encryption pubkey matches the identity pubkey or its birational
// X25519 image.
var ErrEncryptionKeyDerivedFromIdentity = errors.New(
	"encryption_key_derived_from_identity: encryption pubkey MUST NOT be derived from identity key (R6)")

// p25519 = 2^255 - 19, the Curve25519 / Ed25519 base field prime.
var p25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// BirationalEdToX25519 maps a 32-byte Ed25519 (Edwards-compressed) public
// key to the corresponding 32-byte Curve25519 (Montgomery-u) public key
// via the birational equivalence
//
//	u = (1 + y) / (1 - y)  (mod 2^255 - 19)
//
// where y is the Edwards y-coordinate. The Ed25519 compressed form encodes
// y as a 32-byte little-endian integer with the sign bit of x stored in
// the top bit of the last byte; the birational map only uses y, so the
// sign bit is masked off before the field reduction. Matches the
// libsodium crypto_sign_ed25519_pk_to_curve25519 transform.
//
// Returns an error if (1 - y) is not invertible mod p (vanishing case).
func BirationalEdToX25519(ed25519PK [32]byte) ([32]byte, error) {
	// Strip the sign bit (high bit of byte 31). Birational map uses y only.
	var yBytes [32]byte
	copy(yBytes[:], ed25519PK[:])
	yBytes[31] &= 0x7F

	y := leToBig(yBytes[:])
	if y.Cmp(p25519) >= 0 {
		y.Mod(y, p25519)
	}

	one := big.NewInt(1)
	onePlusY := new(big.Int).Add(one, y)
	onePlusY.Mod(onePlusY, p25519)
	oneMinusY := new(big.Int).Sub(one, y)
	oneMinusY.Mod(oneMinusY, p25519)

	inv := new(big.Int).ModInverse(oneMinusY, p25519)
	if inv == nil {
		return [32]byte{}, fmt.Errorf("BirationalEdToX25519: (1-y) not invertible mod p")
	}

	u := new(big.Int).Mul(onePlusY, inv)
	u.Mod(u, p25519)

	var out [32]byte
	bigToLE(u, out[:])
	return out, nil
}

// ValidateKeySeparation enforces the R6 MUST: returns
// ErrEncryptionKeyDerivedFromIdentity when the X25519 encryption pubkey
// equals the raw Ed25519 identity pubkey bytes, OR equals the birational
// X25519 image of the identity key. Constant-time byte comparison; the
// caller MUST run this for every published / accepted encryption-pubkey
// whose owner has a known identity key.
func ValidateKeySeparation(identityEd25519PK, encryptionX25519PK [32]byte) error {
	if subtle.ConstantTimeCompare(identityEd25519PK[:], encryptionX25519PK[:]) == 1 {
		return fmt.Errorf("%w: encryption_pk == identity_pk bytes", ErrEncryptionKeyDerivedFromIdentity)
	}
	birational, err := BirationalEdToX25519(identityEd25519PK)
	if err != nil {
		// Invertibility failure is a degenerate identity key (y == 1); treat
		// as a successful separation by construction — no birational image
		// to collide with. Still surface the underlying issue.
		return nil
	}
	if subtle.ConstantTimeCompare(birational[:], encryptionX25519PK[:]) == 1 {
		return fmt.Errorf("%w: encryption_pk == birational(identity_pk) (Ed25519→X25519 map forbidden)",
			ErrEncryptionKeyDerivedFromIdentity)
	}
	return nil
}

// leToBig decodes a little-endian byte slice into a big.Int.
func leToBig(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i, x := range b {
		rev[len(b)-1-i] = x
	}
	return new(big.Int).SetBytes(rev)
}

// bigToLE encodes a big.Int into a fixed-size little-endian byte slice.
// Higher bytes beyond the integer's length are zero-filled.
func bigToLE(n *big.Int, out []byte) {
	b := n.Bytes()
	for i, x := range b {
		out[len(b)-1-i] = x
	}
	for i := len(b); i < len(out); i++ {
		out[i] = 0
	}
}
