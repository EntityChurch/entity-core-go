package crypto

import (
	"crypto/sha256"
	"fmt"

	ecerrors "go.entitychurch.org/entity-core-go/core/errors"

	"github.com/mr-tron/base58"
)

// v7.66 §2.2 errata + §4.3 reserved-range allocation. The key_type byte
// space partitions as:
//
//	0x01            Ed25519 (production)
//	0x02–0xEF       Reserved for future real algorithms
//	0xF0–0xFE       Experimental / test cryptosystems (NOT production)
//	0xFF            Reserved for future protocol use (do not allocate)
//
// The byte values below are the **binary peer_id wire-format prefix** surface
// (varint-encoded leading byte of Base58-decoded peer_id). This is distinct
// from the **system/peer.data.key_type entity-data string** surface (e.g.,
// "ed25519", "experimental-test"); see core/crypto/identity.go peerData
// doc-comment for the two-layer pin (v7.66 §2.2).
const (
	// KeyTypeEd25519 is the binary wire-format prefix for Ed25519 keys.
	// Entity-data string form: "ed25519".
	KeyTypeEd25519 byte = 0x01

	// KeyTypeEd448 is the binary wire-format prefix for Ed448 keys
	// (v7.67 §3.1 allocation). Entity-data string form: "ed448".
	// Canonical-form pair: (0x02, 0x01) — SHA-256-form, forced by the
	// 57-byte raw public_key exceeding the v7.65 §10 substrate floor.
	KeyTypeEd448 byte = 0x02

	// KeyTypeExperimentalTest is the v7.66 §4 stub key_type — test-only
	// "experimental" cryptosystem allocated to validate the non-Ed25519
	// branch of every per-key_type code path. NOT a real cryptosystem;
	// no sign/verify semantics. Public key size is 64 bytes (fixed),
	// canonical hash_type is 0x01 (SHA-256-form) — identity-form would
	// exceed substrate floors per v7.65 §10.
	//
	// Entity-data string form: "experimental-test".
	//
	// Historical note: this byte was allocated at v7.64 as a bare
	// "reserved test" decode-only stub (PIM-5 long-key vector). v7.66 §4
	// promotes it to a full canonical-form-bearing key_type for crypto-
	// agility validation.
	KeyTypeExperimentalTest byte = 0xFE

	// KeyTypeReservedTest is the v7.64 alias for KeyTypeExperimentalTest.
	// Retained for backwards-source-compat with v7.64-era test vectors;
	// new code SHOULD use KeyTypeExperimentalTest.
	KeyTypeReservedTest byte = KeyTypeExperimentalTest

	// KeyTypeStringEd25519 is the canonical entity-data string for Ed25519
	// (v7.66 §2.2 errata). Pin: lowercase ASCII "ed25519".
	KeyTypeStringEd25519 = "ed25519"

	// KeyTypeStringEd448 is the canonical entity-data string for Ed448
	// (v7.67 §3.3). Pin: lowercase ASCII "ed448".
	KeyTypeStringEd448 = "ed448"

	// KeyTypeStringExperimentalTest is the canonical entity-data string
	// for the v7.66 §4 stub key_type. Pin: lowercase ASCII
	// "experimental-test".
	KeyTypeStringExperimentalTest = "experimental-test"

	// ExperimentalTestPublicKeyLen is the fixed public-key size for
	// key_type=0xFE — 64 bytes, deliberately above Ed25519's 32 to force
	// SHA-256-form canonicalization (v7.66 §4.2).
	ExperimentalTestPublicKeyLen = 64

	// HashTypeIdentity (V7 §1.5, v7.64) — identity multihash: the digest IS
	// the raw public_key. Recommended default for short key types. Enables
	// DerivePeerFromPeerID without out-of-band data.
	HashTypeIdentity byte = 0x00

	// HashTypeSHA256 — fingerprint form: the digest is SHA-256(public_key).
	// Legacy form retained for backwards-compat with pre-v7.64 peers and
	// for peers wanting public-key non-disclosure via PeerID.
	HashTypeSHA256 byte = 0x01

	// Ed25519PublicKeyLen is the byte length of an Ed25519 public key.
	Ed25519PublicKeyLen = 32

	// Ed25519SignatureSize is the byte length of an Ed25519 signature.
	Ed25519SignatureSize = 64

	// SHA256DigestLen is the byte length of a SHA-256 digest.
	SHA256DigestLen = 32

	// PeerIDByteLen is the decoded length for the canonical Ed25519 PeerID:
	// key_type + hash_type + 32-byte digest. Holds under both identity and
	// SHA-256 forms (Ed25519 public_key is 32 bytes; SHA-256 digest is 32 bytes).
	PeerIDByteLen = 34

	// PeerIDStringLen is the Base58 string length for Ed25519 PeerIDs under
	// either hash_type form (≈46 chars).
	PeerIDStringLen = 46
)

// PeerID is a Base58-encoded peer identifier derived from a public key.
//
// V7.64 §1.5 / §7.4: PeerID := Base58(varint(key_type) || varint(hash_type) || digest)
//
//	hash_type=0x00 (identity): digest = public_key (recommended default)
//	hash_type=0x01 (SHA-256):  digest = SHA-256(public_key) (legacy / privacy / long-key)
type PeerID string

// PeerIDFromKeypair derives the canonical PeerID for a keypair, dispatching
// on KeyType via CanonicalHashType. Panics on a malformed keypair (the only
// failure modes are wrong-size public_key, which Generate / FromSeed /
// Ed448FromSeed / LoadIdentityFromFile never produce).
func PeerIDFromKeypair(k Keypair) PeerID {
	pid, err := PeerIDFromPublicKey(k.PublicKey, k.KeyType)
	if err != nil {
		panic(fmt.Sprintf("PeerIDFromKeypair: %v", err))
	}
	return pid
}

// CanonicalHashType returns the canonical hash_type byte for the given
// key_type per V7 §1.5 / v7.66 §4. Per-key_type canonical-form selection
// applies the size-cutoff principle from v7.65 §10: identity-form for
// short keys (raw public_key ≤ 32 bytes), SHA-256-form for long keys
// where identity-form would exceed substrate floors.
//
// Currently allocated:
//
//	0x01 Ed25519           → 0x00 (identity-multihash)
//	0x02 Ed448             → 0x01 (SHA-256-form, v7.67 §3.2)
//	0xFE experimental-test → 0x01 (SHA-256-form, forced by 64-byte pubkey)
//
// Returns ErrAuthenticationFailed for unallocated / unsupported key_types.
func CanonicalHashType(keyType byte) (byte, error) {
	switch keyType {
	case KeyTypeEd25519:
		return HashTypeIdentity, nil
	case KeyTypeEd448:
		return HashTypeSHA256, nil
	case KeyTypeExperimentalTest:
		return HashTypeSHA256, nil
	default:
		return 0, fmt.Errorf("%w: no canonical hash_type for key_type 0x%02x (unallocated or unsupported)",
			ecerrors.ErrAuthenticationFailed, keyType)
	}
}

// KeyTypeString returns the canonical entity-data string for the given
// binary key_type byte (v7.66 §2.2 two-layer pin). Returns "" for
// unallocated key_types.
func KeyTypeString(keyType byte) string {
	switch keyType {
	case KeyTypeEd25519:
		return KeyTypeStringEd25519
	case KeyTypeEd448:
		return KeyTypeStringEd448
	case KeyTypeExperimentalTest:
		return KeyTypeStringExperimentalTest
	default:
		return ""
	}
}

// KeyTypeByte returns the binary wire-format prefix byte for the given
// canonical entity-data string (v7.66 §2.2 two-layer pin reverse). Returns
// (0, false) for unrecognized strings.
func KeyTypeByte(s string) (byte, bool) {
	switch s {
	case KeyTypeStringEd25519:
		return KeyTypeEd25519, true
	case KeyTypeStringEd448:
		return KeyTypeEd448, true
	case KeyTypeStringExperimentalTest:
		return KeyTypeExperimentalTest, true
	default:
		return 0, false
	}
}

// PeerIDFromExperimentalTestPublicKey mints a canonical PeerID for the
// v7.66 §4 stub key_type 0xFE. Canonical pair is (0xFE, 0x01) — SHA-256-form,
// forced by the 64-byte fixed pubkey size (identity-form would exceed
// substrate floors per v7.65 §10). The pubkey MUST be exactly 64 bytes.
//
// This is the test-only mint path for the agility validation vectors
// (AGILITY-ENTITY-1, AGILITY-CANONICAL-1, AGILITY-PATTERN-1). Not for
// production use; 0xFE has no sign/verify semantics.
func PeerIDFromExperimentalTestPublicKey(pub []byte) (PeerID, error) {
	if len(pub) != ExperimentalTestPublicKeyLen {
		return "", fmt.Errorf("%w: key_type=0xFE public_key must be %d bytes, got %d",
			ecerrors.ErrAuthenticationFailed, ExperimentalTestPublicKeyLen, len(pub))
	}
	return derivePeerID(pub, KeyTypeExperimentalTest, HashTypeSHA256)
}

// PeerIDFromPublicKey derives the canonical PeerID for the given (publicKey,
// keyType). The hash_type is selected via CanonicalHashType: Ed25519 uses
// identity-form (0x00); Ed448 uses SHA-256-form (0x01); experimental-test
// uses SHA-256-form (0x01). Public-key length is validated per key_type
// (refused if it doesn't match the algorithm's declared length).
//
// V7.67 Phase 2 unification: replaces the prior Ed25519-only signature.
func PeerIDFromPublicKey(publicKey []byte, keyType byte) (PeerID, error) {
	if err := validatePublicKeyLen(publicKey, keyType); err != nil {
		return "", err
	}
	hashType, err := CanonicalHashType(keyType)
	if err != nil {
		return "", err
	}
	return derivePeerID(publicKey, keyType, hashType)
}

// PeerIDFromEd25519PublicKey is the Ed25519-only convenience form used by
// substrate sites that already have an ed25519-typed public key. Panics on
// length mismatch (unreachable for a well-formed 32-byte key). Prefer
// PeerIDFromPublicKey with an explicit key_type for new code.
func PeerIDFromEd25519PublicKey(publicKey []byte) PeerID {
	pid, err := derivePeerID(publicKey, KeyTypeEd25519, HashTypeIdentity)
	if err != nil {
		panic(fmt.Sprintf("PeerIDFromEd25519PublicKey: %v", err))
	}
	return pid
}

// PeerIDFromPublicKeyWithHashType derives an Ed25519 PeerID with an
// explicit hash_type. v7.65 §4 / v7.66 §3 mandate canonical hash_type =
// HashTypeIdentity (0x00) for Ed25519 at the mint boundary; construction
// under any other hash_type is REFUSED. Retained for source-compat with
// pre-unification call sites.
func PeerIDFromPublicKeyWithHashType(publicKey []byte, hashType byte) (PeerID, error) {
	if hashType != HashTypeIdentity {
		return "", fmt.Errorf("%w: v7.65 §4 / v7.66 §3 — Ed25519 canonical hash_type is 0x00 (identity-multihash); refusing mint under hash_type 0x%02x. SHA-256-form wire inputs may be constructed inline as opaque test vectors per v7.66 §3.4 — no mint API path is provided",
			ecerrors.ErrAuthenticationFailed, hashType)
	}
	return derivePeerID(publicKey, KeyTypeEd25519, hashType)
}

func derivePeerID(pub []byte, keyType, hashType byte) (PeerID, error) {
	// V7.67 §5.4 normative: integer value 255 is reserved on both axes
	// (key_type and content_hash_format) and SHALL NOT be allocated as an
	// algorithm code. Refuse mint with the reserved sentinel up front.
	if keyType == 0xFF {
		return "", fmt.Errorf("%w: key_type integer value 255 is reserved (v7.67 §5.4) and SHALL NOT be allocated",
			ecerrors.ErrAuthenticationFailed)
	}
	if hashType == 0xFF {
		return "", fmt.Errorf("%w: hash_type integer value 255 is reserved (v7.67 §5.4) and SHALL NOT be allocated",
			ecerrors.ErrAuthenticationFailed)
	}
	var digest []byte
	switch hashType {
	case HashTypeIdentity:
		if err := validatePublicKeyLen(pub, keyType); err != nil {
			return "", err
		}
		digest = pub
	case HashTypeSHA256:
		sum := sha256.Sum256(pub)
		digest = sum[:]
	default:
		return "", fmt.Errorf("%w: unsupported hash_type 0x%02x", ecerrors.ErrAuthenticationFailed, hashType)
	}
	// V7 §1.5 / v7.66 §2.2 normative wire format:
	//   PeerID := Base58(varint(key_type) || varint(hash_type) || H(public_key))
	// LEB128 varint: codes 0x00-0x7F encode as a single byte (Ed25519's
	// 0x01 unchanged); codes 0x80+ require two bytes (0xFE experimental
	// becomes [0xFE, 0x01]). Required for cross-impl convergence with
	// Rust's implementation (v7.66 cohort).
	buf := make([]byte, 0, len(digest)+4)
	buf = appendVarintU8(buf, keyType)
	buf = appendVarintU8(buf, hashType)
	buf = append(buf, digest...)
	return PeerID(base58.Encode(buf)), nil
}

// appendVarintU8 appends a u8 value to buf as LEB128 varint. Values
// 0x00-0x7F use a single byte; 0x80-0xFF use two bytes ([low7|0x80, 1]).
func appendVarintU8(buf []byte, v byte) []byte {
	if v < 0x80 {
		return append(buf, v)
	}
	return append(buf, v|0x80, 0x01)
}

// readVarintU8 reads a u8 value from b as LEB128 varint. Returns the
// decoded value, the number of bytes consumed, and an error if the
// encoding is malformed or overflows u8 (only u8-range values are
// permitted at the key_type / hash_type surfaces per V7 §1.5).
func readVarintU8(b []byte) (byte, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("%w: empty varint", ecerrors.ErrAuthenticationFailed)
	}
	if b[0] < 0x80 {
		return b[0], 1, nil
	}
	if len(b) < 2 {
		return 0, 0, fmt.Errorf("%w: truncated varint (continuation bit set but no following byte)",
			ecerrors.ErrAuthenticationFailed)
	}
	// Two-byte form: lower 7 bits from b[0], high bit from b[1].
	// b[1] MUST be < 0x80 (no further continuation) AND ≤ 0x01 (so total
	// value fits in u8).
	if b[1] >= 0x80 {
		return 0, 0, fmt.Errorf("%w: varint exceeds u8 (continuation past second byte)",
			ecerrors.ErrAuthenticationFailed)
	}
	if b[1] > 0x01 {
		return 0, 0, fmt.Errorf("%w: varint exceeds u8 (second byte 0x%02x > 0x01)",
			ecerrors.ErrAuthenticationFailed, b[1])
	}
	v := (b[0] & 0x7F) | (b[1] << 7)
	if v == 0xFF {
		// V7.67 §5: the integer value 255 is reserved on both axes and
		// SHALL NOT be allocated as an algorithm code (key_type or
		// content_hash_format). Decode rejects.
		return 0, 0, fmt.Errorf("%w: varint value 255 is reserved (v7.67 §5)",
			ecerrors.ErrAuthenticationFailed)
	}
	return v, 2, nil
}

func validatePublicKeyLen(pub []byte, keyType byte) error {
	switch keyType {
	case KeyTypeEd25519:
		if len(pub) != Ed25519PublicKeyLen {
			return fmt.Errorf("%w: ed25519 public_key must be %d bytes, got %d",
				ecerrors.ErrAuthenticationFailed, Ed25519PublicKeyLen, len(pub))
		}
	case KeyTypeEd448:
		if len(pub) != Ed448PublicKeyLen {
			return fmt.Errorf("%w: ed448 public_key must be %d bytes, got %d",
				ecerrors.ErrAuthenticationFailed, Ed448PublicKeyLen, len(pub))
		}
	case KeyTypeExperimentalTest:
		// v7.66 §4.2: 64-byte fixed synthetic pubkey, sized to force
		// SHA-256-form canonicalization. Identity-form decode of 0xFE
		// historically (v7.64) carried no length check for the long-key
		// decoder vector; v7.66 §4 elevates 0xFE to a canonical-form-bearing
		// type and pins the size at allocation.
		if len(pub) != ExperimentalTestPublicKeyLen {
			return fmt.Errorf("%w: key_type=0xFE (experimental-test) public_key must be %d bytes, got %d",
				ecerrors.ErrAuthenticationFailed, ExperimentalTestPublicKeyLen, len(pub))
		}
	default:
		return fmt.Errorf("%w: unsupported key_type 0x%02x for identity-form public_key validation",
			ecerrors.ErrAuthenticationFailed, keyType)
	}
	return nil
}

// PeerID returns the PeerID for this keypair (v7.64 default: identity form).
func (k Keypair) PeerID() PeerID {
	return PeerIDFromKeypair(k)
}

// DecodedPeerID is the structural decoding of a Base58 PeerID without
// asserting on key_type / hash_type allocation policy.
type DecodedPeerID struct {
	KeyType  byte
	HashType byte
	Digest   []byte
}

// Decode parses the PeerID's Base58 framing into its components.
//
// V7 §1.5 / v7.66 §2.2 normative: key_type and hash_type are LEB128
// varint-encoded. Codes 0x00-0x7F are single-byte (Ed25519's 0x01
// reads identically to the pre-v7.66 raw-byte layout); codes 0x80+
// consume two bytes (0xFE → [0xFE, 0x01]).
func (p PeerID) Decode() (DecodedPeerID, error) {
	raw, err := base58.Decode(string(p))
	if err != nil {
		return DecodedPeerID{}, fmt.Errorf("%w: invalid base58: %v", ecerrors.ErrAuthenticationFailed, err)
	}
	keyType, ktN, err := readVarintU8(raw)
	if err != nil {
		return DecodedPeerID{}, fmt.Errorf("read key_type varint: %w", err)
	}
	hashType, htN, err := readVarintU8(raw[ktN:])
	if err != nil {
		return DecodedPeerID{}, fmt.Errorf("read hash_type varint: %w", err)
	}
	digestStart := ktN + htN
	if len(raw) <= digestStart {
		return DecodedPeerID{}, fmt.Errorf("%w: peer_id has no digest after varint prefix (%d bytes total)",
			ecerrors.ErrAuthenticationFailed, len(raw))
	}
	return DecodedPeerID{
		KeyType:  keyType,
		HashType: hashType,
		Digest:   raw[digestStart:],
	}, nil
}

// DerivePeerFromPeerID extracts (public_key, key_type) from an
// identity-multihash PeerID. Returns ok=false for SHA-256-form PeerIDs
// (the public_key is not recoverable from the PeerID alone and must be
// obtained out-of-band via handshake, system/peer entity exchange, or
// registry).
//
// V7.64 §7.4 normative helper enabling paste-handle-pre-policy for
// identity-form peers (companion of PROPOSAL-V7-POLICY-DUAL-FORM-PRE-CONFIGURATION
// which handles the SHA-256-form residual case).
//
// V7.67 Phase 2: return type generalized from ed25519.PublicKey to []byte —
// identity-form Ed448 peer_ids (when present as wire input per the §5
// carve-out) also decode through this path. Canonical-form Ed448 peer_ids
// are SHA-256-form and return ok=false here per spec.
func DerivePeerFromPeerID(p PeerID) (pub []byte, keyType byte, ok bool) {
	dec, err := p.Decode()
	if err != nil {
		return nil, 0, false
	}
	if dec.HashType != HashTypeIdentity {
		return nil, dec.KeyType, false
	}
	if err := validatePublicKeyLen(dec.Digest, dec.KeyType); err != nil {
		return nil, dec.KeyType, false
	}
	out := make([]byte, len(dec.Digest))
	copy(out, dec.Digest)
	return out, dec.KeyType, true
}

// Validate checks that the PeerID is well-formed under v7.64/v7.65/v7.66
// (accepts both hash_type=0x00 identity and hash_type=0x01 SHA-256;
// recognizes allocated key_types 0x01 Ed25519 and 0xFE experimental-test).
func (p PeerID) Validate() error {
	dec, err := p.Decode()
	if err != nil {
		return err
	}
	switch dec.KeyType {
	case KeyTypeEd25519, KeyTypeEd448, KeyTypeExperimentalTest:
		// allowed; KeyTypeExperimentalTest (0xFE) is v7.66 §4 test stub
	default:
		return fmt.Errorf("%w: unsupported key type 0x%02x", ecerrors.ErrAuthenticationFailed, dec.KeyType)
	}
	switch dec.HashType {
	case HashTypeIdentity:
		// identity-form digest IS the public_key; length per key_type.
		switch dec.KeyType {
		case KeyTypeEd25519:
			if len(dec.Digest) != Ed25519PublicKeyLen {
				return fmt.Errorf("%w: ed25519 identity-form digest must be %d bytes, got %d",
					ecerrors.ErrAuthenticationFailed, Ed25519PublicKeyLen, len(dec.Digest))
			}
		case KeyTypeEd448:
			// v7.67 §3.2: Ed448 canonical pair is (0x02, 0x01) SHA-256-form.
			// Identity-form Ed448 peer_ids are NOT canonical (the 57-byte
			// raw segment exceeds substrate floors) but accept on wire-decode
			// per the v7.66 §5 carve-out symmetric to Ed25519.
			if len(dec.Digest) != Ed448PublicKeyLen {
				return fmt.Errorf("%w: ed448 identity-form digest must be %d bytes, got %d",
					ecerrors.ErrAuthenticationFailed, Ed448PublicKeyLen, len(dec.Digest))
			}
		case KeyTypeExperimentalTest:
			if len(dec.Digest) != ExperimentalTestPublicKeyLen {
				return fmt.Errorf("%w: key_type=0xFE identity-form digest must be %d bytes, got %d",
					ecerrors.ErrAuthenticationFailed, ExperimentalTestPublicKeyLen, len(dec.Digest))
			}
		}
	case HashTypeSHA256:
		if len(dec.Digest) != SHA256DigestLen {
			return fmt.Errorf("%w: sha256 digest must be %d bytes, got %d",
				ecerrors.ErrAuthenticationFailed, SHA256DigestLen, len(dec.Digest))
		}
	default:
		return fmt.Errorf("%w: unsupported hash type 0x%02x", ecerrors.ErrAuthenticationFailed, dec.HashType)
	}
	return nil
}

// VerifyPublicKey checks that the PeerID corresponds to the given public_key
// under either hash_type form. The caller is responsible for asserting the
// key_type matches the signer's PeerData.KeyType separately — this method
// only compares the digest portion.
//
// V7.67 Phase 2: pub generalized to []byte; works for Ed25519 (32 B) and
// Ed448 (57 B) identity-form peer_ids.
func (p PeerID) VerifyPublicKey(pub []byte) bool {
	dec, err := p.Decode()
	if err != nil {
		return false
	}
	switch dec.HashType {
	case HashTypeIdentity:
		if len(dec.Digest) != len(pub) {
			return false
		}
		for i := range dec.Digest {
			if dec.Digest[i] != pub[i] {
				return false
			}
		}
		return true
	case HashTypeSHA256:
		sum := sha256.Sum256(pub)
		if len(dec.Digest) != len(sum) {
			return false
		}
		for i := range dec.Digest {
			if dec.Digest[i] != sum[i] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// String returns the PeerID as a string.
func (p PeerID) String() string {
	return string(p)
}

// Base58EncodeForTests is an internal helper exposed for the v7.67
// VARINT-RESERVED-FF-1 conformance vector that needs to construct a
// hand-built peer_id bytestring with key_type=0xFF for the decode reject
// surface. NOT intended for normal call-site use.
func Base58EncodeForTests(b []byte) string {
	return base58.Encode(b)
}
