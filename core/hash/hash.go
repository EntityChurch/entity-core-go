package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"

	"github.com/fxamacker/cbor/v2"
)

const (
	// AlgorithmSHA256 is the ECFv1-SHA-256 hash algorithm byte (`content_hash_format=0x00`).
	AlgorithmSHA256 byte = 0x00

	// AlgorithmSHA384 is the ECFv1-SHA-384 hash algorithm byte (`content_hash_format=0x01`,
	// v7.67 Phase 1 allocation).
	AlgorithmSHA384 byte = 0x01

	// MaxDigestSize is the in-memory digest array size. Sized to fit any
	// reserved content_hash_format allocation through v7.67 §4 (the largest
	// reserved is SHA-512 at 64 bytes). The Algorithm byte implies the
	// effective digest length; trailing bytes are zero.
	MaxDigestSize = 64

	// SHA256DigestSize is the byte length of a SHA-256 digest.
	SHA256DigestSize = 32

	// SHA384DigestSize is the byte length of a SHA-384 digest.
	SHA384DigestSize = 48

	// DigestSize is the SHA-256 digest size. Retained for backwards-source-
	// compatibility with v7.66-and-earlier call sites; new code should use
	// SHA256DigestSize or DigestLen(alg).
	DigestSize = SHA256DigestSize

	// HashSize is the wire size of a SHA-256 content hash (algorithm + digest).
	// Retained for backwards-source-compat; new code should use HashWireSize(alg).
	HashSize = 1 + SHA256DigestSize
)

// DigestLen returns the digest byte length for the given content_hash_format
// algorithm code. Returns 0 for unsupported codes.
func DigestLen(alg byte) int {
	switch alg {
	case AlgorithmSHA256:
		return SHA256DigestSize
	case AlgorithmSHA384:
		return SHA384DigestSize
	default:
		return 0
	}
}

// HashWireSize returns the on-wire size (algorithm + digest) for the given
// content_hash_format code.
func HashWireSize(alg byte) int {
	d := DigestLen(alg)
	if d == 0 {
		return 0
	}
	return 1 + d
}

// Hash is a content hash: algorithm byte + fixed-capacity digest array.
// The effective digest length is implied by Algorithm; trailing bytes are
// always zero. Hash is comparable and can be used directly as a Go map key.
type Hash struct {
	Algorithm byte
	Digest    [MaxDigestSize]byte
}

// EffectiveDigest returns the digest bytes used by the hash's algorithm
// (32 bytes for SHA-256, 48 bytes for SHA-384). The returned slice aliases
// the underlying array; do not mutate.
func (h Hash) EffectiveDigest() []byte {
	n := DigestLen(h.Algorithm)
	return h.Digest[:n]
}

// NewSHA256 constructs a SHA-256 Hash from a 32-byte digest array. Helper
// for test fixtures and call sites that already hold a [32]byte digest.
func NewSHA256(d [SHA256DigestSize]byte) Hash {
	h := Hash{Algorithm: AlgorithmSHA256}
	copy(h.Digest[:SHA256DigestSize], d[:])
	return h
}

// NewSHA384 constructs a SHA-384 Hash from a 48-byte digest array.
func NewSHA384(d [SHA384DigestSize]byte) Hash {
	h := Hash{Algorithm: AlgorithmSHA384}
	copy(h.Digest[:SHA384DigestSize], d[:])
	return h
}

// ExtendDigest widens a 32-byte digest into the internal [64]byte digest
// array used by Hash. Helper for call sites that already hold a [32]byte
// SHA-256 digest and want to assign it into a Hash struct literal.
func ExtendDigest(d [SHA256DigestSize]byte) [MaxDigestSize]byte {
	var out [MaxDigestSize]byte
	copy(out[:], d[:])
	return out
}

// Compute computes the SHA-256 content hash of an entity with the given type
// and data. ECF-encodes {data, type} and returns the SHA-256 hash. This is
// the default-format hash; use ComputeFormat for non-default formats.
func Compute(entityType string, data cbor.RawMessage) (Hash, error) {
	return ComputeFormat(AlgorithmSHA256, entityType, data)
}

// ComputeFormat computes the content hash under the given format code.
// V7.67 §4 supported formats: 0x00 SHA-256, 0x01 SHA-384.
func ComputeFormat(alg byte, entityType string, data cbor.RawMessage) (Hash, error) {
	encoded, err := ecf.EncodeHashable(entityType, data)
	if err != nil {
		return Hash{}, fmt.Errorf("hash compute: %w", err)
	}
	out := Hash{Algorithm: alg}
	switch alg {
	case AlgorithmSHA256:
		d := sha256.Sum256(encoded)
		copy(out.Digest[:], d[:])
	case AlgorithmSHA384:
		d := sha512.Sum384(encoded)
		copy(out.Digest[:], d[:])
	default:
		return Hash{}, fmt.Errorf("%w: format-code 0x%02x not supported", ErrUnsupportedContentHashFormat, alg)
	}
	return out, nil
}

// Validate recomputes the hash under the claimed algorithm and compares it
// with the claimed hash.
func Validate(entityType string, data cbor.RawMessage, claimed Hash) error {
	computed, err := ComputeFormat(claimed.Algorithm, entityType, data)
	if err != nil {
		return err
	}
	if computed != claimed {
		return fmt.Errorf("%w: computed %s, claimed %s", ErrHashMismatch, computed, claimed)
	}
	return nil
}

// Bytes returns the wire representation: [algorithm || digest]. Size is
// algorithm-dependent (33 for SHA-256, 49 for SHA-384).
func (h Hash) Bytes() []byte {
	n := DigestLen(h.Algorithm)
	if n == 0 {
		// Unallocated algorithm: emit only the algorithm byte. Callers
		// validating wire bytes should reject this; we don't panic so
		// MarshalCBOR on an uninitialized Hash{} still emits something.
		return []byte{h.Algorithm}
	}
	b := make([]byte, 1+n)
	b[0] = h.Algorithm
	copy(b[1:], h.Digest[:n])
	return b
}

// FromBytes parses a wire-format hash byte string into a Hash. The leading
// byte is the format-code; the remaining bytes are the digest, whose length
// must match DigestLen(format).
func FromBytes(b []byte) (Hash, error) {
	if len(b) < 1 {
		return Hash{}, fmt.Errorf("%w: empty hash bytes", ErrInvalidHash)
	}
	alg := b[0]
	n := DigestLen(alg)
	if n == 0 {
		return Hash{}, fmt.Errorf("%w: algorithm byte 0x%02x", ErrUnknownAlgorithm, alg)
	}
	if len(b) != 1+n {
		return Hash{}, fmt.Errorf("%w: format 0x%02x expects %d bytes, got %d",
			ErrInvalidHash, alg, 1+n, len(b))
	}
	var h Hash
	h.Algorithm = alg
	copy(h.Digest[:n], b[1:])
	return h, nil
}

// IsZero returns true if the hash is the zero value.
func (h Hash) IsZero() bool {
	return h == Hash{}
}

// DispatchContentHashFormat is the v7.67 §2.3 normative format-code
// interpretation primitive: an implementation receiving a `content_hash`
// whose format-code it does not support returns
// `unsupported_content_hash_format` rather than silently failing or treating
// the hash as a content miss.
//
// V7.67 supported format-codes: 0x00 ECFv1-SHA-256, 0x01 ECFv1-SHA-384.
// 0x03 ECFv1-BLAKE3-256 is allocated but lands in Phase 3a.
func DispatchContentHashFormat(h Hash) error {
	switch h.Algorithm {
	case AlgorithmSHA256, AlgorithmSHA384:
		return nil
	default:
		return fmt.Errorf("%w: format-code 0x%02x is not supported by this peer",
			ErrUnsupportedContentHashFormat, h.Algorithm)
	}
}

// DispatchContentHashBytes is the raw-bytes form of DispatchContentHashFormat —
// inspects the leading byte of a content_hash bytestring without parsing the
// full Hash. Used by lookup paths that operate on raw bytes.
//
// Per v7.67 §2.3: the leading varint of any `content_hash` IS the
// `content_hash_format` code. Single-byte allocations (0x00–0x7F) read as
// their integer value; multi-byte allocations (0x80+) are normal LEB128 per
// V7 §7.3 and decode here. The integer value 255 is reserved on this axis
// (v7.67 §5).
func DispatchContentHashBytes(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("%w: empty content_hash bytestring", ErrInvalidHash)
	}
	alg, _, err := decodeVarintFormatCode(b)
	if err != nil {
		return err
	}
	switch alg {
	case AlgorithmSHA256, AlgorithmSHA384:
		return nil
	default:
		return fmt.Errorf("%w: format-code 0x%02x is not supported by this peer",
			ErrUnsupportedContentHashFormat, alg)
	}
}

// decodeVarintFormatCode decodes a leading LEB128 varint from b and returns
// the decoded integer value, the number of bytes consumed, and any error.
//
// V7.67 §5.4 normative: the integer value 255 is reserved and MUST NOT be
// allocated as a format-code. Multi-byte encodings (`≥ 0x80` leading byte)
// are normal LEB128 and MUST decode correctly; today no production
// allocation exceeds 0x7F.
func decodeVarintFormatCode(b []byte) (byte, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("%w: empty varint", ErrInvalidHash)
	}
	if b[0] < 0x80 {
		// Single-byte form.
		if b[0] == 0xFF {
			return 0, 0, fmt.Errorf("%w: format-code value 255 is reserved (v7.67 §5)",
				ErrUnsupportedContentHashFormat)
		}
		return b[0], 1, nil
	}
	// Multi-byte LEB128. Currently we only support u8-range values
	// (0x00–0xFE; 0xFF reserved). Two-byte form: [low7|0x80, high].
	if len(b) < 2 {
		return 0, 0, fmt.Errorf("%w: truncated varint", ErrInvalidHash)
	}
	if b[1] >= 0x80 {
		return 0, 0, fmt.Errorf("%w: format-code varint exceeds u8 range",
			ErrUnsupportedContentHashFormat)
	}
	if b[1] > 0x01 {
		return 0, 0, fmt.Errorf("%w: format-code varint exceeds u8 range",
			ErrUnsupportedContentHashFormat)
	}
	v := (b[0] & 0x7F) | (b[1] << 7)
	if v == 0xFF {
		return 0, 0, fmt.Errorf("%w: format-code value 255 is reserved (v7.67 §5)",
			ErrUnsupportedContentHashFormat)
	}
	// Even multi-byte u8-range values reach this point: 0x80 → 128, etc.
	// They're well-formed varints, just unallocated. Return so caller can
	// dispatch (allocated check); we don't classify "unallocated" as
	// "malformed."
	return v, 2, nil
}

// String returns the human-readable form: "ecf-sha256:<hex>" or
// "ecfv1-sha384:<hex>".
func (h Hash) String() string {
	n := DigestLen(h.Algorithm)
	switch h.Algorithm {
	case AlgorithmSHA256:
		return "ecf-sha256:" + hex.EncodeToString(h.Digest[:n])
	case AlgorithmSHA384:
		return "ecfv1-sha384:" + hex.EncodeToString(h.Digest[:n])
	default:
		return fmt.Sprintf("ecf-unknown(0x%02x)", h.Algorithm)
	}
}

// MarshalCBOR encodes the hash as a CBOR byte string ([algorithm || digest]).
// This is the wire format — NOT a CBOR map.
func (h Hash) MarshalCBOR() ([]byte, error) {
	return ecf.Encode(h.Bytes())
}

// UnmarshalCBOR decodes a CBOR byte string back into a Hash.
//
// V7 §1.3 (RULING-Q-OMITZERO-HASH-FIELD): implementations MUST NOT
// reject entities that include optional fields with null or zero values. CBOR
// null (0xf6), CBOR undefined (0xf7), and an empty byte string all signal
// "no hash"; decode them as the zero Hash and let handler logic check
// IsZero() to enforce required-field semantics. Anything else of wrong length
// is genuinely malformed and still rejects.
func (h *Hash) UnmarshalCBOR(data []byte) error {
	if len(data) == 1 && (data[0] == 0xf6 || data[0] == 0xf7) {
		*h = Hash{}
		return nil
	}
	var raw []byte
	if err := ecf.Decode(data, &raw); err != nil {
		return fmt.Errorf("hash unmarshal: %w", err)
	}
	if len(raw) == 0 {
		*h = Hash{}
		return nil
	}
	parsed, err := FromBytes(raw)
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}
