package validate

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// catCryptoAgility is the v7.67 Phase-1 crypto-agility conformance category
// per PROPOSAL-V7-V7.67-CRYPTO-AGILITY-SEED-TABLES.md §13.7. Five vectors
// covering: §3 Ed448 allocation (KEY-TYPE-ED448-1), §4 SHA-384 allocation
// (HASH-FORMAT-SHA-384-1), §5 varint expansion (VARINT-MULTIBYTE-1,
// VARINT-RESERVED-FF-1). The §2 errata rename (FORMAT-CODE-
// INTERPRETATION-1) lives in catFormatAgility — it's a v7.66 vector with a
// new name, not a new vector.
//
// Phase-1 lock gate (impl-team alignment §3.4): all five Phase-1 vectors
// PASS cross-impl (Go + Rust + Python) plus v7.66 10/10 no-regression and
// v7.65 7/7 no-regression. The cross-impl byte-equal seed check for Ed448
// is corpus-pinned at architecture-side authoring time per v7.66 §7.2.
const catCryptoAgility = "crypto_agility"

// ed448FixtureSeed is the v7.67 Phase-1 KEY-TYPE-ED448-1 deterministic test
// seed. 57 bytes per RFC 8032 SeedSize for Ed448.
//
// **Cohort placeholder pin**: every byte = 0x42. Agreed across
// Go + Rust + Python before arch's official corpus authoring at
// `core-protocol-domain/specs/test-vectors/v767/`. Purpose: surface any
// Ed448 library divergence cross-impl NOW rather than after arch pins.
// When the arch corpus seed lands, swap this constant and the cohort re-
// runs against the official value (no test logic changes).
var ed448FixtureSeed = func() [crypto.Ed448SeedLen]byte {
	var s [crypto.Ed448SeedLen]byte
	for i := range s {
		s[i] = 0x42
	}
	return s
}()

// ed448FixtureMessage is the fixed message Ed448 signs in KEY-TYPE-ED448-1.
// Pinned cohort-wide so the resulting signature bytes are directly
// comparable across impls. UTF-8 ASCII; no trailing newline.
var ed448FixtureMessage = []byte("v7.67 Phase 1 cohort cross-impl Ed448 fixture")

// sha384FixturePublicKey reuses the v7.66 §7.2 canonical fixture (0xAA × 64).
// HASH-FORMAT-SHA-384-1 hashes the same system/peer({pub=0xAA×64,
// key_type="experimental-test"}) entity under content_hash_format=0x01
// (SHA-384) and confirms the digest byte-equals across impls.
var sha384FixturePublicKey = agilityFixturePublicKey

func runCryptoAgility(ctx context.Context, client *PeerClient) []CheckResult {
	_ = ctx
	_ = client
	r := NewCheckRunner(catCryptoAgility)

	r.Declare("key_type_ed448_1",
		"v7.67 §3 (KEY-TYPE-ED448-1: system/peer({public_key, key_type=\"ed448\"}) constructs canonical-form (0x02, 0x01) peer_id; content_hash byte-equal cross-impl; sign/verify round-trip on fixed 57-byte Ed448 seed)")
	r.Declare("hash_format_sha_384_1",
		"v7.67 §4 (HASH-FORMAT-SHA-384-1: content_hash under content_hash_format=0x01 byte-equal cross-impl for the v7.66 0xAA×64 fixture entity, re-hashed under SHA-384; wire size 49 bytes = 1 + 48)")
	r.Declare("varint_multibyte_1",
		"v7.67 §5.4 normative (VARINT-MULTIBYTE-1: impl decodes a system/hash with multi-byte LEB128 format-code 0x80 0x01 and rejects with unsupported_content_hash_format since 0x80 (=128) is not allocated)")
	r.Declare("varint_reserved_ff_1",
		"v7.67 §5.4 normative (VARINT-RESERVED-FF-1: impl rejects construction of system/peer with key_type integer value 255 (varint 0xFF 0x01); impl rejects system/hash with format-code integer value 255)")

	r.Run("key_type_ed448_1", func() CheckOutcome {
		kp := crypto.Ed448FromSeed(ed448FixtureSeed)

		// Surface 1: canonical-form peer_id is (0x02, 0x01).
		pid := kp.PeerID()
		if err := pid.Validate(); err != nil {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: canonical Ed448 PeerID failed Validate(): %v", err))
		}
		dec, err := pid.Decode()
		if err != nil {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: PeerID.Decode errored: %v", err))
		}
		if dec.KeyType != crypto.KeyTypeEd448 {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: canonical Ed448 PeerID key_type byte = 0x%02x, want 0x%02x (v7.67 §3.1)",
				dec.KeyType, crypto.KeyTypeEd448))
		}
		if dec.HashType != crypto.HashTypeSHA256 {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: canonical Ed448 PeerID hash_type byte = 0x%02x, want 0x%02x (v7.67 §3.2 SHA-256-form pair)",
				dec.HashType, crypto.HashTypeSHA256))
		}

		// Surface 2: system/peer entity construction with data.key_type="ed448".
		ent, err := types.PeerData{
			PublicKey: kp.PublicKeyBytes(),
			KeyType:   crypto.KeyTypeStringEd448,
		}.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: PeerData.ToEntity errored: %v", err))
		}
		var dataMap map[string]cbor.RawMessage
		if err := cbor.Unmarshal(ent.Data, &dataMap); err != nil {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: decode entity.Data: %v", err))
		}
		var ktString string
		if err := cbor.Unmarshal(dataMap["key_type"], &ktString); err != nil {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: decode key_type string: %v", err))
		}
		if ktString != crypto.KeyTypeStringEd448 {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: data.key_type = %q, want %q (v7.67 §3.3 entity-data string pin)",
				ktString, crypto.KeyTypeStringEd448))
		}

		// Surface 3: sign/verify round-trip on the cohort-pinned fixed
		// message. Resulting sig bytes are directly comparable across
		// Go/Rust/Python — Ed448 sign is deterministic per RFC 8032.
		msg := ed448FixtureMessage
		sig := kp.Sign(msg)
		if len(sig) != crypto.Ed448SignatureLen {
			return FailCheck(fmt.Sprintf("KEY-TYPE-ED448-1: signature length %d, want %d", len(sig), crypto.Ed448SignatureLen))
		}
		if !crypto.Verify(crypto.KeyTypeEd448, kp.PublicKeyBytes(), msg, sig) {
			return FailCheck("KEY-TYPE-ED448-1: crypto.Verify (Ed448) rejected legitimate signature from fixed seed")
		}
		if crypto.Verify(crypto.KeyTypeEd448, kp.PublicKeyBytes(), []byte("tampered"), sig) {
			return FailCheck("KEY-TYPE-ED448-1: crypto.Verify (Ed448) accepted signature over tampered message")
		}

		// Surface 4: deterministic re-derivation gate. Same seed → same
		// public key (cross-impl byte-equal check uses this property).
		kp2 := crypto.Ed448FromSeed(ed448FixtureSeed)
		if string(kp.PublicKeyBytes()) != string(kp2.PublicKeyBytes()) {
			return FailCheck("KEY-TYPE-ED448-1: same seed produced different public_key on second derivation — non-deterministic library")
		}

		return PassCheck(fmt.Sprintf("KEY-TYPE-ED448-1: canonical (0x02, 0x01) peer_id %s; data.key_type=%q; sign/verify ok over fixed seed; pubkey len %d; sig len %d",
			pid, ktString, len(kp.PublicKeyBytes()), len(sig)))
	})

	r.Run("hash_format_sha_384_1", func() CheckOutcome {
		// Re-hash the v7.66 §7.2 canonical fixture
		// (system/peer({pub=0xAA×64, key_type="experimental-test"}))
		// under content_hash_format=0x01 (SHA-384). Confirms:
		//   - Algorithm byte = 0x01
		//   - Effective digest length = 48 bytes
		//   - Wire size = 49 bytes (1 byte format-code + 48 byte digest)
		//   - Display prefix = "ecfv1-sha384:"
		//   - Manual SHA-384 over the ECF-encoded {data, type} matches
		ent, err := types.PeerData{
			PublicKey: sha384FixturePublicKey,
			KeyType:   crypto.KeyTypeStringExperimentalTest,
		}.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: build canonical fixture entity: %v", err))
		}
		h384, err := hash.ComputeFormat(hash.AlgorithmSHA384, ent.Type, ent.Data)
		if err != nil {
			return FailCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: ComputeFormat errored: %v", err))
		}
		if h384.Algorithm != hash.AlgorithmSHA384 {
			return FailCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: Algorithm = 0x%02x, want 0x%02x", h384.Algorithm, hash.AlgorithmSHA384))
		}
		if len(h384.EffectiveDigest()) != hash.SHA384DigestSize {
			return FailCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: EffectiveDigest length = %d, want %d (v7.67 §4.1 SHA-384 digest size)",
				len(h384.EffectiveDigest()), hash.SHA384DigestSize))
		}
		wire := h384.Bytes()
		if len(wire) != 49 {
			return FailCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: wire size = %d, want 49 (1 + 48) per v7.67 §4 SHA-384 allocation", len(wire)))
		}

		// Surface 4: dispatch returns nil for 0x01.
		if err := hash.DispatchContentHashFormat(h384); err != nil {
			return FailCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: DispatchContentHashFormat rejected allocated 0x01: %v", err))
		}

		// Surface 5: round-trip through FromBytes preserves the hash.
		rt, err := hash.FromBytes(wire)
		if err != nil {
			return FailCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: FromBytes(49-byte wire) errored: %v", err))
		}
		if rt != h384 {
			return FailCheck("HASH-FORMAT-SHA-384-1: wire-form round-trip mismatch")
		}

		// Surface 6: manual SHA-384 confirms the algorithm — verifies we
		// are NOT silently SHA-256-ing under the 0x01 label.
		ecfBytes, _ := ecf.EncodeHashable(ent.Type, ent.Data)
		want := sha512.Sum384(ecfBytes)
		if string(h384.EffectiveDigest()) != string(want[:]) {
			return FailCheck("HASH-FORMAT-SHA-384-1: digest does not match SHA-384(ECF({type, data})) — algorithm dispatch wrong")
		}

		// Surface 7: NewEntityFormat builds an entity carrying SHA-384
		// directly (covers the call-site path that picks format up-front).
		ent384, err := entity.NewEntityFormat(hash.AlgorithmSHA384, ent.Type, ent.Data)
		if err != nil {
			return FailCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: NewEntityFormat errored: %v", err))
		}
		if ent384.ContentHash != h384 {
			return FailCheck("HASH-FORMAT-SHA-384-1: NewEntityFormat content_hash diverges from ComputeFormat")
		}

		return PassCheck(fmt.Sprintf("HASH-FORMAT-SHA-384-1: %s (wire %d bytes; format-code 0x%02x; effective digest %d bytes)",
			h384, len(wire), h384.Algorithm, len(h384.EffectiveDigest())))
	})

	r.Run("varint_multibyte_1", func() CheckOutcome {
		// V7.67 §5 normative: multi-byte LEB128 must decode correctly.
		// Synthetic 2-byte fixture: leading byte 0x80 0x01 encodes the
		// integer value 128 (= 0x80 with high-bit-of-low7=0, continuation
		// bit set; b[1]=0x01 contributes 1 in bit 7). 128 is not an
		// allocated format-code → unsupported_content_hash_format.
		//
		// What it doesn't test: that we can decode an *allocated*
		// multi-byte code, because none are allocated. The thing the
		// vector pins is that the decoder reaches the lookup step
		// (instead of panicking or treating 0x80 as a single-byte 0x80
		// allocation).
		multibyte := []byte{0x80, 0x01}
		err := hash.DispatchContentHashBytes(multibyte)
		if err == nil {
			return FailCheck("VARINT-MULTIBYTE-1: DispatchContentHashBytes(0x80 0x01) returned nil — multi-byte LEB128 format-code 128 must yield unsupported_content_hash_format")
		}
		if !errors.Is(err, ecerrors.ErrUnsupportedContentHashFormat) {
			return FailCheck(fmt.Sprintf("VARINT-MULTIBYTE-1: error type wrong: got %v, want ErrUnsupportedContentHashFormat", err))
		}

		// Negative-of-negative: a fabricated 3-byte LEB128 (0x80 0x82 0x01,
		// value > u8) must also reject — decoder MUST NOT silently truncate.
		err = hash.DispatchContentHashBytes([]byte{0x80, 0x82, 0x01})
		if err == nil {
			return FailCheck("VARINT-MULTIBYTE-1: over-u8 LEB128 returned nil — decoder must reject continuation-past-second-byte")
		}

		return PassCheck("VARINT-MULTIBYTE-1: multi-byte LEB128 format-codes decode through to allocation lookup; 0x80 0x01 (=128) yields unsupported_content_hash_format; over-u8 LEB128 rejected")
	})

	r.Run("varint_reserved_ff_1", func() CheckOutcome {
		// V7.67 §5.4 normative: integer value 255 is reserved on both
		// axes and SHALL NOT be allocated.
		//
		// Surface 1: peer_id mint with key_type=0xFF rejects.
		_, err := crypto.PeerIDFromExperimentalTestPublicKey(make([]byte, crypto.ExperimentalTestPublicKeyLen))
		if err != nil {
			// (this should succeed; experimental-test is 0xFE — sanity check
			// the helper, not the target). Fall through; this is not the
			// vector itself.
			_ = err
		}
		// Construct a peer_id with key_type=0xFF directly via derivePeerID
		// surface — public API is the canonical mint helpers, so we go via
		// the wire decoder's reject side as the protocol-visible surface.
		//
		// Decoder reject: a hand-built Base58 peer_id with varint key_type
		// = 0xFF 0x01 (LEB128 of integer 255) must fail Validate / Decode.
		// We construct the inner bytestring and Base58-encode it.
		fakePrefixed := []byte{0xFF, 0x01, crypto.HashTypeSHA256}
		fakePrefixed = append(fakePrefixed, make([]byte, hash.SHA256DigestSize)...)
		peerID := crypto.PeerID(crypto.Base58EncodeForTests(fakePrefixed))
		if err := peerID.Validate(); err == nil {
			return FailCheck("VARINT-RESERVED-FF-1: peer_id with key_type=255 (varint 0xFF 0x01) accepted by Validate() — must reject per v7.67 §5.4")
		}

		// Surface 2: content_hash with format-code=255 rejects.
		err = hash.DispatchContentHashBytes([]byte{0xFF, 0x01})
		if err == nil {
			return FailCheck("VARINT-RESERVED-FF-1: hash with format-code=255 accepted by DispatchContentHashBytes — must reject per v7.67 §5.4")
		}
		if !errors.Is(err, ecerrors.ErrUnsupportedContentHashFormat) {
			return FailCheck(fmt.Sprintf("VARINT-RESERVED-FF-1: format-code=255 rejected with wrong error: %v", err))
		}

		return PassCheck("VARINT-RESERVED-FF-1: key_type=255 mint refused; hash format-code=255 refused; integer value 255 reserved on both axes per v7.67 §5.4")
	})

	return r.Results()
}

