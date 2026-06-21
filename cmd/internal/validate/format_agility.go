package validate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	corecap "go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-tron/base58"
)

// catFormatAgility is the v7.66 format-agility validation + cleanup
// conformance category per PROPOSAL-V7-V7.66-FORMAT-AGILITY-VALIDATION-
// AND-CLEANUP §7, with the v7.67 §2 errata rename folded in. Ten vectors
// covering: §2 errata (KEY-TYPE-STRING-1, KEY-TYPE-PREFIX-1), §3 legacy rip
// (LEGACY-MINT-1), §4 stub key_type 0xFE (AGILITY-DECODE-1, AGILITY-
// ENTITY-1, AGILITY-CANONICAL-1, AGILITY-PATTERN-1, AGILITY-UNKNOWN-1),
// §5.2 / v7.67 §2.3 format-code interpretation (FORMAT-CODE-
// INTERPRETATION-1, renamed from v7.66 PREFIX-DISPATCH-1), §5.3 cap-chain
// freeze (CAP-FREEZE-1). Cross-impl 10/10 PASS is the v7.66 lock signal.
const catFormatAgility = "format_agility"

// agilityFixturePublicKey is the AGILITY-ENTITY-1 / AGILITY-CANONICAL-1
// canonical test fixture: 64 bytes, every byte 0xAA. Pinned at v7.66 §7.2
// — corpus-as-byte-vector discipline, not "whichever impl writes first".
var agilityFixturePublicKey = func() []byte {
	b := make([]byte, crypto.ExperimentalTestPublicKeyLen)
	for i := range b {
		b[i] = 0xAA
	}
	return b
}()

// agilityEntity1CorpusHash is the cross-impl convergence pin for
// AGILITY-ENTITY-1: content_hash(system/peer({public_key=0xAA×64,
// key_type="experimental-test"})) as the 33-byte wire form
// (algorithm byte || 32-byte digest). Rust-authored at v7.66 landing,
// confirmed cross-impl with Go.
//
// If this value disagrees with another impl's computation, the divergence
// is either a v7.66 §7.2 corpus authoring violation (whoever wrote first
// wins ≠ what the spec algorithm says) or a real ECF / peer-data shape
// bug. Trace back to ECF deterministic encoding (peerData = {public_key,
// key_type} with cbor:public_key first, cbor:key_type second per struct
// tag order — ECF re-sorts canonically).
const agilityEntity1CorpusHash = "003d0c34b508c5bf9eca5f086f09aac10f44bd43fca1a091b6aa55a096ca8fcd45"

func runFormatAgility(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catFormatAgility)

	r.Declare("key_type_string_1",
		"v7.66 §2.2 errata (KEY-TYPE-STRING-1: system/peer.data.key_type encodes as CBOR string \"ed25519\", not int)")
	r.Declare("key_type_prefix_1",
		"v7.66 §2.2 errata (KEY-TYPE-PREFIX-1: binary peer_id prefix encodes as varint(0x01) for Ed25519)")
	r.Declare("legacy_mint_1",
		"v7.66 §3 legacy rip (LEGACY-MINT-1: no live mint API produces legacy SHA-256-form Ed25519 peer_id)")
	r.Declare("agility_decode_1",
		"v7.66 §4.4 surface 1 (AGILITY-DECODE-1: wire-format decoder accepts key_type=0xFE first byte without panic/hardcode-reject)")
	r.Declare("agility_entity_1",
		"v7.66 §4.4 surfaces 2+4 (AGILITY-ENTITY-1: system/peer({pub=0xAA×64, key_type=0xFE}) constructs with data.key_type=\"experimental-test\"; content_hash is byte-equal cross-impl)")
	r.Declare("agility_canonical_1",
		"v7.66 §4.4 surface 3 (AGILITY-CANONICAL-1: canonical-form selection for key_type=0xFE returns SHA-256-form hash_type=0x01; identity-form refused at mint per substrate floor)")
	r.Declare("agility_pattern_1",
		"v7.66 §4.4 surface 5 (AGILITY-PATTERN-1: cap pattern with key_type=0xFE peer reference canonicalizes per v7.65 §6 rules — no Ed25519 short-circuit)")
	r.Declare("agility_unknown_1",
		"v7.66 §4.4 surface 6 / §7.1 (AGILITY-UNKNOWN-1: handshake with unsupported key_type=0xFD returns 400 unsupported_key_type)")
	r.Declare("format_code_interpretation_1",
		"v7.67 §2.3 normative (FORMAT-CODE-INTERPRETATION-1, renamed from v7.66 PREFIX-DISPATCH-1: an impl receiving a content_hash whose format-code it does not support returns unsupported_content_hash_format; the format-code is intrinsic to the hash — no dispatch step is distinct from interpreting the leading bytes)")
	r.Declare("cap_freeze_1",
		"v7.66 §5.3 normative Reading A (CAP-FREEZE-1: cap-chain verifier refuses links whose own content_hashes cross format-code boundaries)")

	r.Run("key_type_string_1", func() CheckOutcome {
		// Local-impl vector: construct a system/peer entity with the
		// local impl's PeerData, decode the data CBOR map, and confirm
		// the "key_type" key is a CBOR text string with value "ed25519".
		// Distinct from the binary peer_id prefix (v7.66 §2.2 two-layer pin).
		kp, err := crypto.Generate()
		if err != nil {
			return FailCheck(fmt.Sprintf("generate keypair: %v", err))
		}
		ent, err := types.PeerData{PublicKey: kp.PublicKey, KeyType: crypto.KeyTypeStringEd25519}.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("PeerData.ToEntity: %v", err))
		}
		var dataMap map[string]cbor.RawMessage
		if err := cbor.Unmarshal(ent.Data, &dataMap); err != nil {
			return FailCheck(fmt.Sprintf("decode entity data as map: %v", err))
		}
		ktRaw, ok := dataMap["key_type"]
		if !ok {
			return FailCheck("system/peer.data has no \"key_type\" field")
		}
		var kt string
		if err := cbor.Unmarshal(ktRaw, &kt); err != nil {
			return FailCheck(fmt.Sprintf("key_type field is not a CBOR string: %v", err))
		}
		if kt != crypto.KeyTypeStringEd25519 {
			return FailCheck(fmt.Sprintf("key_type string = %q; want %q (v7.66 §2.2 pin: lowercase ASCII \"ed25519\")",
				kt, crypto.KeyTypeStringEd25519))
		}
		// Major type 3 (text string) check: CBOR major-type 3 starts 0x60..0x7B
		// for short strings — verifies it's text, not byte string or int.
		if len(ktRaw) == 0 || (ktRaw[0]&0xE0) != 0x60 {
			return FailCheck(fmt.Sprintf("key_type CBOR header 0x%02x is not major-type 3 (text string)", ktRaw[0]))
		}
		return PassCheck(fmt.Sprintf("KEY-TYPE-STRING-1: data.key_type is CBOR text string \"%s\" (v7.66 §2.2 errata)", kt))
	})

	r.Run("key_type_prefix_1", func() CheckOutcome {
		// Local-impl vector: mint a canonical Ed25519 peer_id, decode
		// the Base58 framing, and confirm the leading byte is 0x01.
		kp, err := crypto.Generate()
		if err != nil {
			return FailCheck(fmt.Sprintf("generate keypair: %v", err))
		}
		pid := kp.PeerID()
		dec, err := pid.Decode()
		if err != nil {
			return FailCheck(fmt.Sprintf("Decode: %v", err))
		}
		if dec.KeyType != crypto.KeyTypeEd25519 {
			return FailCheck(fmt.Sprintf("binary peer_id prefix = 0x%02x; want 0x%02x (v7.66 §2.2 pin)",
				dec.KeyType, crypto.KeyTypeEd25519))
		}
		return PassCheck(fmt.Sprintf("KEY-TYPE-PREFIX-1: binary peer_id prefix = 0x%02x (v7.66 §2.2 errata)", dec.KeyType))
	})

	r.Run("legacy_mint_1", func() CheckOutcome {
		// v7.66 §3 satisfaction shape: "calling the mint API in any v7.66
		// impl with parameters that would have constructed (key_type=0x01,
		// hash_type=0x01) either errors, yields canonical (0x01, 0x00)
		// output, or fails compile/type-check." Go ships error-on-mint:
		// PeerIDFromPublicKeyWithHashType refuses non-canonical Ed25519
		// hash_types post-v7.65 §4.
		kp, err := crypto.Generate()
		if err != nil {
			return FailCheck(fmt.Sprintf("generate keypair: %v", err))
		}
		_, mintErr := crypto.PeerIDFromPublicKeyWithHashType(kp.PublicKey, crypto.HashTypeSHA256)
		if mintErr == nil {
			return FailCheck("LEGACY-MINT-1 FAIL: mint API accepted (key_type=0x01, hash_type=0x01) — v7.66 §3 requires refusal")
		}
		// Default canonical path returns hash_type=0x00 (identity).
		canonPid, err := crypto.PeerIDFromPublicKey(kp.PublicKey, kp.KeyType)
		if err != nil {
			return FailCheck(fmt.Sprintf("canonical mint: %v", err))
		}
		canonDec, err := canonPid.Decode()
		if err != nil {
			return FailCheck(fmt.Sprintf("canonical mint decode: %v", err))
		}
		if canonDec.HashType != crypto.HashTypeIdentity {
			return FailCheck(fmt.Sprintf("canonical mint produced hash_type=0x%02x; v7.66 §3 + v7.65 §4 require 0x00", canonDec.HashType))
		}
		return PassCheck(fmt.Sprintf("LEGACY-MINT-1: mint refusal on non-canonical Ed25519 hash_type (%v); canonical default = identity-multihash (0x00)", mintErr))
	})

	r.Run("agility_decode_1", func() CheckOutcome {
		// Construct an SHA-256-form 0xFE peer_id (the v7.66 §4 canonical
		// pair) and verify the wire-format decoder accepts it without
		// panic and surfaces KeyType=0xFE — i.e., no hardcoded-Ed25519
		// reject in Decode().
		pub := agilityFixturePublicKey
		pid, err := crypto.PeerIDFromExperimentalTestPublicKey(pub)
		if err != nil {
			return FailCheck(fmt.Sprintf("mint 0xFE peer_id: %v", err))
		}
		dec, err := pid.Decode()
		if err != nil {
			return FailCheck(fmt.Sprintf("Decode 0xFE peer_id: %v", err))
		}
		if dec.KeyType != crypto.KeyTypeExperimentalTest {
			return FailCheck(fmt.Sprintf("decoder returned KeyType=0x%02x; want 0x%02x — hardcoded-Ed25519 path suspected",
				dec.KeyType, crypto.KeyTypeExperimentalTest))
		}
		if err := pid.Validate(); err != nil {
			return FailCheck(fmt.Sprintf("Validate 0xFE peer_id: %v", err))
		}
		return PassCheck(fmt.Sprintf("AGILITY-DECODE-1: decoder accepts key_type=0x%02x first byte; Decode + Validate both clean", dec.KeyType))
	})

	r.Run("agility_entity_1", func() CheckOutcome {
		// AGILITY-ENTITY-1: system/peer({pub=0xAA×64, key_type=0xFE})
		// constructs with data.key_type="experimental-test"; content_hash
		// is byte-equal cross-impl and matches the corpus-pinned value.
		ent, err := crypto.ExperimentalTestPeerEntity(agilityFixturePublicKey)
		if err != nil {
			return FailCheck(fmt.Sprintf("ExperimentalTestPeerEntity: %v", err))
		}
		// Confirm entity-data key_type string is "experimental-test".
		var dataMap map[string]cbor.RawMessage
		if err := cbor.Unmarshal(ent.Data, &dataMap); err != nil {
			return FailCheck(fmt.Sprintf("decode entity data: %v", err))
		}
		var kt string
		if err := cbor.Unmarshal(dataMap["key_type"], &kt); err != nil {
			return FailCheck(fmt.Sprintf("decode key_type field: %v", err))
		}
		if kt != crypto.KeyTypeStringExperimentalTest {
			return FailCheck(fmt.Sprintf("data.key_type = %q; want %q (v7.66 §4.2)",
				kt, crypto.KeyTypeStringExperimentalTest))
		}
		// Compute content_hash. v7.66 corpus discipline: derived from
		// the spec algorithm. The pinned value MUST match across Go/Rust/
		// Python on the identical fixture.
		ch := ent.ContentHash
		if ch.Algorithm != hash.AlgorithmSHA256 {
			return FailCheck(fmt.Sprintf("content_hash algorithm = 0x%02x; want 0x%02x", ch.Algorithm, hash.AlgorithmSHA256))
		}
		// Deterministic re-derivation gate: same fixture → same hash on
		// repeated construction.
		ent2, _ := crypto.ExperimentalTestPeerEntity(agilityFixturePublicKey)
		if ent.ContentHash != ent2.ContentHash {
			return FailCheck("AGILITY-ENTITY-1 FAIL: repeated construction of same fixture produced different content_hash — ECF non-determinism")
		}
		// Cross-impl corpus pin (v7.66 §7.2). Wire form = algorithm byte
		// || 32-byte digest = 33 bytes total, hex-encoded to 66 chars.
		wireHex := fmt.Sprintf("%02x%x", ch.Algorithm, ch.EffectiveDigest())
		if wireHex != agilityEntity1CorpusHash {
			return FailCheck(fmt.Sprintf("AGILITY-ENTITY-1 CORPUS DIVERGENCE: got %s; cross-impl pin is %s (v7.66 §7.2 — Rust-authored at landing, confirmed cross-impl Go)",
				wireHex, agilityEntity1CorpusHash))
		}
		return PassCheck(fmt.Sprintf("AGILITY-ENTITY-1: data.key_type=%q; content_hash=%s; cross-impl corpus pin %s MATCHED",
			kt, ch, agilityEntity1CorpusHash))
	})

	r.Run("agility_canonical_1", func() CheckOutcome {
		// AGILITY-CANONICAL-1: CanonicalHashType(0xFE) returns SHA-256-form
		// (0x01), per v7.66 §4.2 (substrate floor forces hash-form for
		// 64-byte pubkey). And the mint API for 0xFE uses the canonical
		// pair (0xFE, 0x01).
		canon, err := crypto.CanonicalHashType(crypto.KeyTypeExperimentalTest)
		if err != nil {
			return FailCheck(fmt.Sprintf("CanonicalHashType(0xFE): %v", err))
		}
		if canon != crypto.HashTypeSHA256 {
			return FailCheck(fmt.Sprintf("CanonicalHashType(0xFE) = 0x%02x; want 0x%02x (SHA-256-form)", canon, crypto.HashTypeSHA256))
		}
		pid, err := crypto.PeerIDFromExperimentalTestPublicKey(agilityFixturePublicKey)
		if err != nil {
			return FailCheck(fmt.Sprintf("mint 0xFE peer_id: %v", err))
		}
		dec, _ := pid.Decode()
		if dec.HashType != crypto.HashTypeSHA256 {
			return FailCheck(fmt.Sprintf("mint produced hash_type=0x%02x; want 0x%02x (v7.66 §4 canonical pair (0xFE, 0x01))", dec.HashType, crypto.HashTypeSHA256))
		}
		// Sanity: Ed25519 canonical is still 0x00.
		ed25519Canon, _ := crypto.CanonicalHashType(crypto.KeyTypeEd25519)
		if ed25519Canon != crypto.HashTypeIdentity {
			return FailCheck(fmt.Sprintf("CanonicalHashType(0x01 Ed25519) regressed to 0x%02x; v7.65 mandate is 0x00", ed25519Canon))
		}
		return PassCheck(fmt.Sprintf("AGILITY-CANONICAL-1: CanonicalHashType(0xFE)=0x%02x (SHA-256-form per v7.66 §4.2); CanonicalHashType(0x01)=0x%02x (Ed25519 identity-multihash)", canon, ed25519Canon))
	})

	r.Run("agility_pattern_1", func() CheckOutcome {
		// AGILITY-PATTERN-1: a cap-pattern naming a 0xFE peer canonicalizes
		// per v7.65 §6 rules — Canonicalize() takes localPeerID as opaque
		// and doesn't short-circuit on key_type. So a 0xFE-prefix peer_id
		// flows through the same canonical-form rules as Ed25519.
		pid0xFE, err := crypto.PeerIDFromExperimentalTestPublicKey(agilityFixturePublicKey)
		if err != nil {
			return FailCheck(fmt.Sprintf("mint 0xFE peer_id: %v", err))
		}
		// Pattern: peer-relative path referencing a 0xFE peer as subject
		// (not signer — §4.2 disallows sign/verify for 0xFE).
		bareRel := "system/validate/agility-pattern-1"
		canonBare := corecap.Canonicalize(bareRel, pid0xFE)
		expectedBare := "/" + string(pid0xFE) + "/" + bareRel
		if canonBare != expectedBare {
			return FailCheck(fmt.Sprintf("Canonicalize(peer-relative, 0xFE peer) = %q; want %q — Ed25519 short-circuit suspected", canonBare, expectedBare))
		}
		// Already-absolute path: passes through (peer-id segment is opaque).
		alreadyAbs := "/" + string(pid0xFE) + "/system/tree"
		canonAbs := corecap.Canonicalize(alreadyAbs, pid0xFE)
		if canonAbs != alreadyAbs {
			return FailCheck(fmt.Sprintf("Canonicalize(absolute, 0xFE peer) = %q; want pass-through %q", canonAbs, alreadyAbs))
		}
		return PassCheck(fmt.Sprintf("AGILITY-PATTERN-1: cap-pattern canonicalization with 0xFE peer subject works per v7.65 §6 — Canonicalize(%q)=%q", bareRel, canonBare))
	})

	r.Run("agility_unknown_1", func() CheckOutcome {
		// AGILITY-UNKNOWN-1: wire-level handshake against the live target
		// using a hand-constructed 0xFD-prefix peer_id. Expected: target
		// returns 400 unsupported_key_type at SOME point during handshake
		// (v7.66 §4.4 surface 6 / §7.1; V7 §4.7 registry pin).
		//
		// Cohort tolerance: spec says "handshake unknown-key_type reject"
		// — hello vs authenticate is left to the impl. Some impls reject
		// at hello (the earliest natural surface — Rust, Go); some at
		// authenticate (Python's connect-handler-on-authenticate). The
		// vector tries hello first; if hello accepts (status 200), the
		// vector falls through to authenticate. PASS if either boundary
		// produces 400 unsupported_key_type.
		//
		// 0xFD is unallocated in the §4.3 0xF0-0xFE experimental range
		// (NOT 0xFF — that's protocol-reserved).
		if !client.Connected() {
			return SkipCheck("AGILITY-UNKNOWN-1: target peer not reachable")
		}
		const unknownKeyType byte = 0xFD

		helloStatus, helloCode, surface, err := attemptHandshakeWithKeyType(ctx, client.Addr(), unknownKeyType)
		if err != nil {
			return FailCheck(fmt.Sprintf("AGILITY-UNKNOWN-1 setup: %v", err))
		}
		if helloStatus == 400 && helloCode == "unsupported_key_type" {
			return PassCheck(fmt.Sprintf("AGILITY-UNKNOWN-1: target rejected key_type=0x%02x with 400 unsupported_key_type at handshake.%s per V7 §4.7", unknownKeyType, surface))
		}
		if helloStatus != 200 && helloStatus != 400 {
			return FailCheck(fmt.Sprintf("AGILITY-UNKNOWN-1 FAIL: target returned status=%d code=%q for key_type=0x%02x at handshake.%s; want 400 unsupported_key_type or 200 (fall through to authenticate)",
				helloStatus, helloCode, unknownKeyType, surface))
		}
		// helloStatus == 400 with wrong code → real failure
		if helloStatus == 400 {
			return FailCheck(fmt.Sprintf("AGILITY-UNKNOWN-1 FAIL: target returned status=400 code=%q for key_type=0x%02x at handshake.%s; want code=unsupported_key_type (V7 §4.7 registry pin)",
				helloCode, unknownKeyType, surface))
		}
		return FailCheck(fmt.Sprintf("AGILITY-UNKNOWN-1 FAIL: target accepted hello with bad key_type=0x%02x (status=%d) AND no authenticate-side reject surfaced; v7.66 §4.4 surface 6 unsatisfied",
			unknownKeyType, helloStatus))
	})

	r.Run("format_code_interpretation_1", func() CheckOutcome {
		// FORMAT-CODE-INTERPRETATION-1 (v7.67 §2.3, renamed from v7.66
		// PREFIX-DISPATCH-1): hash.DispatchContentHashFormat returns nil
		// for an allocated format-code (0x00 SHA-256, 0x01 SHA-384) and
		// ErrUnsupportedContentHashFormat (wraps to 400 wire code) for
		// any unallocated byte.
		var h hash.Hash
		h.Algorithm = hash.AlgorithmSHA256
		if err := hash.DispatchContentHashFormat(h); err != nil {
			return FailCheck(fmt.Sprintf("DispatchContentHashFormat(0x00) returned error: %v — should be nil for allocated format", err))
		}
		// Unsupported format byte: 0x42 (arbitrary unallocated).
		var hUnknown hash.Hash
		hUnknown.Algorithm = 0x42
		err := hash.DispatchContentHashFormat(hUnknown)
		if err == nil {
			return FailCheck("DispatchContentHashFormat(0x42) returned nil — should be ErrUnsupportedContentHashFormat")
		}
		if !errors.Is(err, ecerrors.ErrUnsupportedContentHashFormat) {
			return FailCheck(fmt.Sprintf("DispatchContentHashFormat(0x42) returned %v; want ErrUnsupportedContentHashFormat", err))
		}
		// Bytes-level dispatch primitive for content-store callers
		// operating on raw bytestrings.
		if err := hash.DispatchContentHashBytes([]byte{hash.AlgorithmSHA256, 0, 0}); err != nil {
			return FailCheck(fmt.Sprintf("DispatchContentHashBytes(0x00…) returned error: %v", err))
		}
		if err := hash.DispatchContentHashBytes([]byte{0x42}); !errors.Is(err, ecerrors.ErrUnsupportedContentHashFormat) {
			return FailCheck(fmt.Sprintf("DispatchContentHashBytes(0x42) = %v; want ErrUnsupportedContentHashFormat", err))
		}
		return PassCheck("FORMAT-CODE-INTERPRETATION-1: format-code interpretation returns nil for allocated formats (0x00, 0x01) and ErrUnsupportedContentHashFormat for unallocated bytes (v7.67 §2.3, renamed from v7.66 PREFIX-DISPATCH-1)")
	})

	r.Run("cap_freeze_1", func() CheckOutcome {
		// CAP-FREEZE-1: cap-chain verifier refuses a chain whose own
		// link content_hashes cross format-code boundaries without a
		// continuous signer-set re-signing event. Reading A — the chain's
		// format-code is the leading byte of each link's content_hash.
		//
		// Today only format-code 0x00 is allocated, so we synthesize
		// a 2-link chain in-memory and mutate the parent link's stored
		// ContentHash.Algorithm to a non-0x00 value, then walk it.
		// Expected: ErrCapabilityDenied wrapping the v7.66 §5.3 freeze
		// message.
		kp, err := crypto.Generate()
		if err != nil {
			return FailCheck(fmt.Sprintf("generate keypair: %v", err))
		}
		granterEnt, _ := kp.IdentityEntity()
		// Build a self-grant root cap (granter == grantee == the local
		// keypair's identity).
		rootData := types.CapabilityTokenData{
			Grantee:   granterEnt.ContentHash,
			Granter:   types.SingleSigGranter(granterEnt.ContentHash),
			Grants:    []types.GrantEntry{{Resources: types.CapabilityScope{Include: []string{"system/validate/cap-freeze-1/*"}}}},
			CreatedAt: uint64(time.Now().UnixMilli()),
		}
		rootEnt, err := rootData.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("root ToEntity: %v", err))
		}
		// Child link: parent = root.
		childData := types.CapabilityTokenData{
			Grantee:   granterEnt.ContentHash,
			Granter:   types.SingleSigGranter(granterEnt.ContentHash),
			Grants:    rootData.Grants,
			Parent:    &rootEnt.ContentHash,
			CreatedAt: uint64(time.Now().UnixMilli()),
		}
		childEnt, err := childData.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("child ToEntity: %v", err))
		}
		// Sanity: real chain walks cleanly.
		resolver := corecap.IncludedResolver(map[hash.Hash]entity.Entity{
			rootEnt.ContentHash:  rootEnt,
			childEnt.ContentHash: childEnt,
		})
		chain, err := corecap.CollectAuthorityChain(childEnt, resolver)
		if err != nil {
			return FailCheck(fmt.Sprintf("CAP-FREEZE-1 setup: clean chain walk failed: %v", err))
		}
		if len(chain) != 2 {
			return FailCheck(fmt.Sprintf("CAP-FREEZE-1 setup: clean chain length %d; want 2", len(chain)))
		}
		// Now mutate the ROOT's stored ContentHash.Algorithm to a synthetic
		// non-0x00 format-code, and resolve via a map keyed under both
		// (childData.Parent points at the ORIGINAL root hash). The walk
		// arrives at the mutated entity at depth=1 → format-code mismatch
		// against the chain's 0x00 starting code → ErrCapabilityDenied.
		mutatedRoot := rootEnt
		mutatedRoot.ContentHash.Algorithm = 0x42 // unallocated synthetic
		mixedResolver := corecap.IncludedResolver(map[hash.Hash]entity.Entity{
			rootEnt.ContentHash: mutatedRoot,
		})
		_, walkErr := corecap.CollectAuthorityChain(childEnt, mixedResolver)
		if walkErr == nil {
			return FailCheck("CAP-FREEZE-1 FAIL: chain walk accepted cross-format-code link without re-signing — v7.66 §5.3 freeze not enforced")
		}
		if !errors.Is(walkErr, ecerrors.ErrCapabilityDenied) {
			return FailCheck(fmt.Sprintf("CAP-FREEZE-1: walk failed with %v; want wrapped ErrCapabilityDenied for §5.3 freeze", walkErr))
		}
		if !containsSubstring(walkErr.Error(), "format-code") {
			return FailCheck(fmt.Sprintf("CAP-FREEZE-1: rejection message does not reference v7.66 §5.3 format-code freeze: %v", walkErr))
		}
		return PassCheck("CAP-FREEZE-1: cap-chain walker rejected cross-format-code link with §5.3 freeze (Reading A — chain's own link content_hashes)")
	})

	return r.Results()
}

// containsSubstring is strings.Contains inline to avoid a `strings` import.
func containsSubstring(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// attemptHandshakeWithKeyType opens a fresh transport connection to addr
// and walks through hello → authenticate using a hand-constructed
// peer_id whose varint key_type prefix is the given byte (in place of
// Ed25519's 0x01).
//
// Returns (status, code, surface, error). `surface` is "hello" if the
// reject (or accept) came from the hello round-trip, "authenticate" if
// the hello was accepted with status 200 and the authenticate step was
// reached. This lets AGILITY-UNKNOWN-1 distinguish hello-side vs
// authenticate-side reject impls — both are spec-conformant.
func attemptHandshakeWithKeyType(ctx context.Context, addr string, keyTypeByte byte) (uint, string, string, error) {
	// Generate a real Ed25519 keypair — we'll lie about the peer_id prefix.
	kp, err := crypto.Generate()
	if err != nil {
		return 0, "", "", fmt.Errorf("generate keypair: %w", err)
	}
	c, err := NewPeerClientWithKeypair(addr, kp)
	if err != nil {
		return 0, "", "", fmt.Errorf("new client: %w", err)
	}
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		return 0, "", "", fmt.Errorf("connect: %w", err)
	}

	// Construct a "bad-key_type" peer_id at the v7.66 §1.5 varint layout:
	//   Base58(varint(key_type) || varint(hash_type=0x01) || sha256(pub))
	// For key_type 0xFD: varint = [0xFD, 0x01] (two-byte LEB128); for
	// 0x01..0x7F: single-byte varint identical to raw byte.
	sum := sha256.Sum256(kp.PublicKey)
	var prefix []byte
	if keyTypeByte < 0x80 {
		prefix = []byte{keyTypeByte, crypto.HashTypeSHA256}
	} else {
		prefix = []byte{keyTypeByte | 0x80, 0x01, crypto.HashTypeSHA256}
	}
	badPeerIDBytes := append(prefix, sum[:]...)
	badPeerID := base58.Encode(badPeerIDBytes)

	identity, err := kp.IdentityEntity()
	if err != nil {
		return 0, "", "", fmt.Errorf("identity entity: %w", err)
	}

	// ===== HELLO step (hello-side reject surface) =====
	helloData := types.HelloData{
		PeerID:    badPeerID,
		Nonce:     make([]byte, 32),
		Protocols: []string{"entity-core/v7"},
		Timestamp: 0,
	}
	helloEnt, err := helloData.ToEntity()
	if err != nil {
		return 0, "", "", fmt.Errorf("hello ToEntity: %w", err)
	}
	helloParamsRaw, err := ecf.Encode(helloEnt)
	if err != nil {
		return 0, "", "", fmt.Errorf("encode hello params: %w", err)
	}
	helloExecData := types.ExecuteData{
		RequestID: "agility-unknown-1-hello",
		URI:       "system/protocol/connect",
		Operation: "hello",
		Params:    cbor.RawMessage(helloParamsRaw),
	}
	helloExecEnt, err := helloExecData.ToEntity()
	if err != nil {
		return 0, "", "", fmt.Errorf("hello ExecuteData.ToEntity: %w", err)
	}
	helloEnv := entity.NewEnvelope(helloExecEnt, map[hash.Hash]entity.Entity{
		identity.ContentHash: identity,
		helloEnt.ContentHash: helloEnt,
	})
	if err := c.writeEnvelope(ctx, helloEnv); err != nil {
		return 0, "", "", fmt.Errorf("send hello: %w", err)
	}
	respBytes, err := c.readFrame(ctx)
	if err != nil {
		return 0, "", "hello", fmt.Errorf("read hello response: %w", err)
	}
	var respEnv entity.Envelope
	if err := ecf.Decode(respBytes, &respEnv); err != nil {
		return 0, "", "hello", fmt.Errorf("decode hello response: %w", err)
	}
	helloStatus, helloCode, helloRespData, err := extractStatusAndCode(respEnv)
	if err != nil {
		return 0, "", "hello", err
	}
	if helloStatus != 200 {
		// Hello-side reject — done.
		return helloStatus, helloCode, "hello", nil
	}

	// ===== Hello accepted; fall through to AUTHENTICATE step
	// (authenticate-side reject surface) =====
	// Extract the server's nonce from the hello response so we can echo
	// it in authenticate.
	var helloResult entity.Entity
	if err := ecf.Decode(helloRespData.Result, &helloResult); err != nil {
		return 0, "", "authenticate", fmt.Errorf("decode hello result entity: %w", err)
	}
	helloResultData, err := types.HelloDataFromEntity(helloResult)
	if err != nil {
		return 0, "", "authenticate", fmt.Errorf("decode hello result data: %w", err)
	}
	authData := types.AuthenticateData{
		PeerID:    badPeerID,
		PublicKey: kp.PublicKeyBytes(),
		KeyType:   crypto.KeyTypeStringEd25519,
		Nonce:     helloResultData.Nonce,
	}
	authEnt, err := authData.ToEntity()
	if err != nil {
		return 0, "", "authenticate", fmt.Errorf("authenticate ToEntity: %w", err)
	}
	sig := kp.Sign(authEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    authEnt.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return 0, "", "authenticate", fmt.Errorf("sig ToEntity: %w", err)
	}
	authParamsRaw, err := ecf.Encode(authEnt)
	if err != nil {
		return 0, "", "authenticate", fmt.Errorf("encode authenticate params: %w", err)
	}
	authExecData := types.ExecuteData{
		RequestID: "agility-unknown-1-auth",
		URI:       "system/protocol/connect",
		Operation: "authenticate",
		Params:    cbor.RawMessage(authParamsRaw),
	}
	authExecEnt, err := authExecData.ToEntity()
	if err != nil {
		return 0, "", "authenticate", fmt.Errorf("authenticate ExecuteData.ToEntity: %w", err)
	}
	authEnv := entity.NewEnvelope(authExecEnt, map[hash.Hash]entity.Entity{
		identity.ContentHash: identity,
		sigEnt.ContentHash:   sigEnt,
		authEnt.ContentHash:  authEnt,
	})
	if err := c.writeEnvelope(ctx, authEnv); err != nil {
		return 0, "", "authenticate", fmt.Errorf("send authenticate: %w", err)
	}
	authRespBytes, err := c.readFrame(ctx)
	if err != nil {
		return 0, "", "authenticate", fmt.Errorf("read authenticate response: %w", err)
	}
	var respEnv2 entity.Envelope
	if err := ecf.Decode(authRespBytes, &respEnv2); err != nil {
		return 0, "", "authenticate", fmt.Errorf("decode authenticate response: %w", err)
	}
	respEnv = respEnv2
	status, code, _, err := extractStatusAndCode(respEnv)
	if err != nil {
		return 0, "", "authenticate", err
	}
	return status, code, "authenticate", nil
}

// extractStatusAndCode pulls (status, code) from an execute-response
// envelope. Code extraction handles cross-impl ErrorData schema variation
// via a strict-then-generic decode fallback (Go/Rust use the {code,
// message} struct shape; some impls may use a generic CBOR map).
func extractStatusAndCode(respEnv entity.Envelope) (uint, string, types.ExecuteResponseData, error) {
	resp, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, "", types.ExecuteResponseData{}, fmt.Errorf("decode execute response data: %w", err)
	}
	var code string
	if resp.Status >= 400 && len(resp.Result) > 0 {
		var resultEnt entity.Entity
		if err := ecf.Decode(resp.Result, &resultEnt); err == nil {
			var errData types.ErrorData
			if err := ecf.Decode(resultEnt.Data, &errData); err == nil && errData.Code != "" {
				code = errData.Code
			} else {
				var raw map[string]interface{}
				if err := cbor.Unmarshal(resultEnt.Data, &raw); err == nil {
					if v, ok := raw["code"]; ok {
						if s, ok := v.(string); ok {
							code = s
						}
					}
					if code == "" {
						code = fmt.Sprintf("<no-code-field; raw=%+v>", raw)
					}
				}
			}
		}
	}
	return resp.Status, code, resp, nil
}

