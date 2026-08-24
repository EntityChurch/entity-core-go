package validate

import (
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catEncoding = "encoding"

// isHashWireSize reports whether n is the on-wire byte length of a content hash
// under some allocated content_hash_format (33 for SHA-256, 49 for SHA-384).
func isHashWireSize(n int) bool {
	for _, a := range hash.Algorithms() {
		if hash.HashWireSize(a) == n {
			return true
		}
	}
	return false
}

// collectHashSizedByteStrings decodes a raw CBOR handshake frame STRUCTURALLY
// and returns every byte-string ITEM whose length is a content-hash wire size
// (algorithm || digest). Each returned slice is the whole byte string, so the
// caller reads its leading format byte at [0].
//
// WHY STRUCTURAL, NOT A BYTE SCAN (fixes the recurring `hash_wire_format` flake).
// This used to walk raw[i:] at every offset looking for the pair 0x58,0x21 /
// 0x58,0x31 (a 1-byte-length CBOR byte string sized 33/49). That pair occurs by
// chance inside the *content* of any sufficiently long byte string — a 32-byte
// digest, a 64-byte signature, a nonce — and when it did, the following random
// byte was read as a bogus "format byte", `hash.HashWireSize` returned 0 ≠ the
// declared length, and the check FAILed. Data-dependent (the digests change per
// run), so it flaked ~1-in-6, same commit, same box — sighted against python
// 2026-08-08 and rust 2026-08-14, both non-reproducing and both closed as
// "flake" because the *mechanism* was never named. Decoding the CBOR and
// inspecting only real byte-string items cannot collide with byte-string
// content, because content is never visited as structure.
//
// The §8.4.5 intent survives: a genuine hash-sized byte-string item carrying an
// unallocated format byte is still an item, still collected, and still failed by
// the caller — only the phantom matches inside other items' payloads are gone.
// An undecodable frame returns nil (the caller then WARNs "could not locate"),
// which is itself a signal, not a silent pass.
func collectHashSizedByteStrings(raw []byte) [][]byte {
	var v interface{}
	if err := cbor.Unmarshal(raw, &v); err != nil {
		return nil
	}
	var out [][]byte
	var walk func(x interface{})
	walk = func(x interface{}) {
		switch t := x.(type) {
		case []byte:
			if isHashWireSize(len(t)) {
				out = append(out, t)
			}
		case []interface{}:
			for _, e := range t {
				walk(e)
			}
		case map[interface{}]interface{}:
			for k, val := range t {
				walk(k)
				walk(val)
			}
		case map[string]interface{}:
			for _, val := range t {
				walk(val)
			}
		case cbor.Tag:
			walk(t.Content)
		}
	}
	walk(v)
	return out
}

// appendFormatOnce records an observed content_hash_format for reporting.
func appendFormatOnce(seen []string, alg byte) []string {
	label := fmt.Sprintf("0x%02x", alg)
	for _, s := range seen {
		if s == label {
			return seen
		}
	}
	return append(seen, label)
}

// runEncoding performs encoding validation checks on raw bytes from the connect handshake.
func runEncoding(client *PeerClient) []CheckResult {
	r := NewCheckRunner(catEncoding)

	// --- Declare all checks ---

	r.Declare("hash_wire_format", "ECF §4.3")
	r.Declare("hash_algorithm_byte", "ECF §4.3")
	r.Declare("entity_hash_valid", "V7 §1.5")
	r.Declare("ecf_key_ordering", "ECF §4.2")
	r.Declare("signature_signer_is_hash", "V7 §3.5")
	r.Declare("caveats_flat_struct", "V7 §3.6")

	// Collect all entities from both handshake responses for inspection.
	var allEntities []entity.Entity
	var allRawFrames [][]byte

	if client.HelloResponseBytes != nil {
		allRawFrames = append(allRawFrames, client.HelloResponseBytes)
		allEntities = append(allEntities, client.HelloResponseEnvelope.Root)
		for _, ent := range client.HelloResponseEnvelope.Included {
			allEntities = append(allEntities, ent)
		}
	}
	if client.AuthenticateResponseBytes != nil {
		allRawFrames = append(allRawFrames, client.AuthenticateResponseBytes)
		allEntities = append(allEntities, client.AuthenticateResponseEnv.Root)
		for _, ent := range client.AuthenticateResponseEnv.Included {
			allEntities = append(allEntities, ent)
		}
	}

	// --- Run checks ---

	r.Run("hash_wire_format", func() CheckOutcome {
		found := false
		valid := true
		var seen []string
		for _, raw := range allRawFrames {
			for _, bs := range collectHashSizedByteStrings(raw) {
				alg, declared := bs[0], len(bs)
				if hash.HashWireSize(alg) == declared {
					found = true
					seen = appendFormatOnce(seen, alg)
				} else {
					// A byte string sized like a hash whose leading
					// format byte implies a different size — the exact
					// shape §8.4.5 exists to catch.
					valid = false
				}
			}
		}
		if found && valid {
			r.Store("hash_wire_ok", true)
			return PassCheck(fmt.Sprintf(
				"hashes are CBOR byte strings whose declared length matches their own format byte (observed: %s)",
				strings.Join(seen, ", ")))
		}
		if !found {
			return WarnCheck("could not locate hash byte strings in raw CBOR")
		}
		return FailCheck("hash wire format invalid: a hash-sized byte string disagrees with its own format byte")
	})

	r.Run("hash_algorithm_byte", func() CheckOutcome {
		if !r.OK("hash_wire_format") {
			return SkipCheck("skipped: no hashes found in raw bytes")
		}
		if r.Load("hash_wire_ok") == nil {
			return SkipCheck("skipped: no hashes found in raw bytes")
		}
		// The algorithm byte MUST be an allocated content_hash_format code.
		// It is NOT required to be 0x00: a peer running a SHA-384 home format
		// emits 0x01 and is fully conformant (ENTITY-CORE-PROTOCOL §1.2;
		// SPECIFICATION-FORMAT §8.4.5). Asserting 0x00 here measured the
		// harness's assumption, not the peer.
		allGood := true
		var seen []string
		for _, raw := range allRawFrames {
			for _, bs := range collectHashSizedByteStrings(raw) {
				alg, declared := bs[0], len(bs)
				if hash.HashWireSize(alg) != declared {
					allGood = false
					continue
				}
				seen = appendFormatOnce(seen, alg)
			}
		}
		if allGood {
			return PassCheck(fmt.Sprintf("hash algorithm byte is an allocated content_hash_format (observed: %s)",
				strings.Join(seen, ", ")))
		}
		return FailCheck("hash algorithm byte is not an allocated content_hash_format")
	})

	r.Run("entity_hash_valid", func() CheckOutcome {
		count := 0
		for _, ent := range allEntities {
			if ent.Type == "" {
				continue
			}
			count++
			// Validate under the entity's CLAIMED algorithm — not the test's
			// process-default. The peer authors entities under its active
			// format (SHA-256 or SHA-384 per v7.67 §4 / v7.69 §1.8); the
			// previous hash.Compute call hardcoded SHA-256 and reported a
			// false mismatch on SHA-384 peers.
			if err := hash.Validate(ent.Type, cbor.RawMessage(ent.Data), ent.ContentHash); err != nil {
				return FailCheck(fmt.Sprintf("entity hash mismatch: type=%s: %v", ent.Type, err))
			}
		}
		if count == 0 {
			return SkipCheck("no entities to check")
		}
		return PassCheck(fmt.Sprintf("all %d entities have valid content hashes", count))
	})

	r.Run("ecf_key_ordering", func() CheckOutcome {
		// Verify the spec's key-ordering rule directly against each wire
		// frame (ECF §4.2 / RFC 8949 §4.2.1: ascending bytewise order of
		// encoded key spans). Does NOT round-trip through Go's encoder —
		// that would conflate key order with value canonicalization and
		// privilege Go's encoder (GUIDE-CONFORMANCE §3.4). The offline
		// `conformance` corpus is the authority for cross-impl byte
		// agreement on values.
		for _, raw := range allRawFrames {
			if err := verifyCanonicalKeyOrder(raw); err != nil {
				return FailCheck("CBOR map key ordering violates ECF §4.2 canonical order: " + err.Error())
			}
		}
		return PassCheck("all map keys in canonical ECF order (checked against the §4.2 rule, not Go's encoder)")
	})

	r.Run("signature_signer_is_hash", func() CheckOutcome {
		env := client.AuthenticateResponseEnv
		found := false
		for _, ent := range env.Included {
			if ent.Type != types.TypeSignature {
				continue
			}
			found = true
			sigData, err := types.SignatureDataFromEntity(ent)
			if err != nil {
				return FailCheck("failed to decode signature entity: " + err.Error())
			}

			if sigData.Signer.IsZero() {
				return FailCheck("signature signer is zero/empty (should be identity entity hash)")
			}

			_, signerFound := env.FindIncluded(sigData.Signer)
			if !signerFound {
				return WarnCheck("signature signer hash does not match any included entity (may be valid if identity not included)")
			}

			return PassCheck("signature.signer is identity entity hash (byte string), not peer_id string")
		}

		if !found {
			return SkipCheck("no signature entities in connect response")
		}
		return SkipCheck("no signature entities in connect response")
	})

	r.Run("caveats_flat_struct", func() CheckOutcome {
		env := client.AuthenticateResponseEnv
		for _, ent := range env.Included {
			if ent.Type != types.TypeCapToken {
				continue
			}

			var rawMap map[string]cbor.RawMessage
			if err := ecf.Decode(ent.Data, &rawMap); err != nil {
				continue
			}

			caveatsRaw, hasCaveats := rawMap["delegation_caveats"]
			if !hasCaveats {
				return PassCheck("delegation_caveats not present (OK — optional field)")
			}

			if len(caveatsRaw) > 0 {
				majorType := caveatsRaw[0] >> 5
				if majorType == 4 {
					return FailCheck("delegation_caveats is CBOR array (should be CBOR map/flat struct)")
				}
				if majorType == 5 {
					return PassCheck("delegation_caveats is CBOR map (correct flat struct)")
				}
				return WarnCheck(fmt.Sprintf("delegation_caveats CBOR major type is %d (expected 5 for map)", majorType))
			}
		}

		return PassCheck("no capability token with delegation_caveats to check")
	})

	return r.Results()
}
