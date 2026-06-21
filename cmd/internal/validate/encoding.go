package validate

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catEncoding = "encoding"

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
		for _, raw := range allRawFrames {
			for i := 0; i < len(raw)-2; i++ {
				if raw[i] == 0x58 && raw[i+1] == 0x21 && i+2+33 <= len(raw) {
					algByte := raw[i+2]
					if algByte == hash.AlgorithmSHA256 {
						found = true
					} else {
						valid = false
					}
				}
			}
		}
		if found && valid {
			r.Store("hash_wire_ok", true)
			return PassCheck("hashes are 33-byte CBOR byte strings (0x5821 prefix)")
		}
		if !found {
			return WarnCheck("could not locate 33-byte hash byte strings in raw CBOR")
		}
		if valid {
			r.Store("hash_wire_ok", true)
			return PassCheck("hashes are 33-byte CBOR byte strings")
		}
		return FailCheck("hash wire format invalid")
	})

	r.Run("hash_algorithm_byte", func() CheckOutcome {
		if !r.OK("hash_wire_format") {
			return SkipCheck("skipped: no hashes found in raw bytes")
		}
		// If hash_wire_format passed with found=true, we stored hash_wire_ok.
		// If it was a warn (not found), we get here only if OK (warn is OK).
		// But warn means not found, so skip.
		if r.Load("hash_wire_ok") == nil {
			return SkipCheck("skipped: no hashes found in raw bytes")
		}
		// Re-scan for algorithm byte validation.
		allGood := true
		for _, raw := range allRawFrames {
			for i := 0; i < len(raw)-2; i++ {
				if raw[i] == 0x58 && raw[i+1] == 0x21 && i+2+33 <= len(raw) {
					if raw[i+2] != hash.AlgorithmSHA256 {
						allGood = false
					}
				}
			}
		}
		if allGood {
			return PassCheck("hash algorithm byte is 0x00 (SHA256)")
		}
		return FailCheck("hash algorithm byte is not 0x00 (SHA256)")
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
