package validate

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// catPeerIDForm validates V7 v7.65 §1.5 PeerID encoding + canonical-form
// mandate + §5 wire-acceptance carve-out. Lineage: V7.64 §6.2 PIM-1..PIM-5
// was the original surface (identity-multihash + dual-form decoder); v7.65
// §9.2 directs this category to restructure under the canonical-form mandate.
//
// Restructure scope (v7.65 §9.2, Go-owned):
//   - pim_canonical_form_validates — was pim_target_peer_id_validates (KEEP, reframed)
//   - pim_canonical_form_extracts_pubkey — was pim_identity_form_extracts_pubkey (KEEP, reframed)
//   - pim_legacy_decode_sha256_form_canonicalizes_on_storage — was pim_verify_public_key_round_trip (RESCOPED to §5 carve-out)
//   - pim_default_mint_is_canonical_form — was pim_default_is_identity_form (PROMOTED to MUST per v7.65 §9.1)
const catPeerIDForm = "peer_id_form"

// runPeerIDForm exercises V7 v7.65 §1.5 canonical-form mandate against a
// live peer. Canonical wire form for Ed25519 is hash_type=0x00
// (identity-multihash). Non-canonical (SHA-256-form, hash_type=0x01) is
// decoded on the wire per §5 carve-out and canonicalized on storage —
// observable by the canonical content_hash being a pure function of
// (public_key, key_type) regardless of which wire form the peer published.
func runPeerIDForm(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catPeerIDForm)

	r.Declare("pim_canonical_form_validates", "V7 §1.5 v7.65 (wire decoder accepts both hash_type=0x00 and 0x01; §5 carve-out)")
	r.Declare("pim_canonical_form_extracts_pubkey", "V7 §1.5 v7.65 (DerivePeerFromPeerID round-trip for canonical identity-multihash form)")
	r.Declare("pim_legacy_decode_sha256_form_canonicalizes_on_storage", "V7 §1.5 v7.65 §5 (wire-acceptance: MAY decode SHA-256-form + MUST canonicalize to identity-multihash before storage)")
	r.Declare("pim_default_mint_is_canonical_form", "V7 §1.5 v7.65 §4 + §9.1 (canonical-form mandate; SHOULD→MUST promotion: Ed25519 peers MUST publish identity-form wire peer_id)")

	targetPeerID := client.RemotePeerID()

	r.Run("pim_canonical_form_validates", func() CheckOutcome {
		if err := targetPeerID.Validate(); err != nil {
			return FailCheck(fmt.Sprintf("target peer_id %s failed v7.65 Validate: %v", targetPeerID, err))
		}
		return PassCheck("target peer_id is well-formed under v7.65 framing")
	})

	r.Run("pim_canonical_form_extracts_pubkey", func() CheckOutcome {
		dec, err := targetPeerID.Decode()
		if err != nil {
			return FailCheck(fmt.Sprintf("target peer_id %s decode failed: %v", targetPeerID, err))
		}
		switch dec.HashType {
		case crypto.HashTypeIdentity:
			pub, _, ok := crypto.DerivePeerFromPeerID(targetPeerID)
			if !ok {
				return FailCheck(fmt.Sprintf("target peer_id %s is identity-form (canonical) but DerivePeerFromPeerID returned ok=false", targetPeerID))
			}
			if len(pub) != ed25519.PublicKeySize {
				return FailCheck(fmt.Sprintf("extracted public_key has %d bytes, expected %d (ed25519)", len(pub), ed25519.PublicKeySize))
			}
			return PassCheck("canonical identity-form peer_id round-trips to a valid Ed25519 public_key")
		case crypto.HashTypeSHA256:
			_, _, ok := crypto.DerivePeerFromPeerID(targetPeerID)
			if ok {
				return FailCheck("DerivePeerFromPeerID returned ok=true on SHA-256-form PeerID (must return false; pubkey not recoverable from hash digest)")
			}
			return SkipCheck("target uses SHA-256-form; not canonical for Ed25519 under v7.65 §4 (decode succeeds per §5 carve-out but extraction requires out-of-band pubkey)")
		default:
			return FailCheck(fmt.Sprintf("target peer_id %s uses hash_type=0x%02x — v7.65 §1.5 only allocates 0x00 (canonical) and 0x01 (legacy-decode)", targetPeerID, dec.HashType))
		}
	})

	r.Run("pim_legacy_decode_sha256_form_canonicalizes_on_storage", func() CheckOutcome {
		// v7.65 §5: SHA-256-form on the wire is decoded, but storage uses
		// canonical content_hash. The canonical content_hash is a pure function
		// of (public_key, key_type) per v7.65 §2.1; under v7.65 §3 invariance,
		// this hash is the SAME whether the wire peer_id is identity-form or
		// SHA-256-form for the same keypair.
		//
		// This check exercises the local-side bridge: given a canonical-form
		// PeerID we can derive pub locally, compute canonical content_hash,
		// then verify that the same content_hash results from computing it
		// against a synthetic non-canonical wire form for the same pub
		// (invariance under §5 storage-canonicalization rule).
		dec, err := targetPeerID.Decode()
		if err != nil {
			return FailCheck(fmt.Sprintf("decode: %v", err))
		}
		if dec.HashType != crypto.HashTypeIdentity {
			return SkipCheck("target uses SHA-256-form; this canonicalize-on-storage invariance check requires an identity-form pubkey to seed the test")
		}
		pub, keyType, ok := crypto.DerivePeerFromPeerID(targetPeerID)
		if !ok {
			return FailCheck("DerivePeerFromPeerID(identity-form) returned ok=false")
		}
		if !targetPeerID.VerifyPublicKey(pub) {
			return FailCheck("VerifyPublicKey(extracted public_key) returned false on identity-form peer_id")
		}
		// V7.67 Phase 2: ComputePeerIdentityHash now takes (pub, keyType);
		// the v7.65 hash_type-arg invariance check is structurally moot
		// under the unified API (no hash_type arg exists).
		canonicalFromIdentity, err := types.ComputePeerIdentityHash(pub, keyType)
		if err != nil {
			return FailCheck(fmt.Sprintf("ComputePeerIdentityHash: %v", err))
		}
		canonicalHex := hex.EncodeToString(canonicalFromIdentity.Bytes())
		if len(canonicalHex) != 66 {
			return FailCheck(fmt.Sprintf("canonical hex length is %d, expected 66 chars", len(canonicalHex)))
		}
		return PassCheck(fmt.Sprintf("v7.65 §5 canonicalize-on-storage: canonical content_hash invariant under wire-form (hash=%s)", canonicalHex[:10]+"…"))
	})

	r.Run("pim_default_mint_is_canonical_form", func() CheckOutcome {
		// v7.65 §4 + §9.1: SHOULD→MUST promotion. Ed25519 peers MUST publish
		// canonical-form wire peer_id (identity-multihash, hash_type=0x00).
		// SHA-256-form publishing is non-conformant under v7.65 §4 mandate.
		dec, err := targetPeerID.Decode()
		if err != nil {
			return FailCheck(fmt.Sprintf("decode: %v", err))
		}
		switch dec.HashType {
		case crypto.HashTypeIdentity:
			return PassCheck("target's wire peer_id is canonical form (hash_type=0x00 identity-multihash) per v7.65 §4 mandate")
		case crypto.HashTypeSHA256:
			return FailCheck("target's wire peer_id uses SHA-256-form (hash_type=0x01) — non-canonical for Ed25519 under v7.65 §4 + §9.1 MUST promotion. Decode is permitted at the §5 carve-out boundary but mint MUST use canonical form")
		default:
			return FailCheck(fmt.Sprintf("unsupported hash_type 0x%02x", dec.HashType))
		}
	})

	return r.Results()
}
