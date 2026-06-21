// Command v767-phase2-pins derives the V7.67 Phase-2 matrix vector byte
// tuples (M2/M3/M6) from the seeds + cap-token convention pinned in
// architecture's SEEDS.md §2 (v767/SEEDS.md). Output is the §2.6 tuple
// shape — pubkeys, peer_ids, home-format peer content_hashes, root_cap
// CBOR + active-format content_hash, A's signature over the root_cap
// content_hash — printed as a JSON object per vector.
//
// Self-checks:
//   - MATRIX-M2-A reuses the Phase-1 KEY-TYPE-ED448-1 identity; this tool
//     asserts pubkey, peer_id, and SHA-256-form content_hash byte-equal
//     the SEEDS.md §1.1 lock (substrate sanity check).
//
// The cap-token entity is authored under the active negotiated format
// (SHA-256 for all three matrix vectors per SEEDS.md §2.2) by inlining
// the ECF-encode + NewEntityFormat path rather than going through
// CapabilityTokenData.ToEntity (which honors the process-global default
// only) — this lets M3/M6 produce SHA-256 cap-tokens while peer A's home
// format is SHA-384.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

type peerPin struct {
	KeyType         string `json:"key_type"`
	HomeFormat      byte   `json:"home_content_hash_format"`
	PubkeyHex       string `json:"pubkey_hex"`
	PeerIDBase58    string `json:"peer_id_base58"`
	PeerEntityCBOR  string `json:"peer_entity_data_cbor_hex"`
	ContentHashHex  string `json:"content_hash_hex"`
}

type matrixPin struct {
	ID                    string  `json:"id"`
	PeerA                 peerPin `json:"peer_a"`
	PeerB                 peerPin `json:"peer_b"`
	ActiveFormat          byte    `json:"negotiated_active_format"`
	RootCapDataCBORHex    string  `json:"root_cap_data_cbor_hex"`
	RootCapContentHashHex string  `json:"root_cap_content_hash_hex"`
	RootCapSignatureHex   string  `json:"root_cap_signature_hex"`
}

func main() {
	pins := []matrixPin{
		buildVector(
			"matrix.M2",
			seedEd448(0x42), 0x00, []byte{0x00}, "initiator",
			seedEd25519(0x43), 0x00, []byte{0x00},
			0x00,
		),
		buildVector(
			"matrix.M3",
			seedEd25519(0x44), 0x01, []byte{0x01, 0x00}, "initiator",
			seedEd25519(0x45), 0x00, []byte{0x00},
			0x00,
		),
		buildVector(
			"matrix.M6",
			seedEd448(0x46), 0x01, []byte{0x01, 0x00}, "initiator",
			seedEd25519(0x47), 0x00, []byte{0x00},
			0x00,
		),
	}

	// Phase-1 substrate sanity: M2-A must reproduce the SEEDS.md §1.1
	// KEY-TYPE-ED448-1 lock. If any of these diverge, the substrate is
	// off — fail loud rather than ship a wrong pin.
	const (
		ed448_42_pubkey     = "2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00"
		ed448_42_peer_id    = "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4"
		ed448_42_content_hash = "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748"
	)
	if got := pins[0].PeerA.PubkeyHex; got != ed448_42_pubkey {
		die("M2-A pubkey divergence: got %s, want %s (Phase-1 §1.1)", got, ed448_42_pubkey)
	}
	if got := pins[0].PeerA.PeerIDBase58; got != ed448_42_peer_id {
		die("M2-A peer_id divergence: got %s, want %s (Phase-1 §1.1)", got, ed448_42_peer_id)
	}
	if got := pins[0].PeerA.ContentHashHex; got != ed448_42_content_hash {
		die("M2-A content_hash divergence: got %s, want %s (Phase-1 §1.1)", got, ed448_42_content_hash)
	}

	out := map[string]any{
		"corpus":            "v7.67 Phase-2 matrix vectors",
		"seeds_source":      "core-protocol-domain/specs/test-vectors/v767/SEEDS.md §2",
		"active_format_all": "SHA-256 (per SEEDS.md §2.2)",
		"phase1_substrate_check": map[string]string{
			"vector": "KEY-TYPE-ED448-1 (reused as M2-A identity)",
			"status": "match: pubkey + peer_id + content_hash byte-equal §1.1 pins",
		},
		"vectors": pins,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		die("encode JSON: %v", err)
	}
}

// buildVector derives one matrix pin tuple from seeds and home-format
// declarations. activeFormat is the negotiated active per SEEDS.md §2.2
// (always 0x00 SHA-256 in the v1 corpus). hashFormatsA / hashFormatsB are
// recorded for completeness in the wider deliverable doc but not consumed
// here since active is pinned.
func buildVector(
	id string,
	keyA crypto.Keypair, homeA byte, hashFormatsA []byte, roleA string,
	keyB crypto.Keypair, homeB byte, hashFormatsB []byte,
	activeFormat byte,
) matrixPin {
	pinA := derivePeerPin(keyA, homeA)
	pinB := derivePeerPin(keyB, homeB)

	// Cap-token payload — SEEDS.md §2.3 verbatim.
	// grantee: B's home-format content_hash. granter: SingleSig over A's
	// home-format content_hash. Single root-cap grant {resources:
	// {include:["system/validate/matrix/*"]}}, parent=null, created_at=0,
	// expires_at=0.
	zero := uint64(0)
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Resources: types.CapabilityScope{
					Include: []string{"system/validate/matrix/*"},
				},
			},
		},
		Granter:   types.SingleSigGranter(mustHash(pinA.ContentHashHex)),
		Grantee:   mustHash(pinB.ContentHashHex),
		Parent:    nil,
		CreatedAt: 0,
		ExpiresAt: &zero,
	}

	dataCBOR, err := ecf.Encode(tokenData)
	if err != nil {
		die("%s: ecf encode cap-token: %v", id, err)
	}

	capEntity, err := entity.NewEntityFormat(activeFormat, types.TypeCapToken, cbor.RawMessage(dataCBOR))
	if err != nil {
		die("%s: NewEntityFormat: %v", id, err)
	}

	// A signs the cap-token's full wire content_hash (algorithm byte + digest).
	sig := keyA.Sign(capEntity.ContentHash.Bytes())

	return matrixPin{
		ID:                    id,
		PeerA:                 pinA,
		PeerB:                 pinB,
		ActiveFormat:          activeFormat,
		RootCapDataCBORHex:    hex.EncodeToString(dataCBOR),
		RootCapContentHashHex: hex.EncodeToString(capEntity.ContentHash.Bytes()),
		RootCapSignatureHex:   hex.EncodeToString(sig),
	}
}

func derivePeerPin(kp crypto.Keypair, homeFormat byte) peerPin {
	pubHex := hex.EncodeToString(kp.PublicKeyBytes())
	peerID, err := crypto.PeerIDFromPublicKey(kp.PublicKeyBytes(), kp.KeyType)
	if err != nil {
		die("PeerIDFromPublicKey: %v", err)
	}
	ent, err := kp.IdentityEntityFormat(homeFormat)
	if err != nil {
		die("IdentityEntityFormat: %v", err)
	}
	keyTypeStr := crypto.KeyTypeString(kp.KeyType)
	return peerPin{
		KeyType:        keyTypeStr,
		HomeFormat:     homeFormat,
		PubkeyHex:      pubHex,
		PeerIDBase58:   string(peerID),
		PeerEntityCBOR: hex.EncodeToString(ent.Data),
		ContentHashHex: hex.EncodeToString(ent.ContentHash.Bytes()),
	}
}

func seedEd25519(b byte) crypto.Keypair {
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = b
	}
	return crypto.FromSeed(seed)
}

func seedEd448(b byte) crypto.Keypair {
	var seed [ed448.SeedSize]byte
	for i := range seed {
		seed[i] = b
	}
	return crypto.Ed448FromSeed(seed)
}

func mustHash(hexStr string) hash.Hash {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		die("mustHash decode: %v", err)
	}
	h, err := hash.FromBytes(raw)
	if err != nil {
		die("mustHash FromBytes: %v", err)
	}
	return h
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "v767-phase2-pins: "+format+"\n", args...)
	os.Exit(1)
}
