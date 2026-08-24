package crypto

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// TypePeer names the V7 peer-keypair entity (V7 §1.5, renamed from
// "system/identity" per PROPOSAL-SYSTEM-PEER-RENAME-AND-SUBSTRATE-CLEANUP).
// Distinct from EXTENSION-IDENTITY's system/identity/*
// extension namespace.
const TypePeer = "system/peer"

// peerData is the data payload for a system/peer entity.
//
// v7.65 Amendment 1: peer_id is NOT in the hashable basis.
// content_hash(system/peer) = SHA256(ECF({type:"system/peer", data:{public_key, key_type}})).
// Cryptographic identity is invariant under wire-form peer_id choice.
//
// v7.66 §2.2 errata — two-layer key_type distinction. The KeyType field is
// the **entity-data string** form: a lowercase ASCII string (e.g., "ed25519",
// "experimental-test"). This is a different surface from the binary peer_id
// wire-format prefix (a varint byte, e.g., 0x01 for Ed25519, 0xFE for the
// v7.66 experimental stub) defined in V7 §1.5. The two share a name but
// encode separately and SHALL NOT be conflated. Future key_type allocations
// declare both their entity-data canonical string AND their binary prefix
// byte at allocation time.
type peerData struct {
	PublicKey []byte `cbor:"public_key"`
	KeyType   string `cbor:"key_type"`
}

// IdentityEntity creates a system/peer entity for this keypair. The method
// name is retained for API stability; the entity type is system/peer.
//
// v7.65 §1.5: the wire peer_id is presentation/routing only and does not
// appear in the entity's data. Callers needing the wire peer_id should
// invoke k.PeerID() separately.
//
// The key_type field is the lowercase ASCII string canonical form
// (v7.66 §2.2 errata) — distinct surface from the binary peer_id varint
// prefix in V7 §1.5.
// **The format is not a parameter.** Per ENTITY-CORE-PROTOCOL §4.5a item 1a
// (v7.77) a `system/peer` entity is authored at the ECFv1-SHA-256 floor
// UNCONDITIONALLY — on every connection, whatever the peer's home format and
// whatever the connection's negotiated active format. It is the single named
// exception to §1.2's "a peer's persistent state is uniformly its home
// format."
//
// This used to take an `alg` argument (`IdentityEntityFormat`), and the
// connect handler passed the negotiated active format. That is now the defect
// the ruling exists to prevent: §4.5a item 4 says one derivation function is
// the conformant shape and two is the defect, so the parameter is removed
// rather than defaulted — a format-taking variant is a place for the second
// function to grow back.
//
// What it buys: §1.8's "use the authored hash, MUST NOT recompute" stops being
// a per-connection coincidence and becomes an identity — the authored hash IS
// the floor-derived hash, the same bytes on every connection in the network
// rather than merely within one. So deriving an identity hash for a
// `{peer_id_hex}` path segment and comparing an authored identity hash for a
// §5.2 `grantee == author` equality are now one value by construction, which
// is what made the {peer_id_hex} pin unimplementable before it was ruled.
func (k Keypair) IdentityEntity() (entity.Entity, error) {
	ktString := KeyTypeString(k.KeyType)
	if ktString == "" {
		return entity.Entity{}, fmt.Errorf("IdentityEntity: unsupported key_type 0x%02x", k.KeyType)
	}
	data := peerData{
		PublicKey: k.PublicKeyBytes(),
		KeyType:   ktString,
	}
	raw, err := ecf.Encode(data)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntityFormat(hash.AlgorithmSHA256, TypePeer, cbor.RawMessage(raw))
}

// ExperimentalTestPeerEntity creates a system/peer entity for the v7.66 §4
// stub key_type 0xFE (entity-data string "experimental-test"). The pubkey
// MUST be exactly 64 bytes (v7.66 §4.2). The resulting content_hash is a
// pure function of (public_key, key_type=0xFE) — same P×I primitive
// discipline as Ed25519 (v7.65 §2). For the AGILITY-ENTITY-1 fixture,
// pubkey is 0xAA repeated 64 times.
//
// Test-only: no sign/verify semantics for 0xFE.
func ExperimentalTestPeerEntity(pub []byte) (entity.Entity, error) {
	if len(pub) != ExperimentalTestPublicKeyLen {
		return entity.Entity{}, fmt.Errorf("ExperimentalTestPeerEntity: public_key must be %d bytes (v7.66 §4.2), got %d",
			ExperimentalTestPublicKeyLen, len(pub))
	}
	// Defensive copy so caller can't mutate after.
	pubCopy := make([]byte, ExperimentalTestPublicKeyLen)
	copy(pubCopy, pub)
	data := peerData{
		PublicKey: pubCopy,
		KeyType:   KeyTypeStringExperimentalTest,
	}
	raw, err := ecf.Encode(data)
	if err != nil {
		return entity.Entity{}, err
	}
	// v7.66 §7.2 AGILITY-ENTITY-1 corpus is pinned cross-impl under SHA-256.
	// Author this fixture under SHA-256 explicitly so the pin holds regardless
	// of the process-global default (a peer running --hash-type sha384 still
	// produces the same corpus hash for this fixture).
	return entity.NewEntityFormat(hash.AlgorithmSHA256, TypePeer, cbor.RawMessage(raw))
}
