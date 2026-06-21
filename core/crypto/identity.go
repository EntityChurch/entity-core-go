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
func (k Keypair) IdentityEntity() (entity.Entity, error) {
	return k.IdentityEntityFormat(entity.DefaultHashAlgorithm())
}

// IdentityEntityFormat creates a system/peer entity hashed under the
// given content_hash_format code. Used by the connect handler to author
// the identity entity under the connection's active format per V7 v7.69
// §4.5a (the local identity entity presented on a connection is hashed
// under the negotiated active format, not the peer-startup default).
func (k Keypair) IdentityEntityFormat(alg byte) (entity.Entity, error) {
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
	return entity.NewEntityFormat(alg, TypePeer, cbor.RawMessage(raw))
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
