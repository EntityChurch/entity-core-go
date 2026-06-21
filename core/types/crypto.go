package types

import (
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Crypto type constants.
//
// V7 §1.5 renamed the peer-keypair entity type from "system/identity" to
// "system/peer" (PROPOSAL-SYSTEM-PEER-RENAME-AND-SUBSTRATE-CLEANUP).
// EXTENSION-IDENTITY's system/identity/* namespace is unrelated and unchanged.
const (
	TypePeer      = "system/peer"
	TypeSignature = "system/signature"
)

// PeerData is the data payload for system/peer (V7 §1.5).
//
// v7.65 Amendment 1 (P×I primitive discipline): peer_id is NOT in the
// hashable basis. content_hash(system/peer) is a pure function of
// (public_key, key_type); cryptographic identity is invariant under
// wire-form peer_id choice.
//
// Composition with v7.64: v7.64-shape system/peer entities (carrying
// peer_id in data) coexist by content_hash. The CBOR decoder silently
// ignores the unknown peer_id field when decoding v7.64-shape entities
// into PeerData; the entity's content_hash is preserved (entity.Data
// is cbor.RawMessage — byte-fidelity intact). Cap chains referencing
// either shape verify against their entity's hash; chains MAY interleave.
type PeerData struct {
	PublicKey []byte `cbor:"public_key"`
	KeyType   string `cbor:"key_type"`
}

// ToEntity creates a system/peer entity.
func (d PeerData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeer, cbor.RawMessage(raw))
}

// KeyTypeByte returns the binary key_type byte for d.KeyType (the
// entity-data string form). The two-layer pin per v7.66 §2.2: entity-data
// string ("ed25519" / "ed448" / "experimental-test") ↔ binary varint byte
// (0x01 / 0x02 / 0xFE). Returns (0, false) for unrecognized strings;
// verify-side callers MUST treat unrecognized as failure (no silent fall
// through to a default algorithm).
func (d PeerData) KeyTypeByte() (byte, bool) {
	return crypto.KeyTypeByte(d.KeyType)
}

// PeerDataFromEntity decodes a system/peer entity's data.
func PeerDataFromEntity(e entity.Entity) (PeerData, error) {
	var d PeerData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return PeerData{}, err
	}
	return d, nil
}

// ComputePeerIdentityHash builds the canonical system/peer entity from
// (public_key, key_type) and returns its content_hash.
//
// V7 §1.5 / v7.65 Amendment 1+2: content_hash(system/peer) is a pure
// function of (public_key, key_type). The keyType parameter selects the
// entity-data string ("ed25519" / "ed448" / "experimental-test") that
// becomes part of the hashable basis.
//
// V7.67 Phase 2 unification: signature changed from
// (pub ed25519.PublicKey, hashType byte) to (pub []byte, keyType byte).
// The prior hashType parameter was unused (peer_id is not in the hashable
// basis per v7.65) and is dropped; the new keyType parameter feeds the
// entity-data string.
//
// The lowercase hex of this hash is the {peer_id_hex} path segment used
// in non-root path positions (system/peer/status, system/connection,
// system/role/.../assignment, etc.). Under v7.65 this hash is the
// canonical content_hash for the peer's cryptographic identity.
func ComputePeerIdentityHash(pub []byte, keyType byte) (hash.Hash, error) {
	ktString := crypto.KeyTypeString(keyType)
	if ktString == "" {
		return hash.Hash{}, fmt.Errorf("ComputePeerIdentityHash: unsupported key_type 0x%02x", keyType)
	}
	data := PeerData{
		PublicKey: pub,
		KeyType:   ktString,
	}
	ent, err := data.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("compute peer identity hash: %w", err)
	}
	return ent.ContentHash, nil
}

// ComputePeerIdentityHashFromPeerID is the local-only bridge from an
// identity-multihash PeerID (v7.64 default; hash_type=0x00) to the canonical
// `{peer_id_hex}` content_hash. Pure local computation; no out-of-band data
// required.
//
// Returns an error for SHA-256-form PeerIDs (hash_type=0x01) — those require
// the peer's public_key from a separate exchange (handshake, system/peer entity
// cache, registry). Callers handling both forms should fall through to
// ComputePeerIdentityHash with a cached public_key when this returns an error.
func ComputePeerIdentityHashFromPeerID(pid crypto.PeerID) (hash.Hash, error) {
	pub, keyType, ok := crypto.DerivePeerFromPeerID(pid)
	if !ok {
		return hash.Hash{}, fmt.Errorf("%w: peer_id %s is SHA-256 form; public_key required out-of-band",
			ecerrors.ErrAuthenticationFailed, pid)
	}
	return ComputePeerIdentityHash(pub, keyType)
}

// PeerIdentityHashHex returns the lowercase hex form of the canonical
// content_hash for use as a {peer_id_hex} path segment.
func PeerIdentityHashHex(h hash.Hash) string {
	return hex.EncodeToString(h.Bytes())
}

// InvariantSignaturePath returns the V7 §3.5 invariant pointer path at
// which a signature over `target`, signed by the peer whose peer_id is
// `signerPeerID`, MUST be discoverable for cross-peer chain transport
// and re-verification (V7 v7.44 SHOULD→MUST).
//
// This is the single source of that path. Every bind site (envelope
// ingest, extension handlers that locally mint transportable caps) and
// every resolver (capability chain-bundle collection, VerifyChain)
// MUST route through here so the bound and resolved paths cannot drift
// — a mismatch silently fails signature resolution, the exact bug
// class this convention exists to prevent.
func InvariantSignaturePath(signerPeerID string, target hash.Hash) string {
	return "/" + signerPeerID + "/system/signature/" + hex.EncodeToString(target.Bytes())
}

// LocalSignaturePath returns the peer-relative form of the V7 §3.5
// invariant-pointer signature path for a signature over `target` signed
// by the local peer: system/signature/{target_hex}. Used by handler
// register/unregister and bootstrap createHandlerGrants per v7.74 v0.4
// §3.4 convergence (grant signatures use the same invariant-pointer
// convention as every other signature in the address space).
func LocalSignaturePath(target hash.Hash) string {
	return "system/signature/" + hex.EncodeToString(target.Bytes())
}

// SignatureData is the data payload for system/signature.
type SignatureData struct {
	Target    hash.Hash `cbor:"target"`
	Signer    hash.Hash `cbor:"signer"`
	Algorithm string    `cbor:"algorithm"`
	Signature []byte    `cbor:"signature"`
}

// ToEntity creates a system/signature entity.
func (d SignatureData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeSignature, cbor.RawMessage(raw))
}

// SignatureDataFromEntity decodes a signature entity's data.
func SignatureDataFromEntity(e entity.Entity) (SignatureData, error) {
	var d SignatureData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SignatureData{}, err
	}
	return d, nil
}
