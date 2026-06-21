package attestation

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// FindSignatureBySigner returns the signature entity at the V7 invariant
// pointer path /{signer_peer_id}/system/signature/{target_hex}, or false
// if not bound. Signer is the content_hash of a system/peer entity;
// the peer_id is recovered from that entity. Per EXTENSION-ATTESTATION
// v1.1 §4.0 (SI-4: pseudocode + behavior inlined into the substrate spec).
//
// Returns null when no signature is bound at the path.
func FindSignatureBySigner(
	cs store.ContentStore,
	li store.LocationIndex,
	target hash.Hash,
	signer hash.Hash,
) (entity.Entity, bool) {
	idEnt, ok := cs.Get(signer)
	if !ok || idEnt.Type != types.TypePeer {
		return entity.Entity{}, false
	}
	idData, err := types.PeerDataFromEntity(idEnt)
	if err != nil {
		return entity.Entity{}, false
	}
	// v7.65 §1.5/§3.5: peer_id derives from (public_key, key_type) — canonical
	// form per crypto.CanonicalHashType.
	ktByte, ktOK := idData.KeyTypeByte()
	if !ktOK {
		return entity.Entity{}, false
	}
	pid, err := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte)
	if err != nil {
		return entity.Entity{}, false
	}
	path := types.InvariantSignaturePath(string(pid), target)
	sigHash, ok := li.Get(path)
	if !ok {
		return entity.Entity{}, false
	}
	sigEnt, ok := cs.Get(sigHash)
	if !ok || sigEnt.Type != types.TypeSignature {
		return entity.Entity{}, false
	}
	return sigEnt, true
}

// VerifyAttestationSignature validates that att is signed by att.Attesting
// (single-sig). Per §4.1: locates the signature via the V7 invariant pointer
// pattern, then verifies the signature over the attestation's content_hash
// bytes using the signer's declared key_type (v7.67 §3 crypto-agility).
//
// This is the default single-sig validator. Used when the attestation's
// expected topology is single-sig from att.Attesting (typical for sub-
// controller certs, agent certs, peer-to-peer claims). Consumers needing
// K-of-N call ext/quorum.VerifyKOfNSignatures; consumers needing dual-sig
// call VerifySpecificSigner per signer.
func VerifyAttestationSignature(
	cs store.ContentStore,
	li store.LocationIndex,
	attHash hash.Hash,
	att types.AttestationData,
) bool {
	return VerifySpecificSigner(cs, li, attHash, att.Attesting)
}

// VerifySpecificSigner verifies that attHash has a valid signature from
// expectedSigner specifically. Per §4.2: used by consumers for multi-sig
// topologies (dual-sig, etc.) without baking multi-sig semantics into the
// primitive. K-of-N callers (ext/quorum.VerifyKOfNSignatures) iterate the
// signer set and call this per constituent.
func VerifySpecificSigner(
	cs store.ContentStore,
	li store.LocationIndex,
	target hash.Hash,
	expectedSigner hash.Hash,
) bool {
	sigEnt, ok := FindSignatureBySigner(cs, li, target, expectedSigner)
	if !ok {
		return false
	}
	sig, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		return false
	}
	if sig.Target != target || sig.Signer != expectedSigner {
		return false
	}
	idEnt, ok := cs.Get(expectedSigner)
	if !ok || idEnt.Type != types.TypePeer {
		return false
	}
	idData, err := types.PeerDataFromEntity(idEnt)
	if err != nil {
		return false
	}
	ktByte, ktOK := idData.KeyTypeByte()
	if !ktOK {
		return false
	}
	if sig.Algorithm != "" && sig.Algorithm != idData.KeyType {
		return false
	}
	return crypto.Verify(ktByte, idData.PublicKey, target.Bytes(), sig.Signature)
}

// loadAttestation fetches a system/attestation entity by hash from the
// content store, returning the decoded AttestationData. Returns an error if
// the entity is not present or is not an attestation.
func loadAttestation(cs store.ContentStore, h hash.Hash) (types.AttestationData, error) {
	ent, ok := cs.Get(h)
	if !ok {
		return types.AttestationData{}, fmt.Errorf("attestation not found: %s", h)
	}
	if ent.Type != types.TypeAttestation {
		return types.AttestationData{}, fmt.Errorf("not a system/attestation: %s (got %s)", h, ent.Type)
	}
	return types.AttestationDataFromEntity(ent)
}
