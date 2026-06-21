package quorum

import (
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// signer wraps a keypair with its identity entity for K-of-N tests.
type signer struct {
	kp     crypto.Keypair
	idHash hash.Hash
	idEnt  entity.Entity
}

func newSigner(t *testing.T, seedByte byte) signer {
	t.Helper()
	var seed [32]byte
	for i := range seed {
		seed[i] = seedByte
	}
	kp := crypto.FromSeed(seed)
	idEnt, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity: %v", err)
	}
	return signer{kp: kp, idHash: idEnt.ContentHash, idEnt: idEnt}
}

// bindIdentity stores the signer's system/peer entity in the content
// store so VerifySpecificSigner can resolve it.
func (f *fixture) bindIdentity(t *testing.T, s signer) {
	t.Helper()
	if _, err := f.cs.Put(s.idEnt); err != nil {
		t.Fatalf("cs.Put identity: %v", err)
	}
}

// signTargetAt produces a signature entity for target signed by s, and binds
// it at the V7 invariant pointer path /{s.peer_id}/system/signature/{target_hex}.
func (f *fixture) signTargetAt(t *testing.T, s signer, target hash.Hash) {
	t.Helper()
	sigBytes := s.kp.Sign(target.Bytes())
	sigData := types.SignatureData{
		Target:    target,
		Signer:    s.idHash,
		Algorithm: "ed25519",
		Signature: sigBytes,
	}
	ent, err := sigData.ToEntity()
	if err != nil {
		t.Fatalf("signature encode: %v", err)
	}
	if _, err := f.cs.Put(ent); err != nil {
		t.Fatalf("cs.Put sig: %v", err)
	}
	idData, _ := types.PeerDataFromEntity(s.idEnt)
	idPID := crypto.PeerIDFromEd25519PublicKey(idData.PublicKey) // v7.65 §1.5
	path := "/" + string(idPID) + "/system/signature/" + hex.EncodeToString(target.Bytes())
	f.li.Set(path, ent.ContentHash)
}

// TV-QF13 (§4.2.1): cache populated for quorum_id; cross-peer sync delivers
// a valid quorum-update; cache MUST be invalidated on validate-accept.
func TestTV_QF13_ValidatedArrivalInvalidates(t *testing.T) {
	f := newFixture()
	a, b, c := newSigner(t, 0x11), newSigner(t, 0x22), newSigner(t, 0x33)
	f.bindIdentity(t, a)
	f.bindIdentity(t, b)
	f.bindIdentity(t, c)

	signers := []hash.Hash{a.idHash, b.idHash, c.idHash}
	qID := f.putQuorum(t, signers, 2, types.SignerResolutionConcrete)

	// Populate cache.
	if _, _, err := f.q.CurrentSignerSet(qID); err != nil {
		t.Fatalf("populate: %v", err)
	}
	if _, _, ok := f.q.cache.get(qID); !ok {
		t.Fatal("cache not populated")
	}

	// Build a quorum-update attestation: rotate to (a, b) with threshold 2.
	props, _ := types.EncodeProperties(types.QuorumUpdateProperties{
		Kind:         types.KindQuorumUpdate,
		NewSigners:   []hash.Hash{a.idHash, b.idHash},
		NewThreshold: 2,
	})
	updateAtt := types.AttestationData{
		Attesting:  qID,
		Attested:   qID,
		Properties: props,
	}
	updateEnt, err := updateAtt.ToEntity()
	if err != nil {
		t.Fatalf("update encode: %v", err)
	}
	if _, err := f.cs.Put(updateEnt); err != nil {
		t.Fatalf("cs.Put update: %v", err)
	}

	// Sign K-of-N (2 of 3) over the update entity hash. Bind signatures at
	// V7 invariant paths.
	f.signTargetAt(t, a, updateEnt.ContentHash)
	f.signTargetAt(t, b, updateEnt.ContentHash)

	// Bind the update at its canonical event path; this is the moment the
	// hook fires.
	updatePath := QuorumEventPath(qID, updateEnt.ContentHash)
	f.li.Set(updatePath, updateEnt.ContentHash)

	// Simulate a sync arrival event for the update.
	evt := store.TreeChangeEvent{
		Path:       store.QualifyPath("p", updatePath),
		Hash:       updateEnt.ContentHash,
		ChangeType: store.ChangeCreated,
	}
	f.q.OnTreeChange(evt)

	if _, _, ok := f.q.cache.get(qID); ok {
		t.Fatal("TV-QF13: cache not invalidated after validated quorum-update arrival")
	}
}

// TV-QF14: a quorum-update that FAILS K-of-N (only 1 of 2 required signs)
// MUST NOT invalidate the cache.
func TestTV_QF14_FailedValidationDoesNotInvalidate(t *testing.T) {
	f := newFixture()
	a, b, c := newSigner(t, 0x11), newSigner(t, 0x22), newSigner(t, 0x33)
	f.bindIdentity(t, a)
	f.bindIdentity(t, b)
	f.bindIdentity(t, c)

	signers := []hash.Hash{a.idHash, b.idHash, c.idHash}
	qID := f.putQuorum(t, signers, 2, types.SignerResolutionConcrete)

	if _, _, err := f.q.CurrentSignerSet(qID); err != nil {
		t.Fatalf("populate: %v", err)
	}

	props, _ := types.EncodeProperties(types.QuorumUpdateProperties{
		Kind:         types.KindQuorumUpdate,
		NewSigners:   []hash.Hash{a.idHash},
		NewThreshold: 1,
	})
	updateAtt := types.AttestationData{
		Attesting:  qID,
		Attested:   qID,
		Properties: props,
	}
	updateEnt, err := updateAtt.ToEntity()
	if err != nil {
		t.Fatalf("update encode: %v", err)
	}
	if _, err := f.cs.Put(updateEnt); err != nil {
		t.Fatalf("cs.Put update: %v", err)
	}

	// Sign with ONLY one signer — quorum requires 2-of-3.
	f.signTargetAt(t, a, updateEnt.ContentHash)

	updatePath := QuorumEventPath(qID, updateEnt.ContentHash)
	f.li.Set(updatePath, updateEnt.ContentHash)

	evt := store.TreeChangeEvent{
		Path:       store.QualifyPath("p", updatePath),
		Hash:       updateEnt.ContentHash,
		ChangeType: store.ChangeCreated,
	}
	f.q.OnTreeChange(evt)

	if _, _, ok := f.q.cache.get(qID); !ok {
		t.Fatal("TV-QF14: cache wrongly invalidated by failed validation")
	}
}
