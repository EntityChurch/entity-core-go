package quorum

import (
	"context"
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TV-Q-V16a (per PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md §3.12):
// Quorum Q with quorum-update u1 (not_before=t1, signers=S1) and u2
// (not_before=t2 > t1, signers=S2; supersedes u1). At as_of=t1.5,
// u2's not_before is in the future so u2 is not effective; u1 is live;
// CurrentSignerSetAt returns S1.
func TestTV_Q_V16a_HistoricalAtIntermediateTimestamp(t *testing.T) {
	f := newFixture()

	// Constituents: three signers, threshold 2.
	a, b, c := newSigner(t, 0x11), newSigner(t, 0x22), newSigner(t, 0x33)
	f.bindIdentity(t, a)
	f.bindIdentity(t, b)
	f.bindIdentity(t, c)
	original := []hash.Hash{a.idHash, b.idHash, c.idHash}
	qID := f.putQuorum(t, original, 2, types.SignerResolutionConcrete)

	// u1: at t1, rotate to {a, b} threshold 2.
	t1 := uint64(1_000_000)
	s1 := []hash.Hash{a.idHash, b.idHash}
	hU1 := f.publishQuorumUpdate(t, qID, s1, 2, nil, t1)

	// u2: at t2 > t1, rotate to {a, c} threshold 2.
	t2 := uint64(2_000_000)
	s2 := []hash.Hash{a.idHash, c.idHash}
	f.publishQuorumUpdate(t, qID, s2, 2, &hU1, t2)

	// At as_of=1.5e6 (t1 < as_of < t2): u2's not_before is t2; u2 is not
	// yet effective. u1 should be live; signer set = S1.
	asOf := uint64(1_500_000)
	got, threshold, err := f.q.CurrentSignerSetAt(qID, asOf)
	if err != nil {
		t.Fatalf("CurrentSignerSetAt: %v", err)
	}
	if threshold != 2 {
		t.Errorf("threshold = %d, want 2", threshold)
	}
	if !sameSigners(got, s1) {
		t.Errorf("signers at as_of=%d = %v, want S1 %v", asOf, got, s1)
	}
}

// TV-Q-V16b: at as_of=t2+1, u2 is live (not_before reached, no live
// descendant); CurrentSignerSetAt returns S2.
func TestTV_Q_V16b_HistoricalAfterSuccessor(t *testing.T) {
	f := newFixture()

	a, b, c := newSigner(t, 0x11), newSigner(t, 0x22), newSigner(t, 0x33)
	f.bindIdentity(t, a)
	f.bindIdentity(t, b)
	f.bindIdentity(t, c)
	original := []hash.Hash{a.idHash, b.idHash, c.idHash}
	qID := f.putQuorum(t, original, 2, types.SignerResolutionConcrete)

	t1 := uint64(1_000_000)
	s1 := []hash.Hash{a.idHash, b.idHash}
	hU1 := f.publishQuorumUpdate(t, qID, s1, 2, nil, t1)

	t2 := uint64(2_000_000)
	s2 := []hash.Hash{a.idHash, c.idHash}
	f.publishQuorumUpdate(t, qID, s2, 2, &hU1, t2)

	asOf := t2 + 1
	got, _, err := f.q.CurrentSignerSetAt(qID, asOf)
	if err != nil {
		t.Fatalf("CurrentSignerSetAt: %v", err)
	}
	if !sameSigners(got, s2) {
		t.Errorf("signers at as_of=%d = %v, want S2 %v", asOf, got, s2)
	}
}

// TV-Q-V16c: identity-resolved mode with controller rotation. The
// resolver returns the controller live at as_of, not the current
// controller. We exercise this by registering a stub resolver that
// returns different peers based on as_of (the real identity-resolved
// resolver would walk the cert chain at as_of; here we simulate the
// behavior to test the wiring).
func TestTV_Q_V16c_IdentityResolvedHistorical(t *testing.T) {
	f := newFixture()

	signers := []hash.Hash{makeFakeHash(0x01)}
	qID := f.putQuorum(t, signers, 1, types.SignerResolutionIdentityResolved)

	// Stub resolver: before t_rot, returns "old controller" hash;
	// at-or-after t_rot, returns "current controller" hash.
	tRot := uint64(5_000_000)
	oldController := makeFakeHash(0xAA)
	newController := makeFakeHash(0xBB)
	f.q.RegisterResolver(types.SignerResolutionIdentityResolved,
		func(_ context.Context, _ hash.Hash, _ store.ContentStore, _ store.LocationIndex, asOf uint64) (hash.Hash, error) {
			return resolveByTime(asOf, tRot, oldController, newController), nil
		})

	// Before rotation: returns old controller.
	asOfBefore := tRot - 1
	got, _, err := f.q.CurrentSignerSetAt(qID, asOfBefore)
	if err != nil {
		t.Fatalf("before rotation: %v", err)
	}
	if got[0] != oldController {
		t.Errorf("before rotation: signers[0] = %s, want oldController %s", got[0], oldController)
	}

	// After rotation: returns new controller.
	asOfAfter := tRot + 1
	got, _, err = f.q.CurrentSignerSetAt(qID, asOfAfter)
	if err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if got[0] != newController {
		t.Errorf("after rotation: signers[0] = %s, want newController %s", got[0], newController)
	}
}

// publishQuorumUpdate writes a quorum-update attestation at not_before=nb
// for the given (newSigners, newThreshold, supersedes), signs it K-of-N
// using the original signer set (or the predecessor's snapshot if
// supersedes is set), and binds it at the canonical event path. Returns
// the new attestation hash.
//
// For these tests we sign with whichever signers are needed using the
// known keypairs in the fixture's identity bindings — for simplicity we
// sign with all three (a, b, c) so any K-of-2 dispatch works.
func (f *fixture) publishQuorumUpdate(
	t *testing.T,
	quorumID hash.Hash,
	newSigners []hash.Hash,
	newThreshold uint64,
	supersedes *hash.Hash,
	notBefore uint64,
) hash.Hash {
	t.Helper()
	props, _ := types.EncodeProperties(types.QuorumUpdateProperties{
		Kind:         types.KindQuorumUpdate,
		NewSigners:   newSigners,
		NewThreshold: newThreshold,
	})
	att := types.AttestationData{
		Attesting:  quorumID,
		Attested:   quorumID,
		Properties: props,
		Supersedes: supersedes,
		NotBefore:  &notBefore,
	}
	ent, err := att.ToEntity()
	if err != nil {
		t.Fatalf("encode update: %v", err)
	}
	if _, err := f.cs.Put(ent); err != nil {
		t.Fatalf("cs.Put update: %v", err)
	}
	// Bind at the canonical event path.
	f.li.Set(QuorumEventPath(quorumID, ent.ContentHash), ent.ContentHash)
	// Add to attestation index.
	f.att.Index().Add(ent.ContentHash, att)
	return ent.ContentHash
}

// resolveByTime is a tiny helper for TV-Q-V16c.
func resolveByTime(asOf, threshold uint64, before, after hash.Hash) hash.Hash {
	if asOf < threshold {
		return before
	}
	return after
}

// sameSigners reports whether two slices contain the same hashes in the
// same order.
func sameSigners(a, b []hash.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// signTargetWithKey produces a signature for `target` by `s` and binds it
// at the V7 invariant pointer path. Used by tests that need K-of-N
// validation to actually pass.
func (f *fixture) signTargetWithKey(t *testing.T, s signer, target hash.Hash) {
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
