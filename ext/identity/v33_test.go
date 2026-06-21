package identity

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// fixture mirrors the substrate test fixtures with a content store, a
// location index, and direct attestation puts. We don't need the full
// handler stack for unit-testing IdentityConfersFunction.
type ifixture struct {
	cs *store.MemoryContentStore
	li *store.MemoryLocationIndex
}

func newIFixture() *ifixture {
	return &ifixture{
		cs: store.NewMemoryContentStore(),
		li: store.NewMemoryLocationIndex(),
	}
}

func makeFakeHash(b byte) hash.Hash {
	var raw [33]byte
	raw[0] = hash.AlgorithmSHA256
	raw[1] = b
	h, err := hash.FromBytes(raw[:])
	if err != nil {
		panic(err)
	}
	return h
}

func (f *ifixture) putAttestation(t *testing.T, a types.AttestationData) hash.Hash {
	t.Helper()
	ent, err := a.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if _, err := f.cs.Put(ent); err != nil {
		t.Fatalf("cs.Put: %v", err)
	}
	return ent.ContentHash
}

// makeIdentityCert builds an identity-cert AttestationData with the given
// attesting / attested / function / mode.
func makeIdentityCert(attesting, attested hash.Hash, function, mode string) types.AttestationData {
	props, _ := types.EncodeProperties(types.IdentityCertProperties{
		Kind:     types.KindIdentityCert,
		Function: function,
		Mode:     mode,
	})
	return types.AttestationData{
		Attesting:  attesting,
		Attested:   attested,
		Properties: props,
	}
}

// makeRotationHandoff builds an identity-rotation-handoff AttestationData
// with the given target_cert.
func makeRotationHandoff(oldKey, newKey, targetCert hash.Hash) types.AttestationData {
	props, _ := types.EncodeProperties(types.IdentityRotationHandoffProperties{
		Kind:       types.KindIdentityRotationHandoff,
		TargetCert: targetCert,
	})
	return types.AttestationData{
		Attesting:  oldKey,
		Attested:   newKey,
		Properties: props,
	}
}

// makeRotationRecovery builds an identity-rotation-recovery
// AttestationData with the given target_cert.
func makeRotationRecovery(quorumID, newKey, targetCert hash.Hash) types.AttestationData {
	props, _ := types.EncodeProperties(types.IdentityRotationRecoveryProperties{
		Kind:       types.KindIdentityRotationRecovery,
		TargetCert: targetCert,
	})
	return types.AttestationData{
		Attesting:  quorumID,
		Attested:   newKey,
		Properties: props,
	}
}

// makeRetirement builds an identity-retirement AttestationData with the
// given target_cert.
func makeRetirement(quorumID, attested, targetCert hash.Hash) types.AttestationData {
	props, _ := types.EncodeProperties(types.IdentityRetirementProperties{
		Kind:       types.KindIdentityRetirement,
		TargetCert: targetCert,
	})
	return types.AttestationData{
		Attesting:  quorumID,
		Attested:   attested,
		Properties: props,
	}
}

// TV-I-V13a (per PROPOSAL §3.9, SI-13): rotation-handoff inherits the
// function from its target_cert. Chain-walk predicates filtering by
// function include handoffs as link types.
//
// Setup: identity-cert(function=controller) → rotation-handoff(target=cert).
// IdentityConfersFunction(handoff, "controller") returns true.
func TestTV_I_V13a_HandoffInheritsFunction(t *testing.T) {
	f := newIFixture()
	quorumID := makeFakeHash(0x10)
	oldKey := makeFakeHash(0x20)
	newKey := makeFakeHash(0x21)

	cert := makeIdentityCert(quorumID, oldKey, types.FunctionController, types.ModePublic)
	hCert := f.putAttestation(t, cert)

	handoff := makeRotationHandoff(oldKey, newKey, hCert)
	_ = f.putAttestation(t, handoff)

	if !IdentityConfersFunction(f.cs, handoff, types.FunctionController) {
		t.Errorf("TV-I-V13a: handoff expected to confer controller (inherited from target_cert)")
	}
	if IdentityConfersFunction(f.cs, handoff, types.FunctionAgent) {
		t.Errorf("TV-I-V13a: handoff should NOT confer agent (target was controller)")
	}

	// Recovery should behave the same way (function inherited).
	recovery := makeRotationRecovery(quorumID, newKey, hCert)
	if !IdentityConfersFunction(f.cs, recovery, types.FunctionController) {
		t.Errorf("TV-I-V13a: recovery expected to confer controller (inherited from target_cert)")
	}
}

// TV-I-V13b (per PROPOSAL §3.9, SI-13): retirement does NOT confer the
// function; the chain ends here as dead.
//
// Setup: identity-cert(function=controller) → retirement(target=cert).
// IdentityConfersFunction(retirement, "controller") returns false.
func TestTV_I_V13b_RetirementTerminatesChain(t *testing.T) {
	f := newIFixture()
	quorumID := makeFakeHash(0x10)
	attested := makeFakeHash(0x20)

	cert := makeIdentityCert(quorumID, attested, types.FunctionController, types.ModePublic)
	hCert := f.putAttestation(t, cert)

	retirement := makeRetirement(quorumID, attested, hCert)
	_ = f.putAttestation(t, retirement)

	if IdentityConfersFunction(f.cs, retirement, types.FunctionController) {
		t.Errorf("TV-I-V13b: retirement should NOT confer the function (chain terminates)")
	}
}

// TV-I-V13c: handoff-of-handoff recursion. The function inheritance
// recurses through nested handoffs to find the original cert's function.
func TestTV_I_V13c_HandoffOfHandoff(t *testing.T) {
	f := newIFixture()
	quorumID := makeFakeHash(0x10)
	keyA := makeFakeHash(0x20)
	keyB := makeFakeHash(0x21)
	keyC := makeFakeHash(0x22)

	cert := makeIdentityCert(quorumID, keyA, types.FunctionAgent, types.ModeInternal)
	hCert := f.putAttestation(t, cert)

	handoffAB := makeRotationHandoff(keyA, keyB, hCert)
	hHandoffAB := f.putAttestation(t, handoffAB)

	// Second handoff: keyB → keyC; target=hHandoffAB (handoff-of-handoff).
	handoffBC := makeRotationHandoff(keyB, keyC, hHandoffAB)
	_ = f.putAttestation(t, handoffBC)

	if !IdentityConfersFunction(f.cs, handoffBC, types.FunctionAgent) {
		t.Errorf("TV-I-V13c: handoff-of-handoff expected to confer agent (recursive inheritance)")
	}
}
