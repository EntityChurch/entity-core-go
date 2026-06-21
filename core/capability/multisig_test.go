package capability

import (
	"errors"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Test vectors from PROPOSAL-MULTISIG-CORE-PRIMITIVE.md §12. Each test case
// references the table row it implements.

// signer is a (keypair, identity entity) pair used for multi-sig construction.
type signer struct {
	kp       crypto.Keypair
	identity entity.Entity
}

func newSigner(t *testing.T) signer {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	id, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity: %v", err)
	}
	return signer{kp: kp, identity: id}
}

// signerHashes returns the identity content hashes of a slice of signers.
func signerHashes(signers []signer) []hash.Hash {
	out := make([]hash.Hash, len(signers))
	for i, s := range signers {
		out[i] = s.identity.ContentHash
	}
	return out
}

// buildMultiSigRoot constructs a multi-sig root cap entity from signers and
// threshold, populating an `included` map with the cap, identity entities,
// and signatures from the given subset of `signWith`.
func buildMultiSigRoot(
	t *testing.T,
	signers []signer,
	threshold uint64,
	signWith []signer,
	grantee hash.Hash,
) (entity.Entity, map[hash.Hash]entity.Entity) {
	t.Helper()
	mg := types.MultiGranter{
		Signers:   signerHashes(signers),
		Threshold: threshold,
	}
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   grantee,
		CreatedAt: 1000,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatalf("cap to entity: %v", err)
	}
	included := map[hash.Hash]entity.Entity{
		capEntity.ContentHash: capEntity,
	}
	for _, s := range signers {
		included[s.identity.ContentHash] = s.identity
	}
	for _, s := range signWith {
		sig := s.kp.Sign(capEntity.ContentHash.Bytes())
		sigData := types.SignatureData{
			Target:    capEntity.ContentHash,
			Signer:    s.identity.ContentHash,
			Algorithm: "ed25519",
			Signature: sig,
		}
		sigEntity, err := sigData.ToEntity()
		if err != nil {
			t.Fatalf("sig to entity: %v", err)
		}
		included[sigEntity.ContentHash] = sigEntity
	}
	return capEntity, included
}

// signSingle adds a single-sig signature to included for a given target and signer.
func signSingle(t *testing.T, target hash.Hash, s signer, included map[hash.Hash]entity.Entity) {
	t.Helper()
	sig := s.kp.Sign(target.Bytes())
	sigData := types.SignatureData{
		Target:    target,
		Signer:    s.identity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		t.Fatalf("sig to entity: %v", err)
	}
	included[sigEntity.ContentHash] = sigEntity
}

// --- Vector 1: Single-sig regression (unchanged from today). ---
// Already covered by TestVerifyChainRootCapability in capability_test.go.

// --- Vector 2: 2-of-3 with 2 valid signatures, local in signers and signed → ALLOW. ---
func TestMultiSig_V2_TwoOfThree_BothSigned_LocalSigner_ALLOW(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	if err := VerifyChain(capEnt, included, a.kp.PeerID()); err != nil {
		t.Fatalf("expected ALLOW; got %v", err)
	}
}

// --- Vector 3: 2-of-3 with 1 valid signature → DENY (below threshold). ---
func TestMultiSig_V3_TwoOfThree_OneSig_DENY(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	err := VerifyChain(capEnt, included, a.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY for below-threshold; got success")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Fatalf("expected ErrCapabilityDenied; got %v", err)
	}
}

// --- Vector 4: 2-of-3 with 3 valid signatures (above threshold) → ALLOW. ---
func TestMultiSig_V4_TwoOfThree_ThreeSigs_ALLOW(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b, c}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	if err := VerifyChain(capEnt, included, a.kp.PeerID()); err != nil {
		t.Fatalf("expected ALLOW; got %v", err)
	}
}

// --- Vector 5: multi-sig cap with non-null parent → DENY at content validation. ---
func TestMultiSig_V5_NonNullParent_DENY(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	parentHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	parentHash.Digest[0] = 0x42
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.MultiSigGranter(types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 2}),
		Grantee:   newSigner(t).identity.ContentHash,
		Parent:    &parentHash, // M3 violation
		CreatedAt: 1000,
	}
	if err := capData.ValidateStructure(); err == nil {
		t.Fatal("expected ValidateStructure to reject non-null parent on multi-sig")
	}
}

// --- Vector 6: K=1 → DENY at content validation. ---
func TestMultiSig_V6_KEqualsOne_DENY(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 1}
	if err := mg.Validate(); err == nil {
		t.Fatal("expected K=1 rejection")
	}
}

// --- Vector 7: K=0 → DENY. ---
func TestMultiSig_V7_KEqualsZero_DENY(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 0}
	if err := mg.Validate(); err == nil {
		t.Fatal("expected K=0 rejection")
	}
}

// --- Vector 8: K > N → DENY. ---
func TestMultiSig_V8_KGreaterThanN_DENY(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 3}
	if err := mg.Validate(); err == nil {
		t.Fatal("expected K>N rejection")
	}
}

// --- Vector 9: duplicate signers → DENY. ---
func TestMultiSig_V9_DuplicateSigners_DENY(t *testing.T) {
	a := newSigner(t)
	mg := types.MultiGranter{Signers: []hash.Hash{a.identity.ContentHash, a.identity.ContentHash}, Threshold: 2}
	if err := mg.Validate(); err == nil {
		t.Fatal("expected duplicate-signer rejection")
	}
}

// --- Vector 10: N=1 → DENY (use single-sig instead). ---
func TestMultiSig_V10_NEqualsOne_DENY(t *testing.T) {
	a := newSigner(t)
	mg := types.MultiGranter{Signers: []hash.Hash{a.identity.ContentHash}, Threshold: 1}
	if err := mg.Validate(); err == nil {
		t.Fatal("expected N=1 rejection")
	}
}

// --- Vector 11: 2-of-3, local peer NOT in signer set → DENY at Site 3. ---
func TestMultiSig_V11_LocalNotInSigners_DENY(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	bystander := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity
	included[bystander.identity.ContentHash] = bystander.identity

	err := VerifyChain(capEnt, included, bystander.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY when local peer not in signers")
	}
}

// --- Vector 12: 2-of-3, local in signers but didn't sign → DENY at Site 3. ---
func TestMultiSig_V12_LocalInSignersDidNotSign_DENY(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	// c is in signers but does not sign; b and a sign.
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	err := VerifyChain(capEnt, included, c.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY: local in signers but did not sign")
	}
}

// --- Vector 13: 2-of-3, local in signers, K=2 signed including local → ALLOW. ---
func TestMultiSig_V13_LocalSignedAndThresholdMet_ALLOW(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{b, c}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	if err := VerifyChain(capEnt, included, c.kp.PeerID()); err != nil {
		t.Fatalf("expected ALLOW; got %v", err)
	}
}

// --- Vector 14: K=N (3-of-3) all signed → ALLOW. ---
func TestMultiSig_V14_KEqualsN_AllSigned_ALLOW(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 3, []signer{a, b, c}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	if err := VerifyChain(capEnt, included, a.kp.PeerID()); err != nil {
		t.Fatalf("expected ALLOW; got %v", err)
	}
}

// --- Vector 15: CheckCreatorAuthority — writer matches single-sig granter → found=true. ---
func TestMultiSig_V15_CheckCreator_SingleSig_ALLOW(t *testing.T) {
	local := newSigner(t)
	grantee := newSigner(t)

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"put"}}},
		},
		Granter:   types.SingleSigGranter(local.identity.ContentHash),
		Grantee:   grantee.identity.ContentHash,
		CreatedAt: 1000,
	}
	capEnt, _ := capData.ToEntity()
	included := map[hash.Hash]entity.Entity{
		capEnt.ContentHash:           capEnt,
		local.identity.ContentHash:   local.identity,
		grantee.identity.ContentHash: grantee.identity,
	}

	found, _, err := CheckCreatorAuthority(capEnt, local.identity.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !found {
		t.Fatal("expected found=true for single-sig writer match")
	}
}

// --- Vector 16: CheckCreatorAuthority — writer in multi-sig signers AND signed → found=true. ---
func TestMultiSig_V16_CheckCreator_MultiSigSigned_ALLOW(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	found, _, err := CheckCreatorAuthority(capEnt, a.identity.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !found {
		t.Fatal("expected found=true for multi-sig writer who signed")
	}
}

// --- Vector 17: CheckCreatorAuthority — writer in signers but didn't sign → found=false. ---
func TestMultiSig_V17_CheckCreator_MultiSigNotSigned_DENY(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	// c is in signers but did not sign.
	found, _, err := CheckCreatorAuthority(capEnt, c.identity.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if found {
		t.Fatal("expected found=false for signer who didn't sign")
	}
}

// --- Vector 18a: CBOR-encoded granter as 33-byte bstr → decode as single-sig. ---
func TestMultiSig_V18a_BstrDecode_Single(t *testing.T) {
	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	for i := 0; i < hash.SHA256DigestSize; i++ {
		h.Digest[i] = byte(i)
	}
	encoded, err := types.SingleSigGranter(h).MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(encoded) == 0 || (encoded[0]>>5)&0x07 != 2 {
		t.Fatalf("expected CBOR major type 2 (bstr); got first byte 0x%02x", encoded[0])
	}
	var got types.Granter
	if err := got.UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.IsSingle() {
		t.Fatal("expected single-sig variant after decode")
	}
	gotHash, _ := got.SingleHash()
	if gotHash != h {
		t.Fatalf("hash mismatch: got %s want %s", gotHash, h)
	}
}

// --- Vector 18b: CBOR-encoded granter as map → decode as multi-sig. ---
func TestMultiSig_V18b_MapDecode_Multi(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 2}
	encoded, err := types.MultiSigGranter(mg).MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(encoded) == 0 || (encoded[0]>>5)&0x07 != 5 {
		t.Fatalf("expected CBOR major type 5 (map); got first byte 0x%02x", encoded[0])
	}
	var got types.Granter
	if err := got.UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.IsMulti() {
		t.Fatal("expected multi-sig variant after decode")
	}
}

// --- Vector 18c: CBOR-encoded granter with a tag → DENY at decode. ---
func TestMultiSig_V18c_TagDecode_DENY(t *testing.T) {
	// A CBOR tag is major type 6. Construct minimum encoding: tag 0xC0 (date)
	// followed by a bstr; we just need first byte to be tag-prefixed.
	tagged := []byte{0xC2, 0x40} // tag(2) followed by bstr of length 0
	var got types.Granter
	err := got.UnmarshalCBOR(tagged)
	if err == nil {
		t.Fatal("expected decode failure on CBOR-tagged granter")
	}
	if !strings.Contains(err.Error(), "tag") {
		t.Fatalf("expected error to mention tag rejection; got %v", err)
	}
}

// --- Vector 19: multi-sig root + downstream single-sig child; child grants ⊆ root → ALLOW. ---
func TestMultiSig_V19_MultiSigRootWithSingleSigChild_ALLOW(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	delegate := newSigner(t)
	finalGrantee := newSigner(t)

	rootCap, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b}, delegate.identity.ContentHash)
	included[delegate.identity.ContentHash] = delegate.identity
	included[finalGrantee.identity.ContentHash] = finalGrantee.identity

	// §PR-8: the root is multi-sig (granter resolves to localPeerID per the
	// Site-3 anchor); the child is single-sig from `delegate` (granter
	// resolves to delegate's peer_id). Each cap's resource patterns
	// canonicalize against ITS granter — so peer-relative "system/tree/*"
	// would canonicalize to /{local}/... on the root and /{delegate}/...
	// on the child, breaking attenuation across the granter boundary. Use
	// the explicit local-namespace form so the chain's authority stays in
	// the multi-sig root's namespace at every link.
	localTreeAll := "/" + string(a.kp.PeerID()) + "/system/tree/*"
	// Child: single-sig from delegate to finalGrantee, narrower grants.
	childData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"system/tree"}}, Resources: types.CapabilityScope{Include: []string{localTreeAll}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.SingleSigGranter(delegate.identity.ContentHash),
		Grantee:   finalGrantee.identity.ContentHash,
		Parent:    &rootCap.ContentHash,
		CreatedAt: 1100,
	}
	childEnt, err := childData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	included[childEnt.ContentHash] = childEnt
	signSingle(t, childEnt.ContentHash, delegate, included)

	// Site 3 still expects local peer to be in root signers and signed.
	if err := VerifyChain(childEnt, included, a.kp.PeerID()); err != nil {
		t.Fatalf("expected ALLOW for multi-sig-rooted single-sig child; got %v", err)
	}
}

// --- Vector 19b: multi-sig root + 3-link single-sig delegation; depth-4 attenuation. ---
func TestMultiSig_V19b_MultiSigRootDepthFour_ALLOW(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	d1 := newSigner(t)
	d2 := newSigner(t)
	d3 := newSigner(t)

	rootCap, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b}, d1.identity.ContentHash)
	included[d1.identity.ContentHash] = d1.identity
	included[d2.identity.ContentHash] = d2.identity
	included[d3.identity.ContentHash] = d3.identity

	// §PR-8: each link canonicalizes resources against its OWN granter
	// (d1, d2, d3 — all distinct); the explicit local-namespace form is
	// the only way to keep all three links in the multi-sig root's namespace.
	localTreeAll := "/" + string(a.kp.PeerID()) + "/system/tree/*"
	// link 2: d1 → d2
	link2 := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"system/tree"}}, Resources: types.CapabilityScope{Include: []string{localTreeAll}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.SingleSigGranter(d1.identity.ContentHash),
		Grantee:   d2.identity.ContentHash,
		Parent:    &rootCap.ContentHash,
		CreatedAt: 1100,
	}
	link2Ent, _ := link2.ToEntity()
	included[link2Ent.ContentHash] = link2Ent
	signSingle(t, link2Ent.ContentHash, d1, included)

	// link 3: d2 → d3
	link3 := types.CapabilityTokenData{
		Grants:    link2.Grants,
		Granter:   types.SingleSigGranter(d2.identity.ContentHash),
		Grantee:   d3.identity.ContentHash,
		Parent:    &link2Ent.ContentHash,
		CreatedAt: 1200,
	}
	link3Ent, _ := link3.ToEntity()
	included[link3Ent.ContentHash] = link3Ent
	signSingle(t, link3Ent.ContentHash, d2, included)

	// link 4 (leaf): d3 → final
	final := newSigner(t)
	included[final.identity.ContentHash] = final.identity
	link4 := types.CapabilityTokenData{
		Grants:    link2.Grants,
		Granter:   types.SingleSigGranter(d3.identity.ContentHash),
		Grantee:   final.identity.ContentHash,
		Parent:    &link3Ent.ContentHash,
		CreatedAt: 1300,
	}
	link4Ent, _ := link4.ToEntity()
	included[link4Ent.ContentHash] = link4Ent
	signSingle(t, link4Ent.ContentHash, d3, included)

	if err := VerifyChain(link4Ent, included, a.kp.PeerID()); err != nil {
		t.Fatalf("expected ALLOW for depth-4 chain rooted in multi-sig; got %v", err)
	}
}

// --- Vector 22: connection-time multi-sig delivery; receiver is in signers and signed → ALLOW. ---
// In our verifier, "connection-time" vs "post-handshake" is not distinguished
// at VerifyChain — the local-peer-in-signers rule applies uniformly. This
// test exercises the same code path as V13 with the framing of M6
// connection-time clarification.
func TestMultiSig_V22_ConnectionTime_ReceiverSigned_ALLOW(t *testing.T) {
	receiver := newSigner(t)
	other := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{receiver, other}, 2, []signer{receiver, other}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	if err := VerifyChain(capEnt, included, receiver.kp.PeerID()); err != nil {
		t.Fatalf("expected ALLOW for connection-time multi-sig with receiver signed; got %v", err)
	}
}

// --- Vector 23: connection-time multi-sig delivery; receiver in signers but didn't sign → DENY. ---
func TestMultiSig_V23_ConnectionTime_ReceiverNotSigned_DENY(t *testing.T) {
	receiver := newSigner(t)
	other := newSigner(t)
	third := newSigner(t)
	grantee := newSigner(t)
	// other and third sign; receiver does NOT.
	capEnt, included := buildMultiSigRoot(t, []signer{receiver, other, third}, 2, []signer{other, third}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	err := VerifyChain(capEnt, included, receiver.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY: connection-time receiver in signers but did not sign")
	}
}

// --- Round-trip determinism: encode → decode → re-encode produces identical bytes. ---
func TestMultiSig_Granter_RoundTripDeterminism(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b, c}), Threshold: 2}
	g := types.MultiSigGranter(mg)

	enc1, err := g.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal 1: %v", err)
	}
	var decoded types.Granter
	if err := decoded.UnmarshalCBOR(enc1); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	enc2, err := decoded.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal 2: %v", err)
	}
	if string(enc1) != string(enc2) {
		t.Fatalf("non-deterministic round-trip: %x != %x", enc1, enc2)
	}
}

// --- Token-level round-trip: CapabilityTokenData with multi-sig granter encodes/decodes to byte-identical bytes. ---
func TestMultiSig_TokenRoundTrip(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 2}

	tok := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}},
		},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   newSigner(t).identity.ContentHash,
		CreatedAt: 1000,
	}
	enc1, err := ecf.Encode(tok)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded types.CapabilityTokenData
	if err := ecf.Decode(enc1, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	enc2, err := ecf.Encode(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if string(enc1) != string(enc2) {
		t.Fatalf("non-deterministic round-trip on token: %x != %x", enc1, enc2)
	}
	if !decoded.Granter.IsMulti() {
		t.Fatal("decoded granter should be multi-sig")
	}
}

// --- Storage path: PathFor returns the M12 path for multi-sig roots. ---
func TestMultiSig_StoragePath_MultiSigRoot(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 2}
	tok := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   newSigner(t).identity.ContentHash,
		CreatedAt: 1000,
	}
	ent, err := tok.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	path, ok, err := PathFor(ent)
	if err != nil {
		t.Fatalf("PathFor err: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for multi-sig root")
	}
	if !strings.HasPrefix(path, MultiSigRootGrantsPrefix+"/") {
		t.Fatalf("path %q lacks expected prefix %q", path, MultiSigRootGrantsPrefix)
	}
}

// --- Vector 24b: M3 violation caught at chain-walk → ErrCapabilityDenied (403 surface). ---
// 24a (decode-layer detection) is impl-specific — Go decodes lazily, so M3 is caught
// at chain-walk; the spec's 24a is exercised by Level-2 impls (Rust). 24c is a
// cross-impl convergence check, exercised in cmd/internal/validate/convergence.go.
func TestMultiSig_V24b_M3_ChainWalk_403_Surface(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	grantee := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 5} // K > N
	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   grantee.identity.ContentHash,
		CreatedAt: 1000,
	}
	capEnt, _ := capData.ToEntity()
	included := map[hash.Hash]entity.Entity{
		capEnt.ContentHash:           capEnt,
		a.identity.ContentHash:       a.identity,
		b.identity.ContentHash:       b.identity,
		grantee.identity.ContentHash: grantee.identity,
	}
	err := VerifyChain(capEnt, included, a.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY for M3 violation")
	}
	// Status normalization: errors from M3 violations must be the
	// ErrCapabilityDenied class (translates to 403 at the wire response
	// boundary), NOT a structural-decode class.
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Fatalf("expected ErrCapabilityDenied (→ 403); got %v", err)
	}
}

// --- Vector 25a: M3 violation + missing K-of-N signatures; M3 wins. ---
// The cap has K > N AND no signatures attached. Both M3 (structural) and M4
// (below threshold) would reject; precedence rule says M3 must win so the
// caller sees `403 capability_denied` from M3, not a sig-failure code.
func TestMultiSig_V25a_M3_Beats_MissingSigs(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	grantee := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 5} // K > N
	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   grantee.identity.ContentHash,
		CreatedAt: 1000,
	}
	capEnt, _ := capData.ToEntity()
	// No signatures attached.
	included := map[hash.Hash]entity.Entity{
		capEnt.ContentHash:           capEnt,
		a.identity.ContentHash:       a.identity,
		b.identity.ContentHash:       b.identity,
		grantee.identity.ContentHash: grantee.identity,
	}
	err := VerifyChain(capEnt, included, a.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Fatalf("expected ErrCapabilityDenied (M3 wins); got %v", err)
	}
	if !strings.Contains(err.Error(), "threshold") && !strings.Contains(err.Error(), "multi-granter") {
		t.Fatalf("error must surface M3 cause, not sig failure; got: %v", err)
	}
}

// --- Vector 25b: M3 violation + invalid signatures; M3 wins. ---
func TestMultiSig_V25b_M3_Beats_InvalidSigs(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	grantee := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 5} // K > N
	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   grantee.identity.ContentHash,
		CreatedAt: 1000,
	}
	capEnt, _ := capData.ToEntity()
	included := map[hash.Hash]entity.Entity{
		capEnt.ContentHash:           capEnt,
		a.identity.ContentHash:       a.identity,
		b.identity.ContentHash:       b.identity,
		grantee.identity.ContentHash: grantee.identity,
	}
	// Attach a deliberately tampered signature claiming `a` signed.
	sigData := types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    a.identity.ContentHash,
		Algorithm: "ed25519",
		Signature: make([]byte, 64), // all zeros — never verifies
	}
	sigEnt, _ := sigData.ToEntity()
	included[sigEnt.ContentHash] = sigEnt

	err := VerifyChain(capEnt, included, a.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Fatalf("expected ErrCapabilityDenied (M3 wins); got %v", err)
	}
	if !strings.Contains(err.Error(), "threshold") && !strings.Contains(err.Error(), "multi-granter") {
		t.Fatalf("error must surface M3 cause, not sig failure; got: %v", err)
	}
}

// --- Vector 25c: structurally valid cap, K-of-N below threshold → 403 (M4). ---
// Structurally well-formed cap, but only 1 of 2 required signatures. M4 fires
// (not M3, since structure is valid). Confirms M4-class rejection still surfaces
// as ErrCapabilityDenied → 403.
func TestMultiSig_V25c_BelowThreshold_403_Surface(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity

	err := VerifyChain(capEnt, included, a.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY for below threshold")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Fatalf("expected ErrCapabilityDenied (→ 403); got %v", err)
	}
}

// --- Vector 25d: structurally valid cap, K signatures present, but local peer not in signers → 403 (M6). ---
func TestMultiSig_V25d_M6_LocalNotInSigners_403_Surface(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	c := newSigner(t)
	bystander := newSigner(t)
	grantee := newSigner(t)
	capEnt, included := buildMultiSigRoot(t, []signer{a, b, c}, 2, []signer{a, b}, grantee.identity.ContentHash)
	included[grantee.identity.ContentHash] = grantee.identity
	included[bystander.identity.ContentHash] = bystander.identity

	err := VerifyChain(capEnt, included, bystander.kp.PeerID())
	if err == nil {
		t.Fatal("expected DENY for M6 violation")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Fatalf("expected ErrCapabilityDenied (→ 403); got %v", err)
	}
}

// --- Within-cap precedence in CheckCreatorAuthority (M7 site): M3 wins. ---
// Tests the amendment's added precedence enforcement in
// CheckCreatorAuthority — if a chain entry has an M3 violation, the function
// must return an error rather than match the writer-as-granter path.
func TestMultiSig_V25_CheckCreator_M3_Beats_Match(t *testing.T) {
	a := newSigner(t)
	b := newSigner(t)
	grantee := newSigner(t)
	mg := types.MultiGranter{Signers: signerHashes([]signer{a, b}), Threshold: 5} // M3 violation
	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   grantee.identity.ContentHash,
		CreatedAt: 1000,
	}
	capEnt, _ := capData.ToEntity()
	included := map[hash.Hash]entity.Entity{
		capEnt.ContentHash:           capEnt,
		a.identity.ContentHash:       a.identity,
		b.identity.ContentHash:       b.identity,
		grantee.identity.ContentHash: grantee.identity,
	}
	signSingle(t, capEnt.ContentHash, a, included)

	// `a` is in signers and signed; without precedence enforcement, the
	// multi-sig branch could return found=true. With precedence, M3 fires
	// first and the function returns an error.
	_, _, err := CheckCreatorAuthority(capEnt, a.identity.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err == nil {
		t.Fatal("expected error for M3 violation; got nil (M3 precedence not enforced)")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Fatalf("expected ErrCapabilityDenied; got %v", err)
	}
}

// --- Storage path: PathFor returns ok=false for single-sig caps. ---
func TestMultiSig_StoragePath_SingleSig_NoMandate(t *testing.T) {
	a := newSigner(t)
	tok := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.SingleSigGranter(a.identity.ContentHash),
		Grantee:   newSigner(t).identity.ContentHash,
		CreatedAt: 1000,
	}
	ent, err := tok.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := PathFor(ent)
	if err != nil {
		t.Fatalf("PathFor err: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for single-sig cap; no protocol-mandated path")
	}
}
