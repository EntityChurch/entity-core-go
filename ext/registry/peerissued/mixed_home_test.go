package peerissued

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Mixed-home evidence for SPECIFICATION-FORMAT §8.4.6 vs ENTITY-CORE-PROTOCOL
// §1.8/§4.5a. These two tests are the *measurement* behind
// docs/validation/spec-issues/SPEC-ISSUE-2026-08-10-peer-identity-hash-disposition.md
// — they exist so the collision is a reproducible fact rather than an
// argument, and so it fails loudly the moment either side of it is ruled.
//
// The collision in one sentence: §8.4.6 rules `{peer_id_hex}` **derive-to-meet**
// (pinned to the ECFv1-SHA-256 floor, computed from `(public_key, key_type)`),
// while §514 rules an identity *reference* — `signature.signer`, a cap
// `grantee`/`granter` — the **authored** `content_hash` of the peer's
// `system/peer` entity, which a peer MUST NOT recompute under its own format.
// Go's `ComputePeerIdentityHash` is the single function serving both roles.
// On a single-format network the two are the same bytes and nothing shows.

// setHome swaps the process-global authoring format for the duration of a
// test, standing in for a peer whose `--hash-type` is that format. The
// analog of ext/encryption/format_test.go's helper.
func setHome(t *testing.T, alg byte) {
	t.Helper()
	prev := entity.DefaultHashAlgorithm()
	entity.SetDefaultHashAlgorithm(alg)
	t.Cleanup(func() { entity.SetDefaultHashAlgorithm(prev) })
}

// The bare fact, at the unit level: the authored identity entity and the
// floor-derived identity hash are the same bytes on a SHA-256-home peer and
// different bytes on a SHA-384-home peer. This is the "local collapse" §8.4.6
// names — the reason the ambiguity survived every test written to date.
func TestPeerIdentityHash_AuthoredVsFloor_DivergesOffTheFloor(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, keyType, ok := crypto.DerivePeerFromPeerID(kp.PeerID())
	if !ok {
		t.Fatalf("DerivePeerFromPeerID: not identity-form")
	}

	// On the floor, authored == derived. The coincidence.
	setHome(t, hash.AlgorithmSHA256)
	authored256, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity (sha256 home): %v", err)
	}
	derived256, err := types.ComputePeerIdentityHash(pub, keyType)
	if err != nil {
		t.Fatalf("ComputePeerIdentityHash (sha256 home): %v", err)
	}
	if authored256.ContentHash != derived256 {
		t.Fatalf("SHA-256 home: authored %s != derived %s — the floor case must coincide",
			authored256.ContentHash, derived256)
	}

	// Off the floor they part. Both follow the home format today, so they
	// still equal each other here — what diverges is this peer's identity
	// hash as seen by a peer on a different home (below).
	entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA384)
	authored384, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity (sha384 home): %v", err)
	}
	if authored384.ContentHash == authored256.ContentHash {
		t.Fatalf("SHA-384 home authored the same content_hash as SHA-256 home (%s) — "+
			"the home format is not reaching the identity entity", authored384.ContentHash)
	}
	// The floor-derived value is what a *differently-homed* peer would
	// construct for this same peer from its peer-id alone. It does not
	// follow this peer's home, which is precisely §8.4.6's requirement and
	// precisely what the authored reference does not satisfy.
	if authored384.ContentHash == derived256 {
		t.Fatalf("SHA-384-home authored hash equals the floor hash — expected divergence")
	}
}

// The end-to-end consequence, at the seam that matters: a register-request
// whose ownership-proof signature was authored by a SHA-384-home publisher is
// rejected by a SHA-256-home registry, because §6a.9 layer-1 compares the
// authored `signer` against a locally-derived identity hash.
//
// This is a PRE-EXISTING defect, not one introduced by the §8.4.6 work — it
// reproduces on an unmodified tree. It is also the exact shape §8.4.6 warns
// about: the two peers never meet, and nothing fails loudly enough to look
// like a format problem. The publisher is told its signature is invalid.
//
// The assertion is deliberately on the *observed* status, not on a desired
// one: which side gives (pin the reference, or float the derivation) is
// arch's ruling to make. When it lands, this test flips and says so.
func TestRegister_MixedHome_OwnershipProofRejected(t *testing.T) {
	// The registry (verifier) is SHA-256-home for the whole test.
	setHome(t, hash.AlgorithmSHA256)

	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))
	// Arm open mode explicitly. Layer-1 ownership-proof runs before the
	// policy is consulted, so this does not change the outcome — it makes
	// the outcome attributable: without it a §6a.9.2 curated-only 404 could
	// be mistaken for the collision this test exists to measure.
	installPolicy(t, hctx, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen})

	publisher, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate publisher: %v", err)
	}
	body := types.RegistryRegisterRequestData{
		Name:         "mixedhome.example",
		TargetPeerID: string(publisher.PeerID()),
		Nonce:        []byte{0x77},
		IssuedAt:     1_000_000,
	}

	// Stage the request + ownership-proof signature as a SHA-384-home
	// publisher would author them, then restore the registry's home before
	// dispatch. Only the authoring format differs between the two peers.
	entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA384)
	reqEnt := stageRequest(t, hctx, publisher, body)
	entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA256)

	resp := dispatchRegister(t, iss, hctx, reqEnt)

	// Same request authored by a same-home publisher succeeds
	// (TestRegister_OpenMode_HappyPath). The only variable is the home
	// format, so a non-200 here is attributable to it and nothing else.
	if resp.Status == 200 {
		t.Fatalf("mixed-home register succeeded (status 200) — the §8.4.6/§514 collision " +
			"has been resolved somewhere; re-read the spec-issue and update it")
	}
	if code := decodeErrorCode(t, resp); code != types.RegistryErrSignatureInvalid {
		t.Fatalf("mixed-home register: want %q (the collision's signature), got %q — "+
			"a different rejection reason means this test is no longer measuring what it claims",
			types.RegistryErrSignatureInvalid, code)
	}
	t.Logf("confirmed: SHA-384-home publisher rejected by SHA-256-home registry with %q "+
		"(pre-existing; see SPEC-ISSUE-2026-08-10-peer-identity-hash-disposition)",
		types.RegistryErrSignatureInvalid)
}
