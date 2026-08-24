package peerissued

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Mixed-home evidence for ENTITY-CORE-PROTOCOL §4.5a item 1a (v7.77).
//
// **These two tests previously asserted the opposite, and that was their
// job.** They were written on 2026-08-10 to make the `{peer_id_hex}`
// collision a reproducible fact rather than an argument, with the assertion
// deliberately on the OBSERVED behavior and a failure message saying to
// re-read the spec-issue when it flipped. It flipped: arch ruled the
// `system/peer` entity **derive-to-meet, authored at the ECFv1-SHA-256 floor
// unconditionally**, and both tests started failing on the tree that
// implements it. They are inverted here rather than deleted, because the
// invariant they now pin is the one the ruling bought.
//
// The collision that was: SPECIFICATION-FORMAT §8.4.6 ruled `{peer_id_hex}`
// derive-to-meet (floor-pinned, computed from `(public_key, key_type)`),
// while §514 ruled an identity *reference* the AUTHORED content_hash, which a
// peer MUST NOT recompute under its own format. One value, two rules, opposite
// directions — invisible on a single-format network because the two coincide.
// Item 1a collapses it by making the authored form floor-derived by
// construction: one derivation function, which §4.5a item 4 now names as the
// conformant shape.

// setHome swaps the process-global authoring format for the duration of a
// test, standing in for a peer whose `--hash-type` is that format.
func setHome(t *testing.T, alg byte) {
	t.Helper()
	prev := entity.DefaultHashAlgorithm()
	entity.SetDefaultHashAlgorithm(alg)
	t.Cleanup(func() { entity.SetDefaultHashAlgorithm(prev) })
}

// The bare fact, at the unit level: the identity entity's content_hash does
// not move when the home format does. Authored and floor-derived are the same
// bytes on every home — not a coincidence preserved per-connection, but an
// identity (§4.5a item 1a; §1.8 restated).
func TestPeerIdentityHash_IsFloorPinnedWhateverTheHome(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, keyType, ok := crypto.DerivePeerFromPeerID(kp.PeerID())
	if !ok {
		t.Fatalf("DerivePeerFromPeerID: not identity-form")
	}

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
		t.Fatalf("SHA-256 home: authored %s != derived %s", authored256.ContentHash, derived256)
	}

	// The case that used to diverge. A SHA-384-home peer authors its OWN
	// identity entity at the floor, so its identity hash is byte-identical
	// to the one a SHA-256-home peer derives for it from its peer-id alone.
	entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA384)
	authored384, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity (sha384 home): %v", err)
	}
	if authored384.ContentHash != authored256.ContentHash {
		t.Fatalf("SHA-384 home authored %s, SHA-256 home authored %s — item 1a requires "+
			"the identity entity to be floor-authored whatever the home format",
			authored384.ContentHash, authored256.ContentHash)
	}
	if authored384.ContentHash != derived256 {
		t.Fatalf("SHA-384-home authored hash %s != floor-derived %s — the two derivation "+
			"routes must yield one value (§4.5a item 4)", authored384.ContentHash, derived256)
	}
	if authored384.ContentHash.Algorithm != hash.AlgorithmSHA256 {
		t.Fatalf("identity entity on a SHA-384 home carries algorithm 0x%02x, want the 0x00 floor",
			authored384.ContentHash.Algorithm)
	}

	// The derived route must be format-independent too — ComputePeerIdentityHash
	// is the function that serves the {peer_id_hex} path-segment role, and it
	// is still under the SHA-384 home here.
	derived384, err := types.ComputePeerIdentityHash(pub, keyType)
	if err != nil {
		t.Fatalf("ComputePeerIdentityHash (sha384 home): %v", err)
	}
	if derived384 != derived256 {
		t.Fatalf("ComputePeerIdentityHash follows the home format (%s vs %s) — the "+
			"{peer_id_hex} derivation must be floor-pinned", derived384, derived256)
	}
}

// The end-to-end consequence at the seam that mattered: a register-request
// whose ownership proof was authored by a SHA-384-home publisher is now
// ACCEPTED by a SHA-256-home registry.
//
// This is the measurement that motivated the ruling, inverted. §6a.9 layer-1
// compares the authored `signer` against a locally-derived identity hash;
// before item 1a those were different bytes across homes and the publisher
// was told its signature was invalid — a silent never-meet that looked like a
// crypto failure rather than a format one. One derivation function makes the
// comparison well-defined across address spaces.
//
// Note the scope: this does NOT make mixed-home a supported deployment
// (§1.2a keeps the uniform network the supported v1 shape, and the probe stays
// diagnostic). It pins that THIS seam is no longer where it breaks.
func TestRegister_MixedHome_OwnershipProofAccepted(t *testing.T) {
	// The registry (verifier) is SHA-256-home for the whole test.
	setHome(t, hash.AlgorithmSHA256)

	registryKP, _, _ := newRegistry(t)
	iss, hctx := newIssuer(t, registryKP,
		WithIssuerClock(func() uint64 { return 1_000_000 }))
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

	if resp.Status != 200 {
		code := decodeErrorCode(t, resp)
		t.Fatalf("mixed-home register → %d/%q, want 200. Under §4.5a item 1a the "+
			"publisher's identity entity is floor-authored, so its `signer` and the "+
			"registry's derived hash are the same bytes; a %q here means some path "+
			"still authors or derives an identity under the home format",
			resp.Status, code, code)
	}
}
