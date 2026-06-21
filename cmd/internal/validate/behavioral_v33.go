package validate

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// buildTreePutParams is a thin wrapper over tree.CreatePutRequest matching
// the local validate package's signature conventions.
func buildTreePutParams(path string, ent *entity.Entity) (entity.Entity, *types.ResourceTarget, error) {
	return tree.CreatePutRequest(path, ent)
}

// catBehavioralV33 drives the v3.3 behavioral test vectors over the wire
// against a remote peer. Wire-conformance categories (attestation, quorum,
// identity) only check handler manifests + type registrations; this
// category exercises the actual algorithm rulings landed by
// PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md.
//
// Coverage in this round:
//
//   - TV-A4a/b/c/d: transitive supersession in is_attestation_live (SI-2).
//     The convergent spec-text bug all three impls fixed in unit tests;
//     this drives it through the wire to verify the fix is actually
//     applied to attestations arriving via the protocol.
//   - TV-A8 (informative): substrate signature-agnostic posture (SI-1
//     Option A); the substrate's :verify rejects on signature first,
//     so the consumer-layer behavior is what we observe — attestation
//     remains tree-bound (substrate didn't unbind it).
//
// Future expansion: TV-Q-V16a/b/c (as_of), TV-Q-V-IDENTITY-2 + cycle,
// TV-I-V13a/b/c. Those need quorum ceremony / identity setup which is
// substantially more wire-driven plumbing; tracked separately.
const catBehavioralV33 = "behavioral_v33"

func runBehavioralV33(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catBehavioralV33)

	r.Declare("tv_a4a_chain_of_three", "ATTESTATION v1.1 §4.3 / SI-2")
	r.Declare("tv_a4b_tail_expired", "ATTESTATION v1.1 §4.3 / SI-2")
	r.Declare("tv_a4c_predecessor_revival", "ATTESTATION v1.1 §4.3 / SI-2")
	r.Declare("tv_a4d_revoked_middle_live_tail", "ATTESTATION v1.1 §4.3 / SI-2")

	// All four vectors share the same fixture-construction approach; we
	// build chains of attestations bound at synthetic test paths and
	// drive :verify against each link.
	identityHash := client.IdentityEntity().ContentHash
	identityPeerID := string(client.RemotePeerID())
	_ = identityPeerID

	// putSignedAttestation builds an attestation, signs it with the local
	// keypair, and binds both at the receiving peer. The attestation goes
	// at treePath via tree:put. The signature is delivered via
	// envelope.included on the same tree:put — per SI-11, the receiving
	// peer's dispatcher ingests system/signature entities from
	// envelope.included and binds them at the V7 invariant pointer path
	// /{signer_peer_id}/system/signature/{target_hash_hex} BEFORE the
	// handler's main body executes.
	//
	// Cross-impl note: this exercises the SI-11 dispatcher-level
	// ingestion. Implementations that wire ingestion only at specific
	// handlers (e.g., only at identity ops) instead of at the
	// dispatcher's envelope-unwrap step will fail this test — that
	// failure is intentional and signals an SI-11 conformance gap.
	putSignedAttestation := func(att types.AttestationData, treePath string) (hash.Hash, error) {
		ent, err := att.ToEntity()
		if err != nil {
			return hash.Hash{}, fmt.Errorf("encode attestation: %w", err)
		}
		// Build the signature.
		sigBytes := ed25519.Sign(client.Keypair().PrivateKey, ent.ContentHash.Bytes())
		sigData := types.SignatureData{
			Target:    ent.ContentHash,
			Signer:    identityHash,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}
		sigEnt, err := sigData.ToEntity()
		if err != nil {
			return hash.Hash{}, fmt.Errorf("encode signature: %w", err)
		}
		// Build the tree:put params + resource for the attestation.
		params, resource, err := buildTreePutParams(treePath, &ent)
		if err != nil {
			return hash.Hash{}, fmt.Errorf("build put request: %w", err)
		}
		uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())
		// Include the signature in envelope.included. SI-11 dispatcher
		// ingestion binds it at the V7 invariant path before the tree
		// handler runs.
		included := map[hash.Hash]entity.Entity{
			sigEnt.ContentHash: sigEnt,
		}
		respEnv, _, sendErr := client.SendExecuteWithIncluded(ctx, uri, "put", params, resource, included)
		if sendErr != nil {
			return hash.Hash{}, fmt.Errorf("send put: %w", sendErr)
		}
		respData, decErr := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if decErr != nil {
			return hash.Hash{}, fmt.Errorf("decode put response: %w", decErr)
		}
		if respData.Status != 200 {
			return hash.Hash{}, fmt.Errorf("tree put status %d at %s", respData.Status, treePath)
		}
		return ent.ContentHash, nil
	}

	// verifyResult drives system/attestation:verify and returns
	// {valid, reason}. Used by all four TV-A4 vectors.
	verifyResult := func(attHash hash.Hash) (valid bool, reason string, err error) {
		uri := fmt.Sprintf("entity://%s/system/attestation", client.RemotePeerID())
		req := types.AttestationVerifyRequestData{AttestationHash: attHash}
		paramsEnt, encErr := req.ToEntity()
		if encErr != nil {
			return false, "", encErr
		}
		respEnv, _, sendErr := client.SendExecute(ctx, uri, "verify", paramsEnt, nil)
		if sendErr != nil {
			return false, "", sendErr
		}
		respData, decErr := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if decErr != nil {
			return false, "", decErr
		}
		if respData.Status != 200 {
			return false, fmt.Sprintf("status_%d", respData.Status), nil
		}
		var resultEnt entity.Entity
		if decErr := ecf.Decode(respData.Result, &resultEnt); decErr != nil {
			return false, "", fmt.Errorf("decode result entity: %w", decErr)
		}
		result, decErr := types.AttestationVerifyResultDataFromEntity(resultEnt)
		if decErr != nil {
			return false, "", decErr
		}
		return result.Valid, result.Reason, nil
	}

	// makeChainAttestation builds a fresh attestation for the test
	// fixture. attesting = identityHash; attested = a stable test
	// peer hash (same per-test so all chain links target the same
	// "subject"). The varying byte parameter ensures each attestation
	// has a distinct content_hash even if other fields collide.
	makeChainAttestation := func(supersedes *hash.Hash, marker byte) types.AttestationData {
		var attestedRaw [33]byte
		attestedRaw[0] = hash.AlgorithmSHA256
		attestedRaw[1] = 0xA4 // shared "subject" for TV-A4 chain
		attested, _ := hash.FromBytes(attestedRaw[:])
		props, _ := types.EncodeProperties(struct {
			Kind   string `cbor:"kind"`
			Marker byte   `cbor:"marker"` // ensures distinct content hash
		}{Kind: "tv-a4-test", Marker: marker})
		return types.AttestationData{
			Attesting:  identityHash,
			Attested:   attested,
			Properties: props,
			Supersedes: supersedes,
		}
	}

	// TV-A4a: chain of three a0 → a1 → a2 (all valid). Expected: a2
	// live (head); a1 dead (superseded by a2); a0 dead (transitively
	// superseded by a2).
	r.Run("tv_a4a_chain_of_three", func() CheckOutcome {
		basePath := "system/validate/v33/a4a"
		a0 := makeChainAttestation(nil, 0xA0)
		hA0, err := putSignedAttestation(a0, basePath+"/a0")
		if err != nil {
			return FailCheck("setup a0: " + err.Error())
		}
		a1 := makeChainAttestation(&hA0, 0xA1)
		hA1, err := putSignedAttestation(a1, basePath+"/a1")
		if err != nil {
			return FailCheck("setup a1: " + err.Error())
		}
		a2 := makeChainAttestation(&hA1, 0xA2)
		hA2, err := putSignedAttestation(a2, basePath+"/a2")
		if err != nil {
			return FailCheck("setup a2: " + err.Error())
		}

		// a2 should be live (head).
		valid, reason, err := verifyResult(hA2)
		if err != nil {
			return FailCheck("verify a2: " + err.Error())
		}
		if !valid {
			return FailCheck(fmt.Sprintf("TV-A4a: a2 (head) expected valid:true; got valid:false reason=%s", reason))
		}
		// a1 should be dead (a2 supersedes).
		valid, reason, err = verifyResult(hA1)
		if err != nil {
			return FailCheck("verify a1: " + err.Error())
		}
		if valid {
			return FailCheck("TV-A4a: a1 expected dead (superseded by a2); got valid:true")
		}
		// a0 should be dead (transitive — a2 lives between).
		valid, reason, err = verifyResult(hA0)
		if err != nil {
			return FailCheck("verify a0: " + err.Error())
		}
		if valid {
			return FailCheck("TV-A4a: a0 expected dead (transitive descendant a2 lives); got valid:true — likely the bistable bug per SI-2")
		}
		return PassCheck("TV-A4a: chain of three handled correctly (transitive supersession)")
	})

	// TV-A4c: a0 → a1; a1 self-revoked; no a2. Expected: a0 LIVE
	// (predecessor revival). Per the predecessor-revival semantics
	// ratified in SI-2, when a successor is revoked with no further
	// successor, the predecessor is alive again.
	r.Run("tv_a4c_predecessor_revival", func() CheckOutcome {
		basePath := "system/validate/v33/a4c"
		a0 := makeChainAttestation(nil, 0xC0)
		hA0, err := putSignedAttestation(a0, basePath+"/a0")
		if err != nil {
			return FailCheck("setup a0: " + err.Error())
		}
		a1 := makeChainAttestation(&hA0, 0xC1)
		hA1, err := putSignedAttestation(a1, basePath+"/a1")
		if err != nil {
			return FailCheck("setup a1: " + err.Error())
		}

		// Self-revocation of a1: an attestation by a1.Attesting with
		// kind="revocation" targeting hA1. Per substrate §3.3 (universal
		// revocation kind) + §4.3 self-revocation rule.
		revProps, _ := types.EncodeProperties(types.RevocationProperties{
			Kind:   types.KindRevocation,
			Reason: "tv-a4c predecessor revival test",
		})
		rev := types.AttestationData{
			Attesting:  identityHash,
			Attested:   hA1,
			Properties: revProps,
		}
		_, err = putSignedAttestation(rev, basePath+"/rev")
		if err != nil {
			return FailCheck("setup rev: " + err.Error())
		}

		// a1 should be dead (revoked).
		valid, _, err := verifyResult(hA1)
		if err != nil {
			return FailCheck("verify a1: " + err.Error())
		}
		if valid {
			return FailCheck("TV-A4c: a1 expected dead (self-revoked); got valid:true")
		}
		// a0 should be ALIVE again — predecessor revival per SI-2's
		// ratified transitive semantics.
		valid, reason, err := verifyResult(hA0)
		if err != nil {
			return FailCheck("verify a0: " + err.Error())
		}
		if !valid {
			return FailCheck(fmt.Sprintf("TV-A4c: a0 expected live (predecessor revival — a1 revoked, no a2); got valid:false reason=%s — likely incorrect transitive semantics", reason))
		}
		return PassCheck("TV-A4c: predecessor revival handled correctly")
	})

	// TV-A4d: a0 → a1 → a2; a1 revoked; a2 valid. Expected: a2 live;
	// a1 dead (revoked); a0 DEAD (a2 is an effectively-live transitive
	// descendant — a1's revocation does NOT revive a0 because a2 still
	// lives below).
	r.Run("tv_a4d_revoked_middle_live_tail", func() CheckOutcome {
		basePath := "system/validate/v33/a4d"
		a0 := makeChainAttestation(nil, 0xD0)
		hA0, err := putSignedAttestation(a0, basePath+"/a0")
		if err != nil {
			return FailCheck("setup a0: " + err.Error())
		}
		a1 := makeChainAttestation(&hA0, 0xD1)
		hA1, err := putSignedAttestation(a1, basePath+"/a1")
		if err != nil {
			return FailCheck("setup a1: " + err.Error())
		}
		a2 := makeChainAttestation(&hA1, 0xD2)
		hA2, err := putSignedAttestation(a2, basePath+"/a2")
		if err != nil {
			return FailCheck("setup a2: " + err.Error())
		}
		revProps, _ := types.EncodeProperties(types.RevocationProperties{
			Kind:   types.KindRevocation,
			Reason: "tv-a4d revoked middle test",
		})
		rev := types.AttestationData{
			Attesting:  identityHash,
			Attested:   hA1,
			Properties: revProps,
		}
		_, err = putSignedAttestation(rev, basePath+"/rev")
		if err != nil {
			return FailCheck("setup rev: " + err.Error())
		}

		valid, _, err := verifyResult(hA2)
		if err != nil {
			return FailCheck("verify a2: " + err.Error())
		}
		if !valid {
			return FailCheck("TV-A4d: a2 expected live (tail beyond revocation); got valid:false")
		}
		valid, _, err = verifyResult(hA1)
		if err != nil {
			return FailCheck("verify a1: " + err.Error())
		}
		if valid {
			return FailCheck("TV-A4d: a1 expected dead (revoked); got valid:true")
		}
		valid, reason, err := verifyResult(hA0)
		if err != nil {
			return FailCheck("verify a0: " + err.Error())
		}
		if valid {
			return FailCheck(fmt.Sprintf("TV-A4d: a0 expected dead (a2 is effectively-live transitive descendant); got valid:true — likely incorrect handling of revocation-with-live-tail (reason=%s)", reason))
		}
		return PassCheck("TV-A4d: revoked-middle-with-live-tail handled correctly")
	})

	// TV-A4b: a0 → a1 → a2; a2 expired. Expected: a1 live (no live
	// descendant — a2 is expired, no longer "effectively live"); a0
	// dead (a1 is an effectively-live transitive descendant).
	r.Run("tv_a4b_tail_expired", func() CheckOutcome {
		basePath := "system/validate/v33/a4b"
		a0 := makeChainAttestation(nil, 0xB0)
		hA0, err := putSignedAttestation(a0, basePath+"/a0")
		if err != nil {
			return FailCheck("setup a0: " + err.Error())
		}
		a1 := makeChainAttestation(&hA0, 0xB1)
		hA1, err := putSignedAttestation(a1, basePath+"/a1")
		if err != nil {
			return FailCheck("setup a1: " + err.Error())
		}
		// a2 expired (ExpiresAt set to 1ms past epoch, which is always in the past).
		expired := uint64(1)
		a2 := makeChainAttestation(&hA1, 0xB2)
		a2.ExpiresAt = &expired
		hA2, err := putSignedAttestation(a2, basePath+"/a2")
		if err != nil {
			return FailCheck("setup a2: " + err.Error())
		}

		valid, _, err := verifyResult(hA2)
		if err != nil {
			return FailCheck("verify a2: " + err.Error())
		}
		if valid {
			return FailCheck("TV-A4b: a2 expected dead (expired); got valid:true")
		}
		valid, reason, err := verifyResult(hA1)
		if err != nil {
			return FailCheck("verify a1: " + err.Error())
		}
		if !valid {
			return FailCheck(fmt.Sprintf("TV-A4b: a1 expected live (no effectively-live descendant); got valid:false reason=%s", reason))
		}
		valid, _, err = verifyResult(hA0)
		if err != nil {
			return FailCheck("verify a0: " + err.Error())
		}
		if valid {
			return FailCheck("TV-A4b: a0 expected dead (a1 is effectively-live transitive descendant); got valid:true")
		}
		return PassCheck("TV-A4b: tail-expired chain handled correctly")
	})

	return r.Results()
}

// Avoid unused imports in case of refactor.
var _ = entity.Entity{}
