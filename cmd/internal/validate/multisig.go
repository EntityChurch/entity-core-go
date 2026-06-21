package validate

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catMultiSig = "multisig"

// runMultiSig validates the peer's behavior on multi-sig root capabilities
// per V7 §3.6 (multi-granter type + M3 validity) and §5.5 (M4/M6/M7 chain
// verification) — multisig merged into the head at v7.60
// (ex-PROPOSAL-MULTISIG-CORE-PRIMITIVE).
//
// Coverage is mostly the negative-test surface — the peer should REJECT each
// of these crafted multi-sig caps for a specific reason: M3 content
// validation, M6 root-trust failure, M4 below-threshold, or a structural/CBOR
// error.
//
// It also runs ONE accept-path check (`valid_2of3_peer_signed_accepted`).
// Without it, the whole category is rejection-only, so a peer that simply
// fail-closes on every multi-granter cap (no real K-of-N) passes identically
// to a genuine implementation. The accept path needs a signature genuinely
// attributable to the verifying peer (M6: the peer must be in `signers` AND
// have signed), which requires its private key. We obtain it by loading the
// peer's on-disk keypair via crypto.LookupKeypairByPeerID — available when the
// peer was started with a persistent name (peer-manager --name). Ephemeral
// peers have no on-disk key, so that one check SKIPs rather than fails.
func runMultiSig(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catMultiSig)

	r.Declare("valid_2of3_peer_signed_accepted", "V7 §5.5 (multisig M4/M6 accept)")
	r.Declare("non_null_parent_rejected", "V7 §3.6 (multisig M3)")
	r.Declare("threshold_zero_rejected", "V7 §3.6 (multisig M3)")
	r.Declare("threshold_one_rejected", "V7 §3.6 (multisig M3)")
	r.Declare("threshold_exceeds_n_rejected", "V7 §3.6 (multisig M3)")
	r.Declare("duplicate_signers_rejected", "V7 §3.6 (multisig M3)")
	r.Declare("n_equals_one_rejected", "V7 §3.6 (multisig M3)")
	r.Declare("local_not_in_signers_rejected", "V7 §5.5 (multisig M6)")
	r.Declare("below_threshold_rejected", "V7 §5.5 (multisig M4)")
	// Multisig amendment §3.3 — within-cap precedence (M3 fires before M4):
	r.Declare("precedence_m3_beats_missing_sigs", "V7 §3.6 (M3 precedence 25a)")
	r.Declare("precedence_m3_beats_invalid_sigs", "V7 §3.6 (M3 precedence 25b)")

	r.Run("valid_2of3_peer_signed_accepted", func() CheckOutcome {
		return toOutcome(checkMultiSigValidAccepted(ctx, client))
	})
	r.Run("non_null_parent_rejected", func() CheckOutcome {
		return toOutcome(checkMultiSigNonNullParent(ctx, client))
	})
	r.Run("threshold_zero_rejected", func() CheckOutcome {
		return toOutcome(checkMultiSigThreshold(ctx, client, 0, "threshold_zero_rejected"))
	})
	r.Run("threshold_one_rejected", func() CheckOutcome {
		return toOutcome(checkMultiSigThreshold(ctx, client, 1, "threshold_one_rejected"))
	})
	r.Run("threshold_exceeds_n_rejected", func() CheckOutcome {
		return toOutcome(checkMultiSigThresholdExceedsN(ctx, client))
	})
	r.Run("duplicate_signers_rejected", func() CheckOutcome {
		return toOutcome(checkMultiSigDuplicateSigners(ctx, client))
	})
	r.Run("n_equals_one_rejected", func() CheckOutcome {
		return toOutcome(checkMultiSigNEqualsOne(ctx, client))
	})
	r.Run("local_not_in_signers_rejected", func() CheckOutcome {
		return toOutcome(checkMultiSigLocalNotInSigners(ctx, client))
	})
	r.Run("below_threshold_rejected", func() CheckOutcome {
		return toOutcome(checkMultiSigBelowThreshold(ctx, client))
	})

	r.Run("precedence_m3_beats_missing_sigs", func() CheckOutcome {
		return toOutcome(checkMultiSigPrecedenceM3BeatsMissingSigs(ctx, client))
	})
	r.Run("precedence_m3_beats_invalid_sigs", func() CheckOutcome {
		return toOutcome(checkMultiSigPrecedenceM3BeatsInvalidSigs(ctx, client))
	})

	return r.Results()
}

// --- helpers ---

// makeAuxSigner creates a fresh keypair + identity entity for use as a
// secondary signer in multi-sig setup. The identity entity is included in
// the envelope so the peer can resolve it.
func makeAuxSigner() (crypto.Keypair, entity.Entity, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return crypto.Keypair{}, entity.Entity{}, err
	}
	idEnt, err := kp.IdentityEntity()
	if err != nil {
		return crypto.Keypair{}, entity.Entity{}, err
	}
	return kp, idEnt, nil
}

// buildMultiSigExecute constructs a complete EXECUTE envelope rooted on a
// multi-sig cap with the given shape. signers/threshold define the cap's
// granter. signWith is the subset of signers whose signatures land in
// `included` (along with their identity entities). Returns the envelope ready
// for SendRawEnvelope.
func buildMultiSigExecute(
	client *PeerClient,
	signers []multiSigSigner,
	threshold uint64,
	signWith []multiSigSigner,
	parent *hash.Hash,
) (entity.Envelope, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())

	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000

	signerHashList := make([]hash.Hash, 0, len(signers))
	for _, s := range signers {
		signerHashList = append(signerHashList, s.identity.ContentHash)
	}
	mg := types.MultiGranter{Signers: signerHashList, Threshold: threshold}

	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.MultiSigGranter(mg),
		Grantee:   identity.ContentHash,
		Parent:    parent, // intentionally non-nil for M3 violation tests
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}

	capEntity, err := tokenData.ToEntity()
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("create cap: %w", err)
	}

	included := map[hash.Hash]entity.Entity{
		identity.ContentHash:  identity,
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
			return entity.Envelope{}, fmt.Errorf("create cap sig: %w", err)
		}
		included[sigEntity.ContentHash] = sigEntity
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("build params: %w", err)
	}
	raw, err := ecf.Encode(params)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("encode params: %w", err)
	}
	execData := types.ExecuteData{
		RequestID:  client.NextRequestID(),
		URI:        uri,
		Operation:  "get",
		Params:     cbor.RawMessage(raw),
		Author:     identity.ContentHash,
		Capability: capEntity.ContentHash,
		Resource:   resource,
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("create execute: %w", err)
	}
	execSig, err := signEntity(execEntity.ContentHash, kp, identity)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("sign execute: %w", err)
	}
	included[execSig.ContentHash] = execSig

	return entity.NewEnvelope(execEntity, included), nil
}

type multiSigSigner struct {
	kp       crypto.Keypair
	identity entity.Entity
}

// makeNAuxSigners creates n fresh signer pairs.
func makeNAuxSigners(n int) ([]multiSigSigner, error) {
	out := make([]multiSigSigner, 0, n)
	for i := 0; i < n; i++ {
		kp, idEnt, err := makeAuxSigner()
		if err != nil {
			return nil, err
		}
		out = append(out, multiSigSigner{kp: kp, identity: idEnt})
	}
	return out, nil
}

// sendExpectRejection sends an envelope and reports PASS if the peer rejects
// with a non-200 status. Used for legacy "any rejection is fine" checks; new
// checks should prefer sendExpectStatus(403) per the multisig amendment's
// status normalization rule.
func sendExpectRejection(client *PeerClient, env entity.Envelope, checkName, specRef string) CheckResult {
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return fail(catMultiSig, checkName, specRef,
			fmt.Sprintf("peer crashed or closed connection: %v", err))
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return fail(catMultiSig, checkName, specRef,
			"could not decode response: "+err.Error())
	}
	if respData.Status == 200 {
		return fail(catMultiSig, checkName, specRef,
			"peer accepted (200) a malformed/unauthorized multi-sig cap that should be rejected")
	}
	return pass(catMultiSig, checkName, specRef,
		fmt.Sprintf("peer correctly rejected with status %d", respData.Status))
}

// sendExpectStatus403 sends an envelope and reports PASS only if the peer
// returns exactly 403. Implements the multisig amendment's status
// normalization rule: M3 violations and M6 root-trust violations MUST surface
// as `403 capability_denied` regardless of detection layer.
func sendExpectStatus403(client *PeerClient, env entity.Envelope, checkName, specRef string) CheckResult {
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return fail(catMultiSig, checkName, specRef,
			fmt.Sprintf("peer crashed or closed connection: %v", err))
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return fail(catMultiSig, checkName, specRef,
			"could not decode response: "+err.Error())
	}
	if respData.Status == 403 {
		return pass(catMultiSig, checkName, specRef, "peer correctly rejected with 403 capability_denied")
	}
	return fail(catMultiSig, checkName, specRef,
		fmt.Sprintf("expected 403 (capability_denied) per §3.3 status normalization; got %d", respData.Status))
}

// sendExpectAccept sends an envelope and reports PASS only if the peer accepts
// (200). This is the multi-sig accept path: a genuine K-of-N implementation
// MUST authorize a well-formed 2-of-3 cap that the verifying peer itself
// co-signed (§5.5 M4 quorum + M6 root-at-local). A peer that merely
// fail-closes on every multi-granter cap returns 403 here and FAILS — which is
// exactly what separates a real implementation from vacuous rejection.
func sendExpectAccept(client *PeerClient, env entity.Envelope, checkName, specRef string) CheckResult {
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return fail(catMultiSig, checkName, specRef,
			fmt.Sprintf("peer crashed or closed connection: %v", err))
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return fail(catMultiSig, checkName, specRef,
			"could not decode response: "+err.Error())
	}
	switch respData.Status {
	case 200:
		return pass(catMultiSig, checkName, specRef,
			"peer authorized a valid 2-of-3 multi-sig cap it co-signed (M4 quorum + M6 root-at-local)")
	case 403:
		return fail(catMultiSig, checkName, specRef,
			"peer rejected (403) a VALID 2-of-3 multi-sig cap it co-signed — fail-closed on multi-granter rather than a genuine K-of-N implementation (§5.5 M4/M6)")
	default:
		return fail(catMultiSig, checkName, specRef,
			fmt.Sprintf("expected 200 for a valid co-signed 2-of-3 cap; got %d", respData.Status))
	}
}

// --- check implementations ---

// Accept path — a valid 2-of-3 multi-sig cap that the verifying peer is a
// signer of AND co-signed. M3 structure holds (root, N=3, K=2∈[2,N], distinct);
// M4 quorum is met (peer + one aux = 2 distinct signers ≥ threshold); M6
// root-at-local holds (the peer is in `signers` and signed). The peer MUST
// authorize (200). SKIPs if the peer's keypair isn't on disk (ephemeral peer):
// M6 cannot be satisfied without a signature attributable to the peer.
func checkMultiSigValidAccepted(ctx context.Context, client *PeerClient) CheckResult {
	const name = "valid_2of3_peer_signed_accepted"
	const ref = "V7 §5.5 (multisig M4/M6 accept)"

	peerKP, _, err := crypto.LookupKeypairByPeerID(string(client.RemotePeerID()))
	if err != nil {
		return skip(catMultiSig, name, ref,
			"accept-path requires the peer's on-disk key (M6 root-at-local): peer keypair not locally available — ephemeral peer. Start it with a persistent name (peer-manager --name) to exercise this check: "+err.Error())
	}
	peerIdentity, err := peerKP.IdentityEntity()
	if err != nil {
		return fail(catMultiSig, name, ref, "build peer identity entity: "+err.Error())
	}
	peerSigner := multiSigSigner{kp: peerKP, identity: peerIdentity}

	// Two fresh aux signers → N=3, threshold=2.
	aux, err := makeNAuxSigners(2)
	if err != nil {
		return fail(catMultiSig, name, ref, "setup: "+err.Error())
	}
	signers := []multiSigSigner{peerSigner, aux[0], aux[1]}
	// Peer + one aux sign (the third stays unsigned): 2 distinct signers meet
	// the threshold, and the peer is in the signed set (M6). parent=nil (root).
	signWith := []multiSigSigner{peerSigner, aux[0]}

	env, err := buildMultiSigExecute(client, signers, 2, signWith, nil)
	if err != nil {
		return fail(catMultiSig, name, ref, err.Error())
	}
	return sendExpectAccept(client, env, name, ref)
}

// V5 — multi-sig cap with non-null parent (M3 violation).
func checkMultiSigNonNullParent(ctx context.Context, client *PeerClient) CheckResult {
	signers, err := makeNAuxSigners(2)
	if err != nil {
		return fail(catMultiSig, "non_null_parent_rejected", "V7 §3.6 (multisig M3)", "setup: "+err.Error())
	}
	// Use a fake non-null parent hash.
	parent := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	for i := 0; i < hash.SHA256DigestSize; i++ {
		parent.Digest[i] = byte(i + 1)
	}
	env, err := buildMultiSigExecute(client, signers, 2, signers, &parent)
	if err != nil {
		return fail(catMultiSig, "non_null_parent_rejected", "V7 §3.6 (multisig M3)", err.Error())
	}
	return sendExpectRejection(client, env, "non_null_parent_rejected", "V7 §3.6 (multisig M3)")
}

// V6/V7 — threshold = 0 or 1.
func checkMultiSigThreshold(ctx context.Context, client *PeerClient, threshold uint64, checkName string) CheckResult {
	signers, err := makeNAuxSigners(2)
	if err != nil {
		return fail(catMultiSig, checkName, "V7 §3.6 (multisig M3)", "setup: "+err.Error())
	}
	env, err := buildMultiSigExecute(client, signers, threshold, signers, nil)
	if err != nil {
		return fail(catMultiSig, checkName, "V7 §3.6 (multisig M3)", err.Error())
	}
	return sendExpectStatus403(client, env, checkName, "V7 §3.6 (multisig M3)")
}

// V8 — K > N.
func checkMultiSigThresholdExceedsN(ctx context.Context, client *PeerClient) CheckResult {
	signers, err := makeNAuxSigners(2)
	if err != nil {
		return fail(catMultiSig, "threshold_exceeds_n_rejected", "V7 §3.6 (multisig M3)", "setup: "+err.Error())
	}
	env, err := buildMultiSigExecute(client, signers, 3, signers, nil)
	if err != nil {
		return fail(catMultiSig, "threshold_exceeds_n_rejected", "V7 §3.6 (multisig M3)", err.Error())
	}
	return sendExpectRejection(client, env, "threshold_exceeds_n_rejected", "V7 §3.6 (multisig M3)")
}

// V9 — duplicate signers.
func checkMultiSigDuplicateSigners(ctx context.Context, client *PeerClient) CheckResult {
	a, err := makeNAuxSigners(1)
	if err != nil {
		return fail(catMultiSig, "duplicate_signers_rejected", "V7 §3.6 (multisig M3)", "setup: "+err.Error())
	}
	dup := []multiSigSigner{a[0], a[0]}
	env, err := buildMultiSigExecute(client, dup, 2, dup, nil)
	if err != nil {
		return fail(catMultiSig, "duplicate_signers_rejected", "V7 §3.6 (multisig M3)", err.Error())
	}
	return sendExpectRejection(client, env, "duplicate_signers_rejected", "V7 §3.6 (multisig M3)")
}

// V10 — N = 1.
func checkMultiSigNEqualsOne(ctx context.Context, client *PeerClient) CheckResult {
	a, err := makeNAuxSigners(1)
	if err != nil {
		return fail(catMultiSig, "n_equals_one_rejected", "V7 §3.6 (multisig M3)", "setup: "+err.Error())
	}
	env, err := buildMultiSigExecute(client, a, 1, a, nil)
	if err != nil {
		return fail(catMultiSig, "n_equals_one_rejected", "V7 §3.6 (multisig M3)", err.Error())
	}
	return sendExpectRejection(client, env, "n_equals_one_rejected", "V7 §3.6 (multisig M3)")
}

// V11 — local peer (the validating peer) is not in signers (M6 root-trust fail).
func checkMultiSigLocalNotInSigners(ctx context.Context, client *PeerClient) CheckResult {
	signers, err := makeNAuxSigners(3)
	if err != nil {
		return fail(catMultiSig, "local_not_in_signers_rejected", "V7 §5.5 (multisig M6)", "setup: "+err.Error())
	}
	// signers are all aux keys — none of them is the remote peer. M6: deny.
	env, err := buildMultiSigExecute(client, signers, 2, signers[:2], nil)
	if err != nil {
		return fail(catMultiSig, "local_not_in_signers_rejected", "V7 §5.5 (multisig M6)", err.Error())
	}
	return sendExpectStatus403(client, env, "local_not_in_signers_rejected", "V7 §5.5 (multisig M6)")
}

// 25a — M3 violation (K > N) + missing K-of-N signatures. Per §3.3 precedence,
// M3 fires before M4, so the surfaced code MUST be 403 (capability_denied, M3),
// not a sig-failure code.
func checkMultiSigPrecedenceM3BeatsMissingSigs(ctx context.Context, client *PeerClient) CheckResult {
	signers, err := makeNAuxSigners(2)
	if err != nil {
		return fail(catMultiSig, "precedence_m3_beats_missing_sigs", "V7 §3.6 (M3 precedence 25a)", "setup: "+err.Error())
	}
	// K=3, N=2 → M3 violation. signWith=nothing → no signatures.
	env, err := buildMultiSigExecute(client, signers, 3, nil, nil)
	if err != nil {
		return fail(catMultiSig, "precedence_m3_beats_missing_sigs", "V7 §3.6 (M3 precedence 25a)", err.Error())
	}
	return sendExpectStatus403(client, env, "precedence_m3_beats_missing_sigs", "V7 §3.6 (M3 precedence 25a)")
}

// 25b — M3 violation (K > N) + invalid signatures attached. Same outcome as 25a:
// M3 wins, surfaces as 403, never as 401/sig-failure.
func checkMultiSigPrecedenceM3BeatsInvalidSigs(ctx context.Context, client *PeerClient) CheckResult {
	signers, err := makeNAuxSigners(2)
	if err != nil {
		return fail(catMultiSig, "precedence_m3_beats_invalid_sigs", "V7 §3.6 (M3 precedence 25b)", "setup: "+err.Error())
	}
	// K=3, N=2 → M3 violation. signWith=both signers, but with bogus key → invalid sigs.
	env, err := buildMultiSigExecute(client, signers, 3, signers, nil)
	if err != nil {
		return fail(catMultiSig, "precedence_m3_beats_invalid_sigs", "V7 §3.6 (M3 precedence 25b)", err.Error())
	}
	return sendExpectStatus403(client, env, "precedence_m3_beats_invalid_sigs", "V7 §3.6 (M3 precedence 25b)")
}

// V3 — below threshold (only 1 sig of 2 required).
func checkMultiSigBelowThreshold(ctx context.Context, client *PeerClient) CheckResult {
	signers, err := makeNAuxSigners(3)
	if err != nil {
		return fail(catMultiSig, "below_threshold_rejected", "V7 §5.5 (multisig M4)", "setup: "+err.Error())
	}
	// Only one signature of two required.
	env, err := buildMultiSigExecute(client, signers, 2, signers[:1], nil)
	if err != nil {
		return fail(catMultiSig, "below_threshold_rejected", "V7 §5.5 (multisig M4)", err.Error())
	}
	return sendExpectStatus403(client, env, "below_threshold_rejected", "V7 §5.5 (multisig M4)")
}
