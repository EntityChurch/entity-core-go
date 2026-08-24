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
	r.Declare("below_threshold_denied_write", "V7 §5.5 (multisig M4) + GUIDE-CONFORMANCE §2.4a")
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
	r.Run("below_threshold_denied_write", func() CheckOutcome {
		return toOutcome(checkMultiSigBelowThresholdWrite(ctx, client))
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
	// Every pre-2026-08-12 caller drives a read against the type surface.
	// Preserved exactly so a divergence between the read rows and the new
	// write row is attributable to read-vs-write and nothing else.
	return buildMultiSigExecuteOp(client, signers, threshold, signWith, parent,
		"get", "system/type/system/peer")
}

// buildMultiSigExecuteOp is buildMultiSigExecute with the driven operation and
// resource target made explicit.
//
// WHY IT IS PARAMETERIZED (2026-08-12 §2.4a re-sweep). Every one of the
// category's eleven checks — the whole M3/M4/M6 surface, positive half
// included — drove `Operation: "get"` from a single hardcoded site. That is
// the coverage shape N-2 found in the temporal family, in a class N-2's
// sampling note did not name: a peer that verifies multi-granter structure and
// counts K-of-N signatures on its READ path and not on its WRITE path scores
// 11/11 here and still accepts a forged joint authority to write. The status
// assertion cannot see it, because the status is correct.
func buildMultiSigExecuteOp(
	client *PeerClient,
	signers []multiSigSigner,
	threshold uint64,
	signWith []multiSigSigner,
	parent *hash.Hash,
	operation string,
	resourcePath string,
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

	params, _, err := buildSimpleGetParams()
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("build params: %w", err)
	}
	raw, err := ecf.Encode(params)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("encode params: %w", err)
	}
	resource := &types.ResourceTarget{Targets: []string{resourcePath}}
	execData := types.ExecuteData{
		RequestID:  client.NextRequestID(),
		URI:        uri,
		Operation:  operation,
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
	return sendExpectStatus403Probed(context.Background(), client, env, checkName, specRef, nil)
}

// sendExpectStatus403Probed is sendExpectStatus403 with §2.4a conjuncts 2 and 3
// asserted. A nil probe means the guarded operation is a read — true of every
// caller in this category before 2026-08-12 — where both conjuncts are vacuous.
//
// The probe lives HERE rather than in the caller for the reason
// GUIDE-CONFORMANCE §2.4a gives directly: the gap pools in shared deny
// helpers, so a future multi-sig row that drives a write inherits the negative
// half by construction instead of by the author remembering. The
// UnchangedPrefix snapshot must also be taken before the send, which a caller
// cannot do after the fact.
func sendExpectStatus403Probed(
	ctx context.Context,
	client *PeerClient,
	env entity.Envelope,
	checkName, specRef string,
	probe *denyStateProbe,
) CheckResult {
	var beforeKeys map[string]bool
	if probe != nil && probe.UnchangedPrefix != "" {
		beforeKeys = listingKeys(ctx, client, probe.UnchangedPrefix)
	}

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
	if respData.Status != 403 {
		return fail(catMultiSig, checkName, specRef,
			fmt.Sprintf("expected 403 (capability_denied) per §3.3 status normalization; got %d", respData.Status))
	}
	msg, ok := applyDenyStateProbe(ctx, client, respEnv, probe, beforeKeys)
	if !ok {
		return fail(catMultiSig, checkName, specRef, msg)
	}
	return pass(catMultiSig, checkName, specRef, msg)
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

// buildM4BelowThresholdExecute builds an envelope that fails M4 — and ONLY M4
// — driving the given operation at the given resource path.
//
// WHY THIS EXISTS, AND IT IS THE FINDING OF THE 2026-08-12 §2.4a RE-SWEEP.
// `below_threshold_rejected` is declared against "V7 §5.5 (multisig M4)" and
// built from `makeNAuxSigners(3)` — three fresh aux keys, none of them the
// local peer. Per §5.5's own pseudocode the **M6 root check runs before the
// per-level M4 signature loop**: a multi-sig root whose signer set does not
// contain the local peer is DENIED at M6 and never reaches the threshold
// count. So that row is denied for an M6 reason, is observationally identical
// to `local_not_in_signers_rejected`, and **cannot fail for the reason its
// name and spec-ref claim.**
//
// Not caught by review, and not catchable by review — it PASSes, against a
// correct peer, for a correct reason. It was caught by MUTATING it: satisfying
// the threshold (signWith 2 of 2) left the response at 403 where an M4 row
// must have gone green. A check that still refuses when you remove the thing
// it tests is measuring something else (§2.4a's corollary; doctrine 3).
//
// Isolating M4 requires satisfying M6 first: the local peer must be in
// `signers` AND have signed. That needs the peer's own key, so these rows
// SKIP on an ephemeral peer exactly as the accept row does.
func buildM4BelowThresholdExecute(client *PeerClient, operation, resourcePath string) (entity.Envelope, error, bool) {
	peerKP, _, err := crypto.LookupKeypairByPeerID(string(client.RemotePeerID()))
	if err != nil {
		return entity.Envelope{}, err, false
	}
	peerIdentity, err := peerKP.IdentityEntity()
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("build peer identity entity: %w", err), true
	}
	peerSigner := multiSigSigner{kp: peerKP, identity: peerIdentity}

	aux, err := makeNAuxSigners(2)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("setup: %w", err), true
	}
	// N=3, K=2, and the local peer is in the signer set and signs — so M3 is
	// structurally clean and M6 is satisfied. Only the peer signs, giving ONE
	// valid signature against a threshold of two: M4, and nothing else, is the
	// rule that denies this.
	signers := []multiSigSigner{peerSigner, aux[0], aux[1]}
	env, err := buildMultiSigExecuteOp(client, signers, 2, []multiSigSigner{peerSigner}, nil, operation, resourcePath)
	return env, err, true
}

// V3w — below threshold, driven against a WRITE. The §2.4a negative half for
// M4 on the path where conjuncts 2 and 3 are not vacuous.
//
// SAMPLED DELIBERATELY, AND SAID OUT LOUD (no silent caps). Before this row,
// all eleven checks in this category drove `get` from one hardcoded site, so
// the whole M3/M4/M6 surface was read-only — a peer that verifies joint
// authority on its read path and not its write path scored 11/11 and still
// accepted a forged joint authority to write. This closes the hole for the
// **M4 signature-count** class only: the one carrying the security
// consequence, and the one most often hoisted into a read-side authorization
// cache. The M3 structural rows and the M6 root-trust row remain read-only and
// are recorded as such here rather than left implied; extending them is the
// same three lines and is deliberately not done in this pass.
func checkMultiSigBelowThresholdWrite(ctx context.Context, client *PeerClient) CheckResult {
	const checkName = "below_threshold_denied_write"
	const specRef = "V7 §5.5 (multisig M4) + GUIDE-CONFORMANCE §2.4a"

	// A path we control, so conjunct 2+3 absence is directly assertable.
	const writePath = "system/validate/multisig-test"

	env, err, haveKey := buildM4BelowThresholdExecute(client, "put", writePath)
	if !haveKey {
		return skip(catMultiSig, checkName, specRef,
			"M4 isolation requires the peer's on-disk key (M6 must be satisfied before M4 is reachable): "+err.Error())
	}
	if err != nil {
		return fail(catMultiSig, checkName, specRef, err.Error())
	}
	return sendExpectStatus403Probed(ctx, client, env, checkName, specRef,
		&denyStateProbe{AbsentPath: writePath})
}

// V3 — below threshold (one valid signature against a threshold of two).
//
// CORRECTED 2026-08-12. This row previously built its cap from three aux
// signers with none of them the local peer, so §5.5's M6 root check denied it
// before the M4 threshold count ever ran: it was declared against M4, was
// observationally identical to `local_not_in_signers_rejected`, and passed
// unchanged when the threshold was SATISFIED. It now shares
// `buildM4BelowThresholdExecute` with the write row, which satisfies M6 so
// that M4 is the only rule left to deny it — see that function for how the
// mutation surfaced it.
//
// The cost of the correction is stated rather than hidden: isolating M4 needs
// the peer's own key, so this row now SKIPs against an ephemeral peer where it
// used to PASS. That is the honest reading — it was never measuring M4 on
// those peers either, and a skip is visible where a false pass is not.
func checkMultiSigBelowThreshold(ctx context.Context, client *PeerClient) CheckResult {
	const checkName = "below_threshold_rejected"
	const specRef = "V7 §5.5 (multisig M4)"

	env, err, haveKey := buildM4BelowThresholdExecute(client, "get", "system/type/system/peer")
	if !haveKey {
		return skip(catMultiSig, checkName, specRef,
			"M4 isolation requires the peer's on-disk key (M6 must be satisfied before M4 is reachable): "+err.Error())
	}
	if err != nil {
		return fail(catMultiSig, checkName, specRef, err.Error())
	}
	return sendExpectStatus403(client, env, checkName, specRef)
}
