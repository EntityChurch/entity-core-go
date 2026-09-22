package validate

import (
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catResolutionIntegrity = "resolution_integrity"

// runResolutionIntegrity drives the K1 resolution-integrity forgery (§1.8 /
// §5.2a — 0.8.2.23). The `included` map is keyed by wire content hashes, and
// every authority lookup (author identity, capability, chain granter/signer,
// grantee) resolves an entity BY that key. Absent a binding of key ==
// content_hash({type,data}), an attacker who knows a victim's public identity
// hash — the grantee field of any capability the victim presents — files THEIR
// OWN system/peer under the victim's key; the peer then verifies the attacker's
// own signature against the attacker's own key while attributing it to the
// victim. Full impersonation, wielding the victim's own capability, no victim
// key needed.
//
// The canonical arm is the AUTHOR forgery: the wire vector below substitutes
// the attacker's identity under the connection identity's hash and signs the
// EXECUTE with the attacker's key. On a peer that does not bind the key it is
// ACCEPTED (200) and attributed to the victim; a conformant peer refuses it.
//
// Assert the STATUS, not just the refusal (arch ROUTING-2026-09-13-d §4.1): the
// three §5.2a resolution-integrity rows carry different codes (author → 401
// authentication_failed, capability/granter → 403 capability_denied, grantee →
// 401 unresolvable_grantee), and that divergence was live across three seats
// until the fold. A peer that BINDS THE KEY (mechanism a — go, entity-core-rust)
// detects a mis-addressed entry as a MAP-WIDE defect at the receive boundary and
// answers ONE verdict for every row; §5.2a states this uniform verdict is
// conformant and MUST NOT be required to differ (a key-DISCARDING peer sees the
// per-row miss instead). So this check asserts the forgery is REFUSED (never
// 200) and RECORDS the observed (status, code) for the cross-impl drive — it
// does not hard-fail go's uniform verdict.
//
// Two controls make the author-forgery refusal ATTRIBUTABLE to the key binding
// rather than to a generic signature check:
//   - positive control: the same request, correctly keyed and self-signed →
//     MUST succeed (200). Proves the request shape, cap and path are otherwise
//     valid, so the forgery's non-200 is the substitution being refused, not a
//     broken request.
//   - signer-mismatch control: the correct identity, correctly keyed, but the
//     EXECUTE signed by the attacker's key → MUST refuse. Proves the peer's
//     signature verification is live, so if the forgery arm were ACCEPTED it
//     would be the substituted key being trusted, not a skipped signature check.
func runResolutionIntegrity(ctx context.Context, newClient func() (*PeerClient, error)) []CheckResult {
	r := NewCheckRunner(catResolutionIntegrity)

	r.Declare("resolution_integrity_positive_control",
		"V7 §1.8/§5.2 (K1 anchor): a correctly-keyed, self-signed EXECUTE MUST succeed (200). Without this, the author-forgery arm's non-200 cannot be told from a generically broken request.")
	r.Declare("resolution_integrity_author_forgery",
		"V7 §1.8/§5.2a (K1, 0.8.2.23): the attacker's identity filed under the victim's author hash, EXECUTE signed by the attacker's key, MUST be REFUSED — a peer that resolves author BY the unverified key verifies the attacker's own signature and attributes it to the victim (impersonation, no victim key). Records the (status, code); §5.2a assigns the author row 401 authentication_failed, and a key-binding peer's uniform map-wide verdict is conformant.")
	r.Declare("resolution_integrity_signer_mismatch_control",
		"V7 §5.2a (K1 attributability): correct identity, correctly keyed, EXECUTE signed by the attacker's key MUST be refused. Proves signature verification is live, so an ACCEPTED author-forgery would be the substituted key being trusted, not a skipped check.")
	r.Declare("resolution_integrity_wrong_root_type_invalid_request",
		"ENTITY-CORE-PROTOCOL §3.3 / §4.11 (0.8.2.25 pre-admission refusal): a post-handshake frame whose ROOT entity is neither EXECUTE nor EXECUTE_RESPONSE (here a well-formed third-typed entity) MUST be refused 400 invalid_request with a coded frame — the pre-0.8.2.25 corpus mandated a bare close here, which §4.11 replaces (a bare close is indistinguishable from a network fault and, on a multiplexed connection, destroys unrelated admitted requests). The code is the CAUSE's (invalid_request), distinct from the resolution-integrity arm's hash_mismatch. Positive control: this category's self-signed EXECUTE succeeds (200), so the 400 here is attributable to the root TYPE, not a broken request. A silent drop / bare close (no coded frame) is the non-conformance.")

	// The author-forgery arm's refusal is a RECEIVE-boundary connection close
	// (go's validateRecv path), which is terminal for the connection. Run this
	// whole category on a DEDICATED, sacrificial client so the close never leaks
	// into the shared suite connection and breaks every later category. Requires
	// single-peer mode (newClient present); SKIP otherwise.
	// setupOutcome, if non-empty, is applied to all three arms (dedicated-client
	// setup failed). A SKIP when newClient is absent (multi-peer mode); a FAIL if
	// the dedicated connection or handshake could not be established.
	var client *PeerClient
	setupSkip := ""
	setupFail := ""
	if newClient == nil {
		setupSkip = "resolution_integrity needs a dedicated connection (single-peer mode / newClient); the forgery arm closes the connection and must not run on the shared suite connection"
	} else if c, err := newClient(); err != nil {
		setupFail = "new dedicated client: " + err.Error()
	} else {
		client = c
		defer client.Close()
		if cErr := client.Connect(ctx); cErr != nil {
			setupFail = "connect dedicated client: " + cErr.Error()
		} else if _, ok := runConnectivity(ctx, client); !ok {
			setupFail = "handshake on dedicated client failed"
		}
	}
	setupGate := func() (CheckOutcome, bool) {
		if setupSkip != "" {
			return SkipCheck(setupSkip), false
		}
		if setupFail != "" {
			return FailCheck(setupFail), false
		}
		return CheckOutcome{}, true
	}

	if client == nil {
		// No usable dedicated client — every arm degrades to the setup verdict.
		for _, name := range []string{
			"resolution_integrity_positive_control",
			"resolution_integrity_signer_mismatch_control",
			"resolution_integrity_author_forgery",
			"resolution_integrity_wrong_root_type_invalid_request",
		} {
			r.Run(name, func() CheckOutcome { out, _ := setupGate(); return out })
		}
		return r.Results()
	}

	remote := string(client.RemotePeerID())
	uri := fmt.Sprintf("entity://%s/system/tree", remote)

	// Legitimate connection identity + capability (the "victim": the server
	// knows this identity, and its hash is public in any cap it presents).
	victimKP := client.Keypair()
	victimIdentity := client.IdentityEntity()
	victimCap := client.CapEntity()

	// Attacker keypair — a real, valid identity the attacker controls but which
	// is NOT the victim. Minted once; reused across arms.
	attackerKP, akErr := crypto.Generate()
	var attackerIdentity entity.Entity
	if akErr == nil {
		attackerIdentity, akErr = attackerKP.IdentityEntity()
	}

	params, resource, pErr := buildSimpleGetParams()
	rawParams, rpErr := func() (cbor.RawMessage, error) {
		if pErr != nil {
			return nil, pErr
		}
		b, e := ecf.Encode(params)
		return cbor.RawMessage(b), e
	}()

	setupErr := ""
	switch {
	case akErr != nil:
		setupErr = "attacker keypair: " + akErr.Error()
	case pErr != nil:
		setupErr = "build get params: " + pErr.Error()
	case rpErr != nil:
		setupErr = "encode params: " + rpErr.Error()
	}
	gate := func() (CheckOutcome, bool) {
		if setupErr != "" {
			return FailCheck("setup: " + setupErr), false
		}
		return CheckOutcome{}, true
	}

	// authChain returns a fresh copy of the connection auth chain (cap + cap sig
	// + server identity) for an included map. Direct map entries, so the harness
	// controls the exact keying (Include would re-key by content hash).
	authChain := func() map[hash.Hash]entity.Entity {
		m := map[hash.Hash]entity.Entity{
			victimCap.ContentHash: victimCap,
		}
		for h, ent := range client.AuthenticateIncluded() {
			m[h] = ent
		}
		return m
	}

	// buildExec builds the base tree:get EXECUTE (author = victim, cap = victim's
	// connection cap) and a signature whose Signer FIELD is claimedSigner's hash
	// but whose bytes are produced by signKP. Every arm sets Author = victim, so
	// the signature's Signer field also names the victim — signer == author, and
	// the existing signer_author_mismatch check never fires. The three arms then
	// differ ONLY in (signKP, and what is filed under the victim's hash):
	//   - positive control : signKP=victim, included[victim]=victimIdentity   → 200
	//   - signer mismatch   : signKP=attacker, included[victim]=victimIdentity → sig fails
	//   - author forgery    : signKP=attacker, included[victim]=attackerIdentity → the
	//                         attacker's own key verifies its own signature; ONLY the
	//                         map-key binding (attackerIdentity.hash != victimHash)
	//                         catches it. This is the isolated K1 vector: it shares
	//                         signer==author with the control so nothing BUT the
	//                         binding distinguishes accept from refuse.
	buildExec := func(signKP crypto.Keypair, claimedSigner entity.Entity) (entity.Entity, entity.Entity, error) {
		execData := types.ExecuteData{
			RequestID:  client.NextRequestID(),
			URI:        uri,
			Operation:  "get",
			Params:     rawParams,
			Author:     victimIdentity.ContentHash,
			Capability: victimCap.ContentHash,
			Resource:   resource,
		}
		execEntity, err := execData.ToEntity()
		if err != nil {
			return entity.Entity{}, entity.Entity{}, err
		}
		execSig, err := signEntity(execEntity.ContentHash, signKP, claimedSigner)
		if err != nil {
			return entity.Entity{}, entity.Entity{}, err
		}
		return execEntity, execSig, nil
	}

	// sendClassify sends env and reports (status, code, closed). A go peer binds
	// the included map at validateRecv on the RECEIVE boundary (core/peer
	// connection.go serve()). N4 (0.8.2.24 §4.9(c)/§4.10(a)) RULED the
	// decode-boundary question arch had left open: a peer that refuses there MUST
	// put a coded frame on the wire (correlated by request_id where the root
	// decodes) before closing — go now emits 400 hash_mismatch (F79), then the
	// connection closes. This probe still accepts a bare close as a valid REFUSAL
	// (the denyOutcome/closeIsDeny precedent, security_chain.go) because the
	// property under test is that the FORGERY is refused, not accepted, and
	// keystone's five transport-drop peers have not yet adopted N4; the coded
	// (status, code) is recorded for the cross-impl drive. A separate wire vector
	// (KB-16 / rust's frame vector) gates N4's frame-shape conformance directly.
	sendClassify := func(env entity.Envelope) (status uint, code string, closed bool) {
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return 0, "", true
		}
		st, cd, _, dErr := extractStatusAndCode(respEnv)
		if dErr != nil {
			return 0, "", true
		}
		return st, cd, false
	}

	// (anchor) positive control: correct identity, self-signed → live 200. Runs
	// FIRST, while the connection is guaranteed open.
	r.Run("resolution_integrity_positive_control", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		execEntity, execSig, err := buildExec(victimKP, victimIdentity)
		if err != nil {
			return FailCheck("build exec: " + err.Error())
		}
		inc := authChain()
		inc[victimIdentity.ContentHash] = victimIdentity // correctly keyed
		inc[execSig.ContentHash] = execSig
		status, code, closed := sendClassify(entity.NewEnvelope(execEntity, inc))
		if closed {
			return FailCheck("positive control got no decodable response (connection closed) — a legitimate request of this shape must be honored, or the category is unattributable")
		}
		if status == 200 {
			return PassCheck("correctly-keyed self-signed EXECUTE succeeded (200) — the anchor: the forgery arm's refusal is attributable to the substitution")
		}
		return FailCheck(fmt.Sprintf("positive control did not succeed: status=%d code=%q", status, code))
	})

	// (attributability) signer mismatch: correct identity, correctly keyed, but
	// signed by the attacker. Fails at VerifyRequest DURING dispatch (hashes are
	// valid, so validateRecv passes and the connection stays open) → a graceful
	// non-200. Runs BEFORE the forgery arm, which closes the connection.
	r.Run("resolution_integrity_signer_mismatch_control", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		execEntity, execSig, err := buildExec(attackerKP, victimIdentity)
		if err != nil {
			return FailCheck("build exec: " + err.Error())
		}
		inc := authChain()
		inc[victimIdentity.ContentHash] = victimIdentity // correctly keyed
		inc[execSig.ContentHash] = execSig               // but signed by the attacker
		status, code, closed := sendClassify(entity.NewEnvelope(execEntity, inc))
		if closed {
			return PassCheck("signer mismatch refused (connection closed, fail-closed) — signature verification is live")
		}
		if status == 200 {
			return FailCheck("signer-mismatch control ACCEPTED (200): the peer honored a signature that does not verify against the resolved author — signature verification is not live, so the author-forgery result is unattributable")
		}
		return PassCheck(fmt.Sprintf("signer mismatch refused (status=%d code=%q) — signature verification is live, so an accepted forgery would be the substituted key being trusted", status, code))
	})

	// (pre-admission) wrong root type: a well-formed frame whose ROOT is a third
	// entity type (neither EXECUTE nor EXECUTE_RESPONSE nor a §6.5(b) reentry
	// grant) → MUST refuse 400 invalid_request with a coded frame, and the
	// connection MUST survive (the frame decoded whole; §4.9(c) forbids
	// destroying admitted in-flight requests over one bad frame). Runs BEFORE the
	// forgery arm because that arm closes the connection.
	r.Run("resolution_integrity_wrong_root_type_invalid_request", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		thirdType, err := entity.NewEntity("system/validate/preadmission", rawParams)
		if err != nil {
			return FailCheck("build third-type root: " + err.Error())
		}
		status, code, closed := sendClassify(entity.NewEnvelope(thirdType, nil))
		if closed {
			return FailCheck("wrong-root-type frame got no decodable coded response (bare close / silent drop) — the pre-0.8.2.25 non-conformance; §4.11 requires a coded 400 invalid_request frame")
		}
		if status == 400 && code == "invalid_request" {
			return PassCheck("wrong-root-type frame refused 400 invalid_request with a coded frame, connection survived (§4.11 pre-admission refusal; the positive control's 200 makes this attributable to the root type)")
		}
		if status == 200 {
			return FailCheck("wrong-root-type frame ACCEPTED (200): a non-EXECUTE/EXECUTE_RESPONSE root reached dispatch")
		}
		return FailCheck(fmt.Sprintf("wrong-root-type FAIL: got status=%d code=%q; want 400 invalid_request", status, code))
	})

	// (K1) author forgery: attacker identity under the victim's author hash,
	// signed by the attacker → MUST refuse. Runs LAST because go refuses it at
	// the receive boundary by closing the connection, which is terminal for the
	// shared client connection.
	r.Run("resolution_integrity_author_forgery", func() CheckOutcome {
		if out, ok := gate(); !ok {
			return out
		}
		execEntity, execSig, err := buildExec(attackerKP, victimIdentity)
		if err != nil {
			return FailCheck("build exec: " + err.Error())
		}
		inc := authChain()
		// THE FORGERY: the attacker's identity filed under the VICTIM's key.
		inc[victimIdentity.ContentHash] = attackerIdentity
		inc[execSig.ContentHash] = execSig
		status, code, closed := sendClassify(entity.NewEnvelope(execEntity, inc))
		if closed {
			return PassCheck("K1 forgery REFUSED fail-closed (connection closed at the receive-boundary binding check, no coded response) — the substitution is not resolved as the victim; access denied. N4 (0.8.2.24) makes the bare close non-conformant (a coded frame is now owed before close); a peer that has not yet adopted N4 still refuses the forgery, so this arm passes")
		}
		if status == 200 {
			return FailCheck("K1 FORGERY ACCEPTED (200): the peer resolved the author by the unverified included key, verified the attacker's signature against the attacker's substituted identity, and attributed the request to the victim — full impersonation")
		}
		switch status {
		case 401:
			return PassCheck(fmt.Sprintf("K1 forgery refused 401 code=%q (§5.2a author row / key-binding map-wide verdict)", code))
		case 403:
			return PassCheck(fmt.Sprintf("K1 forgery refused 403 code=%q (a key-binding peer's uniform authz-class verdict; §5.2a author row would be 401 for a key-discarding peer)", code))
		case 400:
			return PassCheck(fmt.Sprintf("K1 forgery refused 400 code=%q (§5.2a decode-boundary row; go's N4-conformant coded frame is 400 hash_mismatch, per F79)", code))
		default:
			return PassCheck(fmt.Sprintf("K1 forgery refused status=%d code=%q (not accepted); recorded for the cross-impl §5.2a status comparison", status, code))
		}
	})

	return r.Results()
}
