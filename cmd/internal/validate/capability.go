// EXTENSION-V7-CAPABILITY (V7 v7.62 §6.2) — behavioral conformance for
// the system/capability handler. Manifest presence is already covered by
// the `handlers` category; this category drives request/revoke/configure/
// delegate over the wire and validates the result envelopes per V7 §6.2.
//
// V7 v7.62 amendment (arch commit 4b82043) promotes the handler from
// SHOULD to MUST: peers MUST implement request/revoke/configure/delegate
// and MUST surface 501 unsupported_operation for any other op on the
// registered handler. The vectors below cover the six §9 test-vector
// categories that GUIDE-CONFORMANCE §9 lists as the conformance pin:
//
//   1. subset-validation at request (against caller's cap AND policy)
//   2. revoke happy path (marker written; revoked cap rejected on use)
//   3. revoke authz (no granter-only carve-out)
//   4. configure (writes policy entry; rejects partial prefixes)
//   5. §4.4 union at authenticate-response
//      (deferred — needs a fresh handshake; see running log §5)
//   6. 501 distinction (unsupported_operation vs 404 vs 403)

package validate

import (
	"context"
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catCapability = "capability"

// runCapability drives the V7 §6.2 capability handler over the wire.
func runCapability(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catCapability)

	r.Declare("request_returns_grant", "V7 §6.2 request → system/capability/grant")
	r.Declare("request_token_signed_by_peer", "V7 §6.2 + §6.8 token grant signed by local peer identity")
	r.Declare("request_token_attenuated", "V7 §6.2 (may have narrower scope than requested) — peer-policy attenuation")
	r.Declare("request_rejects_scope_widening", "V7 §6.2 — handler MUST NOT grant scope exceeding caller's authorization")
	r.Declare("delegate_requires_parent_field", "V7 v7.62 §9 — delegate-request.parent MUST be non-zero")
	r.Declare("revoke_rejects_zero_token", "V7 v7.62 §10 + sanity — revoke-request.token MUST be non-zero")
	// V7 v7.62 §9 vectors — new in this cycle.
	r.Declare("unsupported_op_returns_501", "V7 v7.62 §6.2 status-code table — registered handler, unknown op → 501 (distinct from 404 handler_not_found / 403 capability_denied)")
	r.Declare("configure_writes_policy_entry", "V7 v7.62 §6.2 §4 + closeout F8 — configure → entry bound at system/capability/policy/{peer_pattern}; fallback segment is literal \"default\" (renamed from \"*\")")
	r.Declare("configure_rejects_partial_prefix", "V7 v7.62 §4 — partial-prefix peer_pattern (e.g. 00abc*) MUST be rejected at 400")
	r.Declare("revoke_happy_path_writes_marker", "V7 v7.62 §5 + §6 — revoke writes marker at system/capability/revocations/{cap_hash_hex} with handler-set revoked_at")
	r.Declare("revoked_cap_denied_on_use", "V7 v7.62 §5.1 is_revoked — presenting a revoked cap on a subsequent EXECUTE MUST be refused")
	r.Declare("delegate_remote_caller_returns_501", "V7 closeout F1 (§2.6) — delegate is same-peer-only in v1; a remote caller MUST receive 501 unsupported_operation (not 403)")

	uri := fmt.Sprintf("entity://%s/system/capability", client.RemotePeerID())

	r.Run("request_returns_grant", func() CheckOutcome {
		grants := client.Grants()
		if len(grants) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		params, err := types.CapabilityRequestData{Grants: grants[:1]}.ToEntity()
		if err != nil {
			return FailCheck("build request params: " + err.Error())
		}
		respEnv, _, err := client.SendExecute(ctx, uri, "request", params, nil)
		if err != nil {
			return FailCheck("send request: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("expected status 200, got %d", respData.Status))
		}
		var resultEnt entity.Entity
		if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
			return FailCheck("decode result entity: " + err.Error())
		}
		if resultEnt.Type != types.TypeCapGrant {
			return FailCheck(fmt.Sprintf("expected result type %s, got %s", types.TypeCapGrant, resultEnt.Type))
		}
		var grant types.CapabilityGrantData
		if err := ecf.Decode(resultEnt.Data, &grant); err != nil {
			return FailCheck("decode grant: " + err.Error())
		}
		if grant.Token.IsZero() {
			return FailCheck("grant.token is the zero hash")
		}
		r.Store("issued_token_hash", grant.Token)
		r.Store("response_included", respEnv.Included)
		return PassCheck(fmt.Sprintf("issued token %s", grant.Token.String()))
	})

	r.Run("request_token_signed_by_peer", func() CheckOutcome {
		out, ok := r.Require("request_returns_grant")
		if !ok {
			return out
		}
		issued := r.Load("issued_token_hash").(hash.Hash)
		included := r.Load("response_included").(map[hash.Hash]entity.Entity)
		tokenEnt, ok := included[issued]
		if !ok {
			return FailCheck("issued token entity not in response.included")
		}
		if tokenEnt.Type != types.TypeCapToken {
			return FailCheck(fmt.Sprintf("included token has type %s (expected %s)", tokenEnt.Type, types.TypeCapToken))
		}
		tokenData, err := types.CapabilityTokenDataFromEntity(tokenEnt)
		if err != nil {
			return FailCheck("decode included token: " + err.Error())
		}
		if !tokenData.Granter.IsSingle() {
			return FailCheck("issued token granter is not single-sig (peer-rooted token expected)")
		}
		granterHash, _ := tokenData.Granter.SingleHash()
		for _, ent := range included {
			if ent.Type != types.TypeSignature {
				continue
			}
			var sig types.SignatureData
			if err := ecf.Decode(ent.Data, &sig); err != nil {
				continue
			}
			if sig.Target == issued && sig.Signer == granterHash {
				return PassCheck("issued token has a signature by its granter in response.included")
			}
		}
		return FailCheck("no signature entity over the issued token by its granter found in included")
	})

	r.Run("request_token_attenuated", func() CheckOutcome {
		out, ok := r.Require("request_returns_grant")
		if !ok {
			return out
		}
		issued := r.Load("issued_token_hash").(hash.Hash)
		included := r.Load("response_included").(map[hash.Hash]entity.Entity)
		tokenEnt := included[issued]
		tokenData, err := types.CapabilityTokenDataFromEntity(tokenEnt)
		if err != nil {
			return FailCheck("decode included token: " + err.Error())
		}
		if len(tokenData.Grants) == 0 {
			return FailCheck("issued token has no grant entries")
		}
		caller := client.Grants()
		for i, child := range tokenData.Grants {
			covered := false
			for _, parent := range caller {
				if grantEntryCovers(parent, child) {
					covered = true
					break
				}
			}
			if !covered {
				return FailCheck(fmt.Sprintf("issued grant[%d] exceeds caller's authorized scope", i))
			}
		}
		return PassCheck("issued token's grants are a subset of the caller's authorized scope")
	})

	r.Run("request_rejects_scope_widening", func() CheckOutcome {
		// Attenuate-then-widen. Requesting `*` directly is vacuous when the
		// caller already holds `*` (the open-access / framework-admin case) —
		// nothing exceeds wildcard, so the old probe SKIPped and could never
		// pass under the standard identity. Instead, delegate a NARROW child
		// cap (authority over system/capability only), present it as the
		// request's authority, and from that narrow position ask for a wildcard
		// grant. The handler MUST refuse: the requested `handlers:[*]` exceeds
		// the presented cap's `handlers:[system/capability]` (§6.2:985 / §5.6 —
		// an issued grant MUST NOT exceed the caller's authorization). This
		// works regardless of how broad the connection identity is, because the
		// caller's authority for the request is the cap it presents.
		grants := client.Grants()
		if len(grants) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		narrow := types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/capability"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"request"}},
		}
		narrowCap, narrowSig, err := buildAttenuatedChildCap(client, narrow)
		if err != nil {
			return FailCheck("build narrow child cap: " + err.Error())
		}
		widened := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}}
		params, err := types.CapabilityRequestData{Grants: widened}.ToEntity()
		if err != nil {
			return FailCheck("build params: " + err.Error())
		}
		env, err := buildDelegatedExecute(client, narrowCap, narrowSig, uri, "request", params, nil)
		if err != nil {
			return FailCheck("build delegated request: " + err.Error())
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status >= 200 && respData.Status < 300 {
			return FailCheck(fmt.Sprintf("widening request returned success status %d — handler MUST refuse a grant exceeding the presented (narrow) capability", respData.Status))
		}
		return PassCheck(fmt.Sprintf("scope-widening from a narrow presented capability refused with status %d", respData.Status))
	})

	r.Run("delegate_requires_parent_field", func() CheckOutcome {
		// V7 v7.62 §9 swapped delegate's input from a token-via-resource-
		// target to a dedicated delegate-request type in params. A request
		// with a zero parent hash MUST be refused.
		//
		// Closeout F1 (§2.6) reorders the gate: the same-peer check fires
		// FIRST, so a remote caller (validate-peer is always remote)
		// receives 501 before the zero-parent validation runs. Accept 501
		// as PASS — it is the spec-correct outcome under the F1 ordering;
		// the same-peer happy path covers the zero-parent rejection.
		grants := client.Grants()
		if len(grants) == 0 {
			return SkipCheck("no authenticated grants")
		}
		params, err := (types.CapabilityDelegateRequestData{
			Parent: hash.Hash{},
			Grants: grants[:1],
		}).ToEntity()
		if err != nil {
			return FailCheck("build delegate-request: " + err.Error())
		}
		respEnv, _, err := client.SendExecute(ctx, uri, "delegate", params, nil)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status >= 200 && respData.Status < 300 {
			return FailCheck(fmt.Sprintf("delegate with zero parent returned success status %d (v7.62 §9 says parent is required)", respData.Status))
		}
		// 501 = closeout F1 same-peer gate fired first (correct ordering).
		if respData.Status == 501 {
			return PassCheck("delegate from remote caller refused with 501 — same-peer gate (closeout F1) preempts zero-parent validation, spec-correct ordering")
		}
		// 403 means the validator's cap doesn't cover delegate — auth gate
		// fires before payload validation, which is correct per the §6.2
		// status-code priority (501 > 403 > 400). The test cannot exercise
		// the zero-parent branch under that cap; SKIP rather than FAIL.
		if respData.Status == 403 {
			return SkipCheck("delegate refused 403 — validator's cap does not cover system/capability:delegate; cannot exercise the zero-parent branch")
		}
		// Pre-closeout impls (no F1 same-peer gate) hit parent validation:
		//   - 400 invalid_params (Go pre-F1 — SEC-18 zero-hash precedent).
		//   - 404 parent_not_found (Rust + Python — structural-check skip).
		// Both spec-conformant under v7.62 absent F1.
		if respData.Status == 400 || respData.Status == 404 {
			return PassCheck(fmt.Sprintf("delegate with zero parent refused with %d (pre-closeout-F1 ordering; F1-compliant impls return 501)", respData.Status))
		}
		return WarnCheck(fmt.Sprintf("delegate with zero parent returned %d; expected 501 (F1) or 400/404 (pre-F1)", respData.Status))
	})

	r.Run("delegate_remote_caller_returns_501", func() CheckOutcome {
		// Closeout F1 §2.6: delegate v1 is same-peer-only. Cross-peer
		// self-attenuation is structurally impossible (the handler signs
		// the child with the local keypair, which breaks §5.5 chain
		// validation when the caller is remote). A remote caller MUST
		// receive 501 unsupported_operation — the operation does not
		// exist on this handler in this dispatch context (caller authority
		// is irrelevant per §6.2 status-code semantics; this distinguishes
		// from 403 capability_denied).
		//
		// Validate-peer's identity is never the peer's local identity, so
		// it is always a remote caller. We submit a syntactically-valid
		// delegate-request (non-zero parent that LOOKS plausible — its
		// non-existence is irrelevant since the same-peer gate fires
		// first). Expect 501 regardless of whether the parent resolves.
		grants := client.Grants()
		if len(grants) == 0 {
			return SkipCheck("no authenticated grants")
		}
		// Construct a non-zero parent hash that will NOT match any stored
		// cap (synthetic content — the same-peer gate should fire before
		// parent lookup runs).
		fakeParent := hash.Hash{Algorithm: 0x12}
		for i := 0; i < hash.SHA256DigestSize; i++ {
			fakeParent.Digest[i] = byte(i + 1)
		}
		params, err := (types.CapabilityDelegateRequestData{
			Parent: fakeParent,
			Grants: grants[:1],
		}).ToEntity()
		if err != nil {
			return FailCheck("build delegate-request: " + err.Error())
		}
		respEnv, _, err := client.SendExecute(ctx, uri, "delegate", params, nil)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status == 501 {
			return PassCheck("remote delegate caller refused with 501 unsupported_operation — closeout F1 same-peer gate")
		}
		if respData.Status == 403 {
			// Pre-closeout-F1 impls returned 403 scope_exceeds_authority
			// for the cross-peer case. Flag it explicitly so the matrix
			// can see which impls have absorbed F1.
			return WarnCheck("remote delegate caller refused with 403 (pre-closeout-F1); F1-compliant impls return 501 unsupported_operation")
		}
		if respData.Status == 404 {
			return WarnCheck("remote delegate caller refused with 404 parent_not_found — same-peer gate (F1) did not fire; impl is leaking parent lookup to remote callers")
		}
		return FailCheck(fmt.Sprintf("remote delegate caller returned %d; expected 501 unsupported_operation per closeout F1", respData.Status))
	})

	r.Run("revoke_rejects_zero_token", func() CheckOutcome {
		// v7.62 §10: input type is now revoke-request, not the marker.
		params, err := (types.CapabilityRevokeRequestData{
			Token:  hash.Hash{},
			Reason: "validate-zero-token",
		}).ToEntity()
		if err != nil {
			return FailCheck("build params: " + err.Error())
		}
		respEnv, _, err := client.SendExecute(ctx, uri, "revoke", params, nil)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status >= 200 && respData.Status < 300 {
			return FailCheck(fmt.Sprintf("revoke with zero token returned success status %d", respData.Status))
		}
		if respData.Status == 403 {
			return SkipCheck("revoke refused 403 — validator's cap does not cover system/capability:revoke; cannot exercise the zero-token branch")
		}
		return PassCheck(fmt.Sprintf("revoke with zero token refused with status %d", respData.Status))
	})

	// ---------- V7 v7.62 new vectors ----------

	r.Run("unsupported_op_returns_501", func() CheckOutcome {
		// V7 v7.62 §6.2 status-code table:
		//   - 404 handler_not_found: no handler at pattern.
		//   - 501 unsupported_operation: handler exists, op does not.
		//   - 403 capability_denied: handler+op exist, cap insufficient.
		// We hit a registered handler (system/capability) with an op that
		// is NOT in the v7.62 manifest. Expect 501.
		grants := client.Grants()
		if len(grants) == 0 {
			return SkipCheck("no authenticated grants")
		}
		// Use a clearly-bogus op name unlikely to collide with any future op.
		params, err := types.CapabilityRequestData{Grants: grants[:1]}.ToEntity()
		if err != nil {
			return FailCheck("build params: " + err.Error())
		}
		respEnv, _, err := client.SendExecute(ctx, uri, "validate_peer_bogus_op", params, nil)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status == 501 {
			return PassCheck("unknown op on registered handler returned 501 unsupported_operation")
		}
		// 400 was the pre-v7.62 convention some impls may still emit;
		// flag explicitly so the divergence is visible.
		if respData.Status == 400 {
			return WarnCheck("unknown op returned 400 (pre-v7.62 convention); v7.62 §6.2 status-code table requires 501")
		}
		if respData.Status == 404 {
			return FailCheck("unknown op returned 404 — the v7.62 status-code table reserves 404 for handler_not_found; 501 distinguishes operation_unknown_on_registered_handler")
		}
		return FailCheck(fmt.Sprintf("unknown op returned %d; v7.62 §6.2 requires 501 unsupported_operation", respData.Status))
	})

	r.Run("configure_writes_policy_entry", func() CheckOutcome {
		// V7 v7.62 §4 + closeout F8: configure accepts a policy-entry;
		// handler binds it at system/capability/policy/{peer_pattern}.
		// We write under a SYNTHETIC hex pattern (a freshly-generated
		// keypair's identity hash) rather than the "default" fallback.
		// Writing under "default" would poison the policy ceiling for
		// every later category's handshake reconnect (handshake §8 unions
		// the default-policy grants into the new connection cap, the cap
		// hash drifts vs the initial handshake, and downstream
		// transport_family.r3a_cap_hash_stable_across_reconnect +
		// session.session_minted_matches_handshake fail spuriously).
		// The "default" literal acceptance is covered by
		// policy_dual_form.poldf_configure_default_accepted instead;
		// this test's job is just to verify configure WRITES the entry
		// at the canonical path.
		grants := client.Grants()
		if len(grants) == 0 {
			return SkipCheck("no authenticated grants")
		}
		synthKP, _ := crypto.Generate()
		synthHash, _ := types.ComputePeerIdentityHashFromPeerID(synthKP.PeerID())
		synthHex := hex.EncodeToString(synthHash.Bytes())
		policy := types.CapabilityPolicyEntryData{
			PeerPattern: synthHex,
			// Mirror the validator's OWN connection grants under "default"
			// so the policy ceiling can never gate the validator's own
			// requests on subsequent handshakes. A narrow grant here
			// (e.g. system/tree:get only) poisons every later category's
			// reconnect: the handshake §8 dual-form policy consultation
			// unions the narrow default grant into the new connection cap,
			// the cap hash changes vs the initial handshake, and downstream
			// transport_family.r3a_cap_hash_stable_across_reconnect +
			// session.session_minted_matches_handshake (which both depend
			// on cap-hash stability across reconnect with the same
			// identity) fail spuriously. Mirroring keeps the cap shape
			// identical across reconnects and tests configure's accept
			// path (status 200 + readback at the canonical path) just as
			// well — the test's job is to verify configure WRITES, not to
			// verify it can write something narrow.
			Grants: append([]types.GrantEntry(nil), grants...),
			Notes:  "validate-peer configure smoke",
		}
		params, err := policy.ToEntity()
		if err != nil {
			return FailCheck("build policy-entry: " + err.Error())
		}
		respEnv, _, err := client.SendExecute(ctx, uri, "configure", params, nil)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status != 200 {
			// Some peers gate configure behind a cap we may not have.
			// Report the cap-denial as a SKIP so the matrix distinguishes
			// "missing op" from "ACL refused for this validator identity."
			if respData.Status == 403 {
				return SkipCheck(fmt.Sprintf("configure refused 403 — validator identity does not hold a cap covering system/capability:configure (per V7 v7.62 §4 bootstrap is implementation-defined)"))
			}
			if respData.Status == 501 {
				return FailCheck("configure returned 501 — v7.62 §6.2 makes configure a MUST op on the registered handler")
			}
			if respData.Status == 404 {
				return FailCheck("configure returned 404 — v7.62 §6.2 makes configure a MUST op on the registered handler")
			}
			return FailCheck(fmt.Sprintf("configure returned status %d", respData.Status))
		}
		// Verify the entry is reachable at the canonical path.
		policyPath := "system/capability/policy/" + synthHex
		entry, _, err := client.TreeGet(ctx, policyPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree get %s after configure: %v", policyPath, err))
		}
		if entry.Type != types.TypeCapPolicyEntry {
			return FailCheck(fmt.Sprintf("entry at %s has type %s (expected %s)", policyPath, entry.Type, types.TypeCapPolicyEntry))
		}
		return PassCheck("configure wrote policy-entry at " + policyPath)
	})

	r.Run("configure_rejects_partial_prefix", func() CheckOutcome {
		// V7 v7.62 §4 + closeout F8: peer_pattern is exactly "default" or
		// 66 hex chars.
		// Partial prefixes (e.g., "00abc*") MUST be rejected — they open
		// a typo attack surface and have no meaning the operator can
		// reason about.
		policy := types.CapabilityPolicyEntryData{
			PeerPattern: "00abc*",
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/type/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
		}
		params, err := policy.ToEntity()
		if err != nil {
			return FailCheck("build policy-entry: " + err.Error())
		}
		respEnv, _, err := client.SendExecute(ctx, uri, "configure", params, nil)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status >= 200 && respData.Status < 300 {
			return FailCheck("configure accepted a partial-prefix peer_pattern; v7.62 §4 explicitly rejects partial prefixes")
		}
		if respData.Status == 403 {
			return SkipCheck("configure pattern check unreachable — validator identity refused at authz")
		}
		if respData.Status != 400 {
			return WarnCheck(fmt.Sprintf("configure rejected partial-prefix with %d; expected 400 invalid_params", respData.Status))
		}
		return PassCheck("configure rejected partial-prefix peer_pattern with 400")
	})

	r.Run("revoke_happy_path_writes_marker", func() CheckOutcome {
		// Use the token issued by request_returns_grant. Revoke it; verify
		// the marker entity is present at system/capability/revocations/
		// {cap_hash_hex} and carries handler-set revoked_at per §2a.
		out, ok := r.Require("request_returns_grant")
		if !ok {
			return out
		}
		issued := r.Load("issued_token_hash").(hash.Hash)
		params, err := (types.CapabilityRevokeRequestData{
			Token:  issued,
			Reason: "validate-peer revoke happy path",
		}).ToEntity()
		if err != nil {
			return FailCheck("build revoke-request: " + err.Error())
		}
		respEnv, _, err := client.SendExecute(ctx, uri, "revoke", params, nil)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		if respData.Status != 200 {
			if respData.Status == 403 {
				return SkipCheck("revoke refused 403 — validator's cap does not cover system/capability:revoke")
			}
			return FailCheck(fmt.Sprintf("revoke returned %d", respData.Status))
		}
		// Read the marker from the tree.
		markerPath := "system/capability/revocations/" + hex.EncodeToString(issued.Bytes())
		markerEnt, _, err := client.TreeGet(ctx, markerPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree get %s after revoke: %v", markerPath, err))
		}
		if markerEnt.Type != types.TypeCapRevocation {
			return FailCheck(fmt.Sprintf("entry at %s has type %s (expected %s)", markerPath, markerEnt.Type, types.TypeCapRevocation))
		}
		var marker types.CapabilityRevocationData
		if err := ecf.Decode(markerEnt.Data, &marker); err != nil {
			return FailCheck("decode marker: " + err.Error())
		}
		if marker.Token != issued {
			return FailCheck("marker.token does not match revoked cap")
		}
		if marker.RevokedAt == 0 {
			return FailCheck("marker.revoked_at is zero; v7.62 §2a requires handler-set wall-clock timestamp")
		}
		r.Store("revoked_token_hash", issued)
		return PassCheck(fmt.Sprintf("revoke wrote marker at %s with revoked_at=%d", markerPath, marker.RevokedAt))
	})

	r.Run("revoked_cap_denied_on_use", func() CheckOutcome {
		// V7 v7.62 §5.1: presenting a revoked cap on a subsequent EXECUTE
		// MUST surface as a denial. This is the integration test for the
		// is_revoked wire-in — peers that ship is_revoked as a primitive
		// but don't wire it into envelope verify will pass the prior
		// revoke_happy_path test but FAIL this one. That's the v7.62
		// verdict-determinism signal.
		out, ok := r.Require("revoke_happy_path_writes_marker")
		if !ok {
			return out
		}
		revoked, _ := r.Load("revoked_token_hash").(hash.Hash)
		if revoked.IsZero() {
			return SkipCheck("no revoked token recorded")
		}
		// The validator's CURRENT connection cap is the one revoke happy
		// path issued and then revoked. Any EXECUTE that depends on it
		// SHOULD now refuse. Use a cheap read against the tree handler
		// (covered by the original connection grant scope) but signed
		// using the now-revoked token. The easiest probe: re-attempt
		// request with the issued token presented as the auth cap.
		// However, the wire client uses its OWN cap (the original
		// auth cap), not the issued one — so the simplest verification
		// path is to delegate FROM the revoked cap and watch the receiver
		// reject the chain on revocation grounds.
		//
		// Build a child cap whose parent is the REVOKED token, present
		// the chain, and request a fresh grant. Expect 403 (the receiver
		// sees the chain root is revoked).
		issued := revoked
		// Resolve the issued token entity + signature from the prior
		// response.included.
		included := r.Load("response_included").(map[hash.Hash]entity.Entity)
		tokenEnt, ok := included[issued]
		if !ok {
			return SkipCheck("issued token entity not preserved across checks")
		}
		var sigEnt entity.Entity
		for _, e := range included {
			if e.Type != types.TypeSignature {
				continue
			}
			var sd types.SignatureData
			if ecf.Decode(e.Data, &sd) == nil && sd.Target == issued {
				sigEnt = e
				break
			}
		}
		if sigEnt.Type == "" {
			return SkipCheck("issued token signature not preserved across checks")
		}
		// Build a wire EXECUTE that presents the revoked token as its auth.
		// Any further dispatch using this token SHOULD return 403 on a
		// peer that has wired is_revoked into envelope verify.
		probeParams, err := types.CapabilityRequestData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/type/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
		}.ToEntity()
		if err != nil {
			return FailCheck("build probe params: " + err.Error())
		}
		env, err := buildDelegatedExecute(client, tokenEnt, sigEnt, uri, "request", probeParams, nil)
		if err != nil {
			return FailCheck("build probe envelope: " + err.Error())
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode EXECUTE_RESPONSE: " + err.Error())
		}
		// Decode the error code if present so the matrix sees the reason
		// (some impls reject via revocation marker check; some reject via
		// granter chain mismatch when the child's granter is the validator
		// but the EXECUTE author also equals the validator — different
		// path, same outcome).
		errCode := "(no error code)"
		var errData types.ErrorData
		if ecf.Decode(respData.Result, &errData) == nil && errData.Code != "" {
			errCode = errData.Code
		}
		if respData.Status == 200 {
			return FailCheck("presenting a revoked cap was accepted (status 200); v7.62 §5.1 requires is_revoked to deny on verify")
		}
		if respData.Status == 403 {
			return PassCheck(fmt.Sprintf("revoked cap refused with %d %s", respData.Status, errCode))
		}
		if respData.Status >= 400 {
			// Any 4xx/5xx is a rejection. Note the exact code for the
			// cross-impl notes — some impls might reject via chain-walk
			// failures rather than explicit is_revoked.
			return WarnCheck(fmt.Sprintf("revoked cap refused with %d %s — non-403 rejection; verify cross-impl path", respData.Status, errCode))
		}
		return WarnCheck(fmt.Sprintf("revoked cap returned %d %s; expected 403 capability_denied", respData.Status, errCode))
	})

	return r.Results()
}

// grantEntryCovers returns true if `parent` covers `child` — i.e. every
// dimension in child is a subset of the corresponding dimension in
// parent.
func grantEntryCovers(parent, child types.GrantEntry) bool {
	return scopeCovered(child.Handlers, parent.Handlers) &&
		scopeCovered(child.Resources, parent.Resources) &&
		scopeCovered(child.Operations, parent.Operations)
}

func scopeCovered(child, parent types.CapabilityScope) bool {
	for _, c := range child.Include {
		matched := false
		for _, p := range parent.Include {
			if patternCovers(p, c) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func patternCovers(pattern, target string) bool {
	if pattern == "*" || pattern == "/*/*" {
		return true
	}
	if pattern == target {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		if len(target) >= len(prefix) && target[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
