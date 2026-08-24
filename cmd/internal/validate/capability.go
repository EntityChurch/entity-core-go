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
	"math/big"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
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
	r.Declare("hash_hex_path_segment_lowercase", "V7 §3.5 / RT-14 — a peer-emitted content-hash-hex tree path segment MUST be lowercase (format-code byte included); an uppercase segment self-loopbacks but fails cross-peer")
	// 0.8.1 CAP-1..CAP-7 fold (core-protocol 30ca731); GUIDE-CONFORMANCE §9 register (r),(t),(u),(v).
	r.Declare("configure_empty_grants_withdrawal", "V7 §6.2 CAP-2/CAP-3 (0.8.1) — configure MUST accept grants:[] and write it as the withdrawal form (present entry, empty grants; distinct from removal)")
	r.Declare("request_mint_temporal_ceiling", "V7 §6.2/§5.6 CAP-5 (0.8.1) — request over-long ttl_ms mints a CLAMPED token: 200 AND expires_at == MIN_DEFINED exactly (not a 403, not a `<=` check)")
	r.Declare("request_ttl_zero_and_overflow", "V7 §5.6 CAP-6 (0.8.1) — ttl_ms:0 = expire immediately (created_at, before caller cap); overflow term drops out (no wrap, no saturate)")
	r.Declare("configure_rejects_base58_partial_prefix", "V7 §6.2 CAP-7 (0.8.1) — partial prefixes rejected in the Base58 encoding too (a truncated peer-id + glob → 400)")
	r.Declare("ingest_rejects_unrepresentable_expiry", "V7 §6.2 CAP-6a INGEST (0.8.1; rust CAP-6b) — a RECEIVED token whose expires_at, not_before, OR created_at does not fit uint64 (bignum / negative / out of range) is malformed and MUST be refused via the capability_denied disposition (§5.2), NOT fail-open to never-expiring nor a silent decode drop")

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

	r.Run("hash_hex_path_segment_lowercase", func() CheckOutcome {
		// RT-14 (§3.5): content-hash hex in ANY tree path segment MUST be
		// lowercase, format-code byte included. Tree path segments are
		// case-sensitive, so an uppercase-hex segment self-loopbacks (a peer's
		// own writer and reader agree) but breaks cross-peer.
		//
		// The revoke marker at system/capability/revocations/{cap_hash_hex} is
		// a PEER-CHOSEN content-hash-hex segment: the client sends the token as
		// bytes; the peer picks the hex casing of the storage-path segment. We
		// probe the peer's own storage casing with two case-sensitive gets: the
		// marker MUST resolve at the lowercase segment and (segments being
		// case-sensitive) MUST NOT resolve at the uppercase one. This observes
		// where the PEER wrote, not a client-constructed lowercase path.
		out, ok := r.Require("revoke_happy_path_writes_marker")
		if !ok {
			return out
		}
		revoked, _ := r.Load("revoked_token_hash").(hash.Hash)
		if revoked.IsZero() {
			return SkipCheck("no revoked token recorded — cannot probe the peer-emitted hex segment")
		}
		lowerHex := hex.EncodeToString(revoked.Bytes())
		upperHex := strings.ToUpper(lowerHex)
		if upperHex == lowerHex {
			return SkipCheck("revoked token hex has no alpha nibbles — cannot distinguish case (astronomically unlikely for a 33-byte hash)")
		}
		lowerPath := "system/capability/revocations/" + lowerHex
		upperPath := "system/capability/revocations/" + upperHex
		if _, _, err := client.TreeGet(ctx, lowerPath); err != nil {
			return FailCheck(fmt.Sprintf("revocation marker did NOT resolve at the lowercase segment %s (%v) — the peer emitted a non-lowercase content-hash-hex path segment (RT-14 §3.5 violation)", lowerPath, err))
		}
		if _, _, err := client.TreeGet(ctx, upperPath); err == nil {
			return WarnCheck("revocation marker resolved at BOTH lowercase and UPPERCASE segments — the peer's tree-path lookup appears case-insensitive (§3.5 requires case-sensitive segments); cannot positively confirm lowercase-only emission")
		}
		return PassCheck("peer stored the revocation marker at the lowercase content-hash-hex segment and not the uppercase one — segment is lowercase and case-sensitive (RT-14 §3.5)")
	})

	// --- 0.8.1 CAP-1..CAP-7 fold checks (§9 register (r),(t),(u),(v)) ---

	// (r) CAP-2/CAP-3: configure MUST accept grants:[] and persist it as the
	// WITHDRAWAL form — a present policy entry with an empty grants array,
	// distinct from removal (which restores the `default` fallback). Written
	// under a SYNTHETIC hex pattern that never dials in: an empty entry under
	// the validator's own pattern (or "default") would suppress the validator's
	// own default ceiling and poison every later category's handshake reconnect
	// (see configure_writes_policy_entry). The dynamic leg — "an exact-match
	// empty entry suppresses `default` → a subsequent request from THAT peer
	// gets 403 scope_exceeds_authority" — keys on the requester's identity, so
	// exercising it needs a second authenticated peer and cannot run from one
	// connection without that poisoning. Here we pin CAP-2/CAP-3 structurally:
	// accept + readback of a present entry whose grants array is empty.
	r.Run("configure_empty_grants_withdrawal", func() CheckOutcome {
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants")
		}
		synthKP, _ := crypto.Generate()
		synthHash, _ := types.ComputePeerIdentityHashFromPeerID(synthKP.PeerID())
		synthHex := hex.EncodeToString(synthHash.Bytes())
		policy := types.CapabilityPolicyEntryData{
			PeerPattern: synthHex,
			Grants:      []types.GrantEntry{}, // the withdrawal form
			Notes:       "validate-peer CAP-2/CAP-3 empty-grants withdrawal",
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
		if respData.Status == 403 {
			return SkipCheck("configure refused 403 — validator identity does not hold a cap covering system/capability:configure")
		}
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("configure grants:[] returned %d — CAP-2 requires accepting the empty (withdrawal) form, not rejecting it", respData.Status))
		}
		policyPath := "system/capability/policy/" + synthHex
		entry, _, err := client.TreeGet(ctx, policyPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("tree get %s after configure: %v — the empty entry MUST be written (present), CAP-3", policyPath, err))
		}
		if entry.Type != types.TypeCapPolicyEntry {
			return FailCheck(fmt.Sprintf("entry at %s has type %s (expected %s)", policyPath, entry.Type, types.TypeCapPolicyEntry))
		}
		var readback types.CapabilityPolicyEntryData
		if err := ecf.Decode(entry.Data, &readback); err != nil {
			return FailCheck("decode policy readback: " + err.Error())
		}
		if len(readback.Grants) != 0 {
			return FailCheck(fmt.Sprintf("readback grants has %d entries — the empty write MUST persist as an empty grants array (CAP-3: the withdrawal form is a present, empty entry, distinct from removal)", len(readback.Grants)))
		}
		return PassCheck("configure accepted grants:[] and wrote a present policy entry with an empty grants array — CAP-2 withdrawal form, CAP-3 distinct from removal")
	})

	// (t) CAP-5: a request whose ttl_ms far exceeds the caller cap's expiry MUST
	// mint a CLAMPED token — 200, expires_at == MIN_DEFINED(caller, policy, req)
	// — not reject. The caller cap is built client-side with a known 1h expiry
	// (delegate is same-peer-only; a remote validator gets 501, so we present a
	// client-signed attenuated child cap instead). Assert the EXACT clamped
	// value: a `<= caller_exp` assertion scores clamp-and-mint identically to
	// reject-outright, which is exactly how this defect hid in two impls facing
	// opposite directions (core-rust raised this; core-go seconded it).
	r.Run("request_mint_temporal_ceiling", func() CheckOutcome {
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants")
		}
		callerExp := uint64(time.Now().UnixMilli()) + 3_600_000 // 1h — tighter than any plausible policy ttl
		childCap, childSig, err := buildChildCapWithExpiry(client, capRequestGrant(), callerExp)
		if err != nil {
			return FailCheck("build child cap: " + err.Error())
		}
		tenYears := uint64(315_360_000_000)
		status, minted, err := requestPresentingCap(client, uri, childCap, childSig, []types.GrantEntry{capRequestGrant()}, &tenYears)
		if err != nil {
			return FailCheck(err.Error())
		}
		if status == 403 {
			return FailCheck("over-long ttl_ms rejected (403) instead of clamping — CAP-5 requires minting a clamped token (200), not rejecting; this is the reject-direction defect")
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("expected 200, got %d", status))
		}
		if minted.ExpiresAt == nil {
			return FailCheck("minted token has no expires_at — MUST clamp to the caller cap's finite expiry (CAP-5)")
		}
		if *minted.ExpiresAt != callerExp {
			return FailCheck(fmt.Sprintf("minted expires_at=%d, expected exact MIN_DEFINED == caller_exp=%d — a `<= caller_exp` check would pass this; CAP-5 requires the exact clamped value (delta %d ms)", *minted.ExpiresAt, callerExp, int64(*minted.ExpiresAt)-int64(callerExp)))
		}
		return PassCheck(fmt.Sprintf("over-long request clamped to the caller cap exactly (expires_at=%d) and returned 200 — CAP-5", callerExp))
	})

	// (u) CAP-6: two wire-observable properties of MIN_DEFINED.
	//   1. ttl_ms == 0 is DEFINED and means expire immediately (created_at),
	//      NOT "no bound". With a caller cap expiring in 1h, the minted expiry
	//      MUST be strictly before the caller cap (≈ now). The pre-CAP-6 reading
	//      (0 == not defined) would clamp to the caller cap instead, so
	//      minted < caller_exp cleanly distinguishes the two.
	//   2. An overflowing created_at+ttl_ms term contributes NO ceiling — it
	//      drops out, leaving the finite caller cap as the mint expiry. A wrap
	//      would yield a past/earlier value < caller_exp; asserting == caller_exp
	//      proves the term was dropped, not wrapped. (Drop-vs-saturate is not
	//      wire-observable under §5.6's finite-parent chain rule — both give the
	//      caller cap here — so that half is pinned by go's unit
	//      TestClampMintExpiry, "overflow request ttl drops out → nil".)
	r.Run("request_ttl_zero_and_overflow", func() CheckOutcome {
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants")
		}
		// 1. ttl_ms == 0 → expire immediately.
		callerExp := uint64(time.Now().UnixMilli()) + 3_600_000
		childCap, childSig, err := buildChildCapWithExpiry(client, capRequestGrant(), callerExp)
		if err != nil {
			return FailCheck("build child cap (zero): " + err.Error())
		}
		zero := uint64(0)
		status, minted, err := requestPresentingCap(client, uri, childCap, childSig, []types.GrantEntry{capRequestGrant()}, &zero)
		nowAfter := uint64(time.Now().UnixMilli())
		if err != nil {
			return FailCheck("ttl_ms:0 " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("ttl_ms:0 expected 200, got %d", status))
		}
		if minted.ExpiresAt == nil {
			return FailCheck("ttl_ms:0 minted a token with nil expires_at — 0 must be a DEFINED ceiling (created_at), not the 'no bound' spelling (CAP-6 rule 2)")
		}
		if *minted.ExpiresAt >= callerExp {
			return FailCheck(fmt.Sprintf("ttl_ms:0 minted expires_at=%d is NOT before the caller cap %d — 0 was treated as 'no bound' (clamped to caller) instead of expire-immediately (CAP-6 rule 2)", *minted.ExpiresAt, callerExp))
		}
		if *minted.ExpiresAt > nowAfter+300_000 {
			return FailCheck(fmt.Sprintf("ttl_ms:0 minted expires_at=%d is far in the future — expected ≈ created_at (now)", *minted.ExpiresAt))
		}
		// 2. overflow term drops out.
		callerExp2 := uint64(time.Now().UnixMilli()) + 3_600_000
		childCap2, childSig2, err := buildChildCapWithExpiry(client, capRequestGrant(), callerExp2)
		if err != nil {
			return FailCheck("build child cap (overflow): " + err.Error())
		}
		overflow := ^uint64(0) - 10
		status2, minted2, err := requestPresentingCap(client, uri, childCap2, childSig2, []types.GrantEntry{capRequestGrant()}, &overflow)
		if err != nil {
			return FailCheck("overflow " + err.Error())
		}
		if status2 != 200 {
			return FailCheck(fmt.Sprintf("overflow ttl_ms expected 200, got %d", status2))
		}
		if minted2.ExpiresAt == nil {
			return FailCheck("overflow: minted expires_at is nil — the finite caller cap MUST bind once the overflowing term drops")
		}
		if *minted2.ExpiresAt != callerExp2 {
			return FailCheck(fmt.Sprintf("overflow: minted expires_at=%d, expected the caller cap %d — an overflowing created_at+ttl_ms MUST drop out (no wrap: a wrap yields an earlier value); CAP-6", *minted2.ExpiresAt, callerExp2))
		}

		// 3. overflow with NO other ceiling — the only wire condition that
		//    distinguishes "term absent" (correct → nil) from a WRAP/SATURATE/
		//    huge-finite encoding (e.g. an arbitrary-precision `created_at+ttl_ms`
		//    that never overflows → a bounded, non-nil expires_at). Constructible
		//    only when the caller cap has no finite expiry (else §5.6's null-child
		//    rule forbids it); the §4.4 connection cap is nil-expiry, so present it
		//    directly with an overflowing ttl and require the mint to carry NO
		//    expiry at all.
		strongProbe := ""
		if connCap, cErr := types.CapabilityTokenDataFromEntity(client.CapEntity()); cErr == nil && connCap.ExpiresAt == nil {
			grants := client.Grants()
			if len(grants) > 0 {
				params, pErr := types.CapabilityRequestData{Grants: grants[:1], TTLMs: &overflow}.ToEntity()
				if pErr != nil {
					return FailCheck("build no-ceiling overflow params: " + pErr.Error())
				}
				respEnv, _, sErr := client.SendExecute(ctx, uri, "request", params, nil)
				if sErr != nil {
					return FailCheck("no-ceiling overflow send: " + sErr.Error())
				}
				respData, dErr := types.ExecuteResponseDataFromEntity(respEnv.Root)
				if dErr != nil {
					return FailCheck("no-ceiling overflow decode response: " + dErr.Error())
				}
				if respData.Status == 200 {
					var resultEnt entity.Entity
					if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
						return FailCheck("no-ceiling overflow decode result: " + err.Error())
					}
					var grant types.CapabilityGrantData
					if err := ecf.Decode(resultEnt.Data, &grant); err != nil {
						return FailCheck("no-ceiling overflow decode grant: " + err.Error())
					}
					if tokenEnt, ok := respEnv.Included[grant.Token]; ok {
						td, tErr := types.CapabilityTokenDataFromEntity(tokenEnt)
						if tErr != nil {
							// An expires_at that does not fit uint64 IS the CAP-6 defect,
							// not a harness fault: the term was neither dropped nor
							// bounded — an arbitrary-precision created_at+ttl_ms that
							// never overflows. The minted token is not even wire-
							// decodable by a uint64 implementation.
							if strings.Contains(tErr.Error(), "overflow") || strings.Contains(tErr.Error(), "expires_at") {
								return FailCheck("overflow with a no-expiry caller cap minted an expires_at that OVERFLOWS uint64 — the overflowing created_at+ttl_ms term MUST be ABSENT (nil), not an arbitrary-precision huge value; the token is not wire-decodable by a uint64 impl. CAP-6. (" + tErr.Error() + ")")
							}
							return FailCheck("no-ceiling overflow decode minted token: " + tErr.Error())
						}
						if td.ExpiresAt != nil {
							return FailCheck(fmt.Sprintf("overflow with a no-expiry caller cap minted a BOUNDED expires_at=%d — the overflowing term MUST be ABSENT (nil), not wrapped, saturated, or a huge-finite value (e.g. arbitrary-precision created_at+ttl_ms). CAP-6", *td.ExpiresAt))
						}
						strongProbe = "; no-ceiling overflow minted NO expiry (term absent, not huge-finite/saturated)"
					}
				}
				// A non-200 here (peer refuses to mint a never-expiring token) is
				// not a CAP-6 violation — the absent-term property is then simply
				// not wire-observable on this peer; the child-cap assertion above
				// still pins no-wrap.
			}
		}
		return PassCheck("ttl_ms:0 mints an immediately-expired token (created_at, before the caller cap) and an overflowing ttl_ms drops out leaving the caller-cap ceiling — CAP-6" + strongProbe)
	})

	// (v) CAP-7: partial prefixes are rejected in the Base58 encoding too — not
	// just hex (configure_rejects_partial_prefix) and not just bare "*"
	// (policy_dual_form.poldf_configure_wildcard_rejected). A truncated real
	// peer-id with a trailing glob is a partial prefix in the Base58 form and
	// MUST be rejected at 400, never treated as a prefix match. The accepted
	// forms (hex, full Base58, "default") are covered by policy_dual_form.
	r.Run("configure_rejects_base58_partial_prefix", func() CheckOutcome {
		synthKP, _ := crypto.Generate()
		full := string(synthKP.PeerID())
		if len(full) < 12 {
			return SkipCheck("generated peer-id too short to form a partial prefix")
		}
		partial := full[:len(full)-4] + "*"
		policy := types.CapabilityPolicyEntryData{
			PeerPattern: partial,
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
			return FailCheck("configure accepted a partial-prefix Base58 peer_pattern — CAP-7 rejects partial prefixes in EITHER encoding")
		}
		if respData.Status == 403 {
			return SkipCheck("configure pattern check unreachable — validator identity refused at authz")
		}
		if respData.Status != 400 {
			return WarnCheck(fmt.Sprintf("configure rejected Base58 partial-prefix with %d; expected 400 invalid_params", respData.Status))
		}
		return PassCheck("configure rejected a partial-prefix Base58 peer_pattern with 400 — CAP-7 (partial prefixes rejected in either encoding)")
	})

	// CAP-6a INGEST (0.8.1; rust's "CAP-6b" — decode side). CAP-6's "an
	// unrepresentable temporal term MUST be absent" rule binds the MINTER; the
	// READER is where it fails OPEN. If a peer collapses an undecodable temporal
	// field to "no expiry" (a common decode-error → None path), a RECEIVED token
	// whose value does not fit uint64 — e.g. py's pre-fix bignum mint — becomes a
	// never-expiring capability on ingest. One token, two peers, two lifetimes;
	// fixing the mint does not recall tokens already issued. Every other CAP-6
	// check here is mint-side; this is the only one that drives the reader.
	//
	// CAP-6a (protocol d382d2c) binds ALL THREE temporal fields, not just
	// expires_at: "A capability token whose expires_at, not_before, or created_at
	// is not representable as primitive/uint — a bignum, a negative integer, or any
	// value outside the range — is malformed. A verifier MUST refuse it and MUST
	// NOT treat the unrepresentable field as absent." So this drives the full 3×2
	// field×shape matrix; a peer that refuses a bignum expires_at but fail-opens on
	// a bignum not_before/created_at would wrongly pass a single-field probe.
	// Refusal MUST be the capability_denied disposition of §5.2, "not a decode-layer
	// silent drop" — so the check tallies disposition (status-bearing refusal vs a
	// transport-level drop) and reports it in its own PASS message rather than
	// silently counting a transport timeout as a clean refusal. A present but
	// unrepresentable field MUST be refused; an ABSENT (null) expires_at stays legal
	// and is NOT exercised here.
	r.Run("ingest_rejects_unrepresentable_expiry", func() CheckOutcome {
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants")
		}
		// TEETH CONTROL (self-mutation): the same round-trip construction with a
		// NORMAL, representable expiry (and normal not_before-absent / created_at)
		// MUST be HONORED. This proves the token reaches the temporal validation as
		// an otherwise-valid cap — so a refusal of the hostile variants below is
		// attributable to the mutated field, not to a round-trip that corrupted the
		// granter/grantee/chain (which any peer would reject, making the check a
		// false pass). The three fields all decode through one
		// CapabilityTokenDataFromEntity path, so a single honored control witnesses
		// that path for every variant. If the control is not honored, the check
		// cannot distinguish fail-open from fail-closed on this peer and SKIPs
		// rather than passing. (py's pre-fix state is not directly testable from
		// here — the git boundary forbids checking out a sibling — so the teeth are
		// carried in-check.)
		normal := uint64(time.Now().UnixMilli()) + 3_600_000
		ctlTok, ctlSig, err := buildTokenWithRawTemporal(client, capRequestGrant(), "expires_at", normal)
		if err != nil {
			return FailCheck("build control token: " + err.Error())
		}
		ctlParams, err := types.CapabilityRequestData{Grants: []types.GrantEntry{capRequestGrant()}}.ToEntity()
		if err != nil {
			return FailCheck("build control params: " + err.Error())
		}
		ctlEnv, err := buildDelegatedExecute(client, ctlTok, ctlSig, uri, "request", ctlParams, nil)
		if err != nil {
			return FailCheck("build control execute: " + err.Error())
		}
		ctlResp, _, err := client.SendRawEnvelope(ctlEnv)
		if err != nil {
			return SkipCheck("control (round-tripped normal-temporal token) not deliverable — cannot attribute a hostile-token refusal to the mutated field: " + err.Error())
		}
		ctlData, err := types.ExecuteResponseDataFromEntity(ctlResp.Root)
		if err != nil {
			return FailCheck("decode control response: " + err.Error())
		}
		if !(ctlData.Status >= 200 && ctlData.Status < 300) {
			return SkipCheck(fmt.Sprintf("control (round-tripped normal-temporal token) was refused with status %d — the construction does not reach temporal validation on this peer, so a hostile-token refusal is not attributable to the mutated field; the check has no teeth here", ctlData.Status))
		}
		// Full field×shape matrix. Two undecodable-as-uint64 shapes, both must be
		// refused for EACH of the three CAP-6a temporal fields:
		//   over  — a bignum above 2^64 (the exact shape py's pre-fix mint emitted)
		//   under — a negative value (undecodable as uint64; "absent" would be
		//           WRONG here — negative means already-past, not never-expiring)
		over := new(big.Int).Add(new(big.Int).SetUint64(^uint64(0)), big.NewInt(1000))
		under := big.NewInt(-1)
		// Disposition tally (CAP-6a §5.2): a conformant refusal is the
		// capability_denied disposition (a status-bearing 4xx response); a
		// transport/decode-level drop is a refusal but NOT the required disposition
		// — surfaced so a silent-drop peer is visible, not counted as clean.
		denied, dropped := 0, 0
		for _, field := range []string{"expires_at", "not_before", "created_at"} {
			for _, tc := range []struct {
				name string
				raw  interface{}
			}{
				{">2^64 (bignum)", over},
				{"negative", under},
			} {
				tok, sig, err := buildTokenWithRawTemporal(client, capRequestGrant(), field, tc.raw)
				if err != nil {
					return FailCheck(fmt.Sprintf("build %s=%s token: %v", field, tc.name, err))
				}
				params, err := types.CapabilityRequestData{Grants: []types.GrantEntry{capRequestGrant()}}.ToEntity()
				if err != nil {
					return FailCheck("build request params: " + err.Error())
				}
				env, err := buildDelegatedExecute(client, tok, sig, uri, "request", params, nil)
				if err != nil {
					return FailCheck(fmt.Sprintf("build execute with %s=%s token: %v", field, tc.name, err))
				}
				respEnv, _, err := client.SendRawEnvelope(env)
				if err != nil {
					// A transport/decode-level rejection IS a refusal — the peer
					// declined to ingest the token — but it is not the §5.2
					// capability_denied disposition CAP-6a requires. Counted, not
					// treated as clean.
					dropped++
					continue
				}
				respData, derr := types.ExecuteResponseDataFromEntity(respEnv.Root)
				if derr != nil {
					return FailCheck(fmt.Sprintf("decode response (%s=%s): %v", field, tc.name, derr))
				}
				if respData.Status >= 200 && respData.Status < 300 {
					return FailCheck(fmt.Sprintf("peer HONORED a presented cap whose %s is %s — status %d. The undecodable temporal field was collapsed to 'no expiry' (fail-open), making a hostile token a never-expiring capability. CAP-6a ingest requires REFUSAL.", field, tc.name, respData.Status))
				}
				denied++
			}
		}
		disp := fmt.Sprintf("%d capability_denied, %d transport-drop", denied, dropped)
		if dropped > 0 {
			return WarnCheck(fmt.Sprintf("peer refused all 6 field×shape variants (expires_at/not_before/created_at × >2^64/negative) — CAP-6a ingest, not fail-open — but %s: a transport/decode drop is a refusal yet NOT the §5.2 capability_denied disposition CAP-6a mandates (\"not a decode-layer silent drop\")", disp))
		}
		return PassCheck(fmt.Sprintf("peer refused all 6 field×shape variants (expires_at/not_before/created_at × >2^64 bignum/negative) via the capability_denied disposition — CAP-6a ingest, not fail-open to never-expiring (%s)", disp))
	})

	return r.Results()
}

// buildTokenWithRawTemporal builds a client-signed child cap (chained to the
// connection cap, granter=grantee=us) that is structurally valid EXCEPT that the
// named temporal field (expires_at / not_before / created_at) carries a hostile,
// non-uint64-representable value (a bignum above 2^64, or a negative). It
// round-trips a valid token through a generic map and replaces only that one
// field, so every other field stays valid and a refusal is attributable to the
// mutated field rather than to a malformed granter/grantee/chain. Used by the
// CAP-6a ingest check: a conformant reader must refuse such a token, not collapse
// the undecodable field to "absent" (which, for expires_at, means never expires).
// Passing a representable value (e.g. a normal expiry) builds the honored teeth
// control.
func buildTokenWithRawTemporal(client *PeerClient, grant types.GrantEntry, field string, rawValue interface{}) (entity.Entity, entity.Entity, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	now := uint64(time.Now().UnixMilli())
	normalExp := now + 3_600_000
	base := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{grant},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &normalExp,
	}
	baseEnt, err := base.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, err
	}
	var m map[string]interface{}
	if err := ecf.Decode(baseEnt.Data, &m); err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("decode base token to map: %w", err)
	}
	m[field] = rawValue
	raw, err := ecf.Encode(m)
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("re-encode hostile token: %w", err)
	}
	tokenEnt, err := entity.NewEntity(types.TypeCapToken, cbor.RawMessage(raw))
	if err != nil {
		return entity.Entity{}, entity.Entity{}, err
	}
	sigEnt, err := signEntity(tokenEnt.ContentHash, kp, identity)
	if err != nil {
		return entity.Entity{}, entity.Entity{}, err
	}
	return tokenEnt, sigEnt, nil
}

// capRequestGrant is the narrow grant used by the CAP-5/CAP-6 mint-ceiling
// checks: authority over system/capability:request only. A client-built child
// cap carrying it can both invoke `request` and be the attenuation floor for a
// request asking for the same grant (a subset of itself).
func capRequestGrant() types.GrantEntry {
	return types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/capability"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
		Operations: types.CapabilityScope{Include: []string{"request"}},
	}
}

// buildChildCapWithExpiry builds a client-side attenuated child cap (chained to
// the connection cap, granter=grantee=us, signed by us) carrying `grant` and an
// explicit expires_at — the caller-cap expiry the request-mint temporal ceiling
// (CAP-5/CAP-6) clamps against. Mirrors buildAttenuatedChildCap but lets the
// caller pin the expiry. delegate is same-peer-only (a remote validator gets
// 501), so the cap is constructed and signed client-side rather than minted by
// the peer.
func buildChildCapWithExpiry(client *PeerClient, grant types.GrantEntry, expiresAt uint64) (entity.Entity, entity.Entity, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()
	now := uint64(time.Now().UnixMilli())
	td := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{grant},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &expiresAt,
	}
	return createCapabilityToken(td, kp, identity)
}

// requestPresentingCap sends a system/capability:request presenting childCap as
// the caller capability, asking for reqGrants with the given ttl_ms (nil omits
// the field). On 200 it returns the decoded minted token pulled from
// response.included — the CAP-5/CAP-6 checks must read the minted expires_at
// exactly. On a non-200 it returns the status and a nil token (no error), so the
// caller can distinguish a clamp-and-mint 200 from a reject 403.
func requestPresentingCap(client *PeerClient, uri string, childCap, childSig entity.Entity, reqGrants []types.GrantEntry, ttlMs *uint64) (uint, *types.CapabilityTokenData, error) {
	params, err := types.CapabilityRequestData{Grants: reqGrants, TTLMs: ttlMs}.ToEntity()
	if err != nil {
		return 0, nil, fmt.Errorf("build request params: %w", err)
	}
	env, err := buildDelegatedExecute(client, childCap, childSig, uri, "request", params, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build delegated request: %w", err)
	}
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return 0, nil, fmt.Errorf("send: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, nil, fmt.Errorf("decode EXECUTE_RESPONSE: %w", err)
	}
	if respData.Status != 200 {
		return respData.Status, nil, nil
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		return respData.Status, nil, fmt.Errorf("decode result entity: %w", err)
	}
	if resultEnt.Type != types.TypeCapGrant {
		return respData.Status, nil, fmt.Errorf("expected result type %s, got %s", types.TypeCapGrant, resultEnt.Type)
	}
	var grant types.CapabilityGrantData
	if err := ecf.Decode(resultEnt.Data, &grant); err != nil {
		return respData.Status, nil, fmt.Errorf("decode grant: %w", err)
	}
	tokenEnt, ok := respEnv.Included[grant.Token]
	if !ok {
		return respData.Status, nil, fmt.Errorf("minted token %s not in response.included", grant.Token)
	}
	td, err := types.CapabilityTokenDataFromEntity(tokenEnt)
	if err != nil {
		return respData.Status, nil, fmt.Errorf("decode minted token: %w", err)
	}
	return respData.Status, &td, nil
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
