// V7 v7.71 §A4-AUTHZ — authorization-denial status+code matrix.
//
// Seven vectors that exercise the §5.2 / §6.2 / §5.5 authorization-path
// boundaries and pin the exact `(status, result.data.code)` pair v7.71
// requires. Cohort gate per REQUEST-COHORT-V767-BYTE-FIXTURES-AND-AGILITY-
// RECONCILIATION §A4-AUTHZ.
//
// What this category is for: V7 §3.3 establishes a two-level error model
// (status centralized in §3.3; codes domain-scoped). v7.71 ratifies a
// normative MUST that the authorization path SHALL NOT emit catch-all
// codes (e.g. `verification_failed`) — every DENY surfaces a defined
// authorization code. This file is the conformance vector that enforces
// that prose, exactly as the §4.7 connection vectors enforce theirs.
//
// Spec sources:
//   - V7 §3.3 (status registry) — 401 / 403 mapping with authz pointers
//   - V7 §5.2 (verify_request) — dispatch-level cap-coverage check
//   - V7 §5.5 (chain verify) — granter resolution + revocation cascade
//   - V7 §5.6 (validity) — expires_at maps to default `capability_denied`
//   - V7 §6.2 (cap handler) — `request` op subset-validation
//   - PR-3 (v7.39) — unresolvable_grantee single 401 carve-out
//   - PR-8.2 — delegate cap-coverage check
//   - EXTENSION-ROLE §5.5 — in-flight revocation cascade
//
// Overlap notes (per v7.71 §3.3 dedup):
//   - `AUTHZ-SCOPE-EXCEEDS-1` (m) overlaps with the existing capability.go
//     vector `request_rejects_scope_widening` (the (a) specialization).
//     (a) tests the cap-handler `request` op specifically; (m) covers the
//     general §6.2 dispatch-layer case. Authored once here; (a) remains.
//   - `AUTHZ-REVOKED-1` complements the existing capability.go vector
//     `revoked_cap_denied_on_use` (the (i) specialization). (i) verifies
//     the marker mechanism wires through; this vector pins the surfaced
//     status+code per v7.71.

package validate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catAuthz = "authz"

// runAuthz drives the v7.71 §A4-AUTHZ authorization-denial matrix.
func runAuthz(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catAuthz)

	r.Declare("authz_delegate_grant_1",
		"V7 v7.71 §A4-AUTHZ (AUTHZ-DELEGATE-GRANT-1): delegate without system/role:delegate grant (PR-8.2) MUST surface 403 capability_denied (not 501, not scope_exceeds_authority, not verification_failed)")
	// V7 v7.72 §9.0 carve-out: authz_delegate_grant_1 targets system/role
	// (EXTENSION-ROLE). Under --profile core a core peer 404s before the
	// PR-8.2 cap-coverage check fires (§6.5 resolution-first). The check
	// stays under --profile full; under --profile core it skips with
	// diagnostic in the runner below. §A4-AUTHZ scope-exceeds and
	// deny-default carry the core surface.
	r.Declare("authz_deny_default_1",
		"V7 v7.71 §A4-AUTHZ (AUTHZ-DENY-DEFAULT-1): generic verify_request DENY (cap does not cover op) MUST surface 403 capability_denied as the default authorization code")
	r.Declare("authz_scope_exceeds_1",
		"V7 v7.71 §A4-AUTHZ (AUTHZ-SCOPE-EXCEEDS-1): §6.2-dispatch-level request exceeds policy/caller authority MUST surface 403 scope_exceeds_authority (not capability_denied default)")
	r.Declare("authz_grantee_1",
		"V7 v7.71 §A4-AUTHZ (AUTHZ-GRANTEE-1): cap whose grantee does not resolve to a system/peer entity MUST surface 401 unresolvable_grantee (§5.2 / PR-3 single 401 carve-out — NOT 403 authentication_failed)")
	r.Declare("authz_revoked_1",
		"V7 v7.71 §A4-AUTHZ (AUTHZ-REVOKED-1) + RULING-CLASS-C: revoked cap presented on use MUST surface one of (403, capability_revoked) | (403, capability_denied) | (401, capability_revoked); first is RECOMMENDED when verifier has is_revoked semantic, third is the ROLE §5.5 T_old/T_new in-flight cascade carve-out")
	// V7 v7.72 §9.0 + RULING-CLASS-C-403-CAPABILITY-REVOKED-CORE:
	// three blessed surfaces for revoked-cap-on-use. (1) (403, capability_revoked)
	// — core, RECOMMENDED when the verifier knows the cap is revoked
	// (`is_revoked` returns true at the §5.2 step-4 rejection site); preserving
	// the revocation semantic is the v7.71 §3.3 line 900 "defined code where
	// one applies" principle. (2) (403, capability_denied) — core, legitimate
	// fallback when the verifier doesn't track the specific reason. (3)
	// (401, capability_revoked) — ROLE §5.5 in-flight cascade carve-out
	// (T_old yanked mid-EXECUTE → fail-fast retry). All three PASS. Outside
	// ROLE, (401, *) is the cascade-vocabulary footprint and remains PASS in
	// a ROLE-installed test env; the (403, verification_failed) catch-all
	// remains FAIL per v7.71's no-catch-all MUST.
	r.Declare("authz_revoked_core_1",
		"V7 v7.72 §9.0 + RULING-CLASS-C: revoked cap on use MUST surface one of (403, capability_revoked), (403, capability_denied), or (401, capability_revoked); first is RECOMMENDED when verifier has the is_revoked semantic, third is the ROLE §5.5 cascade carve-out")
	r.Declare("authz_no_catchall_1",
		"V7 v7.71 §A4-AUTHZ (AUTHZ-NO-CATCHALL-1): granter identity unresolvable during chain verify MUST surface 403 capability_denied (§5.5 `granter is null → DENY`) — explicit regression pin against the verification_failed catch-all")
	r.Declare("authz_expired_1",
		"V7 v7.71 §A4-AUTHZ (AUTHZ-EXPIRED-1): cap used after expires_at MUST surface 403 capability_denied as the default code (§5.6 / §5.2 validity — NOT a separate capability_expired string)")
	r.Declare("f40_id_scope_include_control",
		"V7 §5.2 / F40 — control row A (VECTOR-SPEC-2026-07-27): the include-only grant (NO exclude) MUST allow a real `get`. This is the positive control that isolates the exclude entry so a Row-B deny is attributable to canonicalization and not an unrelated policy deny.")
	r.Declare("f40_id_scope_exclude_literal",
		"V7 §5.2 / F40 — operations/peers are id-scope (literal match): an operations exclude \"/*/get\" is a literal string that MUST NOT be canonicalized as a §5.4 path and block a real `get`. Scored on the A→B differential (VECTOR-SPEC-2026-07-27): (ALLOW,ALLOW)=PASS literal · (ALLOW,DENY)=FAIL canonicalization · (DENY,DENY)=unrelated deny, not F40.")
	r.Declare("f40_id_scope_include_no_overgrant",
		"V7 §5.2 / F40 — a path-syntax operations include (probed across /*/get, /{local}/get, /*/*, /*/{peer}) matches only the literal op string; none may canonicalize as a path and over-grant a real `get` (reject-path complement; a canonicalizing peer wrongly allows at least one)")

	roleURI := fmt.Sprintf("entity://%s/system/role", client.RemotePeerID())
	treeURI := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())
	capURI := fmt.Sprintf("entity://%s/system/capability", client.RemotePeerID())

	r.Run("authz_delegate_grant_1", func() CheckOutcome {
		// V7 v7.72 §9.0 carve-out: targets system/role (EXTENSION-ROLE).
		// Under --profile core a core peer correctly 404s before the
		// PR-8.2 cap-coverage check fires.
		if client.Profile() == ProfileCore {
			return SkipCheck("V7 v7.72 §9.0 carve-out: targets system/role (extension); core peer 404s before PR-8.2 fires per §6.5 resolution-first. See v7.72 §A4-AUTHZ scope-exceeds + deny-default for the core surface.")
		}
		// PR-8.2 cap-coverage check: a delegate op without a cap covering
		// system/role:delegate MUST fire as 403 capability_denied at the
		// dispatch layer. We hold a narrow attenuated cap that covers
		// system/tree:get only — system/role is absent from the include
		// set. The handler is registered (501 ordering does not apply)
		// and the op exists (delegate is in the v7.62 role manifest).
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		narrow := types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/authz/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}
		narrowCap, narrowSig, err := buildAttenuatedChildCap(client, narrow)
		if err != nil {
			return FailCheck("build narrow child cap: " + err.Error())
		}
		// Syntactically-valid delegate-request — under v7.71 §A4-AUTHZ +
		// PR-8.2 the cap-coverage check fires at the dispatch layer before
		// any payload-level inspection. Delegate target is a placeholder
		// hash (the call should never reach the role handler's payload
		// validation).
		placeholderDelegate := hash.Hash{Algorithm: hash.AlgorithmSHA256}
		for i := range placeholderDelegate.Digest {
			placeholderDelegate.Digest[i] = byte(i + 1)
		}
		params, err := types.RoleDelegateRequestData{
			Delegate: placeholderDelegate,
			Context:  "system/validate/authz/ctx",
			Role:     "system/validate/authz/role",
			Scope: []types.GrantEntry{
				{Resources: types.CapabilityScope{Include: []string{"system/validate/authz/*"}}},
			},
		}.ToEntity()
		if err != nil {
			return FailCheck("build delegate-request: " + err.Error())
		}
		env, err := buildDelegatedExecute(client, narrowCap, narrowSig, roleURI, "delegate", params, nil)
		if err != nil {
			return FailCheck("build delegated execute: " + err.Error())
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		status, code, _, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("extract response: " + err.Error())
		}
		if status == 403 && code == "capability_denied" {
			return PassCheck("delegate without system/role:delegate grant refused with 403 capability_denied (v7.71 §A4-AUTHZ PR-8.2)")
		}
		if status == 403 && code == "scope_exceeds_authority" {
			return FailCheck(fmt.Sprintf("AUTHZ-DELEGATE-GRANT-1 FAIL: returned 403 %q; v7.71 pins capability_denied for the missing-grant case (scope_exceeds_authority is for over-broad asks under a covering cap, not a missing cap)", code))
		}
		if status == 403 && (code == "verification_failed" || code == "authentication_failed") {
			return FailCheck(fmt.Sprintf("AUTHZ-DELEGATE-GRANT-1 FAIL: returned 403 %q; v7.71 §3.3 prohibits catch-all defaults on the authz path — the authorization domain's defined code is `capability_denied`", code))
		}
		if status == 501 {
			return FailCheck("AUTHZ-DELEGATE-GRANT-1 FAIL: returned 501 — the system/role handler MUST be registered (501 is for unknown-op on a registered handler); cap-coverage check is missing or fires after op-existence")
		}
		return FailCheck(fmt.Sprintf("AUTHZ-DELEGATE-GRANT-1 FAIL: returned status=%d code=%q; v7.71 pins 403 capability_denied", status, code))
	})

	r.Run("authz_deny_default_1", func() CheckOutcome {
		// §5.2 / §6.2 dispatch-layer default: a cap whose scope does NOT
		// cover the target op surfaces 403 capability_denied. Use a narrow
		// cap that covers system/tree:get on a non-matching path; ask for
		// system/tree:get on a path the cap does not include. The handler
		// + op exist; what fails is the FindMatchingGrant subset check.
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		narrow := types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/authz/scoped/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}
		narrowCap, narrowSig, err := buildAttenuatedChildCap(client, narrow)
		if err != nil {
			return FailCheck("build narrow child cap: " + err.Error())
		}
		// Ask for a path outside the include set (system/type/ — clearly not
		// under system/validate/authz/scoped/).
		params, _, err := buildSimpleGetParams()
		if err != nil {
			return FailCheck("build params: " + err.Error())
		}
		resource := &types.ResourceTarget{Targets: []string{"system/type/system/peer"}}
		env, err := buildDelegatedExecute(client, narrowCap, narrowSig, treeURI, "get", params, resource)
		if err != nil {
			return FailCheck("build delegated execute: " + err.Error())
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		status, code, _, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("extract response: " + err.Error())
		}
		if status == 403 && code == "capability_denied" {
			return PassCheck("out-of-scope tree:get refused with 403 capability_denied (v7.71 §A4-AUTHZ default code)")
		}
		if status == 403 && (code == "verification_failed" || code == "authentication_failed") {
			return FailCheck(fmt.Sprintf("AUTHZ-DENY-DEFAULT-1 FAIL: returned 403 %q; v7.71 §3.3 prohibits catch-all defaults on the authz path — the authorization default code is `capability_denied`", code))
		}
		return FailCheck(fmt.Sprintf("AUTHZ-DENY-DEFAULT-1 FAIL: returned status=%d code=%q; v7.71 pins 403 capability_denied for the default-deny case", status, code))
	})

	r.Run("authz_scope_exceeds_1", func() CheckOutcome {
		// §6.2 cap-handler `request` op subset-validation: the presented
		// cap is narrow, the requested grant is broader. The cap-handler
		// MUST refuse with 403 scope_exceeds_authority. This is the
		// dispatch-layer general case; the cap-handler-row (a) vector
		// (`request_rejects_scope_widening`) is the specialization.
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		// Narrow presented cap: cap-handler request only.
		narrow := types.GrantEntry{
			Handlers:   types.CapabilityScope{Include: []string{"system/capability"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"request"}},
		}
		narrowCap, narrowSig, err := buildAttenuatedChildCap(client, narrow)
		if err != nil {
			return FailCheck("build narrow child cap: " + err.Error())
		}
		// Ask for a wildcard grant — exceeds the presented cap's narrow
		// handlers scope.
		widened := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}}
		params, err := types.CapabilityRequestData{Grants: widened}.ToEntity()
		if err != nil {
			return FailCheck("build cap-request params: " + err.Error())
		}
		env, err := buildDelegatedExecute(client, narrowCap, narrowSig, capURI, "request", params, nil)
		if err != nil {
			return FailCheck("build delegated execute: " + err.Error())
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		status, code, _, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("extract response: " + err.Error())
		}
		if status == 403 && code == "scope_exceeds_authority" {
			return PassCheck("widening cap-request under a narrow presented cap refused with 403 scope_exceeds_authority (v7.71 §A4-AUTHZ §6.2 specialization)")
		}
		if status == 403 && code == "capability_denied" {
			return WarnCheck(fmt.Sprintf("AUTHZ-SCOPE-EXCEEDS-1: returned 403 capability_denied — spec-defensible (default code), but v7.71 prefers the more-specific scope_exceeds_authority for §6.2 overscope; flag for cohort-side normalization"))
		}
		if status == 403 && (code == "verification_failed" || code == "authentication_failed") {
			return FailCheck(fmt.Sprintf("AUTHZ-SCOPE-EXCEEDS-1 FAIL: returned 403 %q; v7.71 §3.3 prohibits catch-all defaults on the authz path", code))
		}
		return FailCheck(fmt.Sprintf("AUTHZ-SCOPE-EXCEEDS-1 FAIL: returned status=%d code=%q; v7.71 pins 403 scope_exceeds_authority", status, code))
	})

	r.Run("authz_grantee_1", func() CheckOutcome {
		// PR-3 single 401 carve-out: a cap whose `grantee` does not resolve
		// to a system/peer entity in the wire envelope or local store MUST
		// be refused with 401 unresolvable_grantee. Construct a cap whose
		// grantee is a fresh random hash (not the validator identity, not
		// in included). Build the EXECUTE using that cap — chain walk
		// reaches the per-link grantee check (delegation.go §99) and fires
		// ErrUnresolvableGrantee.
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		kp := client.Keypair()
		identity := client.IdentityEntity()
		parentCap := client.CapEntity()
		now := uint64(time.Now().UnixMilli())
		fiveMin := now + 5*60*1000
		// Synthetic non-existent grantee hash (definitely not in the wire
		// envelope or store — fresh entropy).
		var bogusGrantee hash.Hash
		bogusGrantee.Algorithm = hash.AlgorithmSHA256
		for i := range bogusGrantee.Digest {
			bogusGrantee.Digest[i] = byte(0xC0 ^ i) // non-zero, won't resolve
		}
		td := types.CapabilityTokenData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
			Granter:   types.SingleSigGranter(identity.ContentHash),
			Grantee:   bogusGrantee, // <-- the unresolvable bit
			Parent:    &parentCap.ContentHash,
			CreatedAt: now,
			ExpiresAt: &fiveMin,
		}
		childCap, childSig, err := createCapabilityToken(td, kp, identity)
		if err != nil {
			return FailCheck("mint cap with bogus grantee: " + err.Error())
		}
		// Build EXECUTE using the bogus-grantee cap. ExecuteData.Author is
		// the validator's real identity (so author-sig verifies); the chain
		// walk reaches the cap's per-link grantee check and rejects.
		params, _, err := buildSimpleGetParams()
		if err != nil {
			return FailCheck("build params: " + err.Error())
		}
		env, err := buildDelegatedExecute(client, childCap, childSig, treeURI, "get",
			params, &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
		if err != nil {
			return FailCheck("build envelope: " + err.Error())
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		status, code, _, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("extract response: " + err.Error())
		}
		if status == 401 && code == "unresolvable_grantee" {
			return PassCheck("cap with unresolvable grantee refused with 401 unresolvable_grantee (v7.71 §A4-AUTHZ / PR-3 single 401 carve-out)")
		}
		if status == 403 && (code == "authentication_failed" || code == "capability_denied") {
			return FailCheck(fmt.Sprintf("AUTHZ-GRANTEE-1 FAIL: returned 403 %q; v7.71 §5.2 single 401 carve-out (PR-3) pins 401 unresolvable_grantee — the impl is lumping the unresolvable-grantee sentinel into a generic auth-class error", code))
		}
		return FailCheck(fmt.Sprintf("AUTHZ-GRANTEE-1 FAIL: returned status=%d code=%q; v7.71 pins 401 unresolvable_grantee", status, code))
	})

	r.Run("authz_revoked_1", func() CheckOutcome {
		// V7 v7.72 §9.0 carve-out: this check expects the EXTENSION-ROLE
		// §5.5 in-flight cascade vocabulary (401 capability_revoked).
		// A core peer's revoked-cap-on-use returns the §5.2 step-4
		// default (403 capability_denied) — confirmed by F19 §5.3 of
		// the v7.72 proposal. The core surface is asserted by
		// authz_revoked_core_1 below.
		if client.Profile() == ProfileCore {
			return SkipCheck("V7 v7.72 §9.0 carve-out: expects ROLE §5.5 401 capability_revoked (extension vocabulary). Core peer's revocation denial is 403 capability_denied (v7.71 §5.2 step-4 default); see authz_revoked_core_1.")
		}
		// EXTENSION-ROLE §5.5 in-flight cascade: a revoked cap presented on
		// use MUST surface 401 capability_revoked. Mint an attenuated child
		// cap, revoke it via the cap-handler, then use it on a fresh EXECUTE.
		// (Different from the capability.go `revoked_cap_denied_on_use`
		// vector — that one tests the marker-write mechanism; this one
		// tests the surfaced status+code per v7.71.)
		status, code, setup := stageRevokedCapProbe(ctx, client, capURI, treeURI)
		if setup != nil {
			return *setup
		}
		if status == 403 && code == "capability_revoked" {
			return PassCheck("revoked cap on use refused with 403 capability_revoked (RULING-CLASS-C RECOMMENDED core surface — verifier preserves is_revoked semantic)")
		}
		if status == 403 && code == "capability_denied" {
			return PassCheck("revoked cap on use refused with 403 capability_denied (RULING-CLASS-C legitimate core fallback when no specific reason tracked)")
		}
		if status == 401 && code == "capability_revoked" {
			return PassCheck("revoked cap on use refused with 401 capability_revoked (ROLE §5.5 in-flight cascade carve-out surface)")
		}
		if status == 403 && (code == "verification_failed" || code == "authentication_failed") {
			return FailCheck(fmt.Sprintf("AUTHZ-REVOKED-1 FAIL: returned 403 %q; v7.71 §3.3 prohibits catch-all defaults on the authz path", code))
		}
		return FailCheck(fmt.Sprintf("AUTHZ-REVOKED-1 FAIL: returned status=%d code=%q; RULING-CLASS-C blesses (403, capability_revoked) | (403, capability_denied) | (401, capability_revoked)", status, code))
	})

	// V7 v7.72 §9.0 + RULING-CLASS-C-403-CAPABILITY-REVOKED-CORE:
	// three blessed surfaces, all PASS. (403, capability_revoked) is the
	// recommended core surface when the verifier has the is_revoked semantic
	// (preserves information per v7.71 §3.3 line 900 — "defined code where
	// one applies"). (403, capability_denied) is the legitimate core fallback
	// when no specific reason is tracked. (401, capability_revoked) is the
	// ROLE §5.5 in-flight cascade vocabulary; conformant in a ROLE-installed
	// test env (the ROLE surface implies a revocation rejection path exists).
	// Catch-all `verification_failed` / `authentication_failed` remain FAIL
	// per v7.71's no-catch-all MUST.
	r.Run("authz_revoked_core_1", func() CheckOutcome {
		status, code, setup := stageRevokedCapProbe(ctx, client, capURI, treeURI)
		if setup != nil {
			return *setup
		}
		if status == 403 && code == "capability_revoked" {
			return PassCheck("revoked cap on use refused with 403 capability_revoked (RULING-CLASS-C: recommended core surface — verifier preserves the is_revoked semantic per v7.71 §3.3 line 900)")
		}
		if status == 403 && code == "capability_denied" {
			return PassCheck("revoked cap on use refused with 403 capability_denied (V7 §5.2 step-4 default; legitimate core fallback per RULING-CLASS-C)")
		}
		if status == 401 && code == "capability_revoked" {
			return PassCheck("revoked cap on use refused with 401 capability_revoked (ROLE §5.5 cascade surface; conformant in ROLE-installed env per RULING-CLASS-C)")
		}
		if status == 403 && (code == "verification_failed" || code == "authentication_failed") {
			return FailCheck(fmt.Sprintf("AUTHZ-REVOKED-CORE-1 FAIL: returned 403 %q; v7.71 §3.3 prohibits catch-all defaults on the authz path", code))
		}
		return FailCheck(fmt.Sprintf("AUTHZ-REVOKED-CORE-1 FAIL: returned status=%d code=%q; RULING-CLASS-C blesses (403, capability_revoked) | (403, capability_denied) | (401, capability_revoked)", status, code))
	})

	r.Run("authz_no_catchall_1", func() CheckOutcome {
		// §5.5 "granter is null → DENY" pin — the explicit regression pin
		// for the Rust verification_failed residual. A cap whose granter
		// identity hash does NOT appear in the wire envelope's included
		// (and is not in the local store) MUST be refused with 403
		// capability_denied — the authorization domain's defined default
		// code, NOT the catch-all verification_failed.
		//
		// Construct: a cap whose granter is a fresh foreign identity that
		// we deliberately DROP from included. The envelope carries the
		// cap but not the granter's system/peer entity. Chain walk: the
		// dispatcher's ResolveGranterPeerID (execute.go:161) fails to
		// resolve the granter, fires its 403 capability_denied path.
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		// Foreign keypair — we'll mint a self-loop cap rooted at this
		// keypair, then drop the foreign identity entity from included
		// so the granter is unresolvable on the receiver side.
		foreignKP, err := crypto.Generate()
		if err != nil {
			return FailCheck("generate foreign keypair: " + err.Error())
		}
		foreignIdentity, err := foreignKP.IdentityEntity()
		if err != nil {
			return FailCheck("foreign identity: " + err.Error())
		}
		now := uint64(time.Now().UnixMilli())
		fiveMin := now + 5*60*1000
		td := types.CapabilityTokenData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
			Granter:   types.SingleSigGranter(foreignIdentity.ContentHash),
			Grantee:   client.IdentityEntity().ContentHash,
			CreatedAt: now,
			ExpiresAt: &fiveMin,
		}
		capEnt, sigEnt, err := createCapabilityToken(td, foreignKP, foreignIdentity)
		if err != nil {
			return FailCheck("mint foreign-rooted cap: " + err.Error())
		}
		// Build EXECUTE with this cap. We INTENTIONALLY do not add
		// foreignIdentity to included — that's the bug-under-test on the
		// validator side, which the peer MUST surface as 403
		// capability_denied (not verification_failed).
		paramsEnt, _, err := buildSimpleGetParams()
		if err != nil {
			return FailCheck("build params: " + err.Error())
		}
		kp := client.Keypair()
		identity := client.IdentityEntity()
		rawParams, err := ecf.Encode(paramsEnt)
		if err != nil {
			return FailCheck("encode params: " + err.Error())
		}
		execData := types.ExecuteData{
			RequestID:  client.NextRequestID(),
			URI:        treeURI,
			Operation:  "get",
			Params:     cbor.RawMessage(rawParams),
			Author:     identity.ContentHash,
			Capability: capEnt.ContentHash,
			Resource:   &types.ResourceTarget{Targets: []string{"system/type/system/peer"}},
		}
		execEntity, err := execData.ToEntity()
		if err != nil {
			return FailCheck("build execute entity: " + err.Error())
		}
		execSig := kp.Sign(execEntity.ContentHash.Bytes())
		execSigData := types.SignatureData{
			Target:    execEntity.ContentHash,
			Signer:    identity.ContentHash,
			Algorithm: crypto.KeyTypeString(kp.KeyType),
			Signature: execSig,
		}
		execSigEnt, err := execSigData.ToEntity()
		if err != nil {
			return FailCheck("build execute signature: " + err.Error())
		}
		included := map[hash.Hash]entity.Entity{
			identity.ContentHash:   identity,
			capEnt.ContentHash:     capEnt,
			sigEnt.ContentHash:     sigEnt,
			execSigEnt.ContentHash: execSigEnt,
		}
		// NOTE: foreignIdentity intentionally omitted.
		env := entity.NewEnvelope(execEntity, included)
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		status, code, _, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("extract response: " + err.Error())
		}
		if status == 403 && code == "capability_denied" {
			return PassCheck("granter unresolvable refused with 403 capability_denied (v7.71 §A4-AUTHZ AUTHZ-NO-CATCHALL-1 regression pin)")
		}
		if status == 403 && code == "verification_failed" {
			return FailCheck("AUTHZ-NO-CATCHALL-1 FAIL: returned 403 verification_failed — this is exactly the v7.71 §3.3 catch-all default the proposal outlaws on the authz path; the authorization domain's defined code is `capability_denied`")
		}
		if status == 403 && code == "authentication_failed" {
			return FailCheck("AUTHZ-NO-CATCHALL-1 FAIL: returned 403 authentication_failed — granter-unresolvable is an authz-domain failure (§5.5), not an auth-class one; the impl is mis-routing the chain-walk failure")
		}
		return FailCheck(fmt.Sprintf("AUTHZ-NO-CATCHALL-1 FAIL: returned status=%d code=%q; v7.71 pins 403 capability_denied", status, code))
	})

	r.Run("authz_expired_1", func() CheckOutcome {
		// §5.6 + §5.2 validity: a cap whose expires_at is in the past MUST
		// be refused with 403 capability_denied — NOT a separate
		// capability_expired string. v7.71 §A4-AUTHZ pins that expiry
		// surfaces as the default authorization code.
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		kp := client.Keypair()
		identity := client.IdentityEntity()
		parentCap := client.CapEntity()
		now := uint64(time.Now().UnixMilli())
		// 1 hour in the past.
		past := now - uint64(time.Hour.Milliseconds())
		notBefore := past - uint64(time.Minute.Milliseconds())
		expiresAt := past // expires_at < now → expired
		td := types.CapabilityTokenData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
			Granter:   types.SingleSigGranter(identity.ContentHash),
			Grantee:   identity.ContentHash,
			Parent:    &parentCap.ContentHash,
			CreatedAt: past - uint64(2*time.Minute.Milliseconds()),
			NotBefore: &notBefore,
			ExpiresAt: &expiresAt,
		}
		expiredCap, expiredSig, err := createCapabilityToken(td, kp, identity)
		if err != nil {
			return FailCheck("mint expired cap: " + err.Error())
		}
		params, _, err := buildSimpleGetParams()
		if err != nil {
			return FailCheck("build params: " + err.Error())
		}
		env, err := buildDelegatedExecute(client, expiredCap, expiredSig, treeURI, "get",
			params, &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
		if err != nil {
			return FailCheck("build delegated execute: " + err.Error())
		}
		respEnv, _, err := client.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send: " + err.Error())
		}
		status, code, _, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("extract response: " + err.Error())
		}
		if status == 403 && code == "capability_denied" {
			return PassCheck("expired cap on use refused with 403 capability_denied (v7.71 §A4-AUTHZ — expiry uses the default code, NOT a separate capability_expired string)")
		}
		if status == 403 && code == "capability_expired" {
			return FailCheck("AUTHZ-EXPIRED-1 FAIL: returned 403 capability_expired; v7.71 §A4-AUTHZ explicitly pins that expiry uses the default `capability_denied` code (no separate capability_expired string)")
		}
		if status == 403 && (code == "verification_failed" || code == "authentication_failed") {
			return FailCheck(fmt.Sprintf("AUTHZ-EXPIRED-1 FAIL: returned 403 %q; v7.71 §3.3 prohibits catch-all defaults on the authz path — the authorization domain's defined code is `capability_denied`", code))
		}
		return FailCheck(fmt.Sprintf("AUTHZ-EXPIRED-1 FAIL: returned status=%d code=%q; v7.71 pins 403 capability_denied", status, code))
	})

	r.Run("f40_id_scope_include_control", func() CheckOutcome {
		// F40 control Row A (VECTOR-SPEC-2026-07-27): the exact Row-B grant
		// MINUS the exclude entry — an operations include of only "get" over
		// cross-peer resources "/*/*". With no exclude in play, a `get` MUST be
		// ALLOWED on any conformant peer regardless of how it matches id-scope.
		// This row establishes the positive baseline so that Row B's deny (if
		// any) is attributable to the exclude entry alone, not to some
		// unrelated policy. A deny here means the differential is unattributable
		// (DENY,* = not an F40 canonicalization defect), so this is WARN, not a
		// canonicalization FAIL.
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		allowA, statusA, codeA, err := probeF40Row(client, treeURI, false)
		if err != nil {
			return FailCheck("F40 control row A: " + err.Error())
		}
		det := map[string]any{"row": "A", "status": statusA, "code": codeA, "allow": allowA}
		if allowA {
			return PassCheck("F40 control row A: include-only grant (no exclude) ALLOWED a `get` — positive baseline holds; Row B's verdict is now attributable to the exclude entry (VECTOR-SPEC-2026-07-27)").WithDetails(det)
		}
		return WarnCheck(fmt.Sprintf("F40 control row A: include-only grant (no exclude) DENIED a `get` (status=%d code=%q) — the baseline itself refuses, so the exclude-row differential is unattributable to id-scope typing (DENY,* = not an F40 canonicalization defect). Investigate the unrelated deny before scoring F40.", statusA, codeA)).WithDetails(det)
	})

	r.Run("f40_id_scope_exclude_literal", func() CheckOutcome {
		// F40 (§5.2 id-scope grammar): operations/peers are id-scope
		// dimensions matched as LITERAL strings (only bare "*" and a trailing
		// "/*"), NOT through §5.4 path canonicalization. The highest-value
		// accept-path row: an operations EXCLUDE of "/*/get". Read literally,
		// "/*/get" is an operation string that does not equal "get", so the
		// exclude does NOT fire and a `get` is ALLOWED. A peer that routes
		// id-scope through path canonicalization reads "/*/get" as
		// /{any-peer}/get, matches the request, and wrongly DENIES.
		//
		// Scored on the A→B DIFFERENTIAL (VECTOR-SPEC-2026-07-27), not Row B's
		// deny in isolation: the exclude entry is the ONLY variable between the
		// control (Row A, include-only) and this probe (Row B, include+exclude),
		// so a verdict flip is attributable to it and nothing else. A bare 403
		// can arise from any unrelated policy; without the control it cannot be
		// pinned to canonicalization (this is the confound that false-positived
		// swift). Attribution:
		//   (ALLOW,ALLOW) = literal matcher, exclude never fires → PASS
		//   (ALLOW,DENY)  = the exclude entry alone flipped the verdict → FAIL, cause=canonicalization
		//   (DENY,DENY)   = baseline denies regardless → unrelated deny, NOT an F40 defect → WARN (exonerate)
		//   (DENY,ALLOW)  = adding an exclude widened access → incoherent → WARN (harness/setup error)
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		// Resources use the cross-peer "/*/*" pattern (pass-through absolute
		// canonicalization → covers the responder's subtree), NOT bare "*".
		// Bare "*" canonicalizes against the child cap's GRANTER (this client,
		// per PR-8) → /{client}/*, which never covers the responder's
		// namespace and would 403 on the RESOURCE dimension — confounding the
		// operations-exclude signal. "/*/*" ⊆ the open-access parent's
		// {"*","/*/*"}, so only the operations exclude is the variable.
		allowA, statusA, codeA, err := probeF40Row(client, treeURI, false)
		if err != nil {
			return FailCheck("F40 row A (control): " + err.Error())
		}
		allowB, statusB, codeB, err := probeF40Row(client, treeURI, true)
		if err != nil {
			return FailCheck("F40 row B (exclude): " + err.Error())
		}
		det := map[string]any{
			"rowA": map[string]any{"status": statusA, "code": codeA, "allow": allowA},
			"rowB": map[string]any{"status": statusB, "code": codeB, "allow": allowB},
		}
		switch {
		case allowA && allowB:
			return PassCheck(fmt.Sprintf("F40 (ALLOW,ALLOW): operations exclude \"/*/get\" did NOT block a `get` (A=%d, B=%d) — id-scope matched literally, not canonicalized as a path (§5.2 accept-path)", statusA, statusB)).WithDetails(det)
		case allowA && !allowB:
			return FailCheck(fmt.Sprintf("F40 FAIL (ALLOW,DENY) cause=canonicalization: `get` was ALLOWED without an exclude (A=%d) but DENIED with exclude:[\"/*/get\"] (B=%d %s) — the exclude entry, and only it, flipped the verdict, so the peer canonicalized an id-scope entry as a §5.4 path (§5.2). Fix: branch the matcher on scope kind — id-scope compares literally (only bare \"*\" + trailing \"/*\"); path-scope canonicalizes.", statusA, statusB, codeB)).WithDetails(det)
		case !allowA && !allowB:
			return WarnCheck(fmt.Sprintf("F40 (DENY,DENY) unrelated-deny: the baseline denies regardless of the exclude (A=%d %s, B=%d %s) — the deny is UNRELATED to id-scope typing and is NOT an F40 canonicalization defect (exonerate; not scored as F40). Investigate the unrelated deny separately.", statusA, codeA, statusB, codeB)).WithDetails(det)
		default: // !allowA && allowB
			return WarnCheck(fmt.Sprintf("F40 (DENY,ALLOW) harness/setup error: adding an exclude WIDENED access (A=%d %s denied, B=%d allowed) — incoherent; excludes only narrow. Do not score; investigate the harness/setup.", statusA, codeA, statusB)).WithDetails(det)
		}
	})

	r.Run("f40_id_scope_include_no_overgrant", func() CheckOutcome {
		// F40 reject-path complement: an operations INCLUDE carrying path
		// syntax matches only the literal operation string — which no real op
		// equals — so it authorizes NOTHING and a `get` is DENIED. A peer that
		// canonicalizes id-scope reads the pattern as a §5.4 path, matches the
		// `get`, and OVER-GRANTS. Conformant → deny (4xx) for every shape;
		// canonicalizing → 2xx on at least one. The packet names four
		// over-grant shapes; probe all so a peer that canonicalizes on any of
		// them (not just "/*/get") is caught. Robust to parent scope: a
		// conformant peer denies whether by literal op-mismatch or chain
		// subset-validation; only a canonicalizing peer reaches 2xx. Resources
		// use cross-peer "/*/*" (see the exclude-literal row) so the RESOURCE
		// dimension covers the target and the operations include is the sole
		// variable.
		if len(client.Grants()) == 0 {
			return SkipCheck("no authenticated grants to attenuate from")
		}
		localID := string(client.RemotePeerID())
		shapes := []struct{ name, pattern string }{
			{"interior_peer_wildcard", "/*/get"},            // matches /{any}/get
			{"leading_slash_local", "/" + localID + "/get"}, // §5.4 absolute universal-ish scope
			{"full_path_wildcard", "/*/*"},                  // matches any /{peer}/*
			{"trailing_peer_segment", "/*/" + localID},      // interior wildcard + trailing peer id
		}
		var passed []string
		for _, s := range shapes {
			child := types.GrantEntry{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
				Operations: types.CapabilityScope{Include: []string{s.pattern}},
			}
			childCap, childSig, err := buildAttenuatedChildCap(client, child)
			if err != nil {
				return FailCheck("build child cap (" + s.name + "): " + err.Error())
			}
			params, resource, err := buildSimpleGetParams()
			if err != nil {
				return FailCheck("build params: " + err.Error())
			}
			env, err := buildDelegatedExecute(client, childCap, childSig, treeURI, "get", params, resource)
			if err != nil {
				return FailCheck("build delegated execute (" + s.name + "): " + err.Error())
			}
			respEnv, _, err := client.SendRawEnvelope(env)
			if err != nil {
				return FailCheck("send (" + s.name + "): " + err.Error())
			}
			status, code, _, err := extractStatusAndCode(respEnv)
			if err != nil {
				return FailCheck("extract response (" + s.name + "): " + err.Error())
			}
			if status >= 200 && status < 300 {
				return FailCheck(fmt.Sprintf("F40 FAIL: `get` ALLOWED (2xx) under an operations include of only %q [%s] — the peer canonicalized an id-scope pattern as a §5.4 path and OVER-GRANTED. A path-syntax operation string no real op equals must authorize nothing (§5.2).", s.pattern, s.name))
			}
			if status >= 400 {
				passed = append(passed, fmt.Sprintf("%s=%d/%s", s.name, status, code))
				continue
			}
			return WarnCheck(fmt.Sprintf("F40: shape %s (%q) expected a denial (4xx) but got status=%d code=%q — investigate before scoring", s.name, s.pattern, status, code))
		}
		return PassCheck("`get` DENIED under all four path-syntax operations includes (" + strings.Join(passed, ", ") + ") — id-scope matched literally, no path over-grant (F40 §5.2)")
	})

	return r.Results()
}

// stageRevokedCapProbe mints a child cap via the cap-handler `request`
// op, revokes it, then presents the revoked cap on a fresh EXECUTE
// against the tree handler. Returns the probe response (status, code)
// or a setup outcome (SKIP for missing prerequisites, FAIL for hard
// errors). Shared between authz_revoked_1 (extension surface) and
// authz_revoked_core_1 (core surface); the two callers only differ on
// how they interpret the (status, code) pair per V7 v7.71 + v7.72 §9.0.
func stageRevokedCapProbe(ctx context.Context, client *PeerClient, capURI, treeURI string) (uint, string, *CheckOutcome) {
	if len(client.Grants()) == 0 {
		out := SkipCheck("no authenticated grants to attenuate from")
		return 0, "", &out
	}
	grants := client.Grants()
	params, err := types.CapabilityRequestData{Grants: grants[:1]}.ToEntity()
	if err != nil {
		out := FailCheck("build cap-request params: " + err.Error())
		return 0, "", &out
	}
	respEnv, _, err := client.SendExecute(ctx, capURI, "request", params, nil)
	if err != nil {
		out := FailCheck("send cap-request: " + err.Error())
		return 0, "", &out
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		out := FailCheck("decode cap-request response: " + err.Error())
		return 0, "", &out
	}
	if respData.Status != 200 {
		out := SkipCheck(fmt.Sprintf("cap-request setup returned %d; revoked-cap probe needs a peer-minted cap to revoke", respData.Status))
		return 0, "", &out
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		out := FailCheck("decode result entity: " + err.Error())
		return 0, "", &out
	}
	var grant types.CapabilityGrantData
	if err := ecf.Decode(resultEnt.Data, &grant); err != nil {
		out := FailCheck("decode grant: " + err.Error())
		return 0, "", &out
	}
	issued := grant.Token
	revokeParams, err := types.CapabilityRevokeRequestData{
		Token:  issued,
		Reason: "AUTHZ-REVOKED probe v7.72 §9.0 / v7.71 §A4-AUTHZ",
	}.ToEntity()
	if err != nil {
		out := FailCheck("build revoke-request: " + err.Error())
		return 0, "", &out
	}
	revRespEnv, _, err := client.SendExecute(ctx, capURI, "revoke", revokeParams, nil)
	if err != nil {
		out := FailCheck("send revoke: " + err.Error())
		return 0, "", &out
	}
	revRespData, err := types.ExecuteResponseDataFromEntity(revRespEnv.Root)
	if err != nil {
		out := FailCheck("decode revoke response: " + err.Error())
		return 0, "", &out
	}
	if revRespData.Status != 200 {
		if revRespData.Status == 403 {
			out := SkipCheck("validator's cap does not cover system/capability:revoke; cannot stage the revoked-cap probe")
			return 0, "", &out
		}
		out := FailCheck(fmt.Sprintf("revoke setup returned status=%d", revRespData.Status))
		return 0, "", &out
	}
	issuedEnt, ok := respEnv.Included[issued]
	if !ok {
		out := SkipCheck("issued token entity not present in original response.included")
		return 0, "", &out
	}
	var issuedSig entity.Entity
	for _, e := range respEnv.Included {
		if e.Type != types.TypeSignature {
			continue
		}
		var sd types.SignatureData
		if ecf.Decode(e.Data, &sd) == nil && sd.Target == issued {
			issuedSig = e
			break
		}
	}
	if issuedSig.Type == "" {
		out := SkipCheck("issued token signature not present in original response.included")
		return 0, "", &out
	}
	probeParams, _, err := buildSimpleGetParams()
	if err != nil {
		out := FailCheck("build probe params: " + err.Error())
		return 0, "", &out
	}
	env, err := buildDelegatedExecute(client, issuedEnt, issuedSig, treeURI, "get",
		probeParams, &types.ResourceTarget{Targets: []string{"system/type/system/peer"}})
	if err != nil {
		out := FailCheck("build delegated execute: " + err.Error())
		return 0, "", &out
	}
	probeResp, _, err := client.SendRawEnvelope(env)
	if err != nil {
		out := FailCheck("send: " + err.Error())
		return 0, "", &out
	}
	status, code, _, err := extractStatusAndCode(probeResp)
	if err != nil {
		out := FailCheck("extract response: " + err.Error())
		return 0, "", &out
	}
	return status, code, nil
}

// probeF40Row runs one F40 id-scope row: an attenuated child cap granting an
// operations include of only "get" over cross-peer resources "/*/*", optionally
// carrying the exclude entry ["/*/get"]. It executes a `get` and reports
// whether the op was ALLOWED (2xx). Row A (withExclude=false) is the positive
// control; Row B (withExclude=true) is the exclude probe. The F40
// canonicalization verdict is the A→B differential — see
// VECTOR-SPEC-2026-07-27-F40-scope-typing-control-row.md.
func probeF40Row(client *PeerClient, treeURI string, withExclude bool) (allowed bool, status uint, code string, err error) {
	ops := types.CapabilityScope{Include: []string{"get"}}
	if withExclude {
		ops.Exclude = []string{"/*/get"}
	}
	child := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
		Resources:  types.CapabilityScope{Include: []string{"/*/*"}},
		Operations: ops,
	}
	childCap, childSig, err := buildAttenuatedChildCap(client, child)
	if err != nil {
		return false, 0, "", fmt.Errorf("build child cap: %w", err)
	}
	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return false, 0, "", fmt.Errorf("build params: %w", err)
	}
	env, err := buildDelegatedExecute(client, childCap, childSig, treeURI, "get", params, resource)
	if err != nil {
		return false, 0, "", fmt.Errorf("build delegated execute: %w", err)
	}
	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return false, 0, "", fmt.Errorf("send: %w", err)
	}
	status, code, _, err = extractStatusAndCode(respEnv)
	if err != nil {
		return false, 0, "", fmt.Errorf("extract response: %w", err)
	}
	return status >= 200 && status < 300, status, code, nil
}
