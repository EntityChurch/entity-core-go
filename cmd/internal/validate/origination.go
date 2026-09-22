package validate

import (
	"context"
	"fmt"
	"time"
)

const catOrigination = "origination"

// runOriginationCore is the §10.2 core-tier origination probe per
// GUIDE-CONFORMANCE §7a / §7a.2a — the validator drives the target's
// system/validate/dispatch-outbound handler, which originates one
// outbound EXECUTE via the §6.11 reentry seam back to the validator's
// own system/validate/echo handler over the SAME inbound connection.
// The validator plays B-role on that connection; the round-trip proves
// the target's §6.13(b) outbound seam is live (not continuation, not
// INSTALL, not inbox — pure reentry).
//
// SKIP semantics (§7a.4): when the target peer was not started with
// --validate, the two test handlers 404; this gate then SKIPs honestly
// rather than FAILing on absent scaffolding. A peer claiming `--profile
// core` is free to run without --validate; absence is conformant via
// the code-attestation floor (§7a.4 floor tier).
//
// The reference peer is still connected at handshake time so the gate
// can match the call shape of the original A-role suite — but the
// dispatch-outbound probe targets the validator-as-B over the SAME
// connection, not a fresh dial to reference. The reference peer just
// confirms the handshake half (shared-keypair + reference_ready) and
// is otherwise unused under --profile core. The continuation-driven
// origination legs (checkRemoteExecute / chain_sync / psync / filesync)
// stay under `--profile full` per the routing-doc reservation.
func runOriginationCore(ctx context.Context, target *PeerClient, referenceAddr string, identityName string) []CheckResult {
	r := NewCheckRunner(catOrigination)

	r.Declare("reference_connect", "harness precondition (not a spec vector) — dial the reference peer with the TARGET's keypair, so the validator presents one byte-equal identity to both peers per EXTENSION-CONTINUATION §4.2 case 3")
	r.Declare("reference_ready", "harness precondition (not a spec vector) — the reference peer completed its connectivity checks and is usable as the handshake half")
	r.Declare("dispatch_outbound_reentry", "GUIDE-CONFORMANCE §7a.1 + §7a.2a; PROPOSAL v7.74 §10.2")
	r.Declare("dispatch_outbound_ambient_refused", "ENTITY-CORE-PROTOCOL §5.2 PD-2 (0.8.2.17) negative arm — an outbound sub-dispatch to a foreign peer on ambient handler authority (no target-minted capability presented) MUST be refused")
	r.Declare("dispatch_outbound_narrow_grant_refuses_out_of_scope", "GUIDE-CONFORMANCE §7a.1 ⛔ + §7a.1a + ENTITY-CORE-PROTOCOL §6.8 (0.8.2.19 E1/F67) — the F63 compose-vs-bypass discriminator: a valid target-minted credential presented to dispatch-outbound (narrow grant = echo only) MUST NOT authorize an OUT-OF-SCOPE sub-dispatch. The credential relaxes Dimension 4 (WHERE); the handler grant still gates operations (WHAT). Paired with an in-scope positive control on the SAME credential so the refusal is attributable to the narrow grant, not a bad credential")
	r.Declare("dispatch_outbound_multisig_root_refused", "GUIDE-CONFORMANCE §7a.1 plural carrier + §2.4b + §7a.1a + ENTITY-CORE-PROTOCOL §1.4 (0.8.2.19 E3/F66) — a K-of-2 multi-sig-rooted credential (the target is one of two signers) is NOT the target's sole authority and MUST NOT relax Dimension 4, even though VerifyChain accepts the root; the sub-dispatch falls to ambient and the foreign target is refused. That antecedent — VerifyChain accepting the root — is ESTABLISHED, not merely asserted, by the single-sig target-minted positive control on the SAME probe (granter form the only variable): the credential is otherwise valid and covering, so the deny is attributable to the multi-sig root and not to any unrelated defect in the mint. A deny-only check MUST establish its own antecedent, and this row names the arm that does (the single-sig control)")

	var subResults []CheckResult

	r.Run("reference_connect", func() CheckOutcome {
		reference, err := NewPeerClientWithKeypair(referenceAddr, target.Keypair())
		if err != nil {
			return FailCheck(fmt.Sprintf("connect to reference peer %s: %v", referenceAddr, err))
		}
		r.Store("reference", reference)
		return PassCheck(fmt.Sprintf("connected to reference peer %s (shared keypair with target)", referenceAddr))
	})

	r.Run("reference_ready", func() CheckOutcome {
		if out, ok := r.Require("reference_connect"); !ok {
			return out
		}
		reference := r.Load("reference").(*PeerClient)
		connChecks, connected := runConnectivity(ctx, reference)
		if !connected {
			for _, c := range connChecks {
				if c.Severity == Fail {
					subResults = append(subResults, c)
				}
			}
			return FailCheck(fmt.Sprintf("reference peer %s failed handshake", referenceAddr))
		}
		return PassCheck(fmt.Sprintf("reference peer %s ready as B-role (core slice)", referenceAddr))
	})

	if r.OK("reference_ready") {
		reference := r.Load("reference").(*PeerClient)
		defer reference.Close()

		// §7a.2a reentry probe. SKIP rather than FAIL when the target
		// 404s system/validate/dispatch-outbound (peer not run with
		// --validate); a peer not opted into conformance scaffolding is
		// the code-attestation floor case, not a failure of the seam.
		r.Run("dispatch_outbound_reentry", func() CheckOutcome {
			if !target.HasConformanceHandlers(ctx) {
				return SkipCheck("target peer not run with --validate (system/validate/dispatch-outbound absent; §7a.4 falls back to code-attestation floor)")
			}
			st := target.ArmReentryEcho()
			defer target.DisarmReentryEcho()
			hits, err := target.SendDispatchOutboundProbe(ctx, "core-origination-probe", st)
			if err != nil {
				return FailCheck(err.Error())
			}
			return PassCheck(fmt.Sprintf("dispatch-outbound reentry round-tripped (validator-as-B served %d inbound echo on the same connection)", hits))
		})

		// PD-2 negative arm. Drive the SAME handler with NO capability: the
		// outbound to a foreign peer now rides ambient handler authority and
		// MUST be refused (§5.2 — a handler with no peers scope covering the
		// target cannot reach a foreign peer). Paired with the positive
		// dispatch_outbound_reentry above, this discriminates: a peer that
		// refuses everything fails the positive arm, and a peer that authorizes
		// everything fails this one. One arm alone is not a check.
		r.Run("dispatch_outbound_ambient_refused", func() CheckOutcome {
			if !target.HasConformanceHandlers(ctx) {
				return SkipCheck("target peer not run with --validate (system/validate/dispatch-outbound absent; §7a.4 falls back to code-attestation floor)")
			}
			outerStatus, outerCode, innerStatus, err := target.SendDispatchOutboundProbeAmbient(ctx)
			if err != nil {
				return FailCheck(err.Error())
			}
			// The ambient Dimension-4 refusal surfaces in either scaffold shape,
			// both a pass (the §7a scaffold does not pin which):
			//   - RELAYED (py): outer 403 capability_denied.
			//   - WRAPPED (go, rust): outer 200, inner 403.
			if outerStatus == 403 && outerCode == "capability_denied" {
				return PassCheck("PD-2 negative arm: ambient outbound sub-dispatch to a foreign peer refused (outer 403 capability_denied, relayed shape) — Dimension 4 enforced on outbound (§5.2)")
			}
			if outerStatus == 200 {
				if innerStatus == 200 {
					return FailCheck("PD-2 negative arm: an ambient outbound sub-dispatch to a foreign peer SUCCEEDED (inner 200) — the peer authorized a foreign sub-dispatch on a handler grant with no peers scope (§5.2 escalation the peers dimension exists to close)")
				}
				if innerStatus != 403 {
					return FailCheck(fmt.Sprintf("PD-2 negative arm: ambient outbound sub-dispatch refused with inner status %d, want 403 capability_denied (§5.2 Dimension 4)", innerStatus))
				}
				return PassCheck("PD-2 negative arm: ambient outbound sub-dispatch to a foreign peer refused (inner 403 capability_denied, wrapped shape) — Dimension 4 enforced on outbound (§5.2)")
			}
			// A strict handler refuses the omitted-triple probe at param
			// validation (outer 400 invalid_params), before any dispatch — the
			// ambient arm is not reachable over this probe. UNMEASURED, not a
			// defect: SKIP (a param-validation refusal is not a Dimension-4
			// refusal; the "early refusal reads as unmeasurability" trap).
			return SkipCheck(fmt.Sprintf("target keeps the §7a.2a triple mandatory (omitted-triple probe refused at param validation: outer status %d code %q) — PD-2 ambient arm not reachable over this probe; the cohort scaffold makes the triple optional (outer 403 relayed, or outer 200 + inner 403) so the arm is measured there", outerStatus, outerCode))
		})

		// F63 compose-vs-bypass discriminator (0.8.2.19 E1, the missing wire
		// evidence). The two arms above cannot see a bypass: dispatch_outbound_
		// reentry is "all sources agree → allow" and dispatch_outbound_ambient_
		// refused is "no source at all → refuse". This one presents a VALID
		// target-minted credential to a handler whose NARROW grant does not
		// cover the sub-dispatched operation, with an in-scope positive control
		// on the same credential — the vector that stayed absent while the F67
		// confused-deputy bypass passed the two blind arms cohort-wide.
		r.Run("dispatch_outbound_narrow_grant_refuses_out_of_scope", func() CheckOutcome {
			if !target.HasConformanceHandlers(ctx) {
				return SkipCheck("target peer not run with --validate (system/validate/dispatch-outbound absent; §7a.4 falls back to code-attestation floor)")
			}
			st := target.ArmReentryEcho()
			defer target.DisarmReentryEcho()
			o, err := target.SendDispatchOutboundF63Discriminator(ctx, st)
			if err != nil {
				return FailCheck(err.Error())
			}
			// Positive control: the in-scope op must succeed and reach the
			// validator exactly once — proving the credential is valid and
			// covering, so the out-of-scope refusal below is attributable to the
			// narrow grant and not to a bad credential (the negative-authz-test
			// false-pass trap, 0.8.2.19 close-out).
			if o.inScopeOuterStatus != 200 || o.inScopeInnerStatus != 200 || o.hitsAfterInScope != 1 {
				return FailCheck(fmt.Sprintf("F63 positive control failed: in-scope echo outer=%d inner=%d hits=%d, want 200/200/1 — the target-minted credential must relax Dimension 4 for the in-scope op, else the out-of-scope refusal is not attributable to the narrow grant", o.inScopeOuterStatus, o.inScopeInnerStatus, o.hitsAfterInScope))
			}
			// Bypass = defect: the out-of-scope op succeeded through the credential.
			if o.oosOuterStatus == 200 && o.oosInnerStatus == 200 {
				return FailCheck(fmt.Sprintf("F63 §7a.1 ⛔ violation: an out-of-scope sub-dispatch (op=%s) SUCCEEDED while presenting a target-minted credential. Two causes, same remediation: (a) the pre-E1 confused-deputy BYPASS — the credential was treated as a standalone authorizer, steering dispatch-outbound past its grant (§6.8); or (b) the dispatch-outbound handler grant is NOT narrow (§7a.1 ⛔) — a wide grant covers the op, so compose and bypass agree and the discriminator cannot fire. Fix: scope the dispatch-outbound grant to echo only, then confirm no bypass", reentryOutOfScopeOp))
			}
			// Carry-the-teeth: the refusal must fire BEFORE reentry — the
			// validator must not have been contacted a second time.
			if o.hitsAfterOOS != 1 {
				return FailCheck(fmt.Sprintf("F63: the out-of-scope sub-dispatch reached the validator (reentry hits went %d→%d) — the refusal did not fire before the outbound left the peer", o.hitsAfterInScope, o.hitsAfterOOS))
			}
			// Refused, either scaffold shape.
			if o.oosOuterStatus == 403 && o.oosOuterCode == "capability_denied" {
				return PassCheck("F63 compose-vs-bypass: out-of-scope sub-dispatch refused (outer 403 capability_denied, relayed) while the in-scope op on the SAME credential succeeded — the narrow handler grant gates operations, the credential relaxes only Dimension 4 (§6.8 E1)")
			}
			if o.oosOuterStatus == 200 && o.oosInnerStatus == 403 {
				return PassCheck("F63 compose-vs-bypass: out-of-scope sub-dispatch refused (inner 403 capability_denied, wrapped) while the in-scope op on the SAME credential succeeded — the narrow handler grant gates operations, the credential relaxes only Dimension 4 (§6.8 E1)")
			}
			// The sub-dispatch was refused (no bypass — the in-scope control
			// succeeded and hits stayed at 1), but the outer shape is neither the
			// relayed 403 capability_denied nor the wrapped inner 403. Per §7a.1a
			// (0.8.2.19d fold) a §1.4/§6.8 refusal is an authorization DENY
			// whichever dimension raised it, and a handler that wraps it in a
			// generic catch-all (e.g. a 5xx reentry_dispatch_failed) launders an
			// authorization verdict into a transport fault — §2.4b's
			// unattributability one layer over. WARN, never a silent PASS: the
			// property may hold, but the code does not say so, and go does not
			// discriminate on a code it cannot attribute.
			return WarnCheck(fmt.Sprintf("out-of-scope sub-dispatch refused with a NON-AUTHORIZATION code (outer=%d code=%q inner=%d) — F63 not measured over this shape. Per GUIDE-CONFORMANCE §7a.1a the refusal must surface capability_denied (or a defined authorization code), relayed as outer 403 or wrapped as inner 403; a generic catch-all launders the §6.8 verdict into a transport fault", o.oosOuterStatus, o.oosOuterCode, o.oosInnerStatus))
		})

		// E3/F66 fail-closed wire vector (0.8.2.19, unblocked by the §7a.1
		// plural carrier), now a differential with its own positive control per
		// the F70 ruling (keystone option (b), §2.4b). A K-of-2 multi-sig root
		// that merely includes the target as one signer must not relax Dimension
		// 4 — but a bare refusal proves nothing about WHY it was refused. The
		// single-sig control (granter form the only variable) establishes the
		// antecedent: the credential family IS otherwise valid and covering.
		r.Run("dispatch_outbound_multisig_root_refused", func() CheckOutcome {
			if !target.HasConformanceHandlers(ctx) {
				return SkipCheck("target peer not run with --validate (system/validate/dispatch-outbound absent; §7a.4 falls back to code-attestation floor)")
			}
			st := target.ArmReentryEcho()
			defer target.DisarmReentryEcho()
			o, err := target.SendDispatchOutboundE3MultiSig(ctx, st)
			if err != nil {
				return FailCheck(err.Error())
			}
			// Positive control (§2.4b): the single-sig target-minted covering
			// credential must relax Dimension 4 for the SAME echo op and reach the
			// validator exactly once. If it does not, the credential family is not
			// valid+covering at this seat, so the multi-sig refusal below is NOT
			// attributable to the granter form — the deny would measure nothing.
			if o.singleSigOuterStatus != 200 || o.singleSigInnerStatus != 200 || o.hitsAfterSingleSig != 1 {
				return FailCheck(fmt.Sprintf("E3 positive control failed: single-sig target-minted echo outer=%d inner=%d hits=%d, want 200/200/1 — the single-sig credential (granter form the only variable vs the multi-sig arm) must relax Dimension 4, else the multi-sig refusal is not attributable to the multi-sig root (§2.4b: a deny-only check MUST establish its own antecedent)", o.singleSigOuterStatus, o.singleSigInnerStatus, o.hitsAfterSingleSig))
			}
			// A multi-sig root must NOT relax Dimension 4 → the in-scope echo
			// sub-dispatch falls to ambient and is refused (foreign target, no
			// peers scope). If it SUCCEEDED, the multi-sig root wrongly relaxed.
			if o.multiSigOuterStatus == 200 && o.multiSigInnerStatus == 200 {
				return FailCheck(fmt.Sprintf("E3/F66 over-acceptance: a K-of-2 multi-sig-rooted credential relaxed Dimension 4 and the sub-dispatch SUCCEEDED (outer 200 inner 200, reentry hits went 1→%d) while the single-sig control over the identical request also succeeded — the granter form is the only variable, so the multi-sig root wrongly authorized; a multi-sig root is not 'minted BY the target peer', it must fail closed (§1.4)", o.hitsAfterMultiSig))
			}
			// Carry-the-teeth: the refusal must fire BEFORE reentry — hits must
			// still be 1 (the single-sig control's), not 2.
			if o.hitsAfterMultiSig != o.hitsAfterSingleSig {
				return FailCheck(fmt.Sprintf("E3/F66: the multi-sig-rooted sub-dispatch reached the validator (reentry hits went %d→%d) — the credential relaxed Dimension 4 before the fail-closed check", o.hitsAfterSingleSig, o.hitsAfterMultiSig))
			}
			if o.multiSigOuterStatus == 403 && o.multiSigOuterCode == "capability_denied" {
				return PassCheck("E3/F66 fail-closed: a K-of-2 multi-sig-rooted credential (target is one signer) did NOT relax Dimension 4 while the single-sig control over the identical request (granter form the only variable) succeeded; the multi-sig sub-dispatch fell to ambient and was refused (outer 403 capability_denied, relayed) — a multi-sig root is not the target's sole authority (§1.4)")
			}
			if o.multiSigOuterStatus == 200 && o.multiSigInnerStatus == 403 {
				return PassCheck("E3/F66 fail-closed: a K-of-2 multi-sig-rooted credential (target is one signer) did NOT relax Dimension 4 while the single-sig control over the identical request (granter form the only variable) succeeded; the multi-sig sub-dispatch fell to ambient and was refused (inner 403 capability_denied, wrapped) — a multi-sig root is not the target's sole authority (§1.4)")
			}
			// Refused (single-sig control succeeded, hits stayed at 1 — no
			// over-acceptance) but with a non-authorization code. §7a.1a: the
			// §1.4 refusal must surface capability_denied, not a generic
			// catch-all. A further caveat rides E3 specifically (§7a.1 multi-sig
			// note): a seat that cannot ACCEPT a valid multi-signature root
			// anywhere (fail-closed-by-absence) has not been measured by E3 at
			// all — read that seat's convergence.msp_2of3_verifier_signed_ALLOW
			// before reading this row's green.
			return WarnCheck(fmt.Sprintf("multi-sig-rooted sub-dispatch refused with a NON-AUTHORIZATION code (outer=%d code=%q inner=%d hits=%d) while the single-sig control succeeded — E3 not measured over this shape. Per GUIDE-CONFORMANCE §7a.1a the §1.4 refusal must surface capability_denied (relayed outer 403 or wrapped inner 403); a generic catch-all launders the authorization verdict into a transport fault", o.multiSigOuterStatus, o.multiSigOuterCode, o.multiSigInnerStatus, o.hitsAfterMultiSig))
		})

		// reference is connected to keep the gate's input shape
		// (`-reference-peer required`) consistent with the full-profile
		// suite below. The §7a.2a probe is intrinsically validator-as-B
		// so reference is unused once handshake is up; closing the
		// connection happens via the deferred reference.Close() above.
		_ = reference
	} else {
		if ref := r.Load("reference"); ref != nil {
			ref.(*PeerClient).Close()
		}
	}

	results := r.Results()
	results = append(results, subResults...)
	return results
}

// runOrigination exercises the target peer as an A-role originator against a
// known-good reference peer B. Catches bugs that single-peer responder-only
// validation cannot surface by design: outbound EXECUTE params must be
// entity-shaped per V7 §3.4, continuation dispatch must read the `resource`
// field rather than reusing `target`, inbox notification deliveries must
// trigger continuation advance (not be mailbox dead-ends), subscription-
// triggered chains must complete through extract+merge, etc.
//
// The check set mirrors the A-role portion of the convergence suite but
// without the multi-peer determinism / merge-convergence checks, which
// belong to the dedicated convergence runner. If all of these pass, the
// target peer is a conformant A-role implementation.
func runOrigination(ctx context.Context, target *PeerClient, referenceAddr string, identityName string) []CheckResult {
	r := NewCheckRunner(catOrigination)

	// --- Declare all checks ---

	r.Declare("reference_connect", "harness precondition (not a spec vector) — dial the reference peer with the TARGET's keypair; a byte-distinct identity makes the writer-on-A differ from the leaf-granter-on-B and §3.1a in-chain checks 403 embedded_cap_unauthorized")
	r.Declare("reference_ready", "harness precondition (not a spec vector) — the reference peer completed its connectivity checks and is usable as the A-role counterpart")
	r.Declare("chain_sync", "sub-suite DRIVER (not a spec vector) — runs the chain-sync sub-suite; its checks are scored under their own categories, this only reports that the sub-suite executed")
	r.Declare("psync", "sub-suite DRIVER (not a spec vector) — runs the prefix extract+merge sync sub-suite; its checks are scored under their own categories")
	r.Declare("filesync", "sub-suite DRIVER (not a spec vector) — runs the file-sync sub-suite; SKIPs unless the local/files handler is present on both peers")

	// Sub-suite results collected separately (they carry their own categories).
	var subResults []CheckResult

	// --- Step 1: Connect to reference peer ---

	r.Run("reference_connect", func() CheckOutcome {
		// EXTENSION-CONTINUATION §4.2 case 3 models ONE installer principal
		// across all peer connections (cap chain rooted at B granted to the
		// installer; installer re-attenuates as leaf granter; installs on A).
		// The validator IS that one principal. The reference peer client
		// MUST share the target's keypair so the validator presents one
		// byte-equal identity to both peers; otherwise the writer-on-A is
		// byte-distinct from the leaf-granter-on-B and §3.1a in-chain checks
		// fail with 403 embedded_cap_unauthorized.
		//
		// See the matching fix in suite.go:RunConvergence (commit 9c56d5d)
		// and the V7.69 same-format drift postmortem.
		reference, err := NewPeerClientWithKeypair(referenceAddr, target.Keypair())
		if err != nil {
			return FailCheck(fmt.Sprintf("connect to reference peer %s: %v", referenceAddr, err))
		}
		r.Store("reference", reference)
		return PassCheck(fmt.Sprintf("connected to reference peer %s (shared keypair with target)", referenceAddr))
	})

	r.Run("reference_ready", func() CheckOutcome {
		if out, ok := r.Require("reference_connect"); !ok {
			return out
		}
		reference := r.Load("reference").(*PeerClient)

		connChecks, connected := runConnectivity(ctx, reference)
		if !connected {
			// Include failing connectivity checks in sub-results for diagnostics.
			for _, c := range connChecks {
				if c.Severity == Fail {
					subResults = append(subResults, c)
				}
			}
			return FailCheck(fmt.Sprintf("reference peer %s failed handshake", referenceAddr))
		}
		return PassCheck(fmt.Sprintf("reference peer %s ready as B-role", referenceAddr))
	})

	// --- Steps 2-7: Run sub-suites (only if reference is ready) ---

	// All sub-suites need reference_ready to pass. Run them only if it did.
	if r.OK("reference_ready") {
		reference := r.Load("reference").(*PeerClient)
		defer reference.Close()

		// GUIDE-CONFORMANCE §3.1 item 5: when target and reference negotiate
		// different active content_hash_formats (cross-home-format pairing),
		// cross-peer hash-equality + content-routing tests are single-
		// address-space by design (V7 §1.2 / §1.2a). They MUST be explicitly
		// SKIPped with the tracked reason — never silently failed, never
		// silently passed. They run normally under same-format pairings.
		crossFormat := target.ActiveHashFormat() != reference.ActiveHashFormat()
		crossFormatReason := fmt.Sprintf("single-address-space test; cross-format pairing is experimental per V7 §1.5 (target active=0x%02x, reference active=0x%02x)",
			target.ActiveHashFormat(), reference.ActiveHashFormat())

		// Pre-put the target peer's cap entity -- continuations reference it by
		// hash via dispatch_capability (W9).
		if !target.CapEntity().ContentHash.IsZero() {
			target.TreePut(ctx, "system/validate/origination-cap-store", target.CapEntity())
		}

		suffix := fmt.Sprintf("orig-%d", time.Now().UnixNano())

		// Async delivery (A's deliver_to plumbing). Must precede rexec since
		// rexec relies on the async-dispatch path working.
		subResults = append(subResults, checkAsyncDelivery(ctx, target, suffix, "A")...)

		// Single-step remote execute via continuation -- catches params entity
		// wrapping (V7 §3.4) and continuation resource-field handling.
		var rexecChecks []CheckResult
		var remoteOK bool
		if crossFormat {
			rexecChecks = []CheckResult{
				{Category: catConvergence, Name: "rexec_setup", SpecRef: "REMOTE §2", Severity: Skip, Message: crossFormatReason},
				{Category: catConvergence, Name: "rexec_put_b", SpecRef: "REMOTE §1", Severity: Skip, Message: crossFormatReason},
				{Category: catConvergence, Name: "rexec_trigger", SpecRef: "REMOTE §2", Severity: Skip, Message: crossFormatReason},
				{Category: catConvergence, Name: "rexec_delivered", SpecRef: "REMOTE §3", Severity: Skip, Message: crossFormatReason},
			}
		} else {
			rexecChecks = checkRemoteExecute(ctx, target, reference, suffix)
			remoteOK = allPassed(rexecChecks)
		}
		subResults = append(subResults, rexecChecks...)

		// Cross-peer subscription delivery -- A subscribes on B, A consumes the
		// delivered notifications.
		if crossFormat {
			subResults = append(subResults, []CheckResult{
				{Category: catConvergence, Name: "xsub_setup_transport", SpecRef: "NETWORK §10", Severity: Skip, Message: crossFormatReason},
			}...)
		} else {
			subResults = append(subResults, checkCrossPeerSubscription(ctx, target, reference, suffix)...)
		}

		// Multi-step continuation chain.
		r.Run("chain_sync", func() CheckOutcome {
			if !remoteOK {
				return SkipCheck("skipped -- rexec must pass first")
			}
			chainChecks := checkContinuationChainSync(ctx, target, reference, suffix)
			subResults = append(subResults, chainChecks...)
			return PassCheck(fmt.Sprintf("chain sync sub-suite ran (%d checks)", len(chainChecks)))
		})

		// Prefix extract+merge sync.
		r.Run("psync", func() CheckOutcome {
			if !remoteOK {
				return SkipCheck("skipped -- rexec must pass first")
			}
			psyncChecks := checkPrefixSync(ctx, target, reference, suffix)
			subResults = append(subResults, psyncChecks...)
			return PassCheck(fmt.Sprintf("prefix sync sub-suite ran (%d checks)", len(psyncChecks)))
		})

		// File sync.
		r.Run("filesync", func() CheckOutcome {
			if !remoteOK {
				return SkipCheck("skipped -- rexec must pass first")
			}
			if !target.GrantsAllow("local/sync/test") || !reference.GrantsAllow("local/sync/test") {
				return SkipCheck("skipped -- local/files handler not present on both peers")
			}
			fsChecks := checkFileSync(ctx, target, reference, suffix)
			fsChecks = append(fsChecks, checkBidirectionalFileSync(ctx, target, reference, suffix)...)
			subResults = append(subResults, fsChecks...)
			return PassCheck(fmt.Sprintf("file sync sub-suite ran (%d checks)", len(fsChecks)))
		})
	} else {
		// reference not ready -- close if we got a connection
		if ref := r.Load("reference"); ref != nil {
			ref.(*PeerClient).Close()
		}
	}

	// Merge runner's own declared checks with sub-suite results.
	results := r.Results()
	results = append(results, subResults...)
	return results
}
