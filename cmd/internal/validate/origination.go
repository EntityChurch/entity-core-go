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

	r.Declare("reference_connect", "")
	r.Declare("reference_ready", "")
	r.Declare("dispatch_outbound_reentry", "GUIDE-CONFORMANCE §7a.1 + §7a.2a; PROPOSAL v7.74 §10.2")

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

	r.Declare("reference_connect", "")
	r.Declare("reference_ready", "")
	r.Declare("chain_sync", "")
	r.Declare("psync", "")
	r.Declare("filesync", "")

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
