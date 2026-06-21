// Category: peer_issued. Probes the EXTENSION-REGISTRY peer-issued backend
// per PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND v0.3 §6 — six vectors:
//
//   REG-PEERISSUED-RESOLVE-1         — by-name → binding → verify → resolved (live)
//   REG-PEERISSUED-VERIFY-FAIL-1     — non-pinned signer → rejected, chain advances
//   REG-PEERISSUED-REVOKED-1         — verifying revocation → excluded
//   REG-PEERISSUED-EXPIRED-1         — issued_at + ttl ≤ now → excluded
//   REG-PEERISSUED-PRECEDE-1         — offline binding identical-verify to live
//   REG-PEERISSUED-OFFLINE-NOTFOUND-1 — name absent → not_found + neg_ttl
//
// v1 status (Go reference): the backend itself is unit-tested in
// ext/registry/peerissued (8 tests, all six vectors covered in-process).
// The wire vectors here SKIP — driving them against an external peer
// needs (a) the target to be started with --peer-issued-registry pinning
// the validator's chosen registry identity, AND (b) the validator to
// either serve an http-poll fixture (RESOLVE-1) or write signed bindings
// into the target's local tree (PRECEDE-1, etc.). That fixture wiring is
// the Keystone leg per handoff §7 ("a later gating step, not a do-now").
// The skip messages are explicit so they aren't silent.

package validate

const catPeerIssued = "peer_issued"

func runPeerIssued() []CheckResult {
	r := NewCheckRunner(catPeerIssued)

	r.Declare("v1_resolve_happy_path",
		"REG-PEERISSUED-RESOLVE-1 — by-name → binding → verify → resolved (live-fetch)")
	r.Declare("v2_verify_fail_non_pinned_signer",
		"REG-PEERISSUED-VERIFY-FAIL-1 — non-pinned signer → rejected, chain advances")
	r.Declare("v3_revoked",
		"REG-PEERISSUED-REVOKED-1 — verifying revocation → excluded")
	r.Declare("v4_expired",
		"REG-PEERISSUED-EXPIRED-1 — issued_at + ttl ≤ now → excluded")
	r.Declare("v5_precede_offline_identical_verify",
		"REG-PEERISSUED-PRECEDE-1 — offline binding identical-verify to live")
	r.Declare("v6_offline_not_found",
		"REG-PEERISSUED-OFFLINE-NOTFOUND-1 — name absent → not_found + neg_ttl")

	const skipReason = "peer-issued wire vectors need a fixture-pinned registry on the target peer " +
		"(start target with --peer-issued-registry=<pid>@<url>) plus an http-poll fixture " +
		"OR a tree:put pre-seed step for offline vectors. Backend is unit-tested in " +
		"ext/registry/peerissued (8 vectors, all six paths). Fixture wiring is the Keystone " +
		"leg per HANDOFF-PEER-ISSUED-REGISTRY-BACKEND-IMPL §7 — deferred from the Go reference cycle."

	r.Run("v1_resolve_happy_path", func() CheckOutcome { return SkipCheck(skipReason) })
	r.Run("v2_verify_fail_non_pinned_signer", func() CheckOutcome { return SkipCheck(skipReason) })
	r.Run("v3_revoked", func() CheckOutcome { return SkipCheck(skipReason) })
	r.Run("v4_expired", func() CheckOutcome { return SkipCheck(skipReason) })
	r.Run("v5_precede_offline_identical_verify", func() CheckOutcome { return SkipCheck(skipReason) })
	r.Run("v6_offline_not_found", func() CheckOutcome { return SkipCheck(skipReason) })

	return r.Results()
}
