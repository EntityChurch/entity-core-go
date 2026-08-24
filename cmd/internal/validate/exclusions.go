package validate

// Declared exclusions — the vectors this instrument does NOT measure, stated
// as data so absence of coverage is asserted positively.
//
// WHY THIS EXISTS. `EXTENSION-NETWORK` §5.4a `[corrected 2026-08-12]` pins a
// vector pair and then states its own satisfaction mode, because the negative
// half is not constructible by a conformance client: where an
// evict-without-demote path is installed (RELAY deployed) it MUST be
// wire-driven, and **otherwise it is satisfied in-process, and the
// implementation MUST record a declared exclusion naming the mutation it was
// verified against.** Per `GUIDE-CONFORMANCE` §5.2b.1 the gap is then *stated*
// rather than *absent* — a declared exclusion is an honest zero; a proxy is a
// false one.
//
// WHY IT LIVES IN THE REPORT AND NOT ONLY IN A DOC. The failure mode §5.4a
// guards against is a specific sentence: "an in-process result reported as a
// cross-impl vector pass is a false conformance claim." That claim would be
// made *here* — in a `validate-peer` report against rust or py, where a reader
// counts categories and concludes the pair is covered. So the exclusion prints
// in every run, against every peer, in text and in JSON. A register that lives
// only in `docs/` is read by whoever already knows to look.
//
// The same shape as `encvectors.Excludes()` (§16.6 requirement 4), one layer
// up: that states what a vector FILE does not gate, this states what the SUITE
// does not measure.

// DeclaredExclusion is one vector the suite does not exercise against the peer
// under test, with the reason and — where the rule is satisfied another way —
// the mutation that proves the substitute can actually fail.
type DeclaredExclusion struct {
	// VectorID is the pinned vector's spec ID, so a reader comparing a
	// report against the spec's vector list finds it by name.
	VectorID string `json:"vector_id"`

	// SpecRef is the clause that pins the vector AND states its satisfaction
	// mode — for §5.4a those are the same section by construction.
	SpecRef string `json:"spec_ref"`

	// Why states what makes the state unconstructible at the wire. This is
	// the half a future author needs: if the obstacle is removed, the
	// exclusion is void and the vector must be driven.
	Why string `json:"why"`

	// SatisfiedBy names where the rule IS verified, precisely enough to run.
	SatisfiedBy string `json:"satisfied_by"`

	// Mutation names the change that MUST make SatisfiedBy fail. A test that
	// cannot fail is the exact thing this whole mechanism exists to catch, so
	// the exclusion is only honest if this is stated and has been run.
	Mutation string `json:"mutation"`

	// Voids states the condition under which this exclusion stops applying —
	// §5.4a's satisfaction mode is conditional, not blanket.
	Voids string `json:"voids"`
}

// DeclaredExclusions returns every vector the suite deliberately does not
// exercise against the peer under test.
//
// Keep this list SHORT and keep each entry falsifiable. An entry that cannot
// be checked by reading the named test and applying the named mutation is a
// story, not an exclusion.
func DeclaredExclusions() []DeclaredExclusion {
	return []DeclaredExclusion{
		{
			VectorID: "NET-LIVENESS-NO-ESCALATION-WITHOUT-EPISODE-1",
			SpecRef:  "EXTENSION-NETWORK §5.4a — the negative half of the escalation-survives-eviction pair",
			Why: "The state the vector requires — a peer UNBOUND yet still `connected` — is reachable " +
				"only from the two paths §A1's scope deliberately excludes from demoting (the §10.2 " +
				"dispatch-fallback and the RELAY terminal hop), and both need a store-and-forward " +
				"deployment. In this peer the §10.2 seam is nil-gated (`p.dispatchFallback != nil`, " +
				"core/peer/remote.go), so no conformance client can construct it over the wire. " +
				"The scope pin and the obstacle have one cause.",
			SatisfiedBy: "in-process: TestLivenessNoEscalationWithoutFailureEpisode " +
				"(core/peer/peer_status_liveness_test.go) — evicts the pooled binding directly, " +
				"writing no status, and asserts the keepalive teardown never writes `disconnected`.",
			Mutation: "EXECUTED, not described: TestLivenessNoEscalationMutationHasTeeth " +
				"(core/peer) sets suspectScopeGuardDisabled, runs the same scenario, and asserts " +
				"the escalation DOES fire — so it fails if the scope guard is not what makes the " +
				"exclusion's test pass. Runs in the unit suite on every commit. §5.2b.1 as " +
				"sharpened 2026-08-12 (d) takes core-py's stronger form for a reason worth " +
				"repeating: their §5.5a control and its mutation both ran against a malformed " +
				"probe, so neither could have failed. A mutation nobody runs is a claim.",
			Voids: "This exclusion is void for any peer with an evict-without-demote path installed " +
				"(RELAY deployed) — §5.4a requires the negative half be WIRE-driven there. It is not " +
				"a standing exemption, and the obvious substitute is explicitly rejected by §5.4a: a " +
				"live idle counterpart stays BOUND, so a proxy exercises a timer-driven escalation and " +
				"never the scope-pin defect, reading as coverage while missing the case.",
		},
		{
			VectorID: "TV-SS-CORE-1..7 / TV-SS-COMP-1..4 / TV-SS-BARE-1..2 / TV-SS-DISP-1..3",
			SpecRef:  "EXTENSION-SUBSTITUTE §9 — the §3 chain-consultation vectors (chain order; hash-mismatch discard+advance; unsigned-entry reject; cap-denied abort; exhausted→404+meta; expires_at; supersedes; the CONTENT pending/miss composition; bare-hash no-consult; convention dispatch)",
			Why: "The §3 chain fires only for a caller that supplies `claimed_source_peer_id`, which the " +
				"storage-substitute cross-impl Ruling 4 makes LOCAL DISPATCHER CONTEXT and explicitly NOT a " +
				"wire field on `system/content:get-request`. No production path populates it in ANY of the " +
				"three implementations, read live 2026-08-13: rust `1152d35` binds `let claimed_source: " +
				"Option<Hash> = None;` at the miss-hook call site (extensions/content/src/handler.rs:164) " +
				"under a comment saying CONTENT-level gets do not trigger consult; py `d6cfbda` states the " +
				"same at entity_handlers/content/handler.py:201 (\"this handler does NOT auto-invoke it\"); " +
				"go's `WithClaimedSource` has exactly one caller in the whole repo and it is a test. So no " +
				"conformance client can enter the chain over the wire — the deferral is cohort-convergent " +
				"and deliberate, not a go gap. **This is an honest zero, and it is the reason this " +
				"extension had no checks at all until 2026-08-13** — what IS reachable (the §7 convention " +
				"handler) is now driven by the `substitute` category.",
			SatisfiedBy: "in-process: ext/storagesubstitutesources/orchestrator_test.go — 15 tests covering " +
				"priority ordering, advance-on-not-found, advance-on-hash-mismatch, abort-on-cap-denied, " +
				"disabled/expired/wrong-source skipping, rejected-signature skipping, and the four §8 " +
				"cap-scoping refusals; plus integration_test.go's end-to-end miss→fetch and the " +
				"no-claimed-source bypass.",
			Mutation: "EXECUTED, not described: TestConsultFailClosedMutationHasTeeth " +
				"(ext/storagesubstitutesources/mutation_test.go) sets consultGateDisabled, replays " +
				"TestConsult_FailClosed_NoCallerCapability's exact setup, and asserts the chain DOES " +
				"consult and DOES dispatch — so it fails if the §8 gate is not what makes the fail-closed " +
				"test pass. Runs in the unit suite on every commit.",
			Voids: "This exclusion is void the moment any production caller populates the claimed source — " +
				"the SDK closure-fetch and the Phase-2 dispatcher tree-walk that rust and py both name as " +
				"the intended driver. At that point the chain becomes wire-reachable and these vectors MUST " +
				"be driven, starting with the fail-closed cap gate: the surface it protects is an " +
				"arbitrary-caller-triggered outbound fetch followed by a forced ingestion (§8), which is " +
				"the highest-consequence hole in this extension and the one an in-process test is least " +
				"able to speak for.",
		},
	}
}
