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
	}
}
