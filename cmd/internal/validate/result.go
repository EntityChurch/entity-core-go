package validate

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Severity indicates the outcome of a validation check.
type Severity string

const (
	Pass Severity = "PASS"
	Warn Severity = "WARN"
	Fail Severity = "FAIL"
	Skip Severity = "SKIP"
)

// CheckResult is the outcome of a single validation check.
type CheckResult struct {
	Category  string   `json:"category"`
	Name      string   `json:"name"`
	Severity  Severity `json:"severity"`
	Message   string   `json:"message"`
	SpecRef   string   `json:"spec_ref"`
	Details   any      `json:"details,omitempty"`
	ElapsedMs int64    `json:"elapsed_ms"`

	// SelfCheck marks a check that never contacts the peer under test — it
	// exercises THIS validator's own library in-process.
	//
	// Such checks are legitimate (an offline KAT, a pure ordering rule), but
	// their result says nothing about the peer named in the report. Unmarked,
	// they are indistinguishable from probes, so a run against rust or python
	// lands ~29 passes in that peer's row that measured core-go's code. That is
	// how "three-way green" can be one implementation counted three times.
	//
	// Marked rather than removed from the totals: the suite total is a
	// cross-repo number that arch and both siblings quote, and moving it
	// unilaterally would break comparisons to make a labelling point. Whether
	// self-checks should be scored per-peer at all is routed to arch.
	SelfCheck bool `json:"self_check,omitempty"`
}

// Summary counts check outcomes.
//
// A SKIP means we did not run the test — the system's behavior on that
// path is UNKNOWN, which is not evidence of correctness. Skips are
// counted distinctly in `Skipped`, but the run-result gate
// (`Report.Passed()`) requires `Failed + Skipped == 0` (unless an
// explicit `-allow-skip` allowlist exempts specific checks). The
// summary line surfaces both counts and explicitly notes that any
// non-zero skip count is a FAIL unless allowlisted.
//
// Rationale: the same-format drift postmortem. Treating skips as "not a
// failure" hid a 23-day-old harness bug behind silently-skipped tests
// (e.g., msp_*/xsubhttp_* gates that required persistent peers + HTTP
// listeners). With those skips counted toward the gate, the bug would
// have been caught at the first cohort closeout that depended on it.
type Summary struct {
	Total     int   `json:"total"`
	Passed    int   `json:"passed"`
	Warned    int   `json:"warned"`
	Failed    int   `json:"failed"`
	Skipped   int   `json:"skipped"`
	ElapsedMs int64 `json:"elapsed_ms"`

	// SelfChecks counts results that never contacted the peer (CheckResult
	// .SelfCheck). Total minus this is the peer-attributable count — the
	// number a reader comparing two implementations actually wants.
	SelfChecks int `json:"self_checks"`
}

// RuntimeBudgetMs is the soft ceiling on total per-check wall-clock for a
// validation run. Sum of all CheckResult.ElapsedMs above this surfaces a
// warning to stderr and a populated BudgetWarning on the report.
//
// Sized off the worst observed healthy-peer full validation (Rust pre-fix
// ~5m20s, normal-state runs ~30–60s) — 10 minutes leaves headroom for tests
// being added without flagging healthy growth, but trips on a ~5m+ regression.
// See the Rust perf-regression incident report for the
// incident this guardrail is calibrated against.
const RuntimeBudgetMs int64 = 10 * 60 * 1000

// Report is the full validation result for a peer.
type Report struct {
	PeerAddr      string        `json:"peer_addr"`
	PeerID        string        `json:"peer_id,omitempty"`
	Peers         []PeerInfo    `json:"peers,omitempty"`
	Timestamp     string        `json:"timestamp"`
	Summary       Summary       `json:"summary"`
	Checks        []CheckResult `json:"checks"`
	BudgetWarning string        `json:"budget_warning,omitempty"`

	// Exclusions are the pinned vectors this suite does not exercise against
	// the peer, stated positively (see exclusions.go). They are NOT results:
	// they never enter Summary, never count as a pass, and are printed
	// whether or not anything failed — the claim they guard against ("the
	// pair is covered") is made by a reader of a GREEN report.
	Exclusions []DeclaredExclusion `json:"declared_exclusions,omitempty"`

	// allowedSkips holds check names the user explicitly marked as
	// "skip this — intentional", via -allow-skip on the validate-peer
	// CLI. A skipped check listed here is NOT counted as a failure by
	// HasFailures / the Result: PASS/FAIL gate. Unlisted skips count
	// as failures per the drift postmortem: a skip is
	// UNKNOWN behavior, not PASS.
	allowedSkips map[string]bool
}

// PeerInfo identifies a peer in a multi-peer convergence report.
type PeerInfo struct {
	Label  string `json:"label"`
	Addr   string `json:"addr"`
	PeerID string `json:"peer_id"`
}

// NewReport creates a new report for the given peer address.
func NewReport(addr string) *Report {
	return &Report{
		PeerAddr:   addr,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Exclusions: DeclaredExclusions(),
	}
}

// Add appends a check result and updates the summary.
func (r *Report) Add(c CheckResult) {
	r.Checks = append(r.Checks, c)
	r.Summary.Total++
	r.Summary.ElapsedMs += c.ElapsedMs
	if c.SelfCheck {
		r.Summary.SelfChecks++
	}
	switch c.Severity {
	case Pass:
		r.Summary.Passed++
	case Warn:
		r.Summary.Warned++
	case Fail:
		r.Summary.Failed++
	case Skip:
		r.Summary.Skipped++
	}
}

// AddAll appends multiple check results.
func (r *Report) AddAll(checks []CheckResult) {
	for _, c := range checks {
		r.Add(c)
	}
}

// HasFailures returns true if any check failed OR skipped without being
// in the explicit allowlist. Skips count as failures (drift
// postmortem) — a skipped test means UNKNOWN, not pass. Use
// SetAllowedSkips to exempt specific check names that the user has
// explicitly marked as intentionally skipped.
//
// V7 v7.72 §9.0 auto-allowlist: skips whose message names
// the profile contract ("V7 v7.72 §9.0" or "outside --profile core")
// are intentional by construction (extension category / per-check
// carve-out under --profile core). They count as PASS without manual
// -allow-skip wrangling. This preserves the v7.69 invariant for every
// other skip class.
func (r *Report) HasFailures() bool {
	if r.Summary.Failed > 0 {
		return true
	}
	if r.Summary.Skipped == 0 {
		return false
	}
	for _, c := range r.Checks {
		if c.Severity != Skip {
			continue
		}
		if r.allowedSkips[c.Name] {
			continue
		}
		if isProfileKeyedSkip(c) {
			continue
		}
		if isEnvironmentSkip(c) {
			continue
		}
		if isTotalHandlerSkip(c) {
			continue
		}
		return true
	}
	return false
}

// isTotalHandlerSkip reports whether a SKIP is the §3.3 total-handler exception
// (0.8.2.8): the 404 handler_not_found row cannot be driven against a peer that
// registers a catch-all handler, because no unregistered path exists. The spec
// rules such a peer CONFORMANT and requires a declared SKIP that MUST NOT be
// reported as a failure of the row — so this skip class is exempt from the
// PASS/FAIL gate, the same way profile and environment skips are. Keyed on the
// distinctive marker the check stamps (connectivity_section33.go), so it can
// never catch that check's OTHER, genuinely-unattributable skip, which stays
// scored. This closes the blocker core-py named: go moved FAIL→SKIP but the
// gate still scored the SKIP, so a spec-mandated declared SKIP failed the run.
func isTotalHandlerSkip(c CheckResult) bool {
	return strings.Contains(c.Message, totalHandlerSkipMarker)
}

// isEnvironmentSkip reports whether a SKIP is conditioned on a local-test-
// environment capability that is a hard physical limit, not a conformance gap
// — currently the multi-sig accept path, which can only run when the verifying
// peer's keypair is available on disk (required to produce a signature
// attributable to the peer, per §5.5 M6 root-at-local). Managed peers
// (peer-manager) always have their key on disk and DO run it; only ad-hoc
// ephemeral peers skip. Distinct from a profile carve-out, so it is bucketed
// and reported separately rather than masquerading as a §9.0 skip.
func isEnvironmentSkip(c CheckResult) bool {
	return strings.Contains(c.Message, "accept-path requires the peer's on-disk key")
}

// isProfileKeyedSkip reports whether a SKIP was generated by a v7.72
// §9.0 profile carve-out (extension-only category or per-check
// extension-targeted exclusion under --profile core). Profile-keyed
// skips are intentional and do not count toward the PASS/FAIL gate.
func isProfileKeyedSkip(c CheckResult) bool {
	if strings.Contains(c.Message, "V7 v7.72 §9.0") {
		return true
	}
	if strings.Contains(c.Message, "outside --profile core") {
		return true
	}
	return false
}

// SetAllowedSkips records the set of check names that the user has
// explicitly marked as intentionally skipped (the `-allow-skip` flag).
// Allowlisted skips do not count toward the run's PASS/FAIL gate.
func (r *Report) SetAllowedSkips(names []string) {
	r.allowedSkips = make(map[string]bool, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			r.allowedSkips[n] = true
		}
	}
}

// ExcludeCategories removes checks matching the given selectors and recalculates
// the summary. A selector is either a bare category ("serving_mode") or a single
// check ("serving_mode.content_get_out_of_scope_404").
//
// Check-level selectors exist because a whole-category exclude is a blunt
// instrument that hides real failures. `validate-complete.sh` pass 1 excluded
// all of serving_mode to dodge four T4 checks that are genuinely unsatisfiable
// under closure-of-signed-root scope (if everything is in scope, nothing is out
// of scope) — and in doing so it stopped scoring 49 checks that ARE meaningful
// there. That masked a peer failing every in-scope serve under closure scope
// while the run still reported 0 failures. Exclude the four, not the category.
func (r *Report) ExcludeCategories(sel map[string]bool) {
	var filtered []CheckResult
	for _, c := range r.Checks {
		if !sel[c.Category] && !sel[c.Category+"."+c.Name] {
			filtered = append(filtered, c)
		}
	}
	// Re-sum through Add rather than inline, so there is exactly ONE place
	// that knows how to count a CheckResult.
	//
	// This was an inline copy of Add's switch, and it bit immediately: adding
	// Summary.SelfChecks updated Add and left this copy behind, so a plain
	// `-category` run reported the self-check count and a full run — which
	// passes -exclude and therefore lands here — silently reported zero. The
	// per-check [self] markers still printed, so the output looked complete
	// while the roll-up was missing. A second summation path is a place for
	// every future field to be forgotten.
	r.Summary = Summary{}
	r.Checks = nil
	for _, c := range filtered {
		r.Add(c)
	}
	// Budget warning is recomputed here so an exclude doesn't leave a stale
	// warning attached when the excluded category was the cause.
	r.BudgetWarning = ""
	r.applyBudgetCheck()
}

// applyBudgetCheck populates BudgetWarning if Summary.ElapsedMs exceeds
// RuntimeBudgetMs. Idempotent — safe to call after summary recomputation.
func (r *Report) applyBudgetCheck() {
	if r.Summary.ElapsedMs > RuntimeBudgetMs {
		r.BudgetWarning = fmt.Sprintf(
			"total runtime %s exceeds soft budget %s — possible perf regression, consider /ultrareview or per-category timing inspection",
			(time.Duration(r.Summary.ElapsedMs) * time.Millisecond).Truncate(time.Second),
			(time.Duration(RuntimeBudgetMs) * time.Millisecond).Truncate(time.Second),
		)
	}
}

// Finalize computes any post-run derived fields (currently the runtime
// budget warning). Call once at the end of a run, before WriteText/WriteJSON.
func (r *Report) Finalize() {
	r.applyBudgetCheck()
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a human-readable report. When failuresOnly is true, passing
// checks are suppressed — only failures, warnings, and skips are shown.
func (r *Report) WriteText(w io.Writer, failuresOnly bool) {
	if len(r.Peers) > 0 {
		fmt.Fprintf(w, "Multi-Peer Convergence Report\n")
		fmt.Fprintf(w, "=============================\n")
		for _, p := range r.Peers {
			fmt.Fprintf(w, "Peer %s:  %s (%s)\n", p.Label, p.Addr, p.PeerID)
		}
	} else {
		fmt.Fprintf(w, "Peer Validation Report\n")
		fmt.Fprintf(w, "======================\n")
		fmt.Fprintf(w, "Peer:      %s\n", r.PeerAddr)
		if r.PeerID != "" {
			fmt.Fprintf(w, "PeerID:    %s\n", r.PeerID)
		}
	}
	fmt.Fprintf(w, "Timestamp: %s\n", r.Timestamp)
	fmt.Fprintf(w, "\n")

	// Group by category.
	categories := make(map[string][]CheckResult)
	var order []string
	for _, c := range r.Checks {
		if _, seen := categories[c.Category]; !seen {
			order = append(order, c.Category)
		}
		categories[c.Category] = append(categories[c.Category], c)
	}

	for _, cat := range order {
		checks := categories[cat]
		var visible []CheckResult
		for _, c := range checks {
			if !failuresOnly || c.Severity != Pass {
				visible = append(visible, c)
			}
		}
		if failuresOnly && len(visible) == 0 {
			continue
		}
		fmt.Fprintf(w, "[%s]\n", cat)
		for _, c := range visible {
			icon := severityIcon(c.Severity)
			name := c.Name
			if c.SelfCheck {
				name += " [self]"
			}
			fmt.Fprintf(w, "  %s %-50s %s\n", icon, name, c.SpecRef)
			if c.Severity != Pass {
				fmt.Fprintf(w, "    %s\n", c.Message)
			}
			if c.Details != nil {
				fmt.Fprintf(w, "    details: %v\n", c.Details)
			}
		}
		fmt.Fprintln(w)
	}

	// Category summary table — pass/warn/fail/skip counts plus per-category
	// elapsed. Skip is its own column (not lumped with Fail) so the reader
	// can see exactly what didn't run; the run-result gate below treats
	// Skip as Fail unless explicitly allowlisted via -allow-skip.
	fmt.Fprintf(w, "%-20s %5s %5s %5s %5s %5s %10s\n", "Category", "Pass", "Warn", "Fail", "Skip", "Total", "Elapsed")
	fmt.Fprintf(w, "%-20s %5s %5s %5s %5s %5s %10s\n", "--------", "----", "----", "----", "----", "-----", "-------")
	for _, cat := range order {
		checks := categories[cat]
		var p, wa, f, sk int
		var elapsedMs int64
		for _, c := range checks {
			elapsedMs += c.ElapsedMs
			switch c.Severity {
			case Pass:
				p++
			case Warn:
				wa++
			case Fail:
				f++
			case Skip:
				sk++
			}
		}
		fmt.Fprintf(w, "%-20s %5d %5d %5d %5d %5d %10s\n", cat, p, wa, f, sk, len(checks),
			(time.Duration(elapsedMs) * time.Millisecond).Truncate(time.Millisecond))
	}
	fmt.Fprintln(w)

	// Count skips by class. Profile-keyed skips (v7.72 §9.0 carve-outs)
	// are auto-allowlisted by HasFailures; surface them in their own
	// bucket so the reader can tell "intentional by --profile core" from
	// "user said allow this" from "the rest count as FAIL".
	var allowedSkip, profileSkip, envSkip, postureSkip, unallowedSkip int
	for _, c := range r.Checks {
		if c.Severity != Skip {
			continue
		}
		switch {
		case r.allowedSkips[c.Name]:
			allowedSkip++
		case isProfileKeyedSkip(c):
			profileSkip++
		case isEnvironmentSkip(c):
			envSkip++
		case isTotalHandlerSkip(c):
			postureSkip++
		default:
			unallowedSkip++
		}
	}

	// G-23: stamp the headline total PARTIAL when surfaces went unexercised.
	// The COVERAGE roll-up below already names what did not run, but the
	// "Summary:" line is the one a reader lifts out of context — and twice this
	// cycle a bare-peer partial total (27-28 surfaces unexercised) was reported
	// as a full-surface number. Marking the total itself means the number cannot
	// travel without the caveat attached. A fully-configured run (e.g.
	// validate-complete.sh) has zero unexercised surfaces and prints the clean
	// form unchanged.
	unexercised := r.unexercisedSurfaces()
	if len(unexercised) > 0 {
		fmt.Fprintf(w, "Summary: PARTIAL — %d total ran, but %d surface(s) were UNEXERCISED (see COVERAGE); this is NOT a full-surface measurement — do not cite this total as one. Use scripts/validate-complete.sh <impl>.\n",
			r.Summary.Total, len(unexercised))
		fmt.Fprintf(w, "         %d passed, %d warned, %d failed, %d skipped (elapsed %s)\n",
			r.Summary.Passed, r.Summary.Warned, r.Summary.Failed, r.Summary.Skipped,
			(time.Duration(r.Summary.ElapsedMs) * time.Millisecond).Truncate(time.Millisecond))
	} else {
		fmt.Fprintf(w, "Summary: %d total, %d passed, %d warned, %d failed, %d skipped (elapsed %s)\n",
			r.Summary.Total, r.Summary.Passed, r.Summary.Warned, r.Summary.Failed, r.Summary.Skipped,
			(time.Duration(r.Summary.ElapsedMs) * time.Millisecond).Truncate(time.Millisecond))
	}

	// Self-checks, said out loud. Without this line a reader comparing two
	// peers' totals is silently comparing a number that includes ~29 results
	// produced by the same core-go library in both runs.
	if r.Summary.SelfChecks > 0 {
		fmt.Fprintf(w, "         %d are SELF-CHECKS [self] — run in-process against this validator's own\n",
			r.Summary.SelfChecks)
		fmt.Fprintf(w, "         library; they never contacted %s. Peer-attributable: %d of %d.\n",
			r.PeerAddr, r.Summary.Total-r.Summary.SelfChecks, r.Summary.Total)
		fmt.Fprintf(w, "         A self-check PASS is evidence about core-go, not about this peer.\n")
	}

	if unallowedSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) count as FAIL — an unexercised surface is an UNTESTED surface\n", unallowedSkip)
	}
	if profileSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL gate\n", profileSkip)
	}
	if envSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) conditioned on local-test-env capability (e.g. multi-sig accept path needs the peer's on-disk key) — exempt from the FAIL gate\n", envSkip)
	}
	if postureSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) are §3.3 total-handler declared SKIPs (0.8.2.8) — the peer registers a catch-all, so the 404 row is unconstructible and the peer is conformant; exempt from the FAIL gate\n", postureSkip)
	}
	if allowedSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) allowlisted via -allow-skip — exempt from the FAIL gate\n", allowedSkip)
	}

	// COVERAGE — the roll-up this suite was missing, and the reason a run could
	// look green while whole surfaces went untested.
	//
	// The per-check gate was already honest (a harness skip does count as FAIL),
	// but nothing told the reader WHAT never ran or HOW to make it run. A default
	// invocation exercises ~1429 checks; a fully-configured one exercises ~1500+,
	// and the difference is not noise — it is the local-files round-trip, the
	// published-root/manifest face, origination, concurrent-reentry, and the
	// liveness/reconnect vectors, several of which fail the first time they are
	// actually run. A number that omits them is not a smaller number, it is a
	// different claim.
	//
	// So: name every unexercised surface, grouped, with the switch that closes
	// it. This project implements everything, which means the target is zero.
	if len(unexercised) > 0 {
		fmt.Fprintf(w, "\nCOVERAGE: %d check(s) did not run, across %d surface(s). An unexercised surface is an\n", unallowedSkip+allowedSkip, len(unexercised))
		fmt.Fprintln(w, "          UNTESTED surface — this run does NOT prove the full system works.")
		fmt.Fprintln(w, "          Close each; do not allowlist:")
		for _, line := range unexercised {
			fmt.Fprintf(w, "          - %s\n", line)
		}
		fmt.Fprintln(w, "          scripts/validate-complete.sh configures every surface in one command.")
	}

	// DECLARED EXCLUSIONS — printed on every run, including a clean one and
	// including -failures-only. A skip says "this did not run here"; an
	// exclusion says "this CANNOT run here, and here is where it is verified
	// instead." Suppressing it on a green run would restore exactly the
	// reading §5.4a forbids: a report against rust or py that looks like it
	// covered the pair.
	if len(r.Exclusions) > 0 {
		fmt.Fprintf(w, "\nDECLARED EXCLUSIONS: %d pinned vector(s) are NOT exercised against %s by this\n", len(r.Exclusions), r.PeerAddr)
		fmt.Fprintln(w, "          suite. They are not passes and are not counted. Reporting one as a")
		fmt.Fprintln(w, "          cross-impl vector pass is a false conformance claim (NETWORK §5.4a,")
		fmt.Fprintln(w, "          GUIDE-CONFORMANCE §5.2b.1).")
		for _, e := range r.Exclusions {
			fmt.Fprintf(w, "          - %s  [%s]\n", e.VectorID, e.SpecRef)
			fmt.Fprintf(w, "              not drivable: %s\n", e.Why)
			fmt.Fprintf(w, "              satisfied by: %s\n", e.SatisfiedBy)
			fmt.Fprintf(w, "              mutation:     %s\n", e.Mutation)
			fmt.Fprintf(w, "              void when:    %s\n", e.Voids)
		}
	}

	if r.BudgetWarning != "" {
		fmt.Fprintf(w, "BUDGET:  %s\n", r.BudgetWarning)
	}

	switch {
	case r.Summary.Failed > 0:
		fmt.Fprintf(w, "Result: FAIL\n")
	case unallowedSkip > 0:
		fmt.Fprintf(w, "Result: FAIL (un-allowlisted skips)\n")
	case r.Summary.Warned > 0:
		fmt.Fprintf(w, "Result: PASS (with warnings)\n")
	default:
		fmt.Fprintf(w, "Result: PASS\n")
	}
}

func severityIcon(s Severity) string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	case Skip:
		return "SKIP"
	default:
		return "????"
	}
}

// pass, fail, warn, skip are helpers for constructing check results.

func pass(category, name, specRef, msg string) CheckResult {
	return CheckResult{
		Category: category,
		Name:     name,
		Severity: Pass,
		Message:  msg,
		SpecRef:  specRef,
	}
}

func fail(category, name, specRef, msg string) CheckResult {
	return CheckResult{
		Category: category,
		Name:     name,
		Severity: Fail,
		Message:  msg,
		SpecRef:  specRef,
	}
}

func warn(category, name, specRef, msg string) CheckResult {
	return CheckResult{
		Category: category,
		Name:     name,
		Severity: Warn,
		Message:  msg,
		SpecRef:  specRef,
	}
}

func skip(category, name, specRef, msg string) CheckResult {
	return CheckResult{
		Category: category,
		Name:     name,
		Severity: Skip,
		Message:  msg,
		SpecRef:  specRef,
	}
}

// unwrapResultEnvelope checks if a result entity is a system/envelope, and if so,
// unwraps it to return the inner root entity and included domain entities.
// If the entity is not a system/envelope, it returns the entity as-is with nil included.
// This handles both envelope-wrapped and non-wrapped responses for forward compatibility.
func unwrapResultEnvelope(resultEnt entity.Entity) (entity.Entity, map[hash.Hash]entity.Entity, error) {
	if resultEnt.Type != "system/envelope" {
		return resultEnt, nil, nil
	}
	var env entity.Envelope
	if err := ecf.Decode(resultEnt.Data, &env); err != nil {
		return entity.Entity{}, nil, fmt.Errorf("decode system/envelope: %w", err)
	}
	return env.Root, env.Included, nil
}

// decodeResultData decodes resp.Result into a typed value v, transparently
// unwrapping a system/envelope wrapper if present. Returns the (unwrapped)
// result entity so callers can inspect the result Type alongside the typed
// data. Pass v=nil to only get the unwrapped entity back without typed decode.
//
// Use this from helper sites that previously discarded resp.Result after a
// status check. The typed decode catches cross-impl wire-shape regressions
// (e.g. a hash field emitted as zero-byte string instead of being omitted
// per `omitzero`) that status-only checks let through silently. The earliest
// such gap was the F-CIMP-1 omitzero bug in Python's revision:config result
// — it slipped through every conformance run because writeRevisionConfig
// only checked status. The same gap class exists wherever a helper swallows
// the result; this is the function to plug it with.
func decodeResultData(resp types.ExecuteResponseData, v interface{}) (entity.Entity, error) {
	var ent entity.Entity
	if err := ecf.Decode(resp.Result, &ent); err != nil {
		return entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
	}
	inner, _, err := unwrapResultEnvelope(ent)
	if err != nil {
		return entity.Entity{}, err
	}
	if v != nil {
		if err := ecf.Decode(inner.Data, v); err != nil {
			return inner, fmt.Errorf("decode result data: %w", err)
		}
	}
	return inner, nil
}

// decodeResultErrorCode extracts the error code from a non-2xx EXECUTE
// response, accepting either system/protocol/error or compute/error result
// shapes. Different handlers wrap their errors differently — protocol-level
// errors use system/protocol/error, while compute eval errors use the
// compute/error envelope — and the conformance suite needs to assert against
// either uniformly.
func decodeResultErrorCode(resp types.ExecuteResponseData) (string, error) {
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return "", fmt.Errorf("decode result: %w", err)
	}
	switch resultEnt.Type {
	case types.TypeError, "system/error":
		// system/error is a Rust variant of system/protocol/error with the
		// same {code, message} shape — accepted here so the conformance test
		// can focus on the chain-root check; the type-name deviation surfaces
		// separately via encoding/type-system tests.
		d, err := types.ErrorDataFromEntity(resultEnt)
		if err != nil {
			return "", fmt.Errorf("decode protocol error: %w", err)
		}
		return d.Code, nil
	case types.TypeComputeError:
		d, err := types.ComputeErrorDataFromEntity(resultEnt)
		if err != nil {
			return "", fmt.Errorf("decode compute error: %w", err)
		}
		return d.Code, nil
	default:
		return "", fmt.Errorf("expected system/protocol/error or compute/error, got %s", resultEnt.Type)
	}
}

// requireEmbeddedCapUnauthorized asserts the response is a 403 carrying the
// embedded_cap_unauthorized error code (R1/SB1/CP1 chain-root rejection per
// PROPOSAL-COHERENT-CAPABILITY-AUTHORITY). Any other 4xx — scope violation,
// unknown identity, generic unauthorized — is a fail because it doesn't prove
// the chain-root walk happened. `what` describes the operation for the
// failure message (e.g., "subscribe with foreign deliver_token").
func requireEmbeddedCapUnauthorized(resp types.ExecuteResponseData, what string) CheckOutcome {
	if resp.Status >= 200 && resp.Status < 300 {
		return FailCheck(fmt.Sprintf("%s should be rejected with 403 embedded_cap_unauthorized; got success status=%d (chain-root check not enforced)", what, resp.Status))
	}
	code, err := decodeResultErrorCode(resp)
	if err != nil {
		return FailCheck(fmt.Sprintf("%s rejected with status=%d but error code unreadable: %v", what, resp.Status, err))
	}
	if code != "embedded_cap_unauthorized" {
		return FailCheck(fmt.Sprintf("%s rejected with status=%d code=%q; expected 403 embedded_cap_unauthorized — peer 4xx'd for an unrelated reason, so we cannot verify chain-root enforcement", what, resp.Status, code))
	}
	if resp.Status != 403 {
		return FailCheck(fmt.Sprintf("%s correctly surfaced embedded_cap_unauthorized but status=%d (spec requires 403)", what, resp.Status))
	}
	return PassCheck(fmt.Sprintf("%s rejected with 403 embedded_cap_unauthorized", what))
}

// mustCreateEntity creates a test entity from the given type name and data, panicking on failure.
func mustCreateEntity(typeName string, data interface{}) entity.Entity {
	raw, err := ecf.Encode(data)
	if err != nil {
		panic(fmt.Sprintf("encode test data: %v", err))
	}
	ent, err := entity.NewEntity(typeName, cbor.RawMessage(raw))
	if err != nil {
		panic(fmt.Sprintf("create test entity: %v", err))
	}
	return ent
}

// surfaceSwitch maps a recognisable phrase in a skip message to the concrete
// switch that turns the surface on. Keyed on the guidance the checks already
// emit, so a new skip that reuses the vocabulary is picked up for free.
var surfaceSwitches = []struct {
	match, surface, how string
}{
	{"budget_exhausted", "!! WHOLE CATEGORIES NEVER RAN — the -timeout window expired mid-suite",
		"raise -timeout (default 10m); this is coverage loss, not a slow peer"},
	{"-reference-peer", "origination (A-role: the peer DISPATCHES, not just answers)",
		"-reference-peer <go-peer-addr>"},
	{"--validate", "§7a concurrent-reentry attestation",
		"start the target with --validate"},
	{"-poll-url", "published-root / manifest / HTTP-poll serving face",
		"start with --publish-root --http-poll-addr <a> --serve-namespace system/content/public, pass -poll-url http://<a>"},
	{"local/files root", "LOCAL-FILES read/write/list/delete round-trip + frame-budget chunking",
		"start with --files <name>:/dir:local/files/<name>/"},
	{"publish_descriptors", "LOCAL-FILES §10.5 V3 descriptor publication",
		"configure a root with publish_descriptors=true"},
	{"-keepalive-envelope-ms", "§5.4 keepalive escalation + §4.1 reconnect/retry vectors",
		"start with --keepalive 2000,1000,2 and pass -keepalive-envelope-ms 6000"},
	{"--peer-issued-registry", "peer-issued registry wire vectors",
		"start with --peer-issued-registry <pid>@<url> (fixture wiring — the deferred Keystone leg)"},
	{"rendezvous node", "SIGNALING §4/§5 node role — the whole punch-carrier surface",
		"IMPLEMENT IT (§2.1 server role); Go: start with --signaling-node"},
	{"NOT OFFERED", "NETWORK §6.7 reachability facts",
		"IMPLEMENT IT (observe-address + check-reachability)"},
}

// unexercisedSurfaces returns one human line per skipped check that represents a
// surface which did not run, annotated with how to make it run. Profile-keyed
// and explicitly-allowlisted skips are excluded — those are deliberate scope
// decisions, not silent gaps.
func (r *Report) unexercisedSurfaces() []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range r.Checks {
		if c.Severity != Skip || r.allowedSkips[c.Name] || isProfileKeyedSkip(c) || isTotalHandlerSkip(c) {
			continue
		}
		surface, how := "unclassified", "read the check's message"
		for _, s := range surfaceSwitches {
			if strings.Contains(c.Message, s.match) {
				surface, how = s.surface, s.how
				break
			}
		}
		// Budget exhaustion is reported per category, not deduped to one line:
		// "4 categories never ran" is the fact, and which four is the actionable
		// part. Every other surface dedups, since ten skips from one missing
		// flag are one gap.
		key := surface
		if strings.Contains(c.Message, "budget_exhausted") {
			key = surface + "|" + c.Category
			out = append(out, fmt.Sprintf("%s [%s] → %s", surface, c.Category, how))
			seen[key] = true
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, fmt.Sprintf("%s → %s", surface, how))
	}
	sort.Strings(out)
	return out
}
