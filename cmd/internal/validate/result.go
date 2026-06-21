package validate

import (
	"encoding/json"
	"fmt"
	"io"
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
		PeerAddr:  addr,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// Add appends a check result and updates the summary.
func (r *Report) Add(c CheckResult) {
	r.Checks = append(r.Checks, c)
	r.Summary.Total++
	r.Summary.ElapsedMs += c.ElapsedMs
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
		return true
	}
	return false
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

// ExcludeCategories removes all checks in the given categories and recalculates the summary.
func (r *Report) ExcludeCategories(cats map[string]bool) {
	var filtered []CheckResult
	for _, c := range r.Checks {
		if !cats[c.Category] {
			filtered = append(filtered, c)
		}
	}
	r.Checks = filtered
	r.Summary = Summary{}
	for _, c := range r.Checks {
		r.Summary.Total++
		r.Summary.ElapsedMs += c.ElapsedMs
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
			fmt.Fprintf(w, "  %s %-50s %s\n", icon, c.Name, c.SpecRef)
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
	var allowedSkip, profileSkip, envSkip, unallowedSkip int
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
		default:
			unallowedSkip++
		}
	}

	fmt.Fprintf(w, "Summary: %d total, %d passed, %d warned, %d failed, %d skipped (elapsed %s)\n",
		r.Summary.Total, r.Summary.Passed, r.Summary.Warned, r.Summary.Failed, r.Summary.Skipped,
		(time.Duration(r.Summary.ElapsedMs) * time.Millisecond).Truncate(time.Millisecond))

	if unallowedSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) count as FAIL (use -allow-skip name1,name2,... to exempt intentional skips)\n", unallowedSkip)
	}
	if profileSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL gate\n", profileSkip)
	}
	if envSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) conditioned on local-test-env capability (e.g. multi-sig accept path needs the peer's on-disk key) — exempt from the FAIL gate\n", envSkip)
	}
	if allowedSkip > 0 {
		fmt.Fprintf(w, "         %d skip(s) allowlisted via -allow-skip — exempt from the FAIL gate\n", allowedSkip)
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
