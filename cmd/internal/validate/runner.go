package validate

import (
	"fmt"
	"os"
	"time"
)

// progressOut is the stream where per-check progress lines are written. By
// default this is os.Stderr — silence during a long run is a worse UX than a
// few extra lines of output, and stderr keeps the JSON/text report on stdout
// uncontaminated. Tests may swap this to discard noise.
var progressOut = os.Stderr

// excludedSelectors mirrors the -exclude set so the progress stream can say
// which checks the report will drop. It is set before the run; Report.
// ExcludeCategories applies the same selectors to the scored output after.
// Selector forms match ExcludeCategories: a bare category ("serving_mode")
// or one check ("serving_mode.content_get_out_of_scope_404").
var excludedSelectors map[string]bool

// SetExcludedSelectors records the -exclude set for progress annotation.
func SetExcludedSelectors(sel map[string]bool) { excludedSelectors = sel }

func isExcludedSelector(category, name string) bool {
	if excludedSelectors == nil {
		return false
	}
	return excludedSelectors[category] || excludedSelectors[category+"."+name]
}

// CheckRunner implements the declare-then-run validation pattern.
// All checks are declared upfront via Declare, then executed via Run.
// Results returns all declared checks in declaration order — any that
// were declared but never run appear as FAIL automatically.
//
// This eliminates silent check skipping from early returns. Every
// declared check always produces a result in the report.
type CheckRunner struct {
	category   string
	declared   []string
	specRefs   map[string]string
	selfChecks map[string]bool
	results    map[string]CheckResult
	data       map[string]any
}

// CheckOutcome is returned by check functions to indicate the result.
type CheckOutcome struct {
	severity Severity
	message  string
	details  any
}

// Severity exposes the outcome's severity so a caller that wraps a check
// can branch on the result — e.g. recording state for a later check only
// when the earlier one actually passed.
func (o CheckOutcome) Severity() Severity { return o.severity }

// NewCheckRunner creates a runner for the given validation category.
func NewCheckRunner(category string) *CheckRunner {
	return &CheckRunner{
		category:   category,
		specRefs:   make(map[string]string),
		selfChecks: make(map[string]bool),
		results:    make(map[string]CheckResult),
		data:       make(map[string]any),
	}
}

// Declare registers a check that must produce a result. Call this for
// every check before calling Run. Checks declared but never run appear
// as FAIL in Results().
func (r *CheckRunner) Declare(name, specRef string) {
	if _, exists := r.specRefs[name]; exists {
		panic(fmt.Sprintf("CheckRunner: check %q declared twice", name))
	}
	r.declared = append(r.declared, name)
	r.specRefs[name] = specRef
}

// DeclareSelf registers a check that never contacts the peer under test —
// an offline KAT, a pure ordering rule, a round-trip through our own codec.
//
// Use it for any check whose function does not take the peer client. The
// result still counts exactly as before; what changes is that the report can
// say whose code it measured. A self-check PASS in a run against rust is a
// statement about core-go, and until it is labelled, nothing in the output
// distinguishes it from a probe that actually reached the peer.
func (r *CheckRunner) DeclareSelf(name, specRef string) {
	r.Declare(name, specRef)
	r.selfChecks[name] = true
}

// Run executes a named check. The check must have been declared.
// Panics in fn are recovered and recorded as FAIL.
func (r *CheckRunner) Run(name string, fn func() CheckOutcome) {
	specRef, ok := r.specRefs[name]
	if !ok {
		panic(fmt.Sprintf("CheckRunner: Run(%q) but check was not declared", name))
	}
	if _, already := r.results[name]; already {
		panic(fmt.Sprintf("CheckRunner: Run(%q) called twice", name))
	}

	fmt.Fprintf(progressOut, "RUN  %s.%s\n", r.category, name)
	start := time.Now()

	var outcome CheckOutcome
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				outcome = FailCheck(fmt.Sprintf("panic: %v", rec))
			}
		}()
		outcome = fn()
	}()

	elapsed := time.Since(start)
	// A check the report will EXCLUDE still runs, and its progress line
	// still streams. That is how `FAIL serving_mode.content_get_out_of_scope_404`
	// scrolls past during a run that then reports 0 failures and exits 0 —
	// which reads as the report hiding a failure rather than as the check
	// being deliberately out of scope. It cost core-py a cycle and was
	// reported to us; annotate the line rather than suppressing it, since a
	// dropped line would hide a genuine failure whenever someone excludes a
	// whole category.
	marker := ""
	if isExcludedSelector(r.category, name) {
		marker = "  [excluded from scoring]"
	}
	fmt.Fprintf(progressOut, "%-4s %s.%s %s%s\n", outcome.severity, r.category, name, elapsed.Truncate(time.Millisecond), marker)

	r.results[name] = CheckResult{
		Category:  r.category,
		Name:      name,
		Severity:  outcome.severity,
		Message:   outcome.message,
		SpecRef:   specRef,
		Details:   outcome.details,
		ElapsedMs: elapsed.Milliseconds(),
		SelfCheck: r.selfChecks[name],
	}
}

// Passed returns true if the named check completed with Pass severity.
func (r *CheckRunner) Passed(name string) bool {
	result, ok := r.results[name]
	return ok && result.Severity == Pass
}

// OK returns true if the named check completed with Pass or Warn severity.
func (r *CheckRunner) OK(name string) bool {
	result, ok := r.results[name]
	return ok && (result.Severity == Pass || result.Severity == Warn)
}

// Require checks that all named dependencies succeeded (Pass or Warn).
// Returns a blocking outcome if any dependency failed or hasn't run.
// Usage: if out, ok := r.Require("dep1", "dep2"); !ok { return out }
func (r *CheckRunner) Require(deps ...string) (CheckOutcome, bool) {
	for _, dep := range deps {
		if r.OK(dep) {
			continue
		}
		// A dependency that was intentionally SKIPped (e.g. a hop-2 test
		// needing more peers than this run provides) makes the dependent
		// un-runnable too — that is the same skip propagating, NOT a
		// failure. Only a dependency that actually FAILed (or never ran)
		// blocks as Fail.
		if result, ok := r.results[dep]; ok && result.Severity == Skip {
			return CheckOutcome{
				severity: Skip,
				message:  fmt.Sprintf("skipped: prerequisite %s was skipped", dep),
			}, false
		}
		return BlockCheck(dep), false
	}
	return CheckOutcome{}, true
}

// Store saves a value for retrieval by later checks.
func (r *CheckRunner) Store(key string, v any) {
	r.data[key] = v
}

// Load retrieves a stored value. Returns nil if the key was never stored.
func (r *CheckRunner) Load(key string) any {
	return r.data[key]
}

// Results returns all declared checks in declaration order. Checks that
// were declared but never run are included as FAIL.
func (r *CheckRunner) Results() []CheckResult {
	out := make([]CheckResult, 0, len(r.declared))
	for _, name := range r.declared {
		if result, ok := r.results[name]; ok {
			out = append(out, result)
		} else {
			out = append(out, CheckResult{
				Category:  r.category,
				Name:      name,
				Severity:  Fail,
				SpecRef:   r.specRefs[name],
				SelfCheck: r.selfChecks[name],
				Message:   "not reached (check was declared but never run)",
			})
		}
	}
	return out
}

// --- Outcome constructors ---

func PassCheck(msg string) CheckOutcome {
	return CheckOutcome{severity: Pass, message: msg}
}

func FailCheck(msg string) CheckOutcome {
	return CheckOutcome{severity: Fail, message: msg}
}

func WarnCheck(msg string) CheckOutcome {
	return CheckOutcome{severity: Warn, message: msg}
}

func SkipCheck(msg string) CheckOutcome {
	return CheckOutcome{severity: Skip, message: msg}
}

// BlockCheck indicates a check could not run because a dependency failed.
func BlockCheck(dep string) CheckOutcome {
	return CheckOutcome{severity: Fail, message: fmt.Sprintf("blocked: depends on %s", dep)}
}

// WithDetails attaches structured data to an outcome.
func (o CheckOutcome) WithDetails(d any) CheckOutcome {
	o.details = d
	return o
}
