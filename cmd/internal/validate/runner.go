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

// CheckRunner implements the declare-then-run validation pattern.
// All checks are declared upfront via Declare, then executed via Run.
// Results returns all declared checks in declaration order — any that
// were declared but never run appear as FAIL automatically.
//
// This eliminates silent check skipping from early returns. Every
// declared check always produces a result in the report.
type CheckRunner struct {
	category string
	declared []string
	specRefs map[string]string
	results  map[string]CheckResult
	data     map[string]any
}

// CheckOutcome is returned by check functions to indicate the result.
type CheckOutcome struct {
	severity Severity
	message  string
	details  any
}

// NewCheckRunner creates a runner for the given validation category.
func NewCheckRunner(category string) *CheckRunner {
	return &CheckRunner{
		category: category,
		specRefs: make(map[string]string),
		results:  make(map[string]CheckResult),
		data:     make(map[string]any),
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
	fmt.Fprintf(progressOut, "%-4s %s.%s %s\n", outcome.severity, r.category, name, elapsed.Truncate(time.Millisecond))

	r.results[name] = CheckResult{
		Category:  r.category,
		Name:      name,
		Severity:  outcome.severity,
		Message:   outcome.message,
		SpecRef:   specRef,
		Details:   outcome.details,
		ElapsedMs: elapsed.Milliseconds(),
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
				Category: r.category,
				Name:     name,
				Severity: Fail,
				SpecRef:  r.specRefs[name],
				Message:  "not reached (check was declared but never run)",
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
