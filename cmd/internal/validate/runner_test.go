package validate

import (
	"strings"
	"testing"
)

func TestCheckRunner_AllPass(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("a", "§1")
	r.Declare("b", "§2")

	r.Run("a", func() CheckOutcome { return PassCheck("ok") })
	r.Run("b", func() CheckOutcome { return PassCheck("ok") })

	results := r.Results()
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, c := range results {
		if c.Severity != Pass {
			t.Errorf("check %q: expected PASS, got %s", c.Name, c.Severity)
		}
	}
}

func TestCheckRunner_UnrunDeclaredCheckFails(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("a", "§1")
	r.Declare("b", "§2")
	r.Declare("c", "§3")

	r.Run("a", func() CheckOutcome { return PassCheck("ok") })
	// b never run
	r.Run("c", func() CheckOutcome { return PassCheck("ok") })

	results := r.Results()
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Severity != Pass {
		t.Errorf("a: expected PASS, got %s", results[0].Severity)
	}
	if results[1].Severity != Fail {
		t.Errorf("b: expected FAIL (unrun), got %s", results[1].Severity)
	}
	if results[1].Name != "b" {
		t.Errorf("b: expected name 'b', got %q", results[1].Name)
	}
	if results[2].Severity != Pass {
		t.Errorf("c: expected PASS, got %s", results[2].Severity)
	}
}

func TestCheckRunner_RequireBlocks(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("setup", "§1")
	r.Declare("dependent", "§2")

	r.Run("setup", func() CheckOutcome { return FailCheck("setup failed") })
	r.Run("dependent", func() CheckOutcome {
		if out, ok := r.Require("setup"); !ok {
			return out
		}
		return PassCheck("should not reach")
	})

	results := r.Results()
	if results[0].Severity != Fail {
		t.Errorf("setup: expected FAIL, got %s", results[0].Severity)
	}
	if results[1].Severity != Fail {
		t.Errorf("dependent: expected FAIL (blocked), got %s", results[1].Severity)
	}
	if results[1].Message != "blocked: depends on setup" {
		t.Errorf("dependent: unexpected message: %s", results[1].Message)
	}
}

func TestCheckRunner_RequireAllowsWarn(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("setup", "§1")
	r.Declare("dependent", "§2")

	r.Run("setup", func() CheckOutcome { return WarnCheck("minor issue") })
	r.Run("dependent", func() CheckOutcome {
		if out, ok := r.Require("setup"); !ok {
			return out
		}
		return PassCheck("proceeded past warn")
	})

	results := r.Results()
	if results[0].Severity != Warn {
		t.Errorf("setup: expected WARN, got %s", results[0].Severity)
	}
	if results[1].Severity != Pass {
		t.Errorf("dependent: expected PASS, got %s: %s", results[1].Severity, results[1].Message)
	}
}

func TestCheckRunner_StoreLoad(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("producer", "§1")
	r.Declare("consumer", "§2")

	r.Run("producer", func() CheckOutcome {
		r.Store("value", 42)
		return PassCheck("stored")
	})
	r.Run("consumer", func() CheckOutcome {
		v := r.Load("value").(int)
		if v != 42 {
			return FailCheck("wrong value")
		}
		return PassCheck("loaded")
	})

	results := r.Results()
	for _, c := range results {
		if c.Severity != Pass {
			t.Errorf("check %q: expected PASS, got %s: %s", c.Name, c.Severity, c.Message)
		}
	}
}

func TestCheckRunner_DeclarationOrder(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("third", "§3")
	r.Declare("first", "§1")
	r.Declare("second", "§2")

	r.Run("second", func() CheckOutcome { return PassCheck("ok") })
	r.Run("first", func() CheckOutcome { return PassCheck("ok") })
	r.Run("third", func() CheckOutcome { return PassCheck("ok") })

	results := r.Results()
	expected := []string{"third", "first", "second"}
	for i, name := range expected {
		if results[i].Name != name {
			t.Errorf("position %d: expected %q, got %q", i, name, results[i].Name)
		}
	}
}

func TestCheckRunner_PanicRecovery(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("panicker", "§1")

	r.Run("panicker", func() CheckOutcome {
		panic("test panic")
	})

	results := r.Results()
	if results[0].Severity != Fail {
		t.Errorf("expected FAIL after panic, got %s", results[0].Severity)
	}
	if results[0].Message != "panic: test panic" {
		t.Errorf("unexpected message: %s", results[0].Message)
	}
}

func TestCheckRunner_SpecRefPreserved(t *testing.T) {
	r := NewCheckRunner("mycat")
	r.Declare("check1", "SPEC §4.2")

	r.Run("check1", func() CheckOutcome { return PassCheck("ok") })

	results := r.Results()
	if results[0].Category != "mycat" {
		t.Errorf("expected category 'mycat', got %q", results[0].Category)
	}
	if results[0].SpecRef != "SPEC §4.2" {
		t.Errorf("expected spec ref 'SPEC §4.2', got %q", results[0].SpecRef)
	}
}

func TestCheckRunner_WithDetails(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("detailed", "§1")

	r.Run("detailed", func() CheckOutcome {
		return FailCheck("bad").WithDetails(map[string]string{"got": "foo", "want": "bar"})
	})

	results := r.Results()
	if results[0].Details == nil {
		t.Error("expected details to be set")
	}
}

func TestCheckRunner_DuplicateDeclarePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate declare")
		}
	}()
	r := NewCheckRunner("test")
	r.Declare("dup", "§1")
	r.Declare("dup", "§1")
}

func TestCheckRunner_RunUndeclaredPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on undeclared run")
		}
	}()
	r := NewCheckRunner("test")
	r.Run("missing", func() CheckOutcome { return PassCheck("ok") })
}

func TestCheckRunner_RunTwicePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on double run")
		}
	}()
	r := NewCheckRunner("test")
	r.Declare("x", "§1")
	r.Run("x", func() CheckOutcome { return PassCheck("ok") })
	r.Run("x", func() CheckOutcome { return PassCheck("ok") })
}

func TestReport_BudgetWarningTriggers(t *testing.T) {
	r := NewReport("test:0")
	// Just under budget — no warning.
	r.Add(CheckResult{Category: "x", Name: "a", Severity: Pass, ElapsedMs: RuntimeBudgetMs - 1})
	r.Finalize()
	if r.BudgetWarning != "" {
		t.Errorf("under-budget run should not warn, got %q", r.BudgetWarning)
	}
	// Push over.
	r.Add(CheckResult{Category: "x", Name: "b", Severity: Pass, ElapsedMs: 2})
	r.Finalize()
	if r.BudgetWarning == "" {
		t.Fatal("expected budget warning when total exceeds RuntimeBudgetMs")
	}
	if !strings.Contains(r.BudgetWarning, "exceeds soft budget") {
		t.Errorf("warning text unexpected: %q", r.BudgetWarning)
	}
}

func TestReport_ExcludeRecomputesElapsedAndBudget(t *testing.T) {
	r := NewReport("test:0")
	r.Add(CheckResult{Category: "slow", Name: "x", Severity: Pass, ElapsedMs: RuntimeBudgetMs + 1})
	r.Add(CheckResult{Category: "fast", Name: "y", Severity: Pass, ElapsedMs: 5})
	r.Finalize()
	if r.BudgetWarning == "" {
		t.Fatal("setup invariant: should be over budget before exclude")
	}
	r.ExcludeCategories(map[string]bool{"slow": true})
	if r.Summary.ElapsedMs != 5 {
		t.Errorf("elapsed should recompute to 5 after exclude, got %d", r.Summary.ElapsedMs)
	}
	if r.BudgetWarning != "" {
		t.Errorf("excluding the slow category should clear the warning, got %q", r.BudgetWarning)
	}
}

// A check-level selector must drop exactly that check and leave the rest of its
// category scored. The category-wide form is what let a peer fail every
// in-scope closure-scope serve while the run still reported zero failures:
// serving_mode runs under the exclude and is only dropped from SCORING, so
// excluding the category to silence four unsatisfiable T4 checks stopped
// scoring the other 49 as well.
func TestReport_ExcludeCheckLevelSelectorKeepsSiblingsScored(t *testing.T) {
	r := NewReport("test:0")
	r.Add(CheckResult{Category: "serving_mode", Name: "content_get_out_of_scope_404", Severity: Fail})
	r.Add(CheckResult{Category: "serving_mode", Name: "content_get_in_scope_status", Severity: Fail})
	r.Add(CheckResult{Category: "other", Name: "z", Severity: Pass})
	r.Finalize()

	r.ExcludeCategories(map[string]bool{"serving_mode.content_get_out_of_scope_404": true})

	if r.Summary.Total != 2 {
		t.Fatalf("total = %d; want 2 (only the named check dropped)", r.Summary.Total)
	}
	if r.Summary.Failed != 1 {
		t.Errorf("failed = %d; want 1 — the in-scope failure MUST still be scored", r.Summary.Failed)
	}
	for _, c := range r.Checks {
		if c.Name == "content_get_out_of_scope_404" {
			t.Error("the check-level selector did not drop its target")
		}
	}
}

// ExcludeCategories re-sums the report, and it used to do so with an inline
// copy of Add's switch. Summary.SelfChecks was added to Add and not to the
// copy, so a `-category` run reported the self-check roll-up and a full run —
// which passes -exclude — reported zero, with the per-check [self] markers
// still printing so the output looked complete.
//
// The assertion is deliberately "every counter survives", not "SelfChecks
// survives": the defect is a second summation path, and the next field added
// would be dropped the same way.
func TestReport_ExcludeKeepsEveryCounter(t *testing.T) {
	r := NewReport("test:0")
	r.Add(CheckResult{Category: "keep", Name: "a", Severity: Pass, SelfCheck: true, ElapsedMs: 1})
	r.Add(CheckResult{Category: "keep", Name: "b", Severity: Warn, ElapsedMs: 2})
	r.Add(CheckResult{Category: "keep", Name: "c", Severity: Fail, ElapsedMs: 3})
	r.Add(CheckResult{Category: "keep", Name: "d", Severity: Skip, ElapsedMs: 4})
	r.Add(CheckResult{Category: "drop", Name: "e", Severity: Pass, SelfCheck: true, ElapsedMs: 5})
	r.Finalize()

	before := r.Summary
	r.ExcludeCategories(map[string]bool{"drop": true})

	want := Summary{
		Total: 4, Passed: 1, Warned: 1, Failed: 1, Skipped: 1,
		SelfChecks: 1, ElapsedMs: 10,
	}
	if r.Summary != want {
		t.Errorf("summary after exclude = %+v, want %+v (before exclude it was %+v)",
			r.Summary, want, before)
	}
}

func TestCheckRunner_RecordsElapsed(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("timed", "§1")
	r.Run("timed", func() CheckOutcome { return PassCheck("ok") })
	results := r.Results()
	// ElapsedMs is non-negative; we don't assert a positive value because
	// trivially-fast checks can round to 0 ms.
	if results[0].ElapsedMs < 0 {
		t.Errorf("ElapsedMs should be non-negative, got %d", results[0].ElapsedMs)
	}
}

func TestCheckRunner_PassedAndOK(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("pass_check", "§1")
	r.Declare("warn_check", "§2")
	r.Declare("fail_check", "§3")

	r.Run("pass_check", func() CheckOutcome { return PassCheck("ok") })
	r.Run("warn_check", func() CheckOutcome { return WarnCheck("meh") })
	r.Run("fail_check", func() CheckOutcome { return FailCheck("bad") })

	if !r.Passed("pass_check") {
		t.Error("Passed should be true for PASS")
	}
	if r.Passed("warn_check") {
		t.Error("Passed should be false for WARN")
	}
	if r.Passed("fail_check") {
		t.Error("Passed should be false for FAIL")
	}

	if !r.OK("pass_check") {
		t.Error("OK should be true for PASS")
	}
	if !r.OK("warn_check") {
		t.Error("OK should be true for WARN")
	}
	if r.OK("fail_check") {
		t.Error("OK should be false for FAIL")
	}
}

// TestCheckRunner_GateSkipsTrailingSection is the teeth for the S1 gate: when
// a gate prerequisite SKIPs (an optional handler is absent), every check Run
// afterward SKIPs without invoking its body — the whole behavioral section
// degrades to SKIP, not FAIL. Checks Run before Gate are unaffected. A gate
// that FAILs (or never ran) blocks the trailing checks as FAIL, so a genuine
// defect is never laundered into a skip.
func TestCheckRunner_GateSkipsTrailingSection(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("before_gate", "§0")
	r.Declare("handler_present", "§1")
	r.Declare("behavioral_root", "§2")
	r.Declare("behavioral_body_ran", "§3")

	before := false
	r.Run("before_gate", func() CheckOutcome { before = true; return PassCheck("ran before gate") })

	// Handler absent → the presence check SKIPs.
	r.Run("handler_present", func() CheckOutcome { return SkipCheck("handler not present (optional extension)") })

	r.Gate("handler_present")

	// Neither behavioral body may run once the gate is skipped.
	bodyRan := false
	r.Run("behavioral_root", func() CheckOutcome { bodyRan = true; return PassCheck("should not be reached") })
	r.Run("behavioral_body_ran", func() CheckOutcome { bodyRan = true; return FailCheck("should not be reached") })

	if !before {
		t.Fatal("check before Gate() must run")
	}
	if bodyRan {
		t.Fatal("a gated check's body must NOT be invoked when the gate skipped")
	}
	sev := map[string]Severity{}
	for _, c := range r.Results() {
		sev[c.Name] = c.Severity
	}
	if sev["before_gate"] != Pass {
		t.Errorf("before_gate: want PASS, got %s", sev["before_gate"])
	}
	if sev["handler_present"] != Skip {
		t.Errorf("handler_present: want SKIP, got %s", sev["handler_present"])
	}
	if sev["behavioral_root"] != Skip {
		t.Errorf("behavioral_root: want SKIP (gate propagated), got %s", sev["behavioral_root"])
	}
	if sev["behavioral_body_ran"] != Skip {
		t.Errorf("behavioral_body_ran: want SKIP, got %s — a FAIL here is the pre-S1 spurious-fail defect", sev["behavioral_body_ran"])
	}
}

// TestCheckRunner_GateFailBlocksNotSkips proves the gate does not launder a
// genuine failure into a skip: a FAILed gate prerequisite blocks trailing
// checks as FAIL (present-but-broken handler is a real defect, not an absence).
func TestCheckRunner_GateFailBlocksNotSkips(t *testing.T) {
	r := NewCheckRunner("test")
	r.Declare("handler_present", "§1")
	r.Declare("behavioral_root", "§2")

	r.Run("handler_present", func() CheckOutcome { return FailCheck("handler present but manifest is corrupt") })
	r.Gate("handler_present")

	bodyRan := false
	r.Run("behavioral_root", func() CheckOutcome { bodyRan = true; return PassCheck("unreached") })

	if bodyRan {
		t.Fatal("gated body must not run when the gate failed")
	}
	for _, c := range r.Results() {
		if c.Name == "behavioral_root" && c.Severity != Fail {
			t.Errorf("behavioral_root: want FAIL (gate failed, not skipped), got %s", c.Severity)
		}
	}
}
