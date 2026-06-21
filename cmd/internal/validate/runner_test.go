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
