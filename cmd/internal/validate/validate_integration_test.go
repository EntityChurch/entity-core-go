package validate

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestValidatePeer runs the full validation suite against a remote peer.
// Requires INTEROP_ADDR environment variable (e.g., "127.0.0.1:9001").
func TestValidatePeer(t *testing.T) {
	addr := os.Getenv("INTEROP_ADDR")
	if addr == "" {
		t.Skip("INTEROP_ADDR not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suite := NewValidationSuite(addr)
	report, err := suite.Run(ctx)
	if err != nil {
		t.Fatalf("validation suite error: %v", err)
	}

	// Print the text report.
	report.WriteText(os.Stdout, false)

	// Each check becomes a subtest.
	for _, check := range report.Checks {
		t.Run(check.Category+"/"+check.Name, func(t *testing.T) {
			switch check.Severity {
			case Pass:
				t.Logf("PASS: %s [%s]", check.Message, check.SpecRef)
			case Warn:
				t.Logf("WARN: %s [%s]", check.Message, check.SpecRef)
			case Fail:
				t.Errorf("FAIL: %s [%s]", check.Message, check.SpecRef)
			case Skip:
				t.Skipf("SKIP: %s", check.Message)
			}
		})
	}
}

// TestValidatePeerCategory runs a single category of the validation suite.
// Requires INTEROP_ADDR and INTEROP_CATEGORY environment variables.
func TestValidatePeerCategory(t *testing.T) {
	addr := os.Getenv("INTEROP_ADDR")
	if addr == "" {
		t.Skip("INTEROP_ADDR not set")
	}
	category := os.Getenv("INTEROP_CATEGORY")
	if category == "" {
		t.Skip("INTEROP_CATEGORY not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suite := NewValidationSuite(addr)
	report, err := suite.RunCategory(ctx, category)
	if err != nil {
		t.Fatalf("validation suite error: %v", err)
	}

	report.WriteText(os.Stdout, false)

	for _, check := range report.Checks {
		t.Run(check.Category+"/"+check.Name, func(t *testing.T) {
			switch check.Severity {
			case Pass:
				t.Logf("PASS: %s [%s]", check.Message, check.SpecRef)
			case Warn:
				t.Logf("WARN: %s [%s]", check.Message, check.SpecRef)
			case Fail:
				t.Errorf("FAIL: %s [%s]", check.Message, check.SpecRef)
			case Skip:
				t.Skipf("SKIP: %s", check.Message)
			}
		})
	}
}
