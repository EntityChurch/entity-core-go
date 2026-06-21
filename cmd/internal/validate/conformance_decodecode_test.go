package validate

import (
	"strings"
	"testing"
)

func mkEmission(label string, rejected bool, code string, hasCode bool) *ConformanceEmission {
	em := &ConformanceEmission{
		DecodeResults: map[string]bool{"tag_reject.1": rejected},
		DecodeCodes:   map[string]string{},
	}
	if hasCode {
		em.DecodeCodes["tag_reject.1"] = code
	}
	return em
}

func runDecodeDiff(emissions map[string]*ConformanceEmission) CheckOutcome {
	var peers []ConformancePeerEmission
	for label := range emissions {
		peers = append(peers, ConformancePeerEmission{Label: label, Path: label})
	}
	// Deterministic order for stable messages.
	for i := range peers {
		for j := i + 1; j < len(peers); j++ {
			if peers[j].Label < peers[i].Label {
				peers[i], peers[j] = peers[j], peers[i]
			}
		}
	}
	return diffDecodeReject("tag_reject.1", peers, emissions)
}

func TestDiffDecodeReject_CodeMatch_Pass(t *testing.T) {
	out := runDecodeDiff(map[string]*ConformanceEmission{
		"go":   mkEmission("go", true, "non_canonical_ecf", true),
		"rust": mkEmission("rust", true, "non_canonical_ecf", true),
	})
	if out.severity != Pass {
		t.Fatalf("want Pass, got %v: %s", out.severity, out.message)
	}
}

func TestDiffDecodeReject_WrongCode_Fail(t *testing.T) {
	out := runDecodeDiff(map[string]*ConformanceEmission{
		"go":   mkEmission("go", true, "non_canonical_ecf", true),
		"rust": mkEmission("rust", true, "invalid_cbor", true),
	})
	if out.severity != Fail {
		t.Fatalf("want Fail on code mismatch, got %v: %s", out.severity, out.message)
	}
	if !strings.Contains(out.message, "invalid_cbor") {
		t.Errorf("message should name the divergent code: %s", out.message)
	}
}

func TestDiffDecodeReject_MissingCode_Warn(t *testing.T) {
	// One impl's emission predates decode_codes — reject confirmed, code
	// can't be asserted for it → WARN, not FAIL (so it doesn't break the
	// cohort before that team updates its emit harness).
	out := runDecodeDiff(map[string]*ConformanceEmission{
		"go":   mkEmission("go", true, "non_canonical_ecf", true),
		"rust": mkEmission("rust", true, "", false),
	})
	if out.severity != Warn {
		t.Fatalf("want Warn on missing code, got %v: %s", out.severity, out.message)
	}
	if !strings.Contains(out.message, "rust") {
		t.Errorf("message should name the impl lacking decode_codes: %s", out.message)
	}
}

func TestDiffDecodeReject_SplitRejection_Fail(t *testing.T) {
	out := runDecodeDiff(map[string]*ConformanceEmission{
		"go":   mkEmission("go", true, "non_canonical_ecf", true),
		"rust": mkEmission("rust", false, "", false),
	})
	if out.severity != Fail {
		t.Fatalf("want Fail on split rejection, got %v: %s", out.severity, out.message)
	}
}

func TestExpectedRejectCode(t *testing.T) {
	if got := expectedRejectCode("tag_reject.3"); got != "non_canonical_ecf" {
		t.Errorf("tag_reject → %q, want non_canonical_ecf", got)
	}
	if got := expectedRejectCode("some_future_category.1"); got != "" {
		t.Errorf("undocumented category → %q, want empty", got)
	}
}
