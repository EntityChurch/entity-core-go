package validate

import "testing"

// Deterministic teeth for the two §3.3 (0.8.2.7) harness classifiers. The WARN
// (op-absent) and SKIP (catch-all posture) branches are UNREACHABLE go-on-go —
// go implements every type op and registers no `*` catch-all — so the cross-impl
// wire run is the only thing that exercises them at runtime, and it cannot serve
// as a regression guard in CI. These pin each branch so a mutation reddens.

func TestClassifyHandlerNotFound(t *testing.T) {
	cases := []struct {
		name        string
		probeStatus uint
		probeCode   string
		ctlStatus   uint
		ctlCode     string
		want        Severity
	}{
		// A catch-all peer (core-py registers `*`) answers the probe with 501 —
		// a handler IS registered, so the 404 "no handler" row is not drivable.
		// §3.3 satisfaction-mode: MUST NOT pin a check to a row it cannot reach.
		{"catch_all_probe_501_skips", 501, "unsupported_operation", 501, "unsupported_operation", Skip},
		// The reference posture: unregistered path → 404/handler_not_found, and a
		// registered path discriminates (control not 404).
		{"clean_404_passes", 404, "handler_not_found", 501, "unsupported_operation", Pass},
		// A peer that 404s everything cannot attribute the probe's 404 → SKIP.
		{"control_404_everywhere_skips", 404, "handler_not_found", 404, "not_found", Skip},
		// Right status, wrong code → the 404 slot's spelling is off → FAIL.
		{"wrong_code_fails", 404, "not_found", 200, "", Fail},
		// Some other status entirely → FAIL.
		{"unexpected_status_fails", 200, "", 200, "", Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyHandlerNotFound(tc.probeStatus, tc.probeCode, tc.ctlStatus, tc.ctlCode).Severity()
			if got != tc.want {
				t.Fatalf("classifyHandlerNotFound(%d/%q, ctl %d/%q) = %v, want %v",
					tc.probeStatus, tc.probeCode, tc.ctlStatus, tc.ctlCode, got, tc.want)
			}
		})
	}
}

// TestTotalHandlerSkipExemptFromGate pins the §3.3 total-handler exception
// (0.8.2.8): a catch-all peer's declared SKIP is conformant and MUST NOT fail
// the run, while the OTHER skip this same check can emit — the unattributable
// control-404 case — is NOT a conformant posture and MUST still fail the gate.
//
// It drives the REAL classifier output through HasFailures rather than a
// hand-copied message, so a drift in the skip message that unlinks it from
// totalHandlerSkipMarker reddens here instead of silently re-failing the python
// passes (the blocker core-py named). The control-404 row is the mutation
// witness: if isTotalHandlerSkip ever broadened to match it, this row flips.
func TestTotalHandlerSkipExemptFromGate(t *testing.T) {
	// The catch-all posture: probe 501 → declared SKIP naming the catch-all.
	totalHandler := classifyHandlerNotFound(501, "unsupported_operation", 501, "unsupported_operation")
	if totalHandler.Severity() != Skip {
		t.Fatalf("total-handler case: got %v, want SKIP", totalHandler.Severity())
	}
	rTotal := &Report{}
	rTotal.Add(CheckResult{
		Category: catConnectivity, Name: "handler_not_found_on_unregistered_path",
		Severity: totalHandler.Severity(), Message: totalHandler.message,
	})
	if rTotal.HasFailures() {
		t.Fatalf("a §3.3 total-handler declared SKIP must NOT fail the gate (0.8.2.8); message=%q", totalHandler.message)
	}

	// The unattributable posture: registered path also 404s → SKIP, but this is
	// a genuine "cannot tell", not a conformant catch-all — it MUST still fail.
	unattributable := classifyHandlerNotFound(404, "handler_not_found", 404, "not_found")
	if unattributable.Severity() != Skip {
		t.Fatalf("control-404 case: got %v, want SKIP", unattributable.Severity())
	}
	rUnattr := &Report{}
	rUnattr.Add(CheckResult{
		Category: catConnectivity, Name: "handler_not_found_on_unregistered_path",
		Severity: unattributable.Severity(), Message: unattributable.message,
	})
	if !rUnattr.HasFailures() {
		t.Fatalf("an unattributable control-404 SKIP must still fail the gate; message=%q", unattributable.message)
	}
}

func TestClassifyOptionalTypeOp(t *testing.T) {
	const rt = "system/type/compare-result"
	cases := []struct {
		name          string
		status        uint
		errCode       string
		gotResultType string
		want          Severity
	}{
		// Implemented: 200 with the declared result type.
		{"implemented_passes", 200, "", rt, Pass},
		// Implemented but wrong result type → FAIL.
		{"wrong_result_type_fails", 200, "", "system/type/other", Fail},
		// Conformantly not-implemented: 501 with the single §3.3 slot spelling.
		{"not_impl_501_unsupported_operation_warns", 501, "unsupported_operation", "", Warn},
		// The core-rust case: 501 but the code is unreadable because the error
		// entity mislabels the §3.3 `code` field (comes back ""). NOT laundered —
		// this is a real §3.3 error-shape violation → FAIL, not WARN.
		{"not_impl_501_empty_code_fails", 501, "", "", Fail},
		// 501 with some other non-slot spelling → FAIL.
		{"not_impl_501_wrong_code_fails", 501, "not_implemented", "", Fail},
		// The retired pre-0.8.2.7 answer (400 unknown_operation) → FAIL now.
		{"retired_400_fails", 400, "unknown_operation", "", Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyOptionalTypeOp("compare", rt, tc.status, tc.errCode, tc.gotResultType, nil).Severity()
			if got != tc.want {
				t.Fatalf("classifyOptionalTypeOp(status=%d code=%q rt=%q) = %v, want %v",
					tc.status, tc.errCode, tc.gotResultType, got, tc.want)
			}
		})
	}
}
