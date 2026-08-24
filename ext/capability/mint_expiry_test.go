package capability

import "testing"

// clampMintExpiry — §6.2 request step-4 temporal ceiling
// (PROPOSAL-CAPABILITY-MINT-TEMPORAL-CEILING / arch ROUTING-2026-08-17-f §3).
// A request-minted token MUST NOT outlive the caller's cap, the policy ttl_ms,
// or the request ttl_ms — whichever defined value is smallest.
func TestClampMintExpiry(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }
	const now = 1_000_000

	cases := []struct {
		name      string
		callerExp *uint64
		policyTTL *uint64
		reqTTL    *uint64
		want      *uint64
	}{
		{"none defined → no expiry", nil, nil, nil, nil},
		{"request ttl only", nil, nil, u(5_000), u(now + 5_000)},
		{"policy ttl only", nil, u(3_000), nil, u(now + 3_000)},
		{"caller exp only", u(now + 2_000), nil, nil, u(now + 2_000)},
		// The load-bearing case: caller cap expires long before the requested
		// ttl — mint MUST clamp to the caller cap, not honor the 10y request.
		{"mint cannot outlive caller cap", u(now + 3_600_000), nil, u(315_360_000_000), u(now + 3_600_000)},
		// Policy ttl is the tightest ceiling.
		{"policy ttl is tightest", u(now + 9_000), u(1_000), u(9_000), u(now + 1_000)},
		// Request ttl is the tightest.
		{"request ttl is tightest", u(now + 9_000), u(9_000), u(500), u(now + 500)},
		// Caller cap is the tightest.
		{"caller cap is tightest", u(now + 100), u(9_000), u(9_000), u(now + 100)},
		// CAP-6 rule 2 (0.8.1): ttl_ms == 0 is a DEFINED value meaning "expire
		// immediately" — its term is createdAt+0 = createdAt, and it is a real
		// ceiling that can win the MIN. nil (not 0) is the sole "no bound" spelling;
		// the case at line 20 covers all-nil → nil. This inverts the pre-CAP-6
		// reading that treated 0 as "not defined."
		{"zero request ttl → expire immediately (== createdAt)", nil, nil, u(0), u(now)},
		{"zero policy ttl → expire immediately, beats finite request", nil, u(0), u(4_000), u(now)},
		{"zero request ttl beats finite policy", nil, u(4_000), u(0), u(now)},
		// Overflow: a ttl so large that now+ttl wraps uint64 drops out (matches
		// rust's checked_add→None), rather than wrapping to a past expiry. With
		// no other ceiling, the result is nil (no expiry); with a caller cap,
		// the caller cap binds.
		{"overflow request ttl drops out → nil", nil, nil, u(^uint64(0) - 10), nil},
		{"overflow request ttl drops, caller cap binds", u(now + 500), nil, u(^uint64(0) - 10), u(now + 500)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clampMintExpiry(now, tc.callerExp, tc.policyTTL, tc.reqTTL)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("want nil, got %d", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("want %d, got nil", *tc.want)
			case tc.want != nil && got != nil && *got != *tc.want:
				t.Fatalf("want %d, got %d", *tc.want, *got)
			}
		})
	}
}
