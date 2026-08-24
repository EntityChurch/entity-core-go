package capability

import "testing"

// TestExpiredExclusiveBoundary pins CAP-6 (0.8.1): expiry is an EXCLUSIVE upper
// bound — a capability is expired when now >= expires_at. The exact-boundary case
// (now == expires_at → expired) is the one the pre-CAP-6 `< now` form got wrong,
// and it is why a ttl_ms:0 token (expires_at == created_at) is dead at every
// observable instant rather than valid for one instant and racing.
func TestExpiredExclusiveBoundary(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }
	const t0 = 1_000_000

	cases := []struct {
		name      string
		expiresAt *uint64
		now       uint64
		want      bool
	}{
		{"nil never expires (far future now)", nil, ^uint64(0), false},
		{"before expiry → valid", u(t0), t0 - 1, false},
		{"exactly at expiry → EXPIRED (exclusive bound)", u(t0), t0, true},
		{"after expiry → expired", u(t0), t0 + 1, true},
		{"ttl_ms:0 token (expires_at == created_at) is dead at created_at", u(t0), t0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Expired(tc.expiresAt, tc.now); got != tc.want {
				t.Fatalf("Expired(%v, %d) = %v, want %v", tc.expiresAt, tc.now, got, tc.want)
			}
		})
	}
}
