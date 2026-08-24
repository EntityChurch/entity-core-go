package types

import (
	"math"
	"testing"
)

// The §2.2 retry pacing, as a vector table.
//
// DeriveRetryState is a pure function of (failing_since, backoff config, now),
// so the whole surface tests as data: no peers, no sockets, no timing flake,
// and nothing to be flaky about at 4am. These vectors are also the convergence
// artifact — the shape a sibling impl is expected to reproduce is a table of
// inputs and outputs, not a prose description of a state machine.
//
// Semantics pinned here (the rulings, in executable form):
//   - k is 1-INDEXED: DelayMs(1) is the wait before the FIRST retry.
//   - Attempt counts retries FIRED — 0 in the gap between the failure and the
//     first retry coming due.
//   - elapsed_to(0) = 0.
//   - The boundary is INCLUSIVE: at exactly elapsed_to(k), retry k has fired.
//   - No jitter in v1: same inputs, same outputs, always.

// fsBase is an arbitrary but realistic failing_since (ms since epoch). The
// derivation only ever uses now-failingSince, so the absolute value is
// immaterial — it is fixed here so a failure prints a stable number.
const fsBase uint64 = 1_700_000_000_000

func u64p(v uint64) *uint64 { return &v }

// defaultBackoff is the §2.2 default config: exponential, min 1s, max 60s.
// Delays:     1s, 2s, 4s, 8s, 16s, 32s, 60s (capped), 60s, …
// elapsed_to: 1s, 3s, 7s, 15s, 31s, 63s, 123s, 183s, …
var defaultBackoff = BackoffConfigData{}

func TestBackoffDelayMs(t *testing.T) {
	tests := []struct {
		name string
		cfg  BackoffConfigData
		k    uint64
		want uint64
	}{
		{"default k=0 is no wait", defaultBackoff, 0, 0},
		{"default k=1 is min", defaultBackoff, 1, 1000},
		{"default k=2 doubles", defaultBackoff, 2, 2000},
		{"default k=3 doubles", defaultBackoff, 3, 4000},
		{"default k=6 doubles", defaultBackoff, 6, 32000},
		{"default k=7 clamps at max", defaultBackoff, 7, 60000},
		{"default k=8 stays clamped", defaultBackoff, 8, 60000},
		{"default k=100 stays clamped", defaultBackoff, 100, 60000},

		{"constant ignores k", BackoffConfigData{Strategy: "constant", MinMs: u64p(5000)}, 1, 5000},
		{"constant ignores k (later)", BackoffConfigData{Strategy: "constant", MinMs: u64p(5000)}, 9, 5000},

		{"linear k=1", BackoffConfigData{Strategy: "linear", MinMs: u64p(1000)}, 1, 1000},
		{"linear k=3", BackoffConfigData{Strategy: "linear", MinMs: u64p(1000)}, 3, 3000},
		{"linear clamps at max", BackoffConfigData{Strategy: "linear", MinMs: u64p(1000)}, 100, 60000},

		// A config with max < min is not a licence to wait less than min: max
		// is raised to min, so the delay is min flat.
		{"inverted min/max yields min", BackoffConfigData{MinMs: u64p(5000), MaxMs: u64p(1000)}, 1, 5000},
		{"inverted min/max stays min", BackoffConfigData{MinMs: u64p(5000), MaxMs: u64p(1000)}, 5, 5000},

		// Saturating arithmetic: a huge k must not wrap into a small delay.
		{"linear cannot overflow into a short delay",
			BackoffConfigData{Strategy: "linear", MinMs: u64p(math.MaxUint64 / 2), MaxMs: u64p(math.MaxUint64)}, 4, math.MaxUint64},
		{"exponential cannot overflow into a short delay",
			BackoffConfigData{MinMs: u64p(math.MaxUint64 / 2), MaxMs: u64p(math.MaxUint64)}, 4, math.MaxUint64},

		{"degenerate zero min", BackoffConfigData{MinMs: u64p(0), MaxMs: u64p(0)}, 3, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.DelayMs(tt.k); got != tt.want {
				t.Errorf("DelayMs(%d) = %d, want %d", tt.k, got, tt.want)
			}
		})
	}
}

func TestDeriveRetryState(t *testing.T) {
	tests := []struct {
		name         string
		cfg          BackoffConfigData
		failingSince uint64
		now          uint64
		wantAttempt  uint64
		wantNext     uint64 // absolute ms; 0 means "expect zero value"
	}{
		// --- the default curve; elapsed_to = 1s, 3s, 7s, 15s, 31s, 63s, 123s
		{"at the failure, nothing has fired", defaultBackoff, fsBase, fsBase, 0, fsBase + 1000},
		{"1ms before the first retry", defaultBackoff, fsBase, fsBase + 999, 0, fsBase + 1000},
		{"exactly at the first retry (inclusive)", defaultBackoff, fsBase, fsBase + 1000, 1, fsBase + 3000},
		{"between first and second", defaultBackoff, fsBase, fsBase + 2999, 1, fsBase + 3000},
		{"exactly at the second", defaultBackoff, fsBase, fsBase + 3000, 2, fsBase + 7000},
		// The worked example from DeriveRetryState's doc comment.
		{"worked example: 5s elapsed", defaultBackoff, fsBase, fsBase + 5000, 2, fsBase + 7000},
		{"exactly at the third", defaultBackoff, fsBase, fsBase + 7000, 3, fsBase + 15000},
		{"exactly at the sixth", defaultBackoff, fsBase, fsBase + 63000, 6, fsBase + 123000},
		// Crossing into the plateau: delay(7) is the first clamped delay.
		{"exactly at the seventh, on the plateau", defaultBackoff, fsBase, fsBase + 123000, 7, fsBase + 183000},
		{"mid-plateau", defaultBackoff, fsBase, fsBase + 150000, 7, fsBase + 183000},

		// --- constant: elapsed_to = 5s, 10s, 15s, …
		{"constant, before the first", BackoffConfigData{Strategy: "constant", MinMs: u64p(5000)},
			fsBase, fsBase + 4999, 0, fsBase + 5000},
		{"constant, two fired", BackoffConfigData{Strategy: "constant", MinMs: u64p(5000)},
			fsBase, fsBase + 12000, 2, fsBase + 15000},

		// --- linear: delays 1s,2s,3s,4s,5s → elapsed_to = 1s,3s,6s,10s,15s
		{"linear, three fired", BackoffConfigData{Strategy: "linear", MinMs: u64p(1000)},
			fsBase, fsBase + 9999, 3, fsBase + 10000},
		{"linear, four fired (inclusive)", BackoffConfigData{Strategy: "linear", MinMs: u64p(1000)},
			fsBase, fsBase + 10000, 4, fsBase + 15000},

		// --- THE restart-hammering vector.
		//
		// A peer dead for 30 days. The point is the derived delay: the next
		// retry is one max-length (60s) interval out, NOT min_ms. An in-memory
		// attempt counter reset by the restart would redial in 1s here and keep
		// doing so forever — which is the bug this whole design deletes.
		//
		// elapsed_to(7) = 123000 (last pre-plateau), then 60s per retry:
		//   extra   = (2592000000 - 123000) / 60000 = 43197
		//   attempt = 7 + 43197                     = 43204
		//   cum     = 123000 + 43197*60000          = 2591943000
		//   next    = fsBase + 2591943000 + 60000   = fsBase + 2592003000
		{"a peer dead for 30 days resumes the curve, it does not hammer",
			defaultBackoff, fsBase, fsBase + 2592000000, 43204, fsBase + 2592003000},

		// --- the OPTIONAL §2.2 bounds, while still within them: pacing is
		// unaffected. Reaching them is TestDeriveRetryStateExhaustion's job.
		{"max_attempts not yet reached",
			BackoffConfigData{MaxAttempts: u64p(3)}, fsBase, fsBase + 3000, 2, fsBase + 7000},
		{"max_elapsed_ms not yet reached",
			BackoffConfigData{MaxElapsedMs: u64p(10000)}, fsBase, fsBase + 3000, 2, fsBase + 7000},

		// --- edges
		{"no episode: failing_since unset", defaultBackoff, 0, fsBase + 5000, 0, 0},
		{"clock skew: now before failing_since", defaultBackoff, fsBase, fsBase - 10000, 0, fsBase + 1000},
		{"degenerate zero delay is always due, never counted",
			BackoffConfigData{MinMs: u64p(0), MaxMs: u64p(0)}, fsBase, fsBase + 100000, 0, fsBase},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.DeriveRetryState(tt.failingSince, tt.now)
			if got.Attempt != tt.wantAttempt {
				t.Errorf("Attempt = %d, want %d", got.Attempt, tt.wantAttempt)
			}
			if got.NextAttemptAt != tt.wantNext {
				t.Errorf("NextAttemptAt = %d, want %d (offset %d, want offset %d)",
					got.NextAttemptAt, tt.wantNext,
					int64(got.NextAttemptAt)-int64(tt.failingSince),
					int64(tt.wantNext)-int64(tt.failingSince))
			}
		})
	}
}

// The OPTIONAL §2.2 give-up bounds. Retry-forever is the normative default, so
// the headline vector here is the one that proves the default never gives up:
// a peer dead for a year under the default config is still retrying.
func TestDeriveRetryStateExhaustion(t *testing.T) {
	const year = uint64(365 * 24 * 60 * 60 * 1000)
	tests := []struct {
		name          string
		cfg           BackoffConfigData
		now           uint64
		wantExhausted bool
		wantAttempt   uint64
	}{
		// Delays 1s,2s,4s,8s…; elapsed_to 1s,3s,7s,15s,31s…
		// 525604 = the 7 pre-plateau retries + (year - 123s)/60s at the cap.
		// The number is incidental; Exhausted staying false is the point.
		{"default config never exhausts, even after a year", defaultBackoff, fsBase + year, false, 525604},

		{"max_attempts=3, two fired", BackoffConfigData{MaxAttempts: u64p(3)}, fsBase + 3000, false, 2},
		{"max_attempts=3, exactly three fired", BackoffConfigData{MaxAttempts: u64p(3)}, fsBase + 7000, true, 3},
		// elapsed_to(5)=31s <= 60s < elapsed_to(6)=63s, so 5 have fired.
		{"max_attempts=3, well past", BackoffConfigData{MaxAttempts: u64p(3)}, fsBase + 60000, true, 5},
		{"max_attempts=0 gives up immediately", BackoffConfigData{MaxAttempts: u64p(0)}, fsBase, true, 0},

		{"max_elapsed_ms=10s, before", BackoffConfigData{MaxElapsedMs: u64p(10000)}, fsBase + 9999, false, 3},
		{"max_elapsed_ms=10s, exactly at (inclusive)", BackoffConfigData{MaxElapsedMs: u64p(10000)}, fsBase + 10000, true, 3},
		{"max_elapsed_ms=10s, past", BackoffConfigData{MaxElapsedMs: u64p(10000)}, fsBase + 11000, true, 3},

		// Whichever bound trips first wins.
		{"both set, attempts trips first",
			BackoffConfigData{MaxAttempts: u64p(2), MaxElapsedMs: u64p(600000)}, fsBase + 3000, true, 2},
		{"both set, elapsed trips first",
			BackoffConfigData{MaxAttempts: u64p(99), MaxElapsedMs: u64p(5000)}, fsBase + 5000, true, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.DeriveRetryState(fsBase, tt.now)
			if got.Exhausted != tt.wantExhausted {
				t.Errorf("Exhausted = %v, want %v (attempt %d)", got.Exhausted, tt.wantExhausted, got.Attempt)
			}
			if got.Attempt != tt.wantAttempt {
				t.Errorf("Attempt = %d, want %d", got.Attempt, tt.wantAttempt)
			}
			// An exhausted episode has no next attempt: a nonzero here would
			// have the caller schedule a retry it just decided not to make.
			if got.Exhausted && got.NextAttemptAt != 0 {
				t.Errorf("NextAttemptAt = %d on an exhausted episode, want 0", got.NextAttemptAt)
			}
			if !got.Exhausted && got.NextAttemptAt == 0 {
				t.Errorf("NextAttemptAt = 0 on a live episode, want a scheduled time")
			}
		})
	}
}

// The plateau shortcut is an optimisation, so it must agree exactly with the
// naive schedule it replaces. This walks elapsed_to by hand and compares.
func TestDeriveRetryStateMatchesNaiveSchedule(t *testing.T) {
	cfgs := []struct {
		name string
		cfg  BackoffConfigData
	}{
		{"default exponential", defaultBackoff},
		{"constant 5s", BackoffConfigData{Strategy: "constant", MinMs: u64p(5000)}},
		{"linear 1s", BackoffConfigData{Strategy: "linear", MinMs: u64p(1000)}},
		{"tight cap", BackoffConfigData{MinMs: u64p(1000), MaxMs: u64p(1500)}},
	}
	for _, c := range cfgs {
		t.Run(c.name, func(t *testing.T) {
			for elapsed := uint64(0); elapsed <= 400_000; elapsed += 250 {
				wantAttempt, wantNext := naiveSchedule(c.cfg, elapsed)
				got := c.cfg.DeriveRetryState(fsBase, fsBase+elapsed)
				if got.Attempt != wantAttempt || got.NextAttemptAt != fsBase+wantNext {
					t.Fatalf("elapsed %d: got (attempt %d, next +%d), naive says (attempt %d, next +%d)",
						elapsed, got.Attempt, got.NextAttemptAt-fsBase, wantAttempt, wantNext)
				}
			}
		})
	}
}

// naiveSchedule is the definition, walked one retry at a time: the largest k
// with elapsed_to(k) <= elapsed, and the offset of retry k+1.
func naiveSchedule(cfg BackoffConfigData, elapsed uint64) (attempt, nextOffset uint64) {
	var cum uint64
	for k := uint64(1); ; k++ {
		next := cum + cfg.DelayMs(k)
		if next > elapsed {
			return k - 1, next
		}
		cum = next
	}
}

// Invariants that must hold for any config, at any point in an episode.
func TestDeriveRetryStateInvariants(t *testing.T) {
	cfgs := []BackoffConfigData{
		defaultBackoff,
		{Strategy: "constant", MinMs: u64p(5000)},
		{Strategy: "linear", MinMs: u64p(1000)},
		{MinMs: u64p(5000), MaxMs: u64p(1000)}, // inverted
		{MinMs: u64p(1), MaxMs: u64p(3)},       // very tight
	}
	for _, cfg := range cfgs {
		var prevAttempt uint64
		for elapsed := uint64(0); elapsed <= 200_000; elapsed += 137 {
			now := fsBase + elapsed
			got := cfg.DeriveRetryState(fsBase, now)

			// The next retry is always still ahead: a derivation that returned
			// a due-in-the-past time would spin the retry loop.
			if got.NextAttemptAt <= now {
				t.Fatalf("cfg %+v elapsed %d: NextAttemptAt %d is not after now %d",
					cfg, elapsed, got.NextAttemptAt, now)
			}
			// Attempt only ever grows as time passes within an episode.
			if got.Attempt < prevAttempt {
				t.Fatalf("cfg %+v elapsed %d: Attempt went backwards, %d then %d",
					cfg, elapsed, prevAttempt, got.Attempt)
			}
			// The wait until the next retry never exceeds one max-length delay.
			if wait := got.NextAttemptAt - now; wait > cfg.EffectiveMaxMs() && wait > cfg.EffectiveMinMs() {
				t.Fatalf("cfg %+v elapsed %d: wait %d exceeds the max delay", cfg, elapsed, wait)
			}
			prevAttempt = got.Attempt
		}
	}
}
