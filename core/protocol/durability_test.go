package protocol

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// TestDurabilityReconcile walks the EXTENSION-DURABILITY §5 verdict table and
// asserts the contract invariants on every produced verdict:
//   - applied is never a promise (it equals a level physically determinable now)
//   - committed appears ONLY with status 202
//   - max_available appears ONLY with status 412
//   - 412 means the operation is NOT performed (PerformOp == false)
func TestDurabilityReconcile(t *testing.T) {
	storePolicy := DefaultDurabilityPolicy() // MaxSelfDeterminable = stored
	nonePolicy := DurabilityPolicy{MaxSelfDeterminable: types.DurabilityNone}
	zeroPolicy := DurabilityPolicy{} // unset == none, never overclaims
	replPolicy := DurabilityPolicy{
		MaxSelfDeterminable:   types.DurabilityStored,
		ReplicationConfigured: map[string]bool{types.DurabilityReplicated: true},
	}

	cases := []struct {
		name      string
		policy    DurabilityPolicy
		req       types.DurabilityRequestData
		status    uint
		applied   string
		committed string
		maxAvail  string
		reason    string
		perform   bool
		preserve  bool
	}{
		// Row 1: receiver can do >= X.
		{
			name: "stored_met_must_have", policy: storePolicy,
			req:    types.DurabilityRequestData{Level: types.DurabilityStored, MustHave: true},
			status: 200, applied: types.DurabilityStored, perform: true, preserve: true,
		},
		{
			name: "stored_met_best_effort", policy: storePolicy,
			req:    types.DurabilityRequestData{Level: types.DurabilityStored},
			status: 200, applied: types.DurabilityStored, perform: true, preserve: true,
		},
		{
			name: "none_trivially_met", policy: storePolicy,
			req:    types.DurabilityRequestData{Level: types.DurabilityNone},
			status: 200, applied: types.DurabilityNone, perform: true,
		},
		// Row 2: weaker available, not must-have.
		{
			name: "wants_stored_only_none_best_effort", policy: nonePolicy,
			req:    types.DurabilityRequestData{Level: types.DurabilityStored},
			status: 200, applied: types.DurabilityNone, reason: types.ReasonNoDurableStore, perform: true,
		},
		// Row 3: no durable store, not must-have (zero-value policy).
		{
			name: "no_store_best_effort_zero_policy", policy: zeroPolicy,
			req:    types.DurabilityRequestData{Level: types.DurabilityStored},
			status: 200, applied: types.DurabilityNone, reason: types.ReasonNoDurableStore, perform: true,
		},
		// Row 4: must-have, cannot meet (self-determinable stronger than offered).
		{
			name: "must_have_stored_no_store_refused", policy: nonePolicy,
			req:    types.DurabilityRequestData{Level: types.DurabilityStored, MustHave: true},
			status: 412, applied: types.DurabilityNone, maxAvail: types.DurabilityNone,
			reason: types.ReasonRequiredUnmet, perform: false,
		},
		// Row 4: must-have replication, not configured for the topology.
		{
			name: "must_have_replicated_not_configured_refused", policy: storePolicy,
			req:    types.DurabilityRequestData{Level: types.DurabilityReplicated, MustHave: true},
			status: 412, applied: types.DurabilityNone, maxAvail: types.DurabilityStored,
			reason: types.ReasonRequiredUnmet, perform: false,
		},
		// Replication not configured, best-effort: strongest self-determinable.
		{
			name: "replicated_best_effort_falls_back_to_stored", policy: storePolicy,
			req:    types.DurabilityRequestData{Level: types.DurabilityReplicated},
			status: 200, applied: types.DurabilityStored, perform: true, preserve: true,
		},
		// Row 5: configured for replication, completes asynchronously.
		{
			name: "replicated_configured_async_committed", policy: replPolicy,
			req:       types.DurabilityRequestData{Level: types.DurabilityReplicated, MustHave: true},
			status:    202,
			applied:   types.DurabilityStored,
			committed: types.DurabilityReplicated,
			perform:   true, preserve: true,
		},
		// Unknown level (not in vocabulary) — treated conservatively.
		{
			name: "unknown_level_must_have_refused", policy: storePolicy,
			req:    types.DurabilityRequestData{Level: "quantum", MustHave: true},
			status: 412, applied: types.DurabilityNone, maxAvail: types.DurabilityStored,
			reason: types.ReasonRequiredUnmet, perform: false,
		},
		// EXTENSION-DURABILITY §5 / §8: unknown level + not-must-have → applied:none,
		// reason:unknown_level. Don't promise what you don't understand.
		// (Pre-amendment, Go fell back to applied:bestSelf — best-effort.
		// The new MUST is stricter and more honest.)
		{
			name: "unknown_level_best_effort", policy: storePolicy,
			req:    types.DurabilityRequestData{Level: "quantum"},
			status: 200, applied: types.DurabilityNone, reason: types.ReasonUnknownLevel,
			perform: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.policy.Reconcile(tc.req)

			if v.Status != tc.status {
				t.Errorf("status: got %d, want %d", v.Status, tc.status)
			}
			if v.Result.Requested != tc.req.Level {
				t.Errorf("requested: got %q, want %q", v.Result.Requested, tc.req.Level)
			}
			if v.Result.Applied != tc.applied {
				t.Errorf("applied: got %q, want %q", v.Result.Applied, tc.applied)
			}
			if v.Result.Committed != tc.committed {
				t.Errorf("committed: got %q, want %q", v.Result.Committed, tc.committed)
			}
			if v.Result.MaxAvailable != tc.maxAvail {
				t.Errorf("max_available: got %q, want %q", v.Result.MaxAvailable, tc.maxAvail)
			}
			if v.Result.Reason != tc.reason {
				t.Errorf("reason: got %q, want %q", v.Result.Reason, tc.reason)
			}
			if v.PerformOp != tc.perform {
				t.Errorf("performOp: got %v, want %v", v.PerformOp, tc.perform)
			}
			if v.Preserve != tc.preserve {
				t.Errorf("preserve: got %v, want %v", v.Preserve, tc.preserve)
			}

			// Structural invariants — hold on EVERY verdict (EXTENSION-DURABILITY §5 / §8).
			if v.Result.Committed != "" && v.Status != 202 {
				t.Errorf("invariant: committed=%q present without status 202 (status=%d)",
					v.Result.Committed, v.Status)
			}
			if v.Result.MaxAvailable != "" && v.Status != 412 {
				t.Errorf("invariant: max_available=%q present without status 412 (status=%d)",
					v.Result.MaxAvailable, v.Status)
			}
			if v.Status == 412 && v.PerformOp {
				t.Error("invariant: 412 must mean operation NOT performed")
			}
			if v.Async != (v.Status == 202) {
				t.Errorf("invariant: Async=%v but status=%d", v.Async, v.Status)
			}
		})
	}
}
