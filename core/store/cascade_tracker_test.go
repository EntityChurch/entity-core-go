package store

import (
	"testing"
	"time"
)

func TestCascadeTrackerUpdate(t *testing.T) {
	ct := NewCascadeTracker(time.Hour)

	// First update for a chain returns the incoming depth.
	if got := ct.Update("chain-1", 5); got != 5 {
		t.Fatalf("Update(chain-1, 5) = %d, want 5", got)
	}

	// Higher depth replaces the tracked value.
	if got := ct.Update("chain-1", 10); got != 10 {
		t.Fatalf("Update(chain-1, 10) = %d, want 10", got)
	}

	// Lower depth is ignored; returns the previously tracked max.
	if got := ct.Update("chain-1", 3); got != 10 {
		t.Fatalf("Update(chain-1, 3) = %d, want 10", got)
	}

	// Independent chain is tracked separately.
	if got := ct.Update("chain-2", 7); got != 7 {
		t.Fatalf("Update(chain-2, 7) = %d, want 7", got)
	}

	// Original chain still has its max.
	if got := ct.Depth("chain-1"); got != 10 {
		t.Fatalf("Depth(chain-1) = %d, want 10", got)
	}
}

func TestCascadeTrackerDepth(t *testing.T) {
	ct := NewCascadeTracker(time.Hour)

	// Unknown chain returns 0.
	if got := ct.Depth("unknown"); got != 0 {
		t.Fatalf("Depth(unknown) = %d, want 0", got)
	}

	ct.Update("chain-1", 15)
	if got := ct.Depth("chain-1"); got != 15 {
		t.Fatalf("Depth(chain-1) = %d, want 15", got)
	}
}

func TestCascadeTrackerPrune(t *testing.T) {
	// Use a very short TTL so entries expire quickly.
	ct := NewCascadeTracker(50 * time.Millisecond)

	ct.Update("old-chain", 5)
	ct.Update("new-chain", 8)

	// Both should be present.
	if got := ct.Depth("old-chain"); got != 5 {
		t.Fatalf("before prune: Depth(old-chain) = %d, want 5", got)
	}

	// Wait for TTL to expire.
	time.Sleep(60 * time.Millisecond)

	// Touch new-chain to refresh its LastSeen.
	ct.Update("new-chain", 8)

	ct.Prune()

	// old-chain should be pruned.
	if got := ct.Depth("old-chain"); got != 0 {
		t.Fatalf("after prune: Depth(old-chain) = %d, want 0", got)
	}

	// new-chain was refreshed, should survive.
	if got := ct.Depth("new-chain"); got != 8 {
		t.Fatalf("after prune: Depth(new-chain) = %d, want 8", got)
	}
}

func TestCascadeTrackerUpdateRefreshesLastSeen(t *testing.T) {
	ct := NewCascadeTracker(100 * time.Millisecond)

	ct.Update("chain-1", 5)
	time.Sleep(60 * time.Millisecond)

	// Update with lower depth still refreshes LastSeen.
	ct.Update("chain-1", 2)
	time.Sleep(60 * time.Millisecond)

	// Entry was refreshed 60ms ago, TTL is 100ms, so it should survive.
	ct.Prune()
	if got := ct.Depth("chain-1"); got != 5 {
		t.Fatalf("after refresh+prune: Depth(chain-1) = %d, want 5", got)
	}
}
