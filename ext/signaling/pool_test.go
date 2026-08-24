package signaling

import (
	"testing"
)

// A three-member single-tier pool with distinct endpoints — enough for the
// weight function to discriminate (a two-instance pool is the gate minimum;
// three makes the reordering test meaningful).
func tierZeroPool() []PoolMember {
	return []PoolMember{
		{Endpoint: "node-a:4050", Priority: 0},
		{Endpoint: "node-b:4051", Priority: 0},
		{Endpoint: "node-c:4052", Priority: 0},
	}
}

// §3.1.1: selection is stable under reordering of the advertisement. Two peers
// holding the same members in different order MUST pick the same server — a tie
// resolved by iteration order would be a convergence bug visible only under
// reordering.
func TestSelectionIsStableUnderReordering(t *testing.T) {
	d := deriver(t)
	key := d(TagKey("chess"))

	pool := tierZeroPool()
	want, ok := Select(key, pool)
	if !ok {
		t.Fatal("Select returned no member for a non-empty pool")
	}

	// Every rotation and reversal must agree.
	orders := [][]PoolMember{
		{pool[2], pool[0], pool[1]},
		{pool[1], pool[2], pool[0]},
		{pool[2], pool[1], pool[0]},
	}
	for i, ord := range orders {
		got, ok := Select(key, ord)
		if !ok || got.Endpoint != want.Endpoint {
			t.Errorf("reorder %d: picked %q, want %q", i, got.Endpoint, want.Endpoint)
		}
	}
}

// §3.1.1: priority partitions BEFORE the hash runs — the winner always comes
// from the lowest tier present, whatever the weights in higher tiers compute.
func TestPriorityPartitionsBeforeTheHashRuns(t *testing.T) {
	d := deriver(t)
	// Many tier-1 members (high weight-space coverage) and one tier-0 member.
	// If partition were applied AFTER the hash, some key would pick a tier-1
	// member; partitioning first, tier 0 always wins.
	pool := []PoolMember{
		{Endpoint: "lo-0:1", Priority: 0},
		{Endpoint: "hi-1:1", Priority: 1},
		{Endpoint: "hi-1:2", Priority: 1},
		{Endpoint: "hi-1:3", Priority: 1},
		{Endpoint: "hi-1:4", Priority: 1},
	}
	for _, label := range []string{"chess", "go", "poker", "bridge", "hearts", "spades"} {
		key := d(TagKey(label))
		got, ok := Select(key, pool)
		if !ok || got.Priority != 0 {
			t.Fatalf("%q: picked tier %d (%q), want tier 0", label, got.Priority, got.Endpoint)
		}
	}
}

// §3.1.1: the winning tier is the lowest one PRESENT — withdraw all tier-0
// members and selection falls through to tier 1 rather than selecting nothing.
func TestWinningTierIsTheLowestPresent(t *testing.T) {
	d := deriver(t)
	key := d(TagKey("chess"))
	pool := []PoolMember{
		{Endpoint: "t1-a:1", Priority: 1},
		{Endpoint: "t1-b:1", Priority: 1},
		{Endpoint: "t2-a:1", Priority: 2},
	}
	got, ok := Select(key, pool)
	if !ok || got.Priority != 1 {
		t.Fatalf("picked tier %d (%q), want the lowest present tier 1", got.Priority, got.Endpoint)
	}
}

// §3.1.1: empty pool → no rendezvous, surfaced as ok=false.
func TestSelectEmptyPool(t *testing.T) {
	d := deriver(t)
	if _, ok := Select(d(TagKey("chess")), nil); ok {
		t.Fatal("empty pool must return ok=false")
	}
}

// §4.2: a one-member pool validates nothing — argmax returns it whatever the
// weight computes. Documented as a test so the property is explicit.
func TestSingleMemberIsAlwaysSelected(t *testing.T) {
	d := deriver(t)
	only := PoolMember{Endpoint: "solo:1", Priority: 0}
	got, ok := Select(d(SecretKey("anything")), []PoolMember{only})
	if !ok || got.Endpoint != only.Endpoint {
		t.Fatalf("single-member pool picked %q, want %q", got.Endpoint, only.Endpoint)
	}
}

// §3.1.1: SelectTop(..., 1) agrees with Select, and SelectTop ranks within the
// lowest tier only, capped at n.
func TestSelectTopAgreesWithSelectAndCaps(t *testing.T) {
	d := deriver(t)
	key := d(TagKey("chess"))
	pool := tierZeroPool()

	top1 := SelectTop(key, pool, 1)
	sel, ok := Select(key, pool)
	if !ok || len(top1) != 1 || top1[0].Endpoint != sel.Endpoint {
		t.Fatalf("SelectTop(...,1)=%v disagrees with Select=%q", top1, sel.Endpoint)
	}

	top2 := SelectTop(key, pool, SkewFanout)
	if len(top2) != 2 {
		t.Fatalf("SelectTop(...,2) returned %d members, want 2", len(top2))
	}
	if top2[0].Endpoint != sel.Endpoint {
		t.Errorf("SelectTop's first choice %q != Select %q", top2[0].Endpoint, sel.Endpoint)
	}
	if top2[0].Endpoint == top2[1].Endpoint {
		t.Error("SelectTop returned a duplicate member")
	}

	// n larger than the tier yields the whole tier, not padding.
	all := SelectTop(key, pool, 99)
	if len(all) != len(pool) {
		t.Errorf("SelectTop(...,99) returned %d, want %d (whole tier)", len(all), len(pool))
	}

	// A single-member tier yields one choice however large n is.
	one := SelectTop(key, []PoolMember{{Endpoint: "solo:1", Priority: 0}}, SkewFanout)
	if len(one) != 1 {
		t.Errorf("single-member tier under n=2 returned %d, want 1", len(one))
	}
}

// §3.1.1: endpoint bytes are used exactly as published — two members differing
// only by a trailing slash are DIFFERENT members and must be discriminable
// (a peer that canonicalized them would collapse the pool).
func TestEndpointBytesAreNotCanonicalized(t *testing.T) {
	d := deriver(t)
	a := weight(d(TagKey("chess")), "node:4050")
	b := weight(d(TagKey("chess")), "node:4050/")
	if a == b {
		t.Fatal("endpoint weight ignored a trailing-slash difference — canonicalization leaked in")
	}
}
