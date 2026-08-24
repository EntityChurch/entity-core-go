package compute

// EXTENSION-COMPUTE §5.2: `request_budget = params.budget or infinity`, and
// operations is min(request_budget, bounds_budget, compute_ops_limit).
//
// The request budget went unread until 2026-07-22 — initBudget took only the
// handler context, so a caller's `params: {budget: N}` (the shape §3.2's own
// EXECUTE example shows) was silently ignored and every eval ran at the peer
// default. That is invisible in ordinary use, because ignoring a voluntary
// self-restriction never denies anything; it surfaces the moment something
// depends on being cut off early — a preemption probe, or a conformance vector
// that pins where evaluation stops.

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func paramsWith(t *testing.T, m map[string]interface{}) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	ent, err := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return ent
}

func TestRequestBudgetLowersTheCeiling(t *testing.T) {
	hctx := &handler.HandlerContext{}
	b := initBudget(hctx, paramsWith(t, map[string]interface{}{"budget": uint64(24)}))
	if b.Operations != 24 {
		t.Errorf("params.budget=24 ignored: got %d operations (§5.2 min rule)", b.Operations)
	}
	if b.Depth != DefaultMaxDepth {
		t.Errorf("depth should come from constraints, not params: got %d", b.Depth)
	}
}

// The request budget enters a min, so it can only narrow. A caller asking for
// more than the peer allows must not get it — otherwise an optional knob would
// widen what a capability authorizes.
func TestRequestBudgetCannotRaiseTheCeiling(t *testing.T) {
	hctx := &handler.HandlerContext{}
	b := initBudget(hctx, paramsWith(t, map[string]interface{}{"budget": uint64(DefaultMaxOps * 10)}))
	if b.Operations != DefaultMaxOps {
		t.Errorf("params.budget raised the ceiling to %d, above the peer default %d",
			b.Operations, DefaultMaxOps)
	}
}

func TestRequestBudgetLosesToATighterBound(t *testing.T) {
	tight := uint64(50)
	hctx := &handler.HandlerContext{Bounds: &types.BoundsData{Budget: &tight}}
	b := initBudget(hctx, paramsWith(t, map[string]interface{}{"budget": uint64(9000)}))
	if b.Operations != 50 {
		t.Errorf("expected the wire bound (50) to win the min, got %d", b.Operations)
	}
}

// Every malformed shape means "no limit requested", never a rejected eval:
// params is primitive/any with no schema, and the §5.2 default is infinity.
// Failing the request would turn an optional knob into a required one.
func TestMalformedRequestBudgetIsIgnored(t *testing.T) {
	cases := []struct {
		name   string
		params entity.Entity
	}{
		{"empty entity", entity.Entity{}},
		{"empty map", paramsWith(t, map[string]interface{}{})},
		{"no budget key", paramsWith(t, map[string]interface{}{"other": uint64(5)})},
		{"non-numeric budget", paramsWith(t, map[string]interface{}{"budget": "lots"})},
		{"zero budget", paramsWith(t, map[string]interface{}{"budget": uint64(0)})},
		{"negative budget", paramsWith(t, map[string]interface{}{"budget": int64(-1)})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := initBudget(&handler.HandlerContext{}, tc.params)
			if b.Operations != DefaultMaxOps {
				t.Errorf("expected the peer default %d, got %d", DefaultMaxOps, b.Operations)
			}
		})
	}
}
