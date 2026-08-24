package revision

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestMergeConfigKey_TotalOrder is the pinned order as a pure comparator:
// exact(3) > subtree(2) > suffix(1) > match-all(0); longer literal within a rank;
// then lexicographic pattern, then name. Every pair below is strictly ordered and
// its inverse is asserted, so the relation is a total order with no ties.
func TestMergeConfigKey_TotalOrder(t *testing.T) {
	k := func(pattern, name string) mergeConfigKey { return mergeConfigKeyOf(pattern, name) }
	// each pair: more specific FIRST.
	pairs := [][2]mergeConfigKey{
		{k("a", "n"), k("docs/*", "n")},           // rank 3 > 2
		{k("docs/*", "n"), k("*.lock", "n")},      // rank 2 > 1 (arch's chosen rung)
		{k("*.lock", "n"), k("*", "n")},           // rank 1 > 0
		{k("docs/deep/*", "n"), k("docs/*", "n")}, // longer literal within rank 2
		{k("*.longer", "n"), k("*.x", "n")},       // longer literal within rank 1
		{k("docs/*", "a"), k("docs/*", "z")},      // same pattern → name tiebreak, a < z
	}
	for _, p := range pairs {
		hi, lo := p[0], p[1]
		if !hi.moreSpecific(lo) {
			t.Errorf("%+v should outrank %+v", hi, lo)
		}
		if lo.moreSpecific(hi) {
			t.Errorf("order not antisymmetric: %+v vs %+v", lo, hi)
		}
	}
}

// The v3.12 merge-config specificity total order + §4.4.18 V7, six vectors from
// arch ROUTING-2026-08-18-m §3 R15. `pattern_specificity` was called by §5.1 and
// defined nowhere; the three impls invented different ones (go/py scored literal
// chars, rust used pattern.len()), so a conflict resolved differently per peer on
// a merge whose result is byte-identical to a clean one — no audit signal either
// way. These pin the winner deterministically.

// writeMergeCfg sets a path-scope merge-config through the handler (the write-time
// V7 gate runs here) and asserts it bound.
func writeMergeCfg(t *testing.T, h *Handler, hctx *handler.HandlerContext, name, pattern string, strat mergeStrategy) {
	t.Helper()
	resp, err := h.Handle(context.Background(), makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
		Scope:  "path",
		Name:   name,
		Action: "set",
		Config: &types.RevisionMergeConfigData{Pattern: pattern, Strategy: string(strat)},
	}))
	if err != nil || resp.Status != 200 {
		t.Fatalf("write cfg name=%q pattern=%q: status=%d err=%v", name, pattern, resp.Status, err)
	}
}

func winningStrategy(hctx *handler.HandlerContext, relPath string) mergeStrategy {
	return findMergeStrategy(hctx, "", relPath, "", hash.Hash{}, hash.Hash{}).strategy
}

// MERGE-SPEC-ORDER-1 / ORDER-2 / TIE-1 — selection order, driven end-to-end and
// written in BOTH insertion orders so a store-enumeration dependence would show.
func TestFindMergeStrategy_SpecificityTotalOrder(t *testing.T) {
	// ORDER-1: subtree prefix (rank 2) outranks trailing suffix (rank 1).
	t.Run("order1_subtree_beats_suffix", func(t *testing.T) {
		for _, order := range [][2]string{{"pfx", "sfx"}, {"sfx", "pfx"}} {
			h, hctx := NewHandler(), newTestContext()
			write := map[string]func(){
				"pfx": func() { writeMergeCfg(t, h, hctx, "pfx", "docs/*", strategyTargetWins) },
				"sfx": func() { writeMergeCfg(t, h, hctx, "sfx", "*.lock", strategySourceWins) },
			}
			write[order[0]]()
			write[order[1]]()
			if got := winningStrategy(hctx, "docs/a.lock"); got != strategyTargetWins {
				t.Fatalf("order %v: docs/a.lock want target-wins (rank2>rank1) got %q", order, got)
			}
		}
	})

	// ORDER-2: exact (rank 3) outranks match-all (rank 0); one-char patterns, so a
	// length-based scorer would tie and fall to enumeration order.
	t.Run("order2_exact_beats_matchall", func(t *testing.T) {
		for _, order := range [][2]string{{"star", "exact"}, {"exact", "star"}} {
			h, hctx := NewHandler(), newTestContext()
			write := map[string]func(){
				"star":  func() { writeMergeCfg(t, h, hctx, "star", "*", strategySourceWins) },
				"exact": func() { writeMergeCfg(t, h, hctx, "exact", "a", strategyTargetWins) },
			}
			write[order[0]]()
			write[order[1]]()
			if got := winningStrategy(hctx, "a"); got != strategyTargetWins {
				t.Fatalf("order %v: path a want target-wins (rank3>rank0) got %q", order, got)
			}
		}
	})

	// TIE-1: same pattern, different {name} → lexicographic {name} breaks it, so
	// the result never depends on list() order.
	t.Run("tie1_name_breaks_same_pattern", func(t *testing.T) {
		for _, order := range [][2]string{{"z-cfg", "a-cfg"}, {"a-cfg", "z-cfg"}} {
			h, hctx := NewHandler(), newTestContext()
			write := map[string]func(){
				"z-cfg": func() { writeMergeCfg(t, h, hctx, "z-cfg", "docs/*", strategySourceWins) },
				"a-cfg": func() { writeMergeCfg(t, h, hctx, "a-cfg", "docs/*", strategyTargetWins) },
			}
			write[order[0]]()
			write[order[1]]()
			// a-cfg < z-cfg lexicographically → a-cfg (target-wins) wins, both orders.
			if got := winningStrategy(hctx, "docs/x"); got != strategyTargetWins {
				t.Fatalf("order %v: docs/x want target-wins (a-cfg < z-cfg) got %q", order, got)
			}
		}
	})
}

// MERGE-PATTERN-REJECT-1 — §4.4.18 V7: a path-scope pattern outside the four forms
// is 400 config/invalid-merge-pattern at write, no binding lands; control accepts.
func TestMergeConfig_V7RejectsNonFourForms(t *testing.T) {
	for _, pat := range []string{"**", "a/**/b", "a*b", "*a*"} {
		h, hctx := NewHandler(), newTestContext()
		resp, err := h.Handle(context.Background(), makeMergeConfigRequest(t, hctx, types.RevisionMergeConfigParamsData{
			Scope:  "path",
			Name:   "cfg",
			Action: "set",
			Config: &types.RevisionMergeConfigData{Pattern: pat, Strategy: string(strategySourceWins)},
		}))
		if err != nil {
			t.Fatalf("pattern %q: %v", pat, err)
		}
		if resp.Status != 400 {
			t.Fatalf("pattern %q: status want 400 got %d", pat, resp.Status)
		}
		var e types.ErrorData
		if decErr := ecf.Decode(resp.Result.Data, &e); decErr != nil {
			t.Fatalf("pattern %q: decode error: %v", pat, decErr)
		}
		if e.Code != "config/invalid-merge-pattern" {
			t.Fatalf("pattern %q: code want config/invalid-merge-pattern got %q", pat, e.Code)
		}
		if _, ok := hctx.LocationIndex.Get("system/revision/config/merge/path/cfg"); ok {
			t.Fatalf("pattern %q: rejected config MUST NOT bind", pat)
		}
	}

	// Control (required, §2.4a): a valid four-form pattern still binds.
	h, hctx := NewHandler(), newTestContext()
	writeMergeCfg(t, h, hctx, "ok", "docs/*", strategySourceWins)
}
