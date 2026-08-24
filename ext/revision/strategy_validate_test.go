package revision

import (
	"strings"
	"testing"
)

// EXTENSION-REVISION §2.3's write-time strategy-rejection contract, for the
// `strategy` field. Until 2026-08-14 the merge-config write path validated
// only `deletion_resolution`, so the pinned `400 invalid_strategy` could never
// fire for the field it was written about.
//
// v3.9 matters here: the corpus declared this vocabulary three incompatible
// ways, and because the rejection is pinned at write time, WHICH VALUES A PEER
// REFUSES was cross-impl-observable and differed by which list the implementer
// read. These cases are the table.
func TestValidateMergeStrategyAcceptsTheBuiltInTable(t *testing.T) {
	for _, s := range []string{
		"", // empty → documented default (three-way)
		"three-way", "source-wins", "target-wins", "lww", "keep-both", "manual",
	} {
		if err := ValidateMergeStrategy(s, ""); err != nil {
			t.Errorf("strategy %q is in §2.3's built-in table and MUST be accepted at config-write time: %v", s, err)
		}
	}
}

func TestValidateMergeStrategyRejectsValuesOutsideTheTable(t *testing.T) {
	// `field-level` is the exact value v3.9 removed: it is the name of the
	// ALGORITHM §5.2 runs, not a strategy an operator may select. A peer that
	// accepts it read the dispatch list instead of the table.
	//
	// `deterministic` is a deletion_resolution value, not a strategy — the
	// confusion our own type doc carried.
	for _, s := range []string{"field-level", "deterministic", "custom-handler", "app/merge/text-handler", "THREE-WAY", "diff3"} {
		err := ValidateMergeStrategy(s, "")
		if err == nil {
			t.Errorf("strategy %q is not in §2.3's table and MUST be rejected at config-write time", s)
			continue
		}
		if !strings.HasPrefix(err.Error(), "invalid_strategy:") {
			t.Errorf("strategy %q: error must carry the invalid_strategy prefix so merge-config maps it to 400 invalid_strategy, got %q", s, err.Error())
		}
	}
}

// The sentinel encoding, corrected in v3.9. `strategy: "handler"` plus the
// companion `handler` path is the ONLY custom-dispatch encoding; a bare path
// string as the strategy value was the retracted reading, and it is retracted
// precisely because a value set admitting any path string cannot support a
// pinned write-time rejection.
func TestValidateMergeStrategyHandlerSentinelRequiresItsCompanionPath(t *testing.T) {
	if err := ValidateMergeStrategy("handler", "app/merge/text-handler"); err != nil {
		t.Fatalf("the sentinel with its companion path is the ruled custom-dispatch encoding: %v", err)
	}
	if err := ValidateMergeStrategy("handler", ""); err == nil {
		t.Fatal("accepted the sentinel with no handler path — that stores a config whose dispatch has nothing to dispatch to, the invalid persisted value write-time rejection exists to prevent")
	}
	if err := ValidateMergeStrategy("three-way", "app/merge/text-handler"); err == nil {
		t.Fatal("accepted a handler path alongside a built-in strategy — a config that reads as custom dispatch and is not")
	}
}
