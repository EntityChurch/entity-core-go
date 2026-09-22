package capability

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// Teeth for the 0.8.2.21 §5.2/§5.4 scope holes routed cohort-wide by both
// entity-core-rust and entity-core-py on 2026-09-11 after go's first H1 pass
// (77380ba) closed isExcluded but left four fail-open siblings. Each test
// carries a discriminating control so a "denies everything" or "allows
// everything" mutation cannot pass it.

// G-1: CheckPathPermission (§6.3) resource-exclude loop must carry the H1
// NEVER_MATCH arm — an unmatchable grant-exclude excludes EVERYTHING. §6.3 is
// the SOLE resource enforcement when the dispatch-level resource dimension is
// absent, so this is the site that carries the guarantee once the dispatch path
// is made vacuous.
func TestCheckPathPermission_UnmatchableResourceExcludeExcludesEverything(t *testing.T) {
	pid := testPeerID

	// "*/secret" canonicalizes to NEVER_MATCH: the raw matcher carves out
	// nothing, so an unfixed peer would ALLOW. H1 flips it to deny-all.
	unmatchable := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}, Exclude: []string{"*/secret"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
	}
	if CheckPathPermission("get", "system/tree/public", unmatchable, "system/tree", pid, pid) {
		t.Fatal("unmatchable resource exclude must exclude everything (fail closed)")
	}

	// Discriminating control: a WELL-FORMED exclude denies only its match and
	// still ALLOWS a sibling path — proving the row above is a real H1 catch and
	// not a deny-everything regression.
	wellFormed := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}, Exclude: []string{"system/tree/secret"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
	}
	if !CheckPathPermission("get", "system/tree/public", wellFormed, "system/tree", pid, pid) {
		t.Fatal("well-formed exclude must still ALLOW a non-excluded path")
	}
	if CheckPathPermission("get", "system/tree/secret", wellFormed, "system/tree", pid, pid) {
		t.Fatal("well-formed exclude must DENY the excluded path")
	}
}

// G-3: the handlers dimension (path-scope, §3.6) must honor exclude — read at
// BOTH the §6.3 handler-level check (CheckPathPermission) and the dispatch-level
// check (CheckPermission → scopeContains), which share one matcher.
func TestHandlerScope_HonorsExclude(t *testing.T) {
	pid := testPeerID
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}, Exclude: []string{"system/network"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
	}

	// §6.3 path-level: excluded handler is denied though resources/operations match.
	if CheckPathPermission("get", "system/network/x", cap, "system/network", pid, pid) {
		t.Fatal("§6.3: excluded handler must be denied at the path level")
	}
	// Control: a non-excluded handler under the same include is allowed.
	if !CheckPathPermission("get", "system/tree/x", cap, "system/tree", pid, pid) {
		t.Fatal("§6.3: non-excluded handler must be allowed")
	}

	// Dispatch-level (scopeContains): same rule, same matcher.
	exec := types.ExecuteData{Operation: "get"}
	if CheckPermission(exec, cap, "system/network", pid, pid) {
		t.Fatal("dispatch: excluded handler must be denied")
	}
	if !CheckPermission(exec, cap, "system/tree", pid, pid) {
		t.Fatal("dispatch: non-excluded handler must be allowed")
	}
}

// G-2: the capability-validity walk is a PATH-SCOPE walk — handlers AND
// resources. An unmatchable pattern in a handler scope is the same invalid bytes
// as one in a resource scope and MUST be caught at mint/delegate/verify.
func TestFirstUnmatchableScopePattern_WalksHandlers(t *testing.T) {
	// Unmatchable in a handler INCLUDE.
	g1 := []types.GrantEntry{{
		Handlers:  types.CapabilityScope{Include: []string{"./bad"}},
		Resources: types.CapabilityScope{Include: []string{"*"}},
	}}
	if got := FirstUnmatchableScopePattern(g1); got != "./bad" {
		t.Fatalf("handler include: want ./bad, got %q", got)
	}
	// Unmatchable in a handler EXCLUDE.
	g2 := []types.GrantEntry{{
		Handlers:  types.CapabilityScope{Include: []string{"system/tree"}, Exclude: []string{"*/bad"}},
		Resources: types.CapabilityScope{Include: []string{"*"}},
	}}
	if got := FirstUnmatchableScopePattern(g2); got != "*/bad" {
		t.Fatalf("handler exclude: want */bad, got %q", got)
	}
	// Control: all path-scope patterns well-formed → "".
	g3 := []types.GrantEntry{{
		Handlers:  types.CapabilityScope{Include: []string{"system/tree"}},
		Resources: types.CapabilityScope{Include: []string{"system/tree/*"}, Exclude: []string{"system/tree/secret"}},
	}}
	if got := FirstUnmatchableScopePattern(g3); got != "" {
		t.Fatalf("all-valid: want empty, got %q", got)
	}
}

// CheckPathPermission pattern-subject arm (2026-09-12, py routed via
// EXTENSION-SUBSCRIPTION §2.3): the §6.3 check is handed a PATTERN subject (a
// subscription target `data/*`), and the concrete exact-exclude test let it
// re-spell past a concrete grant exclude — the G-4 bypass one handler over. A
// pattern subject overlapping a grant exclude must be denied (no caller-exclude
// at this site to cover it); concrete subjects still take the exact/H1 arm.
func TestCheckPathPermission_PatternSubjectHonorsOverlappingExclude(t *testing.T) {
	pid := testPeerID
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"data/*"}, Exclude: []string{"data/secret"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
	}

	// Pattern subject overlapping the exclude → DENY (the subscription bypass row).
	if CheckPathPermission("get", "data/*", cap, "system/tree", pid, pid) {
		t.Fatal("pattern subject overlapping a grant exclude must be denied")
	}
	// Control 1: a non-overlapping pattern subject → ALLOW (not deny-all-patterns).
	if !CheckPathPermission("get", "data/public/*", cap, "system/tree", pid, pid) {
		t.Fatal("non-overlapping pattern subject must be allowed")
	}
	// Control 2: a concrete in-scope path → ALLOW (concrete arm unchanged).
	if !CheckPathPermission("get", "data/report", cap, "system/tree", pid, pid) {
		t.Fatal("concrete in-scope path must be allowed")
	}
	// Control 3: the concrete excluded path → DENY (concrete arm still excludes).
	if CheckPathPermission("get", "data/secret", cap, "system/tree", pid, pid) {
		t.Fatal("concrete excluded path must be denied")
	}
}

// G-4: the §5.2 pattern-target arm. A pattern target that OVERLAPS a concrete
// grant exclude must be denied unless the caller carries a covering exclude —
// the concrete-only exclude test (MatchesPattern of a pattern against a concrete
// exclude, a literal inequality) let the pattern re-spelling straight through.
func TestCheckResourceScope_PatternTargetHonorsGrantExclude(t *testing.T) {
	pid := testPeerID
	scope := types.CapabilityScope{
		Include: []string{"*"},
		Exclude: []string{"system/tree/secret"},
	}

	// Overlapping pattern target: DENY (spans the forbidden path, caller did not
	// exclude it). This is the G-4 bypass row.
	overlapping := &types.ResourceTarget{Targets: []string{"system/tree/*"}}
	if CheckResourceScope(overlapping, scope, pid, pid) {
		t.Fatal("pattern target overlapping a grant exclude must be denied")
	}

	// Control 1: a non-overlapping pattern target is ALLOWED — proving the row
	// above is not a deny-all-patterns regression.
	nonOverlap := &types.ResourceTarget{Targets: []string{"system/tree/public/*"}}
	if !CheckResourceScope(nonOverlap, scope, pid, pid) {
		t.Fatal("pattern target not overlapping the exclude must be allowed")
	}

	// Control 2: the overlapping pattern target WITH a covering caller exclude is
	// ALLOWED — the caller carved out the forbidden path itself.
	covered := &types.ResourceTarget{
		Targets: []string{"system/tree/*"},
		Exclude: []string{"system/tree/secret"},
	}
	if !CheckResourceScope(covered, scope, pid, pid) {
		t.Fatal("caller excluding the forbidden path must be allowed")
	}
}
