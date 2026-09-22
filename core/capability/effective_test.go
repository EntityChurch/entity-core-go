package capability

import (
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// TestEffectiveTargets pins the §5.2 effective-target function (0.8.2.20): the
// caller's own excludes are removed, the survivor is returned RAW (so handlers
// keep their path semantics), and a no-exclude request is the identity.
func TestEffectiveTargets(t *testing.T) {
	pid := testPeerID
	p := "/" + string(pid) + "/x"
	q := "/" + string(pid) + "/y"

	cases := []struct {
		name string
		res  *types.ResourceTarget
		want []string
	}{
		{"nil", nil, nil},
		{"empty", &types.ResourceTarget{}, []string{}},
		{"no-exclude-identity", &types.ResourceTarget{Targets: []string{p, q}}, []string{p, q}},
		{"self-excluded-sole", &types.ResourceTarget{Targets: []string{p}, Exclude: []string{p}}, []string{}},
		{"mixed-self-exclude", &types.ResourceTarget{Targets: []string{p, q}, Exclude: []string{p}}, []string{q}},
		{"exclude-by-pattern", &types.ResourceTarget{Targets: []string{p, q}, Exclude: []string{"/" + string(pid) + "/*"}}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveTargets(tc.res, pid)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("EffectiveTargets = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCheckResourceScopeSkipsCallerExcluded documents the F68 authorizer half:
// a caller that excludes its own sole target has an empty effective set, so
// CheckResourceScope has nothing to check and returns true EVEN when the target
// is outside the grant. This is correct (§5.2 — demanding coverage for a path
// nobody requested would refuse legitimate traffic) and is exactly why the
// handler MUST derive its subject from effective[0]: with the authorizer
// vacuous, the handler-level empty→path_required is the enforcement (F68).
func TestCheckResourceScopeSkipsCallerExcluded(t *testing.T) {
	pid := testPeerID
	p := "/" + string(pid) + "/secret" // outside the grant below
	grant := types.CapabilityScope{Include: []string{"/" + string(pid) + "/allowed/*"}}

	// Antecedent control: named, NOT excluded → out-of-grant → DENY.
	if CheckResourceScope(&types.ResourceTarget{Targets: []string{p}}, grant, pid, pid) {
		t.Fatal("out-of-grant target with no exclude must be denied (antecedent control)")
	}
	// Self-excluded → empty effective → nothing to check → ALLOW at the authorizer.
	if !CheckResourceScope(&types.ResourceTarget{Targets: []string{p}, Exclude: []string{p}}, grant, pid, pid) {
		t.Fatal("self-excluded target must yield an empty effective set (authorizer allows; handler enforces path_required)")
	}
}

// TestCheckResourceScopeFailsClosedOnMalformedTarget is the G6 teeth (§5.2,
// 0.8.2.20): a malformed concrete target reaching the resource check MUST return
// false rather than proceeding on a discarded verdict. The bite is a target the
// grant's own subtree pattern WOULD cover — a control-character path under a
// normal "/{peer}/*" grant: MatchesPattern admits it as a subtree member, so the
// fail-closed validate (validConcreteTarget → ValidateAbsolutePath) is the ONLY
// thing that refuses it. Mutation: make validConcreteTarget return true and this
// goes green (the bug the discarded verdict left open).
func TestCheckResourceScopeFailsClosedOnMalformedTarget(t *testing.T) {
	pid := testPeerID
	// A normal subtree grant over the local namespace.
	grant := types.CapabilityScope{Include: []string{"/" + string(pid) + "/*"}}

	// Positive control: a well-formed absolute target IS covered — proving the
	// refusals below are attributable to malformedness, not to the grant.
	good := "/" + string(pid) + "/real/path"
	if !CheckResourceScope(&types.ResourceTarget{Targets: []string{good}}, grant, pid, pid) {
		t.Fatal("well-formed absolute target must be covered by the subtree grant (positive control)")
	}

	// Control-character path: MatchesPattern covers it under "/{peer}/*", so only
	// the fail-closed validate refuses it.
	badChars := "/" + string(pid) + "/evil\x00path"
	if CheckResourceScope(&types.ResourceTarget{Targets: []string{badChars}}, grant, pid, pid) {
		t.Fatal("control-character concrete target must fail closed (G6)")
	}

	// Reserved-prefix forms never canonicalize to an absolute path; they are
	// malformed and must fail closed regardless of grant breadth.
	for _, bad := range []string{"./escape", "../escape"} {
		if CheckResourceScope(&types.ResourceTarget{Targets: []string{bad}}, grant, pid, pid) {
			t.Fatalf("malformed concrete target %q must fail closed", bad)
		}
	}
}

// TestCheckResourceScopePeerWildcardCannotReachABogusPeerTarget is the second
// G6 teeth (§5.4 validate_absolute_path clause 3, 0.8.2.20) — the arm a
// chars-only validConcreteTarget dropped, routed cohort-wide by rust and py on
// 2026-09-11. A concrete target rooted at a NON-peer first segment ("/short/x")
// is absolute and star-free, so it is not NEVER_MATCH and the control-char arm
// above never sees it. Against a peer-wildcard grant ("/*/*") the matcher
// strips the first segment whatever it is and the remainder matches — so only
// the peer-id-first-segment clause of validate_absolute_path refuses it. The
// bite is authorization, not hygiene: a "/*/*" grant covering a target rooted
// at a peer that cannot exist.
func TestCheckResourceScopePeerWildcardCannotReachABogusPeerTarget(t *testing.T) {
	pid := testPeerID
	// A peer-wildcard grant — crosses peers by construction (§5.4 "/*/rest").
	grant := types.CapabilityScope{Include: []string{"/*/*"}}

	// Positive control (one dimension apart): first segment IS a peer id → the
	// grant legitimately covers it. Proves the refusal below is attributable to
	// the bogus first segment, not to the grant denying everything.
	good := "/" + string(pid) + "/x"
	if !CheckResourceScope(&types.ResourceTarget{Targets: []string{good}}, grant, pid, pid) {
		t.Fatal(`"/*/*" must cover a target rooted at a real peer id (positive control)`)
	}

	// The bite: a non-peer first segment. ValidateAbsolutePath's peer-id clause
	// is the ONLY refusal — mutation (drop the clause / revert to ValidatePathChars)
	// turns this green.
	bogus := "/short/x"
	if CheckResourceScope(&types.ResourceTarget{Targets: []string{bogus}}, grant, pid, pid) {
		t.Fatal(`a target rooted at a non-peer segment must fail closed under "/*/*" (G6 clause 3)`)
	}
}

// TestCheckResourceScopeUnmatchableExcludeExcludesEverything is the H1
// fail-OPEN teeth (§5.2/§5.4, 0.8.2.21 — the CORE-EXCLUDE-UNMATCHABLE-1 shape).
// A grant exclude "*/secret" is unmatchable (canonicalizes to NEVER_MATCH); the
// 0.8.2.20 reading carved out NOTHING with it, silently widening the grant. It
// MUST exclude everything (deny). The discriminating control is a well-formed
// "/*/secret" beside it — it denies /{peer}/secret but NOT /{peer}/public, so a
// green row cannot be a grant that simply denies everything. Mutation: drop the
// IsUnmatchablePattern arm in isExcluded and the first assertion goes green
// (the fail-open the old rule left).
func TestCheckResourceScopeUnmatchableExcludeExcludesEverything(t *testing.T) {
	pid := testPeerID
	secret := "/" + string(pid) + "/secret"
	other := "/" + string(pid) + "/public"

	// Unmatchable exclude "*/secret" MUST exclude everything → deny.
	badGrant := types.CapabilityScope{Include: []string{"/*/*"}, Exclude: []string{"*/secret"}}
	if CheckResourceScope(&types.ResourceTarget{Targets: []string{secret}}, badGrant, pid, pid) {
		t.Fatal(`unmatchable exclude "*/secret" must exclude everything, not carve out nothing (H1 fail-open)`)
	}

	// Control: a WELL-FORMED "/*/secret" excludes /{peer}/secret ...
	goodGrant := types.CapabilityScope{Include: []string{"/*/*"}, Exclude: []string{"/*/secret"}}
	if CheckResourceScope(&types.ResourceTarget{Targets: []string{secret}}, goodGrant, pid, pid) {
		t.Fatal(`well-formed exclude "/*/secret" must exclude /{peer}/secret`)
	}
	// ... but NOT /{peer}/public — proving the deny above is the exclude working,
	// not a grant that denies everything.
	if !CheckResourceScope(&types.ResourceTarget{Targets: []string{other}}, goodGrant, pid, pid) {
		t.Fatal(`well-formed exclude must NOT deny an unexcluded path (discriminating control)`)
	}
}

// TestFirstUnmatchableScopePatternDetectsAllForms is the H1 authoring-validity
// teeth (§5.2/§5.4/§6.2, 0.8.2.21): a capability carrying ANY unmatchable scope
// pattern — in an include OR an exclude — is invalid and refused at
// mint/delegate/verify. Covers all three §5.4 NEVER_MATCH forms.
func TestFirstUnmatchableScopePatternDetectsAllForms(t *testing.T) {
	for _, bad := range []string{"*/secret", "./escape", "../escape"} {
		gEx := []types.GrantEntry{{Resources: types.CapabilityScope{Include: []string{"/*/*"}, Exclude: []string{bad}}}}
		if got := FirstUnmatchableScopePattern(gEx); got != bad {
			t.Fatalf("exclude %q must be flagged unmatchable, got %q", bad, got)
		}
		gIn := []types.GrantEntry{{Resources: types.CapabilityScope{Include: []string{bad}}}}
		if got := FirstUnmatchableScopePattern(gIn); got != bad {
			t.Fatalf("include %q must be flagged unmatchable, got %q", bad, got)
		}
	}
	// Well-formed grant is clean (bare "*" and "/*/rest" are matchable).
	ok := []types.GrantEntry{{Resources: types.CapabilityScope{Include: []string{"/*/*", "*"}, Exclude: []string{"/*/secret"}}}}
	if got := FirstUnmatchableScopePattern(ok); got != "" {
		t.Fatalf("well-formed grant must be clean, got %q", got)
	}
}

// TestIsCoveredByBarePeerWildcardMatchesNothing is the R11 grant-side arm: a
// "*/"-leading pattern (the ambiguous bare peer wildcard) is passed through
// canonicalization unchanged and matches nothing — it does not error, and it
// does not accidentally cover a peer-qualified path (only "/*/rest" crosses
// peers, §5.4).
func TestIsCoveredByBarePeerWildcardMatchesNothing(t *testing.T) {
	pid := testPeerID
	target := "/" + string(pid) + "/system"
	if IsCoveredBy(target, []string{"*/system"}, pid, pid) {
		t.Fatal(`bare-peer-wildcard grant "*/system" must match nothing (R11)`)
	}
	// Contrast: the well-formed peer wildcard DOES cross peers.
	if !IsCoveredBy(target, []string{"/*/system"}, pid, pid) {
		t.Fatal(`"/*/system" must cover /{peer}/system (peer-wildcard, §5.4)`)
	}
}
