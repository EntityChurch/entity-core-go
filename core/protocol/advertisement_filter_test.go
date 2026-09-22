package protocol

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The §3 advertisement filter's matching rule, pinned (EXTENSION-SIGNALING
// §6.5 (b) Contents; arch 977667f): an assembled entry is retained iff the
// advertised served-scope COVERS it under the same four-axis scope_subset
// relation the chain uses for attenuation, and an uncovered entry is DROPPED,
// not narrowed.
//
// The ruling names two shapes as non-conformant by name — exact-op-match and
// namespace-prefix-match — because they split across the seam. Go shipped the
// second one: it stripped a trailing `/*` and asked the registry whether the
// base resolved. These tests pin the corrected behavior, and the
// prefix-vs-pattern case below is the exact example the ruling gives.

const filterTestPeer = crypto.PeerID("2KTestPeerIdForAdvertisementFilterAAAAAAAAAA")

func scope(patterns ...string) types.CapabilityScope {
	return types.CapabilityScope{Include: patterns}
}

func entry(handler, resource, operation string) types.GrantEntry {
	return types.GrantEntry{
		Handlers:   scope(handler),
		Resources:  scope(resource),
		Operations: scope(operation),
	}
}

func TestAdvertisementFilterMatchingRule(t *testing.T) {
	// What the peer says it serves: one concrete handler, wholly.
	advertised := []types.GrantEntry{entry("foo/bar", "*", "*")}

	cases := []struct {
		name   string
		grant  types.GrantEntry
		retain bool
		why    string
	}{
		{
			name:   "the ruling's own example — a prefix claim over a single served handler",
			grant:  entry("foo/*", "*", "*"),
			retain: false,
			why: "claiming foo/* while serving only foo/bar over-claims the handler space. " +
				"Go's old filter stripped the trailing /* and asked whether `foo` resolved, " +
				"which RETAINED this — the namespace-prefix-match the ruling names non-conformant",
		},
		{
			name:   "an exactly-served handler is covered",
			grant:  entry("foo/bar", "*", "*"),
			retain: true,
		},
		{
			name:   "a narrower resource under a served handler is covered",
			grant:  entry("foo/bar", "foo/bar/thing", "get"),
			retain: true,
			why:    "entry ⊆ advertised on every axis — this is the ordinary attenuation direction",
		},
		{
			name:   "an unserved handler drops",
			grant:  entry("other/handler", "*", "*"),
			retain: false,
			why:    "the 404-at-dispatch the discipline exists to prevent",
		},
		{
			name:   "a sibling under the same namespace drops",
			grant:  entry("foo/baz", "*", "*"),
			retain: false,
			why:    "sharing a prefix with a served handler is not being served",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterAdvertisedGrants([]types.GrantEntry{tc.grant}, advertised, filterTestPeer)
			retained := len(got) == 1
			if retained != tc.retain {
				verb := "dropped"
				if tc.retain {
					verb = "retained"
				}
				t.Fatalf("grant %v: want %s, got the opposite.\n%s",
					tc.grant.Handlers.Include, verb, tc.why)
			}
		})
	}
}

// TestAdvertisementFilterForeignNamespaceResource pins the coverage relation
// on the axis that bit us: a grant whose resource names ANOTHER peer's
// namespace (a §1.4 universal-address-space path this peer's store serves — a
// cached-remote entity, a follow mirror) must be RETAINED against an
// advertisement that serves the handler across all peers ("/*/*"), and is
// DROPPED against the own-namespace-only bare "*" spelling.
//
// The bare-"*" case is the bug: advertisedServedScope used to derive its
// resources axis as bare "*", which §5.5 / PR-8 canonicalization resolves to
// "/{local}/*". An operator who widens a grant by adding the foreign row then
// has the whole entry deleted — a widening that silently narrows. See
// core/peer.advertisedServedScope (fixed to "/*/*") and its sibling
// defaultHandlerSelfGrant.
func TestAdvertisementFilterForeignNamespaceResource(t *testing.T) {
	foreignGrant := entry("foo/bar", "/2KSomeOtherPeerNamespaceAAAAAAAAAAAAAAAAAAA/system/signature/*", "get")

	// The fixed spelling: the peer serves foo/bar across the universal address
	// space, so the foreign-namespace resource is backed and retained.
	crossPeer := []types.GrantEntry{entry("foo/bar", "/*/*", "*")}
	got := filterAdvertisedGrants([]types.GrantEntry{foreignGrant}, crossPeer, filterTestPeer)
	if len(got) != 1 {
		t.Fatal("a grant naming a foreign namespace was DROPPED against a /*/* " +
			"advertisement. The peer serves foo/bar across the universal address " +
			"space (§1.4), so the entry is backed — dropping it is the bug that " +
			"deletes a grant an operator widened.")
	}

	// The old own-namespace-only spelling drops it — pinned so a regression of
	// advertisedServedScope back to bare "*" is a visible relation change here.
	ownNamespace := []types.GrantEntry{entry("foo/bar", "*", "*")}
	got = filterAdvertisedGrants([]types.GrantEntry{foreignGrant}, ownNamespace, filterTestPeer)
	if len(got) != 0 {
		t.Fatal("bare \"*\" canonicalizes to /{local}/* (PR-8), which cannot cover " +
			"a foreign namespace — this direction documents why the fix was needed")
	}
}

// TestAdvertisementFilterKeepsTheUniversalCarveOut pins the boundary the ruling
// does not address, so that a later arch ruling against it is a visible test
// change rather than a silent behavior drift.
//
// No finite advertised scope can cover a `handlers: ["*"]` claim, so a literal
// "drop, not narrow" deletes every open-access grant and the peer hands its
// counterparts nothing. Go retains the universal claim iff it serves anything at
// all — the same carve-out the pre-ruling filter made explicitly. Filed and
// routed; see docs/validation/spec-issues/.
func TestAdvertisementFilterKeepsTheUniversalCarveOut(t *testing.T) {
	advertised := []types.GrantEntry{entry("foo/bar", "*", "*")}
	universal := entry("*", "*", "*")

	got := filterAdvertisedGrants([]types.GrantEntry{universal}, advertised, filterTestPeer)
	if len(got) != 1 {
		t.Fatal("the universal grant was dropped. That is the literal reading of " +
			"'uncovered entries drop, not narrow' — and it deletes open access entirely, " +
			"since no finite advertised scope covers `*`. If arch has ruled for the literal " +
			"reading, this test changes deliberately and every OpenAccessGrants deployment " +
			"changes with it")
	}

	// A peer that serves nothing advertises nothing, and the carve-out does not
	// manufacture authority out of that.
	got = filterAdvertisedGrants([]types.GrantEntry{universal}, nil, filterTestPeer)
	if len(got) != 0 {
		t.Fatal("a peer with an empty advertised scope retained a universal grant — " +
			"the carve-out is 'backed by whatever we serve', not 'always backed'")
	}
}
