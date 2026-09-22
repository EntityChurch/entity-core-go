package peer

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/handler"
)

// bareHandler is a handler with NO manifest, so advertisedServedScope reaches
// its derivation fallback (the path this test pins). A handler that published a
// MaxScope would bypass the fallback and is the operator's own spelling.
type bareHandler struct{}

func (bareHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	return &handler.Response{}, nil
}

func (bareHandler) Name() string { return "bareHandler" }

// TestAdvertisedServedScopeResourcesIsCrossPeer pins that the derived
// served-scope spells its resources axis as the cross-peer peer-wildcard
// "/*/*", NOT bare "*".
//
// This is the exact class defaultHandlerSelfGrant documents and fixed: §5.5 /
// PR-8 canonicalization (capability.Canonicalize) resolves a bare "*" resource
// pattern to "/{granter}/*" — OWN NAMESPACE ONLY. The advertised served-scope
// is the parent side of the §3 advertisement subset check, so a bare "*" here
// canonicalizes to the local namespace and DROPS every grant whose resource
// names another peer's namespace (a §1.4 cached-remote / follow-mirror address
// this peer's store legitimately serves). An operator who WIDENS a grant by
// adding a foreign-namespace resource row would see the whole entry deleted.
//
// The peer serves its handler across the universal address space, so the
// advertisement is "/*/*": all peers, all paths.
func TestAdvertisedServedScopeResourcesIsCrossPeer(t *testing.T) {
	reg := handler.NewRegistry()
	reg.Register("foo/bar", bareHandler{})

	scope := advertisedServedScope(reg)
	if len(scope) != 1 {
		t.Fatalf("expected one advertised entry, got %d", len(scope))
	}
	res := scope[0].Resources.Include
	if len(res) != 1 || res[0] != "/*/*" {
		t.Fatalf("advertised resources = %v, want [/*/*].\n"+
			"A bare \"*\" canonicalizes to /{local}/* (own namespace only, PR-8) "+
			"and drops every grant naming a foreign namespace — the same trap "+
			"defaultHandlerSelfGrant fixed one function over.", res)
	}
	// Operations is not a path namespace, so bare "*" is correct there and must
	// NOT be rewritten (MatchesPattern short-circuits "*" and no canonicalization
	// applies).
	if ops := scope[0].Operations.Include; len(ops) != 1 || ops[0] != "*" {
		t.Fatalf("advertised operations = %v, want [*] (ops is not a path axis)", ops)
	}
}
