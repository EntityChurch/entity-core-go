// The flag-reachability audit, as a TEST rather than a discipline.
//
// WHY THIS IS A TEST. Three surfaces in one cycle turned out to be fully
// built, correct, flagged, documented — and unreachable by the conformance
// suite, because `entity-peer` exposed a flag that `peer-manager` did not
// forward. The suite could not turn them on, so the absent coverage was
// invisible and the scoreboard read *covered*:
//
//   - `--hash-type sha384`      every published conformance number this cohort
//     had ever produced was measured under exactly
//     one content_hash_format.
//   - `--issuer-policy-mode`    EXTENSION-REGISTRY §6a.9 live registration:
//     three ops, three policy modes, zero checks.
//   - `--discovery-announce`    the `:announce` operation had no check at all;
//     v7 only ever stopped a never-announced profile.
//
// Arch folded the class as GUIDE-CONFORMANCE §5.2b and adopted this audit
// explicitly as a **test rather than a discipline** — because a discipline is
// precisely what failed all three times. Nobody forgot to be careful; being
// careful is not a mechanism.
//
// WHAT IT ASSERTS. Every `entity-peer` flag is either forwarded by
// `peer-manager` or listed below with a reason. A new flag with neither is a
// FAILING TEST, not a note in a handoff someone reads later.
//
// The exclusion list is the other half of §5.2b: where a flag is deliberately
// unreachable, the gap must be STATED rather than ABSENT. Adding an entry is
// cheap and legitimate — leaving one undocumented is what this test exists to
// prevent.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// deliberatelyUnreachable maps an entity-peer flag name to the reason
// peer-manager does not forward it. Every entry is a declared coverage
// exclusion — keep the reason specific enough that a reader can tell whether
// it is still true.
var deliberatelyUnreachable = map[string]string{
	"storage-path": "peer-manager owns the on-disk layout: it derives the sqlite path from --name under its own state dir (~/.entity/peers/{name}/peer.db). Forwarding a caller-chosen path would let a managed peer write outside the directory peer-manager cleans up. --storage (the backend selector) IS forwarded, so the storage axis itself is reachable.",
}

func TestEveryEntityPeerFlagIsReachableThroughPeerManager(t *testing.T) {
	peerFlags, err := entityPeerFlagNames()
	if err != nil {
		t.Fatalf("parse entity-peer flags: %v", err)
	}
	if len(peerFlags) < 20 {
		t.Fatalf("only found %d entity-peer flags — the parser is probably broken, and a broken parser here reports full reachability", len(peerFlags))
	}

	forwarded, err := peerManagerForwardedFlags()
	if err != nil {
		t.Fatalf("scan peer-manager forwarded flags: %v", err)
	}

	var unreachable []string
	for _, f := range peerFlags {
		if forwarded[f] {
			continue
		}
		if _, declared := deliberatelyUnreachable[f]; declared {
			continue
		}
		unreachable = append(unreachable, f)
	}
	sort.Strings(unreachable)

	if len(unreachable) > 0 {
		t.Errorf(`%d entity-peer flag(s) cannot be reached through peer-manager: %v

Every conformance run starts its peers through peer-manager, so a surface
behind one of these flags CANNOT BE EXERCISED by the suite — and its absent
coverage will read as "covered" (GUIDE-CONFORMANCE §5.2b).

Fix it one of two ways:
  1. forward the flag in cmd/peer-manager/start.go (the usual answer), or
  2. add it to deliberatelyUnreachable in this file WITH A REASON, which
     records the gap instead of leaving it silent.`, len(unreachable), unreachable)
	}

	// A stale exclusion is its own hazard: it claims a gap that no longer
	// exists, and the next reader trusts it.
	for f := range deliberatelyUnreachable {
		if forwarded[f] {
			t.Errorf("flag %q is listed as deliberately unreachable but peer-manager DOES forward it — drop the stale exclusion", f)
			continue
		}
		if !contains(peerFlags, f) {
			t.Errorf("flag %q is listed as deliberately unreachable but entity-peer no longer defines it — drop the stale exclusion", f)
		}
	}
}

// entityPeerFlagNames parses cmd/entity-peer/main.go and returns the name of
// every flag it defines. Parsed via go/ast rather than grepped: a regex over
// source silently under-reports when a definition is reformatted, and
// under-reporting here manufactures a passing test.
func entityPeerFlagNames() ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "entity-peer", "main.go"), nil, 0)
	if err != nil {
		return nil, err
	}

	var names []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "flag" {
			return true
		}
		switch sel.Sel.Name {
		case "String", "Bool", "Int", "Int64", "Uint", "Uint64", "Float64", "Duration":
		default:
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if name, err := strconv.Unquote(lit.Value); err == nil && name != "" {
			names = append(names, name)
		}
		return true
	})
	sort.Strings(names)
	return names, nil
}

// peerManagerForwardedFlags returns every flag name peer-manager passes to a
// child peer, across all peer types.
//
// Two things make this fiddly, and getting either wrong produces a test that
// passes when it should not:
//
//   - Forwarding is not always a dashed literal. The keepalive trio is a table
//     of BARE names with the dash prepended at build time
//     (`{"keepalive-timeout-ms", ...}` + `args("-")`), so requiring a leading
//     dash misses three genuinely-forwarded flags.
//   - peer-manager's own flag DEFINITIONS carry long help strings that name
//     other flags ("pair with --http-poll-addr", "--publish-prefix ignored
//     for..."). Counting those as forwarding would mark a flag reachable
//     because prose mentions it. So `fs.String(...)` / `fs.Bool(...)` calls
//     are skipped entirely — that is exactly where help text lives.
func peerManagerForwardedFlags() (map[string]bool, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			return nil, err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			// Skip flag definitions: `fs.String("name", def, "help ...")`.
			// The help argument is prose about other flags.
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "fs" {
						return false
					}
				}
			}
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			out[strings.TrimLeft(s, "-")] = true
			return true
		})
	}
	return out, nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
