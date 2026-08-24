// The category-reachability audit, as a TEST rather than a discipline.
//
// WHY THIS IS A TEST. `peer_id_form` (4 checks) and `policy_dual_form` (5) were
// each registered in AllCategories, given a RunCategory case, and printed by
// -list-categories — and never called from ValidationSuite.Run. They ran only
// if someone typed `-category peer_id_form`, and nothing ever did. Nine checks
// therefore sat outside every conformance number this project has published,
// and one of them (`pim_legacy_decode_sha256_form_canonicalizes_on_storage`)
// was FAILING under `--hash-type sha384` the whole time.
//
// Nothing could have caught it by reading: the category existed, its runner was
// correct, the constant was in the list, and the CLI advertised it. The only
// observable was a category absent from a 52-row summary table — which is
// exactly the shape GUIDE-CONFORMANCE §5.2b names: the surface is built and the
// harness has no way to turn it on, so the absence of coverage is invisible and
// the scoreboard reads *covered*.
//
// This is the same class as cmd/peer-manager/reachability_test.go (a flag
// entity-peer exposes and peer-manager does not forward), one layer up: a
// category the suite defines and the suite does not call. Both are tests for
// the same reason — a discipline is precisely what failed.
//
// WHAT IT ASSERTS. Every category in AllCategories() has at least one runner
// reachable from ValidationSuite.Run (single-peer) or RunConvergence
// (multi-peer), or is listed below with a reason. A new category wired into
// AllCategories but not into a run is a FAILING TEST.
//
// The exclusion map is the other half of §5.2b: where a category is
// deliberately not in either run, the gap must be STATED rather than ABSENT.
package validate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// notInAnyRun maps a category constant identifier to the reason no run calls
// its runner. Every entry is a declared coverage exclusion — keep the reason
// specific enough that a reader can tell whether it is still true.
var notInAnyRun = map[string]string{
	"catConformance": "OFFLINE and corpus-driven: it connects to no peer and diffs per-impl `emit-canonical` artifacts against a shared corpus (GUIDE-CONFORMANCE §3.3). Its -peers flag carries <label>:<path> emission FILES, not addresses, so it is not a thing ValidationSuite.Run — which holds peer connections — can call. Reachable via `validate-peer -category conformance -corpus <f> -peers go:emit-go.cbor,...`.",

	"catConformancePassthrough": "Needs a corpus artifact that does not live in this repo — `-corpus <conformance-vectors-v1.cbor>`, produced by the wire-conformance build-fixture tool. ValidationSuite.Run has no corpus path and would have to skip every check, which is a skip masquerading as coverage. Reachable via `validate-peer -addr <p> -category conformance_passthrough -corpus <f>`. If the corpus ever ships in-repo or in validate-complete.sh, delete this entry and wire it into Run — this test will then hold it there.",
}

// runRoots are the entry points a category must be reachable from. Anything
// else (RunCategory's switch, -category) is caller-driven and does not count:
// reachability by explicit request is what made the peer_id_form gap invisible.
var runRoots = []string{"ValidationSuite.Run", "ValidationSuite.RunConvergence"}

func TestEveryCategoryIsReachableFromARun(t *testing.T) {
	pkg, err := parsePackageNonTest(".")
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	cats := allCategoryIdents(pkg)
	if len(cats) < 50 {
		t.Fatalf("found only %d category constants in AllCategories — the parser is probably broken, and a broken parser here reports full reachability", len(cats))
	}

	funcs := packageFuncs(pkg)
	for _, root := range runRoots {
		if _, ok := funcs[root]; !ok {
			t.Fatalf("run root %q not found — this test cannot measure anything", root)
		}
	}

	// A runner "owns" a category when it constructs the CheckRunner for it.
	// That is the one binding every category runner in this package shares.
	owners := map[string][]string{} // catIdent -> owning func keys
	for key, fn := range funcs {
		for _, cat := range checkRunnerCategories(fn) {
			owners[cat] = append(owners[cat], key)
		}
	}

	reachable := reachableFrom(funcs, runRoots)

	var unreachable, unknown, staleExclusion []string
	for _, cat := range cats {
		declared, isDeclared := notInAnyRun[cat]
		_ = declared

		ownerKeys, known := owners[cat]
		if !known {
			// No runner constructs a CheckRunner for this constant. Either the
			// category is emitted some other way or the constant is dead; both
			// deserve a look rather than a silent pass.
			if !isDeclared {
				unknown = append(unknown, cat)
			}
			continue
		}

		hit := false
		for _, k := range ownerKeys {
			if reachable[k] {
				hit = true
				break
			}
		}
		switch {
		case hit && isDeclared:
			staleExclusion = append(staleExclusion, cat)
		case !hit && !isDeclared:
			unreachable = append(unreachable, cat)
		}
	}

	sort.Strings(unreachable)
	sort.Strings(unknown)
	sort.Strings(staleExclusion)

	if len(unreachable) > 0 {
		t.Errorf("%d category/ies are in AllCategories() but no run calls their runner — they are reachable only by an explicit -category, so they score in no published number:\n  %s\n\nFix by adding a runCat(...) to ValidationSuite.Run (or a call in RunConvergence), or by adding an entry to notInAnyRun with the reason.",
			len(unreachable), strings.Join(unreachable, "\n  "))
	}
	if len(unknown) > 0 {
		t.Errorf("%d category constant(s) have no runner that calls NewCheckRunner(cat) — dead constant, or a runner that binds its category some other way (which this test cannot follow):\n  %s",
			len(unknown), strings.Join(unknown, "\n  "))
	}
	if len(staleExclusion) > 0 {
		t.Errorf("%d category/ies are listed in notInAnyRun but ARE reachable — remove the stale exclusion so the list keeps meaning something:\n  %s",
			len(staleExclusion), strings.Join(staleExclusion, "\n  "))
	}
}

// parsePackageNonTest parses the package's non-test files.
func parsePackageNonTest(dir string) ([]*ast.File, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, p := range pkgs {
		for _, f := range p.Files {
			files = append(files, f)
		}
	}
	return files, nil
}

// funcKey names a declaration uniquely: "Name" for a plain func,
// "RecvType.Name" for a method.
func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func packageFuncs(files []*ast.File) map[string]*ast.FuncDecl {
	out := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				out[funcKey(fd)] = fd
			}
		}
	}
	return out
}

// checkRunnerCategories returns the category constant identifiers this function
// passes to NewCheckRunner or skipCategory.
func checkRunnerCategories(fn *ast.FuncDecl) []string {
	var cats []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || (id.Name != "NewCheckRunner" && id.Name != "skipCategory") {
			return true
		}
		if arg, ok := call.Args[0].(*ast.Ident); ok && strings.HasPrefix(arg.Name, "cat") {
			cats = append(cats, arg.Name)
		}
		return true
	})
	return cats
}

// reachableFrom walks plain-identifier calls (package-level functions) from the
// given roots. Method calls are not resolved — without type information a
// selector cannot be attributed to a receiver type, and guessing would create
// edges that do not exist. The walk is therefore conservative in the direction
// that FAILS this test rather than passes it: a missed edge reports a category
// as unreachable, which is a visible error, not a silent pass.
func reachableFrom(funcs map[string]*ast.FuncDecl, roots []string) map[string]bool {
	seen := map[string]bool{}
	var visit func(key string)
	visit = func(key string) {
		if seen[key] {
			return
		}
		seen[key] = true
		fn, ok := funcs[key]
		if !ok {
			return
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				if _, isPkgFunc := funcs[id.Name]; isPkgFunc {
					visit(id.Name)
				}
			}
			return true
		})
	}
	for _, r := range roots {
		visit(r)
	}
	return seen
}

// allCategoryIdents extracts the constant identifiers listed in the
// AllCategories() slice literal.
func allCategoryIdents(files []*ast.File) []string {
	var out []string
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name != "AllCategories" || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				for _, el := range cl.Elts {
					if id, ok := el.(*ast.Ident); ok && strings.HasPrefix(id.Name, "cat") {
						out = append(out, id.Name)
					}
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out
}
