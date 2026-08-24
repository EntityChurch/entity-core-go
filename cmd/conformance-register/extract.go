package main

// Extraction — the oracle's declared checks, read out of its source.
//
// Every check in `cmd/internal/validate` is registered by a
// `r.Declare(name, specRef)` / `r.DeclareSelf(name, specRef)` call on a
// `CheckRunner` built by `NewCheckRunner(catX)`. That is already the register's
// raw material: category, check name, the normative citation the check claims,
// and (via DeclareSelf) whether it contacts the peer at all. This walks the AST
// and reads it out.
//
// Static, not runtime, on purpose. A runtime extract would need a live peer,
// would only see the categories that ran in that configuration, and would make
// the register a function of how the suite was invoked. The declarations are
// the contract; they are visible without running anything, in a tree that does
// not have to compile.
//
// THE RULE THIS FILE IS BUILT AROUND: a declaration that cannot be read is
// REPORTED, never dropped. An extractor that silently skips the checks whose
// spec-ref is a variable would report a smaller, cleaner register than the one
// that exists — which is precisely the defect class (a green report that
// measured less than it claimed) this whole register exists to surface. Every
// declare site lands in the output as some row; `Reconcile` proves it.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Row is one declared conformance check.
type Row struct {
	Category    string `json:"category"`
	Check       string `json:"check"`
	SpecRef     string `json:"spec_ref"`
	SelfCheck   bool   `json:"self_check"`
	CoreProfile bool   `json:"core_profile"`
	Source      string `json:"source"`

	// Citations is the parsed, resolved form of SpecRef. Filled by the
	// resolver, not the extractor.
	Citations []Citation `json:"citations,omitempty"`
	Verdict   Verdict    `json:"verdict"`

	// Note carries why a row could not be read cleanly — a non-literal
	// spec-ref, a declare in a helper with no runner in scope. Empty on a
	// normal row.
	Note string `json:"note,omitempty"`
}

// Key is the register's stable identifier for a row: `category.check`, the
// same selector `validate-peer -category` and every published conformance
// citation already use.
func (r Row) Key() string {
	if r.Category == "" {
		return "?." + r.Check
	}
	return r.Category + "." + r.Check
}

// Extraction is the result of a source walk, including the counts that prove
// nothing was dropped.
type Extraction struct {
	Rows []Row

	// DeclareSites is every `.Declare(`/`.DeclareSelf(` call the walk saw,
	// including the ones it could not read into a clean Row. len(Rows) must
	// equal it or the extractor lied.
	DeclareSites int

	// Categories seen in NewCheckRunner calls, and the ones AllCategories()
	// advertises — a category the CLI offers but that declares nothing is a
	// finding, not a formatting problem.
	CategoriesSeen map[string]bool
}

// Reconcile reports whether every declare site produced a row.
func (e Extraction) Reconcile() error {
	if len(e.Rows) != e.DeclareSites {
		return fmt.Errorf("extractor dropped declarations: %d declare sites, %d rows — every site must produce a row, even an unreadable one",
			e.DeclareSites, len(e.Rows))
	}
	return nil
}

// Extract walks the validate package and reads out every declared check.
func Extract(pkgDir string) (*Extraction, error) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pkgDir, err)
	}

	var files []*ast.File
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(pkgDir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no non-test .go files in %s", pkgDir)
	}

	consts := collectStringConsts(files)
	core := collectCoreProfile(files, consts)

	out := &Extraction{CategoriesSeen: map[string]bool{}}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			cat, catNote := categoryOf(fn, consts)
			if cat != "" {
				out.CategoriesSeen[cat] = true
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				self := sel.Sel.Name == "DeclareSelf"
				if sel.Sel.Name != "Declare" && !self {
					return true
				}
				out.DeclareSites++

				row := Row{
					Category:  cat,
					SelfCheck: self,
					Source:    posOf(fset, call.Pos(), pkgDir),
					Note:      catNote,
				}
				name, nameOK := literalString(call.Args, 0, consts)
				ref, refOK := literalString(call.Args, 1, consts)
				row.Check, row.SpecRef = name, ref

				switch {
				case !nameOK && !refOK:
					row.Check = "<computed>"
					row.Note = joinNote(row.Note, "check name and spec ref are both computed at runtime")
				case !nameOK:
					row.Check = "<computed>"
					row.Note = joinNote(row.Note, "check name is computed at runtime")
				case !refOK:
					row.Note = joinNote(row.Note, "spec ref is computed at runtime")
				}
				if !nameOK || !refOK {
					row.Verdict = VerdictDynamic
				}
				row.CoreProfile = core[cat]
				out.Rows = append(out.Rows, row)
				return true
			})
		}
	}

	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Key() != out.Rows[j].Key() {
			return out.Rows[i].Key() < out.Rows[j].Key()
		}
		return out.Rows[i].Source < out.Rows[j].Source
	})
	return out, nil
}

// categoryOf finds the category a function's checks belong to, by locating the
// `NewCheckRunner(catX)` call that builds its runner.
//
// A function with no such call still gets its declares extracted — it is a
// helper that takes a runner from its caller — but with an empty category and
// a note saying so. Guessing the category from the filename would be a
// plausible-looking wrong answer, which is worse than an explicit gap.
func categoryOf(fn *ast.FuncDecl, consts map[string]string) (cat, note string) {
	var found []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "NewCheckRunner" || len(call.Args) != 1 {
			return true
		}
		if v, ok := literalString(call.Args, 0, consts); ok {
			found = append(found, v)
		}
		return true
	})
	switch len(found) {
	case 0:
		return "", "declared in a helper — no NewCheckRunner in scope, category not attributable from source"
	case 1:
		return found[0], ""
	default:
		// More than one runner in one function: the declares cannot be
		// attributed without executing it. Say so rather than picking.
		return "", "function builds " + strconv.Itoa(len(found)) + " runners — category ambiguous"
	}
}

// literalString resolves argument i to a string, following package-level
// string constants one hop (`catMultiSig` -> "multisig"). It deliberately does
// not evaluate concatenation or fmt calls: a spec ref assembled at runtime is a
// finding for the register, not something to reconstruct approximately.
func literalString(args []ast.Expr, i int, consts map[string]string) (string, bool) {
	if i >= len(args) {
		return "", false
	}
	switch e := args[i].(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return v, true
	case *ast.Ident:
		if v, ok := consts[e.Name]; ok {
			return v, true
		}
	}
	return "", false
}

// collectStringConsts gathers package-level `const x = "..."` values so a
// category constant resolves to the category name the wire actually carries.
func collectStringConsts(files []*ast.File) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if v, err := strconv.Unquote(lit.Value); err == nil {
						out[name.Name] = v
					}
				}
			}
		}
	}
	return out
}

// collectCoreProfile reads `coreProfileCategories` — the set scored under
// `--profile core`. Read from source rather than hardcoded here for the reason
// AGENTS.md gives about hand-counting it: the set moved from 14 to 16 when
// v7.75 folded concurrency and resource_bounds, and every copy of the number
// that was not derived went stale.
func collectCoreProfile(files []*ast.File, consts map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "coreProfileCategories" {
					continue
				}
				if len(vs.Values) != 1 {
					continue
				}
				cl, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range cl.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if v, ok := literalString([]ast.Expr{kv.Key}, 0, consts); ok {
						out[v] = true
					}
				}
			}
		}
	}
	return out
}

// AllCategoriesFrom reads the AllCategories() list so the register can name a
// category the CLI advertises but that declares nothing.
func AllCategoriesFrom(pkgDir string) (map[string]bool, error) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(pkgDir, ent.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	consts := collectStringConsts(files)
	out := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "AllCategories" || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				for _, elt := range cl.Elts {
					if v, ok := literalString([]ast.Expr{elt}, 0, consts); ok {
						out[v] = true
					}
				}
				return true
			})
		}
	}
	return out, nil
}

func posOf(fset *token.FileSet, p token.Pos, root string) string {
	pos := fset.Position(p)
	return fmt.Sprintf("%s:%d", filepath.Base(pos.Filename), pos.Line)
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}
