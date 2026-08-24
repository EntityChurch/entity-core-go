package main

// The fold-debt census — checks that assert a rule the cited spec does not carry.
//
// # Why this is a different question from every other mode in this tool
//
// Every other mode asks whether a citation RESOLVES. This one asks whether a
// citation that resolves perfectly is nonetheless in conflict with the text it
// points at, and those are opposite shapes:
//
//	UNRESOLVED   the check names a section that is not there   → citation hygiene
//	CONFLICT     the check names a section that IS there, and  → arch's fold debt
//	             asserts the opposite of what it says
//
// **The distinction is not academic and it inverts arch's framing.** Arch's
// `ROUTING-2026-08-13-j` §4 asked how many of the 212 UNRESOLVED rows are
// fold debt. The answer is essentially none of them, and the reason is
// `network_maintain_installs_graph`: it cites `EXTENSION-NETWORK §4.1`, that
// section exists, the citation resolves — and §4.1's normative pseudocode mints
// `chain_id = "network/maintain/" + session_id` while the check FAILS any peer
// whose `chain_id` contains a `/`. A peer implementing the spec as written
// fails the conformance run.
//
// So the fold debt does not live in the unresolved rows at all. **It lives in
// the RESOLVED ones, which is exactly why five arch reviews walked past it** —
// every automated signal was green, because resolution was the only thing
// anything measured.
//
// # What this can and cannot do
//
// It CANNOT read a spec section and decide whether a check contradicts it. That
// needs both texts read by someone who understands the rule, and pretending
// otherwise would produce a census that is confidently wrong.
//
// What it CAN do is find every check where **we already wrote the divergence
// down** — in a comment, or as a `spec-issues/` filing. That is a genuine
// mechanical census with one honest property:
//
//	IT IS A LOWER BOUND, NEVER A TOTAL.
//
// A divergence nobody commented on is invisible here, and the count is
// therefore a floor on arch's fold debt rather than a measure of it. Reported
// that way in the output, deliberately: a lower bound presented as a total is
// how "we checked" becomes "there are no others."
//
// The marker vocabulary is tuned for PRECISION over recall. A census arch will
// act on is worth more small and trustworthy than large and noisy — every row
// here should survive being opened.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// conflictMarker is a phrase that means "the SPEC is wrong or behind", as
// distinct from the far more common "the PEER is wrong".
//
// That distinction is the whole design problem. `non-conformant` appears ~20
// times in the validator and almost every one describes a peer — the normal
// direction — so it is deliberately NOT a marker on its own. What earns a row
// here is language about the DOCUMENT: a filed spec-issue, a section whose
// literal text is called out, a fold that has not happened.
type conflictMarker struct {
	phrase string
	why    string
}

var conflictMarkers = []conflictMarker{
	// The strongest signal by far: we filed it. A `spec-issues/` reference in
	// a check's comment is this repo's canonical record of "we believe the
	// spec is wrong here", and it is already routed to arch by construction.
	{"spec-issues/", "a filed spec-issue — our canonical divergence record"},

	// Language about the document's own text.
	{"stale pseudocode", "the cited pseudocode is called stale"},
	{"the spec still", "the spec is described as not yet updated"},
	{"spec still reads", "the spec is described as not yet updated"},
	{"spec is wrong", "stated outright"},
	{"the spec carries", "the spec is described as carrying something else"},
	{"'s literal", "a section's literal text is singled out (e.g. \"§4.1's literal\")"},
	{"literal pseudocode", "the cited pseudocode's literal reading is rejected"},
	{"ruled non-conformant", "a spec-described construction is ruled out"},

	// Fold state.
	{"not yet folded", "an accepted ruling has not reached the spec"},
	{"unfolded", "an accepted ruling has not reached the spec"},
	{"fold owed", "an accepted ruling has not reached the spec"},
	{"never landed", "built here, never landed upstream"},
	{"arch owes", "explicitly routed"},
	{"drafted but unsent", "routed nowhere yet — the weakest form, and the one that goes stale"},
}

// Conflict is one check whose citation resolves and whose source records a
// divergence from the cited document.
type Conflict struct {
	Category string
	Check    string
	SpecRef  string
	Verdict  Verdict
	Source   string
	Marker   string
	Why      string
	Excerpt  string
}

// scanConflicts walks the oracle package a second time, with comments retained
// (the main extraction drops them), and ties each comment block to the check
// whose `Run("<name>", …)` it sits on or in.
//
// Attribution is by NAME rather than by position: a check is declared in one
// place and run in another, and the divergence commentary is almost always at
// the run site where the assertion actually lives.
func scanConflicts(pkgDir string, rows []Row) ([]Conflict, error) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pkgDir, err)
	}

	// check name -> the comment text surrounding its Run site.
	commentary := map[string]string{}

	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		// Every comment in the file, by position, so a range query is cheap.
		type placedComment struct {
			start, end token.Pos
			text       string
		}
		var comments []placedComment
		for _, cg := range f.Comments {
			comments = append(comments, placedComment{cg.Pos(), cg.End(), cg.Text()})
		}

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Run" && sel.Sel.Name != "Declare" && sel.Sel.Name != "DeclareSelf") {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			checkName := strings.Trim(lit.Value, `"`)
			if checkName == "" {
				return true
			}

			// The window: from a little before the call (to catch the doc
			// comment sitting on top of it) through the end of the call
			// itself (to catch comments inside the closure body).
			lo := call.Pos() - 2000
			hi := call.End()
			var b strings.Builder
			for _, c := range comments {
				if c.end >= lo && c.start <= hi {
					b.WriteString(c.text)
					b.WriteString("\n")
				}
			}
			commentary[checkName] += b.String()
			return true
		})
	}

	var out []Conflict
	for _, r := range rows {
		// Only rows whose citation RESOLVES are candidates. An unresolved row
		// is citation hygiene and is already reported by -findings; mixing the
		// two is what produced arch's framing error in the first place.
		if r.Verdict != VerdictResolved && r.Verdict != VerdictPartial {
			continue
		}
		text := commentary[r.Check]
		if text == "" {
			continue
		}
		lower := strings.ToLower(text)
		for _, m := range conflictMarkers {
			idx := strings.Index(lower, strings.ToLower(m.phrase))
			if idx < 0 {
				continue
			}
			out = append(out, Conflict{
				Category: r.Category,
				Check:    r.Check,
				SpecRef:  r.SpecRef,
				Verdict:  r.Verdict,
				Source:   r.Source,
				Marker:   m.phrase,
				Why:      m.why,
				Excerpt:  excerptAround(text, idx),
			})
			break // one row per check — the first marker is enough to open it
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Check < out[j].Check
	})
	return out, nil
}

// excerptAround pulls the sentence the marker sits in, so a reader can triage
// the row without opening the file.
func excerptAround(text string, idx int) string {
	const span = 150
	lo := idx - span/2
	if lo < 0 {
		lo = 0
	}
	hi := idx + span
	if hi > len(text) {
		hi = len(text)
	}
	s := strings.Join(strings.Fields(text[lo:hi]), " ")
	if lo > 0 {
		s = "…" + s
	}
	if hi < len(text) {
		s += "…"
	}
	return s
}

func reportConflicts(conflicts []Conflict, total int) {
	fmt.Println("fold-debt census — checks whose citation RESOLVES but whose source records a divergence")
	fmt.Println()
	fmt.Println("  These are NOT the -findings rows. A finding is a citation that does not resolve")
	fmt.Println("  (hygiene). These resolve perfectly and still conflict with the text they cite —")
	fmt.Println("  the shape that fails a peer for implementing the spec as written.")
	fmt.Println()

	if len(conflicts) == 0 {
		fmt.Println("  none found.")
	} else {
		byCat := map[string]int{}
		for _, c := range conflicts {
			byCat[c.Category]++
		}
		cats := make([]string, 0, len(byCat))
		for k := range byCat {
			cats = append(cats, k)
		}
		sort.Strings(cats)

		for _, c := range conflicts {
			fmt.Printf("  %s.%s\n", c.Category, c.Check)
			fmt.Printf("      cites   %s  [%s]\n", c.SpecRef, c.Verdict)
			fmt.Printf("      marker  %q — %s\n", c.Marker, c.Why)
			fmt.Printf("      source  %s\n", c.Source)
			fmt.Printf("      context %s\n", c.Excerpt)
			fmt.Println()
		}

		fmt.Println("  by category:")
		for _, k := range cats {
			fmt.Printf("    %-28s %d\n", k, byCat[k])
		}
		fmt.Println()
	}

	fmt.Printf("  %d of %d checks carry a recorded divergence.\n", len(conflicts), total)
	fmt.Println()
	fmt.Println("  THIS IS A LOWER BOUND, NOT A TOTAL. It finds divergences we already wrote")
	fmt.Println("  down; one nobody commented on is invisible to it. Read the count as a floor")
	fmt.Println("  on the fold debt — reporting it as a measure is how a census becomes a")
	fmt.Println("  false all-clear.")
}
