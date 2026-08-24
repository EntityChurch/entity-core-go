// Command conformance-register emits the conformance category register — every
// check the oracle declares, the citation it claims, and whether that citation
// resolves in a normative document.
//
// # Why this exists
//
// PROPOSAL-CONFORMANCE-ORACLE-CONTRACT (arch, 2026-08-13) specifies a category
// register: "each category names what it asserts, its normative home, and its
// profile membership," and calls it "the largest single piece of work in the
// proposal" — expected to be walked by hand. It does not need to be walked by
// hand. Every check already declares its category, its name, its citation, and
// (since the 2026-08-12 self-check audit) whether it contacts the peer at all.
// This reads that out and resolves it against the live spec trees.
//
// What the walk was actually going to buy is the part arch predicted: "where a
// category asserts something with no normative home, that is a finding, not a
// formatting problem." This enumerates those instead of anticipating them.
//
// # Determinism
//
// Same source + same spec trees => byte-identical output. No network, no model,
// no heuristic matching: a document token resolves by name against files that
// exist, and a section resolves against headings that exist. A token that
// matches nothing is reported as unresolved rather than guessed at.
//
// # Usage
//
//	go run ./cmd/conformance-register                     # summary
//	go run ./cmd/conformance-register -md > REGISTER.md    # the register
//	go run ./cmd/conformance-register -findings            # only the gaps
//	go run ./cmd/conformance-register -json                # machine-readable
//	go run ./cmd/conformance-register -check               # gate (ratchet)
//	go run ./cmd/conformance-register -write-baseline      # re-pin the ratchet
//
// # The gate
//
// -check is a RATCHET, not a pass/fail on the findings themselves. A large
// minority of rows do not resolve cleanly today (run it and read the count —
// this comment deliberately does not carry one, because a number written into
// prose is a number that goes stale); a gate that failed on all of those would
// be red on arrival, which is what this repo declined to do with the corpus
// verifier.
// Instead the current findings are pinned in a committed baseline, and -check
// fails on any row that is newly unresolved. The baseline is exact in both
// directions: a row that becomes resolved also fails the gate, because a
// baseline nobody re-pins is a baseline that stops meaning anything.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	flagPkg      = flag.String("validate-pkg", "cmd/internal/validate", "the oracle's check package")
	flagProto    = flag.String("proto", "../entity-core-protocol", "entity-core-protocol checkout (the core spec floor)")
	flagArch     = flag.String("arch", "../entity-system-architecture", "entity-system-architecture checkout (extensions, guides, proposals)")
	flagBaseline = flag.String("baseline", "docs/validation/conformance-register-baseline.json", "committed findings baseline for -check")

	flagMD        = flag.Bool("md", false, "emit the register as markdown")
	flagJSON      = flag.Bool("json", false, "emit the register as JSON")
	flagFindings  = flag.Bool("findings", false, "emit only rows with no normative home")
	flagCheck     = flag.Bool("check", false, "compare findings to the baseline; exit 1 on any difference")
	flagWriteBase = flag.Bool("write-baseline", false, "rewrite the baseline from the current tree")
	flagCategory  = flag.String("category", "", "restrict output to one category")
	flagBoundary  = flag.Bool("boundary", false, "report where each check's requirement lives: core floor vs adoptable extension")
	flagConflicts = flag.Bool("conflicts", false, "the fold-debt census: checks whose citation RESOLVES but whose source records a divergence from the cited text (a LOWER BOUND — see conflicts.go)")
)

// Register is the whole emitted document.
type Register struct {
	Rows       []Row          `json:"rows"`
	Counts     map[string]int `json:"counts"`
	Categories []CategoryStat `json:"categories"`
	Documents  int            `json:"documents_indexed"`
	Orphans    []string       `json:"categories_declaring_nothing,omitempty"`
}

// CategoryStat is the per-category summary — the shape §2 of the proposal asks
// for, plus the peer-attributable split the draft does not yet require.
type CategoryStat struct {
	Category     string `json:"category"`
	CoreProfile  bool   `json:"core_profile"`
	Checks       int    `json:"checks"`
	SelfChecks   int    `json:"self_checks"`
	Resolved     int    `json:"resolved"`
	Partial      int    `json:"partial"`
	Unresolved   int    `json:"unresolved"`
	NonNormative int    `json:"non_normative"`
	NoCitation   int    `json:"no_citation"`
	Dynamic      int    `json:"dynamic"`
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "conformance-register:", err)
		os.Exit(1)
	}
}

func run() error {
	ext, err := Extract(*flagPkg)
	if err != nil {
		return err
	}
	// Reconciliation before anything else: a register that quietly covers
	// fewer checks than the oracle declares is the exact defect it exists to
	// find, one level up.
	if err := ext.Reconcile(); err != nil {
		return err
	}

	docs, err := LoadDocs(*flagProto, *flagArch)
	if err != nil {
		return err
	}
	for i := range ext.Rows {
		Resolve(&ext.Rows[i], docs)
	}

	reg := build(ext, docs)

	switch {
	case *flagConflicts:
		conflicts, err := scanConflicts(*flagPkg, ext.Rows)
		if err != nil {
			return err
		}
		reportConflicts(conflicts, len(ext.Rows))
		return nil
	case *flagWriteBase:
		return writeBaseline(reg)
	case *flagCheck:
		return check(reg)
	case *flagJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(reg)
	case *flagMD:
		return emitMarkdown(os.Stdout, reg)
	case *flagBoundary:
		return emitBoundary(os.Stdout, reg)
	case *flagFindings:
		return emitFindings(os.Stdout, reg)
	default:
		return emitSummary(os.Stdout, reg)
	}
}

func build(ext *Extraction, docs *DocSet) *Register {
	reg := &Register{Counts: map[string]int{}, Documents: docs.Len()}
	stats := map[string]*CategoryStat{}

	for _, row := range ext.Rows {
		if *flagCategory != "" && row.Category != *flagCategory {
			continue
		}
		reg.Rows = append(reg.Rows, row)
		reg.Counts[string(row.Verdict)]++

		st := stats[row.Category]
		if st == nil {
			st = &CategoryStat{Category: row.Category, CoreProfile: row.CoreProfile}
			stats[row.Category] = st
		}
		st.Checks++
		if row.SelfCheck {
			st.SelfChecks++
		}
		switch row.Verdict {
		case VerdictResolved:
			st.Resolved++
		case VerdictPartial:
			st.Partial++
		case VerdictUnresolved:
			st.Unresolved++
		case VerdictNonNormative:
			st.NonNormative++
		case VerdictNoCitation:
			st.NoCitation++
		case VerdictDynamic:
			st.Dynamic++
		}
	}

	for _, st := range stats {
		reg.Categories = append(reg.Categories, *st)
	}
	sort.Slice(reg.Categories, func(i, j int) bool {
		return reg.Categories[i].Category < reg.Categories[j].Category
	})

	// A category the CLI advertises but that declares nothing is a gap in the
	// register, not an empty row.
	if all, err := AllCategoriesFrom(*flagPkg); err == nil {
		for cat := range all {
			if !ext.CategoriesSeen[cat] {
				reg.Orphans = append(reg.Orphans, cat)
			}
		}
		sort.Strings(reg.Orphans)
	}
	return reg
}

// namedCategories counts real categories. The register also carries an
// unattributed bucket for checks declared in helpers, and folding that into the
// category count would overstate the suite by one against every other count in
// the repo (`AllCategories()`, the CHANGELOG, arch's citations).
func (r *Register) namedCategories() int {
	n := 0
	for _, st := range r.Categories {
		if st.Category != "" {
			n++
		}
	}
	return n
}

func (r *Register) unattributed() int {
	for _, st := range r.Categories {
		if st.Category == "" {
			return st.Checks
		}
	}
	return 0
}

// tiersOf returns the distinct tiers a row's resolved citations land in.
func tiersOf(row Row) []Tier {
	seen := map[Tier]bool{}
	var out []Tier
	for _, c := range row.Citations {
		if !c.Resolved() || c.Tier == "" || seen[c.Tier] {
			continue
		}
		seen[c.Tier] = true
		out = append(out, c.Tier)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// crossesAdoptionBoundary reports a core-profile check whose requirement lives
// in an adoptable document.
//
// This is NOT automatically a defect, and the tool does not call it one. Some
// core-profile behaviour is genuinely specified in an extension document —
// `tree_operations` is scored against V7 §9.5a while the operations themselves
// are written up in EXTENSION-TREE. What it means is that a peer claiming
// `--profile core` is being held to text it could otherwise decline, and that
// is a fact worth being able to see rather than infer.
func crossesAdoptionBoundary(row Row) bool {
	if !row.CoreProfile {
		return false
	}
	for _, t := range tiersOf(row) {
		if t.Adoptable() {
			return true
		}
	}
	return false
}

func emitBoundary(w *os.File, reg *Register) error {
	byTier := map[Tier]int{}
	coreProfileTiers := map[Tier]int{}
	var crossings []Row
	coreChecks := 0

	for _, row := range reg.Rows {
		for _, t := range tiersOf(row) {
			byTier[t]++
			if row.CoreProfile {
				coreProfileTiers[t]++
			}
		}
		if row.CoreProfile {
			coreChecks++
			if crossesAdoptionBoundary(row) {
				crossings = append(crossings, row)
			}
		}
	}

	order := []Tier{TierCore, TierExtension, TierDomain, TierSystem, TierSDK, TierApp, TierGuide, TierProposal}
	label := map[Tier]string{
		TierCore:      "core floor — binds every conforming peer, no adoption step",
		TierExtension: "extension — adopted; absent is a SKIP, never a FAIL",
		TierDomain:    "domain — application domain over the core",
		TierSystem:    "system — architecture / composition",
		TierSDK:       "sdk — implementer surface, not peer behaviour",
		TierApp:       "application convention — above the protocol",
		TierGuide:     "guide — NON-NORMATIVE",
		TierProposal:  "proposal — NON-NORMATIVE, not yet folded",
	}

	fmt.Fprintf(w, "adoption boundary — where each check's requirement actually lives\n\n")
	fmt.Fprintf(w, "  %-11s %8s %8s   %s\n", "tier", "checks", "of which", "")
	fmt.Fprintf(w, "  %-11s %8s %8s   %s\n", "", "(any)", "core-prof", "")
	for _, t := range order {
		if byTier[t] == 0 {
			continue
		}
		fmt.Fprintf(w, "  %-11s %8d %8d   %s\n", t, byTier[t], coreProfileTiers[t], label[t])
	}

	fmt.Fprintf(w, "\n  %d of %d core-profile checks cite a requirement in an adoptable document.\n",
		len(crossings), coreChecks)
	fmt.Fprintln(w, "  Not a defect by itself — some core behaviour is written up in an extension spec.")
	fmt.Fprintln(w, "  It is what a peer claiming --profile core is held to beyond the core floor:")

	byCat := map[string]map[string]bool{}
	for _, row := range crossings {
		if byCat[row.Category] == nil {
			byCat[row.Category] = map[string]bool{}
		}
		for _, c := range row.Citations {
			if c.Resolved() && c.Tier.Adoptable() {
				byCat[row.Category][c.Doc] = true
			}
		}
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		docs := make([]string, 0, len(byCat[c]))
		for d := range byCat[c] {
			docs = append(docs, d)
		}
		sort.Strings(docs)
		fmt.Fprintf(w, "    %-24s -> %s\n", c, strings.Join(docs, ", "))
	}

	// The sharper subset, and the zero is REPORTED rather than left silent: a
	// core-profile requirement whose only home is non-normative. An extension
	// crossing is a documented dependency between two ratified specs; a
	// guide-only crossing is a publication-contract MUST resting on text nothing
	// ratifies. A reader must be able to tell "checked, none" from "not checked."
	var nonNorm []Row
	for _, row := range crossings {
		normative := false
		for _, c := range row.Citations {
			if c.Resolved() && c.Normative {
				normative = true
				break
			}
		}
		if !normative {
			nonNorm = append(nonNorm, row)
		}
	}
	fmt.Fprintf(w, "\n  Of those, %d rest on a NON-NORMATIVE home alone (a guide or a proposal,\n", len(nonNorm))
	fmt.Fprintf(w, "  with no normative co-citation) — a core-profile MUST nothing ratifies.\n")
	for _, row := range nonNorm {
		var where []string
		for _, c := range row.Citations {
			if c.Resolved() {
				where = append(where, c.Doc+" "+c.Raw)
			}
		}
		fmt.Fprintf(w, "    %-46s %s\n", row.Key(), strings.Join(where, ", "))
	}
	return nil
}

// findings are the rows without a resolved normative home, keyed for baseline
// comparison.
//
// A key can cover more than one declaration — 8 rows share `handlers.<computed>`
// because the extractor cannot name a check whose name is built at runtime, and
// two `origination` checks are declared under one name at two sites. So the
// value is the SORTED MULTISET of verdicts across every row sharing the key, not
// a single verdict.
//
// The first version stored one verdict per key and silently collapsed 227 rows
// into 205 entries: a shared key whose rows changed from
// {RESOLVED, UNRESOLVED} to {UNRESOLVED, UNRESOLVED} was invisible to the gate,
// and the reported finding count was 22 short of the rows it described. Keying
// on `file:line` instead would make it exact and make the baseline churn on
// every line shift — and line numbers expire (AGENTS-STANDARD: pin to
// symbol + path). The multiset is exact without being positional.
func (r *Register) findings() map[string]string {
	byKey := map[string][]string{}
	interesting := map[string]bool{}
	for _, row := range r.Rows {
		k := row.Key()
		byKey[k] = append(byKey[k], string(row.Verdict))
		if row.Verdict != VerdictResolved {
			interesting[k] = true
		}
	}
	out := map[string]string{}
	for k := range interesting {
		v := byKey[k]
		sort.Strings(v)
		out[k] = strings.Join(v, ",")
	}
	return out
}

// findingRows counts the DECLARATIONS behind the findings, which is the number a
// reader comparing against the register's verdict table expects.
func (r *Register) findingRows() int {
	n := 0
	for _, row := range r.Rows {
		if row.Verdict != VerdictResolved {
			n++
		}
	}
	return n
}

// --- output ----------------------------------------------------------------

func emitSummary(w *os.File, reg *Register) error {
	total := len(reg.Rows)
	fmt.Fprintf(w, "conformance register — %d declared checks across %d categories, %d documents indexed\n",
		total, reg.namedCategories(), reg.Documents)
	if n := reg.unattributed(); n > 0 {
		fmt.Fprintf(w, "  (+ %d checks declared in helpers, not attributable to a category from source)\n", n)
	}
	fmt.Fprintln(w)

	order := []Verdict{VerdictResolved, VerdictPartial, VerdictNonNormative, VerdictUnresolved, VerdictNoCitation, VerdictDynamic}
	labels := map[Verdict]string{
		VerdictResolved:     "every citation resolves, normatively",
		VerdictPartial:      "has a normative home; one or more citations do not resolve",
		VerdictNonNormative: "resolves only into a guide or proposal",
		VerdictUnresolved:   "cites a document or section that does not resolve",
		VerdictNoCitation:   "carries no parseable citation",
		VerdictDynamic:      "declaration is not a literal (unreadable from source)",
	}
	for _, v := range order {
		n := reg.Counts[string(v)]
		fmt.Fprintf(w, "  %-14s %5d  %5.1f%%  %s\n", v, n, pct(n, total), labels[v])
	}

	self := 0
	for _, row := range reg.Rows {
		if row.SelfCheck {
			self++
		}
	}
	fmt.Fprintf(w, "\n  peer-attributable %d of %d (%d self-checks)\n", total-self, total, self)

	if len(reg.Orphans) > 0 {
		fmt.Fprintf(w, "\n  categories advertised by AllCategories() that declare nothing: %s\n",
			strings.Join(reg.Orphans, ", "))
	}
	fmt.Fprintf(w, "\nrun with -findings for the gaps, -boundary for the core/extension split, -md for the register\n")
	return nil
}

func emitFindings(w *os.File, reg *Register) error {
	byVerdict := map[Verdict][]Row{}
	for _, row := range reg.Rows {
		if row.Verdict != VerdictResolved {
			byVerdict[row.Verdict] = append(byVerdict[row.Verdict], row)
		}
	}
	for _, v := range []Verdict{VerdictUnresolved, VerdictPartial, VerdictNonNormative, VerdictNoCitation, VerdictDynamic} {
		rows := byVerdict[v]
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n## %s (%d)\n\n", v, len(rows))
		for _, row := range rows {
			fmt.Fprintf(w, "  %-58s %s\n", row.Key(), row.Source)
			fmt.Fprintf(w, "  %-58s ref: %s\n", "", oneLine(row.SpecRef))
			if row.Note != "" {
				fmt.Fprintf(w, "  %-58s note: %s\n", "", row.Note)
			}
			for _, c := range row.Citations {
				if c.Resolved() {
					continue
				}
				doc := c.Doc
				if doc == "" {
					doc = "(no document named)"
				}
				fmt.Fprintf(w, "  %-58s  -> %s %s [%s]\n", "", doc, c.Raw, c.Status)
				switch {
				case len(c.Candidates) > 0:
					fmt.Fprintf(w, "  %-58s     carried by: %s\n", "", strings.Join(c.Candidates, ", "))
				case c.CandidatesTotal > 0:
					fmt.Fprintf(w, "  %-58s     carried by %d documents — too shallow to disambiguate\n", "", c.CandidatesTotal)
				}
			}
		}
	}
	return nil
}

func emitMarkdown(w *os.File, reg *Register) error {
	fmt.Fprintf(w, "# Conformance category register\n\n")
	fmt.Fprintf(w, "Generated by `go run ./cmd/conformance-register -md`. Do not hand-edit — ")
	fmt.Fprintf(w, "every row is read from the oracle's own declarations and resolved against the live spec trees.\n\n")
	fmt.Fprintf(w, "**%d declared checks · %d categories · %d documents indexed**\n\n",
		len(reg.Rows), reg.namedCategories(), reg.Documents)
	if n := reg.unattributed(); n > 0 {
		fmt.Fprintf(w, "A further **%d** checks are declared in shared helpers and are not attributable to a category from source; they are listed under *(unattributed)* below.\n\n", n)
	}

	fmt.Fprintf(w, "## Categories\n\n")
	fmt.Fprintf(w, "| Category | Profile | Checks | Peer-attributable | Resolved | No normative home |\n")
	fmt.Fprintf(w, "|---|---|---:|---:|---:|---:|\n")
	for _, st := range reg.Categories {
		profile := "full"
		if st.CoreProfile {
			profile = "**core**"
		}
		gaps := st.Partial + st.Unresolved + st.NonNormative + st.NoCitation + st.Dynamic
		label := "`" + st.Category + "`"
		if st.Category == "" {
			label = displayCat("")
		}
		fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d |\n",
			label, profile, st.Checks, st.Checks-st.SelfChecks, st.Resolved, gaps)
	}

	cur := ""
	for _, row := range reg.Rows {
		if row.Category != cur {
			cur = row.Category
			fmt.Fprintf(w, "\n## `%s`\n\n", displayCat(cur))
			fmt.Fprintf(w, "| Check | Normative home | Tier | Verdict | Peer |\n|---|---|---|---|---|\n")
		}
		tiers := tiersOf(row)
		tierCell := "—"
		if len(tiers) > 0 {
			parts := make([]string, len(tiers))
			for i, t := range tiers {
				parts[i] = string(t)
			}
			tierCell = strings.Join(parts, "+")
		}
		fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s |\n",
			row.Check, homeOf(row), tierCell, row.Verdict, peerMark(row))
	}
	return nil
}

func homeOf(row Row) string {
	var parts []string
	for _, c := range row.Citations {
		if !c.Resolved() {
			continue
		}
		label := c.Doc
		if c.Section != "" {
			label += " §" + c.Section
		} else if c.Amendment != "" {
			label += " Amendment " + c.Amendment
		}
		if !c.Normative {
			label += " _(non-normative)_"
		}
		parts = append(parts, label)
	}
	if len(parts) == 0 {
		return "— " + oneLine(row.SpecRef)
	}
	return strings.Join(parts, ", ")
}

func peerMark(row Row) string {
	if row.SelfCheck {
		return "self"
	}
	return "peer"
}

func displayCat(c string) string {
	if c == "" {
		return "(unattributed — declared in a helper)"
	}
	return c
}

// --- the ratchet -----------------------------------------------------------

type baselineFile struct {
	Comment  string            `json:"_comment"`
	Findings map[string]string `json:"findings"`
}

const baselineComment = "Rows with no resolved normative home, pinned so -check can fail on NEW ones. " +
	"Exact in both directions: fixing a row also fails the gate until the baseline is rewritten " +
	"(go run ./cmd/conformance-register -write-baseline). Shrinking this file is the point."

func writeBaseline(reg *Register) error {
	if *flagCategory != "" {
		return fmt.Errorf("-write-baseline with -category would pin a partial tree as the whole baseline")
	}
	b := baselineFile{Comment: baselineComment, Findings: reg.findings()}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*flagBaseline), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*flagBaseline, append(data, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s — %d findings across %d keys pinned\n", *flagBaseline, reg.findingRows(), len(b.Findings))
	return nil
}

func check(reg *Register) error {
	if *flagCategory != "" {
		return fmt.Errorf("-check with -category cannot see the whole baseline")
	}
	data, err := os.ReadFile(*flagBaseline)
	if err != nil {
		return fmt.Errorf("baseline unreadable (%s) — run -write-baseline once to pin the current state: %w", *flagBaseline, err)
	}
	var b baselineFile
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}

	cur := reg.findings()
	var added, fixed, changed []string
	for k, v := range cur {
		old, ok := b.Findings[k]
		switch {
		case !ok:
			added = append(added, fmt.Sprintf("%s [%s]", k, v))
		case old != v:
			changed = append(changed, fmt.Sprintf("%s [%s -> %s]", k, old, v))
		}
	}
	for k, v := range b.Findings {
		if _, ok := cur[k]; !ok {
			fixed = append(fixed, fmt.Sprintf("%s [was %s]", k, v))
		}
	}
	sort.Strings(added)
	sort.Strings(fixed)
	sort.Strings(changed)

	fmt.Printf("conformance register: %d checks, %d findings across %d keys (baseline pins %d keys)\n",
		len(reg.Rows), reg.findingRows(), len(cur), len(b.Findings))

	if len(added) == 0 && len(fixed) == 0 && len(changed) == 0 {
		fmt.Println("PASS  register matches baseline")
		return nil
	}
	if len(added) > 0 {
		fmt.Printf("\nFAIL  %d check(s) newly have no resolved normative home:\n", len(added))
		for _, s := range added {
			fmt.Println("      +", s)
		}
	}
	if len(changed) > 0 {
		fmt.Printf("\nFAIL  %d check(s) changed classification:\n", len(changed))
		for _, s := range changed {
			fmt.Println("      ~", s)
		}
	}
	if len(fixed) > 0 {
		fmt.Printf("\nFAIL  %d baseline entry(ies) no longer apply — re-pin so the ratchet keeps the gain:\n", len(fixed))
		for _, s := range fixed {
			fmt.Println("      -", s)
		}
	}
	fmt.Println("\n      A new finding means a check cites something that does not resolve — either the")
	fmt.Println("      citation is wrong, or the spec moved. Fix the citation, or re-pin with")
	fmt.Println("      -write-baseline if the classification change is intended.")
	return fmt.Errorf("register does not match baseline")
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 96 {
		return s[:93] + "..."
	}
	return s
}
