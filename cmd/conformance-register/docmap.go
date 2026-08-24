package main

// The document universe — discovered from the spec trees, not typed here.
//
// A citation resolves only if the document exists and the section exists in it.
// Both halves are read from the sibling repos at run time, so this tool cannot
// drift ahead of the specs the way a hand-maintained table would: when arch
// renames a document or renumbers a section, the resolver notices on the next
// run instead of the next reader.
//
// Only two aliases are hardcoded (`V7`, `ECF`), because they are genuine
// shorthand with no textual relationship to the filename. Everything else is
// derived: `EXTENSION-NETWORK.md` answers to `EXTENSION-NETWORK` and `NETWORK`,
// `DOMAIN-LOCAL-FILES.md` to `DOMAIN-LOCAL-FILES` and `LOCAL-FILES`. A token
// that matches no document is a finding, never a guess — a resolver that
// fuzzy-matched its way to a plausible document would manufacture exactly the
// false confidence the register exists to remove.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Tier is what kind of document a citation lands in — the adoption boundary.
//
// This is the distinction that decides what a peer is BOUND to. The core floor
// is not optional: a peer either implements it or does not conform. An extension
// is adopted, and a peer that has not adopted one owes nothing to its spec — an
// absent optional extension is a SKIP, never a FAIL (arch's oracle-contract
// §3(d)). Recording the tier per check is what lets the register answer "which
// of these requirements apply to a peer that adopts nothing but the core."
type Tier string

const (
	TierCore      Tier = "core"      // entity-core-protocol/specs — the floor, non-optional
	TierExtension Tier = "extension" // EXTENSION-* — adopted, not assumed
	TierDomain    Tier = "domain"    // specs/domains — application domains over the core
	TierSDK       Tier = "sdk"       // specs/sdk — implementer surface, not peer behaviour
	TierSystem    Tier = "system"    // arch specs root — architecture, composition
	TierApp       Tier = "app"       // specs/applications — conventions above the protocol
	TierGuide     Tier = "guide"     // guides/ — non-normative
	TierProposal  Tier = "proposal"  // docs/proposals — non-normative, not yet folded
)

// Adoptable reports whether a peer may decline this tier and still conform.
// The core floor is the only tier that is not adoptable.
func (t Tier) Adoptable() bool { return t != TierCore }

// Doc is one specification, guide, or proposal.
type Doc struct {
	Name      string // basename without .md
	Path      string // path as cited in output, repo-relative
	Normative bool   // false for guides/ and docs/proposals/
	Tier      Tier
	rank      int // lower wins an alias collision

	headings map[string]bool // section numbers that are headings
	body     map[string]bool // section numbers cited anywhere in the text
	amend    map[string]bool // "Amendment N" numbers present
	ambig    []string        // other docs that wanted the same short alias
}

// DocSet is the resolved universe plus its alias index.
type DocSet struct {
	docs    map[string]*Doc // by Name
	aliases map[string]*Doc // by every accepted spelling
}

type docRoot struct {
	dir       string
	normative bool
	rank      int
}

// hardAliases are the two shorthands with no textual relationship to a
// filename. Kept deliberately short: every entry here is a place the tool
// stops being derived from the trees.
var hardAliases = map[string]string{
	"V7":  "ENTITY-CORE-PROTOCOL",
	"ECF": "ENTITY-CBOR-ENCODING",
}

// stripPrefixes are the document-class prefixes a citation may omit.
var stripPrefixes = []string{"EXTENSION-", "DOMAIN-", "GUIDE-", "PROPOSAL-", "SPEC-", "ENTITY-", "SYSTEM-", "ARCHITECTURE-"}

// LoadDocs discovers every spec, guide and proposal reachable from the sibling
// repos. protoRoot is entity-core-protocol; archRoot is
// entity-system-architecture.
func LoadDocs(protoRoot, archRoot string) (*DocSet, error) {
	roots := []docRoot{
		{filepath.Join(protoRoot, "specs"), true, 0},
		{filepath.Join(archRoot, "specs"), true, 1},
		{filepath.Join(archRoot, "guides"), false, 2},
		{filepath.Join(archRoot, "docs", "proposals"), false, 3},
	}

	ds := &DocSet{docs: map[string]*Doc{}, aliases: map[string]*Doc{}}
	for _, root := range roots {
		if _, err := os.Stat(root.dir); err != nil {
			return nil, fmt.Errorf("spec root not readable (%s) — the register resolves against the live trees, so a missing sibling is a hard error, not an empty result: %w", root.dir, err)
		}
		err := filepath.WalkDir(root.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
				return nil
			}
			name := strings.TrimSuffix(d.Name(), ".md")
			if _, exists := ds.docs[name]; exists {
				// Same basename in two roots. Keep the higher-ranked
				// (more normative) one and say nothing further: the
				// alias index records the collision below.
				return nil
			}
			doc := &Doc{Name: name, Path: path, Normative: root.normative, Tier: tierOf(path, root), rank: root.rank}
			if err := doc.index(); err != nil {
				return err
			}
			ds.docs[name] = doc
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// Alias index, built in rank order so a spec beats a guide for a bare
	// name (EXTENSION-IDENTITY wins `IDENTITY` over GUIDE-IDENTITY).
	names := make([]string, 0, len(ds.docs))
	for n := range ds.docs {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if ds.docs[names[i]].rank != ds.docs[names[j]].rank {
			return ds.docs[names[i]].rank < ds.docs[names[j]].rank
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		doc := ds.docs[n]
		ds.claim(n, doc)
		for _, p := range stripPrefixes {
			if strings.HasPrefix(n, p) {
				ds.claim(strings.TrimPrefix(n, p), doc)
				break
			}
		}
	}
	for alias, target := range hardAliases {
		if doc, ok := ds.docs[target]; ok {
			ds.aliases[alias] = doc
		}
	}
	return ds, nil
}

// tierOf classifies a document by where it lives. Layout, not filename: a
// document's tier is a fact about which tree publishes it, and inferring it from
// the name would break the moment arch files an EXTENSION-shaped document
// somewhere else.
func tierOf(path string, root docRoot) Tier {
	if !root.normative {
		if strings.Contains(path, string(filepath.Separator)+"proposals"+string(filepath.Separator)) {
			return TierProposal
		}
		return TierGuide
	}
	if root.rank == 0 {
		// entity-core-protocol/specs — the floor. Everything here binds every
		// conforming peer, with no adoption step.
		return TierCore
	}
	switch {
	case strings.Contains(path, "/extensions/"):
		return TierExtension
	case strings.Contains(path, "/domains/"):
		return TierDomain
	case strings.Contains(path, "/sdk/"):
		return TierSDK
	case strings.Contains(path, "/applications/"):
		return TierApp
	default:
		return TierSystem
	}
}

func (ds *DocSet) claim(alias string, doc *Doc) {
	if alias == "" {
		return
	}
	if prev, taken := ds.aliases[alias]; taken {
		if prev != doc {
			prev.ambig = append(prev.ambig, doc.Name)
		}
		return
	}
	ds.aliases[alias] = doc
}

// Lookup resolves a citation's document token.
func (ds *DocSet) Lookup(token string) (*Doc, bool) {
	d, ok := ds.aliases[token]
	return d, ok
}

func (ds *DocSet) Len() int { return len(ds.docs) }

// Candidates names the normative documents carrying the given section as a
// heading. It exists to make an unnamed citation FIXABLE without the tool
// guessing: a `§6.5.6` that names no document is a defect, and knowing that
// exactly one specification has a §6.5.6 is what lets a human repair it in
// seconds. The resolver reports this list; it never applies it.
// It reports nothing past candidateLimit: `§2` is a heading in forty
// documents, and printing forty names buries the citations where the answer is
// unambiguous. Deep sections are the ones worth listing, and they are the ones
// with few carriers.
func (ds *DocSet) Candidates(section string) ([]string, int) {
	var out []string
	for name, doc := range ds.docs {
		if doc.Normative && doc.headings[section] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	total := len(out)
	if total > candidateLimit {
		return nil, total
	}
	return out, total
}

const candidateLimit = 3

var (
	// Specs head sections with a bare number (`### 1.2a Content format`);
	// guides head them with the section mark (`### §2.4a Every check ...`).
	// Both shapes, one expression.
	reHeading = regexp.MustCompile(`(?m)^#{1,6}\s+§?\s*([0-9]+[a-zA-Z]?(?:\.[0-9]+[a-zA-Z]?)*)\b`)
	// A section cited in running text.
	reBodySection = regexp.MustCompile(`§\s*([0-9]+[a-zA-Z]?(?:\.[0-9]+[a-zA-Z]?)*)`)
	reAmendment   = regexp.MustCompile(`(?i)\bamendment\s+([0-9]+)\b`)
)

func (d *Doc) index() error {
	b, err := os.ReadFile(d.Path)
	if err != nil {
		return err
	}
	text := string(b)
	d.headings = map[string]bool{}
	d.body = map[string]bool{}
	d.amend = map[string]bool{}
	for _, m := range reHeading.FindAllStringSubmatch(text, -1) {
		d.headings[m[1]] = true
	}
	for _, m := range reBodySection.FindAllStringSubmatch(text, -1) {
		d.body[m[1]] = true
	}
	for _, m := range reAmendment.FindAllStringSubmatch(text, -1) {
		d.amend[m[1]] = true
	}
	return nil
}

// HasSection classifies how a section number is present in the document.
func (d *Doc) HasSection(sec string) SectionHit {
	if d.headings[sec] {
		return HitHeading
	}
	// A citation deeper than the document's headings (§6a.9.1 where the
	// heading stops at §6a.9) still resolves — the section exists and the
	// sub-clause is prose beneath it.
	//
	// The parent MUST itself be at least two components deep. Without that
	// floor, every document has a §3, so `§3.6999` — a typo, a line number, a
	// mangled vector id — resolves against §3 and the gate reports it clean.
	// That escape was found by mutation, not by review: a citation was
	// deliberately corrupted in the live tree and -check still passed.
	for parent := sec; ; {
		i := strings.LastIndex(parent, ".")
		if i < 0 {
			break
		}
		parent = parent[:i]
		if strings.Count(parent, ".") < 1 {
			break
		}
		if d.headings[parent] {
			return HitHeadingParent
		}
	}
	if d.body[sec] {
		return HitBody
	}
	return HitMissing
}

func (d *Doc) HasAmendment(n string) bool { return d.amend[n] }

// SectionHit is how firmly a cited section landed.
type SectionHit string

const (
	HitHeading       SectionHit = "heading"
	HitHeadingParent SectionHit = "heading-parent"
	HitBody          SectionHit = "body"
	HitMissing       SectionHit = "missing"
)
