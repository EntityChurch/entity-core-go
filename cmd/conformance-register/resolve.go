package main

// Resolution — does the citation a check claims actually exist?
//
// `spec_ref` is free text today: `"V7 §5.5 (multisig M4)"`, `"Amendment 5 —
// seed: out-of-scope binding"`, `"COMPUTE F10 (v3.19)"`, `"harness"`. This
// parses each one into zero or more (document, section) citations and resolves
// them against the live spec trees.
//
// The classification is the product. A check whose citation resolves to a
// heading in a normative document has a normative home; one that cites a guide,
// a proposal, a section that no longer exists, or nothing at all does not — and
// per arch's own framing that is a finding, not a formatting problem.
//
// Nothing here infers meaning from prose. A ref that does not parse into a
// citation is reported as carrying none; the tool never decides what a check
// "probably meant."

import (
	"regexp"
	"strings"
)

// Verdict is a row's register status.
type Verdict string

const (
	// VerdictResolved — every citation lands, at least one of them in a
	// normative document.
	VerdictResolved Verdict = "RESOLVED"
	// VerdictPartial — the row has a normative home, but at least one of its
	// citations does not resolve. Counted as a finding rather than folded into
	// RESOLVED: `"V7 §5.2/§975"` is a real citation beside a malformed one,
	// and a row that hides the malformed half is how a citation stays wrong
	// for a year.
	VerdictPartial Verdict = "PARTIAL"
	// VerdictNonNormative — citations resolve, but only into guides/ or
	// docs/proposals/. The check asserts something real with no normative home.
	VerdictNonNormative Verdict = "NON_NORMATIVE"
	// VerdictUnresolved — citations were parsed and none of them resolve:
	// an unknown document, or a section that is not in the document.
	VerdictUnresolved Verdict = "UNRESOLVED"
	// VerdictNoCitation — the spec ref carries no parseable citation at all.
	VerdictNoCitation Verdict = "NO_CITATION"
	// VerdictDynamic — the declaration is not a literal; the register cannot
	// read it from source. Set by the extractor.
	VerdictDynamic Verdict = "DYNAMIC"
)

// Citation is one (document, section) pair pulled out of a spec ref.
type Citation struct {
	Raw       string     `json:"raw"`
	Doc       string     `json:"doc"`
	DocPath   string     `json:"doc_path,omitempty"`
	Section   string     `json:"section,omitempty"`
	Amendment string     `json:"amendment,omitempty"`
	Hit       SectionHit `json:"hit"`
	Status    string     `json:"status"`
	Normative bool       `json:"normative"`
	Tier      Tier       `json:"tier,omitempty"`

	// Candidates names the documents that DO carry the cited section, for a
	// citation that never said which document it meant. Reported, never
	// applied: picking the single candidate would be the tool deciding what a
	// check meant, which is arch's call. One candidate is a strong hint; six
	// is the reason the citation needed a document in the first place, and
	// past candidateLimit only the count is kept.
	Candidates      []string `json:"candidates,omitempty"`
	CandidatesTotal int      `json:"candidates_total,omitempty"`
}

const (
	statusOK        = "ok"
	statusMissing   = "missing-section"
	statusUnknown   = "unknown-document"
	statusNoDoc     = "no-document"
	statusNoSection = "document-only"
)

// Resolved reports whether the citation landed somewhere real.
func (c Citation) Resolved() bool { return c.Status == statusOK || c.Status == statusNoSection }

var reToken = regexp.MustCompile(`§\s*([0-9]+[a-zA-Z]?(?:\.[0-9]+[a-zA-Z]?)*)|([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)|([0-9]+)`)

// Resolve fills in a row's citations and verdict.
func Resolve(row *Row, ds *DocSet) {
	if row.Verdict == VerdictDynamic {
		return
	}
	row.Citations = parseCitations(row.SpecRef, ds)
	row.Verdict = verdictFor(row.Citations)
}

func verdictFor(cits []Citation) Verdict {
	if len(cits) == 0 {
		return VerdictNoCitation
	}
	anyResolved, anyNormative, allResolved := false, false, true
	for _, c := range cits {
		if !c.Resolved() {
			allResolved = false
			continue
		}
		anyResolved = true
		if c.Normative {
			anyNormative = true
		}
	}
	switch {
	case anyNormative && allResolved:
		return VerdictResolved
	case anyNormative:
		return VerdictPartial
	case anyResolved:
		return VerdictNonNormative
	default:
		return VerdictUnresolved
	}
}

// parseCitations scans a spec ref left to right. A document token sets the
// document in force; a following section binds to it. That is what makes
// `"REVISION v1.6 §3.2"` resolve against EXTENSION-REVISION and
// `"COMPUTE §2.1 + V7 §6.6"` produce two citations against two documents.
func parseCitations(ref string, ds *DocSet) []Citation {
	idx := reToken.FindAllStringSubmatchIndex(ref, -1)
	var (
		out        []Citation
		curDoc     *Doc
		curName    string
		claimed    string // last doc-shaped token that resolved to nothing
		claimedEnd int    // where that token ended, for the adjacency test
		pending    bool   // last word was "Amendment", awaiting its number
	)
	group := func(m []int, n int) string {
		if m[2*n] < 0 {
			return ""
		}
		return ref[m[2*n]:m[2*n+1]]
	}
	for _, m := range idx {
		section, word, number := group(m, 1), group(m, 2), group(m, 3)

		// A doc-shaped token only claims the section that FOLLOWS IT
		// DIRECTLY. Anything but whitespace between them means the token was
		// part of the prose, not a document name: in
		// `V7 §A4-AUTHZ (AUTHZ-SCOPE-EXCEEDS-1): §6.2`, the vector ID is
		// parenthesized and punctuated away from the section, so §6.2 belongs
		// to V7 — which is what the check actually cites.
		if claimed != "" && strings.TrimSpace(ref[claimedEnd:m[0]]) != "" {
			claimed = ""
		}

		switch {
		case section != "":
			pending = false
			// A section binds to the document token immediately before it if
			// that token was doc-shaped but unknown — that is a citation to a
			// document that does not exist, and it is worth distinguishing
			// from a citation that never named one.
			doc, name := curDoc, curName
			if claimed != "" {
				doc, name = nil, claimed
			}
			out = append(out, resolveSection(doc, name, section, ds))
			claimed = ""

		case word != "":
			if strings.EqualFold(word, "amendment") {
				pending = true
				continue
			}
			pending = false
			if d, ok := ds.Lookup(word); ok {
				curDoc, curName, claimed = d, word, ""
				continue
			}
			// Only a token that is BOTH doc-shaped and immediately followed by
			// a section counts as a claim on a document. Without that second
			// condition the scanner reports every hyphenated identifier in a
			// message — `TV-RV-2`, `A4-AUTHZ`, `SHA-384` — as a missing
			// document, and the real gaps drown in it.
			if looksLikeDocToken(word) {
				claimed, claimedEnd = word, m[1]
			} else {
				claimed = ""
			}

		case number != "" && pending:
			pending = false
			out = append(out, resolveAmendment(curDoc, curName, number))
			claimed = ""
		}
	}
	return out
}

func resolveSection(doc *Doc, docName, section string, ds *DocSet) Citation {
	c := Citation{Raw: "§" + section, Doc: docName, Section: section}
	if doc == nil {
		if docName == "" {
			c.Status = statusNoDoc
		} else {
			c.Status = statusUnknown
		}
		c.Candidates, c.CandidatesTotal = ds.Candidates(section)
		return c
	}
	c.DocPath, c.Normative, c.Tier = doc.Path, doc.Normative, doc.Tier
	c.Hit = doc.HasSection(section)
	if c.Hit == HitMissing {
		c.Status = statusMissing
	} else {
		c.Status = statusOK
	}
	return c
}

func resolveAmendment(doc *Doc, docName, n string) Citation {
	c := Citation{Raw: "Amendment " + n, Doc: docName, Amendment: n}
	if doc == nil {
		c.Status = statusNoDoc
		return c
	}
	c.DocPath, c.Normative, c.Tier = doc.Path, doc.Normative, doc.Tier
	if doc.HasAmendment(n) {
		c.Status, c.Hit = statusOK, HitBody
	} else {
		c.Status = statusMissing
	}
	return c
}

// looksLikeDocToken keeps ordinary prose out of the findings. Document names
// in this ecosystem are upper-case and usually hyphenated; a lower-case word
// or a bare capitalized word is prose, and reporting it as a missing document
// would bury the real gaps in noise.
func looksLikeDocToken(w string) bool {
	if len(w) < 4 || !strings.Contains(w, "-") {
		return false
	}
	return w == strings.ToUpper(w)
}
