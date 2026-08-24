package main

// Cross-bless — the gate.
//
// GUIDE-CONFORMANCE §7c.5(d): "cross-bless — lock only when byte-identical;
// divergence → §4." And §7c.4(3): "for the cross-impl corpus, no impl is
// privileged... Disagreement routes through §4 — one impl differs = its bug;
// all differ = spec ambiguity (the round's work product); NO VOTING."
//
// The no-voting rule is the whole design of this file. It would be easy, and
// wrong, to compute a majority answer and mark the odd impl out as failing. A
// 2-of-3 majority is not evidence: the cohort's own honesty rule says a set of
// implementers agreeing is cohort-consistent, not correct. So this tool
// CLASSIFIES divergence and never adjudicates it. When all three differ, the
// output is a spec-ambiguity item for arch, not a scoreboard.
//
// WHAT IS COMPARED STRICTLY, AND ONE THING THAT IS NOT
//
// Kind, boundary bytes, and error code are compared byte-for-byte. Error
// MESSAGE is not — and as of the 2026-07-23 arch ruling (Q1), this is no longer
// a deviation from §7c.3 but its resolution:
//
//	A MATERIALIZED compute/error is content-hashed over `code` ALONE
//	(EXTENSION-COMPUTE §2.4, amended). message/at/expression are diagnostic and
//	MUST NOT enter the bytes V7 content-addresses. So the corpus boundary and the
//	AE-1 boundary coincide, and comparing `code` strictly IS the
//	materialized-boundary comparison — §7c.3's "(+message)" parenthesis was
//	amended to match. The first run measured why: 135 vectors agreed on the code
//	and differed on the prose; comparing messages strictly would have reddened
//	135 of 328 and buried the real divergences.
//
// So messages are carried in the emission and reported as advisory notes (they
// remain useful for triage — the first run had one code-only coincidental
// agreement the messages disambiguated), never as a gate.

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// verdictKind classifies one vector across the emissions.
type verdictKind int

const (
	verdictAgree verdictKind = iota
	// verdictOneDiffers: exactly one impl stands apart from a group that
	// agrees. §4 routes this as that impl's bug.
	verdictOneDiffers
	// verdictAllDiffer: no two impls agree. §4 routes this as a spec ambiguity
	// — the round's work product, not anyone's bug.
	verdictAllDiffer
	// verdictSplit: impls partition into two or more groups of size > 1 with
	// none isolated. §4 does not name this case; it is reported as unrouted
	// rather than forced into one of the two.
	verdictSplit
	// verdictTwoWay: exactly two emissions disagree.
	//
	// §4's rule reads "one impl differs = its bug; all differ = spec ambiguity"
	// — and with two impls those are the SAME observation. Reporting a 1-vs-1
	// disagreement as ALL-DIFFER would route a plain impl bug to arch as a spec
	// ambiguity; reporting it as ONE-DIFFERS would name a culprit the evidence
	// does not identify. Neither is honest, so it gets its own verdict: a real
	// divergence, not routable by §4 until a third impl answers.
	verdictTwoWay
	// verdictIncomplete: at least one impl did not answer. A skip counts as a
	// failure (§3.1(2)), so this is never silently treated as agreement.
	verdictIncomplete
)

func (v verdictKind) String() string {
	switch v {
	case verdictAgree:
		return "AGREE"
	case verdictOneDiffers:
		return "ONE-DIFFERS"
	case verdictAllDiffer:
		return "ALL-DIFFER"
	case verdictSplit:
		return "SPLIT"
	case verdictTwoWay:
		return "TWO-WAY"
	default:
		return "INCOMPLETE"
	}
}

type vectorVerdict struct {
	id       string
	kind     verdictKind
	groups   map[string][]string // canonical outcome → impl names
	outlier  string              // set when kind == verdictOneDiffers
	msgNotes []string            // advisory: differing error messages under an agreed code
}

// crossBless compares two or more emissions over the same corpus.
func crossBless(c *Corpus, ems []*Emission, corpusSHA []byte) ([]vectorVerdict, error) {
	if len(ems) < 2 {
		return nil, fmt.Errorf("cross-bless needs at least 2 emissions, got %d", len(ems))
	}
	// Every emission must answer the SAME artifact. Without this check a stale
	// emission silently "agrees" on the vectors that happen to share an ID and
	// the lock is meaningless.
	seenImpl := map[string]bool{}
	for _, em := range ems {
		if !bytes.Equal(em.CorpusSHA256, corpusSHA) {
			return nil, fmt.Errorf("emission %s/%s answers corpus %x, not %x — rebuild it",
				em.Impl, em.Engine, em.CorpusSHA256, corpusSHA)
		}
		key := em.Impl + "/" + em.Engine
		if seenImpl[key] {
			return nil, fmt.Errorf("two emissions declare the same impl/engine %q", key)
		}
		seenImpl[key] = true
	}

	verdicts := make([]vectorVerdict, 0, len(c.Vectors))
	for _, v := range c.Vectors {
		verdicts = append(verdicts, blessOne(v, ems))
	}
	return verdicts, nil
}

func blessOne(v Vector, ems []*Emission) vectorVerdict {
	vv := vectorVerdict{id: v.ID, groups: map[string][]string{}}

	msgsByCode := map[string]map[string][]string{}
	for _, em := range ems {
		name := em.Impl + "/" + em.Engine
		o, ok := em.Results[v.ID]
		if !ok {
			vv.kind = verdictIncomplete
			vv.groups["<no answer>"] = append(vv.groups["<no answer>"], name)
			continue
		}
		vv.groups[canonicalOutcome(o)] = append(vv.groups[canonicalOutcome(o)], name)
		if o.Kind == OutcomeError {
			if msgsByCode[o.Code] == nil {
				msgsByCode[o.Code] = map[string][]string{}
			}
			msgsByCode[o.Code][o.Message] = append(msgsByCode[o.Code][o.Message], name)
		}
	}
	if vv.kind == verdictIncomplete {
		return vv
	}

	// Advisory: same code, different prose. Not a divergence — see the header.
	for code, byMsg := range msgsByCode {
		if len(byMsg) > 1 {
			msgs := make([]string, 0, len(byMsg))
			for m, who := range byMsg {
				msgs = append(msgs, fmt.Sprintf("%s: %q", strings.Join(who, "+"), m))
			}
			sort.Strings(msgs)
			vv.msgNotes = append(vv.msgNotes,
				fmt.Sprintf("code %s agreed, messages differ — %s", code, strings.Join(msgs, "; ")))
		}
	}
	sort.Strings(vv.msgNotes)

	if len(vv.groups) == 1 {
		vv.kind = verdictAgree
		return vv
	}
	// With only two emissions, "one differs" and "all differ" are the same
	// observation and §4 cannot route it. Say so rather than pick one.
	if len(ems) == 2 {
		vv.kind = verdictTwoWay
		return vv
	}
	switch len(vv.groups) {
	case len(ems):
		// Every impl in its own group.
		vv.kind = verdictAllDiffer
		return vv
	}

	// Exactly one impl isolated against a single agreeing group.
	if len(vv.groups) == 2 {
		for _, members := range vv.groups {
			if len(members) == 1 {
				vv.kind = verdictOneDiffers
				vv.outlier = members[0]
				return vv
			}
		}
	}
	vv.kind = verdictSplit
	return vv
}

// canonicalOutcome renders an outcome as the exact string the gate compares.
// Message is excluded by construction — see the file header.
func canonicalOutcome(o Outcome) string {
	switch o.Kind {
	case OutcomeError:
		return "error/" + o.Code
	case OutcomeEntity:
		return fmt.Sprintf("entity/%x", o.Boundary)
	case OutcomeValue:
		return fmt.Sprintf("value/%x", o.Boundary)
	default:
		return "malformed/" + o.Kind
	}
}

// summarize renders the cross-bless report and reports whether the corpus locks.
func summarize(verdicts []vectorVerdict) (string, bool) {
	counts := map[verdictKind]int{}
	var sb strings.Builder
	var notes int

	for _, vv := range verdicts {
		counts[vv.kind]++
		if vv.kind == verdictAgree {
			notes += len(vv.msgNotes)
			for _, n := range vv.msgNotes {
				fmt.Fprintf(&sb, "  note  %-52s %s\n", vv.id, n)
			}
			continue
		}
		fmt.Fprintf(&sb, "  %-11s %s\n", vv.kind, vv.id)
		keys := make([]string, 0, len(vv.groups))
		for k := range vv.groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			members := vv.groups[k]
			sort.Strings(members)
			fmt.Fprintf(&sb, "                %-24s %s\n", strings.Join(members, ","), k)
		}
		switch vv.kind {
		case verdictOneDiffers:
			fmt.Fprintf(&sb, "                → §4: %s's bug (one impl differs)\n", vv.outlier)
		case verdictAllDiffer:
			fmt.Fprintf(&sb, "                → §4: spec ambiguity (all differ) — route to arch\n")
		case verdictSplit:
			fmt.Fprintf(&sb, "                → §4 does not route an even split; needs a ruling\n")
		case verdictTwoWay:
			fmt.Fprintf(&sb, "                → real divergence; §4 cannot route it with two impls "+
				"(one-differs and all-differ are the same observation) — needs a third answer\n")
		case verdictIncomplete:
			fmt.Fprintf(&sb, "                → §3.1(2): a missing answer counts as a failure\n")
		}
	}

	locked := counts[verdictAgree] == len(verdicts)
	var head strings.Builder
	fmt.Fprintf(&head, "cross-bless over %d vectors: %d agree, %d one-differs, %d all-differ, %d two-way, %d split, %d incomplete\n",
		len(verdicts), counts[verdictAgree], counts[verdictOneDiffers],
		counts[verdictAllDiffer], counts[verdictTwoWay], counts[verdictSplit], counts[verdictIncomplete])
	if notes > 0 {
		fmt.Fprintf(&head, "%d advisory message-text differences (code agreed; not a divergence)\n", notes)
	}
	if locked {
		head.WriteString("LOCKED — every vector byte-identical across all emissions\n")
	} else {
		head.WriteString("NOT LOCKED — the corpus locks only when every vector is byte-identical\n")
	}
	return head.String() + sb.String(), locked
}
