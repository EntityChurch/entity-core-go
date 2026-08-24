#!/usr/bin/env python3
"""The proposal close-out board — which ACTIVE proposals we have already built.

WHY THIS IS THE INTERESTING QUESTION. An unimplemented extension is not a
problem; it just has not been built yet. The problem is a proposal we have
implemented, validated, and gone rounds on that is STILL a proposal — because
the spec then trails the cohort, and a new implementer reads a document that
does not describe what three peers actually do. That is the class that had
`EXTENSION-NETWORK` §4.1 instructing implementers to mint a `chain_id` our own
oracle fails them for.

THREE SIGNALS, IN DESCENDING RELIABILITY. Reported separately, never merged into
one score, because they fail differently:

  CITED    an oracle check names the proposal as its spec home. Exact: the
           register resolves it. A check citing a proposal is validating
           against something no spec carries.
  NAMED    the proposal filename appears in a Go source comment. Exact, but
           silent when the code cites the SECTION instead of the file — which
           is the common case, so absence here means nothing on its own.
  CONCEPT  distinctive identifiers from the proposal appear in our tree.
           FUZZY, and deliberately marked so: `service-advertisement` misses
           because Go spells the same idea `serviceAdvertisement`. Good for
           surfacing candidates, useless as proof.

A row is only worth acting on after someone opens the file. This board says
where to look; it does not rule.
"""
import collections
import json
import os
import re
import subprocess
import sys

ARCH = os.environ.get("ARCH", "../entity-system-architecture")
REG = os.environ.get("REG")
TREES = ["core", "ext", "cmd"]

# Tokens too generic to mean anything — every proposal mentions `priority` and
# `registry`. Without this the CONCEPT column matches everything and is worse
# than not running.
STOP = {
    "priority", "registry", "policy", "resolve", "services", "signaling",
    "operation", "request", "response", "handler", "capability", "entity",
    "content", "compute", "network", "identity", "subscription", "continuation",
    "revision", "history", "attestation", "discovery", "encryption", "quorum",
    "inbox", "relay", "clock", "query", "role", "type", "tree", "peer", "true",
    "false", "null", "string", "number", "boolean", "object", "array",
}


# A proposal that says "see `core/crypto`" or "`cmd/entity-peer`" is CITING OUR
# TREE, not describing a concept — and those paths trivially exist, so matching
# on them scored a proposal as built purely for mentioning us. This produced the
# worst false positives in the first cut: APP-CONVENTION-CHAT (browser-rust's,
# no Go implementation) matched on `applications/`, and NAMESPACE-CLEANUP
# matched on `core/crypto` + `core/types/` + `cmd/entity-peer`.
PATH_LIKE = re.compile(
    r"^(core|ext|cmd|docs|scripts|src|packages|extensions|applications)/"
    r"|entity-(core|browser|workbench|system|lab)"
    r"|\.(md|go|rs|py|sh|json|toml)$"
)


def tokens(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    out = set()
    for t in re.findall(r"`([a-z][a-z0-9/_.-]{6,})`", text):
        if t in STOP or PATH_LIKE.search(t):
            continue
        # A token earns its place by being compound — a bare English word is
        # noise, `endpoint_bytes` and `system/peer/inbox-relay` are not.
        if "_" in t or "/" in t or "-" in t:
            out.add(t)
    return out


# A token is only evidence FOR A PARTICULAR PROPOSAL if it is rare across the
# corpus. `chain_id`, `deliver_to` and `content-hash` are shared vocabulary —
# they appear in a dozen proposals and in every tree, so matching on them made
# 16 of 22 rows read "likely built", including APP-CONVENTION-CHAT, which is
# browser-rust's and has no Go implementation at all. Document frequency is the
# fix: keep only tokens that fewer than MAX_DF proposals use.
MAX_DF = 3


def distinctive_sets(pdir, active):
    raw = {p: tokens(os.path.join(pdir, p + ".md")) for p in active}
    df = collections.Counter()
    for toks in raw.values():
        for t in toks:
            df[t] += 1
    return {p: {t for t in toks if df[t] < MAX_DF} for p, toks in raw.items()}


def landed_corpus():
    """Every landed normative spec, concatenated.

    THIS IS THE COLUMN THAT ACTUALLY DECIDES A ROW, and without it the board is
    worse than useless — it reports the OPPOSITE of the truth for every proposal
    that was folded successfully.

    The reason: a folded proposal's vocabulary is, by definition, now IN the
    spec. So "we implement this proposal's concepts" is equally true of a
    proposal that was folded years ago and one that was never folded at all.
    Concept hits alone cannot separate them. `identity-rotation-handoff` is in
    our tree AND appears 23 times in EXTENSION-IDENTITY.md — the fold already
    happened, and the first cut of this tool called it "fold owed".

    So the test is: a concept that is in our tree and in NO landed spec is
    unfolded. A concept in both is done.
    """
    text = []
    for root in (os.path.join(ARCH, "specs"),
                 os.path.join(os.environ.get("PROTO", "../entity-core-protocol"), "specs")):
        for dirpath, _, names in os.walk(root):
            if "test-vectors" in dirpath:
                continue
            for n in names:
                if n.endswith(".md"):
                    try:
                        text.append(open(os.path.join(dirpath, n),
                                         encoding="utf-8", errors="replace").read())
                    except Exception:
                        pass
    return "\n".join(text)


def grep_count(tok):
    try:
        r = subprocess.run(["grep", "-rl", "--include=*.go", tok] + TREES,
                           capture_output=True, text=True, timeout=60)
        return len([x for x in r.stdout.splitlines() if x.strip()])
    except Exception:
        return 0


def main():
    pdir = os.path.join(ARCH, "docs/proposals")
    active = sorted(x[:-3] for x in os.listdir(pdir)
                    if x.startswith("PROPOSAL-") and x.endswith(".md"))

    cited = collections.Counter()
    if REG and os.path.exists(REG):
        reg = json.load(open(REG))
        for r in reg["rows"]:
            for c in r.get("citations") or []:
                dp = c.get("doc_path") or ""
                if "/proposals/" in dp and c.get("status") == "ok":
                    cited[os.path.basename(dp)[:-3]] += 1

    print()
    print("PROPOSAL CLOSE-OUT BOARD — active proposals we have already built")
    print()
    print(f"{'PROPOSAL':<46}{'cited':>6}{'named':>6}{'con':>5}{'unfolded':>9}  verdict")
    print("-" * 100)

    landed = landed_corpus()
    distinct = distinctive_sets(pdir, active)
    buckets = collections.defaultdict(list)
    for p in active:
        toks = distinct[p]
        named = grep_count(p)
        hits = [t for t in sorted(toks) if grep_count(t)]
        # Split the hits: in our tree AND in a landed spec = the fold happened.
        # In our tree and in NO landed spec = built here, unfolded there.
        unfolded = [t for t in hits if t not in landed]
        n_concept = len(hits)

        if cited[p] or named:
            verdict, key = "BUILT — fold owed", "fold"
        # ANY unfolded token counts. The threshold was >=2 and that was wrong:
        # REGISTRY-SERVICE-ADVERTISEMENT has exactly one (`endpoint_bytes`, in
        # ext/signaling/pool.go, zero hits across every landed spec) and it is
        # decisive — arch independently confirmed the row as C-3 and has since
        # ruled RATIFY on it. A threshold that buries a row a second party
        # already confirmed is tuned wrong, not conservative.
        elif unfolded:
            verdict, key = "built, concepts unfolded", "likely"
        elif hits:
            verdict, key = "built — concepts already in a landed spec", "folded"
        else:
            verdict, key = "no signal", "none"
        buckets[key].append((p, unfolded or hits))
        print(f"{p:<46}{cited[p]:>6}{named:>6}{n_concept:>5}{len(unfolded):>9}  {verdict}")

    print()
    print("cited  = oracle checks naming this proposal as their spec home (exact)")
    print("named  = Go files naming the proposal file (exact; silent when code cites the section)")
    print("concept= distinctive identifiers found in our tree (FUZZY — candidates, not proof)")
    print()

    if buckets["folded"]:
        print("ALREADY FOLDED (%d) — built here, and the concepts ARE in a landed spec:"
              % len(buckets["folded"]))
        for p, _ in buckets["folded"]:
            print(f"    {p}")
        print()
    if buckets["fold"]:
        print("FOLD OWED (%d) — built here, still a proposal there:" % len(buckets["fold"]))
        for p, hits in buckets["fold"]:
            print(f"    {p}")
            if hits:
                print(f"        evidence: {', '.join(hits[:6])}")
    if buckets["likely"]:
        print()
        print("BUILT, CONCEPTS UNFOLDED (%d) — in our tree, in NO landed spec:"
              % len(buckets["likely"]))
        for p, hits in buckets["likely"]:
            print(f"    {p}")
            print(f"        evidence: {', '.join(hits[:6])}")
    if buckets["none"]:
        print()
        print("NO SIGNAL (%d) — not built here, or built under names this cannot see:"
              % len(buckets["none"]))
        for p, _ in buckets["none"]:
            print(f"    {p}")

    print()
    print("A 'no signal' row is NOT evidence of absence — it is the absence of")
    print("evidence, and the CONCEPT column is fuzzy enough that both directions")
    print("are cheap to get wrong. Open the file before reporting either way.")


if __name__ == "__main__":
    if not os.path.isdir(os.path.join(ARCH, "docs/proposals")):
        sys.exit("arch proposals not found at %s" % ARCH)
    main()
