#!/usr/bin/env python3
"""Join the static register against live per-impl runs. See impl-inventory.sh."""
import collections
import json
import os
import sys

REG = os.environ.get("REG")
IMPLDIR = os.environ.get("IMPLDIR")
ARCH = os.environ.get("ARCH", "../entity-system-architecture")
IMPLS = ["go", "rust", "python"]

# Where each impl keeps its extension surfaces. Names differ across impls
# (localfiles / local-files / storage), so presence is matched loosely and
# reported as a HINT — never as the answer. See the header of impl-inventory.sh.
# Several surfaces are NOT under the extension dir — go's tree/capability live
# in core/, rust splits crates across core/ and extensions/. Searching only the
# extension dir reported EXTENSION-TREE as unbuilt in go, which is false and is
# exactly the failure mode this column is warned about.
IMPL_DIRS = {
    "go": ["ext", "core"],
    "rust": ["../entity-core-rust/extensions", "../entity-core-rust/core"],
    "python": ["../entity-core-py/packages/entity-handlers/src/entity_handlers",
               "../entity-core-py/packages/entity-core/src/entity_core"],
}


def norm(s):
    return s.lower().replace("-", "").replace("_", "")


def main():
    reg = json.load(open(REG))

    spec_cats = collections.defaultdict(set)
    spec_checks = collections.defaultdict(set)
    cat_unres = collections.Counter()
    for r in reg["rows"]:
        cat = r["category"]
        if cat and r["verdict"] in ("UNRESOLVED", "NO_CITATION"):
            cat_unres[cat] += 1
        for c in r.get("citations") or []:
            if c.get("status") == "ok" and c.get("doc_path"):
                k = os.path.basename(c["doc_path"])[:-3]
                spec_checks[k].add(cat + "." + r["check"])
                if cat:
                    spec_cats[k].add(cat)

    runtime = {}
    for t in IMPLS:
        m = collections.defaultdict(lambda: [0, 0, 0])
        try:
            d = json.load(open(os.path.join(IMPLDIR, "impl-%s.json" % t)))
        except Exception:
            d = {"checks": []}
        for c in d.get("checks", []):
            i = {"pass": 0, "passed": 0, "fail": 1, "failed": 1,
                 "skip": 2, "skipped": 2}.get((c.get("severity") or "").lower())
            if i is not None:
                m[c.get("category", "")][i] += 1
        runtime[t] = m

    present = {}
    for t, dirs in IMPL_DIRS.items():
        names = []
        for d in dirs:
            try:
                names += [norm(x) for x in os.listdir(d)]
            except Exception:
                pass
        present[t] = names

    specdir = os.path.join(ARCH, "specs/extensions")
    specs = sorted(x[:-3] for x in os.listdir(specdir) if x.endswith(".md"))

    print()
    print("IMPLEMENTATION INVENTORY — built / validated / cited are three questions")
    print()
    print(f"{'EXTENSION SPEC':<26}{'built':>7}{'chk':>5}   "
          f"{'go P/F/S':>11}{'rust P/F/S':>12}{'py P/F/S':>12}")
    print("-" * 80)

    unbuilt, unvalidated = [], []
    for s in specs:
        stem = norm(s.replace("EXTENSION-", ""))
        built = [t for t in IMPLS if any(stem in p or p in stem for p in present[t] if p)]
        cats = spec_cats.get(s, set())
        n = len(spec_checks.get(s, ()))
        cells = []
        for t in IMPLS:
            p = f = k = 0
            for c in cats:
                a = runtime[t].get(c, [0, 0, 0])
                p, f, k = p + a[0], f + a[1], k + a[2]
            cells.append(f"{p}/{f}/{k}")
        mark = "".join(t[0] if t in built else "-" for t in IMPLS)
        print(f"{s:<26}{mark:>7}{n:>5}   "
              f"{cells[0]:>11}{cells[1]:>12}{cells[2]:>12}")
        if not built:
            unbuilt.append(s)
        elif n == 0:
            unvalidated.append(s)

    print()
    print("built column: g/r/p present, '-' absent. A HINT from directory names,")
    print("which differ across impls — never read it as the answer on its own.")
    print()
    if unbuilt:
        print("SPEC'D BUT UNBUILT IN ALL THREE (%d):" % len(unbuilt))
        for s in unbuilt:
            print("   ", s)
    if unvalidated:
        print()
        print("BUILT BUT ZERO ORACLE CHECKS (%d) — the dangerous column:" % len(unvalidated))
        for s in unvalidated:
            print("   ", s, " — shipping, and nothing measures it")

    print()
    print("WORST CITATION HYGIENE (checks whose citation does not resolve):")
    for cat, n in cat_unres.most_common(8):
        print(f"    {cat:<32}{n:>4}")

    print()
    print("CAVEATS — read before quoting any number above:")
    print("  * SINGLE-PEER run. Multi-peer categories (signaling, convergence,")
    print("    relay multi-peer, cross-peer subscription) score 0/0/0 here and that")
    print("    is a surface this harness did not configure, NOT a gap.")
    print("  * Arming differs across impls. go gates registry handler registration")
    print("    on --issuer-policy-mode; rust and py register unconditionally. A bare")
    print("    run therefore shows go failing checks it passes when armed.")
    print("  * A category spans several specs, so the per-spec runtime cells and the")
    print("    uncited counts attribute the same check to every spec it touches.")
    print("    Read them as 'the neighbourhood is healthy', not as an exact per-spec")
    print("    score.")


if __name__ == "__main__":
    if not REG or not IMPLDIR:
        sys.exit("REG and IMPLDIR must be set — run via scripts/impl-inventory.sh")
    main()
