#!/usr/bin/env bash
# What is implemented, what is validated, and what is neither.
#
# WHY THIS EXISTS. Three separate questions kept getting answered as one, and
# every wrong answer this cycle came from conflating them:
#
#   BUILT      an implementation package exists          (ls ext/ — weak, see below)
#   VALIDATED  oracle checks exercise it against a peer  (validate-peer)
#   CITED      those checks name a spec section that resolves (conformance-register)
#
# A spec can be built and unvalidated (EXTENSION-SUBSTITUTE), validated and
# uncited (`signaling`: 6 checks, all citing "brief §5.1/§7" — no document), or
# spec'd and unbuilt (GROUP, TRANSACTION). "Is X implemented?" has no single
# answer, and a table with one column per spec is how you get a confident wrong
# one.
#
# DIRECTORY LISTINGS ARE NOT THE STATE. `ls ext/` reports go's `localfiles`,
# rust's `local-files` and py's `storage` as three different things; arch spent
# three handoffs reporting peer state as "unknown" off a directory model. The
# authoritative signal is the oracle: what runs, and what it scores.
#
# READ THE CAVEATS THE REPORT PRINTS. In particular this runs SINGLE-PEER, so
# every multi-peer category (signaling, convergence, relay multi-peer,
# cross-peer subscription) scores 0/0/0 here and that is not a gap — it is a
# surface this harness did not configure. Use scripts/validate-complete.sh and
# scripts/test-cross-peer.sh for those.
#
# Usage:
#   ./scripts/impl-inventory.sh            # start peers, measure, report
#   REUSE=1 ./scripts/impl-inventory.sh    # reuse managed peers named go/rust/python

set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${OUT:-$(mktemp -d)}"
echo "workdir: $OUT"

if [ -z "${REUSE:-}" ]; then
    for t in go rust python; do
        go run ./cmd/peer-manager start --name "$t" --type "$t" \
            --validate --keepalive 1000,500,2 --debug >/dev/null 2>&1 || true
    done
fi

echo "==> register (static: what the oracle claims, and whether it resolves)"
go run ./cmd/conformance-register -json > "$OUT/register.json" 2>/dev/null

echo "==> peers (runtime: what each impl actually answers)"
for t in go rust python; do
    addr=$(go run ./cmd/peer-manager list 2>/dev/null | awk -v n="$t" '$1==n{print $4}')
    if [ -z "$addr" ]; then
        echo "    $t: NOT RUNNING — its column will read as absent, which is not the same as failing"
        echo '{"checks":[],"summary":{}}' > "$OUT/impl-$t.json"
        continue
    fi
    echo "    $t @ $addr"
    go run ./cmd/validate-peer -addr "$addr" -keepalive-envelope-ms 2000 -json \
        > "$OUT/impl-$t.json" 2>/dev/null || true
done

REG="$OUT/register.json" IMPLDIR="$OUT" python3 scripts/impl_inventory.py
