#!/usr/bin/env bash
# Validate a peer with EVERY surface turned on.
#
# WHY THIS EXISTS
#
# The plain `validate-peer -addr <a>` invocation does not exercise the whole
# suite. Several categories are gated on the peer being STARTED with a surface
# enabled and the validator being PASSED the matching flag, and when either is
# missing those checks skip. A default run exercises ~1429 checks; this one
# scores 1538 in pass 1 plus 53 in pass 2. The difference is not noise — it is:
#
#   - the LOCAL-FILES read/write/list/delete round-trip and frame-budget chunking
#   - the published-root / manifest / HTTP-poll serving face
#   - origination (the peer DISPATCHING, not just answering)
#   - §7a concurrent-reentry attestation
#   - the §5.4 keepalive-escalation and §4.1 reconnect/retry vectors
#
# Those checks are not decorative: the first fully-configured run of this script
# surfaced failures in the registry and published-root vectors that no default
# run had ever executed. A suite that silently omits them does not report a
# smaller number — it reports a different claim.
#
# THIS PROJECT IMPLEMENTS EVERYTHING. An unimplemented surface is an untested
# surface, so the target here is zero skips and zero failures. Do not close a
# gap with -allow-skip; close it by configuring the surface or building it.
#
# Usage:
#   ./scripts/validate-complete.sh                 # start a Go peer, validate it
#   ./scripts/validate-complete.sh rust            # ditto against a rust peer
#   ./scripts/validate-complete.sh python
#
# Env:
#   KEEP=1     leave the peers running afterwards (default: stop them)
#   EXTRA=...  extra flags appended to validate-peer

set -euo pipefail
cd "$(dirname "$0")/.."

TYPE="${1:-go}"
STAMP="c$$"
TARGET="vc-${STAMP}"
REF="vcref-${STAMP}"
FILES_DIR="$(mktemp -d)"
POLL_PORT="${POLL_PORT:-9451}"
PI_DIR="$(mktemp -d)"
PI_PORT="${PI_PORT:-9401}"

cleanup() {
    if [ "${KEEP:-0}" != "1" ]; then
        go run ./cmd/peer-manager stop "$TARGET" >/dev/null 2>&1 || true
        go run ./cmd/peer-manager stop "$REF"    >/dev/null 2>&1 || true
    fi
    rm -rf "$FILES_DIR" "$PI_DIR"
}
trap cleanup EXIT

# A real file so the LOCAL-FILES round-trip has something to read, and a
# writable root so write/delete and the frame-budget chunking check can run.
mkdir -p "$FILES_DIR/docs"
printf 'entity-core-go validate-complete fixture\n' > "$FILES_DIR/docs/fixture.txt"

# The peer-issued fixture registry (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §6).
#
# The target must be started with the registry ALREADY PINNED, before the
# validator stands the fixture server up — which works only because the
# registry's peer-id is a deterministic constant of the generator's fixed
# seed. Read it out of the bundle rather than hard-coding it, so a
# regenerated bundle can never silently drift from the pin.
#
# `-wire` (not the default cohort bundle) is required: the cohort bundle puts
# all six vectors on ONE name as the cross-impl NFC/byte-equality pin, and
# against a single long-lived peer the backend's cacheOnResolve then makes
# each vector resolve the previous vector's leftovers. The validator refuses a
# cohort bundle rather than reporting six green checks that measured nothing.
# Armed where `--peer-issued-registry` exists — now all three. Python landed
# the pin on 2026-08-08 (trust root + §4 chain entry, both halves); Rust's live
# remote-read seam landed at 5c58195 (RegistryTreeReader + HttpPollRegistryReader),
# so its pin reaches the wire rather than resolving against the local store.
#
# Until that seam existed the category SKIPped against rust deliberately:
# pinning a peer whose remote-read surface is genuinely absent reports six MUST
# failures against something that is not there — a false cross-impl finding of
# exactly the kind this repo has withdrawn before. The gate closed on UNBUILT,
# not on impl identity, so building the surface is what opens it.
PI_ARGS_PEER=()
PI_ARGS_VALIDATE=()
if [ "$TYPE" = "go" ] || [ "$TYPE" = "python" ] || [ "$TYPE" = "rust" ]; then
    echo "==> peer-issued fixture registry bundle"
    go run ./cmd/peerissued-fixtures -wire -out "$PI_DIR" >/dev/null
    PI_PID=$(cat "$PI_DIR/registry/peer_id.txt")
    echo "    registry $PI_PID → http://127.0.0.1:${PI_PORT}"
    PI_ARGS_PEER=(--peer-issued-registry "${PI_PID}@http://127.0.0.1:${PI_PORT}")
    PI_ARGS_VALIDATE=(-peer-issued-bundle "$PI_DIR" -peer-issued-addr "127.0.0.1:${PI_PORT}")
else
    echo "==> peer-issued fixture registry: SKIPPED for $TYPE"
    echo "    --peer-issued-registry is unavailable for $TYPE; the six"
    echo "    REG-PEERISSUED-* vectors will skip rather than fail an unbuilt surface."
fi

echo "==> reference peer (origination / A-role target)"
REF_ADDR=$(go run ./cmd/peer-manager start --name "$REF" --type go --debug \
    | sed -n 's/.*addr=\([^ ]*\).*/\1/p')
echo "    $REF_ADDR"

# Every surface the suite knows how to gate on:
#   --signaling-node   §4/§5 rendezvous node (the punch carrier)
#   --validate         §7a echo + dispatch-outbound scaffold (concurrent reentry)
#   --publish-root     signed system/peer/published-root on every root change
#   --http-poll-addr   exposes the manifest + content on the wire
#   --serve-closure-root
#                      the content scope, and the ONLY one of the three that is
#                      correct alongside --publish-root. Getting here took two
#                      wrong tries, both of which the suite caught:
#                        --serve-namespace  → v5_outbound_dial and
#                          v7_trie_closure_content_get 404 on the signature
#                          pointer and the root hash. §6.5.6 Amendment 10 makes
#                          the CLOSURE of the signed root the serving floor once
#                          signed_pointer is advertised; trie nodes are
#                          hash-linked, not path-bound (V7 §1.7), so a namespace
#                          scope cannot serve a CHAMP interior node.
#                        --serve-scope-whole-store → the four T4 checks fail,
#                          because if everything is in scope then nothing is
#                          out of scope and "out-of-scope MUST 404" is
#                          unsatisfiable. It is also a DEBUG opt-in that logs a
#                          startup warning.
#                      Closure scope satisfies both: the signed root's closure is
#                      served, everything else 404s.
#   --files            a writable LOCAL-FILES root
#   --publish-descriptors
#                      arms DOMAIN-LOCAL-FILES §10.5 V3 (file reads write
#                      system/content/descriptor/{hash} into the tree). Without
#                      it v3_descriptor_publish_exercised WARNs "not exercised"
#                      — a behavioral check quietly not running, which is the
#                      exact class this script exists to eliminate.
#   --keepalive        a short §2.3 envelope so §5.4 escalation is observable
echo "==> target peer ($TYPE) with every surface enabled"
TARGET_ADDR=$(go run ./cmd/peer-manager start --name "$TARGET" --type "$TYPE" --debug \
    --signaling-node --validate --publish-root \
    --http-poll-addr "127.0.0.1:${POLL_PORT}" \
    --serve-closure-root \
    --files "docs:${FILES_DIR}/docs:local/files/docs/" \
    --publish-descriptors \
    "${PI_ARGS_PEER[@]}" \
    --keepalive 2000,1000,2 \
    | sed -n 's/.*addr=\([^ ]*\).*/\1/p')
echo "    $TARGET_ADDR"

# Exclude the FOUR T4 checks that are genuinely unsatisfiable under closure
# scope — NOT the whole serving_mode category.
#
# This was `-exclude serving_mode` until 2026-08-07, and that was a coverage
# hole, not a simplification. serving_mode still RUNS under the exclude; the
# flag only drops it from SCORING. So excluding the category silently stopped
# scoring 49 checks that are perfectly meaningful under closure scope, and the
# first cross-impl run after the fix found what that hid: a peer 404ing EVERY
# in-scope serve under closure scope (26 F) while the run still reported 0 F.
# Everything 404ing also makes the out-of-scope T4 checks pass vacuously, so
# the category-wide exclude turned a total serving failure into a clean sheet.
#
# Only these four are unsatisfiable here, and only because --publish-root makes
# the signed root's closure cover the whole store: if everything is in scope,
# nothing is out of scope, so "out-of-scope MUST 404" has nothing to probe.
# Pass 2 scores them against a namespace-scoped peer where they mean something.
T4_UNSATISFIABLE="serving_mode.content_get_out_of_scope_404,serving_mode.content_get_t4_oracle_identity,serving_mode.tree_entity_out_of_scope_404,serving_mode.tree_entity_t4_oracle_identity"

echo "==> PASS 1/2 — every surface, closure-of-signed-root scope"
set +e
go run ./cmd/validate-peer \
    -addr "$TARGET_ADDR" \
    -reference-peer "$REF_ADDR" \
    -poll-url "http://127.0.0.1:${POLL_PORT}" \
    "${PI_ARGS_VALIDATE[@]}" \
    -keepalive-envelope-ms 6000 \
    -exclude "$T4_UNSATISFIABLE" \
    ${EXTRA:-}
RC1=$?
set -e

# PASS 2 — serving_mode ONLY, against a namespace-scoped peer.
#
# serving_mode's Amendment 5 §6.5.6 T4 checks require something to be OUT of
# scope ("out-of-scope MUST 404, byte-identical to unbound"). That is
# unsatisfiable under the closure scope pass 1 needs: --publish-root publishes
# the whole tree, so its transitive closure covers essentially the whole store
# and a genuinely out-of-scope hash does not exist to probe. Under whole-store
# it is unsatisfiable by definition.
#
# So the two requirements cannot both hold in ONE peer configuration, and a
# single-configuration run cannot reach zero — it can only choose which four
# checks to fail. Rather than pick, run serving_mode against a second peer
# scoped by namespace, where T4 is meaningful. Every check then runs in the
# configuration where it means something, and the union is real coverage.
#
# (This is a property of the spec surfaces, not a Go defect: §6.5.6 Amendment 10
# makes closure the floor when signed_pointer is advertised, and T4 governs the
# namespace-scoped posture. A peer picks one posture; the suite must cover both.)
echo
echo "==> PASS 2/2 — serving_mode against a namespace-scoped peer (T4 needs an out-of-scope hash)"
NS_TARGET="vcns-${STAMP}"
NS_PORT=$((POLL_PORT + 1))
NS_ADDR=$(go run ./cmd/peer-manager start --name "$NS_TARGET" --type "$TYPE" --debug \
    --http-poll-addr "127.0.0.1:${NS_PORT}" \
    --serve-namespace system/content/public \
    | sed -n 's/.*addr=\([^ ]*\).*/\1/p')
set +e
go run ./cmd/validate-peer \
    -addr "$NS_ADDR" \
    -poll-url "http://127.0.0.1:${NS_PORT}" \
    -category serving_mode
RC2=$?
set -e
if [ "${KEEP:-0}" != "1" ]; then
    go run ./cmd/peer-manager stop "$NS_TARGET" >/dev/null 2>&1 || true
fi

echo
echo "PASS 1 exit $RC1 (all surfaces, closure scope) · PASS 2 exit $RC2 (serving_mode, namespace scope)"
echo "Zero failures AND zero skips in BOTH is the bar — read each COVERAGE block for"
echo "anything that did not run, and close it rather than allowlisting it."
[ "$RC1" -eq 0 ] && [ "$RC2" -eq 0 ] || exit 1
exit 0
