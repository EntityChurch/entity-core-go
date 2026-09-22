#!/usr/bin/env bash
# Validate a peer with EVERY surface turned on.
#
# WHY THIS EXISTS
#
# The plain `validate-peer -addr <a>` invocation does not exercise the whole
# suite. Several categories are gated on the peer being STARTED with a surface
# enabled and the validator being PASSED the matching flag, and when either is
# missing those checks skip. A default run against a bare peer scores 1458 with
# 10 F and 26 S; this one scores 1566 · 0F · 0S in pass 1, plus 55 in pass 2 and
# 12 in pass 3 (go, measured at the commit that added this line, under BOTH
# content_hash_formats). The difference is not noise — it is:
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
#   HASH_TYPE=sha384
#              run the whole thing on a SHA-384 home content_hash_format
#              (V7 §1.2). Sets --hash-type on EVERY peer and -hash-format on
#              the validator, because §1.2a makes a single-format network the
#              supported deployment and a mix of homes the experimental
#              two-address-space mode — starting one peer SHA-384 and leaving
#              the rest SHA-256 would be testing the non-v1 case by accident.
#
#              Worth running, not decorative: `--hash-type sha384` shipped in
#              all three implementations long before anything ever set it, and
#              the first run under it found ComputePubkeyHash authoring pubkey
#              hashes under SHA-256 on a SHA-384 peer. Everything a default run
#              exercises, it exercises under exactly one format.
#
#              AGAINST A GO PEER THIS IS A GATE, NOT A DIAGNOSTIC. Arch ruled
#              both blocking gaps on 2026-08-10 (NETWORK §6.5.3.1 the hex length
#              follows its own format byte and is never assumed; SIGNALING §6.3
#              drops the fixed-33 on inner_content_hash) and set the promotion
#              condition explicitly: sha384 becomes a gate once the impl lands
#              the ruling and the validator's own SHA-256 assumptions land with
#              it. Go did both at e166971. Run it; treat a failure as a failure.
#
#              AND FOR TWO DAYS NOBODY DID. Promoted to a gate 2026-08-10, first
#              measured 2026-08-12 (e): it was **1 F**, and had been the whole
#              time — published_root.v5_outbound_dial, `signer
#              ecf-sha256:ef55… ≠ pinned identity ecfv1-sha384:f2ed…`, the
#              validator deriving the publisher's identity under its own home
#              format while the publisher authored it at the §4.5a item 1a
#              floor. Two more of the same defect were invisible until
#              core/entity started refusing the construction. All three fixed;
#              this run is now 1571 · 0F · 0S · 0W / 633 / 55 / 19, exit 0 on
#              all four passes.
#
#              THE LESSON IS NOT THE BUG. A gate whose number no tracker carries
#              is indistinguishable from one nobody runs — the same class as a
#              conformance profile nothing invokes (G-2/G-2a). docs/status/
#              WORK-STATUS.md §1 now has a row for this run, and it is not
#              redundant with the SHA-256 row: every check exercises exactly one
#              format, so a home-format defect is reachable ONLY here.
#
#              This block previously read "IT DOES NOT PASS TODAY, AND THAT IS
#              THE FINDING — 27 F + 1 S in pass 1, 13 F in pass 2 at 502ac9c."
#              Every word of that was true when written and false four commits
#              later. It is left named rather than quietly deleted because a
#              measurement pinned to a commit that has since moved is the
#              stale-build-state defect this repo keeps catching in OTHER
#              people's text (AGENTS.md, "Verify build state before you assert
#              it"), and it is worth one recorded instance of catching it in
#              our own.
#
#              STILL A DIAGNOSTIC AGAINST `rust` / `python`, and the reason is
#              a build-state fact with a pin, not an assumption: at
#              entity-core-rust b8e0ae2 the poll route is still
#              `content/{hex33}` (core/peer/src/http_live.rs) and
#              bindings/ffi/src/hash.rs still rejects `hex.len() != 66`, so a
#              SHA-384 run against a rust peer measures the pre-ruling gate.
#              Re-read that tree before trusting this sentence — it decays the
#              moment rust commits.

set -euo pipefail
cd "$(dirname "$0")/.."

# Impl is the POSITIONAL arg, never $TYPE. The env-var form reads natural
# (`TYPE=rust ./validate-complete.sh`) and is the exact footgun that shipped a
# perfect go score labelled as rust this cycle: $TYPE gets overwritten by
# ${1:-go} below, so the run silently measures go. Refuse it loudly rather than
# print a plausible wrong number.
_ENV_TYPE="${TYPE:-}"
TYPE="${1:-go}"
if [ -n "$_ENV_TYPE" ] && [ "$_ENV_TYPE" != "$TYPE" ]; then
    echo "REFUSING TO RUN: impl is the POSITIONAL arg, not \$TYPE." >&2
    echo "  You exported TYPE=$_ENV_TYPE, but this script reads \$1 (='$TYPE')." >&2
    echo "  As written it would measure '$TYPE' and print it as a '$_ENV_TYPE' score." >&2
    echo "  Run:  ./scripts/validate-complete.sh $_ENV_TYPE" >&2
    exit 2
fi
STAMP="c$$"
TARGET="vc-${STAMP}"
REF="vcref-${STAMP}"
FILES_DIR="$(mktemp -d)"
POLL_PORT="${POLL_PORT:-9451}"
PI_DIR="$(mktemp -d)"
PI_PORT="${PI_PORT:-9401}"

# Home content_hash_format for every peer, and the matching validator
# advertisement. Empty (the default) leaves both alone so the SHA-256 path is
# byte-for-byte what it always was.
HASH_ARGS_PEER=()
HASH_ARGS_VALIDATE=()
if [ -n "${HASH_TYPE:-}" ]; then
    HASH_ARGS_PEER=(--hash-type "$HASH_TYPE")
    HASH_ARGS_VALIDATE=(-hash-format "$HASH_TYPE")
fi

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

# PASS 0 — the conformance corpora, before any peer starts.
#
# A-3, closed 2026-08-12. This is a STATIC artifact check: it decodes the
# corpus, re-derives every crypto vector, and asserts the file sha. It needs no
# peer, so it runs first and fails fast — a bad corpus invalidates every
# cross-impl claim made against it, and finding that out after four peer passes
# is four passes too late.
#
# It is wired here rather than left as a manual command because that is the
# defect that produced A-3 in the first place: the corpus was generated once by
# a script that was never committed, drifted from its source for two months, and
# nothing noticed — because nothing ran. A verifier nobody invokes is the same
# class as the SHA-384 gate nobody read (G-9) and the core profile nothing ran
# (G-2). If it is not in the gate, it is not a check.
#
# TWO ASSERTIONS, AND THEY ARE DIFFERENT. Running only the first is what let the
# corpus drift:
#   artifact-is-expected     — the committed .cbor matches its pinned sha256.
#   source-produces-artifact — re-encoding the committed .diag reproduces it.
# The F16 correction landed in the .cbor and never in the .diag; both files
# stayed internally plausible and the corpus verified 52/0 against itself for
# two months. Only the second assertion can see that.
#
# Both now live in ONE contract (`cmd/internal/corpus`) applied to EVERY
# registered corpus, rather than in one corpus's builder. See CONFORMANCE-
# STANDARD.md §2.
echo "==> PASS 0 — the conformance corpora (static; no peer)"
RC0=0
# Guard on the spec repo's test-vectors dir, NOT a single corpus subdir. The
# crypto-agility corpus was de-versioned (v767/ deleted at core-protocol
# b4ea610, ROUTING-2026-08-22-a); guarding on the parent covers both registered
# corpora and cannot go silently stale when one corpus's dir name changes again.
if [ -d "../entity-core-protocol/specs/test-vectors" ]; then
    set +e
    # ONE CONTRACT, EVERY CORPUS. `corpus-check` holds each registered corpus to
    # the same three assertions — artifact-is-expected (pinned sha),
    # source-produces-artifact (re-encode), and copies-agree. Registry:
    # cmd/internal/corpus.
    #
    # This replaced a per-corpus process. crypto-agility had both gates while
    # ecf-conformance — 71 vectors against 13, and the more widely vendored —
    # had NEITHER: its only test read the .cbor and never the .diag, so the
    # exact drift that hid for two months on the first corpus was structurally
    # undetectable on the second. Adding a corpus is now a registry entry, not
    # a third process.
    go run ./cmd/corpus-check
    RC0=$?
    if [ "$RC0" -eq 0 ]; then
        echo "    crypto-agility depth (re-derives every crypto vector):"
        # Layered ON TOP of the contract, not instead of it: this one decodes
        # the agility corpus and re-derives all 13 vectors' hashes, signatures
        # and key material. Corpus-specific by nature — the contract is the
        # floor every corpus meets, this is the depth one corpus has.
        go run ./cmd/agility-corpus-verify
        RC0=$?
    fi
    set -e
else
    echo "    SKIPPED — ../entity-core-protocol is not present."
    echo "    This is the spec repo's artifact; without it there is nothing to verify."
    echo "    Clone the sibling to run this pass. Not an allowlisted skip: it is an"
    echo "    absent input, and it is reported rather than silently passed."
fi
echo

# PASS 0b — the conformance register, also static, also before any peer.
#
# The corpus checks assert that the VECTORS are what they claim. This asserts
# that the CHECKS are: every check declares a spec citation, and this resolves
# each one against the live spec trees. A citation to a section that does not
# exist is a check whose grounds cannot be read — the oracle still runs it, the
# peer still passes or fails it, and nobody can say against what.
#
# It is a RATCHET, not a pass/fail on the whole register: a large minority of
# citations do not resolve today (proposals, guides, sections with no document
# named), and those are pinned in the committed baseline. What fails the gate is
# a NEW one — a citation that stops resolving because the spec moved under it,
# which is precisely the drift no amount of review catches.
#
# Runs against the sibling spec trees, read-only. Skipped, loudly, without them.
echo "==> PASS 0b — conformance register (static; no peer)"
RC0B=0
if [ -d "../entity-core-protocol/specs" ] && [ -d "../entity-system-architecture/specs" ]; then
    set +e
    go run ./cmd/conformance-register -check
    RC0B=$?
    set -e
else
    echo "    SKIPPED — a sibling spec tree is not present."
    echo "    The register resolves citations against ../entity-core-protocol and"
    echo "    ../entity-system-architecture. Without them every citation would read as"
    echo "    unresolved, which is a missing checkout reported as a thousand findings."
fi
echo

echo "==> reference peer (origination / A-role target)"
REF_ADDR=$(go run ./cmd/peer-manager start --name "$REF" --type go --debug \
    "${HASH_ARGS_PEER[@]}" \
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

# FAIL CLOSED on the http-poll listener's config BEFORE the peer starts. If
# POLL_PORT (target, pass 1) or POLL_PORT+1 (NS_PORT, pass 2's serving target)
# is already bound — a leftover peer, a sibling squatting it, the same
# cross-session collision class as PI_PORT 9401 — entity-peer logs
# "WARNING: http-poll listener: … address already in use" and CONTINUES with no
# content server, so serving_mode 404s EVERY in-scope serve (~23 checks) and the
# gate scores them as conformance FAILs indistinguishable from a real defect. The
# peer's warn-and-continue is a fail-open; the gate must fail closed for it. This
# is a PRE-flight check (the port must be FREE now), not an after-start liveness
# probe — a squatted port IS listening, so "something answers" cannot tell the
# target's own listener from the squatter's. Cost a bisect to attribute on
# 2026-09-04.
for probe in "${POLL_PORT}:target(pass1)" "$((POLL_PORT + 1)):NS_PORT(pass2)"; do
    p="${probe%%:*}"; role="${probe##*:}"
    if (exec 3<>"/dev/tcp/127.0.0.1/${p}") 2>/dev/null; then
        # NB: close fd 3 with a bare `exec 3>&-` — do NOT append `2>/dev/null`,
        # which on an exec line redirects the SHELL's stderr to /dev/null for
        # good and swallows the abort message below (caught 2026-09-04).
        exec 3>&-
        echo "ABORT: 127.0.0.1:${p} — the ${role} http-poll port — is already bound before we start the peer." >&2
        echo "       A leftover peer is squatting it (this box's recurring cross-session collision). If we" >&2
        echo "       continued, the target's http-poll listener would fail to bind, serving_mode would 404" >&2
        echo "       every in-scope serve, and the gate would score ~23 FALSE conformance FAILs." >&2
        echo "       Re-run on free ports:  POLL_PORT=<free> PI_PORT=<free> $0 $TYPE" >&2
        echo "       Find the squatter:     ss -ltnp | grep :${p}" >&2
        exit 2
    fi
done

echo "==> target peer ($TYPE) with every surface enabled"
TARGET_ADDR=$(go run ./cmd/peer-manager start --name "$TARGET" --type "$TYPE" --debug \
    --signaling-node --validate --publish-root \
    --http-poll-addr "127.0.0.1:${POLL_PORT}" \
    --serve-closure-root \
    --files "docs:${FILES_DIR}/docs:local/files/docs/" \
    --publish-descriptors \
    "${PI_ARGS_PEER[@]}" \
    "${HASH_ARGS_PEER[@]}" \
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

# registry_issuer is scored in PASS 3, against a peer that IS a registry.
#
# THE ORIGINAL REASON IS FIXED, and is recorded here because the fix is what
# makes the current reason legible. This used to read: arming the §6a.9 issuer
# changes the peer's ADMISSION POSTURE, because the issuer seeds its narrow
# register-request grant at the `default` policy pattern and a policy entry is
# a request-time CEILING (V7 v7.62 §4) — so --open-access and
# --issuer-policy-mode, two flags that each GRANT, combined to grant LESS than
# either alone (six `capability` checks 403, two `authz` skipped). That was a
# real defect in our own CLI composition, not a property of the deployment;
# entity-peer now unions the two (issuerSeedGrants, guarded by
# TestIssuerSeedGrantsAreMonotoneUnderOpenAccess). Measured after the fix on a
# single peer carrying BOTH flags: capability 13/13, authz 11/11,
# registry_issuer 12/12.
#
# The remaining reason is state, not authority: registry_issuer drives live
# register / revoke / renew against an armed issuer and leaves bindings behind,
# and it rewrites `system/registry/issuer-policy` to reach all three policy
# modes. Pass 1's target also scores the `registry` and `peer_issued`
# categories, which read that same surface. Keeping them on separate peers
# keeps one pass from resolving the other's leftovers — the same reason the
# peer-issued fixture is pinned with `-wire` rather than the cohort bundle.
#
# `substitute` joins it for a DIFFERENT and sharper reason: pass 1's target is
# started with `--peer-issued-registry <pid>@http://127.0.0.1:…`, and
# peer-manager turns an http:// pin into `-substitute-allow-http` — a flag
# entity-peer itself documents as "insecure; testing only". So pass 1's peer
# deliberately accepts plaintext substitute fetches, and TV-CDN-TLS-1
# (`https_required_at_consume`) correctly FAILS it.
#
# That is not a false positive and the check is not softened for it. **A peer
# running --substitute-allow-http is not TLS-conformant, and ours was — we
# simply had no check that could say so until 2026-08-13.** The right home is a
# peer that is not deliberately insecure, and pass 3's registry target is
# started without the flag. Scoring it there measures the real posture instead
# of scoring the fixture's.
PASS3_ONLY="registry_issuer,substitute"

# relay_store_bounds is EXTENSION-RELAY §8.1 (v1.3), default-off: a relay with no
# configured retention ceiling enforces none, so these checks SKIP could-not-look
# against the bare pass-1 target. They are scored in PASS 4 against a peer started
# with --relay-store-retention-ms. Excluding here keeps pass 1's zero-skip bar
# honest — the surface is UNARMED on this target, not covered.
PASS4_ONLY="relay_store_bounds"

echo "==> PASS 1/2 — every surface, closure-of-signed-root scope"
set +e
go run ./cmd/validate-peer \
    -addr "$TARGET_ADDR" \
    -reference-peer "$REF_ADDR" \
    -poll-url "http://127.0.0.1:${POLL_PORT}" \
    "${PI_ARGS_VALIDATE[@]}" \
    "${HASH_ARGS_VALIDATE[@]}" \
    -keepalive-envelope-ms 6000 \
    -exclude "$T4_UNSATISFIABLE,$PASS3_ONLY,$PASS4_ONLY" \
    ${EXTRA:-}
RC1=$?
set -e

# PASS 1b — the SAME target, scored under --profile core (V7 v7.72 §9.0).
#
# WHY THIS EXISTS (G-2a, closed 2026-08-12). The core profile was invoked by
# NOTHING. No script ran it, so the core-tier gate existed only as a flag
# someone could type — and "a conformance tool nothing runs is
# indistinguishable from one that does not exist" is the doctrine this repo
# earned the expensive way (it is how the §2.4a register negative half sat in
# a profile nothing invoked, scoring zero peers for weeks).
#
# It reuses pass 1's target rather than starting a fifth peer: --profile core
# changes which checks are SCORED, not which surfaces the peer needs, and the
# pass-1 target already has every surface armed. The core profile's carve-out
# rows (handler_scope_denied_core_1 and friends) are exactly the ones that
# only run here.
#
# NOT a subset of pass 1, which is the point: the core profile scores the §9.0
# core-tier rows on their own terms, and some of them SKIP under full profile
# where the extension-targeted variant runs instead.
echo
echo "==> PASS 1b — the same target under --profile core (V7 v7.72 §9.0 core tier)"
set +e
go run ./cmd/validate-peer \
    -addr "$TARGET_ADDR" \
    -reference-peer "$REF_ADDR" \
    -poll-url "http://127.0.0.1:${POLL_PORT}" \
    "${PI_ARGS_VALIDATE[@]}" \
    "${HASH_ARGS_VALIDATE[@]}" \
    -keepalive-envelope-ms 6000 \
    -profile core \
    -exclude "$T4_UNSATISFIABLE,$PASS3_ONLY,$PASS4_ONLY" \
    ${EXTRA:-}
RC1B=$?
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
echo "==> PASS 2/3 — serving_mode against a namespace-scoped peer (T4 needs an out-of-scope hash)"
NS_TARGET="vcns-${STAMP}"
NS_PORT=$((POLL_PORT + 1))
NS_ADDR=$(go run ./cmd/peer-manager start --name "$NS_TARGET" --type "$TYPE" --debug \
    --http-poll-addr "127.0.0.1:${NS_PORT}" \
    --serve-namespace system/content/public \
    "${HASH_ARGS_PEER[@]}" \
    | sed -n 's/.*addr=\([^ ]*\).*/\1/p')
set +e
go run ./cmd/validate-peer \
    -addr "$NS_ADDR" \
    -poll-url "http://127.0.0.1:${NS_PORT}" \
    "${HASH_ARGS_VALIDATE[@]}" \
    -category serving_mode
RC2=$?
set -e
if [ "${KEEP:-0}" != "1" ]; then
    go run ./cmd/peer-manager stop "$NS_TARGET" >/dev/null 2>&1 || true
fi

# PASS 3 — registry_issuer ONLY, against a peer that is a REGISTRY.
#
# EXTENSION-REGISTRY §6a.9's live-registration surface is default-off: without
# --issuer-policy-mode the handler is not registered at all. That is why the
# surface sat fully built and fully unvalidated until 2026-08-10 — peer-manager
# had no passthrough, so no check could start it, and the absent coverage read
# as covered (GUIDE-CONFORMANCE §5.2b).
#
# `open` here is only the ARMING mode. The category writes the
# system/registry/issuer-policy entity itself to drive open / allowlist /
# manual in turn — the Issuer resolves policy store-first — so all three modes
# are measured against this one peer, and the store-wins precedence gets
# exercised as a side effect.
echo
echo "==> PASS 3/3 — registry_issuer against a peer that is a registry (§6a.9 is default-off)"
REG_TARGET="vcreg-${STAMP}"
# --issuer-policy-default-ttl is REQUIRED post-CAP-D11: a live registry with no
# default_ttl can only mint null-ttl bindings (D3 makes them unresolvable), and
# set-issuer-policy/register now refuse that configuration. An armed registry
# with no default_ttl would fail its own register vectors at D12.
# --issuer-policy-max-ttl is REQUIRED post-v1.11: a live policy MUST carry the
# issuer-side ceiling, and REG-TTL-CLAMP-1 exercises clamping against it. The
# ceiling is set well above the default so it never clamps the default-path
# bindings the other register vectors assert on.
REG_ADDR=$(go run ./cmd/peer-manager start --name "$REG_TARGET" --type "$TYPE" --debug \
    --issuer-policy-mode open \
    --issuer-policy-default-ttl 720h \
    --issuer-policy-max-ttl 8760h \
    "${HASH_ARGS_PEER[@]}" \
    | sed -n 's/.*addr=\([^ ]*\).*/\1/p')
set +e
go run ./cmd/validate-peer \
    -addr "$REG_ADDR" \
    "${HASH_ARGS_VALIDATE[@]}" \
    -category registry_issuer
RC3=$?
# EXTENSION-SUBSTITUTE §7 — the http convention, on the same peer for the
# reason recorded at PASS3_ONLY: this target is not started with
# --substitute-allow-http, so the TLS refusal means what it says. `-category`
# takes one name, hence the second invocation rather than a list.
go run ./cmd/validate-peer \
    -addr "$REG_ADDR" \
    "${HASH_ARGS_VALIDATE[@]}" \
    -category substitute
RC3S=$?
if [ "$RC3" -eq 0 ]; then RC3=$RC3S; fi
set -e
if [ "${KEEP:-0}" != "1" ]; then
    go run ./cmd/peer-manager stop "$REG_TARGET" >/dev/null 2>&1 || true
fi

# PASS 4 — relay_store_bounds against a peer armed with a §8.1 retention ceiling.
#
# EXTENSION-RELAY §8.1 (v1.3) is default-off, so these checks SKIP could-not-look
# against every pass-1 target; they are scored here against a peer started with
# --relay-store-retention-ms. RELAY v1.3 was Go-first, but rust (411bee4) and py
# (ROUTING-2026-09-01-b) have now landed it and matched the Go flag strings, and
# peer-manager forwards --relay-store-retention-ms to all three runners, so this
# pass now GATES all three. Formerly `if TYPE = go`: that exit-0-for-rust/py was a
# fail-open control — a pass that never ran reported the same exit 0 as a pass
# (rust 411bee4 §4). An armed peer that does not clamp FAILs (not SKIPs), which is
# the honest signal for a regression or a not-yet-built surface.
RC4=0
echo
echo "==> PASS 4/4 — relay_store_bounds against a $TYPE peer with a §8.1 retention ceiling (default-off)"
RSB_TARGET="vcrsb-${STAMP}"
# A comfortable ceiling (1h): well above the check's runtime so the clamped
# entries do not expire mid-check, and well below the ~100y far probe so the
# clamp is unmistakable.
RSB_ADDR=$(go run ./cmd/peer-manager start --name "$RSB_TARGET" --type "$TYPE" --debug \
    --relay-store-retention-ms 3600000 \
    "${HASH_ARGS_PEER[@]}" \
    | sed -n 's/.*addr=\([^ ]*\).*/\1/p')
set +e
go run ./cmd/validate-peer \
    -addr "$RSB_ADDR" \
    "${HASH_ARGS_VALIDATE[@]}" \
    -category relay_store_bounds
RC4=$?
set -e
if [ "${KEEP:-0}" != "1" ]; then
    go run ./cmd/peer-manager stop "$RSB_TARGET" >/dev/null 2>&1 || true
fi

echo
echo "PASS 0 exit $RC0 (conformance corpora, static) · PASS 0b exit $RC0B (conformance register, static) · PASS 1 exit $RC1 (all surfaces, closure scope) · PASS 1b exit $RC1B (core profile, same target) · PASS 2 exit $RC2 (serving_mode, namespace scope) · PASS 3 exit $RC3 (registry_issuer, registry posture) · PASS 4 exit $RC4 (relay_store_bounds, §8.1 armed)"
echo "Zero failures AND zero skips is the bar for passes 1, 2, 3 and 4 — read each COVERAGE"
echo "block for anything that did not run, and close it rather than allowlisting it."
echo
echo "PASS 1b is the one pass that legitimately reports skips (~100), and the distinction"
echo "matters: they are PROFILE-KEYED skips — the extension surface that sits outside the"
echo "v7.72 §9.0 core tier by definition, exempted in HasFailures via isProfileKeyedSkip,"
echo "NOT by an -allow-skip allowlist. A skip there that is not profile-keyed still fails"
echo "the pass. Read 1b's exit code, not its skip count."
[ "$RC0" -eq 0 ] && [ "$RC0B" -eq 0 ] && [ "$RC1" -eq 0 ] && [ "$RC1B" -eq 0 ] && [ "$RC2" -eq 0 ] && [ "$RC3" -eq 0 ] && [ "$RC4" -eq 0 ] || exit 1
exit 0
