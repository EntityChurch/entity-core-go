#!/usr/bin/env bash
# Release-green cohort orchestrator.
#
# Per-impl, brings up TWO peers (a "main" + a "closure" peer) and runs the
# validate-peer suite split across them. This is by design — one peer can't
# satisfy both the serving_mode T4 family (presence-oracle prevention, which
# requires constructable out-of-scope state) AND the published_root.v4/v5/v7
# family (which requires --publish-root + closure-or-whole-store serving
# scope per NETWORK §6.5.6 Amendment 10) at the same time:
#
#   • Under --serve-namespace, tree:put outside the served prefix produces
#     a bound-but-out-of-scope entity → CONTENT_GET returns 404 → T4 holds.
#     But the peer can't advertise signed_pointer, so v4/v5/v7 have nothing
#     to fetch.
#
#   • Under --serve-closure-root + --publish-root, the peer publishes a
#     signed root_hash and serves the closure → v4/v5/v7 PASS. But every
#     tree:put extends the closure, so the validator can't construct
#     out-of-scope state via tree:put → T4 has no subjects to test.
#
# The protocol intent is that scope is a per-peer deployment choice; the
# cohort tests each shape on its own peer. Per impl:
#
#   green-${impl}          --serve-namespace system/content/public
#                          Runs full suite EXCEPT published_root.
#
#   green-${impl}-closure  --serve-closure-root --publish-root
#                          Runs ONLY published_root (7/7 expected).
#
# A cohort "PASS" requires both peer runs to pass for the impl.
#
# Other flags (unchanged from prior orchestrator):
#   --validate              unblocks concurrency.t1_2_concurrent_reentry
#   --http-poll-addr        unblocks serving_mode.* + transport_family WARN
#   --files <writable>      unblocks local_files.* (5 WARNs + 1 SKIP each)
#   --publish-descriptors   unblocks local_files.v3_descriptor_publish_exercised
#                           (Go + Rust; Python CLI rollout pending)
#
# Usage:
#   ./scripts/validate-peers-green.sh                 # validate go + rust + python
#   ./scripts/validate-peers-green.sh rust            # rust only
#   ./scripts/validate-peers-green.sh go python       # subset
#
# Options (env):
#   SAVE=1               Save per-target JSON reports to docs/validation/reports/
#                        (writes ${logical}-green.json + ${logical}-green-published-root.json)
#   JSON=1               Stream raw JSON to stdout instead of human text
#   CATEGORY=name        Run a single category on the MAIN peer (skips closure peer)
#   KEEP=1               Don't tear peers down at end (for follow-up probing)
#   FAILURES_ONLY=1      Only print failed/skipped/warned checks

set -euo pipefail
cd "$(dirname "$0")/.."

KEEP="${KEEP:-0}"

# ---- shared state -----------------------------------------------------------

declare -A TARGET_NAMES         # logical name -> peer-manager name (main peer)
declare -A TARGET_POLLS         # logical name -> http-poll URL (main peer)
declare -A TARGET_FILES         # logical name -> writable dir we created
declare -A CLOSURE_NAMES        # logical name -> peer-manager name (closure peer)
declare -A CLOSURE_POLLS        # logical name -> http-poll URL (closure peer)
REF_NAME=""
TMPROOT=""

cleanup() {
    local rc=$?
    if [[ "$KEEP" == "1" ]]; then
        echo "KEEP=1: peers left running. peer-manager list to see; stop --all to tear down."
        echo "Writable --files mounts at: $TMPROOT (KEEP=1 — not cleaned)"
        return $rc
    fi
    echo
    echo "--- Tearing down ---"
    for name in "${TARGET_NAMES[@]}"; do
        go run ./cmd/peer-manager stop "$name" 2>/dev/null || true
    done
    for name in "${CLOSURE_NAMES[@]}"; do
        go run ./cmd/peer-manager stop "$name" 2>/dev/null || true
    done
    if [[ -n "$REF_NAME" ]]; then
        go run ./cmd/peer-manager stop "$REF_NAME" 2>/dev/null || true
    fi
    if [[ -n "$TMPROOT" && -d "$TMPROOT" ]]; then
        rm -rf "$TMPROOT"
    fi
    return $rc
}
trap cleanup EXIT

# ---- helpers ---------------------------------------------------------------

# free_port — bind+release a TCP port and echo the number. Race-y but fine for
# orchestration (the peer grabs it within a second of free_port returning).
free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

start_target() {
    local logical="$1"
    local peer_type="$2"
    local pm_name="green-${logical}"
    local poll_port
    poll_port=$(free_port)
    local files_dir="$TMPROOT/$logical"
    mkdir -p "$files_dir"

    local extra_args=()
    if [[ "$peer_type" == "go" || "$peer_type" == "rust" ]]; then
        extra_args+=(--publish-descriptors)
    fi

    echo "--- Starting main peer $logical ($peer_type, namespace scope) ---"
    go run ./cmd/peer-manager start \
        --name "$pm_name" \
        --type "$peer_type" \
        --validate \
        --http-poll-addr "127.0.0.1:$poll_port" \
        --serve-namespace "system/content/public" \
        --files "green:$files_dir:local/files/green/" \
        "${extra_args[@]}" \
        2>&1 | sed 's/^/  /'

    TARGET_NAMES[$logical]="$pm_name"
    TARGET_POLLS[$logical]="http://127.0.0.1:$poll_port"
    TARGET_FILES[$logical]="$files_dir"
}

start_closure() {
    local logical="$1"
    local peer_type="$2"
    local pm_name="green-${logical}-closure"
    local poll_port
    poll_port=$(free_port)

    echo "--- Starting closure peer $logical ($peer_type, closure-root + publish-root) ---"
    go run ./cmd/peer-manager start \
        --name "$pm_name" \
        --type "$peer_type" \
        --validate \
        --http-poll-addr "127.0.0.1:$poll_port" \
        --serve-closure-root \
        --publish-root \
        2>&1 | sed 's/^/  /'

    CLOSURE_NAMES[$logical]="$pm_name"
    CLOSURE_POLLS[$logical]="http://127.0.0.1:$poll_port"
}

start_reference() {
    REF_NAME="green-ref-$$"
    echo "--- Starting Go reference peer ($REF_NAME) ---"
    go run ./cmd/peer-manager start --name "$REF_NAME" --type go 2>&1 | sed 's/^/  /'
}

validate_target_main() {
    local logical="$1"
    local pm_name="${TARGET_NAMES[$logical]}"
    local addr
    addr=$(go run ./cmd/peer-manager addrs "$pm_name")
    local ref_addr
    ref_addr=$(go run ./cmd/peer-manager addrs "$REF_NAME")
    local poll_url="${TARGET_POLLS[$logical]}"

    echo
    echo "=== Validating $logical (main, namespace) @ $addr (poll=$poll_url, ref=$ref_addr) ==="

    # 60s validator default is too short under full-flag config — local_files
    # behavioral + serving_mode probes are I/O-heavy and starve downstream
    # categories of budget. 300s leaves headroom for the slowest cohort sibling
    # (Python ~3-5× Go runtime under behavioral_v33 / concurrency).
    #
    # -exclude published_root — that category runs against the closure peer.
    # The main peer is on --serve-namespace and has no --publish-root, so
    # MANIFEST_GET 404s and v4/v5/v7 would SKIP. Routing the category to the
    # closure peer converts them to genuine PASS signal cohort-wide.
    local args=(
        -addr "$addr"
        -identity framework-admin
        -reference-peer "$ref_addr"
        -poll-url "$poll_url"
        -timeout "${VALIDATOR_TIMEOUT:-300s}"
    )
    if [[ -n "${CATEGORY:-}" ]]; then
        args+=(-category "$CATEGORY")
    else
        # published_root → routes to the closure peer (see validate_target_closure).
        # peer_issued → opt-in extension category; vectors SKIP without a fixture
        # (target started with --peer-issued-registry pinning a registry the
        # validator can drive). Excluded from the default orchestrator run, same
        # pattern as convergent_mirror (multi-peer-only). When the cohort wires
        # the Keystone fixture per HANDOFF-PEER-ISSUED-REGISTRY-BACKEND-IMPL §7,
        # this exclusion drops.
        args+=(-exclude published_root,peer_issued)
    fi
    [[ "${FAILURES_ONLY:-}" == "1" ]] && args+=(-failures-only)
    [[ "${JSON:-}" == "1" ]] && args+=(-json)

    if [[ "${SAVE:-}" == "1" ]]; then
        mkdir -p docs/validation/reports
        local outfile="docs/validation/reports/${logical}-green.json"
        go run ./cmd/validate-peer "${args[@]}" -json-out "$outfile" -failures-only || true
        echo "Saved: $outfile"
    else
        go run ./cmd/validate-peer "${args[@]}" || true
    fi
}

validate_target_closure() {
    local logical="$1"
    # Closure peer covers published_root only — skip when the user requested a
    # specific category that isn't published_root.
    if [[ -n "${CATEGORY:-}" && "${CATEGORY}" != "published_root" ]]; then
        return
    fi
    local pm_name="${CLOSURE_NAMES[$logical]}"
    local addr
    addr=$(go run ./cmd/peer-manager addrs "$pm_name")
    local ref_addr
    ref_addr=$(go run ./cmd/peer-manager addrs "$REF_NAME")
    local poll_url="${CLOSURE_POLLS[$logical]}"

    echo
    echo "=== Validating $logical (closure, closure-root+publish-root) @ $addr (poll=$poll_url) ==="

    local args=(
        -addr "$addr"
        -identity framework-admin
        -reference-peer "$ref_addr"
        -poll-url "$poll_url"
        -timeout "${VALIDATOR_TIMEOUT:-300s}"
        -category published_root
    )
    [[ "${FAILURES_ONLY:-}" == "1" ]] && args+=(-failures-only)
    [[ "${JSON:-}" == "1" ]] && args+=(-json)

    if [[ "${SAVE:-}" == "1" ]]; then
        mkdir -p docs/validation/reports
        local outfile="docs/validation/reports/${logical}-green-published-root.json"
        go run ./cmd/validate-peer "${args[@]}" -json-out "$outfile" -failures-only || true
        echo "Saved: $outfile"
    else
        go run ./cmd/validate-peer "${args[@]}" || true
    fi
}

# ---- main -----------------------------------------------------------------

targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    targets=(go rust python)
fi

# Stop any leftover green peers from a prior run (other peers untouched).
for t in "${targets[@]}"; do
    go run ./cmd/peer-manager stop "green-$t" 2>/dev/null || true
    go run ./cmd/peer-manager stop "green-$t-closure" 2>/dev/null || true
done

TMPROOT=$(mktemp -d -t green-files.XXXXXX)
echo "--files writable root: $TMPROOT"
echo

start_reference

for t in "${targets[@]}"; do
    case "$t" in
        go|rust|python)
            start_target "$t" "$t"
            start_closure "$t" "$t"
            ;;
        *) echo "Unknown target type: $t (supported: go, rust, python)"; exit 1 ;;
    esac
done

echo
go run ./cmd/peer-manager list

for t in "${targets[@]}"; do
    validate_target_main "$t"
    validate_target_closure "$t"
done
