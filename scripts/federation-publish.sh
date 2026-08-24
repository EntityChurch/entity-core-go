#!/usr/bin/env bash
# federation-publish.sh — go's leg of the multi-host cross-impl federation gate
# (COHORT-OPEN-ITEMS C-7 · CDN-corridor meta-rule).
#
# Stands up a GO http-poll publisher as ITS OWN container on a podman bridge,
# with a routable non-loopback address, and prints the consumer contract
# (origin + peer-id + root hash). browser-rust's (or workbench-go's) existing
# consumer then walks MANIFEST_GET → verify → TREE_GET → CONTENT_GET against it
# across a real TCP hop — one implementation publishing, a DIFFERENT one
# consuming, which is the half a single-impl rig (however many hosts) can't
# exercise.
#
#   bash scripts/federation-publish.sh up      # build + start; STDOUT = evalable contract
#   bash scripts/federation-publish.sh probe   # verify the origin from a container on the bridge
#   bash scripts/federation-publish.sh down     # tear down
#
# WHAT A GREEN CONSUME RUN CLAIMS: a separate network namespace, a distinct
# routable address, a real TCP hop, hash+signature verification at a consumer
# that shares NO process and NO filesystem with the go publisher — TWO
# IMPLEMENTATIONS ON ONE CHAIN. IT DOES NOT CLAIM: two physical machines, the
# public internet, TLS, a CDN, or NAT. Stated here because a rig that overstates
# its scope is how a green gate launders an untested claim.
#
# THREE GOTCHAS, inherited from browser-rust's rig and handled below — each cost
# them real time and each presents as a broken server when it is not:
#   1. The host has no route into a rootless bridge network — so `probe` runs
#      FROM A CONTAINER on the bridge, the vantage the consumer actually has.
#   2. The bridge gateway is not the host — so the publisher gets ITS OWN
#      container rather than being served from the host at the gateway address.
#   3. Ordering: the container must exist and its address be read back BEFORE the
#      contract is emitted; the origin is the container's bridge IP, unknowable
#      until it is running. (go's published root does not bake the origin into
#      its signed bytes — the consumer is given the origin out of band, "an
#      origin plus a peer-id" — so a mis-ordered emit degrades only the contract,
#      never the signature; the readback is still done first so the origin is right.)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NET="${FED_NET:-entity-go-fed}"
PUB="${FED_PUB:-entity-go-fed-pub}"
PORT="${FED_PORT:-8099}"
IMG="${FED_IMG:-docker.io/library/alpine:3.20}"
BIN="${FED_BIN:-/tmp/entity-go-publish-fixture}"

# Logs to STDERR so STDOUT is nothing but the evalable consumer contract.
log() { printf '  %s\n' "$*" >&2; }

build_bin() {
  log "building static publish-fixture (CGO off, linux/amd64)…"
  ( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BIN" ./cmd/publish-fixture )
}

down() {
  podman rm -f "$PUB" >/dev/null 2>&1 || true
  podman network rm -f "$NET" >/dev/null 2>&1 || true
  log "torn down ($PUB, $NET)"
}

# read_ip reads the container's bridge address and enforces the two controls a
# rootless-podman quirk could otherwise let pass silently.
read_ip() {
  local ip
  ip="$(podman inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PUB")"
  [ -n "$ip" ] || { echo "FATAL: no address on $PUB" >&2; exit 1; }
  case "$ip" in
    127.*|localhost) echo "FATAL: publisher address $ip is loopback — not a separate host" >&2; exit 1 ;;
  esac
  if ip -4 addr show 2>/dev/null | grep -qw "$ip"; then
    echo "FATAL: publisher address $ip is also a host address — not a separate host" >&2
    exit 1
  fi
  printf '%s' "$ip"
}

# wait_contract polls the publisher's logs until it prints its ready contract,
# then echoes the whole contract block.
wait_contract() {
  local i out
  for i in $(seq 1 60); do
    out="$(podman logs "$PUB" 2>/dev/null || true)"
    if printf '%s\n' "$out" | grep -q '^# ready'; then
      printf '%s\n' "$out"
      return 0
    fi
    sleep 0.5
  done
  echo "FATAL: publisher did not become ready within 30s" >&2
  podman logs "$PUB" >&2 || true
  exit 1
}

up() {
  down
  build_bin
  podman network create "$NET" >/dev/null
  # Gotcha 2: publisher gets its OWN container (not the host at the gateway).
  # A CGO-free static Go binary needs no libc, so a bare alpine is enough.
  podman run -d --name "$PUB" --network "$NET" \
    -v "$BIN:/publish-fixture:z,ro" \
    "$IMG" /publish-fixture -addr "0.0.0.0:$PORT" >/dev/null

  # Gotcha 3 / ordering: read the address back BEFORE emitting the contract.
  local ip contract peer_id root rootpath
  ip="$(read_ip)"
  contract="$(wait_contract)"
  peer_id="$(printf '%s\n' "$contract" | sed -n 's/^peer_id=//p')"
  root="$(printf '%s\n' "$contract" | sed -n 's/^published_root_hash=//p')"
  rootpath="$(printf '%s\n' "$contract" | sed -n 's/^published_root_content_path=//p')"
  [ -n "$peer_id" ] || { echo "FATAL: no peer_id in publisher contract" >&2; exit 1; }

  log "go federation up: peer $peer_id serving http-poll at http://$ip:$PORT"
  log "verify liveness + B4 (root served by its signed hash) with:  bash $0 probe"
  # STDOUT: the evalable consumer environment. Origin is the BRIDGE IP.
  echo "FED_ORIGIN=http://$ip:$PORT"
  echo "FED_PEER_ID=$peer_id"
  echo "FED_ROOT_HASH=$root"
  echo "FED_ROOT_CONTENT_PATH=$rootpath"
  echo "FED_MANIFEST_URL=http://$ip:$PORT/manifest"
  echo "FED_CONTENT_PREFIX=http://$ip:$PORT/content"
}

# probe verifies the manifest is reachable FROM A CONTAINER on the bridge
# (gotcha 1 — the host cannot route into a rootless bridge). Exit 0 iff the
# MANIFEST_GET returns success.
probe() {
  local ip rootpath
  ip="$(read_ip)"
  log "probing http://$ip:$PORT/manifest from a container on $NET…"
  if ! podman run --rm --network "$NET" "$IMG" \
       wget -q -O /dev/null "http://$ip:$PORT/manifest"; then
    echo "FATAL: manifest not reachable at http://$ip:$PORT/manifest from the bridge" >&2
    exit 1
  fi
  log "manifest OK — served over a real bridge hop"

  # B4 (C-7 §1b.2): the SIGNED ROOT MUST be served at its own content hash. This
  # is the exact fetch browser-rust's consumer makes and the one a go-on-go
  # per-leaf check skips — a root the publisher signs but does not serve 404s
  # here and the whole walk terminates tree/incomplete-walk.
  rootpath="$(podman logs "$PUB" 2>/dev/null | sed -n 's/^published_root_content_path=//p')"
  [ -n "$rootpath" ] || { echo "FATAL: no root content path in contract" >&2; exit 1; }
  log "B4: fetching the signed root by hash — GET /content/$rootpath …"
  if podman run --rm --network "$NET" "$IMG" \
       wget -q -O /dev/null "http://$ip:$PORT/content/$rootpath"; then
    log "PROBE OK — signed root served at its own hash (B4 met); walk closure is resolvable"
  else
    echo "FATAL: signed root 404s at /content/$rootpath — B4 NOT met (root signed but not served)" >&2
    exit 1
  fi
}

case "${1:-}" in
  up)    up ;;
  down)  down ;;
  probe) probe ;;
  *) echo "usage: $0 {up|probe|down}" >&2; exit 2 ;;
esac
