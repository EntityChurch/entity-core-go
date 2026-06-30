# entity-core-go — status

_Updated: 2026-06-30 · public: v0.8.0 (master)_

## Where it is

Go reference implementation of the Entity Core Protocol v7 — the third
ground-up reference implementation (after Python and Rust), and the project's
SDK prototype + interop oracle. Because Go **leads on new protocol features**,
cross-implementation convergence is downstream feedback here, not a gate, and
the other implementations validate against this one as the interop baseline.
The codebase is a three-module `go.work` workspace — `core` (the protocol
library, a strict 14-package DAG: `errors → ecf → hash → entity, crypto,
store, types, wire → capability → handler → protocol, tree → peer`), `ext`
(system extensions, each depending only on `core`), and `cmd` (CLIs, the
~60-category validation suite, and cross-impl interop tooling). Go 1.25, only
two external dependencies (`fxamacker/cbor` for ECF, `mr-tron/base58` for
PeerID), pure-Go/no-CGo. The build is fully containerized (`make` + `podman`,
per-invocation resource caps in the `Makefile` / `RESOURCE-CAPS.md`); a fresh
clone with no sibling repos present builds and tests standalone. Maturity:
**v0.8.0 research-preview** — publicly released and tagged. The extension
surface is broad and landed: `inbox`, `subscription`, `continuation`,
`revision`, `role`, `type` (+`constraint`), `localfiles`, `content`,
`identity`/`attestation`/`quorum`, `registry`, `relay`, `discovery`,
`publishedroot`, `encryption`, `compute`, plus the HTTP storage-substitute and
live-HTTP transport surfaces.

## Where we left off

Stable at the v0.8.0 research-preview line; no code or protocol changes are in
flight. The substantive engineering push before the preview cut was the
**network/relay release-readiness milestone**, which was driven to "nothing
external blocks the release" — the relay substrate, the publish→fetch path,
and the HTTP-transport relay coverage gate were all closed and wire-verified
three ways (Go/Rust/Python), and WebSocket transport on Go landed and was
cross-impl-validated against Rust. ENCRYPTION v1.0 (first block) and the
peer-issued registry path also landed in that run. The next substantive work
is opening the v1.x cycle — implementing the Tier-2 dispatch-fallback seam to
the byte-identical-envelope bar, paired with the encrypted-relay boundary.

## Backlog

Ranked roughly by readiness to pick up.

**Tier-2 async delivery (next protocol cycle).**
- Implement the **dispatch-fallback seam** end to end. The seam is wired
  (`*peer.Peer` carries a `DispatchFallbackFunc`, consulted at the remote-EXECUTE
  caller that holds both `peer_id` and the EXECUTE envelope — not inside
  connection resolution) and the happy-path build-test passes (sender →
  inbox-relay store-and-forward → offline target polls on reconnect → verifies
  the sender signature exactly as a direct dispatch would). The remaining work
  is the v1.x cycle: prove the **byte-identical-envelope** guarantee (a peer
  with the seam unset is byte-for-byte identical to one without it) and pair the
  implementation with encryption at the encrypted-relay boundary.

**Encryption beyond the first block.**
- ENCRYPTION v1.0 self/peer/group end-to-end is landed with byte-pinned
  known-answer tests. The forward work is the **encrypted-inner-over-relay**
  case (gift-wrap / WRAP model for the relay path, with the inside-envelope
  form retained for at-rest `self` mode) and continuing the cohort's
  follow-on findings to a full cross-impl close.

**Routing / reachability (parked until there's a driver).**
- **ROUTE auto-population (GOSSIP / adaptive routing).** Storage plane is green;
  tables are hand-populated today, which already expresses the VPN/gateway
  case correctly (`system/route` entry with `action="forward", via=<gateway>`).
  Adaptive multi-hop convergence (anti-entropy gossip is the natural fit) is
  deferred until a real adaptive-routing need appears.
- **NAT traversal.** Proposal-grade analysis exists; it is Tier-3 territory and
  deferred. Decoupled from the WebSocket transport work, which is already done.

**Demos / reach (stretch).**
- **Phone-browser → desktop-native (WebSocket) demo.** The transport substrate
  is in place on Go; the remaining piece is a minimal HTML page that dials the
  `ws://` endpoint. Stretch goal, downstream of the substrate.
- **Browser ↔ browser (WebRTC).** Deferred — requires signaling/STUN
  infrastructure the project does not operate.

**Cross-impl conformance & quality.**
- Stand up dated, oracle-pinned **per-peer conformance reports** for the Rust
  and Python implementations (the local `docs/validation/` reporting tier is
  not part of the published surface yet). Every published number must be
  reproducible and oracle-pinned (P/W/F/S breakdown, not a bare percentage).
- **Expand the behavioral wire harness.** Some v3.3 conformance vectors
  (transitive supersession / predecessor revival) already drive over the wire;
  the remaining v3.3 vectors run only as in-process unit tests. Promoting them
  to wire-driven cohort vectors is optional follow-up.

**Exploratory (not on any critical path).**
- EXTENSION-DURABILITY is implemented only as a reference surface — exploratory
  / optional, absence is conformant, no deployment depends on it.

## Waiting on

- **Spec (upstream).** The canonical protocol spec is owned by the architecture
  repo; normative/protocol changes flow from there. Implementations implement
  the landed spec and route gaps/ambiguities upstream rather than inventing wire
  shapes locally.
- **Sibling implementations present on disk.** Cross-impl interop validation
  (`make validate-rust` / `make validate-python`, the convergence harness)
  drives live peers and needs the Rust and Python repos available alongside
  this one.

## Done recently

- **v0.8.0 initial public research-preview** — first public release, tagged.
- **Network/relay release-readiness milestone closed.** Relay substrate (single-
  hop, source-routed multi-hop, Mode-S queued fallback, Mode-F over any
  transport) plus the ROUTE storage plane green three-way; publish→fetch end-to-
  end over `http-poll` (the Tier-1 publish gate) closed three-way, with a
  cross-impl wire-drive of Go-publish → Rust/Python-consume confirming byte-equal
  contract over real HTTP; the HTTP-transport relay coverage gate closed
  three-way after the Python `send_raw_frame` substrate gap was filled.
- **WebSocket transport on Go.** Ships a `-ws-addr` listener + outbound dialer
  (via `coder/websocket`); Go-self three-way green and a Go→Go(WS)→Rust(WS)
  terminal-hop leg byte-equal cross-impl. Unblocks the phone-browser →
  desktop-native (M2) demo substrate.
- **ENCRYPTION v1.0 (first block).** self / peer / group end-to-end with
  byte-pinned KATs; registered as a validation category; cohort wire surface
  brought to three-way green.
- **Peer-issued registry path.** Live registration (replay defense + peer-id
  allowlist) plus a self-verified fixture bundle (resolve / expired / revoked /
  precede / verify-fail / offline-not-found vectors).
- **Containerized bare-box build.** `make` + `podman` build/test/vet/race with
  the repo mounted directly, per-invocation memory/CPU/pids caps, Go 1.25, and
  vanity module paths (`go.entitychurch.org/entity-core-go/{core,ext,cmd}`);
  `peer-manager` launches Rust/Python peers via podman to match.

## Next

1. Open the v1.x cycle: implement Tier-2 dispatch-fallback to the
   byte-identical-envelope bar, paired with the encrypted-relay boundary, and
   stand up dated, oracle-pinned cross-impl conformance reports for Rust and
   Python once the sibling repos are available.
