# entity-core-go — status

_Updated: 2026-08-04 · public: v0.8.0 (master)_

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

**The connectivity cycle — EXTENSION-SIGNALING — is the live work**, and has
been since early July. It is a cohort effort with `entity-core-rust`,
`entity-system-architecture` (spec) and `entity-browser-rust` (the browser leg),
routed through dated `ROUTING-*` / `HANDOFF-*` docs in this directory.

Landed here: the §4 rendezvous node + client, the §3 key derivation and pool
selection, the §7 NAT-punch choreography (gather → carrier exchange →
measure-and-schedule → simultaneous open over a shared SO_REUSEPORT socket →
§7.4 identity check), wired to a live peer through `ext/signaling/peerwiring`
behind EXTENSION-NETWORK §10.3's `establish_live` seam. The §6.5 WebRTC
coordination layer is implemented as coordination RULES ONLY — Go has no ICE
stack, terminates no data channel, and publishes no WebRTC transport profile.

**The §6.3 coordination envelope is folded** (arch `b99304d`) after crossing
both ways: Go `38·0F` verified by rust, rust `36·0F` verified by us. Every
correction this repo routed is in the normative text — the derived-and-compared
peer-id, the two hash axes, and the four-disposition anti-downgrade rule.

**The flag day is nearly closed.** Both implementations now read AND seal, on
both loops. §6.1: Go at `d56a690`, rust shortly after; rust then ran a live
cross-impl sealed punch (both seats over the CLI/JSON contract, Go's binary
built from `6a3f1b6`) and raised their `PUNCH_TRUST` to `Require` on the
strength of it. Our collector is proven to enforce from our own seat too —
`cmd/signaling-punch --trust require` completes Go↔Go over a live node, and a
bare depositor built from our pre-flip commit is refused by name, not by
timeout.

**The flag day is CLOSED.** `peerwiring.DefaultTrust` is now `VerifyRequire`:
an unsealed §6.1 coordination message is refused, which is what §6.3's MUST
asks for. Verified after the flip with no `--trust` flag passed at all —
default posture, `verified:true` both seats over a live node, `signaling` 7/7.

`entity-core-py` is unaffected: it has the §4 signaling client but does not
punch and has no signed-blob support, so it never enters the path this
governs. When Python builds the punch it seals from the start — there is no
tolerant window left to arrive into.

**Where this is NOT.** Coordination-green is not transport-works. §11.5.1's S5
gate — two real browser peers establishing a real data channel over a real
signaling node — has not been run, and nothing in this arc moved it. The
browser leg is one box and it is `entity-browser-rust`'s.

The v1.x protocol cycle (Tier-2 dispatch-fallback to the byte-identical-envelope
bar, paired with the encrypted-relay boundary) is queued behind this and
unstarted.

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
- ~~**NAT traversal.** Proposal-grade analysis exists; it is Tier-3 territory
  and deferred.~~ **Superseded** — EXTENSION-SIGNALING §7 is implemented and
  wired (see "Where we left off"). What remains unproven is traversal under
  REAL NAT: the punch is validated on loopback, which has no mapping to punch,
  so both-fire correctness is asserted at the `DialFunc` seam rather than
  observed. That is the §7.5-class gate and it has not been run.

**Demos / reach (stretch).**
- **Phone-browser → desktop-native (WebSocket) demo.** The transport substrate
  is in place on Go; the remaining piece is a minimal HTML page that dials the
  `ws://` endpoint. Stretch goal, downstream of the substrate.
- **Browser ↔ browser (WebRTC).** No longer deferred and no longer Go's:
  the signaling substrate is built (that was the blocker), and the browser leg
  is `entity-core-rust`'s wasm32 transport (S3) → `entity-browser-rust` (S4) →
  S5. Go's part is the §6.5 coordination rules as a second independent
  implementation of the conventions, which is done.

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

- **EXTENSION-SIGNALING §4 node + client, §3 keys/pool, §7 punch**, wired to a
  live peer via `ext/signaling/peerwiring` behind NETWORK §10.3's
  `establish_live` seam. Validated over a live node (`signaling_punch`
  category) and Go↔Go end to end on loopback.
- **§6.5 WebRTC coordination rules** — the offerer/glare resolution, session
  correlation, the trickle-settled gate, and the channel-identity guard, as a
  second independent implementation of conventions the S5 gate cannot validate
  (two browser peers likely run the SAME WebRTC stack). Coordination crossed
  both ways with rust at `21·0F`/`23·0F`.
- **§6.3 coordination envelope — built, crossed both ways, FOLDED into the
  spec** (arch `b99304d`). Go `38·0F` verified by rust, rust `36·0F` verified
  by us. Two blocking corrections this repo raised are in the normative text:
  the peer-id is derived-and-compared in full (a wire `signer` is forgeable,
  and a non-canonical `hash_type` would let one key present two ids and choose
  its own glare role), and the two hash axes are distinguished.
- **The §6.1 flag day, Go's half** — §6.3 step 3 wired into the read path (it
  can only live where the claim is known, which is why the API had no caller
  and the gap survived the crossing), skip-own moved onto the verified signer,
  and all three §6.1 deposits sealed as bucket-bound containers. `SelfID` is
  gone: the party derives its id from the key it signs with, so the id/key skew
  rust refuses at runtime is unrepresentable here. Vector file re-emitted at
  `42·0F @ 204e1d9` with four §6.1 rows, closing the same-side-tested limit
  rust flagged on their own read side.
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

1. ~~**Close the §6.1 flag day.**~~ **DONE** — both impls seal, read, and now
   refuse. Nothing in the signaling security arc is open on either side.
2. **Cross-verify the §6.1 rows.** Crossed one way: rust reads our file at
   `42·0F`. We read theirs at `40·1W·0F` — their false-claim row's payload
   names its own signer, so only the row field is false and the row cannot
   catch a read path with step 3 unwired on the payload side. Routed; one
   field on their end closes it.
3. **Two real machines.** This is the gap that matters and it is not blocked
   on code. Everything above is loopback, where there is no NAT to punch —
   so both implementations agreeing proves they wrote the same code, not that
   traversal works. The §7.5 emulated-NAT rung and §11.5.1's S5 are both
   unrun, and Python catching up to the punch is queued behind neither.
3. Open the v1.x cycle: implement Tier-2 dispatch-fallback to the
   byte-identical-envelope bar, paired with the encrypted-relay boundary, and
   stand up dated, oracle-pinned cross-impl conformance reports for Rust and
   Python once the sibling repos are available.

**The honesty line, unchanged.** No number in this document is a WebRTC
transport claim. Coordination-green means two implementations agree about
coordination bytes; §11.5.1's S5 — two real browser peers, a real data channel,
a real signaling node — remains the only evidence that the browser leg works,
and it has not been run.
