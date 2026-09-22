# The punch socket requirements (EXTENSION-SIGNALING §7.3 / EXTENSION-NETWORK §6.7.3)

**Audience:** implementers of the SIGNALING §7 hole punch, in any language. This
guide records the socket-level requirement that is *not* satisfiable by
discipline, how entity-core-go satisfies it, and what is interoperable versus
platform-local — so a Rust/Python/other peer can converge without re-deriving it.

> **The one MUST that is a socket option, not code.** A NAT allocates a mapping
> **per local socket**. A `srflx` candidate is the mapping observed for the
> socket that produced it (via the §6.7.1 reflector), so it is meaningful **only**
> for that socket. The punch therefore **MUST dial from the same local endpoint
> whose mapping was observed** (EXTENSION-NETWORK §6.7.3, EXTENSION-SIGNALING
> §7.3). On UDP/QUIC that is one socket reused, effectively free. **On TCP it
> requires `SO_REUSEADDR` + `SO_REUSEPORT` plus an explicit local-address bind on
> BOTH the reflector dial and the punch dial** — no amount of careful code
> substitutes for the socket options.

A `srflx` gathered on one ephemeral socket and punched from another is **a hole
that will never open**. This failure *wears another failure's costume*: the
symptom is "the punch didn't land," identical to a mistimed open (whose delay is
a sanctioned local tunable). **On a first cross-implementation punch failure,
bisect the socket binding before touching the timing.**

## What is interoperable vs. platform-local

| Concern | Status | Notes |
|---|---|---|
| The candidate/socket **binding** (same local port for reflector + punch) | **normative / MUST** | Cross-peer observable in effect; the interoperable requirement. |
| `fire_at` clock domain + encoding (delay-from-receipt, uint ms) | **normative / MUST** | §7.2. Not a socket concern, but the other load-bearing cross-peer pin. |
| The exact sockopt spelling / constant values | **platform-local, MAY diverge** | §7.2/§11.4 implementation-defined. See the per-OS table below. |
| `rtt` measurement, probe pacing, retry counts, timeouts | **platform-local, MAY diverge** | §11.4. |

Two peers in different languages interoperate as long as each honors the
*binding* and the `fire_at` contract. **The socket-option constants are not on
the wire and need not match.**

## Per-OS socket options (the constant is NOT hardcoded — resolve it per-GOOS)

`SO_REUSEPORT` has different numeric values per platform, which is exactly why an
implementation should resolve it from the platform's own headers/bindings rather
than hardcoding a magic number:

| Platform | `SO_REUSEPORT` | How entity-core-go gets it | Status in go impl |
|---|---|---|---|
| Linux | `0x0F` (15) | `golang.org/x/sys/unix.SO_REUSEPORT` | **built** |
| macOS / *BSD | `0x0200` | `golang.org/x/sys/unix.SO_REUSEPORT` | **built** (same build tag) |
| Windows | no `SO_REUSEPORT`; `SO_REUSEADDR` behaves closer to REUSEPORT | dedicated `reuseport_windows.go` (TBD) | **not yet** — fails closed to relay |
| other | — | `reuseport_unsupported.go` stub | fails closed → relay fallback (§10) |

**entity-core-go's layout** (`ext/signaling/reuseport*.go`):

- `reuseport.go` — platform-agnostic seam: `dialReusePort` / `listenReusePort`
  wire the `Control` hook onto `net.Dialer` / `net.ListenConfig`.
- `reuseport_supported.go` (`//go:build linux || darwin || *bsd`) — sets
  `SO_REUSEADDR` + `SO_REUSEPORT` via `golang.org/x/sys/unix` before bind/connect.
  `golang.org/x/sys` is already in the module graph, so this adds no new module.
- `reuseport_unsupported.go` — returns `ErrReusePortUnsupported`, which the
  coordinator maps to "no live path" → the ladder falls through to the relay
  fallback (§10). A platform without the sockopt is **conformant-degraded**, not
  broken: it simply cannot offer the direct-path optimization.

## How the direct path is established (go impl)

The spec models §7.1 step 4 as a TCP **simultaneous open** (both sides SYN at
`fire_at`; the crossing SYNs form one connection). Pure both-sides-only-dial
simultaneous-open connects **only** in the instant both sockets sit in
`SYN_SENT`, which is fragile. entity-core-go instead uses the technique real TCP
hole-punch stacks use — **both share the reflector port via `SO_REUSEPORT`, and
a deterministic peer-id role split converges on one connection**:

- The **lower peer-id** dials the counterpart's `srflx` from the shared port.
- The **higher peer-id** listens on that same port and accepts.

Either outcome binds each side's advertised `srflx` port (the §6.7.3 MUST) and is
bidirectional, so the entity handshake role is independent of the TCP
dialer/acceptor role: the punch **initiator** (which offered `connect-request`)
always runs the client handshake (`PerformConnect`, §7.4), the **responder**
always serves — exactly one HELLO is sent regardless of which end dialed.

> **Cross-NAT note (the §7.5 gate).** Under real NAT the *listening* side must
> also emit an outbound packet toward the dialer's `srflx` to open its **own**
> mapping before the dial arrives; that dual-hole sequencing (and the TCP 4-tuple
> hazards it creates — a throwaway hole-punch dial can complete a
> simultaneous-open on the dialing socket and steal the 4-tuple) is hardened
> against real NAT at the cross-NAT gate, not on loopback (which has no mapping
> to open). The loopback proof (`TestPunchLoopbackDirectPath`) validates the
> coordination protocol + the shared-port substrate; it does not claim to
> reproduce NAT crossing.

## The §7.4 connectivity check is not a new handshake

Do not invent a handshake to "confirm the peer." The punched TCP connection runs
the **ordinary** `PerformConnect` (HELLO/AUTHENTICATE), which proves the far end
holds the expected peer-id's key. §7.4's "nonce plus identity binding" is met by
(a) that identity proof and (b) the exchange nonce echo — so a forged candidate
that reaches *some* peer but not the *expected* one fails closed, and the seam
returns nil → relay fallback. In the go impl: `conn.Session().RemotePeerID` after
`PerformConnect` MUST equal the peer the punch targeted.
