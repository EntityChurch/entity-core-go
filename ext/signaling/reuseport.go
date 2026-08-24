package signaling

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// The §7.3 substrate: TCP simultaneous-open needs the punch to dial from the
// SAME local endpoint whose NAT mapping was observed by the reflector (§6.7.3 /
// EXTENSION-NETWORK §6.7.3). A NAT allocates a mapping per local socket, so a
// srflx candidate is meaningful ONLY for the socket that produced it. On TCP
// that shared local port is "not satisfiable by discipline" — it is the socket
// options SO_REUSEADDR + SO_REUSEPORT plus an explicit LocalAddr bind on both
// the reflector dial and the punch dial.
//
// This file is the platform-agnostic seam; reusePortControl is defined per-GOOS
// (reuseport_supported.go via golang.org/x/sys/unix on the unix-likes,
// reuseport_unsupported.go a stub elsewhere). For an implementer in another
// language, the interoperable requirement is only the shared-local-port binding;
// the exact sockopt spelling is platform-local and MAY diverge (§7.2 / §7.3).
//
// WHY THIS IS A SOCKET OPTION AND NOT DISCIPLINE. On UDP/QUIC "dial from the
// endpoint the reflector observed" is one socket reused, and costs nothing. On
// TCP it cannot be bought with careful sequencing at all, for two independent
// reasons: the reflector connection must CLOSE before the punch can dial, and
// re-binding that same local port is refused without SO_REUSEADDR; and the
// §7.1 step-4 crossing wants that one port to DIAL and LISTEN concurrently
// (see listenReusePort below), which is refused without SO_REUSEPORT. So the
// requirement is SO_REUSEADDR + SO_REUSEPORT plus an explicit LocalAddr bind
// on BOTH the reflector dial and the punch dial — no ordering, retry, or
// hold-open trick substitutes for the options.
//
// AND THE FAILURE WEARS ANOTHER FAILURE'S COSTUME. A srflx gathered on one
// ephemeral socket and punched from another is a hole that will never open,
// but the symptom is only "the punch didn't land" — indistinguishable from a
// mistimed open, whose fire_at delay is a sanctioned local tunable and so is
// the tempting thing to adjust. On a first cross-implementation punch failure,
// bisect the socket binding before touching the timing.
//
// Resolve SO_REUSEPORT from the platform's own headers, never as a literal:
// the constant is 0x0F on Linux and 0x0200 on macOS/*BSD, and Windows has no
// SO_REUSEPORT at all (its SO_REUSEADDR is the nearest analogue). The value is
// not on the wire, so two peers need not agree on it. A platform without the
// option is conformant-DEGRADED, not broken: it simply cannot offer the
// direct-path optimization, and ErrReusePortUnsupported below routes it to the
// §10 relay fallback.

// ErrReusePortUnsupported is returned by the punch transport on a platform where
// SO_REUSEPORT is not wired. The §7.3 same-socket TCP punch cannot be honored
// without it, so the coordinator treats this as "no live path" and falls through
// to the relay fallback (§10) — never a hard failure.
var ErrReusePortUnsupported = errors.New("signaling: SO_REUSEPORT not supported on this platform")

// dialReusePort dials remote over TCP from the bound local address with
// SO_REUSEADDR/SO_REUSEPORT set, so the reflector dial and the punch dial can
// share one local port — and therefore one NAT mapping (§7.3). local carries the
// exact host:port the reflector dial used; the punch MUST reuse it or the srflx
// candidate it advertised is "a hole that will never open" (§6.7.3).
//
// A nil local lets the OS pick the port (used only by the sockopt-path test);
// the punch always passes the reflector socket's own local address.
func dialReusePort(ctx context.Context, local *net.TCPAddr, remote string) (net.Conn, error) {
	d := net.Dialer{
		LocalAddr: local,
		Control:   reusePortControl,
	}
	return d.DialContext(ctx, "tcp", remote)
}

// DialReusePort is the exported default punch dialer — the same reuseport dial
// PunchParty uses when its Dial seam is nil. It is exported so a cmd-layer driver
// can wrap it (e.g. to record that this side fired an outbound dial for the §7.1
// step-4 both-fire cross-impl check) without reaching into the package: the
// wrapper taps the call and delegates here for the real SO_REUSEPORT dial.
func DialReusePort(ctx context.Context, local *net.TCPAddr, remote string) (net.Conn, error) {
	return dialReusePort(ctx, local, remote)
}

// DialReflector opens a reflector connection for §6.7.1 observe-address discovery
// from a REUSEADDR/REUSEPORT-bound local socket, and reports the concrete local
// address it bound. The reflector observes the NAT mapping of THAT socket, so the
// srflx candidate it yields is meaningful only for that local endpoint: the caller
// MUST dial the subsequent punch from the same address (pass the returned
// *net.TCPAddr as PunchParty.LocalAddr, §6.7.3 / §7.3). REUSEPORT is exactly what
// lets the punch re-bind that port after this connection closes.
//
// The OS picks the local port (nil bind); the observed mapping and the returned
// LocalAddr necessarily agree because they are the one socket. On a platform
// without the sockopt this returns a wrapped ErrReusePortUnsupported, which the
// caller maps to "no srflx — host candidates only," never a hard failure.
func DialReflector(ctx context.Context, reflector string) (net.Conn, *net.TCPAddr, error) {
	conn, err := dialReusePort(ctx, nil, reflector)
	if err != nil {
		return nil, nil, err
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		conn.Close()
		return nil, nil, fmt.Errorf("signaling: reflector dial local addr is %T, want *net.TCPAddr", conn.LocalAddr())
	}
	return conn, local, nil
}

// listenReusePort listens on local with SO_REUSEADDR/SO_REUSEPORT set, so the
// SAME local port that dials the peer can also accept the peer's dial. Pure TCP
// simultaneous-open (both sides only dialing) only connects when both sockets
// are in SYN_SENT at the crossing instant — fragile; listening as well means a
// peer's dial always lands rather than being refused between our dial attempts.
// Both sides dialing is still what opens both NAT holes (§7.1 step 4); the
// listener just catches the surviving direction. Returns ErrReusePortUnsupported
// (wrapped) on a platform without the sockopt.
func listenReusePort(local *net.TCPAddr) (net.Listener, error) {
	lc := net.ListenConfig{Control: reusePortControl}
	return lc.Listen(context.Background(), "tcp", local.String())
}
