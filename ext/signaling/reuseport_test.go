package signaling

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// §7.3: the reflector dial and the punch dial must share ONE local port so they
// share ONE NAT mapping. This proves the SO_REUSEPORT path directly: a second
// dial that binds a local port already held by a live connection succeeds ONLY
// because REUSEPORT is set — without it the bind fails with EADDRINUSE. The two
// dials go to DIFFERENT remotes (distinct 4-tuples), which is exactly the punch
// shape: same local port, one leg to the reflector, one to the peer.
func TestReusePortDialSharesLocalPortAcrossRemotes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reflector := mustAcceptOnce(t) // stands in for the §6.7.1 reflector
	peer := mustAcceptOnce(t)      // stands in for the far peer's srflx

	// Leg 1 — the "reflector" dial: OS picks the local port P.
	c1, err := dialReusePort(ctx, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, reflector)
	if err != nil {
		if errors.Is(err, ErrReusePortUnsupported) {
			t.Skip("SO_REUSEPORT not supported on this platform")
		}
		t.Fatalf("reflector-leg dial: %v", err)
	}
	defer c1.Close()
	p := c1.LocalAddr().(*net.TCPAddr).Port

	// Leg 2 — the "punch" dial: bind the SAME local port P to a DIFFERENT remote.
	c2, err := dialReusePort(ctx, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}, peer)
	if err != nil {
		t.Fatalf("punch-leg dial binding shared local port %d: %v (REUSEPORT not honored?)", p, err)
	}
	defer c2.Close()

	if got := c2.LocalAddr().(*net.TCPAddr).Port; got != p {
		t.Fatalf("punch leg bound local port %d, want the shared %d", got, p)
	}
}

// TestDialReflectorLocalAddrIsPunchReusable proves the exported §6.7.1 reflector
// dial reports the exact local address the punch must re-bind: the returned
// *net.TCPAddr equals the connection's own LocalAddr, and a punch-leg dial to a
// DIFFERENT remote binds that same local port (only REUSEPORT makes this bind
// succeed while the reflector conn is still live). This is the §7.3 same-socket
// contract at the API the srflx gatherer consumes.
func TestDialReflectorLocalAddrIsPunchReusable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reflector := mustAcceptOnce(t)
	peer := mustAcceptOnce(t)

	conn, local, err := DialReflector(ctx, reflector)
	if err != nil {
		if errors.Is(err, ErrReusePortUnsupported) {
			t.Skip("SO_REUSEPORT not supported on this platform")
		}
		t.Fatalf("DialReflector: %v", err)
	}
	defer conn.Close()

	if got := conn.LocalAddr().(*net.TCPAddr); got.Port != local.Port {
		t.Fatalf("reported local port %d != conn.LocalAddr port %d", local.Port, got.Port)
	}

	// The punch re-binds `local` toward the peer while the reflector conn is live.
	punch, err := dialReusePort(ctx, local, peer)
	if err != nil {
		t.Fatalf("punch leg re-binding reflector local %s: %v (same-socket reuse broken)", local, err)
	}
	defer punch.Close()

	if got := punch.LocalAddr().(*net.TCPAddr).Port; got != local.Port {
		t.Fatalf("punch bound local port %d, want the reflector's %d", got, local.Port)
	}
}

// mustAcceptOnce starts a loopback TCP listener that accepts and holds one
// connection for the duration of the test, and returns its dial address.
func mustAcceptOnce(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Hold it open until the test ends so the 4-tuple stays live.
		t.Cleanup(func() { conn.Close() })
	}()
	return ln.Addr().String()
}
