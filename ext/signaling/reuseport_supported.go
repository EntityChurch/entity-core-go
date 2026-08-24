//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package signaling

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortControl sets SO_REUSEADDR + SO_REUSEPORT on the socket fd before
// bind/connect, on the unix-likes where golang.org/x/sys/unix exports
// SO_REUSEPORT. Wired as the net.Dialer Control hook (§7.3). Both options are
// load-bearing: REUSEADDR lets the port be re-bound while a prior mapping
// lingers; REUSEPORT lets the reflector dial and the punch dial hold the same
// local port at once, which is the whole point (a single NAT mapping shared by
// both) — see reuseport.go.
//
// golang.org/x/sys is already in the module graph (an indirect dep of
// x/crypto / x/net), so this promotes an existing, Go-team-maintained module to
// a direct import and adds no new module to go.sum. unix.SO_REUSEPORT resolves
// to the per-GOOS constant (Linux 0x0F, Darwin/BSD 0x0200) — which is exactly
// why the constant is not hardcoded here.
func reusePortControl(network, address string, c syscall.RawConn) error {
	var sockErr error
	ctrlErr := c.Control(func(fd uintptr) {
		if sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); sockErr != nil {
			return
		}
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return sockErr
}
