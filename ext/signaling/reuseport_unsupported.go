//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package signaling

import "syscall"

// reusePortControl on a platform where SO_REUSEPORT is not wired (notably
// Windows, whose port-reuse model differs — SO_REUSEADDR there behaves closer to
// REUSEPORT and belongs in a dedicated windows file when that platform is
// brought up). Fails closed with ErrReusePortUnsupported so the coordinator
// falls through to the relay fallback (§10) rather than attempting a punch that
// cannot honor the §6.7.3 same-socket MUST.
func reusePortControl(network, address string, c syscall.RawConn) error {
	return ErrReusePortUnsupported
}
