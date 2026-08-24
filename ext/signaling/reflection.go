package signaling

import (
	"fmt"
	"strconv"
	"strings"
)

// ValidateReflectionEndpoint checks that s is a well-formed RFC 7064 STUN URI in
// the shape EXTENSION-SIGNALING §4.5.1 pins for `reflection_endpoints` (added
// v1.1). The rule is intentionally identical to EXTENSION-REGISTRY §3b.0 — the
// two fields describe the same kind of thing and MUST NOT differ in shape.
//
// The pinned form is NON-HIERARCHICAL:
//
//   - scheme is `stun:` (STUN over UDP/TCP) or `stuns:` (STUN over TLS);
//   - there is NO `//` authority separator — `stun://host:3478` is invalid;
//   - a bare `host:3478` with no scheme is invalid;
//   - the host is required; the port is optional and, if present, is 1..65535.
//
// Why validate at configuration time rather than let the node emit anything: a
// browser hands each entry to RTCIceServer.urls VERBATIM (§4.5.1), and a
// malformed entry does not degrade to host-candidates-only — it throws at
// RTCPeerConnection construction and takes the establisher down with it. The
// node deliberately emits its configured endpoints unchanged (publishing the
// final form is the whole point — no consumer runs a transform), so the form has
// to be right before it is published. Callers (e.g. the entity-peer
// --reflection-endpoint flag) should reject a malformed value at startup with
// the error this returns, not silently drop or "fix" it.
func ValidateReflectionEndpoint(s string) error {
	var host string
	switch {
	case strings.HasPrefix(s, "stuns:"):
		host = s[len("stuns:"):]
	case strings.HasPrefix(s, "stun:"):
		host = s[len("stun:"):]
	default:
		return fmt.Errorf("reflection endpoint %q: must begin with the RFC 7064 scheme %q or %q", s, "stun:", "stuns:")
	}
	if strings.HasPrefix(host, "//") {
		return fmt.Errorf("reflection endpoint %q: RFC 7064 STUN URIs are non-hierarchical — there is no %q (§4.5.1)", s, "//")
	}
	if host == "" {
		return fmt.Errorf("reflection endpoint %q: host is required after the scheme", s)
	}

	// Split an OPTIONAL trailing :port, honoring an IPv6 literal's own colons by
	// requiring bracket form (`[::1]` / `[::1]:3478`) — RFC 3986 host syntax as
	// RFC 7064 inherits it. A bracketed literal is well-formed as long as the
	// bracket closes; only the segment after the closing bracket is the port.
	var portStr string
	hasPort := false
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return fmt.Errorf("reflection endpoint %q: unterminated IPv6 literal — missing %q", s, "]")
		}
		if end == 1 {
			return fmt.Errorf("reflection endpoint %q: empty IPv6 literal", s)
		}
		rest := host[end+1:]
		if rest != "" {
			if rest[0] != ':' {
				return fmt.Errorf("reflection endpoint %q: unexpected %q after IPv6 literal", s, rest)
			}
			portStr, hasPort = rest[1:], true
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		if i == 0 {
			return fmt.Errorf("reflection endpoint %q: host is required before the port", s)
		}
		hostPart := host[:i]
		// An unbracketed host part MUST NOT itself contain a colon. Two malformed
		// shapes reach here, both of which RFC 3986 host syntax (which RFC 7064
		// inherits) forbids and a browser's URL parser rejects:
		//   - an unbracketed IPv6 literal, e.g. `stun:2001:db8::1` — IPv6 MUST be
		//     bracketed (`stun:[2001:db8::1]`), else host and port are ambiguous;
		//   - a doubled scheme, e.g. `stun:stun:relay.example:3478` — §4.5.1 names
		//     the doubled `stun:stun:` prefix as THE failure mode this pinning
		//     exists to foreclose (a prepending consumer applied twice).
		// Refuse both: a config that starts a Go node must not fail a sibling's.
		if strings.ContainsRune(hostPart, ':') {
			return fmt.Errorf("reflection endpoint %q: host %q contains a colon — an IPv6 literal MUST be bracketed as [%s], and a URI carries exactly one scheme (§4.5.1 names the doubled `stun:stun:` prefix as the failure mode)", s, hostPart, hostPart)
		}
		portStr, hasPort = host[i+1:], true
	}
	if hasPort {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("reflection endpoint %q: port %q must be an integer in 1..65535", s, portStr)
		}
	}
	return nil
}
