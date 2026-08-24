package network

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// MappingClass is what several reflectors' §6.7.1 observations say about this
// peer's NAT mapping — the classification EXTENSION-SIGNALING §11.2 SHOULDs and
// §9.3 states as a MUST for concluding a NAT type at all ("a peer MUST consult
// several reflectors and require agreement before concluding a NAT type").
//
// It answers one question: is a punch worth attempting, or is this pair
// relay-only (§10)? It is local advice, never a wire value — nothing in the
// coordination protocol carries a NAT type, and no security decision rests on
// one (§6.7.1: "a single reflector is advisory, never trusted").
type MappingClass string

const (
	// MappingUnknown — not enough agreeing evidence to conclude anything. One
	// observation lands here BY RULE, not by accident: a lone reflector can be
	// wrong or lying, and §6.7.1 forbids concluding from it. Treat as "punch may
	// as well be attempted", not as a failure.
	MappingUnknown MappingClass = "unknown"

	// MappingOpen — the observed source equals the local bind: no NAT in path.
	// Directly reachable; the punch is trivial on this side.
	MappingOpen MappingClass = "open"

	// MappingEndpointIndependent — every reflector observed the SAME mapping for
	// this socket. The mapping does not depend on where the packet is going, so
	// the address advertised to a counterpart is the address that counterpart
	// will hit. This is the punchable class (cone).
	MappingEndpointIndependent MappingClass = "endpoint-independent"

	// MappingEndpointDependent — reflectors disagreed: the mapping differs per
	// destination (symmetric NAT). Whatever this peer advertises names a mapping
	// created for the REFLECTOR, not for the counterpart, so the counterpart's
	// dial arrives at a hole that was never opened for it. Punch will not
	// complete; prefer relay (§10 — Mode-S today, Mode-C when it exists).
	MappingEndpointDependent MappingClass = "endpoint-dependent"
)

// Punchable reports whether a punch is worth attempting on this class. Unknown
// is punchable on purpose: with too little evidence the correct move is to try
// and fall back, not to relay a pair that would have connected directly.
func (c MappingClass) Punchable() bool { return c != MappingEndpointDependent }

// Observation is one reflector's §6.7.1 answer for one local socket.
//
// The socket matters more than the reflector does: a mapping belongs to a
// socket (§6.7.3), so observations are only comparable when they came from the
// SAME local endpoint. Comparing two sockets' mappings classifies every NAT on
// earth as endpoint-dependent, because two sockets get two mappings even from
// the most permissive cone NAT. Gathering enforces that; this type records it.
type Observation struct {
	Reflector string // the reflector consulted (host:port)
	Observed  string // the source it reported seeing (host:port)
}

// MappingAssessment is the classification plus the evidence it rests on, so a
// caller can log or report WHY rather than a bare verdict. Per §11.5.1 a claim
// is scoped by its substrate: the assessment says what was observed, and the
// caller says where it was observed.
type MappingAssessment struct {
	Class        MappingClass
	Mapping      string // the agreed mapping; set only when all observations agree
	Reason       string // one line, quoting the divergence when there is one
	Observations []Observation
}

// ClassifyMapping classifies a socket's NAT mapping from several reflectors'
// observations of THAT socket (§6.7.1 "NAT-type detection falls out for free":
// agreement ⇒ endpoint-independent ⇒ punchable; disagreement ⇒ the mapping
// differs per destination ⇒ symmetric ⇒ prefer relay).
//
// localAddr is the socket's own bind address, used only to separate "no NAT at
// all" from "a NAT that maps consistently"; pass "" to skip that distinction.
// Malformed observations are not silently dropped — an unparseable address is a
// reflector bug or a lie, and either way it must not be averaged into a verdict.
func ClassifyMapping(localAddr string, obs []Observation) MappingAssessment {
	a := MappingAssessment{Observations: obs}

	switch len(obs) {
	case 0:
		a.Class, a.Reason = MappingUnknown, "no reflector observations"
		return a
	case 1:
		// The §6.7.1/§9.3 MUST, enforced rather than commented: one reflector is
		// advisory. The observation is still a usable srflx CANDIDATE — it just
		// cannot conclude a NAT TYPE, and those are different claims.
		a.Class = MappingUnknown
		a.Reason = fmt.Sprintf("one reflector (%s observed %s) — a single reflector is advisory, never a NAT-type conclusion (§6.7.1)",
			obs[0].Reflector, obs[0].Observed)
		return a
	}

	ports := map[string][]string{} // port -> reflectors reporting it
	ips := map[string][]string{}   // ip   -> reflectors reporting it
	for _, o := range obs {
		host, port, err := net.SplitHostPort(o.Observed)
		if err != nil {
			a.Class = MappingUnknown
			a.Reason = fmt.Sprintf("reflector %s reported an unparseable address %q: %v", o.Reflector, o.Observed, err)
			return a
		}
		ports[port] = append(ports[port], o.Reflector)
		ips[host] = append(ips[host], o.Reflector)
	}

	// Port divergence is the classic symmetric signature: the NAT allocates a
	// fresh mapping per destination, so the port a counterpart would have to dial
	// was never the port any reflector saw.
	if len(ports) > 1 {
		a.Class = MappingEndpointDependent
		a.Reason = fmt.Sprintf("mapped port differs per destination (%s) — symmetric NAT; a punch dials a mapping that was never opened for the counterpart (§6.7.1), prefer relay (§10)",
			describeSplit(ports))
		return a
	}

	// Same port, different public IP: an egress-address pool (a NAT farm picking
	// a source IP per destination). Rarer than port divergence and NOT the same
	// mechanism, but it defeats a punch for the same reason — the advertised
	// address is destination-specific — so it classifies together and says which
	// one it saw.
	if len(ips) > 1 {
		a.Class = MappingEndpointDependent
		a.Reason = fmt.Sprintf("mapped port agrees but the public IP differs per destination (%s) — egress-address pool; the advertised candidate is destination-specific, prefer relay (§10)",
			describeSplit(ips))
		return a
	}

	a.Mapping = obs[0].Observed
	if localAddr != "" && localAddr == a.Mapping {
		a.Class = MappingOpen
		a.Reason = fmt.Sprintf("%d reflectors agree on %s, which is this socket's own bind address — no NAT in path", len(obs), a.Mapping)
		return a
	}
	a.Class = MappingEndpointIndependent
	a.Reason = fmt.Sprintf("%d reflectors agree on %s — the mapping does not depend on the destination, so the advertised candidate is what the counterpart will hit",
		len(obs), a.Mapping)
	return a
}

// describeSplit renders "20001 (r1, r2) vs 41337 (r3)" — the divergence itself,
// because "reflectors disagreed" is not a diagnosis and this is what a report or
// a log line has to carry to be actionable.
func describeSplit(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s (%s)", k, strings.Join(m[k], ", ")))
	}
	return strings.Join(parts, " vs ")
}
