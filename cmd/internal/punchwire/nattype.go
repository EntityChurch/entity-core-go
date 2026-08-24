package punchwire

import (
	"context"
	"fmt"
	"net"

	"go.entitychurch.org/entity-core-go/core/peer"
	extnetwork "go.entitychurch.org/entity-core-go/ext/network"
)

// DetectMapping consults several §6.7.1 reflectors about ONE local socket and
// classifies the NAT mapping (EXTENSION-SIGNALING §11.2 SHOULD; §9.3 states the
// several-reflectors requirement as a MUST before concluding a NAT type).
//
// This is the G4 precheck. Two cone NATs punch; a symmetric NAT on either side
// does not, and the punch fails late, at the crossing, looking exactly like a
// counterpart that never showed up. Running this first turns a wasted crossing
// budget — and, on real hardware, a wasted trip — into a classification with the
// divergence quoted in it.
//
// # The rule that makes the result mean anything
//
// EVERY reflector is dialed from the SAME pinned local endpoint, because a
// mapping belongs to a socket (§6.7.3). Consult two reflectors from two sockets
// and a perfectly punchable cone NAT reports two different ports — the exact
// signature of the symmetric NAT this is looking for. There is no way to detect
// that mistake downstream: the observations are well-formed and the verdict is
// confidently wrong. Hence `local` is a parameter, not something each dial picks.
//
// Dials are sequential rather than concurrent, for two reasons that are both
// about not lying: concurrent dials from one REUSEPORT socket are legal but make
// the conntrack state a race, and the caller usually re-binds `local` for the
// punch the moment this returns, so each connection must be closed before the
// next begins.
//
// A reflector that fails is skipped, not fatal — reflectors are untrusted
// infrastructure (§6.7.1) and one being down is an ordinary Tuesday. The per-
// reflector errors are returned alongside the assessment so a caller reports
// what it could not reach instead of quietly concluding from a smaller sample.
// With fewer than two successes the assessment is MappingUnknown by §6.7.1's own
// rule, which is the honest answer, not a degraded one.
func DetectMapping(ctx context.Context, p *peer.Peer, local *net.TCPAddr, reflectors []string) (extnetwork.MappingAssessment, []error) {
	var (
		obs  []extnetwork.Observation
		errs []error
		seen = make(map[string]bool, len(reflectors))
	)
	for _, r := range reflectors {
		if r == "" {
			continue
		}
		// The same reflector twice is one observation, not agreement: it would
		// manufacture the very consensus §6.7.1 requires be independent.
		if seen[r] {
			errs = append(errs, fmt.Errorf("reflector %s listed more than once — one reflector cannot corroborate itself", r))
			continue
		}
		seen[r] = true

		observed, err := ObserveSRFLXFrom(ctx, p, local, r)
		if err != nil {
			errs = append(errs, fmt.Errorf("reflector %s: %w", r, err))
			continue
		}
		obs = append(obs, extnetwork.Observation{Reflector: r, Observed: observed})
	}
	return extnetwork.ClassifyMapping(local.String(), obs), errs
}
