package validate

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// EXTENSION-NETWORK §6.7.1 MUST 2 — the observed address MUST NOT be persisted
// to any durable per-peer address field.
//
// WHY THIS CHECK EXISTS, AND WHY ITS ABSENCE WAS A REAL HOLE
//
// Go writes no responder-side `system/connection` entity, so Go has never been
// at risk of violating this. That is exactly what made it a coverage hole
// rather than a non-issue: the category stayed green three ways while nothing
// in the suite would have caught an implementation that DID persist it, and
// three impls were free to diverge invisibly. It is the same shape as v8's
// key-form blind spot — a green check measuring a property nobody was testing.
//
// The spec is unusually explicit about why the wrong thing is tempting
// (§6.7.1 MUST 2's own note): `system/connection/{peer_id}` is the record an
// implementer reaches for first — keyed by peer, carrying an `address` field,
// already reachable from the handler — and it is wrong twice. Its `address`
// means *the endpoint I dial to reach this peer* and is written dialer-side;
// an ephemeral source port written there is a routable-LOOKING value that
// routes nowhere, and both §10 dispatch and `system/peer/status` consume that
// field as dialable. The cheap fix corrupts dispatch for every other reader.
//
// WHAT THIS CHECK DOES
//
// It asks the peer for our observed address, then reads back every binding
// under the three durable surfaces the MUST names and scans the ENTITY BYTES
// for that literal value. A raw-byte scan rather than a field-by-field
// comparison is deliberate: the MUST says "any durable per-peer address
// field", so an implementation that invents its own field name must not slip
// through a check that only knew about `address`.
//
// Absence of the surface is conformant and passes — but the report distinguishes
// three states that a single "clean" verdict would blur: surfaces we enumerated
// and scanned, surfaces that would not enumerate (404 absent vs 403 denied — the
// status says which, and they are NOT the same claim), and a sweep truncated by
// the path cap. "We looked and found nothing" must never read the same as "we
// could not look."

// reachPersistenceSurfaces are the three durable homes §6.7.1 MUST 2 names.
var reachPersistenceSurfaces = []string{
	"system/connection",     // ENTITY-CORE-PROTOCOL §3.13 — the tempting one
	"system/peer/status",    // §6.5 liveness view; consumes address as dialable
	"system/peer/transport", // §6.5.1 transport profiles
}

// reachScanMaxPaths bounds the sweep. The surfaces are small by construction
// (one record per known peer, a handful of profiles); the cap exists so a peer
// with a large transport tree cannot turn one check into a long walk.
const reachScanMaxPaths = 256

// collectTreePaths walks a prefix breadth-first and returns every bound leaf
// path under it. Listings give one level, so nesting
// (`system/peer/transport/{peer}/{profile}`) needs the walk.
// Returns truncated=true when the cap was hit, so the caller can SAY the sweep
// was bounded. A silent cap reads as "we covered everything" when it did not.
func collectTreePaths(ctx context.Context, client *PeerClient, prefix string) (paths []string, truncated bool, err error) {
	var out []string
	queue := []string{prefix}
	seen := map[string]bool{prefix: true}

	for len(queue) > 0 && len(out) < reachScanMaxPaths {
		cur := queue[0]
		queue = queue[1:]

		entries, _, err := client.TreeListing(ctx, strings.TrimRight(cur, "/")+"/")
		if err != nil {
			// Only the ROOT of a surface failing tells us the surface is
			// unreadable; a child that will not list is just a leaf.
			if cur == prefix {
				return nil, false, err
			}
			continue
		}
		for name, meta := range entries {
			child := cur + "/" + name
			if seen[child] {
				continue
			}
			seen[child] = true
			out = append(out, child)
			// Recurse where the listing says there are children.
			if m, ok := meta.(map[string]interface{}); ok {
				if hc, ok := m["has_children"].(bool); ok && hc {
					queue = append(queue, child)
				}
			}
			if len(out) >= reachScanMaxPaths {
				break
			}
		}
	}
	sort.Strings(out)
	// The cap is a bound on the WALK; report it so a truncated sweep is never
	// mistaken for an exhaustive one.
	return out, len(out) >= reachScanMaxPaths, nil
}

// runReachabilityObservedNotPersisted implements the §6.7.1 MUST 2 check.
func runReachabilityObservedNotPersisted(ctx context.Context, client *PeerClient, observed string) CheckOutcome {
	if observed == "" {
		return SkipCheck(
			"observe-address did not yield an observed address (§12.3 makes §6.7 optional as a whole), so there is " +
				"no value to look for. Skip rather than Pass: nothing about persistence was exercised.")
	}
	needle := []byte(observed)
	// The host alone is far too weak a needle on loopback (every address is
	// 127.0.0.1), and the port alone collides with unrelated integers. The
	// full "host:port" string is what MUST 2 forbids storing, and it is what
	// we search for.
	// net.SplitHostPort, not strings.Cut: an IPv6 observed address is
	// "[::1]:51820" and cutting on the FIRST colon yields "[" — nonsense in the
	// failure message a peer would be handed. Only used for reporting, so a
	// parse failure falls back to the raw value rather than failing the check.
	host, port, splitErr := net.SplitHostPort(observed)
	if splitErr != nil {
		host, port = observed, "?"
	}

	// CONTROL NEEDLE — proof the scan is reading content, not pointers.
	//
	// A byte-scan that silently reads the wrong thing passes forever, which is
	// the failure mode this whole check exists to close; it must not reproduce
	// it. Our own peer-id is a value the responder plausibly records about the
	// connection it is currently serving (`system/peer/status.peer_id` carries
	// it in plaintext), so locating it proves the scan sees entity data.
	//
	// Not a gate, deliberately: a peer that records nothing about us is
	// perfectly conformant, and turning that into a failure would manufacture
	// exactly the kind of false finding this repo has withdrawn before. When
	// the control is absent we still pass, and we say the scan could not be
	// positively verified on this peer.
	//
	// (This caught a wrong assumption on its first run: the responder's status
	// records describe OTHER peers, so the responder's own id is not in them.)
	control := []byte(client.LocalPeerID())

	var (
		readable     []string
		unenumerable []string
		truncated    []string
		hits         []string
		scanned      int
		controlFound bool
	)

	for _, surface := range reachPersistenceSurfaces {
		paths, trunc, err := collectTreePaths(ctx, client, surface)
		if err != nil {
			unenumerable = append(unenumerable, fmt.Sprintf("%s (%v)", surface, err))
			continue
		}
		if trunc {
			truncated = append(truncated, surface)
		}
		readable = append(readable, fmt.Sprintf("%s (%d path(s))", surface, len(paths)))
		for _, p := range paths {
			ent, raw, err := client.TreeGet(ctx, p)
			if err != nil {
				continue
			}
			scanned++
			if bytes.Contains(ent.Data, needle) || bytes.Contains(raw, needle) {
				hits = append(hits, p)
			}
			if len(control) > 0 && (bytes.Contains(ent.Data, control) || bytes.Contains(raw, control)) {
				controlFound = true
			}
		}
	}

	if len(hits) > 0 {
		return FailCheck(fmt.Sprintf(
			"the observed address %q appears in %d durable binding(s) on the responder: %v. EXTENSION-NETWORK §6.7.1 "+
				"MUST 2: an observed source address MUST NOT be persisted to any durable per-peer address field — not "+
				"system/connection.address, not a system/peer/transport/* profile, not system/peer/status. It is a "+
				"RESPONDER-side fact; every durable address field in this spec is DIALER-side dialable-endpoint state. "+
				"An ephemeral source port (%s port %s) written there is a routable-LOOKING value that routes nowhere, "+
				"and both §10 dispatch and system/peer/status consume that field as dialable — so this corrupts "+
				"dispatch for every other reader, not just this operation. It is also insufficient on its own terms: "+
				"§6.7.3's mapping is PER SOCKET, and one record per peer cannot express it. Read the address from the "+
				"live connection and return it; do not store it",
			observed, len(hits), hits, host, port))
	}

	if len(readable) == 0 {
		return SkipCheck(fmt.Sprintf(
			"none of the §6.7.1 MUST 2 surfaces were readable on this peer (%v) — the observed address %q could not "+
				"be looked for. Skip rather than Pass: an unreadable surface is an uninspected one, and this check "+
				"must never report compliance it did not measure",
			unenumerable, observed))
	}

	if scanned == 0 {
		return SkipCheck(fmt.Sprintf(
			"the §6.7.1 MUST 2 surfaces listed but held no readable entities (%s), so the observed address %q was "+
				"never compared against anything. Skip rather than Pass: zero bytes inspected is not compliance",
			strings.Join(readable, ", "), observed))
	}

	detail := fmt.Sprintf(
		"the observed address %q appears in NO durable binding: scanned %d entit(ies) across %s",
		observed, scanned, strings.Join(readable, ", "))
	if len(unenumerable) > 0 {
		// NOT labelled "absent": a 404 means the surface does not exist (which is
		// conformant), but a 403 means we were denied and therefore did not look.
		// The error text carries the status; do not launder one into the other.
		detail += fmt.Sprintf("; not enumerable — absent or access-denied, the status says which: %v", unenumerable)
	}
	if len(truncated) > 0 {
		detail += fmt.Sprintf("; SWEEP TRUNCATED at %d paths on %v — coverage of those surfaces is partial",
			reachScanMaxPaths, truncated)
	}
	if controlFound {
		detail += ". Scan verified live: a control value known to be present (our own peer-id) WAS located in the " +
			"same bytes, so the absence of the observed address is a measurement and not a blind read"
	} else {
		detail += ". NOTE: the control value (our own peer-id) was not located, so this peer appears to record " +
			"nothing about us — conformant, but it means the scan could not be positively verified here"
	}
	return PassCheck(detail + ". §6.7.1 MUST 2 holds — the observed source is read from the live connection and " +
		"returned, not stored as dialer-side state")
}
