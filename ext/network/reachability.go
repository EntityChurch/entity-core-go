package network

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Reachability facts — EXTENSION-NETWORK §6.7 (Amendment 13).
//
//   - observe-address (§6.7.1): reflect the transport source of the connection
//     the request arrived on — the requester's public NAT mapping. Never a
//     body-echoed value (MUST 1); never persisted durably (MUST 2).
//   - check-reachability (§6.7.2): dial back the requester's OWN observed
//     source and report whether it arrived. Never a body-supplied target (the
//     load-bearing anti-DDoS-reflector MUST); rate-limited, fixed-size.
//
// Both facts ride from the accepted connection (protocol.ConnectionState.
// ObservedAddress, set responder-side at accept), not from request params —
// which is what structurally forecloses the body-supplied-address attack: the
// handlers read no address from the body at all.

// dialbackTimeout bounds a single §6.7.2 dial-back probe. A bare TCP connect
// is the minimal zero-amplification "did it arrive" test; it is closed
// immediately on success (no payload sent → no amplification factor).
const dialbackTimeout = 3 * time.Second

// reflectMinInterval / dialbackMinInterval are the per-requester rate limits
// (§6.7.4 — both operations are "always rate-limited"; dial-back the more
// tightly, since it causes the responder to emit traffic).
const (
	reflectMinInterval  = 200 * time.Millisecond
	dialbackMinInterval = 1 * time.Second
)

// rateLimiter is a minimal per-requester min-interval gate. Local operational
// concern (not protocol-deterministic), so it reads the wall clock directly.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     map[crypto.PeerID]time.Time
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{interval: interval, last: make(map[crypto.PeerID]time.Time)}
}

// allow reports whether a call from requester is permitted now, recording the
// time when it is. Empty requester (in-process) is never rate-limited.
func (r *rateLimiter) allow(requester crypto.PeerID) bool {
	if r == nil || requester == "" {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if prev, ok := r.last[requester]; ok && now.Sub(prev) < r.interval {
		return false
	}
	r.last[requester] = now
	return true
}

// observedSourceFor extracts the accept-side observed transport source of the
// connection this request arrived on. Empty (ok=false) for in-process /
// initiator-side dispatch where there is no accepted transport source.
func observedSourceFor(req *handler.Request) (string, bool) {
	if req == nil || req.Context == nil {
		return "", false
	}
	cs, ok := req.Context.ConnectionState.(*protocol.ConnectionState)
	if !ok || cs == nil || cs.ObservedAddress == "" {
		return "", false
	}
	return cs.ObservedAddress, true
}

// requesterOf returns the peer to rate-limit against: the session peer that
// holds the connection (placement identity, §6.7.4 per-requester), falling
// back to the wire author.
func requesterOf(req *handler.Request) crypto.PeerID {
	if req == nil || req.Context == nil {
		return ""
	}
	if req.Context.SessionPeerID != "" {
		return req.Context.SessionPeerID
	}
	return req.Context.Author
}

// handleObserveAddress implements §6.7.1: reflect the transport source of THIS
// connection. The value is read from the accepted connection and returned; it
// is never taken from the request body (MUST 1) and never persisted (MUST 2).
func (h *Handler) handleObserveAddress(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	if !h.reflectLimiter.allow(requesterOf(req)) {
		return handler.NewErrorResponse(429, "rate_limited", "observe-address is rate-limited per requester (§6.7.4)")
	}
	observed, ok := observedSourceFor(req)
	if !ok {
		return handler.NewErrorResponse(400, "no_transport_source",
			"observe-address requires a live accepted connection; there is no observable transport source for an in-process dispatch")
	}
	resp, err := handler.NewResponse(200, types.TypeNetworkObserveAddressResult,
		types.ObserveAddressResultData{ObservedAddress: observed})
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "encode observe-address-result: "+err.Error())
	}
	return resp, nil
}

// handleCheckReachability implements §6.7.2 dial-back: dial the requester's OWN
// observed source and report whether it arrived. The target is the observed
// source and NEVER a body-supplied address (the anti-reflector MUST); the
// handler reads no address from params. Rate-limited per requester, fixed-size,
// bounded timeout — no amplification factor.
func (h *Handler) handleCheckReachability(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	if !h.dialbackLimiter.allow(requesterOf(req)) {
		return handler.NewErrorResponse(429, "rate_limited", "check-reachability is rate-limited per requester (§6.7.2 MUST)")
	}
	observed, ok := observedSourceFor(req)
	if !ok {
		return handler.NewErrorResponse(400, "no_transport_source",
			"check-reachability requires a live accepted connection to dial back")
	}
	reachable := dialBack(ctx, observed)
	resp, err := handler.NewResponse(200, types.TypeNetworkCheckReachabilityResult,
		types.CheckReachabilityResultData{Reachable: reachable, AddressTested: observed})
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "encode check-reachability-result: "+err.Error())
	}
	return resp, nil
}

// dialBack attempts a bounded TCP connect to the observed source and reports
// whether it arrived. A bare connect (closed immediately, no payload) is the
// minimal zero-amplification probe. Honours the request context deadline,
// capped at dialbackTimeout.
func dialBack(ctx context.Context, observed string) bool {
	d := net.Dialer{Timeout: dialbackTimeout}
	dialCtx, cancel := context.WithTimeout(ctx, dialbackTimeout)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", observed)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// GatherCandidates gathers and types this peer's reachability candidates
// (§6.7.3), returned in the try order host → srflx → relay. It only gathers and
// types — nothing here sends a candidate to another peer; exchange is the
// punch-coordination protocol (§6.7.3, deliberately not in NETWORK).
//
// host candidates come from the local non-loopback unicast interface addresses
// paired with localPort. srflx is the §6.7.1 observed mapping (pass "" if not
// yet learned). relay is a configured public relay address (pass "" if none).
// All candidates are TCP-substrate here (the live-transport floor across the
// three impls, §6.5.1); QUIC/WebRTC substrates are added by the punch when it
// gathers on those sockets.
//
// srflx carries a MUST the caller — not this function — must honour: the peer
// MUST punch from the SAME local socket whose mapping was observed (§6.7.3).
// This function types the candidate; binding it to the punch socket is the
// punch's obligation.
func GatherCandidates(localPort int, srflx, relay string) []types.NetworkCandidateData {
	var cands []types.NetworkCandidateData
	for _, host := range localHostAddresses(localPort) {
		cands = append(cands, types.NetworkCandidateData{
			Address:   host,
			Type:      types.CandidateTypeHost,
			Substrate: types.CandidateSubstrateTCP,
		})
	}
	if srflx != "" {
		cands = append(cands, types.NetworkCandidateData{
			Address:   srflx,
			Type:      types.CandidateTypeSrflx,
			Substrate: types.CandidateSubstrateTCP,
		})
	}
	if relay != "" {
		cands = append(cands, types.NetworkCandidateData{
			Address:   relay,
			Type:      types.CandidateTypeRelay,
			Substrate: types.CandidateSubstrateTCP,
		})
	}
	SortCandidates(cands)
	return cands
}

// SortCandidates orders candidates by §6.7.3 try order (host → srflx → relay),
// stable within a type. Exported so the punch can re-sort a merged local+remote
// candidate set.
func SortCandidates(cands []types.NetworkCandidateData) {
	sort.SliceStable(cands, func(i, j int) bool {
		return types.CandidatePriority(cands[i].Type) < types.CandidatePriority(cands[j].Type)
	})
}

// localHostAddresses returns the peer's local non-loopback, non-link-local
// unicast IPs as host:port strings — the §6.7.3 `host` candidates (works when
// peers share a network). Loopback and link-local are excluded (not reachable
// across a real network); errors yield an empty set rather than a failure.
func localHostAddresses(port int) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		}
	}
	return out
}
