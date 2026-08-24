package signaling

import (
	"crypto/rand"
	"sort"

	"go.entitychurch.org/entity-core-go/core/types"
)

// The §3 coordination messages — what actually rides through the node as opaque
// blobs. The node sees only the 33-byte key and an opaque blob; it never decodes
// any of this (§3 "carrier-agnostic").
//
// This package builds and reads the three wire shapes (via the core/types
// structs) and owns the two pieces of §4 step 3 that are pure, cross-peer-
// observable computation: fire_at's clock domain (§4.1) and PunchDelay. Actually
// measuring RTT and firing are socket work — Stage 2, not here. Nothing in this
// package writes tree state: candidates are session-scoped and ephemeral and
// MUST NOT be persisted as durable transport profiles (§5.4).

// Candidate class tags (§4). host is cheapest and tried first; srflx is the
// hole-punch target; relay is the metered always-works fallback, tried last.
const (
	CandidateHost  = "host"
	CandidateSRFLX = "srflx"
	CandidateRelay = "relay"
)

// Substrate tags (§5). Only tcp ships in v1; quic/webrtc are declared but unbuilt.
const (
	SubstrateTCP    = "tcp"
	SubstrateQUIC   = "quic"
	SubstrateWebRTC = "webrtc"
)

// PunchDelayFloorMs is the default floor in §4.1's d = max(rtt, 250 ms). It is a
// local tunable, not a wire constant — two peers may hold different floors
// without failing to meet; they may not differ on the clock domain or encoding.
const PunchDelayFloorMs uint64 = 250

// classRank gives the §4 dial-class ordering: host → srflx → relay. An unknown
// class sorts LAST (rank 3) rather than being dropped — MUST-ignore means a peer
// that learns a new class from a newer impl still tries what it understands
// first, not refuses the whole message.
func classRank(candidateType string) int {
	switch candidateType {
	case CandidateHost:
		return 0
	case CandidateSRFLX:
		return 1
	case CandidateRelay:
		return 2
	default:
		return 3
	}
}

// OrderForDialing orders a candidate list for dialing: class first (host → srflx
// → relay), then priority ascending, then address for a total order. "First pair
// that completes a connectivity check wins" (§4), so this ordering IS the dial
// plan, and it is deterministic to the last tiebreak on purpose — two peers that
// order differently waste attempts crossing at different candidates. Returns a
// new slice; the input is not mutated.
func OrderForDialing(candidates []types.NATCandidateData) []types.NATCandidateData {
	ordered := make([]types.NATCandidateData, len(candidates))
	copy(ordered, candidates)
	sort.SliceStable(ordered, func(i, j int) bool {
		ri, rj := classRank(ordered[i].Type), classRank(ordered[j].Type)
		if ri != rj {
			return ri < rj
		}
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].Address < ordered[j].Address
	})
	return ordered
}

// GenerateNonce returns 16 random bytes — enough that two concurrent exchanges
// in one lobby bucket will not collide. The nonce is a correlator, not a secret
// (§4.5): anyone who can collect the bucket can read and echo it.
func GenerateNonce() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// PunchDelay derives the fire_at delay from the measured carrier round-trip
// (§4.1): d = max(rtt, 250 ms). rttMs is the round trip THROUGH the carrier
// (A's offer to the collect that returns B's response) — the only latency
// estimate either peer has, since neither can yet reach the other directly. The
// MUST it enforces: d ≥ the one-way carrier latency (rtt/2), below which B's
// fire time has already elapsed on arrival. d ≥ rtt implies d ≥ rtt/2, so the
// guarantee holds for any floor.
func PunchDelay(rttMs uint64) uint64 {
	if rttMs > PunchDelayFloorMs {
		return rttMs
	}
	return PunchDelayFloorMs
}
