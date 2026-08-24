package signaling

import (
	"crypto/rand"
	"sort"

	"go.entitychurch.org/entity-core-go/core/types"
)

// The §6 coordination messages — what actually rides through the node as opaque
// blobs. The node sees only the 33-byte key and an opaque blob; it never decodes
// any of this (§6.2 "carrier opacity").
//
// This package builds and reads the three wire shapes (via the core/types
// structs) and owns the two pieces of §7.1 step 3 that are pure, cross-peer-
// observable computation: fire_at's clock domain (§7.2) and PunchDelay. Actually
// measuring RTT and firing are socket work — Stage 2, not here. Nothing in this
// package writes tree state: candidates are session-scoped and ephemeral and
// MUST NOT be persisted as durable transport profiles (EXTENSION-NETWORK §6.7.3).
//
// The candidate class/substrate tags and try-order rank are NOT redefined here:
// the coordination messages carry system/network/candidate (§6.1 → EXTENSION-
// NETWORK §6.7.3), so the canonical constants (types.CandidateType*,
// types.CandidateSubstrate*) and ordering (types.CandidatePriority) live in
// core/types/reachability.go and are reused, one canonical home per fact.

// PunchDelayFloorMs is the default floor in §7.2's d = max(rtt, 250 ms). It is a
// local tunable, not a wire constant — two peers may hold different floors
// without failing to meet; they may not differ on the clock domain or encoding.
const PunchDelayFloorMs uint64 = 250

// OrderForDialing orders a candidate list for dialing: class first (host → srflx
// → relay, via types.CandidatePriority), then address for a total order. "First
// pair that completes a connectivity check wins" (§7.1), so this ordering IS the
// dial plan, and it is deterministic to the last tiebreak on purpose — two peers
// that order differently waste attempts crossing at different candidates. An
// unknown class sorts LAST (CandidatePriority rank 3) rather than being dropped —
// MUST-ignore means a peer that learns a new class from a newer impl still tries
// what it understands first, not refuses the whole message. Returns a new slice;
// the input is not mutated.
func OrderForDialing(candidates []types.NetworkCandidateData) []types.NetworkCandidateData {
	ordered := make([]types.NetworkCandidateData, len(candidates))
	copy(ordered, candidates)
	sort.SliceStable(ordered, func(i, j int) bool {
		ri, rj := types.CandidatePriority(ordered[i].Type), types.CandidatePriority(ordered[j].Type)
		if ri != rj {
			return ri < rj
		}
		return ordered[i].Address < ordered[j].Address
	})
	return ordered
}

// GenerateNonce returns 16 random bytes — enough that two concurrent exchanges
// in one lobby bucket will not collide. The nonce is a correlator, not a secret
// (§6.4): anyone who can collect the bucket can read and echo it.
func GenerateNonce() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// PunchDelay derives the fire_at delay from the measured carrier round-trip
// (§7.2): d = max(rtt, 250 ms). rttMs is the round trip THROUGH the carrier
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
