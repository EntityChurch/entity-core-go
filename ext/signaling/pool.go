package signaling

import (
	"bytes"
	"crypto/sha256"
	"sort"
)

// Provider selection — which node of a pool a peer talks to (§3.1.1).
//
// Both peers of a handshake MUST meet at the same provider, for every key mode.
// A mismatch is a silent never-meet exactly like a key-derivation mismatch, so
// §3.1.1 pins all four free variables of the highest-random-weight family:
//
//	weight(k, endpoint) = SHA-256( k ‖ endpoint_bytes )
//	server              = argmax over the tier, weights compared lexicographically
//
//   - k is the 33-byte rendezvous key EXACTLY as derived (§2.2) — the same bytes
//     that go on the wire, not a re-hash.
//   - endpoint_bytes are the advertised string exactly as published: no
//     normalization, no case-folding, no scheme/default-port canonicalization.
//   - No separator — k is fixed at 33 bytes, so the concatenation is unambiguous.
//     (NOT the missing-separator bug §2.2 had to fix in pair.)
//   - Highest weight wins; ties break to the LOWER endpoint. A tie is a SHA-256
//     collision away, but argmax alone is not a total order.
//   - Plain crypto/sha256, NOT the substrate content-hash primitive — a
//     format-carrying digest would reintroduce §2.2's home-format divergence.
//   - priority PARTITIONS before the hash runs: take the lowest tier PRESENT,
//     then rendezvous-hash within it. Hashing first and filtering after is not
//     tiering.
//
// A one-member pool cannot validate any of this: argmax over one member returns
// it whatever the weight computes. The gate needs two instances with DIFFERENT
// endpoint strings (§4.2, PROPOSAL-CONNECTION-NODE §6 step 2).

// PoolMember is one node of a signaling service pool, as a client holds it from
// the deployment's advertisement: an endpoint string and its priority tier. The
// endpoint is the identity the weight is computed over, so it must be the
// advertised string byte-for-byte — normalizing it weights a different string
// and lands on a different member.
type PoolMember struct {
	Endpoint string
	Priority uint32
}

// SkewFanout is §3.1's "try your top-2" stale-pool-skew breadth.
const SkewFanout = 2

// weight is the per-member weight SHA-256(k ‖ endpoint_bytes), compared
// lexicographically over the 32 digest bytes with highest winning (§3.1.1).
func weight(key []byte, endpoint string) [32]byte {
	h := sha256.New()
	h.Write(key)
	h.Write([]byte(endpoint))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// lowestTier returns the lowest priority value present in the pool. The bool is
// false for an empty pool. It is the lowest tier PRESENT, not a fixed number —
// a pool whose tier-0 members are all withdrawn falls through to tier 1.
func lowestTier(pool []PoolMember) (uint32, bool) {
	if len(pool) == 0 {
		return 0, false
	}
	tier := pool[0].Priority
	for _, m := range pool[1:] {
		if m.Priority < tier {
			tier = m.Priority
		}
	}
	return tier, true
}

// Select picks the member both peers will independently pick for key, in two
// steps and in this order (§3.1.1): partition to the lowest priority tier
// present, then rendezvous-hash within it. Ties break on the endpoint string
// (byte-wise, lower wins) so the result is total and deterministic even under a
// reordered advertisement. The bool is false for an empty pool — a deployment
// that advertises no signaling service offers no rendezvous, a fact for the
// caller to surface rather than paper over.
func Select(key []byte, pool []PoolMember) (PoolMember, bool) {
	tier, ok := lowestTier(pool)
	if !ok {
		return PoolMember{}, false
	}
	var best PoolMember
	var bestW [32]byte
	found := false
	for _, m := range pool {
		if m.Priority != tier {
			continue
		}
		w := weight(key, m.Endpoint)
		if !found {
			best, bestW, found = m, w, true
			continue
		}
		switch cmp := bytes.Compare(w[:], bestW[:]); {
		case cmp > 0:
			best, bestW = m, w
		case cmp == 0 && m.Endpoint < best.Endpoint:
			best, bestW = m, w
		}
	}
	return best, found
}

// SelectTop returns the top n members in descending weight within the lowest
// tier — the §3.1 stale-pool-skew mitigation. With n = SkewFanout (2), two
// peers whose advertisements differ by at most one member still have
// intersecting choice sets. It ranks within the lowest tier only, exactly as
// Select does, so SelectTop(key, pool, 1) always agrees with Select. A
// single-member tier yields one choice however large n is.
func SelectTop(key []byte, pool []PoolMember, n int) []PoolMember {
	tier, ok := lowestTier(pool)
	if !ok || n <= 0 {
		return nil
	}
	type ranked struct {
		w [32]byte
		m PoolMember
	}
	var rs []ranked
	for _, m := range pool {
		if m.Priority == tier {
			rs = append(rs, ranked{weight(key, m.Endpoint), m})
		}
	}
	// Descending weight, then ascending endpoint — the same total order Select
	// uses, so SelectTop(..., 1) and Select always agree.
	sort.Slice(rs, func(i, j int) bool {
		if c := bytes.Compare(rs[i].w[:], rs[j].w[:]); c != 0 {
			return c > 0
		}
		return rs[i].m.Endpoint < rs[j].m.Endpoint
	})
	if n > len(rs) {
		n = len(rs)
	}
	out := make([]PoolMember, n)
	for i := 0; i < n; i++ {
		out[i] = rs[i].m
	}
	return out
}
