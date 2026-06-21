package attestation

import (
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// DefaultMaxChainDepth is the default upper bound on chain-walk depth per
// §5.1. Consumers MAY pass a different limit to WalkAttestingChain;
// implementations SHOULD provide bounded-depth walks per §9.2.
const DefaultMaxChainDepth = 32

// FindAttestationsTargeting returns all indexed attestations whose
// `attested` field equals entityHash AND match `predicate`. Predicate is
// consumer-supplied for filtering by properties.kind, properties.function,
// storage-path scope, etc. Per §5.4.
//
// `predicate` is called with the attestation hash and the decoded data.
// Predicate-supplied filtering avoids re-decoding attestations the consumer
// already loaded. Pass nil for "all attestations".
func FindAttestationsTargeting(
	cs store.ContentStore,
	ix *Index,
	entityHash hash.Hash,
	predicate func(attHash hash.Hash, att types.AttestationData) bool,
) []AttestationRef {
	candidates := ix.FindByAttested(entityHash)
	return collectMatching(cs, candidates, predicate)
}

// FindAttestationsBy returns all indexed attestations whose `attesting`
// field equals peerHash AND match `predicate`. Per §5.5.
func FindAttestationsBy(
	cs store.ContentStore,
	ix *Index,
	peerHash hash.Hash,
	predicate func(attHash hash.Hash, att types.AttestationData) bool,
) []AttestationRef {
	candidates := ix.FindByAttesting(peerHash)
	return collectMatching(cs, candidates, predicate)
}

// FindRevocationsFor returns the hashes of all attestations whose
// `attested` equals attestationHash AND whose properties.kind equals
// "revocation". Per §5.6. The consumer applies its own authority rules to
// determine which revocations are valid.
func FindRevocationsFor(ix *Index, attestationHash hash.Hash) []hash.Hash {
	// Use the kind index for selectivity; intersect against attested.
	kindCandidates := ix.FindByKind(types.KindRevocation)
	if len(kindCandidates) == 0 {
		return nil
	}
	attestedSet := make(map[hash.Hash]struct{})
	for _, h := range ix.FindByAttested(attestationHash) {
		attestedSet[h] = struct{}{}
	}
	var out []hash.Hash
	for _, h := range kindCandidates {
		if _, ok := attestedSet[h]; ok {
			out = append(out, h)
		}
	}
	return out
}

// FindAttestationsWithSupersedes returns all attestations whose `supersedes`
// field equals predecessorHash. Inverse of the supersedes pointer; used by
// liveness checks and forward-chain walks (FindLiveHead). Per §5.6a.
func FindAttestationsWithSupersedes(ix *Index, predecessorHash hash.Hash) []hash.Hash {
	return ix.FindBySupersedes(predecessorHash)
}

// FindAttestationsWithKind returns all attestations whose properties.kind
// equals kindValue. Per §5.6b.
func FindAttestationsWithKind(ix *Index, kindValue string) []hash.Hash {
	return ix.FindByKind(kindValue)
}

// AttestationRef pairs an attestation's content hash with its decoded data.
// Returned by FindAttestationsTargeting / FindAttestationsBy so callers
// don't have to re-decode each candidate.
type AttestationRef struct {
	Hash hash.Hash
	Data types.AttestationData
}

func collectMatching(
	cs store.ContentStore,
	candidates []hash.Hash,
	predicate func(hash.Hash, types.AttestationData) bool,
) []AttestationRef {
	var out []AttestationRef
	for _, h := range candidates {
		att, err := loadAttestation(cs, h)
		if err != nil {
			continue
		}
		if predicate != nil && !predicate(h, att) {
			continue
		}
		out = append(out, AttestationRef{Hash: h, Data: att})
	}
	return out
}

// WalkSupersedesChain walks the supersedes pointer back to the oldest
// version. Returns the chain [start, prev, prev_prev, ..., original]. Per
// §5.2. Stops when supersedes is nil or the predecessor is not in the
// content store (chain broken; returns what we have).
func WalkSupersedesChain(
	cs store.ContentStore,
	startHash hash.Hash,
	start types.AttestationData,
) []AttestationRef {
	chain := []AttestationRef{{Hash: startHash, Data: start}}
	current := start
	for current.Supersedes != nil {
		prev, err := loadAttestation(cs, *current.Supersedes)
		if err != nil {
			break
		}
		chain = append(chain, AttestationRef{Hash: *current.Supersedes, Data: prev})
		current = prev
	}
	return chain
}

// FindLiveHead walks the supersedes-DAG forward from `start` and returns
// the live head — the (unique-modulo-tie-break) attestation in the forward
// chain that is currently live. Returns ok=false if no live attestation
// exists in the forward chain. Per §5.3.
//
// Implementation note: under the transitive supersession semantics
// (IsAttestationLive walks forward to find effectively-live descendants —
// see the SI-2 note in liveness.go), the live head must be located by
// enumerating the forward DAG and applying the predicate to each node.
// The earlier direct-successor recursion would break on chains > 2 where
// the head is a grandchild — direct successors look "dead" in the new
// semantics, but their descendants are alive.
//
// Tie-break across multiple live candidates (rare — at most one node
// should be effectively live in a well-formed chain): (NotBefore desc,
// content_hash asc) for cross-impl determinism.
func FindLiveHead(
	cs store.ContentStore,
	li store.LocationIndex,
	ix *Index,
	startHash hash.Hash,
	start types.AttestationData,
	asOf uint64,
) (hash.Hash, types.AttestationData, bool) {
	visited := make(map[hash.Hash]struct{})
	var liveCandidates []AttestationRef
	var walk func(h hash.Hash, att types.AttestationData)
	walk = func(h hash.Hash, att types.AttestationData) {
		if _, seen := visited[h]; seen {
			return
		}
		visited[h] = struct{}{}
		if IsAttestationLive(cs, li, ix, h, att, asOf) {
			liveCandidates = append(liveCandidates, AttestationRef{Hash: h, Data: att})
		}
		for _, succHash := range ix.FindBySupersedes(h) {
			succ, err := loadAttestation(cs, succHash)
			if err != nil {
				continue
			}
			walk(succHash, succ)
		}
	}
	walk(startHash, start)

	if len(liveCandidates) == 0 {
		return hash.Hash{}, types.AttestationData{}, false
	}
	best := liveCandidates[0]
	for _, c := range liveCandidates[1:] {
		if successorWins(c, best) {
			best = c
		}
	}
	return best.Hash, best.Data, true
}

// pickLiveSuccessor selects deterministically among live successors:
// most-recent NotBefore wins; ties broken by lowest content_hash.
func pickLiveSuccessor(succs []AttestationRef) AttestationRef {
	best := succs[0]
	for _, s := range succs[1:] {
		if successorWins(s, best) {
			best = s
		}
	}
	return best
}

func successorWins(a, b AttestationRef) bool {
	an := uint64(0)
	if a.Data.NotBefore != nil {
		an = *a.Data.NotBefore
	}
	bn := uint64(0)
	if b.Data.NotBefore != nil {
		bn = *b.Data.NotBefore
	}
	if an != bn {
		return an > bn
	}
	return hashLess(a.Hash, b.Hash)
}

// TerminatePredicate is invoked by WalkAttestingChain at each link to decide
// whether the walk has reached its end. Consumer-supplied per §5.1.
type TerminatePredicate func(att AttestationRef) bool

// FindAuthorizingFn returns the attestation that authorizes the given peer
// in the consumer's graph, or (zero, false) when none exists. Used by
// WalkAttestingChain to walk back via attesting; consumers MAY override the
// default implementation per §5.1 for non-standard graphs.
type FindAuthorizingFn func(peerHash hash.Hash) (AttestationRef, bool)

// DefaultFindAuthorizing implements the normative algorithm from §5.1. Given
// a peer hash, finds the attestation that authorizes it within the
// attestation graph: candidates are attestations targeting the peer; live
// ones are reduced to live heads of their supersedes chains; the lowest-
// content_hash wins when multiple distinct live heads exist.
//
// This is the right default for identity, group, VC issuance, and most
// consumers. Consumers expecting multi-context peers (the same peer
// authorized under two unrelated identities) SHOULD pass a custom
// FindAuthorizingFn that filters by their own context per the §5.1
// "multi-context peers note".
func DefaultFindAuthorizing(
	cs store.ContentStore,
	li store.LocationIndex,
	ix *Index,
	asOf uint64,
) FindAuthorizingFn {
	return func(peerHash hash.Hash) (AttestationRef, bool) {
		candidates := FindAttestationsTargeting(cs, ix, peerHash, nil)
		var live []AttestationRef
		for _, c := range candidates {
			if IsAttestationLive(cs, li, ix, c.Hash, c.Data, asOf) {
				live = append(live, c)
			}
		}
		if len(live) == 0 {
			return AttestationRef{}, false
		}

		// Resolve to live heads of their supersedes chains.
		seen := make(map[hash.Hash]struct{})
		var heads []AttestationRef
		for _, c := range live {
			headHash, headData, ok := FindLiveHead(cs, li, ix, c.Hash, c.Data, asOf)
			if !ok {
				continue
			}
			if _, dup := seen[headHash]; dup {
				continue
			}
			seen[headHash] = struct{}{}
			heads = append(heads, AttestationRef{Hash: headHash, Data: headData})
		}
		if len(heads) == 0 {
			return AttestationRef{}, false
		}
		if len(heads) == 1 {
			return heads[0], true
		}

		// Multiple distinct live heads — deterministic tie-break by lowest
		// content_hash.
		best := heads[0]
		for _, h := range heads[1:] {
			if hashLess(h.Hash, best.Hash) {
				best = h
			}
		}
		return best, true
	}
}

// WalkAttestingChain walks back via `attesting` until the consumer-supplied
// terminate predicate matches. Returns the chain [start, ..., terminating]
// or false when no chain terminates within maxDepth. Per §5.1.
//
// Termination semantics (per v1.1 §5.1, SI-8): when terminate(current)
// returns true, the chain terminates with `current` included as the last
// element. `chain[-1]` IS the cert at which the predicate matched;
// `chain[-1].Data.Attesting` is the predicate's target value (e.g., the
// quorum_id for identity's IdentityIsQuorumLink predicate). The walker
// does NOT advance one further step after the predicate matches.
//
// findAuthorizing locates the attestation that authorizes a given peer; pass
// DefaultFindAuthorizing(cs, li, ix, asOf) for the normative behavior, or a
// custom function for consumer-specific topologies.
//
// maxDepth defaults to DefaultMaxChainDepth when zero.
func WalkAttestingChain(
	startHash hash.Hash,
	start types.AttestationData,
	terminate TerminatePredicate,
	findAuthorizing FindAuthorizingFn,
	maxDepth int,
) ([]AttestationRef, bool) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxChainDepth
	}
	chain := []AttestationRef{{Hash: startHash, Data: start}}
	current := AttestationRef{Hash: startHash, Data: start}
	for depth := 0; depth < maxDepth; depth++ {
		if terminate(current) {
			return chain, true
		}
		parent, ok := findAuthorizing(current.Data.Attesting)
		if !ok {
			return nil, false
		}
		chain = append(chain, parent)
		current = parent
	}
	return nil, false
}
