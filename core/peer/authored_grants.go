package peer

import (
	"sync"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The receive half of EXTENSION-SIGNALING §6.5 (b) "Wielding" under the arch
// 977667f carriage ruling.
//
// The ruling's two phases are:
//
//	(1) Delivery  — dialer→acceptor, once, post-handshake.
//	(2) Wielding  — acceptor→dialer, per origination: the outbound EXECUTE
//	    carries the §7a.2a triple AS REFERENCES (cap hash / dialer granter-id
//	    hash / dialer signature hash), and "the dialer resolves and verifies
//	    all three from its own content store, because it authored them" — the
//	    chain is not re-inlined per origination.
//
// This file is phase (2)'s RECEIVE side only. It makes a referenced grant
// resolvable here; it does not change what this peer SENDS. That split is
// deliberate — see docs/validation/spec-issues/ for why the send side is
// held, and note that landing this alone is invisible on the wire: a
// counterpart that still inlines its chain (every shipped Go and Rust peer
// today) never reaches the lookup, because the cap is already in `included`.
//
// # Why this is not a content-store lookup
//
// The ruling says "from its own content store." Implemented literally — resolve
// any stored cap by hash — that would let a counterpart wield a cap it was
// minted but never received: naming the hash would replace holding the entity,
// and DELIVERY would stop being a precondition for authority. The grantee ==
// author check still binds a cap to the peer it names, so this is not an
// escalation to a third party; but it does erase the distinction between "we
// minted this for you" and "you hold this," which is the distinction a
// mint-then-send-fails path depends on (sendReciprocalGrant treats a send
// failure as "counterpart stays unauthorized").
//
// So the set here is exactly what this peer minted AND put on the wire, keyed
// by the cap hash the counterpart would name. Same resolution power the ruling
// asks for, without making every stored cap nameable. The routed spec issue
// asks arch to pin which of the two readings is normative.
type authoredGrantSet struct {
	mu sync.RWMutex
	// byCapHash maps a minted reciprocal cap's content hash to the entities a
	// chain walk over it needs: the cap itself, the granter identity (ours),
	// and the granter signature.
	byCapHash map[hash.Hash]map[hash.Hash]entity.Entity
}

// reciprocalCapEntity picks the capability token out of a grant frame built by
// protocol.BuildReentryGrantEnvelope. That builder puts exactly one there; the
// second-hit guard keeps a future builder change from silently registering the
// wrong entity as the wieldable cap.
func reciprocalCapEntity(grantEnv entity.Envelope) (entity.Entity, bool) {
	var found entity.Entity
	var ok bool
	for _, ent := range grantEnv.Included {
		if ent.Type != types.TypeCapToken {
			continue
		}
		if ok {
			return entity.Entity{}, false
		}
		found, ok = ent, true
	}
	return found, ok
}

// record registers a reciprocal grant this peer minted and sent. supporting is
// the grant frame's own included set — cap + signature + granter identity —
// which is already exactly the triple a chain walk needs.
//
// capHash is the minted cap's content hash: the value the counterpart puts in
// its EXECUTE's `capability` field when it wields by reference.
func (s *authoredGrantSet) record(capHash hash.Hash, supporting map[hash.Hash]entity.Entity) {
	if capHash.IsZero() || len(supporting) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byCapHash == nil {
		s.byCapHash = make(map[hash.Hash]map[hash.Hash]entity.Entity)
	}
	entities := make(map[hash.Hash]entity.Entity, len(supporting))
	for h, ent := range supporting {
		entities[h] = ent
	}
	s.byCapHash[capHash] = entities
}

// supply resolves a referenced capability hash to the entities needed to walk
// its chain, reporting whether this peer authored a reciprocal grant under it.
//
// The returned map is a copy: it is merged into a verification-time envelope,
// and handing out the live map would let a caller mutate authority state.
func (s *authoredGrantSet) supply(capHash hash.Hash) (map[hash.Hash]entity.Entity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entities, ok := s.byCapHash[capHash]
	if !ok {
		return nil, false
	}
	out := make(map[hash.Hash]entity.Entity, len(entities))
	for h, ent := range entities {
		out[h] = ent
	}
	return out, true
}
