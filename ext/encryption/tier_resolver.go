package encryption

import (
	"errors"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The §4.4 tier-aware discovery ladder. Where tier_a_resolver.go answers
// "given a pubkey hash, is it still the live one," this answers the step
// before it: "given everything published in a recipient's namespace,
// WHICH pubkey should the sender bind."
//
// §4.4 pins the order — the sender does not know the recipient's tier in
// advance, so it walks the namespace highest-tier-first and takes the
// first tier that yields a live candidate:
//
//	1. Tier C — identity-cert attestations, function="encryption"
//	2. Tier B — encryption-key attestations over the inner pubkey
//	3. Tier A — the V7-signed pubkey entities directly
//	4. none   → 403 encryption_recipient_unknown
//
// "Highest-installed tier wins" is about the RECIPIENT's installation,
// not the sender's: a Tier-A sender resolving a Tier-C recipient walks
// the cert chain down to the inner pubkey hash and binds that. The wire
// carries no tier discriminator (§4.0) because every tier binds the same
// value — content_hash of the one authored inner pubkey entity. That is
// what makes cross-tier interop work at all, and it is why this resolver
// returns a hash rather than a tier-tagged reference.
//
// CARRIERS ARE NOT CANDIDATES (§4.4, ruled 2026-08-09-b). Each tier
// enumerates a tier-shaped *carrier* — a signed pubkey entity at Tier A,
// an attestation at Tiers B/C. Filtering is carrier-scoped; ordering is
// NOT. Surviving carriers are projected to the system/encryption-pubkey
// entity they publish or attest, and the order runs over those entities
// deduplicated by content_hash: two live carriers naming one pubkey are
// ONE candidate, because a device is a private-key holder, not a cert.
//
// The ordering keys therefore come from the PUBKEY entity and never from
// the carrier. That is forced, not chosen: system/attestation has no
// `created` field at all (EXTENSION-ATTESTATION §3.1), so ordering
// carriers by creation time is unimplementable, and ENCRYPTION may not
// mint a field into a type it does not own. The pubkey's `created` is
// hash input (§4.1), so it cannot move without changing the identity of
// the key it orders — a re-issued cert over an unchanged key does not
// reorder devices.
//
// Fetching stays the caller's concern, matching the Tier-A helpers: the
// caller lists the recipient namespace, decodes, and evaluates carrier
// validity (which needs the attestation graph and, at Tier C, identity's
// authority chain). This operates on the decoded set. Keeping I/O out
// means the ladder is testable against authored inputs, including the
// ones a live peer will not produce — which is what ENC-RESOLVE-ORDER-1
// (§16.6) is.

// ErrEncryptionRecipientUnknown carries the §4.4 step-4 / §15
// encryption_recipient_unknown error code: the sender walked every tier
// and found no live encryption-pubkey to bind.
var ErrEncryptionRecipientUnknown = errors.New(types.EncryptionErrRecipientUnknown)

// Tier names the §4.0 configuration tier a publication was found at.
type Tier string

const (
	TierA Tier = "A" // V7 floor — invariant-pointer-signed pubkey
	TierB Tier = "B" // +ATTESTATION — encryption-key attestation
	TierC Tier = "C" // +IDENTITY — identity-cert, function="encryption"
)

// Carrier is one tier-shaped publication found in a recipient's
// namespace: the thing that says "this pubkey is mine."
//
// Hash is the carrier's own content_hash — the attestation hash at Tiers
// B/C, and the pubkey entity's own hash at Tier A, where the carrier IS
// the pubkey entity and projection is the identity function. It is what
// a carrier-targeted revocation (§11.3) names.
//
// Pubkey is the content_hash of the system/encryption-pubkey entity this
// carrier publishes or attests (`attested` at Tiers B/C). This is the
// value the sender ultimately binds as recipient_key, and the value the
// candidate set is deduplicated by.
//
// Live is §4.4 liveness filter 1, carrier validity, and the caller
// computes it because it needs I/O this package deliberately does not
// do: at Tier A that the invariant-pointer system/signature verifies
// against the recipient's V7 peer_id; at Tiers B/C
// attestation.IsAttestationLive (which already covers not_before /
// expires_at / transitive supersession / self-revocation), plus at Tier
// C the identity authority chain walked to the quorum.
//
// A false Live is not an error and not a revocation — the carrier simply
// does not speak for this key right now.
type Carrier struct {
	Hash   hash.Hash
	Pubkey hash.Hash
	Live   bool
}

// PubkeyEntity carries the two §4.1 fields the order reads off the
// authored inner entity.
//
// Both are hash input, so the content_hash a PubkeyEntity is keyed by
// determines them: two carriers naming the same pubkey hash cannot
// disagree about `created`. Modelling them here rather than on Carrier
// is what makes that unrepresentable instead of merely untrue.
type PubkeyEntity struct {
	// Created is §4.1's authored publication timestamp — the primary
	// ordering key.
	Created uint64
	// Expires is §4.1's optional expiry. Zero means absent. When set, a
	// candidate with now >= Expires is dropped from SELECTION only; a
	// receiver MUST NOT refuse to decrypt because a bound key expired
	// (§4.1, ruled 2026-08-09-b). Expiry retires a key from selection,
	// revocation retires it from use.
	Expires uint64
}

// RecipientPublications is a sender's view of one recipient's namespace,
// gathered per §4.2.a/b/c. A tier the recipient does not run is simply
// empty — that is a valid configuration, not a defect (§4.0).
type RecipientPublications struct {
	// TierCRelationship is §4.4 step 1a — the per-relationship carriers a
	// sender finds under system/identity/relationships/{contact_id}/cert/,
	// where {contact_id} is the SENDER's own peer-identity hash (§4.3, the
	// subtree's audience is exactly one contact). Tier C is a two-step walk,
	// most-specific first `[MUST]`: this step is tried BEFORE TierC (1b, the
	// public handle), and a live candidate here ends the walk. An absent or
	// wholly-dead relationships subtree is NOT an error — it falls through to
	// 1b exactly as a tier falls through to the one below it.
	//
	// The two steps are separate candidate sets, never merged: a live
	// per-relationship key is bound over a NEWER live public key, because
	// "most-specific first" is precedence, not recency. Merging them into one
	// ordered set would silently pick the newer public key — the exact
	// divergence §4.4's step split exists to prevent.
	//
	// Populated only at Tier C; every lower tier leaves it nil, which is a
	// valid configuration (§4.0), not a defect.
	TierCRelationship []Carrier

	// TierC is §4.4 step 1b — the public identity certs under
	// system/identity/public/cert/, the only Tier-C shape a sender with no
	// prior relationship can reach. Walked after TierCRelationship.
	TierC []Carrier
	TierB []Carrier
	TierA []Carrier

	// Pubkeys maps an inner pubkey's content_hash to the authored entity
	// behind it. PRESENCE IS RETRIEVABILITY: §4.4 makes keeping the
	// attested inner entity readable a publisher MUST, because a sender
	// cannot encrypt to a key it cannot read — it needs public_key and
	// the suite arrays, not just a hash. A carrier whose pubkey is
	// absent here is dropped and the walk continues; it is not a
	// distinct error, because at the sending peer "publishes nothing,"
	// "publishes only revoked keys" and "publishes a key I cannot read"
	// are one fact: no bindable key.
	Pubkeys map[hash.Hash]PubkeyEntity

	// RevokedPubkeys names keys killed outright by a revocation
	// targeting the INNER PUBKEY hash (§11.1 at Tier A, the universal
	// revocation kind's §11.2 shape at any tier). The key is dead;
	// republication at a lower tier does not revive it, which is why
	// this is not per-tier.
	RevokedPubkeys map[hash.Hash]bool

	// RevokedCarriers names carriers killed by a revocation targeting
	// the CARRIER hash (§11.3). This kills only that carrier: the
	// candidate survives if any other live carrier still attests it.
	// Revoking a per-relationship cert MUST NOT retire the device's
	// public key — that case is exactly why the two granularities
	// cannot share a mechanism.
	RevokedCarriers map[hash.Hash]bool

	// Now is the sender's local clock in epoch milliseconds, used only
	// for the §4.1 `expires` filter. Zero disables the expiry filter
	// rather than treating every key as expired at the epoch — a caller
	// that forgot to set a clock must not silently resolve nothing.
	Now uint64
}

// Resolution is what the ladder concluded, including the tiers it looked
// at and rejected, and why candidates were dropped — so a caller can
// tell "the recipient publishes nothing" from "the recipient publishes
// only revoked keys" from "I could not read the key it publishes."
// Those are different facts. §4.4 makes them ONE error on the wire and
// says an implementation SHOULD distinguish them in its own diagnostics;
// this is that.
type Resolution struct {
	Pubkey hash.Hash
	Tier   Tier

	// Examined lists tiers that held at least one carrier, in walk
	// order. A tier appears here even when everything in it was dropped.
	Examined []Tier

	Dropped DropCounts
}

// DropCounts breaks down what the walk discarded, by §4.4 filter.
type DropCounts struct {
	// CarrierInvalid is filter 1: the carrier does not verify, is
	// expired/superseded/self-revoked, or fails identity's chain.
	CarrierInvalid int
	// CarrierRevoked is filter 2, carrier granularity (§11.3).
	CarrierRevoked int
	// PubkeyRevoked is filter 2, pubkey granularity (§11.1 / §11.2),
	// counted per distinct key rather than per carrier.
	PubkeyRevoked int
	// Expired is filter 3: the pubkey entity's own §4.1 `expires`.
	Expired int
	// Unretrievable is the §4.4 retrievability MUST: a live carrier
	// named a pubkey whose authored entity could not be read.
	Unretrievable int
}

// Total reports how many distinct things the walk dropped.
func (d DropCounts) Total() int {
	return d.CarrierInvalid + d.CarrierRevoked + d.PubkeyRevoked + d.Expired + d.Unretrievable
}

// IsRevoked reports whether the inner pubkey hash carries a
// pubkey-granularity revocation.
func (p RecipientPublications) IsRevoked(pubkey hash.Hash) bool {
	return p.RevokedPubkeys[pubkey]
}

// candidate is one deduplicated inner pubkey, after projection.
type candidate struct {
	pubkey  hash.Hash
	created uint64
}

// ResolveRecipientKey walks the §4.4 ladder and returns the pubkey hash a
// sender should bind, together with the tier it resolved at.
//
// Within a tier: carriers are filtered (validity, carrier-targeted
// revocation), projected to the pubkeys they name, deduplicated, then the
// candidate-level filters run (pubkey-targeted revocation,
// retrievability, expiry) and the survivors are ordered.
//
// A tier that is non-empty but wholly dead does NOT terminate the walk
// (§4.4 MUST): "try tier N" means *did tier N yield a live candidate*,
// not *did tier N publish anything*. A recipient whose Tier-C certs are
// all revoked and whose Tier-A pubkey is live resolves at Tier A. This is
// deliberately unlike ResolveCurrentRecipient, which DOES hard-fail on a
// revoked key — there the caller named a specific key and that key is
// dead; here the caller asked "who is this recipient," and a dead
// publication is simply not an answer.
//
// Tier C is itself TWO steps, most-specific first (§4.4 step 1a/1b `[MUST]`):
// TierCRelationship (the per-relationship cert this sender was handed) is
// walked before TierC (the public handle), and a live per-relationship
// candidate is bound even over a NEWER live public one — precedence, not
// recency. The two are separate candidate sets, never merged; a wholly-dead
// per-relationship step falls through to the public step exactly as one tier
// falls through to the next. Both resolve at Tier C.
func ResolveRecipientKey(pubs RecipientPublications) (Resolution, error) {
	res := Resolution{}
	ladder := []struct {
		tier     Tier
		carriers []Carrier
	}{
		{TierC, pubs.TierCRelationship}, // §4.4 step 1a — per-relationship, most-specific first
		{TierC, pubs.TierC},             // §4.4 step 1b — the public handle
		{TierB, pubs.TierB},
		{TierA, pubs.TierA},
	}

	for _, rung := range ladder {
		if len(rung.carriers) == 0 {
			continue
		}
		// Tier C spans two rungs (1a then 1b); record the tier once so a
		// caller reading Examined sees "Tier C was walked," not the sub-steps.
		if n := len(res.Examined); n == 0 || res.Examined[n-1] != rung.tier {
			res.Examined = append(res.Examined, rung.tier)
		}

		// Project surviving carriers onto the keys they name, preserving
		// first-seen order so the pre-order pass is deterministic. (The
		// final pick is a total order and would be deterministic either
		// way; determinism here keeps the drop counts stable too.)
		var projected []hash.Hash
		seen := make(map[hash.Hash]bool, len(rung.carriers))
		for _, c := range rung.carriers {
			if !c.Live {
				res.Dropped.CarrierInvalid++
				continue
			}
			if pubs.RevokedCarriers[c.Hash] {
				res.Dropped.CarrierRevoked++
				continue
			}
			if seen[c.Pubkey] {
				// A second live carrier over a key already claimed. Not a
				// drop — this is the dedup that makes two certs over one
				// device one candidate.
				continue
			}
			seen[c.Pubkey] = true
			projected = append(projected, c.Pubkey)
		}

		var live []candidate
		for _, pk := range projected {
			if pubs.RevokedPubkeys[pk] {
				res.Dropped.PubkeyRevoked++
				continue
			}
			ent, ok := pubs.Pubkeys[pk]
			if !ok {
				res.Dropped.Unretrievable++
				continue
			}
			if ent.Expires != 0 && pubs.Now != 0 && pubs.Now >= ent.Expires {
				res.Dropped.Expired++
				continue
			}
			live = append(live, candidate{pubkey: pk, created: ent.Created})
		}
		if len(live) == 0 {
			continue
		}

		best := live[0]
		for _, c := range live[1:] {
			if c.created > best.created ||
				(c.created == best.created && winsTieBreak(c.pubkey, best.pubkey)) {
				best = c
			}
		}
		res.Pubkey, res.Tier = best.pubkey, rung.tier
		return res, nil
	}

	if res.Dropped.Total() > 0 {
		return res, fmt.Errorf("%w: recipient publishes no live encryption-pubkey "+
			"(dropped: %d carrier-invalid, %d carrier-revoked, %d key-revoked, %d expired, %d unretrievable)",
			ErrEncryptionRecipientUnknown,
			res.Dropped.CarrierInvalid, res.Dropped.CarrierRevoked,
			res.Dropped.PubkeyRevoked, res.Dropped.Expired, res.Dropped.Unretrievable)
	}
	return res, fmt.Errorf("%w: recipient publishes no encryption-pubkey at any tier",
		ErrEncryptionRecipientUnknown)
}

// winsTieBreak orders two pubkey hashes when `created` cannot separate
// them, per the §4.4 order ruled 2026-08-09 (arch `a19234e`) with its
// inputs pinned 2026-08-09-b (`f855793`):
//
//  1. `created` DESCENDING  — newest publication first
//  2. `content_hash` ASCENDING, compared as raw bytes — the tie-break
//
// The bytes are the FULL authored content_hash — the multihash-prefixed
// form (1-byte format code ‖ digest, 33 bytes under SHA-256), not the
// bare digest. That is Hash.Bytes(), never EffectiveDigest(), and it is
// byte-for-byte the value the sender goes on to bind as recipient_key
// (§7.4 step 1, R5 / F-PY-ENC-2) — the tie-break key and the bound key
// are the same bytes, so there is nothing left to choose. Under a single
// algorithm the two forms agree; they diverge only in a mixed-algorithm
// set, reachable the moment SHA-384 is active.
//
// Direction matters and we had it backwards: this shipped as descending
// (greater wins) until the ruling pinned ascending. Byte-comparison was
// the right instinct — total, deterministic across languages, computable
// without parsing — but "arbitrary" applies to the CHOICE of rule, never
// to whether every implementation applies the same one.
//
// What a divergence costs, which is why it is pinned rather than left to
// implementations: two senders resolving the same recipient silently pick
// different keys. Nothing errors at the sender — it encrypts successfully,
// to a key the reader did not expect. At Tier C it is sharper still,
// because §4.4's multi-device rule makes the receiving agent whoever holds
// the private half of the chosen key: divergent tie-breaks route
// ciphertext to different DEVICES, every peer behaving correctly, the
// message arriving somewhere the user is not looking.
//
// Timestamps alone cannot carry this: clock granularity makes ties
// reachable, and two keys minted in the same millisecond is the normal
// case for a scripted multi-device enrolment, not a rare one.
func winsTieBreak(candidate, incumbent hash.Hash) bool {
	c, i := candidate.Bytes(), incumbent.Bytes()
	for n := 0; n < len(c) && n < len(i); n++ {
		if c[n] != i[n] {
			return c[n] < i[n]
		}
	}
	// A proper prefix sorts first.
	return len(c) < len(i)
}
