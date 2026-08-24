package encryption

import (
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// testHash builds a distinguishable ECFv1-SHA-256 hash from a seed byte.
func testHash(seed byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = 0
	for i := range h.Digest {
		h.Digest[i] = seed
	}
	return h
}

// live builds a Tier-A carrier, where the carrier IS the pubkey entity.
func live(pk hash.Hash) Carrier { return Carrier{Hash: pk, Pubkey: pk, Live: true} }

// attests builds a Tier-B/C carrier: an attestation naming an inner pubkey.
func attests(carrierHash, pk hash.Hash) Carrier {
	return Carrier{Hash: carrierHash, Pubkey: pk, Live: true}
}

// keys builds the authored-entity map from (pubkey, created) pairs.
func keys(pairs ...any) map[hash.Hash]PubkeyEntity {
	m := map[hash.Hash]PubkeyEntity{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(hash.Hash)] = PubkeyEntity{Created: uint64(pairs[i+1].(int))}
	}
	return m
}

func TestResolveRecipientKeyTierOrder(t *testing.T) {
	a, b, c := testHash(0xA1), testHash(0xB1), testHash(0xC1)
	tests := []struct {
		name     string
		pubs     RecipientPublications
		wantKey  hash.Hash
		wantTier Tier
	}{
		{
			name: "tier C wins over B and A",
			pubs: RecipientPublications{
				TierC:   []Carrier{live(c)},
				TierB:   []Carrier{live(b)},
				TierA:   []Carrier{live(a)},
				Pubkeys: keys(c, 1, b, 99, a, 99),
			},
			wantKey: c, wantTier: TierC,
		},
		{
			// Higher `created` at a lower tier does NOT win: §4.4 is a
			// tier ladder, not a global recency sort.
			name: "tier B wins over A when C absent",
			pubs: RecipientPublications{
				TierB:   []Carrier{live(b)},
				TierA:   []Carrier{live(a)},
				Pubkeys: keys(b, 1, a, 99),
			},
			wantKey: b, wantTier: TierB,
		},
		{
			name: "tier A alone — the V7 floor is a valid configuration",
			pubs: RecipientPublications{
				TierA: []Carrier{live(a)}, Pubkeys: keys(a, 7),
			},
			wantKey: a, wantTier: TierA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveRecipientKey(tt.pubs)
			if err != nil {
				t.Fatalf("ResolveRecipientKey: %v", err)
			}
			if got.Pubkey != tt.wantKey {
				t.Errorf("pubkey = %s, want %s", got.Pubkey, tt.wantKey)
			}
			if got.Tier != tt.wantTier {
				t.Errorf("tier = %q, want %q", got.Tier, tt.wantTier)
			}
		})
	}
}

func TestResolveRecipientKeyMostRecentLive(t *testing.T) {
	old, mid, newest := testHash(0x01), testHash(0x02), testHash(0x03)
	pubs := RecipientPublications{
		TierA:   []Carrier{live(old), live(newest), live(mid)},
		Pubkeys: keys(old, 10, newest, 30, mid, 20),
	}
	got, err := ResolveRecipientKey(pubs)
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Pubkey != newest {
		t.Errorf("pubkey = %s, want most recent %s", got.Pubkey, newest)
	}
}

// A revoked candidate must not be picked even when it is the most recent
// — this is the §11 rule that makes revocation mean anything.
func TestResolveRecipientKeySkipsRevoked(t *testing.T) {
	liveKey, revoked := testHash(0x11), testHash(0x22)
	pubs := RecipientPublications{
		TierA:          []Carrier{live(liveKey), live(revoked)},
		Pubkeys:        keys(liveKey, 10, revoked, 99),
		RevokedPubkeys: map[hash.Hash]bool{revoked: true},
	}
	got, err := ResolveRecipientKey(pubs)
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Pubkey != liveKey {
		t.Errorf("pubkey = %s, want the live (older) key %s", got.Pubkey, liveKey)
	}
	if got.Dropped.PubkeyRevoked != 1 {
		t.Errorf("Dropped.PubkeyRevoked = %d, want 1", got.Dropped.PubkeyRevoked)
	}
}

// A tier that is non-empty but wholly dead falls through rather than
// terminating the walk (§4.4 MUST) — the recipient still has a reachable
// key one rung down.
func TestResolveRecipientKeyFallsThroughDeadTier(t *testing.T) {
	revokedC, liveA := testHash(0x33), testHash(0x44)
	pubs := RecipientPublications{
		TierC:          []Carrier{live(revokedC)},
		TierA:          []Carrier{live(liveA)},
		Pubkeys:        keys(revokedC, 99, liveA, 1),
		RevokedPubkeys: map[hash.Hash]bool{revokedC: true},
	}
	got, err := ResolveRecipientKey(pubs)
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Tier != TierA || got.Pubkey != liveA {
		t.Errorf("resolved (%q, %s), want (A, %s)", got.Tier, got.Pubkey, liveA)
	}
	if len(got.Examined) != 2 {
		t.Errorf("Examined = %v, want both C and A walked", got.Examined)
	}
}

// §4.4 step 1a/1b: Tier C is a two-step walk, most-specific first. A live
// per-relationship candidate is bound OVER a newer live public one —
// "most-specific first" is precedence, not recency. A resolver that merged
// the two sets into one ordered candidate list would pick the newer public
// key and fail this row; that merge is the exact divergence the step split
// exists to prevent.
func TestResolveRecipientKeyRelationshipStepOutranksNewerPublic(t *testing.T) {
	rel, pub := testHash(0x71), testHash(0x72)
	got, err := ResolveRecipientKey(RecipientPublications{
		TierCRelationship: []Carrier{attests(testHash(0xD1), rel)},
		TierC:             []Carrier{attests(testHash(0xD2), pub)},
		// The public key is strictly NEWER, so a recency merge would choose it.
		Pubkeys: keys(rel, 1, pub, 99),
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Tier != TierC || got.Pubkey != rel {
		t.Errorf("resolved (%q, %s), want (C, %s) — step 1a is most-specific-first, not most-recent",
			got.Tier, got.Pubkey, rel)
	}
	// Tier C is walked as one tier even though it spans two steps.
	if len(got.Examined) != 1 || got.Examined[0] != TierC {
		t.Errorf("Examined = %v, want [C] once — the two steps are one tier", got.Examined)
	}
}

// A per-relationship subtree that is non-empty but WHOLLY DEAD falls through
// to the public handle (§4.4 step 1a `[MUST]`), exactly as a dead tier falls
// through to the one below it — it does not terminate the walk.
func TestResolveRecipientKeyDeadRelationshipFallsThroughToPublic(t *testing.T) {
	rel, pub := testHash(0x73), testHash(0x74)
	got, err := ResolveRecipientKey(RecipientPublications{
		TierCRelationship: []Carrier{attests(testHash(0xD3), rel)},
		TierC:             []Carrier{attests(testHash(0xD4), pub)},
		Pubkeys:           keys(rel, 99, pub, 1),
		RevokedPubkeys:    map[hash.Hash]bool{rel: true},
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Tier != TierC || got.Pubkey != pub {
		t.Errorf("resolved (%q, %s), want (C, %s) — a dead 1a must fall through to 1b, not terminate",
			got.Tier, got.Pubkey, pub)
	}
	if got.Dropped.PubkeyRevoked != 1 {
		t.Errorf("Dropped.PubkeyRevoked = %d, want 1 — the dead relationship carrier is counted", got.Dropped.PubkeyRevoked)
	}
}

// An ABSENT relationships subtree resolves at 1b with no error (§4.4 step 1a
// `[MUST]`: "a subtree that is absent or unreadable is not an error"). This
// is the default shape every sender-without-a-prior-relationship sees.
func TestResolveRecipientKeyAbsentRelationshipResolvesAtPublic(t *testing.T) {
	pub := testHash(0x75)
	got, err := ResolveRecipientKey(RecipientPublications{
		// TierCRelationship deliberately nil.
		TierC:   []Carrier{attests(testHash(0xD5), pub)},
		Pubkeys: keys(pub, 5),
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v — an absent relationships subtree must not error", err)
	}
	if got.Tier != TierC || got.Pubkey != pub {
		t.Errorf("resolved (%q, %s), want (C, %s)", got.Tier, got.Pubkey, pub)
	}
}

// Q1 (ruled 2026-08-09-b): a candidate is the inner PUBKEY entity, and the
// order runs over pubkeys — never over the carriers that name them.
//
// The two keys tie on `created` and their carrier hashes are ordered
// OPPOSITE to their pubkey hashes, so a resolver that tie-broke on the
// attestation hash would pick the other one. That is the whole ruling in
// one assertion, and it is unobservable at Tier A where the two hashes are
// the same value.
func TestResolveRecipientKeyOrdersByPubkeyNotCarrier(t *testing.T) {
	pkLow, pkHigh := testHash(0x11), testHash(0xEE)
	carrierHi, carrierLo := testHash(0xFD), testHash(0x02)
	got, err := ResolveRecipientKey(RecipientPublications{
		TierC: []Carrier{
			attests(carrierHi, pkLow),
			attests(carrierLo, pkHigh),
		},
		Pubkeys: keys(pkLow, 5, pkHigh, 5),
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Pubkey != pkLow {
		t.Errorf("pubkey = %s, want %s — the tie-break MUST read the attested pubkey's hash, "+
			"not the carrier's (§4.4: attestations have no `created` and ENCRYPTION cannot mint one)",
			got.Pubkey, pkLow)
	}
}

// Two live carriers over one key are ONE candidate: a device is a
// private-key holder, not a cert.
func TestResolveRecipientKeyDedupsCarriersOverOneKey(t *testing.T) {
	pk, other := testHash(0x44), testHash(0x45)
	got, err := ResolveRecipientKey(RecipientPublications{
		TierC: []Carrier{
			attests(testHash(0xC1), pk),
			attests(testHash(0xC2), pk),
			attests(testHash(0xC3), other),
		},
		Pubkeys: keys(pk, 20, other, 10),
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Pubkey != pk {
		t.Errorf("pubkey = %s, want %s", got.Pubkey, pk)
	}
	if got.Dropped.Total() != 0 {
		t.Errorf("Dropped = %+v, want none — a duplicate carrier is deduplicated, not dropped", got.Dropped)
	}
}

// §11.3: revoking a carrier kills only that carrier. Revoking a
// per-relationship cert MUST NOT retire the device's public key, so a
// sibling carrier keeps the candidate alive and the walk does not fall
// through to a lower tier.
func TestResolveRecipientKeyCarrierRevocationLeavesSiblingStanding(t *testing.T) {
	pk, tierA := testHash(0x44), testHash(0x55)
	revoked, sibling := testHash(0xC1), testHash(0xC2)

	got, err := ResolveRecipientKey(RecipientPublications{
		TierC:           []Carrier{attests(revoked, pk), attests(sibling, pk)},
		TierA:           []Carrier{live(tierA)},
		Pubkeys:         keys(pk, 5, tierA, 99),
		RevokedCarriers: map[hash.Hash]bool{revoked: true},
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Tier != TierC || got.Pubkey != pk {
		t.Fatalf("resolved (%q, %s), want (C, %s) — one revoked carrier must not retire the key",
			got.Tier, got.Pubkey, pk)
	}

	// And the other side of the rule: with the last carrier gone, so is the
	// candidate.
	got, err = ResolveRecipientKey(RecipientPublications{
		TierC:           []Carrier{attests(revoked, pk)},
		TierA:           []Carrier{live(tierA)},
		Pubkeys:         keys(pk, 5, tierA, 99),
		RevokedCarriers: map[hash.Hash]bool{revoked: true},
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Tier != TierA {
		t.Errorf("resolved at %q, want A — no live carrier attests the Tier-C key", got.Tier)
	}
}

// Liveness filter 1: a carrier that does not verify does not speak for its
// key. Not an error, not a revocation — the walk continues.
func TestResolveRecipientKeyDropsDeadCarrier(t *testing.T) {
	pk, tierA := testHash(0x44), testHash(0x55)
	got, err := ResolveRecipientKey(RecipientPublications{
		TierC:   []Carrier{{Hash: testHash(0xC1), Pubkey: pk, Live: false}},
		TierA:   []Carrier{live(tierA)},
		Pubkeys: keys(pk, 99, tierA, 1),
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Tier != TierA {
		t.Errorf("resolved at %q, want A — an invalid carrier must not carry its key", got.Tier)
	}
	if got.Dropped.CarrierInvalid != 1 {
		t.Errorf("Dropped.CarrierInvalid = %d, want 1", got.Dropped.CarrierInvalid)
	}
}

// Q3 (ruled 2026-08-09-b): the pubkey entity's own §4.1 `expires` drops a
// candidate from SELECTION. Both directions, because an implementation that
// drops any key merely CARRYING an expiry passes the first half.
func TestResolveRecipientKeyAppliesExpiry(t *testing.T) {
	old, expiring := testHash(0x21), testHash(0x23)
	base := func(now uint64) RecipientPublications {
		return RecipientPublications{
			TierA: []Carrier{live(old), live(expiring)},
			Pubkeys: map[hash.Hash]PubkeyEntity{
				old:      {Created: 10},
				expiring: {Created: 99, Expires: 1000},
			},
			Now: now,
		}
	}

	got, err := ResolveRecipientKey(base(2000))
	if err != nil {
		t.Fatalf("expired case: %v", err)
	}
	if got.Pubkey != old {
		t.Errorf("pubkey = %s, want the unexpired older key %s", got.Pubkey, old)
	}
	if got.Dropped.Expired != 1 {
		t.Errorf("Dropped.Expired = %d, want 1", got.Dropped.Expired)
	}

	got, err = ResolveRecipientKey(base(500))
	if err != nil {
		t.Fatalf("unexpired case: %v", err)
	}
	if got.Pubkey != expiring {
		t.Errorf("pubkey = %s, want %s — `expires` is a comparison, not a flag", got.Pubkey, expiring)
	}
}

// A zero clock disables the expiry filter rather than treating every key as
// expired at the epoch. A caller that forgot to set Now must not silently
// resolve nothing — that failure would look exactly like a recipient with
// no keys.
func TestResolveRecipientKeyZeroClockDoesNotExpireEverything(t *testing.T) {
	pk := testHash(0x23)
	got, err := ResolveRecipientKey(RecipientPublications{
		TierA:   []Carrier{live(pk)},
		Pubkeys: map[hash.Hash]PubkeyEntity{pk: {Created: 1, Expires: 1000}},
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Pubkey != pk {
		t.Errorf("pubkey = %s, want %s", got.Pubkey, pk)
	}
}

// §4.4 retrievability MUST: a sender cannot encrypt to a key it cannot
// read, so an unretrievable candidate is dropped and the walk CONTINUES —
// explicitly not a distinct error.
func TestResolveRecipientKeyDropsUnretrievableKey(t *testing.T) {
	readable, unreadable := testHash(0x21), testHash(0x23)
	got, err := ResolveRecipientKey(RecipientPublications{
		TierA:   []Carrier{live(readable), live(unreadable)},
		Pubkeys: keys(readable, 10), // `unreadable` deliberately absent
	})
	if err != nil {
		t.Fatalf("ResolveRecipientKey: %v", err)
	}
	if got.Pubkey != readable {
		t.Errorf("pubkey = %s, want the readable key %s", got.Pubkey, readable)
	}
	if got.Dropped.Unretrievable != 1 {
		t.Errorf("Dropped.Unretrievable = %d, want 1", got.Dropped.Unretrievable)
	}
}

// The no-answer cases are different facts and must not share a message.
// §4.4 makes them ONE error on the wire and says an implementation SHOULD
// distinguish them locally; this is that.
func TestResolveRecipientKeyDistinguishesEmptyFromDropped(t *testing.T) {
	t.Run("nothing published", func(t *testing.T) {
		_, err := ResolveRecipientKey(RecipientPublications{})
		if !errors.Is(err, ErrEncryptionRecipientUnknown) {
			t.Fatalf("err = %v, want ErrEncryptionRecipientUnknown", err)
		}
		if got := err.Error(); !contains(got, "no encryption-pubkey at any tier") {
			t.Errorf("message %q does not distinguish the empty case", got)
		}
	})
	t.Run("published but nothing live", func(t *testing.T) {
		dead := testHash(0x55)
		_, err := ResolveRecipientKey(RecipientPublications{
			TierA:          []Carrier{live(dead)},
			Pubkeys:        keys(dead, 1),
			RevokedPubkeys: map[hash.Hash]bool{dead: true},
		})
		if !errors.Is(err, ErrEncryptionRecipientUnknown) {
			t.Fatalf("err = %v, want ErrEncryptionRecipientUnknown", err)
		}
		if got := err.Error(); !contains(got, "1 key-revoked") {
			t.Errorf("message %q does not report which filter dropped it", got)
		}
	})
	t.Run("published but unreadable", func(t *testing.T) {
		_, err := ResolveRecipientKey(RecipientPublications{
			TierA: []Carrier{live(testHash(0x56))},
		})
		if !errors.Is(err, ErrEncryptionRecipientUnknown) {
			t.Fatalf("err = %v, want ErrEncryptionRecipientUnknown", err)
		}
		if got := err.Error(); !contains(got, "1 unretrievable") {
			t.Errorf("message %q does not report the retrievability drop", got)
		}
	})
}

// The §4.4 tie-break, ruled 2026-08-09 (arch `a19234e`) with its inputs
// pinned 2026-08-09-b (`f855793`): `created` descending, then the full
// multihash-prefixed `content_hash` ASCENDING as raw bytes.
//
// Both halves are asserted — that the answer does not depend on input
// order, AND that it is the ascending one. Order-independence alone would
// have passed the descending rule this originally shipped with, which is
// the divergence the ruling exists to prevent: two senders picking
// different keys, nothing erroring, and at Tier C the ciphertext routed to
// a different device than the reader is watching.
func TestResolveRecipientKeyTieBreakIsDeterministic(t *testing.T) {
	lo, hi := testHash(0x01), testHash(0xFE)
	forward := RecipientPublications{
		TierA: []Carrier{live(lo), live(hi)}, Pubkeys: keys(lo, 5, hi, 5),
	}
	reverse := RecipientPublications{
		TierA: []Carrier{live(hi), live(lo)}, Pubkeys: keys(hi, 5, lo, 5),
	}
	f, err := ResolveRecipientKey(forward)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	r, err := ResolveRecipientKey(reverse)
	if err != nil {
		t.Fatalf("reversed: %v", err)
	}
	if f.Pubkey != r.Pubkey {
		t.Fatalf("tie-break depends on input order: %s vs %s", f.Pubkey, r.Pubkey)
	}
	if f.Pubkey != lo {
		t.Errorf("tie-break picked %s, want the lexicographically SMALLER %s — §4.4 pins content_hash ASCENDING (arch a19234e)",
			f.Pubkey, lo)
	}
}

// The tie-break compares the FULL multihash-prefixed content_hash, not the
// bare digest (Q2, ruled 2026-08-09-b) — byte-for-byte the value bound as
// recipient_key. The two forms agree under one algorithm and diverge only
// across algorithms, so this asserts the property that makes them agree:
// the compared bytes carry the format prefix.
func TestTieBreakComparesTheFullContentHash(t *testing.T) {
	a := testHash(0x01)
	b := hash.Hash{Algorithm: hash.AlgorithmSHA384}
	for i := range b.Digest[:hash.SHA384DigestSize] {
		b.Digest[i] = 0x00
	}
	// b's DIGEST is all zeros, so a bare-digest comparison would rank it
	// first; its FORMAT byte is 0x01 against a's 0x00, so the prefixed form
	// ranks a first. The direction of this assertion is the ruling.
	if winsTieBreak(b, a) {
		t.Error("tie-break ranked the SHA-384 hash first — it is comparing bare digests, " +
			"not the multihash-prefixed content_hash §4.4 pins")
	}
	if !winsTieBreak(a, b) {
		t.Error("tie-break did not rank the 0x00-format hash first")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
