// Package encvectors holds ENC-RESOLVE-ORDER-1 — the pinned-input
// differential for EXTENSION-ENCRYPTION §4.4's recipient-key resolution —
// together with its emitter and verifier.
//
// WHY A VECTOR AND NOT A PROBE (§16.6). §4.4's resolution is something a
// SENDER does before it encrypts, and ENCRYPTION defines no peer-facing
// encrypt-to-this-recipient operation. No request a validator can make will
// reveal which key another implementation's resolver would have chosen. That is
// a property of the rule, not a gap in any validator — and it is why a
// [cross-peer seam — MUST] sat for a week exercised only by each
// implementation's own resolver, called by its own suite, scoring rows against
// peers it never contacted. A shared row file each implementation runs inside
// its own suite is the only crossing this rule can have.
//
// It lives here rather than inside the command because two callers need the
// rows: cmd/encryption-vectors (which emits the file siblings consume) and
// cmd/internal/validate's `encryption.tier_c_resolution` check. One definition,
// so the file we hand to rust and python cannot drift from the one our own
// suite gates on.
//
// COVERAGE IS THE CONTRACT, NOT THIS FILE. §16.6 makes the required row set
// normative and explicitly says no repo's emitted file is: tier-ladder
// precedence at all three pairings, `created` descending, the tie-break
// direction asserted, `created` outranking `content_hash`, carrier→pubkey
// projection with two carriers over one key deduplicating to one candidate,
// revocation at both granularities, `expires` dropping a candidate, a
// non-empty-but-fully-dead tier falling through, and both step-4 error cases —
// plus order-independence on every row, negative controls that each fire on a
// named row, and declared exclusions.
package encvectors

import (
	"errors"
	"fmt"
	"io"
	"os"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/encryption"
)

// Schema identifies the vector contract. Unlike the WebRTC file's
// `webrtc-sdp-ice/1`, this string is NOT pinned into any wire surface — it
// names a test artifact only — so it can be bumped without a flag day.
//
// Bumped to /2 when arch pinned §4.4's three open inputs (f855793): a row is no
// longer a flat candidate list but a set of CARRIERS plus the pubkey entities
// they project onto, because filtering is carrier-scoped and ordering is not.
// /1 rows cannot be reinterpreted under /2 — a /1 "candidate" conflated the two
// — so the verifier refuses the old schema rather than guessing.
//
// Bumped to /3 when the mixed-content_hash_format rows landed alongside
// ENC-ROUNDTRIP-FORMAT-1. The row SHAPE is unchanged, so a superset would have
// half-parsed — and that is precisely why it is a bump. /3 demands a capability
// /2 did not: every `hash` field may now be 49 bytes (0x01 ‖ 48) as readily as
// 33, so a consumer that fixed the width at 33 fails somewhere in the middle of
// the file and reports it as a row disagreeing about the ORDER, which is the
// one thing it is not. §16.6 also makes coverage part of the contract, and
// these rows add required coverage. A refused schema says "your verifier needs
// a change" in one line; a superset says "your resolver is wrong" in four, and
// is lying.
//
// Bumped to /4 when §4.4's Tier-C two-step walk (step 1a/1b) landed. A row now
// carries a fourth carrier list, `tier_c_relationship` — the per-relationship
// step, walked before the public certs — and rows that exercise it are new
// required coverage (§16.6). This is a real bump for the same reason /2 was: a
// /3 verifier that ignored the new field would silently merge the relationship
// step into the public one and pass a row that gates precisely against that
// merge, reporting "your resolver is right" when it has not read the input the
// row turns on. A refused schema is the honest answer; the field is additive on
// the wire (a /3 row simply has it empty), but the CONTRACT is not, so the
// string moves. Go leads here (§4.4 step 1a); rust + py adopt /4 downstream.
const Schema = "encryption-resolve-order/4"

// VectorFile is the contract shape, following the vector contract agreed with
// entity-core-rust on 2026-08-03: schema + emitter + emitter_commit provenance,
// expectations stated positively, and no field whose absence carries meaning.
type VectorFile struct {
	Schema  string `cbor:"schema"`
	Emitter string `cbor:"emitter"`
	// EmitterCommit pins the tree that produced these bytes (ADR-0012). This
	// file is deterministic — every hash is a fixed byte pattern, every clock
	// is authored per row, nothing calls time.Now or a random source — so
	// re-emitting at the same commit reproduces it exactly.
	EmitterCommit string `cbor:"emitter_commit"`

	// Excludes states, as data, what this file does NOT gate and why (§16.6
	// requirement 4). Absence of coverage is asserted positively for the same
	// reason `expect_absent` is a required array in the WebRTC contract: a
	// verifier cannot otherwise tell "the emitter deliberately left this open"
	// from "the emitter forgot."
	Excludes []string `cbor:"excludes"`

	Rows []ResolveVector `cbor:"rows"`
}

// Carrier is one tier-shaped publication: a V7-signed pubkey entity at Tier A,
// an attestation at Tiers B/C. Carriers are what a tier enumerates and what
// filtering applies to; they are NOT what the order runs over.
type Carrier struct {
	// Hash is the carrier's own content_hash — the attestation hash at Tiers
	// B/C, the pubkey entity's own hash at Tier A. This is what a
	// carrier-targeted revocation (§11.3) names.
	Hash hash.Hash `cbor:"hash"`
	// Pubkey is the content_hash of the system/encryption-pubkey entity this
	// carrier attests (`attested`) or, at Tier A, is.
	Pubkey hash.Hash `cbor:"pubkey"`
	// Live is §4.4 liveness filter 1 (carrier validity), pre-evaluated: the
	// Tier-A invariant-pointer signature, or is_attestation_live plus
	// identity's authority chain at Tiers B/C. Stated as data because
	// evaluating it needs the attestation graph, which a pinned-input vector
	// deliberately does not carry — the rule under test is the ORDER, not
	// ATTESTATION §4.3, which has its own vectors (TV-A1..A6).
	Live bool `cbor:"live"`
}

// PubkeyEntity is the authored inner entity a carrier projects onto, carrying
// the two §4.1 fields the order reads.
//
// Keyed by its own content_hash, and both fields are hash input — so two
// carriers naming one pubkey hash cannot disagree about `created`. Carrying
// them here rather than on Carrier makes that unrepresentable rather than
// merely untrue.
type PubkeyEntity struct {
	Pubkey  hash.Hash `cbor:"pubkey"`
	Created uint64    `cbor:"created"`
	// Expires is §4.1's optional expiry; 0 means absent.
	Expires uint64 `cbor:"expires"`
}

// Outcome discriminates what a row expects. It is an explicit field rather than
// an inference from which of Selected/Error is populated, because a zero
// hash.Hash is NOT a sentinel: content_hash_format 0x00 is SHA-256, so an unset
// Selected encodes as a perfectly well-formed all-zero SHA-256 hash. Inferring
// presence would re-create the absent-vs-null ambiguity one level up — the
// exact defect the WebRTC contract's `expect_absent` amendment was written to
// close.
const (
	OutcomeSelected = "selected"
	OutcomeError    = "error"
)

// Expect is a row's stated expectation. A verifier MUST read these values; it
// must never re-derive them with its own resolver. A verifier that recomputes
// the expected winner can only prove it agrees with itself, and would pass a
// sibling's file that disagreed with it in every row.
type Expect struct {
	Outcome string `cbor:"outcome"`

	// Selected + Tier are meaningful when Outcome == OutcomeSelected.
	Selected hash.Hash `cbor:"selected"`
	Tier     string    `cbor:"tier"`

	// Error is the §15 error code when Outcome == OutcomeError.
	Error string `cbor:"error"`
}

// ResolveVector is one resolution case: a full sender's-eye view of a
// recipient's namespace, plus the single key §4.4 says must come out of it.
type ResolveVector struct {
	Name string `cbor:"name"`
	// Why records what the row is guarding, so a FAIL is diagnosable from the
	// file alone rather than from the emitter's source tree.
	Why string `cbor:"why"`

	// TierCRelationship is §4.4 step 1a — the per-relationship carriers, walked
	// before TierC (step 1b, the public certs). The two are SEPARATE candidate
	// sets, most-specific first: a live carrier here binds even over a newer
	// live public one. Empty on every row that does not exercise the sub-walk,
	// which is the common case and the shape a sender with no prior relationship
	// always sees.
	TierCRelationship []Carrier `cbor:"tier_c_relationship"`
	TierC             []Carrier `cbor:"tier_c"`
	TierB             []Carrier `cbor:"tier_b"`
	TierA             []Carrier `cbor:"tier_a"`

	// Pubkeys are the authored inner entities. PRESENCE IS RETRIEVABILITY:
	// §4.4 makes keeping the attested inner entity readable a publisher MUST,
	// and a candidate whose entity cannot be read is dropped with the walk
	// continuing. A carrier whose Pubkey is absent from this list models
	// exactly that.
	Pubkeys []PubkeyEntity `cbor:"pubkeys"`

	// RevokedPubkeys kill a key outright (§11.1 / §11.2).
	RevokedPubkeys []hash.Hash `cbor:"revoked_pubkeys"`
	// RevokedCarriers kill one carrier (§11.3); the key survives if another
	// live carrier still attests it.
	RevokedCarriers []hash.Hash `cbor:"revoked_carriers"`

	// Now is the authored sender clock (epoch ms) for the §4.1 `expires`
	// filter. Authored per row rather than taken from the system clock, or the
	// expiry rows would not be reproducible — and a vector nobody can
	// re-derive is an assertion, not evidence.
	Now uint64 `cbor:"now"`

	Expect Expect `cbor:"expect"`
}

// --- emit -------------------------------------------------------------------

// fillHash builds a SHA-256 content_hash whose digest is a single repeated
// byte. Fixed patterns rather than derived digests so that a reader can check
// the tie-break rows BY EYE: 0x11… is visibly below 0xEE…, and a row asserting
// otherwise is wrong on inspection without running anything.
func fillHash(b byte) hash.Hash {
	var d [hash.SHA256DigestSize]byte
	for i := range d {
		d[i] = b
	}
	return hash.NewSHA256(d)
}

// fillHash384 is fillHash under content_hash_format 0x01 (ECFv1-SHA-384) —
// a 49-byte wire form, and the only way to build a candidate set where the
// two readings of §4.4's tie-break DISAGREE.
//
// The whole point of the mixed rows: `content_hash ascending` means the
// full multihash-prefixed bytes, not the bare digest. Under one algorithm
// every candidate shares a prefix and the readings are the same function,
// which is why arch could pin the rule (Q2) with nothing able to observe
// it. Across algorithms the format byte is the FIRST byte compared, so it
// decides before any digest byte is read — and a set whose digests order
// the other way makes the wrong reading pick the other key.
func fillHash384(b byte) hash.Hash {
	var d [hash.SHA384DigestSize]byte
	for i := range d {
		d[i] = b
	}
	return hash.NewSHA384(d)
}

// The fixed cast. Named by role so the rows read as prose. Pubkey hashes and
// carrier hashes are drawn from visibly different ranges so a row that confuses
// the two is obvious in a failure message.
var (
	pkLow    = fillHash(0x11)
	pkHigh   = fillHash(0xEE)
	pkOld    = fillHash(0x21)
	pkMid    = fillHash(0x22)
	pkNew    = fillHash(0x23)
	pkTierC  = fillHash(0x31)
	pkTierB  = fillHash(0x32)
	pkTierA  = fillHash(0x33)
	pkShared = fillHash(0x44)
	pkOther  = fillHash(0x45)

	certA1 = fillHash(0xC1)
	certA2 = fillHash(0xC2)
	certB1 = fillHash(0xB1)
	certLo = fillHash(0x02)
	certHi = fillHash(0xFD)

	// The Tier-C sub-walk cast (§4.4 step 1a/1b): a per-relationship key and
	// carrier vs. the public handle's, kept distinct so a row can assert which
	// step bound the key.
	pkRel   = fillHash(0x71)
	pkPub   = fillHash(0x72)
	certRel = fillHash(0xD1)
	certPub = fillHash(0xD2)

	// The mixed-algorithm cast. Named for what they do to the two readings
	// rather than for their bytes, because the bytes are the trap: pk384Low
	// has the LOWER digest and the HIGHER full form, and a reader skimming
	// "low" will get the row backwards.
	//
	//	pk256High  = 0x00 ‖ EE…(32)   full form sorts FIRST  (0x00 < 0x01)
	//	pk384Low   = 0x01 ‖ 11…(48)   bare digest sorts FIRST (0x11 < 0xEE)
	//
	// So the pinned rule picks pk256High and the rejected bare-digest
	// reading picks pk384Low. That opposition is the entire vector.
	pk256High = fillHash(0xEE)
	pk384Low  = fillHash384(0x11)
	pk384High = fillHash384(0xEE)
)

// cert is a Tier-B/C carrier: an attestation naming an inner pubkey.
func cert(carrierHash, pubkey hash.Hash) Carrier {
	return Carrier{Hash: carrierHash, Pubkey: pubkey, Live: true}
}

// deadCert is a carrier that fails §4.4 liveness filter 1.
func deadCert(carrierHash, pubkey hash.Hash) Carrier {
	return Carrier{Hash: carrierHash, Pubkey: pubkey, Live: false}
}

// selfCarrier is a Tier-A carrier, where the publication IS the pubkey entity
// and projection is the identity function — so its carrier hash and its pubkey
// hash are the same value.
func selfCarrier(pk hash.Hash) Carrier {
	return Carrier{Hash: pk, Pubkey: pk, Live: true}
}

func key(pk hash.Hash, created uint64) PubkeyEntity {
	return PubkeyEntity{Pubkey: pk, Created: created}
}

func expiringKey(pk hash.Hash, created, expires uint64) PubkeyEntity {
	return PubkeyEntity{Pubkey: pk, Created: created, Expires: expires}
}

func selected(pk hash.Hash, tier string) Expect {
	return Expect{Outcome: OutcomeSelected, Selected: pk, Tier: tier}
}

func unknownRecipient() Expect {
	return Expect{Outcome: OutcomeError, Error: types.EncryptionErrRecipientUnknown}
}

func Rows() []ResolveVector {
	return []ResolveVector{
		// --- the ladder: tier order beats recency, at every pairing ---
		{
			Name:    "ladder/c-outranks-newer-a",
			Why:     "§4.4 is a ladder, not a global recency sort: a newer Tier-A key does not outrank a Tier-C carrier",
			TierC:   []Carrier{cert(certA1, pkTierC)},
			TierA:   []Carrier{selfCarrier(pkTierA)},
			Pubkeys: []PubkeyEntity{key(pkTierC, 1), key(pkTierA, 99)},
			Expect:  selected(pkTierC, "C"),
		},
		{
			Name:    "ladder/c-outranks-newer-b",
			Why:     "same rule at the C/B pairing",
			TierC:   []Carrier{cert(certA1, pkTierC)},
			TierB:   []Carrier{cert(certB1, pkTierB)},
			Pubkeys: []PubkeyEntity{key(pkTierC, 1), key(pkTierB, 99)},
			Expect:  selected(pkTierC, "C"),
		},
		{
			Name:    "ladder/b-outranks-newer-a",
			Why:     "same rule at the B/A pairing",
			TierB:   []Carrier{cert(certB1, pkTierB)},
			TierA:   []Carrier{selfCarrier(pkTierA)},
			Pubkeys: []PubkeyEntity{key(pkTierB, 1), key(pkTierA, 99)},
			Expect:  selected(pkTierB, "B"),
		},
		{
			Name:    "ladder/a-alone",
			Why:     "the V7 floor is a valid configuration (§4.0), not a degraded one",
			TierA:   []Carrier{selfCarrier(pkTierA)},
			Pubkeys: []PubkeyEntity{key(pkTierA, 7)},
			Expect:  selected(pkTierA, "A"),
		},
		{
			Name: "ladder/same-pubkey-at-c-and-a",
			Why: "when one authored pubkey is published at two tiers the bound hash cannot " +
				"distinguish them, so the REPORTED tier is the only thing that can be wrong here",
			TierC:   []Carrier{cert(certA1, pkShared)},
			TierA:   []Carrier{selfCarrier(pkShared)},
			Pubkeys: []PubkeyEntity{key(pkShared, 1)},
			Expect:  selected(pkShared, "C"),
		},

		// --- recency ---
		{
			Name:  "recency/newest-wins",
			Why:   "`created` DESCENDING within a tier",
			TierA: []Carrier{selfCarrier(pkOld), selfCarrier(pkNew), selfCarrier(pkMid)},
			Pubkeys: []PubkeyEntity{
				key(pkOld, 10), key(pkNew, 30), key(pkMid, 20),
			},
			Expect: selected(pkNew, "A"),
		},
		{
			Name: "recency/input-order-permuted",
			Why: "the same set in a different enumeration order MUST resolve identically — namespace " +
				"listing order is arbitrary, so an implementation that lets it decide is divergent by luck",
			TierA: []Carrier{selfCarrier(pkNew), selfCarrier(pkMid), selfCarrier(pkOld)},
			Pubkeys: []PubkeyEntity{
				key(pkNew, 30), key(pkMid, 20), key(pkOld, 10),
			},
			Expect: selected(pkNew, "A"),
		},

		// --- the tie-break ---
		{
			Name: "tiebreak/ascending-lower-hash-wins",
			Why: "ties on `created` break by content_hash ASCENDING. core-go shipped this DESCENDING " +
				"until arch a19234e pinned it; a row asserting only order-independence passes the " +
				"wrong rule, so this row asserts the direction",
			TierA:   []Carrier{selfCarrier(pkLow), selfCarrier(pkHigh)},
			Pubkeys: []PubkeyEntity{key(pkLow, 5), key(pkHigh, 5)},
			Expect:  selected(pkLow, "A"),
		},
		{
			Name:    "tiebreak/ascending-permuted",
			Why:     "the tie-break must not depend on which of the tied pair was enumerated first",
			TierA:   []Carrier{selfCarrier(pkHigh), selfCarrier(pkLow)},
			Pubkeys: []PubkeyEntity{key(pkHigh, 5), key(pkLow, 5)},
			Expect:  selected(pkLow, "A"),
		},
		{
			Name: "tiebreak/created-outranks-hash",
			Why: "`created` is the PRIMARY key and content_hash only the tie-break — an implementation " +
				"that sorted by hash first passes both rows above and fails this one",
			TierA:   []Carrier{selfCarrier(pkHigh), selfCarrier(pkLow)},
			Pubkeys: []PubkeyEntity{key(pkHigh, 6), key(pkLow, 5)},
			Expect:  selected(pkHigh, "A"),
		},

		// --- the tie-break across content_hash_formats (Q2 made observable) ---
		//
		// These four rows are the reason ENC-ROUNDTRIP-FORMAT-1 had to be
		// built before ENC-RESOLVE-ORDER-1 could be complete. Arch pinned the
		// tie-break to the full multihash-prefixed content_hash (Q2, a19234e)
		// rather than the bare digest; under a single algorithm the two are
		// the same function, so the ruling was unfalsifiable by every row
		// above. A mixed-algorithm candidate set is the only place they
		// differ — reachable exactly when SHA-384 is active, which is now.
		{
			Name: "tiebreak/mixed-format-prefixed-not-bare-digest",
			Why: "THE Q2 ROW. Both keys tie on `created`. Compared as FULL multihash-prefixed bytes " +
				"the SHA-256 key wins on its 0x00 format byte before a digest byte is read; compared " +
				"as BARE DIGESTS the SHA-384 key wins (0x11… < 0xEE…). An implementation that " +
				"strips the format byte — the natural thing to do, and what core-go's own " +
				"EffectiveDigest() would give you — selects the OTHER key and fails only here",
			TierA:   []Carrier{selfCarrier(pk256High), selfCarrier(pk384Low)},
			Pubkeys: []PubkeyEntity{key(pk256High, 5), key(pk384Low, 5)},
			Expect:  selected(pk256High, "A"),
		},
		{
			Name:    "tiebreak/mixed-format-permuted",
			Why:     "the mixed-format tie-break must not depend on enumeration order either",
			TierA:   []Carrier{selfCarrier(pk384Low), selfCarrier(pk256High)},
			Pubkeys: []PubkeyEntity{key(pk384Low, 5), key(pk256High, 5)},
			Expect:  selected(pk256High, "A"),
		},
		{
			Name: "tiebreak/mixed-format-created-still-outranks",
			Why: "the format byte is a TIE-BREAK input, not a precedence signal. The SHA-384 key is " +
				"newer and MUST win despite sorting after every SHA-256 hash. An implementation " +
				"that read 0x00 as 'preferred format' — or that grouped candidates by format " +
				"before ordering — passes the two rows above and fails this one",
			TierA:   []Carrier{selfCarrier(pk256High), selfCarrier(pk384Low)},
			Pubkeys: []PubkeyEntity{key(pk256High, 5), key(pk384Low, 6)},
			Expect:  selected(pk384Low, "A"),
		},
		{
			Name: "tiebreak/within-sha384-ascending",
			Why: "the rule is one total order over all formats, not a SHA-256 rule with a SHA-384 " +
				"special case: two SHA-384 candidates tie-break among themselves by the same " +
				"ascending comparison, on 49-byte forms sharing a 0x01 prefix",
			TierA:   []Carrier{selfCarrier(pk384High), selfCarrier(pk384Low)},
			Pubkeys: []PubkeyEntity{key(pk384High, 5), key(pk384Low, 5)},
			Expect:  selected(pk384Low, "A"),
		},

		// --- projection: the order runs over pubkeys, never over carriers ---
		{
			Name: "projection/tie-breaks-on-pubkey-not-carrier",
			Why: "Q1 (ruled 2026-08-09-b): ordering keys come from the attested PUBKEY entity, never " +
				"from the carrier. Both keys tie on `created`, and the carrier hashes are ordered " +
				"OPPOSITE to the pubkey hashes — so an implementation that tie-breaks on the " +
				"attestation hash picks the other one. This is the row that gates the ruling",
			TierC: []Carrier{
				cert(certHi, pkLow),  // low pubkey, HIGH carrier
				cert(certLo, pkHigh), // high pubkey, LOW carrier
			},
			Pubkeys: []PubkeyEntity{key(pkLow, 5), key(pkHigh, 5)},
			Expect:  selected(pkLow, "C"),
		},
		{
			Name: "projection/two-carriers-one-key-dedup",
			Why: "two live carriers naming one pubkey are ONE candidate — a device is a private-key " +
				"holder, not a cert. Selection is unchanged by the duplicate carrier; what the dedup " +
				"actually protects is the revocation rule two rows down",
			TierC: []Carrier{
				cert(certA1, pkShared),
				cert(certA2, pkShared),
				cert(certB1, pkOther),
			},
			Pubkeys: []PubkeyEntity{key(pkShared, 20), key(pkOther, 10)},
			Expect:  selected(pkShared, "C"),
		},

		// --- the Tier-C sub-walk (§4.4 step 1a/1b, most-specific first) ---
		{
			Name: "tier-c-sub-walk/relationship-outranks-newer-public",
			Why: "§4.4 step 1a/1b: Tier C is two steps, most-specific first `[MUST]`. The " +
				"per-relationship key is bound OVER a strictly NEWER public one — precedence, " +
				"not recency. A resolver that merged 1a and 1b into one ordered set picks the " +
				"newer public key and fails ONLY this row; that merge is the divergence the " +
				"step split exists to prevent",
			TierCRelationship: []Carrier{cert(certRel, pkRel)},
			TierC:             []Carrier{cert(certPub, pkPub)},
			Pubkeys:           []PubkeyEntity{key(pkRel, 1), key(pkPub, 99)},
			Expect:            selected(pkRel, "C"),
		},
		{
			Name: "tier-c-sub-walk/dead-relationship-falls-through-to-public",
			Why: "§4.4 step 1a `[MUST]`: a per-relationship subtree that is non-empty but WHOLLY " +
				"DEAD falls through to 1b, exactly as a dead tier falls through — it does not " +
				"terminate the walk. The relationship key is the newer one, so a resolver that " +
				"failed to drop it would bind it",
			TierCRelationship: []Carrier{cert(certRel, pkRel)},
			TierC:             []Carrier{cert(certPub, pkPub)},
			Pubkeys:           []PubkeyEntity{key(pkRel, 99), key(pkPub, 1)},
			RevokedPubkeys:    []hash.Hash{pkRel},
			Expect:            selected(pkPub, "C"),
		},
		{
			Name: "tier-c-sub-walk/absent-relationship-resolves-at-public",
			Why: "§4.4 step 1a `[MUST]`: an absent or unreadable relationships subtree is NOT an " +
				"error — it means no per-relationship key was published to this sender and the " +
				"walk continues at 1b. This is the shape every sender-without-a-prior-relationship " +
				"sees, so it must resolve cleanly at the public handle",
			// TierCRelationship deliberately empty.
			TierC:   []Carrier{cert(certPub, pkPub)},
			Pubkeys: []PubkeyEntity{key(pkPub, 5)},
			Expect:  selected(pkPub, "C"),
		},

		// --- revocation, at both granularities ---
		{
			Name:           "revocation/pubkey-targeted-kills-the-candidate",
			Why:            "a revocation naming the inner pubkey hash kills the key outright, however recent",
			TierA:          []Carrier{selfCarrier(pkOld), selfCarrier(pkNew)},
			Pubkeys:        []PubkeyEntity{key(pkOld, 10), key(pkNew, 99)},
			RevokedPubkeys: []hash.Hash{pkNew},
			Expect:         selected(pkOld, "A"),
		},
		{
			Name: "revocation/carrier-targeted-leaves-sibling-standing",
			Why: "§11.3: revoking ONE carrier kills only that carrier — the candidate survives while " +
				"any live carrier still attests it. Revoking a per-relationship cert MUST NOT retire " +
				"the device's key. An implementation that collapses the two granularities falls " +
				"through to Tier A here",
			TierC: []Carrier{
				cert(certA1, pkShared),
				cert(certA2, pkShared),
			},
			TierA:           []Carrier{selfCarrier(pkTierA)},
			Pubkeys:         []PubkeyEntity{key(pkShared, 5), key(pkTierA, 99)},
			RevokedCarriers: []hash.Hash{certA1},
			Expect:          selected(pkShared, "C"),
		},
		{
			Name: "revocation/carrier-targeted-last-carrier-falls-through",
			Why: "the other side of the same rule: with no live carrier left, the key has nothing " +
				"attesting it and the walk continues. Distinguishes 'kills only that carrier' from " +
				"'never kills anything'",
			TierC:           []Carrier{cert(certA1, pkShared)},
			TierA:           []Carrier{selfCarrier(pkTierA)},
			Pubkeys:         []PubkeyEntity{key(pkShared, 5), key(pkTierA, 99)},
			RevokedCarriers: []hash.Hash{certA1},
			Expect:          selected(pkTierA, "A"),
		},

		// --- carrier validity (liveness filter 1) ---
		{
			Name: "carrier-validity/dead-carrier-dropped",
			Why: "filter 1: a carrier that does not verify, or is expired / superseded / self-revoked " +
				"per is_attestation_live, does not speak for its key. Not an error — the walk continues",
			TierC:   []Carrier{deadCert(certA1, pkShared)},
			TierA:   []Carrier{selfCarrier(pkTierA)},
			Pubkeys: []PubkeyEntity{key(pkShared, 99), key(pkTierA, 1)},
			Expect:  selected(pkTierA, "A"),
		},

		// --- expiry (liveness filter 3) ---
		{
			Name: "expires/expired-key-dropped",
			Why: "Q3 (ruled 2026-08-09-b): the pubkey entity's own §4.1 `expires` drops a candidate " +
				"from SELECTION when now >= expires, exactly as a revocation would",
			TierA:   []Carrier{selfCarrier(pkOld), selfCarrier(pkNew)},
			Pubkeys: []PubkeyEntity{key(pkOld, 10), expiringKey(pkNew, 99, 1000)},
			Now:     2000,
			Expect:  selected(pkOld, "A"),
		},
		{
			Name: "expires/unexpired-key-still-selected",
			Why: "the other side: `expires` is a comparison against the sender's clock, not a flag. " +
				"An implementation that drops any key CARRYING an expiry passes the row above and " +
				"fails this one",
			TierA:   []Carrier{selfCarrier(pkOld), selfCarrier(pkNew)},
			Pubkeys: []PubkeyEntity{key(pkOld, 10), expiringKey(pkNew, 99, 1000)},
			Now:     500,
			Expect:  selected(pkNew, "A"),
		},

		// --- retrievability ---
		{
			Name: "retrievability/unreadable-key-dropped",
			Why: "§4.4 MUST: a sender cannot encrypt to a key it cannot read — it needs public_key " +
				"and the suite arrays, not just a hash. The newer key's inner entity is absent, so " +
				"the candidate is dropped and the walk continues",
			TierA:   []Carrier{selfCarrier(pkOld), selfCarrier(pkNew)},
			Pubkeys: []PubkeyEntity{key(pkOld, 10)}, // pkNew deliberately absent
			Expect:  selected(pkOld, "A"),
		},

		// --- a non-empty but wholly dead tier does not terminate the walk ---
		{
			Name: "dead-tier/falls-through-to-a-live-lower-tier",
			Why: "§4.4 MUST: 'try tier N' means did tier N yield a LIVE candidate, not did tier N " +
				"publish anything. An implementation that stops at the first non-empty tier reports " +
				"recipient_unknown for a recipient that is reachable one rung down",
			TierC:          []Carrier{cert(certA1, pkTierC)},
			TierA:          []Carrier{selfCarrier(pkTierA)},
			Pubkeys:        []PubkeyEntity{key(pkTierC, 5), key(pkTierA, 1)},
			RevokedPubkeys: []hash.Hash{pkTierC},
			Expect:         selected(pkTierA, "A"),
		},

		// --- step 4: one error, several facts ---
		{
			Name:           "unknown/all-revoked",
			Why:            "every tier exhausted with nothing live is §4.4 step 4",
			TierA:          []Carrier{selfCarrier(pkTierA)},
			Pubkeys:        []PubkeyEntity{key(pkTierA, 5)},
			RevokedPubkeys: []hash.Hash{pkTierA},
			Expect:         unknownRecipient(),
		},
		{
			Name: "unknown/all-unreadable",
			Why: "'publishes a key I cannot read' is the SAME wire error as 'publishes nothing' — " +
				"§4.4 is explicit that the sender reports one code and may only distinguish them " +
				"in local diagnostics",
			TierA:   []Carrier{selfCarrier(pkTierA)},
			Pubkeys: nil,
			Expect:  unknownRecipient(),
		},
		{
			Name:   "unknown/no-publications",
			Why:    "a recipient publishing nothing is also §4.4 step 4 — the same code, a different fact",
			Expect: unknownRecipient(),
		},
	}
}

// Excludes states the scope boundary as data (§16.6 requirement 4).
func Excludes() []string {
	return []string{
		"Carrier validity (§4.4 liveness filter 1) is stated per-carrier as `live`, not derived. " +
			"Evaluating it needs the attestation graph (is_attestation_live: not_before / expires_at / " +
			"transitive supersession / self-revocation) and, at Tier C, identity's authority chain to " +
			"the quorum. Those are ATTESTATION's and IDENTITY's rules with their own vectors " +
			"(TV-A1..TV-A6, IDENTITY §9.3); this file gates the ORDER, and re-deriving them here " +
			"would test someone else's spec while pretending to test this one.",

		"§4.4's 'if one is a proper prefix of the other, the shorter sorts first' clause is NOT " +
			"exercised, and cannot be: the clause is unreachable with the formats V7 §4 allocates. " +
			"Two hashes of one format have equal length, and two of different formats differ in " +
			"byte 0 (the format code), so neither can be a prefix of the other. Reaching it would " +
			"need an unallocated format code, which hash decoding rejects before a row is read. " +
			"It is a defensive clause against a future format, and a row asserting it would have " +
			"to be fabricated from bytes no conformant peer can author — evidence of nothing.",

		"`now` is authored per row and only the §4.1 `expires` filter reads it. §4.1 is explicit " +
			"that expiry is the one input evaluated against the sender's LOCAL clock and that a " +
			"straddling sender fails loudly (older key, or recipient_unknown), so no clock model is " +
			"pinned and none is tested here.",

		"Receiver-side behaviour is out of scope. §4.1 makes expiry a sender-side selection filter " +
			"only — a receiver MUST NOT refuse to decrypt because a bound key expired — and this " +
			"file contains no decrypt path to assert that against. It belongs to the §11 vectors.",

		"This file gates the ORDERING rule only. It does not gate hash derivation (§16's KATs do), " +
			"key agreement, or anything on the wire.",
	}
}

// Encode is the single encode path, shared by the emitter and by tests that
// need to write a deliberately-malformed file through the same codec.
func Encode(f VectorFile) ([]byte, error) { return ecf.Encode(f) }

// Emit writes the vector file. The commit pin is passed in rather than derived
// here: shelling out to git is the CLI's business, and a library that reads the
// repository state out from under its caller is harder to test than one that is
// handed it.
func Emit(path, commit string, out io.Writer) error {
	f := VectorFile{
		Schema:        Schema,
		Emitter:       "core-go",
		EmitterCommit: commit,
		Excludes:      Excludes(),
		Rows:          Rows(),
	}
	raw, err := Encode(f)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s (%d bytes)\n", path, len(raw))
	fmt.Fprintf(out, "  schema=%s emitter=%s commit=%s\n", f.Schema, f.Emitter, f.EmitterCommit)
	fmt.Fprintf(out, "  rows=%d excludes=%d\n", len(f.Rows), len(f.Excludes))
	return nil
}

// --- verify -----------------------------------------------------------------

type Report struct {
	Pass  int
	Fail  int
	Lines []string
}

func (r *Report) ok(name string) { r.Pass++; r.Lines = append(r.Lines, "    ok   "+name) }
func (r *Report) bad(name, why string) {
	r.Fail++
	r.Lines = append(r.Lines, "    FAIL "+name+" — "+why)
}

// ToPublications converts a row into the resolver's input shape.
func ToPublications(v ResolveVector) encryption.RecipientPublications {
	conv := func(cs []Carrier) []encryption.Carrier {
		if len(cs) == 0 {
			return nil
		}
		out := make([]encryption.Carrier, 0, len(cs))
		for _, c := range cs {
			out = append(out, encryption.Carrier{Hash: c.Hash, Pubkey: c.Pubkey, Live: c.Live})
		}
		return out
	}
	keys := make(map[hash.Hash]encryption.PubkeyEntity, len(v.Pubkeys))
	for _, k := range v.Pubkeys {
		keys[k.Pubkey] = encryption.PubkeyEntity{Created: k.Created, Expires: k.Expires}
	}
	revPk := make(map[hash.Hash]bool, len(v.RevokedPubkeys))
	for _, h := range v.RevokedPubkeys {
		revPk[h] = true
	}
	revCar := make(map[hash.Hash]bool, len(v.RevokedCarriers))
	for _, h := range v.RevokedCarriers {
		revCar[h] = true
	}
	return encryption.RecipientPublications{
		TierCRelationship: conv(v.TierCRelationship),
		TierC:             conv(v.TierC),
		TierB:             conv(v.TierB),
		TierA:             conv(v.TierA),
		Pubkeys:           keys,
		RevokedPubkeys:    revPk,
		RevokedCarriers:   revCar,
		Now:               v.Now,
	}
}

func reversed(cs []Carrier) []Carrier {
	out := make([]Carrier, len(cs))
	for i, c := range cs {
		out[len(cs)-1-i] = c
	}
	return out
}

// ResolverFn is the surface under test. It is injectable for one reason that
// matters: without it, half the guards in this harness could not be made to
// fail. The permutation pass, and every row asserting a direction, are checked
// against THIS implementation's resolver — which is correct, so nothing ever
// trips them, and a harness whose negative controls cannot fire has not been
// shown to measure anything. §16.6 requirement 3 makes that mandatory, and the
// tests inject deliberately-wrong resolvers for every rule the rows gate.
//
// Note the signature: a resolver receives ONLY the candidate set. It cannot see
// the row's expectation, so no implementation of it can pass by reading the
// answer.
type ResolverFn func(encryption.RecipientPublications) (encryption.Resolution, error)

// CheckRow runs one row against a resolver and compares the result to the row's
// STATED expectation. Nothing here recomputes what the answer ought to be.
func CheckRow(v ResolveVector, resolve ResolverFn) (string, bool) {
	res, err := resolve(ToPublications(v))

	switch v.Expect.Outcome {
	case OutcomeSelected:
		if err != nil {
			return fmt.Sprintf("resolver returned %q, row expects %s at tier %s",
				err, v.Expect.Selected, v.Expect.Tier), false
		}
		if res.Pubkey != v.Expect.Selected {
			return fmt.Sprintf("resolver bound %s, row expects %s", res.Pubkey, v.Expect.Selected), false
		}
		if string(res.Tier) != v.Expect.Tier {
			return fmt.Sprintf("resolver resolved at tier %q, row expects %q — the bound key is right "+
				"but the tier it was found at is not", res.Tier, v.Expect.Tier), false
		}
	case OutcomeError:
		if err == nil {
			return fmt.Sprintf("resolver bound %s at tier %s, row expects error %q",
				res.Pubkey, res.Tier, v.Expect.Error), false
		}
		if v.Expect.Error != types.EncryptionErrRecipientUnknown {
			return fmt.Sprintf("row states error %q, which is not a §4.4 outcome", v.Expect.Error), false
		}
		if !errors.Is(err, encryption.ErrEncryptionRecipientUnknown) {
			return fmt.Sprintf("resolver returned %q, row expects %s", err, v.Expect.Error), false
		}
	default:
		// Neither an implementation fault nor a pass. A row that does not say
		// what it expects cannot be satisfied, and treating it as a skip is how
		// a malformed file reads as a green one.
		return fmt.Sprintf("row states outcome %q, which is neither %q nor %q",
			v.Expect.Outcome, OutcomeSelected, OutcomeError), false
	}
	return "", true
}

// VerifyRows checks every row, then re-checks every row with each tier's
// carrier list reversed.
//
// The permutation pass is structural rather than left to the emitter (§16.6
// requirement 2): §4.4 is a TOTAL order over a set, and a namespace listing has
// no inherent order, so every row must survive permutation. Two rows in the
// file assert this explicitly (so a sibling verifier that only walks rows still
// gets the coverage); doing it structurally as well means a row added later
// cannot forget to.
func VerifyRows(rows []ResolveVector, resolve ResolverFn) *Report {
	r := &Report{}
	for _, v := range rows {
		if why, ok := CheckRow(v, resolve); !ok {
			r.bad(v.Name, why)
			continue
		}
		flipped := v
		flipped.TierCRelationship = reversed(v.TierCRelationship)
		flipped.TierC = reversed(v.TierC)
		flipped.TierB = reversed(v.TierB)
		flipped.TierA = reversed(v.TierA)
		if why, ok := CheckRow(flipped, resolve); !ok {
			r.bad(v.Name+" [reversed]", "resolution depends on enumeration order: "+why)
			continue
		}
		r.ok(v.Name)
	}
	return r
}

func Verify(path string, out io.Writer) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var f VectorFile
	if err := ecf.Decode(raw, &f); err != nil {
		return false, fmt.Errorf("decode vector file: %w", err)
	}
	if f.Schema != Schema {
		return false, fmt.Errorf("schema %q is not %q — refusing to partially check a file this build does not speak",
			f.Schema, Schema)
	}
	// A file with no rows must never summarize as a pass. "0 checks, 0 failed"
	// is arithmetically green and evidentially empty.
	if len(f.Rows) == 0 {
		return false, fmt.Errorf("file contains no rows — nothing was crossed")
	}

	fmt.Fprintf(out, "verifying %s\n", path)
	fmt.Fprintf(out, "  emitter=%s commit=%s schema=%s\n", f.Emitter, f.EmitterCommit, f.Schema)
	fmt.Fprintln(out)

	rep := VerifyRows(f.Rows, encryption.ResolveRecipientKey)
	fmt.Fprintf(out, "  §4.4 resolution order    %d pass / %d fail\n", rep.Pass, rep.Fail)
	for _, l := range rep.Lines {
		fmt.Fprintln(out, l)
	}
	fmt.Fprintln(out)

	// The scope statement is printed on every run, pass or fail. A reader who
	// sees only the headline number must not come away thinking §4.4 is fully
	// crossed when parts of it are deliberately out of frame.
	fmt.Fprintln(out, "  Scope — stated by the file, not inferred:")
	for _, e := range f.Excludes {
		fmt.Fprintf(out, "    - %s\n", e)
	}
	fmt.Fprintln(out)

	total := rep.Pass + rep.Fail
	if rep.Fail == 0 {
		fmt.Fprintf(out, "ENC-RESOLVE-ORDER-1: PASS — %d·0F @ %s (%s)\n", total, f.EmitterCommit, f.Emitter)
		return true, nil
	}
	fmt.Fprintf(out, "ENC-RESOLVE-ORDER-1: FAIL — %d checks, %d failed (emitter %s @ %s)\n",
		total, rep.Fail, f.Emitter, f.EmitterCommit)
	return false, nil
}
