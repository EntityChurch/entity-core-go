package signaling

import (
	"errors"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §6.3 the self-contained coordination envelope — `system/signaling/signed-blob`.
//
// WHAT IT CLOSES. §6.2 said the blob is the bare entity encoding; §6.3 said the
// blob also carries a detached signature and the signer's public key. Both could
// not be true of the same bytes, and §12 registered no container — so §6.3's
// security MUST was unimplementable and both impls shipped without it. §6.2's
// framing is now repointed here: the carrier stores the ENVELOPE, and the
// coordination entity rides inside it verbatim.
//
// WHY SELF-CONTAINED. A rendezvous verifier is a stranger. It has collected a
// blob from a shared bucket and has no connection to the signer, no capability
// chain, and no way to look a key up — so system/signature (which carries the
// signer as a HASH) cannot serve. Everything needed to verify travels in the
// envelope, and the only thing the verifier supplies is the rendezvous key it
// collected from (see the binding below).
//
// TWO THINGS HERE ARE LOAD-BEARING AND EASY TO GET SUBTLY WRONG:
//
//  1. The peer-id is DERIVED, never decoded from the wire. See OpenBlob.
//  2. The signature covers the rendezvous key, which is NOT a field. See
//     signingInput.

// ErrUnusableKey reports key material that never reached the signature check:
// a public key whose length does not match its key_type, a key_type with no
// canonical hash type, or a `signer` that does not equal the id its own public
// key derives. Distinct from ErrBadSignature on purpose — reporting a bad
// signature here sends a diagnostician after the key material when the fault is
// in the key TYPE. The three names (unusable_key / signer_mismatch /
// bad_signature) are the cohort-agreed taxonomy.
var ErrUnusableKey = errors.New("signaling: key material is unusable — public_key does not derive `signer` (§6.3)")

// ErrNotAContainer reports a blob that is not a `signed-blob` at all — it did
// not decode as an entity, or it decoded as some other type.
//
// A FOURTH OUTCOME, NOT ONE OF THE THREE, and the distinction is operational
// rather than pedantic. §6.4 makes a bucket a mixed set the node never
// interprets: legacy unsigned coordination entities, another impl's traffic, a
// message type this build has never heard of. During the migration window —
// which is now, since both impls still deposit bare entities — a collector sees
// these constantly. Filing them under ErrUnusableKey would flood the local
// observability channel with key-material alarms for blobs that carry no key
// at all, which is exactly the noise that makes a real `unusable_key` easy to
// miss. This is a skip, not a verdict. (entity-core-rust's `decode_skip`,
// 92897a9 — found by their vector row, adopted here.)
var ErrNotAContainer = errors.New("signaling: blob is not a system/signaling/signed-blob (§6.4 skip, not a verification verdict)")

// canSign reports whether a key_type can carry a signature at all.
//
// This gate exists because Go DERIVES a peer-id for key types it cannot verify
// with: KeyTypeExperimentalTest (0xFE) has a canonical hash type and a defined
// public-key length, so PeerIDFromPublicKey succeeds — and then crypto.Verify
// returns false for it, which reported as ErrBadSignature. That is precisely the
// misdiagnosis the three-name taxonomy exists to prevent: it sends a
// diagnostician after the key MATERIAL when the fault is that the key TYPE
// cannot sign, and it is one inference away from the hardcoded reject that
// locked out Ed448. Found by entity-core-rust's `unsupported-key-type/0xfe` row.
//
// Kept as an explicit allowlist rather than a "not experimental" check: a new
// sign-capable key type must be added here deliberately, and a new non-signing
// one is refused by default.
func canSign(keyType byte) bool {
	return keyType == crypto.KeyTypeEd25519 || keyType == crypto.KeyTypeEd448
}

// ErrRendezvousMismatch reports a blob whose signature does not cover the
// rendezvous key it was collected from — a blob lifted from another bucket and
// replayed here. It is a distinct diagnostic from ErrBadSignature because the
// signature is perfectly valid; it is valid for somewhere else.
var ErrRendezvousMismatch = errors.New("signaling: signature does not cover this rendezvous key (§6.3 bucket binding)")

// SigningDomain versions what a coordination signature covers. Adopted from
// entity-core-rust's envelope (0dd1ba3), matching key.go's existing
// "entity:rdv:v1" convention: a future change to what is covered becomes a NEW
// domain rather than a silent reinterpretation of the same bytes.
const SigningDomain = "entity:sigblob:v1"

// signingInput is what a coordination signature actually covers:
//
//	"entity:sigblob:v1" ‖ SEP ‖ rendezvous key (33 bytes) ‖ content_hash (33 bytes)
//
// THE DOMAIN TAG IS RUST'S AND IT IS BETTER THAN THE ALTERNATIVE WE SHIPPED
// FIRST. Go's first cut signed the bare `content_hash ‖ rendezvous_key` and
// argued the 66-byte length domain-separated it from every other signature in
// the tree, all of which sign a bare 33-byte hash. That reasoning is true today
// and fragile: it holds only because no other signature happens to be 66 bytes,
// so the separation would evaporate the first time one was — silently, with a
// cross-protocol replay as the symptom. An explicit versioned tag does not
// depend on a coincidence of lengths. Converged on theirs rather than
// re-litigating; the byte order (key before hash) is theirs too, and arbitrary.
//
// THE CONTENT HASH IS THE 33-BYTE WIRE FORM — `content_hash_format ‖ digest`,
// not the bare 32-byte digest. The format byte travels with the hash everywhere
// else in this codebase (capability/mint, protocol/connect, the invariant-pointer
// rule), and this is the 33-vs-32 trap in a stranger-verifiable place.
//
// THE RENDEZVOUS KEY IS AN INPUT, NOT A FIELD, and that is the whole design.
// Without it a valid blob replays verbatim into any other bucket and verifies —
// not a channel hijack (the SDP's a=fingerprint still binds DTLS, RFC 8827) but
// a peer in an unrelated bucket can be induced to attempt a connection to a
// signer that never addressed it. The obvious fix is a `rendezvous_key` envelope
// field, and it is the WRONG fix: a carried field must be checked against the
// bucket the verifier actually collected from, and a verifier that forgets that
// check accepts every replay while looking correct. Supplying the key as a
// signing input makes the check unforgettable — a verifier that does not have
// the right key cannot construct the message, so it cannot succeed by omission.
// This is the same lesson as the peer-id derivation directly below: do not carry
// a value on the wire that you must remember to validate.
//
// The concatenation after the tag is unambiguous without length prefixes
// because the ONE variable-length component is LAST: tag (17) ‖ SEP (1) ‖
// rendezvous key (33, pinned) ‖ content hash (remainder).
//
// The content hash's length follows its OWN format byte and is never assumed
// (EXTENSION-SIGNALING §6.3 as corrected 2026-08-10; SPECIFICATION-FORMAT
// §8.4.5): 33 bytes under ECFv1-SHA-256, 49 under ECFv1-SHA-384. It is
// AUTHORED CONTENT, so it follows the signing peer's home format. The
// rendezvous key beside it stays pinned at 33 and that is NOT an exception —
// §3.1 pins its digest *format* to the SHA-256 floor because a rendezvous key
// is a lookup token two independent parties must reproduce, not authored
// content, and the width follows from that pin. Authored content vs.
// reproduced lookup token is the whole distinction, and it is why the same
// document is right about one field and was wrong about its neighbour.
func signingInput(contentHash []byte, rendezvousKey []byte) ([]byte, error) {
	if _, err := hash.FromBytes(contentHash); err != nil {
		return nil, fmt.Errorf("%w: content_hash is not a well-formed wire hash (format ‖ digest): %v",
			ErrUnusableKey, err)
	}
	if len(rendezvousKey) != RendezvousKeyLen {
		return nil, fmt.Errorf("%w: rendezvous key is %d bytes, want %d",
			ErrRendezvousMismatch, len(rendezvousKey), RendezvousKeyLen)
	}
	msg := make([]byte, 0, len(SigningDomain)+1+len(rendezvousKey)+len(contentHash))
	msg = append(msg, SigningDomain...)
	msg = append(msg, sep)
	msg = append(msg, rendezvousKey...)
	msg = append(msg, contentHash...)
	return msg, nil
}

// SigningInputLen returns the total byte length of a coordination signing
// input for a content hash of the given content_hash_format:
// 17 (domain) + 1 (SEP) + 33 (rendezvous key) + hash wire size.
//
// 84 under ECFv1-SHA-256, 100 under ECFv1-SHA-384. This was a const pinned at
// 84 — a width lock that made the signing input unrepresentable for any peer
// whose home format is not SHA-256. Returns 0 for an unallocated format.
func SigningInputLen(alg byte) int {
	n := hash.HashWireSize(alg)
	if n == 0 {
		return 0
	}
	return len(SigningDomain) + 1 + RendezvousKeyLen + n
}

// RendezvousKeyLen is the length of a §3.1 rendezvous key: 33 bytes, the
// algorithm‖digest wire form at the SHA-256 floor (see key.go's Derive).
const RendezvousKeyLen = 33

// SealBlob builds the §6.3 envelope for one coordination entity, signing it for
// deposit at a specific rendezvous key.
//
// The entity is encoded ONCE here and the resulting bytes are both signed over
// (via the entity's own content hash) and embedded verbatim. A caller that
// re-encodes the inner entity anywhere downstream invalidates the signature
// silently, which is why OpenBlob hands back the decoded entity and the raw
// bytes are never rebuilt.
func SealBlob(e entity.Entity, kp crypto.Keypair, rendezvousKey []byte) (types.SignedBlobData, error) {
	// Derive the signer's own id canonically. A peer that minted its id any
	// other way would produce an envelope nobody can verify, so this is the
	// same call the verifier makes rather than a stored string.
	signer, err := crypto.PeerIDFromPublicKey(kp.PublicKeyBytes(), kp.KeyType)
	if err != nil {
		return types.SignedBlobData{}, fmt.Errorf("%w: %v", ErrUnusableKey, err)
	}
	inner, err := ecf.Encode(e)
	if err != nil {
		return types.SignedBlobData{}, err
	}
	msg, err := signingInput(e.ContentHash.Bytes(), rendezvousKey)
	if err != nil {
		return types.SignedBlobData{}, err
	}
	return types.SignedBlobData{
		Entity:    inner,
		Signer:    signer.String(),
		PublicKey: kp.PublicKeyBytes(),
		Signature: kp.Sign(msg),
	}, nil
}

// OpenBlob performs §6.3's verification over a decoded envelope and returns the
// verified signer together with the inner coordination entity.
//
// THE PEER-ID IS DERIVED, NOT DECODED. `signer` is a wire field and therefore
// forgeable, so it is never trusted as given: the id is recomputed from
// (public_key, key_type) using the CANONICAL hash type for that key type, and
// the whole `signer` string must equal it. In particular a well-formed but
// non-canonical hash_type is rejected. A verifier that instead parsed hash_type
// out of `signer` and dispatched on it would accept TWO distinct ids for one key
// — `0x01‖0x00‖pk` and `0x01‖0x01‖SHA-256(pk)` both bind the same key — letting a
// peer choose its own identity per message. Every §6.5 decision is a sort over
// that id (§3.2's pair key picks the bucket, Impolite picks the glare winner,
// §6.4 skip-own decides whether an entity is your own), so a chosen id is a
// chosen negotiation role, a split rendezvous, and a peer that stops recognizing
// its own offer. crypto.PeerIDFromPublicKey is canonical-only by construction,
// which is what makes this a one-liner rather than a hand-rolled comparison.
//
// UNSUPPORTED KEY TYPES SKIP, THEY DO NOT REJECT. A well-formed key_type this
// build does not implement returns ErrUnusableKey, and §6.4's disposition for
// any failed check is to skip the blob as if undecodable — never a hardcoded
// rejection of the type. Hardcoding `key_type != ed25519 → reject` is exactly
// the defect Go's Ed448 vector row caught in Rust: it silently locked out an
// identity that implementation itself mints.
func OpenBlob(d types.SignedBlobData, rendezvousKey []byte) (VerifiedSigner, entity.Entity, error) {
	// key_type comes from `signer` — the spec's design, and self-checking
	// despite the field being forgeable: lying about key_type changes the
	// prefix of the id this same key derives, so the full-string comparison
	// below catches it. hash_type is deliberately NOT read; the canonical one
	// for key_type is used instead, which is what closes the malleability.
	decoded, err := crypto.PeerID(d.Signer).Decode()
	if err != nil {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: %v", ErrUnusableKey, err)
	}
	derived, err := crypto.PeerIDFromPublicKey(d.PublicKey, decoded.KeyType)
	if err != nil {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: %v", ErrUnusableKey, err)
	}
	if derived.String() != d.Signer {
		return VerifiedSigner{}, entity.Entity{}, ErrUnusableKey
	}
	// Sign-capability is checked HERE, before the signature, so a key type that
	// cannot sign is reported as unusable rather than as a bad signature. §4
	// requires an unsupported key_type to be SKIPPED (MUST-ignore, ADR-0002);
	// calling it a bad signature codes it as "this peer is lying," which is the
	// reading that justifies a hardcoded reject.
	if !canSign(decoded.KeyType) {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: key_type 0x%02x cannot carry a signature",
			ErrUnusableKey, decoded.KeyType)
	}

	// The inner entity is decoded for the caller but NEVER re-encoded: its
	// content hash is recomputed from the bytes as received, so a blob whose
	// declared content_hash disagrees with its own {type, data} fails here
	// rather than verifying against a hash the sender chose.
	var inner entity.Entity
	if err := ecf.Decode(d.Entity, &inner); err != nil {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: inner entity: %v", ErrUnusableKey, err)
	}
	if err := inner.Validate(); err != nil {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: inner entity content_hash: %v", ErrBadSignature, err)
	}

	msg, err := signingInput(inner.ContentHash.Bytes(), rendezvousKey)
	if err != nil {
		return VerifiedSigner{}, entity.Entity{}, err
	}
	if !crypto.Verify(decoded.KeyType, d.PublicKey, msg, d.Signature) {
		// Ambiguous by construction between "forged/tampered" and "valid but
		// for another bucket" — a verifier cannot tell without trying other
		// keys, and it has none. ErrRendezvousMismatch is reported only where
		// the caller supplied a malformed key (above); on the wire this is one
		// outcome, and §6.4 skips it either way.
		return VerifiedSigner{}, entity.Entity{}, ErrBadSignature
	}
	return VerifiedSigner{PeerID: derived.String()}, inner, nil
}

// SealedToBlob encodes a sealed envelope to the bytes a bucket stores.
func SealedToBlob(d types.SignedBlobData) ([]byte, error) {
	e, err := d.ToEntity()
	if err != nil {
		return nil, err
	}
	return ecf.Encode(e)
}

// OpenBlobBytes is the full receive path: bucket bytes → verified signer +
// inner entity. A blob that is not a signed-blob at all is ErrUnusableKey, which
// §6.4 skips — a shared bucket may hold anything, including a message type this
// build has never heard of.
func OpenBlobBytes(blob []byte, rendezvousKey []byte) (VerifiedSigner, entity.Entity, error) {
	var outer entity.Entity
	if err := ecf.Decode(blob, &outer); err != nil {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: %v", ErrNotAContainer, err)
	}
	if outer.Type != types.TypeSignalingSignedBlob {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: type %q", ErrNotAContainer, outer.Type)
	}
	d, err := types.SignedBlobDataFromEntity(outer)
	if err != nil {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: envelope data: %v", ErrNotAContainer, err)
	}
	return OpenBlob(d, rendezvousKey)
}

// OpenBlobClaimed is OpenBlob plus §6.3 step 3 — the claim comparison, for the
// §6.1 native path where the inner entity names its own initiator/responder.
//
// It is a SEPARATE entry point rather than a flag because the §6.5 payloads
// carry no peer-id: there is nothing to cross-check against, the signature IS
// the claim, and a caller that passed an empty claim to a combined function
// would silently get no check at all. Only the claim comparison catches a
// genuinely valid signature presented under a false identity — every other
// check in OpenBlob passes such a blob, because nothing about it is forged.
func OpenBlobClaimed(d types.SignedBlobData, rendezvousKey []byte, claimedPeerID string) (VerifiedSigner, entity.Entity, error) {
	signer, inner, err := OpenBlob(d, rendezvousKey)
	if err != nil {
		return VerifiedSigner{}, entity.Entity{}, err
	}
	if signer.PeerID != claimedPeerID {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: signature is by %s, claim names %s",
			ErrSignerMismatch, signer.PeerID, claimedPeerID)
	}
	return signer, inner, nil
}

// OpenBlobBytesClaimed is the bytes-in form of OpenBlobClaimed.
func OpenBlobBytesClaimed(blob []byte, rendezvousKey []byte, claimedPeerID string) (VerifiedSigner, entity.Entity, error) {
	signer, inner, err := OpenBlobBytes(blob, rendezvousKey)
	if err != nil {
		return VerifiedSigner{}, entity.Entity{}, err
	}
	if signer.PeerID != claimedPeerID {
		return VerifiedSigner{}, entity.Entity{}, fmt.Errorf("%w: signature is by %s, claim names %s",
			ErrSignerMismatch, signer.PeerID, claimedPeerID)
	}
	return signer, inner, nil
}

// ClassifySealed is the §6.4 bucket-read path with §6.3 applied: verify first,
// then classify. Returns KindUnknown for anything that fails verification, which
// is the §6.4 disposition — a failed check is SKIPPED, never surfaced as an
// error, because a shared mailbox holding a bad entry is a normal condition and
// not a fault of the peer reading it.
//
// The skip is silent ON THE WIRE and observable LOCALLY: the error is returned
// alongside so a caller can log or count it with the taxonomy label. That is
// deliberate — the Ed448 hardcode survived precisely because a failed check is
// skipped and never raised, and it stayed invisible until a vector row crossed
// it. Silence in the implementation is how that class of defect lives.
func ClassifySealed(blob []byte, rendezvousKey []byte) (CollectedMessage, VerifiedSigner, error) {
	signer, inner, err := OpenBlobBytes(blob, rendezvousKey)
	if err != nil {
		return CollectedMessage{Kind: KindUnknown}, VerifiedSigner{}, err
	}
	return Classify(inner), signer, nil
}

// --- the read side of the flag day ------------------------------------------

// ErrPolicyUnset reports a consumer that never chose a verification policy.
//
// The zero value of VerificationPolicy is deliberately NOT a working policy, and
// that costs one constant to say. Go's zero value would otherwise hand a caller
// the tolerant posture for free — the weaker of the two, acquired by forgetting
// a struct field rather than by deciding anything — and the whole point of the
// flag day is that the posture is a decision somebody made on a date. Rust's
// counterpart is a required constructor argument (`PunchParty::new(.., trust)`,
// no default); a Go struct literal has no such thing, so the invalid zero is how
// the same requirement is expressed here.
var ErrPolicyUnset = errors.New("signaling: no VerificationPolicy chosen — the zero value is not a policy (§6.3)")

// VerificationPolicy selects what an exchange accepts from a bucket.
//
// IT IS APPLIED BY THE CONSUMER, NOT BY THE CLASSIFIER, and that placement is
// the rule rather than a layering preference. Only the consumer knows which
// messages were ITS OWN to act on — the nonce echo, the session id, the
// expected peer — and a bare message must be refused loudly if it was ours and
// skipped silently if it was a stranger's. A classifier that dropped bare blobs
// under VerifyRequire would make that distinction impossible to draw: the
// message we needed to refuse by name would already be gone, and the exchange
// would end in a timeout reported as "nobody replied". ClassifyCollected
// therefore takes no policy — it applies §6.4's four dispositions, and the
// consumer decides what to do with an unverified result.
//
// One home for the type, two consumers (the §6.1 punch, and whatever drives
// §6.5), so the postures cannot drift apart. (Same arrangement as
// entity-core-rust's, whose `classify_collected` is likewise policy-free.)
type VerificationPolicy int

const (
	// VerifyUnset is the zero value and is not a policy — see ErrPolicyUnset.
	VerifyUnset VerificationPolicy = iota

	// VerifyTolerant acts on BOTH framings: a §6.3 container and a bare
	// coordination entity. This is the migration posture, because a bucket
	// mid-changeover holds bare entities from peers that have not flipped and
	// containers from peers that have. Refusing either makes the flag day a hard
	// cutover instead of a rolling one.
	//
	// Nothing is lost by tolerating both: which framing arrived IS the presence
	// of a verified Signer on the result, so a consumer can tell them apart, and
	// VerifyRequire turns the distinction into a refusal.
	VerifyTolerant VerificationPolicy = iota

	// VerifyRequire accepts only verified containers. Unsigned entities are
	// skipped. This is the post-flag-day posture and what §6.3's MUST actually
	// asks for. A message that WAS ours and arrived bare is refused by name (see
	// the punch's ErrUnverifiedCounterpart) rather than dropped.
	VerifyRequire
)

// claimedPeerID returns the peer-id a classified message NAMES as its own
// author, and whether it names one at all — §6.3 step 3's left-hand side.
//
// Only the two §6.1 native messages carry an author field. punch-sync names
// nobody (its correlation is the nonce echo), and none of the three §6.5
// payloads carry a peer-id at all — for those the signature IS the claim and
// step 3 has nothing to compare, which is why it went unimplemented while the
// container work was §6.5-shaped.
//
// The bool is not decoration: "names nobody" and "names the empty string" have
// to be different answers, or a payload with an absent field would be compared
// against "" and every verified signer would mismatch it.
func claimedPeerID(m CollectedMessage) (string, bool) {
	switch m.Kind {
	case KindConnectRequest:
		return m.Request.Initiator, true
	case KindConnectResponse:
		return m.Response.Responder, true
	default:
		return "", false
	}
}

// ClassifyCollected is the §6.4 bucket-read path with §6.3 applied.
//
// FOUR BEHAVIORS HERE ARE CROSS-IMPL-VISIBLE even though this is local code,
// and they mirror entity-core-rust's read side (6077229, b1eb4b5) deliberately:
//
//  1. Both framings are classified — a container is unwrapped and verified
//     against the bucket it came from, a bare entity is read as the §6.2 framing
//     it is. Which one arrived is reported as the presence of Signer, and the
//     CONSUMER decides whether bare is acceptable (see VerificationPolicy). This
//     function takes no policy for the reason given there.
//
//  2. A CONTAINER THAT FAILS TO VERIFY IS SKIPPED — NEVER RE-READ AS BARE.
//     This is the one that is easy to get wrong and it is a real attack: if a
//     failed container fell back to the bare path, anyone could downgrade a
//     signed offer into an ACCEPTED unsigned one by corrupting a single
//     signature byte. The container would fail, the fallback would decode the
//     same inner entity, and the peer would act on unauthenticated SDP —
//     defeating the exact thing the container exists to provide. The
//     distinction is only expressible because ErrNotAContainer is separate from
//     the verification failures: "this was never a container" and "this is a
//     container that did not verify" are opposite dispositions.
//
//  3. A signer is USED when present, not ignored. A peer that has flipped gets
//     §6.4's skip-own against a real identity even while its counterpart has
//     not, so the tolerant path converges on the strict one as the migration
//     completes rather than staying permanently weaker.
//
//  4. STEP 3 — THE CLAIM COMPARISON — RUNS HERE, and only here is it possible.
//     §6.1's connect-request and connect-response name their author in a wire
//     field, so a signature that is ENTIRELY VALID under a false `initiator`
//     satisfies every other check in OpenBlob: nothing about such a blob is
//     forged, the key derives its own id honestly, and the signature covers this
//     bucket. Only comparing the verified signer against the claim catches it.
//     The comparison cannot live in OpenBlob because the claim is not known
//     until the inner entity has been classified — which is exactly why
//     OpenBlobClaimed sat here as an API with no caller in the read path while
//     the container work was §6.5-shaped, and why the gap survived the crossing.
//
// The error is returned alongside the message rather than swallowed: §6.4 makes
// the skip silent ON THE WIRE, and local observability is what keeps a failed
// check from being invisible.
func ClassifyCollected(blob []byte, rendezvousKey []byte) (CollectedMessage, error) {
	signer, inner, err := OpenBlobBytes(blob, rendezvousKey)
	switch {
	case err == nil:
		m := Classify(inner)
		if claim, named := claimedPeerID(m); named && claim != signer.PeerID {
			// A valid signature under a false name. Skipped like any other
			// failed check (§6.4), and reported under the taxonomy's third
			// name so it is not read as a broken signature — the signature is
			// fine, the identity behind it is not the one being asserted.
			return CollectedMessage{Kind: KindUnknown}, fmt.Errorf("%w: signature is by %s, the message names %s",
				ErrSignerMismatch, signer.PeerID, claim)
		}
		m.Signer = signer
		return m, nil

	case errors.Is(err, ErrNotAContainer):
		// Never was a container. Normal bucket contents (§6.4) — legacy
		// unsigned traffic, or a message type this build has never heard of.
		// Classified with NO signer, which is how a consumer under VerifyRequire
		// recognizes it and refuses it by name if it was one of ours.
		return ClassifyBlob(blob), nil

	default:
		// WAS a container and failed to verify. Skip it. Falling through to the
		// bare path here is the downgrade attack described above.
		return CollectedMessage{Kind: KindUnknown}, err
	}
}
