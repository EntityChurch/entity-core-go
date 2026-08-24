package signaling

import (
	"bytes"
	"crypto/rand"
	"errors"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §6.5 WebRTC-substrate coordination — the browser leg's half of the carrier.
//
// WHAT THIS IS AND IS NOT. This is the coordination layer only: the three
// signed payloads, their session correlation, the offerer/glare rule, and the
// §6.3 checks that gate them. It is NOT a WebRTC transport. Go has no ICE stack
// and terminates no data channel; it neither publishes nor honors a
// system/peer/transport/webrtc profile (EXTENSION-NETWORK §6.5.2d makes a native
// profile a MAY that stays latent until a native terminator exists, and Go is
// not one). Nothing here should be read as a browser-leg capability claim.
//
// WHY GO BUILDS IT ANYWAY. §6.5's offerer rule is a cross-peer convention, and
// §11.5.1 flags it as pinned-but-single-impl-validated: the S5 gate is two
// browser peers likely running the SAME WebRTC implementation, which cannot
// prove two implementations agree on a convention. fire_at (§7.2) and the
// handshake role (§7.4.1) were both cross-peer conventions found wrong in
// exactly that blind spot. A second, independent implementation of the RULE —
// which is pure, deterministic, and needs no ICE stack — is the cheapest thing
// that narrows it, and it is cheapest now, before S3 builds against it.
//
// WHAT IS DELIBERATELY MISSING. §6.3 says the coordination blob is
// self-contained: "the entity plus a detached signature carrying the signer's
// public_key." The two CHECKS it specifies are implemented below
// (VerifyCoordinationSignature). The CONTAINER that carries the signature and
// public key alongside the entity is not specified anywhere — §6.2 pins the blob
// as the bare {type, data, content_hash} encoding, §12 registers no envelope
// type, and system/signature (core/types/crypto.go) does not fit: it carries
// Signer as a HASH, which is not self-contained for a stranger, which is the
// whole point of the §6.3 exception. Inventing a container here would be
// inventing a cross-peer wire format in an implementation repo. Routed to arch
// instead, 2026-08-03: the §6.3 coordination envelope is unpinned.

// SessionIDMinLen is the §6.5 MUST floor for session_id: freshly random and at
// least 16 bytes. The consequence of a weak or colliding value is not a failed
// handshake but a SILENT CROSS-HANDSHAKE — two concurrent pairings in one lobby
// bucket whose offer/answer/candidate tuples splice together — so this is
// enforced on receipt (Classify) as well as on generation.
const SessionIDMinLen = 16

// ErrSessionIDTooShort is returned by ValidateSessionID. On the READ path a
// message carrying one is skipped rather than surfaced (§6.4): a bucket is a
// shared mailbox, so a malformed entry is a normal condition, not a fault of the
// peer reading it.
var ErrSessionIDTooShort = errors.New("signaling: session_id shorter than 16 bytes (§6.5 MUST)")

// ErrSelfNegotiation reports a negotiation against this peer's own id. §6.4
// requires skipping one's own messages, so reaching a glare resolution with
// two equal peer-ids means that MUST was missed upstream — there is no correct
// answer to return, and returning an arbitrary one would let a peer negotiate
// with itself and report success at every step.
var ErrSelfNegotiation = errors.New("signaling: negotiation against own peer_id (§6.4 skip-own was not applied)")

// ErrSignerMismatch reports that the public key in a coordination blob does not
// derive the peer-id it claims (§6.3 check (a)).
var ErrSignerMismatch = errors.New("signaling: public_key does not derive the claimed peer_id (§6.3)")

// ErrBadSignature reports that the signature does not verify over the entity's
// content hash (§6.3 check (b)).
var ErrBadSignature = errors.New("signaling: signature does not verify over the entity content hash (§6.3)")

// ErrUnverifiedSDP reports an attempt to take SDP out of a message whose signer
// was not verified — §6.5's channel-identity MUST NOT.
var ErrUnverifiedSDP = errors.New("signaling: refusing to hand out SDP from an unverified entity (§6.5)")

// GenerateSessionID returns a fresh random session_id of the §6.5 minimum
// length. Distinct from GenerateNonce despite the identical size: the nonce
// correlates ONE native exchange, while a session_id groups an offer, an answer,
// and an unbounded trickle of candidates arriving over time. They are kept
// separate so a future change to either does not silently move the other.
func GenerateSessionID() ([]byte, error) {
	b := make([]byte, SessionIDMinLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ValidateSessionID enforces the §6.5 length floor. It cannot check randomness
// — no receiver can — which is exactly why the floor is normative: length is the
// only property of the MUST that is checkable on the wire.
func ValidateSessionID(id []byte) error {
	if len(id) < SessionIDMinLen {
		return ErrSessionIDTooShort
	}
	return nil
}

// peerIDLess is the §3.2 byte-wise ascending peer-id order. One canonical home:
// PairKey derives the rendezvous key with it and §6.5 assigns negotiation roles
// with it, and the spec is explicit that the offerer rule REUSES that sort
// rather than introducing a second convention. Two orderings that agreed today
// and drifted later would desynchronize the key and the role together.
func peerIDLess(a, b string) bool {
	return bytes.Compare([]byte(a), []byte(b)) < 0
}

// Impolite reports whether this peer is the impolite one in W3C perfect
// negotiation: the LOWER-sorting peer-id (`lo`), whose offer wins a glare. The
// higher (`hi`) is polite and rolls back. Returns ErrSelfNegotiation when the
// two ids are equal.
func Impolite(myPeerID, theirPeerID string) (bool, error) {
	if myPeerID == theirPeerID {
		return false, ErrSelfNegotiation
	}
	return peerIDLess(myPeerID, theirPeerID), nil
}

// GlareOutcome is what a peer does when it collects an offer while holding its
// own un-answered one. WebRTC is asymmetric and a glare is FATAL to the
// RTCPeerConnection state machine, so this must be deterministic rather than
// empirical — native's both-fire symmetry (§7.1 step 4) and §7.4.1's measured
// role resolution do not survive it.
type GlareOutcome int

const (
	// GlareKeepMine — I am `lo` (impolite): my offer stands, I ignore theirs and
	// wait for their answer. The peer that ends up the offerer is also the
	// §7.4.1 initiator, so the post-establishment HELLO client role follows this
	// same assignment — one role decision, not two.
	GlareKeepMine GlareOutcome = iota
	// GlareRollBack — I am `hi` (polite): I roll back my own offer and answer
	// theirs. Rolling back ABANDONS my session_id: from here the exchange is
	// correlated by the offerer's, and anything I already posted under mine is
	// stranded where no counterpart will look for it. That is what MayTrickle
	// exists to prevent — see its comment for why the loss is silent.
	GlareRollBack
)

// ResolveGlare decides a both-offered collision. It is called only in the glare
// case: the NORMAL flow needs no rule at all, because post order settles it —
// whoever collects an offer while holding none of its own simply answers. That
// is why this package has no "who offers first" function.
//
// Both peer-ids are known at this point (they come from the §6.3 signature, not
// from a payload field — the §6.5 entities carry no peer-id), so both sides run
// this on the same two inputs and converge: exactly one keeps its offer.
func ResolveGlare(myPeerID, theirPeerID string) (GlareOutcome, error) {
	impolite, err := Impolite(myPeerID, theirPeerID)
	if err != nil {
		return GlareKeepMine, err
	}
	if impolite {
		return GlareKeepMine, nil
	}
	return GlareRollBack, nil
}

// PairShouldWaitForOffer reports whether this peer SHOULD suppress its own
// offer and wait — the `pair`-mode optimization (§6.5): both ids are known in
// advance there, so `hi` skips the glare round trip.
//
// This is an optimization and NOT a general rule. In tag / secret / lobby a peer
// does not know its counterpart until it collects the counterpart's first
// entity, so it cannot pre-assign at all; a flat "lo always offers" would be
// wrong there, and worse than wrong — forcing `lo` to counter-offer after `hi`
// legitimately offered first would MANUFACTURE the glare this rule exists to
// prevent. Those modes rely on ResolveGlare instead.
func PairShouldWaitForOffer(myPeerID, theirPeerID string) (bool, error) {
	impolite, err := Impolite(myPeerID, theirPeerID)
	if err != nil {
		return false, err
	}
	return !impolite, nil
}

// TrickleState is what a peer knows about its OWN session at the moment it is
// about to post gathered ICE candidates. The three flags are the only inputs
// the rule needs; they are a struct rather than three positional bools because
// a caller that transposes two of them gets a silent candidate leak, not a
// compile error.
type TrickleState struct {
	// Offered — this peer has posted its own offer, under its own session_id.
	Offered bool
	// Answered — this peer has adopted the counterpart's session_id and
	// answered their offer. Once true the session is final, however it was
	// reached (never offered, or offered and rolled back).
	Answered bool
	// Rollback — this peer holds an un-answered offer of its own AND has
	// collected a counterpart's offer that ResolveGlare resolved as
	// GlareRollBack. Meaningful only while Offered && !Answered; it marks the
	// window in which this peer's own session_id is already doomed but the
	// counterpart's has not been adopted yet.
	Rollback bool
}

// MayTrickle reports whether this peer's session_id is SETTLED — i.e. whether a
// candidate posted now will be correlated by the counterpart, or silently lost.
//
// WHY THIS IS A RULE AND NOT A CALLER'S DETAIL. Candidates correlate on exact
// session_id (CollectWebRTCCandidates), and gathering is driven by the ICE
// agent's clock, not by the signaling exchange — so a peer can have candidates
// in hand BEFORE its session is final. Posting them then is not "early", it is
// LOST: the counterpart queries the settled session and never asks for the
// provisional one, and a substrate that drains its gathering queue destructively
// has no second chance to re-post them. Every individual step reports success —
// the post succeeds, the collect succeeds and returns the offer, the handshake
// simply never completes — which is the §6.4 failure class the spec calls
// miserable to diagnose.
//
// THE TWO WINDOWS. There are exactly two ways to hold a session nobody will
// query, and they are reached from opposite directions:
//
//  1. Never offered. A prospective answerer minted a session for the offer it
//     has not made, and will adopt the offerer's the moment it collects one.
//     (Reported by entity-core-rust, 67e6d96, and fixed there as
//     `!offered && !answered`.)
//  2. Offered, then conceding. A peer that DID offer, hit a glare, and drew
//     GlareRollBack: its session is already abandoned in favor of the
//     offerer's, but it has not answered yet. `offered || answered` reads TRUE
//     across this whole window, so a two-term gate lets candidates out under a
//     session the peer itself is in the middle of discarding.
//
// Window 2 is unreachable in `pair` mode — PairShouldWaitForOffer pre-assigns
// the roles, so exactly one peer offers and no glare occurs — which is why it
// does not appear in a pair-scoped negotiation loop. It opens in tag / secret /
// lobby, where the counterpart is unknown until it speaks and ResolveGlare is
// the only thing standing between two offers.
//
// Browsers happen to gather only after setLocalDescription, which lands after
// adoption on both paths, so both windows are latent against a browser
// substrate and immediate against anything that pre-gathers. That is a property
// of the substrate's timing, not of this rule — which is exactly why the rule
// is stated here rather than left to hold by accident.
func MayTrickle(s TrickleState) bool {
	if s.Answered {
		return true
	}
	if !s.Offered {
		return false
	}
	return !s.Rollback
}

// VerifiedSigner is proof that §6.3's two checks passed for one coordination
// entity: the public key derives the peer-id, and the signature verifies over
// the entity's content hash. It is returned only by VerifyCoordinationSignature,
// so a caller cannot construct one by asserting it — which is what makes
// AcceptRemoteDescription's guard mean something.
type VerifiedSigner struct {
	// PeerID is the derived-and-checked signer identity. For the §6.5 payloads
	// this is the ONLY source of the counterpart's peer-id — offer, answer and
	// candidate carry no initiator/responder field — so the offerer rule above
	// depends on this value existing.
	PeerID string
}

// VerifyCoordinationSignature performs §6.3's two checks over an already-parsed
// triple and returns the verified signer.
//
// It takes (entity, publicKey, keyType, signature) as PARAMETERS rather than
// parsing a blob, and that is deliberate, not an oversight: the checks are
// pinned by the spec and implemented here, while the container that carries the
// signature and public key alongside the entity is NOT pinned anywhere (see the
// file header). Parsing a container Go invented would create a second wire
// format for the cohort to diverge from. When §6.3's envelope lands, the parser
// is a small function above this one and this stays unchanged.
//
// The message signed is the entity's content hash in its 33-byte wire form
// (algorithm ‖ digest) — the same thing every other signature in this codebase
// binds (core/capability/mint.go, core/protocol/connect.go), so the format byte
// travels with it.
func VerifyCoordinationSignature(e entity.Entity, publicKey []byte, keyType byte, signature []byte) (VerifiedSigner, error) {
	derived, err := crypto.PeerIDFromPublicKey(publicKey, keyType)
	if err != nil {
		return VerifiedSigner{}, err
	}
	if !crypto.Verify(keyType, publicKey, e.ContentHash.Bytes(), signature) {
		return VerifiedSigner{}, ErrBadSignature
	}
	return VerifiedSigner{PeerID: derived.String()}, nil
}

// VerifyClaimedSigner is VerifyCoordinationSignature plus §6.3 check (a) against
// a peer-id the payload itself claims — the §6.1 native path, where
// connect-request carries `initiator` and connect-response carries `responder`.
// The §6.5 payloads have no such field and use VerifyCoordinationSignature
// directly: there is nothing to cross-check against, the signature IS the claim.
func VerifyClaimedSigner(e entity.Entity, publicKey []byte, keyType byte, signature []byte, claimedPeerID string) (VerifiedSigner, error) {
	signer, err := VerifyCoordinationSignature(e, publicKey, keyType, signature)
	if err != nil {
		return VerifiedSigner{}, err
	}
	if signer.PeerID != claimedPeerID {
		return VerifiedSigner{}, ErrSignerMismatch
	}
	return signer, nil
}

// AcceptRemoteDescription returns the SDP of a collected offer or answer, and
// ONLY for a verified signer that is not this peer.
//
// This is where §6.5's channel-identity MUST is discharged: a receiving peer
// MUST verify the entity's signature and MUST NOT call setRemoteDescription on
// SDP from an unverified entity. The browser's own stack then binds the
// negotiated DTLS certificate to the SDP's a=fingerprint (RFC 8827), so no
// separate runtime fingerprint compare is needed — but that automatic binding is
// worth exactly as much as the signature check in front of it. A signaling MITM
// that cannot forge the signature cannot substitute a different SDP, hence not a
// different fingerprint, hence not its own channel.
//
// The payload struct's SDP field remains readable — CollectedMessage is a codec
// result and Go has no way to hide a field from its own package's callers — so
// this function is the guarded path, not a sealed one. Reaching past it is the
// documented way to get this wrong.
func AcceptRemoteDescription(m CollectedMessage, signer VerifiedSigner, myPeerID string) (string, error) {
	if signer.PeerID == "" {
		return "", ErrUnverifiedSDP
	}
	if signer.PeerID == myPeerID {
		return "", ErrSelfNegotiation
	}
	switch m.Kind {
	case KindWebRTCOffer:
		return m.WebRTCOffer.SDP, nil
	case KindWebRTCAnswer:
		return m.WebRTCAnswer.SDP, nil
	default:
		return "", ErrUnverifiedSDP
	}
}

// FindWebRTCOffer finds an offer for a session in a collected bucket. Session
// scoping is the §6.5 analogue of the native nonce echo: a lobby or tag key may
// host several concurrent pairings, so a bucket read that ignored session_id
// would splice them.
//
// It does NOT filter by signer, because signer identity lives in the §6.3
// envelope rather than in the payload; the caller applies §6.4's skip-own after
// verifying. Bucket order is deposit order, oldest first, and the first match
// wins.
func FindWebRTCOffer(messages []CollectedMessage, sessionID []byte) (*types.WebRTCOfferData, bool) {
	for _, m := range messages {
		if m.Kind == KindWebRTCOffer && bytes.Equal(m.WebRTCOffer.SessionID, sessionID) {
			return m.WebRTCOffer, true
		}
	}
	return nil, false
}

// FindWebRTCAnswer finds the answer for a session in a collected bucket.
func FindWebRTCAnswer(messages []CollectedMessage, sessionID []byte) (*types.WebRTCAnswerData, bool) {
	for _, m := range messages {
		if m.Kind == KindWebRTCAnswer && bytes.Equal(m.WebRTCAnswer.SessionID, sessionID) {
			return m.WebRTCAnswer, true
		}
	}
	return nil, false
}

// CollectWebRTCCandidates returns every trickled candidate for a session, in
// bucket order. Unlike offer/answer this is a LIST and stays one: trickle ICE
// (RFC 8838) is the sole candidate path, candidates arrive over time and in
// either direction, and a caller that took only the first would strand the
// gathering the seconds-bounded handshake depends on. Returns an empty slice,
// never nil, so a caller can range without a nil check.
func CollectWebRTCCandidates(messages []CollectedMessage, sessionID []byte) []types.WebRTCCandidateData {
	out := make([]types.WebRTCCandidateData, 0, len(messages))
	for _, m := range messages {
		if m.Kind == KindWebRTCCandidate && bytes.Equal(m.WebRTCCandidate.SessionID, sessionID) {
			out = append(out, *m.WebRTCCandidate)
		}
	}
	return out
}
