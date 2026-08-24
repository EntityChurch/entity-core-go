package signaling

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/mr-tron/base58"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §6.3's self-contained coordination envelope.
//
// The tests that matter here are the ones a loopback cannot fake: that a blob
// valid in one bucket is REFUSED in another, that a forged `signer` cannot buy
// an identity, and that the inner entity survives byte-for-byte. Sealing and
// opening with the same code proves only that this package agrees with itself.

func testOffer(t *testing.T) entity.Entity {
	t.Helper()
	sid, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	e, err := types.WebRTCOfferData{
		SDP:       "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 AB:CD\r\n",
		SessionID: sid,
	}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	return e
}

func testBucket(t *testing.T, a, b string) []byte {
	t.Helper()
	k, err := PairKey(a, b)
	if err != nil {
		t.Fatalf("PairKey: %v", err)
	}
	return k
}

func TestSealedBlobRoundTripsAndVerifies(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)
	e := testOffer(t)

	sealed, err := SealBlob(e, kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	blob, err := SealedToBlob(sealed)
	if err != nil {
		t.Fatalf("SealedToBlob: %v", err)
	}

	signer, inner, err := OpenBlobBytes(blob, bucket)
	if err != nil {
		t.Fatalf("OpenBlobBytes: %v", err)
	}
	if signer.PeerID != peerID {
		t.Errorf("verified signer = %q, want %q", signer.PeerID, peerID)
	}
	if inner.ContentHash != e.ContentHash {
		t.Errorf("inner content hash moved: %s != %s", inner.ContentHash, e.ContentHash)
	}

	// Byte fidelity, not just hash equality: §6.2 embeds the inner entity
	// verbatim because the signature binds its bytes. If the envelope ever
	// re-encoded it, this is what would catch it.
	want, err := ecf.Encode(e)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(sealed.Entity, want) {
		t.Error("inner entity was not embedded verbatim")
	}

	// And the envelope makes §6.4 skip-own executable for §6.5 at last: the
	// three payloads carry no peer-id, so before this a peer could not tell its
	// own offer from a counterpart's.
	msg := Classify(inner)
	if msg.Kind != KindWebRTCOffer {
		t.Fatalf("classified as %v, want KindWebRTCOffer", msg.Kind)
	}
	if signer.PeerID != peerID {
		t.Error("skip-own has no referent without the verified signer")
	}
}

// The bucket binding. A blob is signed FOR a rendezvous, and lifting it into
// another bucket must fail — this is the replay the envelope was extended to
// close, and it is the one property no single-bucket test can observe.
func TestASealedBlobDoesNotVerifyInAnotherBucket(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, partner := testKeypair(t)
	_, stranger := testKeypair(t)

	ours := testBucket(t, peerID, partner)
	elsewhere := testBucket(t, peerID, stranger)
	if bytes.Equal(ours, elsewhere) {
		t.Fatal("the two buckets collided; this test's premise is gone")
	}

	sealed, err := SealBlob(testOffer(t), kp, ours)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	blob, err := SealedToBlob(sealed)
	if err != nil {
		t.Fatalf("SealedToBlob: %v", err)
	}

	// Valid where it was signed.
	if _, _, err := OpenBlobBytes(blob, ours); err != nil {
		t.Fatalf("blob must verify in its own bucket: %v", err)
	}
	// Replayed verbatim into an unrelated bucket — byte-identical, genuinely
	// signed, and refused.
	if _, _, err := OpenBlobBytes(blob, elsewhere); !errors.Is(err, ErrBadSignature) {
		t.Errorf("replay into another bucket = %v, want ErrBadSignature", err)
	}
}

// A forged `signer` must buy nothing. This is blocking-1 at the envelope layer:
// the alternate §1.5 encoding of the SAME key is a well-formed peer-id that a
// verifier dispatching on the wire's hash_type would accept.
func TestAForgedSignerFieldIsRefused(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)

	sealed, err := SealBlob(testOffer(t), kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}

	// (a) The alternate encoding of the signer's own key.
	sum := sha256.Sum256(kp.PublicKeyBytes())
	alt := base58.Encode(append([]byte{crypto.KeyTypeEd25519, crypto.HashTypeSHA256}, sum[:]...))
	forged := sealed
	forged.Signer = alt
	if _, _, err := OpenBlob(forged, bucket); !errors.Is(err, ErrUnusableKey) {
		t.Errorf("alternate-encoding signer = %v, want ErrUnusableKey", err)
	}

	// (b) Somebody else's peer-id entirely, with the real signature attached.
	stolen := sealed
	stolen.Signer = other
	if _, _, err := OpenBlob(stolen, bucket); !errors.Is(err, ErrUnusableKey) {
		t.Errorf("claiming another peer's id = %v, want ErrUnusableKey", err)
	}
}

func TestTamperedEnvelopeContentsAreRefused(t *testing.T) {
	kp, peerID := testKeypair(t)
	impostor, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)

	sealed, err := SealBlob(testOffer(t), kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}

	// A rewritten SDP — a different DTLS fingerprint, hence the attacker's own
	// channel. The inner entity is swapped wholesale, so its content hash moves
	// and the signature no longer covers it.
	evil, err := types.WebRTCOfferData{SDP: "v=0 EVIL", SessionID: make([]byte, 16)}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	evilBytes, err := ecf.Encode(evil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	swapped := sealed
	swapped.Entity = evilBytes
	if _, _, err := OpenBlob(swapped, bucket); !errors.Is(err, ErrBadSignature) {
		t.Errorf("swapped inner entity = %v, want ErrBadSignature", err)
	}

	// The impostor substitutes its own key and re-signs: the envelope is
	// internally consistent, but it now names the impostor. Nothing is
	// "accepted as the original signer" — which is the whole self-contained
	// claim, since a stranger has no key lookup to fall back on.
	reSigned, err := SealBlob(testOffer(t), impostor, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	signer, _, err := OpenBlob(reSigned, bucket)
	if err != nil {
		t.Fatalf("OpenBlob: %v", err)
	}
	if signer.PeerID == peerID {
		t.Error("an impostor's envelope verified as the original signer")
	}

	// A truncated signature is a signature failure, not a panic.
	short := sealed
	short.Signature = sealed.Signature[:len(sealed.Signature)-1]
	if _, _, err := OpenBlob(short, bucket); !errors.Is(err, ErrBadSignature) {
		t.Errorf("truncated signature = %v, want ErrBadSignature", err)
	}
}

// The versioned domain tag separates coordination signatures from every other
// signature in the tree, all of which sign a bare 33-byte content hash. Without
// it a signature harvested from a mint or a hello would be replayable as a
// coordination blob by anyone who saw it — and unlike a length-based argument,
// this holds no matter what lengths other signatures grow to.
func TestACoordinationSignatureIsNotABareContentHashSignature(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)
	e := testOffer(t)

	// What mint/connect sign: the bare 33-byte content hash.
	bare := kp.Sign(e.ContentHash.Bytes())

	inner, err := ecf.Encode(e)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	signerID, err := crypto.PeerIDFromPublicKey(kp.PublicKeyBytes(), kp.KeyType)
	if err != nil {
		t.Fatalf("PeerIDFromPublicKey: %v", err)
	}
	lifted := types.SignedBlobData{
		Entity:    inner,
		Signer:    signerID.String(),
		PublicKey: kp.PublicKeyBytes(),
		Signature: bare,
	}
	if _, _, err := OpenBlob(lifted, bucket); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a bare content-hash signature was accepted as a coordination signature: %v", err)
	}
}

// §6.4: a failed check SKIPS. Silent on the wire, observable locally — the
// error comes back beside the KindUnknown so a caller can count it. The Ed448
// hardcode survived because a failed check was skipped and never raised.
func TestClassifySealedSkipsSilentlyButReportsLocally(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)
	elsewhere := testBucket(t, peerID, "peer-stranger")

	sealed, err := SealBlob(testOffer(t), kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	blob, err := SealedToBlob(sealed)
	if err != nil {
		t.Fatalf("SealedToBlob: %v", err)
	}

	msg, signer, err := ClassifySealed(blob, elsewhere)
	if err == nil {
		t.Fatal("a replayed blob must report an error locally, not verify")
	}
	if msg.Kind != KindUnknown {
		t.Errorf("kind = %v, want KindUnknown — a failed check is skipped, not surfaced", msg.Kind)
	}
	if signer.PeerID != "" {
		t.Error("a skipped blob must not yield a signer")
	}

	// A bucket holds anything, including message types this build has never
	// heard of. That is a normal condition, not a fault of the reader.
	if m, _, err := ClassifySealed([]byte{0xff, 0xff, 0xff}, bucket); m.Kind != KindUnknown || err == nil {
		t.Errorf("garbage blob = (%v, %v), want KindUnknown with a local error", m.Kind, err)
	}

	// The happy path still classifies.
	if m, s, err := ClassifySealed(blob, bucket); err != nil || m.Kind != KindWebRTCOffer || s.PeerID != peerID {
		t.Errorf("valid blob = (%v, %v, %v), want a classified offer from %q", m.Kind, s.PeerID, err, peerID)
	}
}

// A key type that cannot sign must be reported as UNUSABLE, not as a bad
// signature. Go derives a peer-id for 0xFE — it has a canonical hash type and a
// defined key length — so it reaches the signature check and fails there, which
// is the misdiagnosis the taxonomy exists to prevent: it points at the key
// material when the fault is the key TYPE, one inference from the hardcoded
// reject that locked Ed448 out of rust. Found by their vector row.
func TestASignIncapableKeyTypeIsUnusableNotABadSignature(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)
	e := testOffer(t)
	inner, err := ecf.Encode(e)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	pub := bytes.Repeat([]byte{0x7E}, 64)
	id, err := crypto.PeerIDFromExperimentalTestPublicKey(pub)
	if err != nil {
		t.Fatalf("PeerIDFromExperimentalTestPublicKey: %v", err)
	}
	exotic := types.SignedBlobData{
		Entity:    inner,
		Signer:    id.String(),
		PublicKey: pub,
		Signature: bytes.Repeat([]byte{0x00}, 64),
	}
	if _, _, err := OpenBlob(exotic, bucket); !errors.Is(err, ErrUnusableKey) {
		t.Errorf("sign-incapable key_type = %v, want ErrUnusableKey", err)
	}

	// The gate must not have made real key types unusable.
	sealed, err := SealBlob(e, kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	if _, _, err := OpenBlob(sealed, bucket); err != nil {
		t.Fatalf("Ed25519 must still verify: %v", err)
	}
}

// A blob that is not a container at all is a §6.4 SKIP, not a verification
// verdict. During the migration window this is the common case — both impls
// still deposit bare unsigned entities — so filing it under ErrUnusableKey
// would bury real key faults in noise from perfectly normal traffic.
func TestABareEntityIsNotAContainerRatherThanAKeyFault(t *testing.T) {
	_, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)

	bare, err := ecf.Encode(testOffer(t))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	_, _, err = OpenBlobBytes(bare, bucket)
	if !errors.Is(err, ErrNotAContainer) {
		t.Errorf("a bare coordination entity = %v, want ErrNotAContainer", err)
	}
	if errors.Is(err, ErrUnusableKey) {
		t.Error("a blob carrying no key at all must not be reported as a key fault")
	}

	// Undecodable bytes are the same disposition.
	if _, _, err := OpenBlobBytes([]byte{0xff, 0xff, 0xff}, bucket); !errors.Is(err, ErrNotAContainer) {
		t.Errorf("garbage = %v, want ErrNotAContainer", err)
	}
}

// §6.3 step 3. A genuinely valid signature under a false claim passes every
// other check — nothing about it is forged — so only the claim comparison
// catches it. The truthful case is asserted alongside so the check cannot be
// satisfied by rejecting every claim.
func TestAFalseClaimIsCaughtAndATrueOneIsNot(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)

	sealed, err := SealBlob(testOffer(t), kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}

	// Unclaimed: valid, because for §6.5 the signature IS the claim.
	if _, _, err := OpenBlob(sealed, bucket); err != nil {
		t.Fatalf("the blob itself must be valid: %v", err)
	}
	if _, _, err := OpenBlobClaimed(sealed, bucket, other); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("false claim = %v, want ErrSignerMismatch", err)
	}
	if _, _, err := OpenBlobClaimed(sealed, bucket, peerID); err != nil {
		t.Errorf("true claim = %v, want it to verify", err)
	}
}

// THE DOWNGRADE FENCE. A container that fails to verify must be SKIPPED, never
// re-read as a bare entity. If it fell back, anyone could corrupt one signature
// byte and have a signed offer accepted as an unsigned one — the peer would act
// on unauthenticated SDP, defeating the exact thing the container provides.
// Mirrors entity-core-rust's fence (6077229) deliberately: this is local code
// with cross-impl-visible behavior.
func TestAFailedContainerIsSkippedNotReadAsBare(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)

	sealed, err := SealBlob(testOffer(t), kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	// Corrupt exactly one signature byte — the blob is still a well-formed
	// container carrying a perfectly decodable inner offer.
	sealed.Signature[0] ^= 0xff
	blob, err := SealedToBlob(sealed)
	if err != nil {
		t.Fatalf("SealedToBlob: %v", err)
	}

	// The anti-downgrade rule is unconditional — it is not a posture a consumer
	// can relax, which is why it lives in the classifier and VerificationPolicy
	// does not.
	m, err := ClassifyCollected(blob, bucket)
	if err == nil {
		t.Fatal("a corrupted container must not be accepted")
	}
	if m.Kind != KindUnknown {
		t.Errorf("kind = %v, want KindUnknown — the inner entity must NOT be recovered", m.Kind)
	}
	if m.WebRTCOffer != nil {
		t.Error("the offer was re-read from a failed container — this is the downgrade attack")
	}
}

// Both framings are classified, and a signer is USED when present rather than
// ignored — so a flipped peer gets §6.4 skip-own against a real identity while
// its counterpart has not flipped yet.
//
// The PRESENCE of the signer is the whole interface between this layer and the
// posture: VerifyRequire is a consumer's refusal of the no-signer case, not a
// second filter here. See VerificationPolicy.
func TestBothFramingsClassifyAndOnlyOneCarriesAnIdentity(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)
	e := testOffer(t)

	bare, err := ecf.Encode(e)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	sealed, err := SealBlob(e, kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	container, err := SealedToBlob(sealed)
	if err != nil {
		t.Fatalf("SealedToBlob: %v", err)
	}

	// Both arrive, and only the container carries an identity.
	m, err := ClassifyCollected(bare, bucket)
	if err != nil || m.Kind != KindWebRTCOffer {
		t.Fatalf("bare = (%v, %v), want an offer", m.Kind, err)
	}
	if m.Signer.PeerID != "" {
		t.Error("an unsigned entity must not carry a signer — that would be an unauthenticated identity")
	}
	m, err = ClassifyCollected(container, bucket)
	if err != nil || m.Kind != KindWebRTCOffer {
		t.Fatalf("container = (%v, %v), want an offer", m.Kind, err)
	}
	if m.Signer.PeerID != peerID {
		t.Errorf("signer = %q, want %q — a present signer must be used, not ignored", m.Signer.PeerID, peerID)
	}
}
