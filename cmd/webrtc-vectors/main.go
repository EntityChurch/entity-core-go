// Command webrtc-vectors emits and verifies the §6.5 WebRTC-coordination
// differential vector file — the cross-impl contract routed by entity-core-rust
// (their ROUTING-2026-08-03-webrtc-coordination-crossimpl-contract-to-go.md).
//
// WHY A VECTOR FILE AND NOT A LIVE CROSSING. Everything §6.5's coordination
// layer does is a pure function over bytes: build an entity, classify a blob,
// decide a role, check a length, verify a signature. None of it needs a browser,
// an ICE stack, a socket, or a NAT. That makes it the cheapest cross-impl
// surface this leg will ever offer — and the window is now, because once a
// transport is wired on top, a divergence here stops being a vector diff and
// becomes an S5 symptom.
//
// WHAT A GREEN RUN IS NOT. It is not evidence that WebRTC transport works. This
// crosses the coordination half only. Per §11.5.1 the S5 gate — two real browser
// peers over a real signaling node — remains the only real evidence, and nothing
// here should be reported as more.
//
// The file is CBOR (this ecosystem is CBOR-only on the wire and both impls
// already have the codec) and is emitted through ECF, so it is deterministic:
// emitting twice produces identical bytes, and every keypair comes from a fixed
// seed. A vector file you cannot re-derive is not a conformance artifact.
//
//	go run ./cmd/webrtc-vectors -emit   docs/validation/vectors/webrtc-coordination-go.cbor
//	go run ./cmd/webrtc-vectors -verify docs/validation/vectors/webrtc-coordination-rust.cbor
package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mr-tron/base58"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// VectorFile is the contract shape. Field names are the routed ones; the
// amendments are marked at each field.
type VectorFile struct {
	// Schema is EXTENSION-NETWORK §6.5.2d's pinned identifier. A file whose
	// schema this build does not speak is refused rather than partially checked.
	Schema  string `cbor:"schema"`
	Emitter string `cbor:"emitter"`
	// EmitterCommit pins the tree that produced these bytes (ADR-0012). AMENDED
	// IN: the routed sketch had no provenance field, and a vector file nobody can
	// re-derive is an assertion, not evidence.
	EmitterCommit string `cbor:"emitter_commit"`

	Entities   []EntityVector    `cbor:"entities"`
	Roles      []RoleVector      `cbor:"roles"`
	SessionIDs []SessionIDVector `cbor:"session_ids"`
	// Signatures is a LIST with expected outcomes. AMENDED IN: the routed sketch
	// had one positive object, and a verifier that always returns "ok" passes a
	// suite of positives. The negatives are what distinguish a verifier from a
	// stub.
	Signatures []SignatureVector `cbor:"signatures"`

	// SignedBlobs is surface 5 — the §6.3 container crossing, the fold trigger.
	//
	// OPTIONAL ON READ, ALWAYS EMITTED, and the schema string is deliberately
	// NOT bumped. `webrtc-sdp-ice/1` is pinned into every
	// system/peer/transport/webrtc profile's negotiation.signaling_schema
	// (EXTENSION-NETWORK §6.5.2d), so bumping it would be a wire-visible change
	// announcing a test-harness addition — and both verifiers hard-refuse an
	// unrecognized schema, so neither impl could land it without a flag day.
	// An additive optional array is MUST-ignore (ADR-0002) instead.
	//
	// Go initially emitted this as a SEPARATE file under its own schema, which
	// also left the pinned string alone. Converged on rust's placement (0dd1ba3)
	// because they had already emitted it and a packaging disagreement is not
	// worth a round trip on the fold trigger — the bytes are what cross, not the
	// container they ship in.
	SignedBlobs []SignedBlobVector `cbor:"signed_blobs,omitempty"`

	// SigningInput states, as DATA, exactly what a coordination signature
	// covers. Go proposed the idea; entity-core-rust adopted it and added the
	// `sample` block, which is the part that actually pins ORDER — a declarative
	// component list lets two impls agree on names and lengths and still
	// concatenate them differently. Optional on read for the same MUST-ignore
	// reason as signed_blobs.
	//
	// It is checked FIRST and separately because a signing-input disagreement
	// otherwise surfaces as every signature row failing identically, which reads
	// as "everything is broken" rather than "we disagree about one field."
	SigningInput *SigningInputSpec `cbor:"signing_input,omitempty"`
}

// SigningInputSpec is the self-describing statement of the signed message.
type SigningInputSpec struct {
	Components []SigningComponent `cbor:"components"`
	Sample     SigningSample      `cbor:"sample"`
	TotalLen   uint64             `cbor:"total_len"`
}

// SigningComponent names one fixed-length part, in concatenation order.
type SigningComponent struct {
	Name string `cbor:"name"`
	Len  uint64 `cbor:"len"`
}

// SigningSample is a worked example: the emitter's own signing_input over two
// recognizable, deliberately unreal inputs. A verifier recomputes Bytes from
// ContentHash and RendezvousKey — which pins the concatenation order
// operationally rather than by agreeing on a word list.
type SigningSample struct {
	Bytes         []byte `cbor:"bytes"`
	ContentHash   []byte `cbor:"content_hash"`
	RendezvousKey []byte `cbor:"rendezvous_key"`
}

// SignedBlobVector is one §6.3 envelope, positive or negative. Field names match
// entity-core-rust's surface 5 exactly so the two files are mutually readable.
type SignedBlobVector struct {
	Name string `cbor:"name"`
	// Blob is the whole system/signaling/signed-blob container as a bucket
	// stores it — an entity encoding, not a bare CBOR map, so the type string
	// stays dispatchable and a signed blob is distinguishable from a legacy
	// unsigned one during the migration window.
	Blob []byte `cbor:"blob"`
	// RendezvousKey is the 33-byte bucket key the signature is bound to. It is
	// NOT a field of the envelope — it is carried HERE, in the vector row, so
	// the crossing is decidable regardless of the binding mechanism: a verifier
	// reproduces these exact bytes or it does not.
	RendezvousKey []byte `cbor:"rendezvous_key"`

	ClaimedPeerID string `cbor:"claimed_peer_id,omitempty"`
	ExpectSigner  string `cbor:"expect_signer,omitempty"`
	// ExpectInnerBlob is the inner entity verbatim — it pins the byte-preservation
	// MUST *through* the container, which is exactly where a decode+re-encode
	// would silently invalidate the signature the container carries.
	ExpectInnerBlob []byte `cbor:"expect_inner_blob,omitempty"`
	// Expect is ok | unusable_key | bad_signature | signer_mismatch.
	Expect string `cbor:"expect"`
}

// EntityVector is one §6.5 entity: the §6.2 blob a bucket would actually hold,
// plus the fields a correct decoder must recover from it.
type EntityVector struct {
	Name string `cbor:"name"`
	Kind string `cbor:"kind"` // offer | answer | candidate
	Blob []byte `cbor:"blob"`

	SessionID        []byte  `cbor:"session_id"`
	SDP              string  `cbor:"sdp,omitempty"`
	Candidate        string  `cbor:"candidate,omitempty"`
	SDPMid           string  `cbor:"sdp_mid,omitempty"`
	SDPMLineIndex    uint64  `cbor:"sdp_mline_index,omitempty"`
	UsernameFragment *string `cbor:"username_fragment,omitempty"`

	// ExpectAbsent names fields that MUST decode as absent — required, possibly
	// empty. AMENDED IN, and it is the amendment that matters most: the routed
	// sketch expressed "expected absent" by omitting the field from the vector
	// row, which re-creates one level up the exact absent-vs-null ambiguity the
	// row exists to test. Absence has to be asserted, not inferred.
	ExpectAbsent []string `cbor:"expect_absent"`
}

// RoleVector is one offerer/glare decision. Both directions of a pair appear as
// separate rows, so a verifier checks convergence rather than one side's answer.
type RoleVector struct {
	Name  string `cbor:"name"`
	Self  string `cbor:"self"`
	Other string `cbor:"other"`

	Impolite *bool `cbor:"impolite,omitempty"`
	// PairSuppress is `pair`-mode pre-assignment: true means this peer SHOULD
	// suppress its own offer and wait. Go's spelling is
	// PairShouldWaitForOffer — same predicate, wait-side naming.
	PairSuppress *bool `cbor:"pair_suppress,omitempty"`

	// Error is "self_negotiation" for the equal-ids row. Present instead of the
	// two booleans.
	Error string `cbor:"error,omitempty"`
}

// SessionIDVector is one §6.5 length-floor decision.
type SessionIDVector struct {
	Name   string `cbor:"name"`
	Bytes  []byte `cbor:"bytes"`
	Accept bool   `cbor:"accept"`
}

// SignatureVector is one §6.3 verification, positive or negative.
type SignatureVector struct {
	Name       string `cbor:"name"`
	EntityBlob []byte `cbor:"entity_blob"`
	PublicKey  []byte `cbor:"public_key"`
	// KeyType is the BINARY peer-id wire-format prefix (0x01 Ed25519, 0x02
	// Ed448), NOT the system/peer.data.key_type entity-data string ("ed25519").
	// AMENDED IN: the routed sketch said `key_type` without saying which surface,
	// and this ecosystem has both — a vector file that leaves it open is how the
	// diff shows up as a mystery rather than a mismatch.
	KeyType   uint64 `cbor:"key_type"`
	Signature []byte `cbor:"signature"`

	// ClaimedPeerID exercises the native §6.1 path, where the payload names its
	// own initiator/responder and §6.3 check (a) cross-checks it. Absent for the
	// §6.5 rows: those payloads carry no peer-id, so the derived id IS the claim.
	ClaimedPeerID string `cbor:"claimed_peer_id,omitempty"`

	ExpectSigner string `cbor:"expect_signer,omitempty"`
	// Expect is ok | bad_signature | signer_mismatch.
	Expect string `cbor:"expect"`
}

const (
	expectOK             = "ok"
	expectBadSignature   = "bad_signature"
	expectSignerMismatch = "signer_mismatch"
	// expectUnusableKey is the cohort's third taxonomy name: key material that
	// never reached the signature check. Distinct from signer_mismatch, which is
	// reserved for the §6.1 claim comparison — filing an unsupported key_type
	// under "this peer is lying" is the reading that justifies a hardcoded
	// reject, and a hardcoded reject is what locked out Ed448.
	expectUnusableKey = "unusable_key"
	// expectDecodeSkip is a FOURTH outcome, not one of the three names. A blob
	// that never parsed as a container is normal bucket contents under §6.4 —
	// legacy unsigned traffic, another impl's message — not a verification
	// verdict. Filing it under unusable_key would flood the diagnostic channel
	// with key alarms for blobs that carry no key at all. (rust's, 92897a9.)
	expectDecodeSkip   = "decode_skip"
	errSelfNegotiation = "self_negotiation"
)

func main() {
	emit := flag.String("emit", "", "write this implementation's vector file to PATH")
	verify := flag.String("verify", "", "verify a sibling's vector file at PATH")
	flag.Parse()

	switch {
	case *emit != "" && *verify != "":
		fail("pick one of -emit / -verify")
	case *emit != "":
		if err := emitFile(*emit); err != nil {
			fail("emit: %v", err)
		}
	case *verify != "":
		ok, err := verifyFile(*verify)
		if err != nil {
			fail("verify: %v", err)
		}
		if !ok {
			os.Exit(1)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "webrtc-vectors: "+format+"\n", args...)
	os.Exit(1)
}

// --- emit -------------------------------------------------------------------

// Fixed seeds: the file must be byte-identical across runs, so nothing here may
// call a random source. Values are arbitrary and have no meaning beyond being
// stable.
var (
	seedA = [32]byte{0x01, 0x02, 0x03, 0x04}
	seedB = [32]byte{0x05, 0x06, 0x07, 0x08}
)

func ed448Seed(b byte) [crypto.Ed448SeedLen]byte {
	var s [crypto.Ed448SeedLen]byte
	s[0] = b
	return s
}

// sid builds a deterministic session_id of the given length.
func sid(fill byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill + byte(i)
	}
	return b
}

func emitFile(path string) error {
	entities, err := emitEntities()
	if err != nil {
		return err
	}
	roles, err := emitRoles()
	if err != nil {
		return err
	}
	sigs, err := emitSignatures()
	if err != nil {
		return err
	}

	blobs, err := emitSignedBlobs()
	if err != nil {
		return err
	}

	f := VectorFile{
		Schema:        types.WebRTCSignalingSchema,
		Emitter:       "core-go",
		EmitterCommit: headCommit(),
		Entities:      entities,
		Roles:         roles,
		SessionIDs:    emitSessionIDs(),
		Signatures:    sigs,
		SignedBlobs:   blobs,
		SigningInput:  emitSigningInput(),
	}
	raw, err := ecf.Encode(f)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(raw))
	fmt.Printf("  schema=%s emitter=%s commit=%s\n", f.Schema, f.Emitter, f.EmitterCommit)
	fmt.Printf("  entities=%d roles=%d session_ids=%d signatures=%d signed_blobs=%d\n",
		len(f.Entities), len(f.Roles), len(f.SessionIDs), len(f.Signatures), len(f.SignedBlobs))
	return nil
}

// headCommit records provenance. "unknown" rather than a failure: a vector file
// emitted from a tarball is still verifiable, it just cannot be re-derived, and
// saying so is better than refusing to emit.
//
// A "-dirty" suffix marks an emission whose tree had modified TRACKED files, so
// the pin cannot silently overclaim: a file naming a commit whose code is not
// what produced it is unreproducible while looking reproducible. Adopted from
// entity-core-rust (68e3b0b), including their correction — untracked files are
// NOT counted. Counting them makes every first emission of a new vector file
// dirty forever (the file is untracked until it is added), and a marker that
// fires unconditionally is one nobody reads. Tracked-only is also the honest
// line: an untracked source file cannot change the emitter without being
// referenced from a tracked one, which would fail to build at the pinned commit
// rather than produce a wrong pin.
func headCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	commit := strings.TrimSpace(string(out))
	if treeIsDirty() {
		commit += "-dirty"
	}
	return commit
}

// treeIsDirty reports modified tracked files. On error it reports false: the
// "unknown" commit case above already covers a non-git tree, and a spurious
// "-dirty" on every emission would train readers to ignore the marker.
func treeIsDirty() bool {
	out, err := exec.Command("git", "status", "--porcelain", "--untracked-files=no").Output()
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

func emitEntities() ([]EntityVector, error) {
	ufrag := "ufrag-abc123"
	sessA := sid(0x10, 16)
	sessB := sid(0x20, 24) // longer than the floor: the floor is a minimum, not a size

	offer, err := types.WebRTCOfferData{
		SDP:       "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 AB:CD\r\n",
		SessionID: sessA,
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	answer, err := types.WebRTCAnswerData{
		SDP:       "v=0\r\no=- 2 2 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 EF:01\r\n",
		SessionID: sessA,
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	// The absent-ufrag candidate: the row the whole exercise turns on. An unset
	// OPTIONAL that encodes as null or "" round-trips perfectly same-side and is
	// wrong on the wire — addIceCandidate reads "" as a real ufrag.
	candBare, err := types.WebRTCCandidateData{
		Candidate:     "candidate:1 1 udp 2130706431 192.0.2.1 41000 typ host",
		SDPMid:        "0",
		SDPMLineIndex: 0,
		SessionID:     sessA,
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	candUfrag, err := types.WebRTCCandidateData{
		Candidate:        "candidate:2 1 udp 1694498815 198.51.100.7 52000 typ srflx raddr 192.0.2.1 rport 41000",
		SDPMid:           "1",
		SDPMLineIndex:    3,
		SessionID:        sessB,
		UsernameFragment: &ufrag,
	}.ToEntity()
	if err != nil {
		return nil, err
	}

	blobs := make([][]byte, 0, 4)
	for _, e := range []entity.Entity{offer, answer, candBare, candUfrag} {
		b, err := signaling.ToBlob(e)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, b)
	}

	return []EntityVector{
		{
			Name: "offer/basic", Kind: "offer", Blob: blobs[0],
			SessionID: sessA, SDP: "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 AB:CD\r\n",
			ExpectAbsent: []string{},
		},
		{
			Name: "answer/basic", Kind: "answer", Blob: blobs[1],
			SessionID: sessA, SDP: "v=0\r\no=- 2 2 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 EF:01\r\n",
			ExpectAbsent: []string{},
		},
		{
			Name: "candidate/ufrag-absent", Kind: "candidate", Blob: blobs[2],
			SessionID:     sessA,
			Candidate:     "candidate:1 1 udp 2130706431 192.0.2.1 41000 typ host",
			SDPMid:        "0",
			SDPMLineIndex: 0,
			ExpectAbsent:  []string{"username_fragment"},
		},
		{
			Name: "candidate/ufrag-present", Kind: "candidate", Blob: blobs[3],
			SessionID:        sessB,
			Candidate:        "candidate:2 1 udp 1694498815 198.51.100.7 52000 typ srflx raddr 192.0.2.1 rport 41000",
			SDPMid:           "1",
			SDPMLineIndex:    3,
			UsernameFragment: &ufrag,
			ExpectAbsent:     []string{},
		},
	}, nil
}

func emitRoles() ([]RoleVector, error) {
	// Real Base58 peer-ids from the cross-impl punch runs, plus pairs chosen to
	// break an ordering that is nearly-but-not byte-wise. AMENDED IN: the sketch
	// did not pin the ids, and "aaa" vs "bbb" agrees under every plausible
	// ordering, so it proves nothing.
	pairs := [][2]string{
		{"2K4c23upg34cKuk2sjoiHkPdn6LmeARntwruwWJLb6tqdG", "2KHGQS5Ur314WoEaVdKH2G4baXcgJDqLLiXGoBN5FsxgcD"},
		// Prefix pair: shorter sorts FIRST byte-wise. A length-first ordering
		// (sort by length, then content) reverses this row and nothing else.
		{"2K4c23", "2K4c23upg34cKuk2sjoiHkPdn6LmeARntwruwWJLb6tqdG"},
		// Case: 'Z' (0x5A) < 'a' (0x61) byte-wise, the reverse of a
		// case-insensitive ordering. Base58 contains both cases, so this is
		// reachable with real ids.
		{"2KZ", "2Ka"},
	}

	out := make([]RoleVector, 0, len(pairs)*2+1)
	for i, p := range pairs {
		for _, d := range [][2]string{{p[0], p[1]}, {p[1], p[0]}} {
			imp, err := signaling.Impolite(d[0], d[1])
			if err != nil {
				return nil, err
			}
			sup, err := signaling.PairShouldWaitForOffer(d[0], d[1])
			if err != nil {
				return nil, err
			}
			impCopy, supCopy := imp, sup
			out = append(out, RoleVector{
				Name: fmt.Sprintf("pair%d/%s", i, map[bool]string{true: "forward", false: "reverse"}[d[0] == p[0]]),
				Self: d[0], Other: d[1],
				Impolite: &impCopy, PairSuppress: &supCopy,
			})
		}
	}
	// The equal-ids row. §6.4's skip-own means neither impl should ever reach
	// it, which is exactly why it belongs in the vectors: it is the row where
	// "fails open to a plausible role" and "refuses" look identical from inside
	// one implementation.
	out = append(out, RoleVector{
		Name: "equal-ids/refused", Self: "2KZ", Other: "2KZ", Error: errSelfNegotiation,
	})
	return out, nil
}

func emitSessionIDs() []SessionIDVector {
	return []SessionIDVector{
		{Name: "empty", Bytes: []byte{}, Accept: false},
		{Name: "15-below-floor", Bytes: sid(0x30, 15), Accept: false},
		{Name: "16-at-floor", Bytes: sid(0x40, 16), Accept: true},
		{Name: "17-above-floor", Bytes: sid(0x50, 17), Accept: true},
		// All-zero at the floor is ACCEPTED. The MUST is "freshly random and
		// ≥16 bytes"; length is the only half a receiver can check, and an impl
		// that added an entropy heuristic would reject this row and diverge on
		// traffic the spec says to accept.
		{Name: "16-all-zero-accepted", Bytes: make([]byte, 16), Accept: true},
	}
}

func emitSignatures() ([]SignatureVector, error) {
	kpA := crypto.FromSeed(seedA)
	kpB := crypto.FromSeed(seedB)
	kp448 := crypto.Ed448FromSeed(ed448Seed(0x11))

	peerA := crypto.PeerIDFromKeypair(kpA).String()
	peerB := crypto.PeerIDFromKeypair(kpB).String()
	peer448 := crypto.PeerIDFromKeypair(kp448).String()

	offer, err := types.WebRTCOfferData{SDP: "v=0\r\na=fingerprint:sha-256 AB:CD\r\n", SessionID: sid(0x60, 16)}.ToEntity()
	if err != nil {
		return nil, err
	}
	tampered, err := types.WebRTCOfferData{SDP: "v=0\r\na=fingerprint:sha-256 99:99\r\n", SessionID: sid(0x60, 16)}.ToEntity()
	if err != nil {
		return nil, err
	}
	// The native §6.1 shape, which DOES name its signer — the only rows where
	// §6.3 check (a) has something to cross-check against.
	native, err := types.ConnectRequestData{Initiator: peerA, Nonce: []byte("nonce-fixed-0001")}.ToEntity()
	if err != nil {
		return nil, err
	}

	offerBlob, err := signaling.ToBlob(offer)
	if err != nil {
		return nil, err
	}
	tamperedBlob, err := signaling.ToBlob(tampered)
	if err != nil {
		return nil, err
	}
	nativeBlob, err := signaling.ToBlob(native)
	if err != nil {
		return nil, err
	}

	sigA := kpA.Sign(offer.ContentHash.Bytes())
	sig448 := kp448.Sign(offer.ContentHash.Bytes())
	sigNative := kpA.Sign(native.ContentHash.Bytes())

	return []SignatureVector{
		{
			Name: "ed25519/valid", EntityBlob: offerBlob,
			PublicKey: kpA.PublicKeyBytes(), KeyType: uint64(kpA.KeyType), Signature: sigA,
			ExpectSigner: peerA, Expect: expectOK,
		},
		{
			// Ed448 is here to settle a live spec question at zero cost: §6.3
			// spells the derivation with the key type hardcoded to 0x01. If a
			// sibling took that literally, this row fails while the Ed25519 one
			// passes — which localizes the bug instead of just reporting a diff.
			Name: "ed448/valid", EntityBlob: offerBlob,
			PublicKey: kp448.PublicKeyBytes(), KeyType: uint64(kp448.KeyType), Signature: sig448,
			ExpectSigner: peer448, Expect: expectOK,
		},
		{
			// Verified against a DIFFERENT peer's key. The self-contained claim
			// is exactly this: a stranger with no key lookup separates the real
			// signer from an impostor.
			Name: "ed25519/wrong-key", EntityBlob: offerBlob,
			PublicKey: kpB.PublicKeyBytes(), KeyType: uint64(kpB.KeyType), Signature: sigA,
			Expect: expectBadSignature,
		},
		{
			// A rewritten SDP carries a different DTLS fingerprint, hence the
			// attacker's own channel. The content hash moves and the signature
			// no longer verifies — which is the entire §6.5 channel-identity
			// argument, reduced to one row.
			Name: "ed25519/tampered-sdp", EntityBlob: tamperedBlob,
			PublicKey: kpA.PublicKeyBytes(), KeyType: uint64(kpA.KeyType), Signature: sigA,
			Expect: expectBadSignature,
		},
		{
			Name: "native/claim-matches", EntityBlob: nativeBlob,
			PublicKey: kpA.PublicKeyBytes(), KeyType: uint64(kpA.KeyType), Signature: sigNative,
			ClaimedPeerID: peerA, ExpectSigner: peerA, Expect: expectOK,
		},
		{
			// Signature valid, claim false: signed by A, claiming to be B. Only
			// check (a) catches it, so a verifier that runs only check (b)
			// passes every other row and fails this one.
			Name: "native/claim-is-another-peer", EntityBlob: nativeBlob,
			PublicKey: kpA.PublicKeyBytes(), KeyType: uint64(kpA.KeyType), Signature: sigNative,
			ClaimedPeerID: peerB, Expect: expectSignerMismatch,
		},
	}, nil
}

// --- verify -----------------------------------------------------------------

type report struct {
	surface string
	pass    int
	warn    int
	fail    int
	lines   []string
}

func (r *report) ok(name string) { r.pass++; r.lines = append(r.lines, "    ok   "+name) }
func (r *report) bad(name, why string) {
	r.fail++
	r.lines = append(r.lines, "    FAIL "+name+" — "+why)
}

// soft records a row that VERIFIED but whose construction means it does not
// test what its name says — a coverage gap in the row, not a fault in the
// implementation that emitted it.
//
// It exists because the alternative is worse in both directions. Counting such
// a row as a FAIL reads as "the sibling's implementation is broken" and gates a
// cycle on a disagreement about what a vector field MEANS; counting it as a
// pass hides the fact that a named negative is not actually negative. A W is
// the honest third answer, and it is loud: it prints the row, says what is not
// being exercised, and is summarized separately so a bare "N·0F" can never
// absorb it.
//
// A W is NOT a skip and does not license one. The row still had to verify.
func (r *report) soft(name, why string) {
	r.warn++
	r.lines = append(r.lines, "    WARN "+name+" — "+why)
}

func verifyFile(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var f VectorFile
	if err := ecf.Decode(raw, &f); err != nil {
		return false, fmt.Errorf("decode vector file: %w", err)
	}
	if f.Schema != types.WebRTCSignalingSchema {
		return false, fmt.Errorf("schema %q is not %q — refusing to partially check a file this build does not speak",
			f.Schema, types.WebRTCSignalingSchema)
	}

	fmt.Printf("verifying %s\n", path)
	fmt.Printf("  emitter=%s commit=%s schema=%s\n", f.Emitter, f.EmitterCommit, f.Schema)
	fmt.Println()

	reports := []*report{
		verifySigningInput(f.SigningInput),
		verifyEntities(f.Entities),
		verifyRoles(f.Roles),
		verifySessionIDs(f.SessionIDs),
		verifySignatures(f.Signatures),
		verifySignedBlobs(f.SignedBlobs),
	}

	total, failed, warned := 0, 0, 0
	for _, r := range reports {
		if r.warn > 0 {
			fmt.Printf("  %-24s %d pass / %d warn / %d fail\n", r.surface, r.pass, r.warn, r.fail)
		} else {
			fmt.Printf("  %-24s %d pass / %d fail\n", r.surface, r.pass, r.fail)
		}
		for _, l := range r.lines {
			fmt.Println(l)
		}
		total += r.pass + r.warn + r.fail
		failed += r.fail
		warned += r.warn
	}
	fmt.Println()
	if failed == 0 {
		// The W is carried INTO the headline, never averaged away. ADR-0012 says
		// a published number is P/W/F-broken-out and never a bare percentage;
		// "42·0F" beside a warned row would be a true number telling a false
		// story, since the reader's whole question is what was actually tested.
		if warned > 0 {
			fmt.Printf("WEBRTC COORDINATION VECTORS: PASS WITH WARNINGS — %d·%dW·0F @ %s (%s)\n",
				total, warned, f.EmitterCommit, f.Emitter)
			fmt.Println("  A warned row verified but does not exercise what its name claims — see above.")
			fmt.Println("  Coordination layer only. NOT evidence that WebRTC transport works (§11.5.1: S5 is).")
			return true, nil
		}
		fmt.Printf("WEBRTC COORDINATION VECTORS: PASS — %d·0F @ %s (%s)\n", total, f.EmitterCommit, f.Emitter)
		fmt.Println("  Coordination layer only. NOT evidence that WebRTC transport works (§11.5.1: S5 is).")
		// The silent-zero guard (rust's, adopted): a missing surface must never
		// read as a crossed one. An all-green summary over four surfaces looks
		// exactly like an all-green summary over five, and the §6.3 container is
		// the whole fold trigger — so say it out loud rather than let the number
		// imply it.
		if len(f.SignedBlobs) == 0 {
			fmt.Printf("  §6.3 container NOT crossed: %s emitted no signed_blobs. The fold trigger is unmet.\n", f.Emitter)
		}
		return true, nil
	}
	fmt.Printf("WEBRTC COORDINATION VECTORS: FAIL — %d checks, %d failed (emitter %s @ %s)\n",
		total, failed, f.Emitter, f.EmitterCommit)
	return false, nil
}

func verifyEntities(rows []EntityVector) *report {
	r := &report{surface: "1. wire shape"}
	for _, v := range rows {
		m := signaling.ClassifyBlob(v.Blob)
		switch v.Kind {
		case "offer":
			if m.Kind != signaling.KindWebRTCOffer {
				r.bad(v.Name, fmt.Sprintf("classified as %v, want offer", m.Kind))
				continue
			}
			if m.WebRTCOffer.SDP != v.SDP {
				r.bad(v.Name, "sdp mismatch")
				continue
			}
			if !bytes.Equal(m.WebRTCOffer.SessionID, v.SessionID) {
				r.bad(v.Name, "session_id mismatch")
				continue
			}
		case "answer":
			if m.Kind != signaling.KindWebRTCAnswer {
				r.bad(v.Name, fmt.Sprintf("classified as %v, want answer", m.Kind))
				continue
			}
			if m.WebRTCAnswer.SDP != v.SDP {
				r.bad(v.Name, "sdp mismatch")
				continue
			}
			if !bytes.Equal(m.WebRTCAnswer.SessionID, v.SessionID) {
				r.bad(v.Name, "session_id mismatch")
				continue
			}
		case "candidate":
			if m.Kind != signaling.KindWebRTCCandidate {
				r.bad(v.Name, fmt.Sprintf("classified as %v, want candidate", m.Kind))
				continue
			}
			c := m.WebRTCCandidate
			if c.Candidate != v.Candidate || c.SDPMid != v.SDPMid || c.SDPMLineIndex != v.SDPMLineIndex {
				r.bad(v.Name, fmt.Sprintf("field mismatch: got {%q,%q,%d}", c.Candidate, c.SDPMid, c.SDPMLineIndex))
				continue
			}
			if !bytes.Equal(c.SessionID, v.SessionID) {
				r.bad(v.Name, "session_id mismatch")
				continue
			}
			if bad := checkUfrag(v, c.UsernameFragment); bad != "" {
				r.bad(v.Name, bad)
				continue
			}
		default:
			r.bad(v.Name, "unknown kind "+v.Kind)
			continue
		}
		r.ok(v.Name)
	}
	return r
}

// checkUfrag enforces the expect_absent contract for the one optional field.
// Absence is asserted positively: a field named in expect_absent MUST decode as
// absent, and one not named MUST decode equal to the row's value.
func checkUfrag(v EntityVector, got *string) string {
	wantAbsent := false
	for _, name := range v.ExpectAbsent {
		if name == "username_fragment" {
			wantAbsent = true
		}
	}
	if wantAbsent {
		if got != nil {
			return fmt.Sprintf("username_fragment decoded as %q; expect_absent says it must be ABSENT (an empty string is read as a real ufrag by addIceCandidate)", *got)
		}
		return ""
	}
	if got == nil {
		if v.UsernameFragment != nil {
			return "username_fragment absent, want " + *v.UsernameFragment
		}
		return ""
	}
	if v.UsernameFragment == nil || *got != *v.UsernameFragment {
		return fmt.Sprintf("username_fragment %q does not match the row", *got)
	}
	return ""
}

func verifyRoles(rows []RoleVector) *report {
	r := &report{surface: "2. offerer / glare"}
	for _, v := range rows {
		imp, impErr := signaling.Impolite(v.Self, v.Other)
		sup, supErr := signaling.PairShouldWaitForOffer(v.Self, v.Other)

		if v.Error != "" {
			if v.Error != errSelfNegotiation {
				r.bad(v.Name, "unknown expected error "+v.Error)
				continue
			}
			if !errors.Is(impErr, signaling.ErrSelfNegotiation) || !errors.Is(supErr, signaling.ErrSelfNegotiation) {
				r.bad(v.Name, fmt.Sprintf("expected refusal, got impolite=%v/%v suppress=%v/%v — a role returned here is §6.4 skip-own failing OPEN", imp, impErr, sup, supErr))
				continue
			}
			r.ok(v.Name)
			continue
		}
		if impErr != nil || supErr != nil {
			r.bad(v.Name, fmt.Sprintf("unexpected error: %v / %v", impErr, supErr))
			continue
		}
		if v.Impolite != nil && imp != *v.Impolite {
			r.bad(v.Name, fmt.Sprintf("impolite=%v, want %v", imp, *v.Impolite))
			continue
		}
		if v.PairSuppress != nil && sup != *v.PairSuppress {
			r.bad(v.Name, fmt.Sprintf("pair_suppress=%v, want %v", sup, *v.PairSuppress))
			continue
		}
		r.ok(v.Name)
	}
	// Convergence is a property of the SET, not of any row: for every pair that
	// appears in both directions, exactly one side may be impolite. A file whose
	// rows are each individually right but jointly non-convergent would pass row
	// checks and still describe a fatal glare.
	if why := checkRoleConvergence(rows); why != "" {
		r.bad("set/convergence", why)
	} else {
		r.ok("set/convergence")
	}
	return r
}

func checkRoleConvergence(rows []RoleVector) string {
	// Reads the FILE's stated values, not Go's recomputation. Recomputing would
	// only ever prove Go agrees with itself — it would report convergence for a
	// sibling file that claims both sides are impolite, which is the one thing
	// this check exists to catch.
	seen := map[[2]string]bool{}
	for _, v := range rows {
		if v.Error != "" || v.Impolite == nil {
			continue
		}
		seen[[2]string{v.Self, v.Other}] = *v.Impolite
	}
	for k, mine := range seen {
		theirs, ok := seen[[2]string{k[1], k[0]}]
		if !ok {
			continue
		}
		if mine == theirs {
			return fmt.Sprintf("pair (%s,%s): both sides impolite=%v — a glare both keep is fatal to the RTCPeerConnection, one neither keeps deadlocks", k[0], k[1], mine)
		}
	}
	return ""
}

func verifySessionIDs(rows []SessionIDVector) *report {
	r := &report{surface: "3. session_id floor"}
	for _, v := range rows {
		err := signaling.ValidateSessionID(v.Bytes)
		accepted := err == nil
		if accepted != v.Accept {
			r.bad(v.Name, fmt.Sprintf("%d bytes accepted=%v, want %v", len(v.Bytes), accepted, v.Accept))
			continue
		}
		r.ok(v.Name)
	}
	return r
}

func verifySignatures(rows []SignatureVector) *report {
	r := &report{surface: "4. §6.3 verification"}
	for _, v := range rows {
		var e entity.Entity
		if err := ecf.Decode(v.EntityBlob, &e); err != nil {
			r.bad(v.Name, "entity_blob does not decode: "+err.Error())
			continue
		}

		var signer signaling.VerifiedSigner
		var err error
		if v.ClaimedPeerID != "" {
			signer, err = signaling.VerifyClaimedSigner(e, v.PublicKey, byte(v.KeyType), v.Signature, v.ClaimedPeerID)
		} else {
			signer, err = signaling.VerifyCoordinationSignature(e, v.PublicKey, byte(v.KeyType), v.Signature)
		}

		switch v.Expect {
		case expectOK:
			if err != nil {
				r.bad(v.Name, "expected ok, got "+err.Error())
				continue
			}
			if v.ExpectSigner != "" && signer.PeerID != v.ExpectSigner {
				r.bad(v.Name, fmt.Sprintf("derived signer %s, want %s — check §6.3's derivation: the canonical Ed25519 form is hash_type 0x00 (identity), not the SHA-256 form §6.3 spells", signer.PeerID, v.ExpectSigner))
				continue
			}
		case expectBadSignature:
			if !errors.Is(err, signaling.ErrBadSignature) {
				r.bad(v.Name, fmt.Sprintf("expected ErrBadSignature, got %v — a verifier that accepts this accepts a forged channel", err))
				continue
			}
		case expectSignerMismatch:
			if !errors.Is(err, signaling.ErrSignerMismatch) {
				r.bad(v.Name, fmt.Sprintf("expected ErrSignerMismatch, got %v — check (a) is what catches a valid signature under a false claim", err))
				continue
			}
		default:
			r.bad(v.Name, "unknown expect "+v.Expect)
			continue
		}
		r.ok(v.Name)
	}
	return r
}

// --- surface 5: the §6.3 container ------------------------------------------

// emitSignedBlobs builds the envelope rows — the crossing that is the §6.3 fold
// trigger. Every row carries the blob bytes AND the rendezvous key a verifier
// must supply, so the crossing is decidable from the file alone.
func emitSignedBlobs() ([]SignedBlobVector, error) {
	kpA := crypto.FromSeed(seedA)
	kpB := crypto.FromSeed(seedB)
	kp448 := crypto.Ed448FromSeed(ed448Seed(0x11))

	idA := crypto.PeerIDFromKeypair(kpA).String()
	idB := crypto.PeerIDFromKeypair(kpB).String()
	id448 := crypto.PeerIDFromKeypair(kp448).String()

	bucketAB, err := signaling.PairKey(idA, idB)
	if err != nil {
		return nil, err
	}
	bucketOther, err := signaling.PairKey(idA, id448)
	if err != nil {
		return nil, err
	}

	offer, err := types.WebRTCOfferData{
		SDP:       "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 AB:CD\r\n",
		SessionID: sid(0x30, 16),
	}.ToEntity()
	if err != nil {
		return nil, err
	}
	innerBlob, err := ecf.Encode(offer)
	if err != nil {
		return nil, err
	}

	sealedA, err := signaling.SealBlob(offer, kpA, bucketAB)
	if err != nil {
		return nil, err
	}
	blobA, err := signaling.SealedToBlob(sealedA)
	if err != nil {
		return nil, err
	}

	var out []SignedBlobVector
	add := func(v SignedBlobVector) { out = append(out, v) }

	// 1. The positive.
	add(SignedBlobVector{
		Name: "ed25519/valid", Blob: blobA, RendezvousKey: bucketAB,
		Expect: expectOK, ExpectSigner: idA, ExpectInnerBlob: innerBlob,
	})

	// 2. THE BINDING ROW. The same valid blob under a different bucket key. An
	// implementation that does not bind passes every other row and fails only
	// this one, which localizes the disagreement to the mechanism.
	add(SignedBlobVector{
		Name: "ed25519/replayed-into-another-bucket", Blob: blobA, RendezvousKey: bucketOther,
		Expect: expectBadSignature,
	})

	// 3. Ed448 — the parametric path. A hardcoded key_type fails here while the
	// Ed25519 rows pass, which localizes rather than merely diffs.
	offer448, err := types.WebRTCOfferData{SDP: "v=0\r\no=- 2 2 IN IP4 0.0.0.0\r\n", SessionID: sid(0x40, 16)}.ToEntity()
	if err != nil {
		return nil, err
	}
	inner448, err := ecf.Encode(offer448)
	if err != nil {
		return nil, err
	}
	bucket448, err := signaling.PairKey(id448, idB)
	if err != nil {
		return nil, err
	}
	sealed448, err := signaling.SealBlob(offer448, kp448, bucket448)
	if err != nil {
		return nil, err
	}
	blob448, err := signaling.SealedToBlob(sealed448)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed448/valid", Blob: blob448, RendezvousKey: bucket448,
		Expect: expectOK, ExpectSigner: id448, ExpectInnerBlob: inner448,
	})

	// 4. The malleability fence: the alternate §1.5 encoding of the signer's OWN
	// key. A verifier that dispatches on the wire's hash_type returns ok here.
	sum := sha256.Sum256(kpA.PublicKeyBytes())
	altID := base58.Encode(append([]byte{crypto.KeyTypeEd25519, crypto.HashTypeSHA256}, sum[:]...))
	forged := sealedA
	forged.Signer = altID
	blobForged, err := signaling.SealedToBlob(forged)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/non-canonical-hash-type", Blob: blobForged, RendezvousKey: bucketAB,
		Expect: expectUnusableKey,
	})

	// 5. Claiming another peer's id with a real signature attached.
	stolen := sealedA
	stolen.Signer = idB
	blobStolen, err := signaling.SealedToBlob(stolen)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/signer-names-another-peer", Blob: blobStolen, RendezvousKey: bucketAB,
		Expect: expectUnusableKey,
	})

	// 6. Tampered inner entity — a rewritten SDP is a different DTLS
	// fingerprint, hence the attacker's own channel.
	evil, err := types.WebRTCOfferData{SDP: "v=0 EVIL", SessionID: sid(0x30, 16)}.ToEntity()
	if err != nil {
		return nil, err
	}
	evilBytes, err := ecf.Encode(evil)
	if err != nil {
		return nil, err
	}
	tampered := sealedA
	tampered.Entity = evilBytes
	blobTampered, err := signaling.SealedToBlob(tampered)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/tampered-inner-entity", Blob: blobTampered, RendezvousKey: bucketAB,
		Expect: expectBadSignature,
	})

	// 7. Domain separation: a signature over the BARE 33-byte content hash —
	// what mint and connect sign. Without the domain tag and the bound key, a
	// signature harvested elsewhere replays as a coordination blob.
	bare := sealedA
	bare.Signature = kpA.Sign(offer.ContentHash.Bytes())
	blobBare, err := signaling.SealedToBlob(bare)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/bare-content-hash-signature", Blob: blobBare, RendezvousKey: bucketAB,
		Expect: expectBadSignature,
	})

	// 8. Wrong key: B signs the right message, A's identity is declared.
	wrong := sealedA
	wrong.Signature = kpB.Sign(coordinationSigningInput(bucketAB, offer.ContentHash.Bytes()))
	blobWrong, err := signaling.SealedToBlob(wrong)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/signed-by-another-key", Blob: blobWrong, RendezvousKey: bucketAB,
		Expect: expectBadSignature,
	})

	// 9. A sign-incapable key_type. Go DERIVES a peer-id for 0xFE — it has a
	// canonical hash type and a defined key length — and then cannot verify with
	// it, which reported as bad_signature until entity-core-rust's row caught it
	// (92897a9). That is the taxonomy's whole point: the fault is in the key
	// TYPE, and calling it a bad signature is one inference from the hardcoded
	// reject that locked out Ed448.
	exoticPub := bytes.Repeat([]byte{0x7E}, 64)
	exoticID, err := crypto.PeerIDFromExperimentalTestPublicKey(exoticPub)
	if err != nil {
		return nil, err
	}
	exotic, err := signaling.SealedToBlob(types.SignedBlobData{
		Entity:    innerBlob,
		Signer:    exoticID.String(),
		PublicKey: exoticPub,
		Signature: bytes.Repeat([]byte{0x00}, 64), // never reached
	})
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "unsupported-key-type/0xfe", Blob: exotic, RendezvousKey: bucketAB,
		Expect: expectUnusableKey,
	})

	// 10. A bare coordination entity — legacy unsigned traffic or another impl's
	// blob. §6.4 makes that normal bucket contents, so it is a SKIP and not a
	// verdict. During the migration window (both impls still deposit bare
	// entities) this is the common case, and filing it under unusable_key would
	// bury real key faults in noise.
	add(SignedBlobVector{
		Name: "not-a-container", Blob: innerBlob, RendezvousKey: bucketAB,
		Expect: expectDecodeSkip,
	})

	// 11-12. §6.3 step 3, the claim comparison. Only this catches a genuinely
	// valid signature presented under a false identity — every other check
	// passes such a blob, because nothing about it is forged. The truthful row
	// exists so the false one cannot pass by a verifier that rejects every
	// claimed-signer row outright.
	add(SignedBlobVector{
		Name: "ed25519/false-claim", Blob: blobA, RendezvousKey: bucketAB,
		ClaimedPeerID: idB, Expect: expectSignerMismatch,
	})
	add(SignedBlobVector{
		Name: "ed25519/true-claim", Blob: blobA, RendezvousKey: bucketAB,
		ClaimedPeerID: idA, Expect: expectOK, ExpectSigner: idA, ExpectInnerBlob: innerBlob,
	})

	// 13-16. THE §6.1 NATIVE ROWS — the ones 11-12 above are not.
	//
	// Rows 11-12 wrap a §6.5 OFFER and hand the verifier a synthetic
	// `claimed_peer_id` in the vector row itself. That exercises the comparison
	// but not the shape: a §6.5 offer carries no peer-id, so the claim had to be
	// invented alongside it. §6.1's connect-request and connect-response carry
	// `initiator` / `responder` AS FIELDS OF THE SIGNED ENTITY, which is the only
	// place in the protocol where step 3 has a real left-hand side.
	//
	// entity-core-rust flagged the honest limit on their own §6.1 read side: it
	// is SAME-SIDE TESTED. The bytes are cross-verified because it shares
	// seal/open with the container that crossed at 38·0F / 36·0F — but "a Go peer
	// seals a §6.1 message and rust reads it" is not, and that row is worth
	// having BEFORE the §6.1 deposits flip rather than after. These are it.
	//
	// `claimed_peer_id` is set on these rows even though the payload already
	// names its author, and the redundancy is deliberate: a verifier that takes
	// the claim from the vector row (both impls' current shape) and one that
	// extracts it from the inner entity (what a real read path does) must reach
	// the same verdict, and setting both means the file needs no verifier change
	// on either side to be readable. Go asserts the two agree — see
	// verifySignedBlobs.
	reqNonce := sid(0x71, 16)
	reqCands := []types.NetworkCandidateData{
		{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: "203.0.113.7:9000"},
	}

	// The honest connect-request: signed by A, naming A.
	reqTrue, err := types.ConnectRequestData{Candidates: reqCands, Initiator: idA, Nonce: reqNonce}.ToEntity()
	if err != nil {
		return nil, err
	}
	reqTrueInner, err := ecf.Encode(reqTrue)
	if err != nil {
		return nil, err
	}
	sealedReqTrue, err := signaling.SealBlob(reqTrue, kpA, bucketAB)
	if err != nil {
		return nil, err
	}
	blobReqTrue, err := signaling.SealedToBlob(sealedReqTrue)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/connect-request/true-initiator", Blob: blobReqTrue, RendezvousKey: bucketAB,
		ClaimedPeerID: idA, Expect: expectOK, ExpectSigner: idA, ExpectInnerBlob: reqTrueInner,
	})

	// The lying connect-request: signed by A, naming B. NOTHING about this blob
	// is forged — A's key derives A's id honestly and the signature covers this
	// bucket — so steps 2 and 4 both pass and only the claim comparison catches
	// it. This is the row that fails against a read path with step 3 unwired,
	// which is what Go's own was until this cycle.
	reqLie, err := types.ConnectRequestData{Candidates: reqCands, Initiator: idB, Nonce: reqNonce}.ToEntity()
	if err != nil {
		return nil, err
	}
	sealedReqLie, err := signaling.SealBlob(reqLie, kpA, bucketAB)
	if err != nil {
		return nil, err
	}
	blobReqLie, err := signaling.SealedToBlob(sealedReqLie)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/connect-request/initiator-names-another-peer", Blob: blobReqLie, RendezvousKey: bucketAB,
		ClaimedPeerID: idB, Expect: expectSignerMismatch,
	})

	// The answering side carries its author in a DIFFERENT field name
	// (`responder`), so a verifier that hardcoded `initiator` passes the two rows
	// above and fails this one — which localizes the disagreement to the field
	// rather than to the mechanism.
	respTrue, err := types.ConnectResponseData{Candidates: reqCands, Nonce: reqNonce, Responder: idB}.ToEntity()
	if err != nil {
		return nil, err
	}
	respTrueInner, err := ecf.Encode(respTrue)
	if err != nil {
		return nil, err
	}
	sealedRespTrue, err := signaling.SealBlob(respTrue, kpB, bucketAB)
	if err != nil {
		return nil, err
	}
	blobRespTrue, err := signaling.SealedToBlob(sealedRespTrue)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/connect-response/true-responder", Blob: blobRespTrue, RendezvousKey: bucketAB,
		ClaimedPeerID: idB, Expect: expectOK, ExpectSigner: idB, ExpectInnerBlob: respTrueInner,
	})

	// punch-sync names NOBODY. It carries no author field at all, so step 3 has
	// nothing to compare and step 2 is the whole check — the position all three
	// §6.5 payloads are in. Emitted with no `claimed_peer_id` on purpose: an
	// implementation that applies the comparison to a message with no claim
	// compares against the empty string and skips every sync it ever collects,
	// which is a silent never-fires rather than a visible failure.
	syncEnt, err := types.PunchSyncData{FireAt: 250, Nonce: reqNonce}.ToEntity()
	if err != nil {
		return nil, err
	}
	syncInner, err := ecf.Encode(syncEnt)
	if err != nil {
		return nil, err
	}
	sealedSync, err := signaling.SealBlob(syncEnt, kpA, bucketAB)
	if err != nil {
		return nil, err
	}
	blobSync, err := signaling.SealedToBlob(sealedSync)
	if err != nil {
		return nil, err
	}
	add(SignedBlobVector{
		Name: "ed25519/punch-sync/names-nobody", Blob: blobSync, RendezvousKey: bucketAB,
		Expect: expectOK, ExpectSigner: idA, ExpectInnerBlob: syncInner,
	})

	return out, nil
}

// coordinationSigningInput re-derives the signed message independently of
// ext/signaling. A negative control built with the code under test can only
// prove self-agreement; this is the cohort's agreed byte layout spelled out
// where a reader can check it against the routed spec.
func coordinationSigningInput(rendezvousKey, contentHash []byte) []byte {
	msg := make([]byte, 0, len(signaling.SigningDomain)+1+len(rendezvousKey)+len(contentHash))
	msg = append(msg, signaling.SigningDomain...)
	msg = append(msg, 0x1F)
	msg = append(msg, rendezvousKey...)
	msg = append(msg, contentHash...)
	return msg
}

func verifySignedBlobs(rows []SignedBlobVector) *report {
	r := &report{surface: "5. §6.3 container"}
	if len(rows) == 0 {
		// ABSENT, not passed. A surface that reports 0/0 and counts toward a
		// green summary is the §11.5.1 blindness this whole proposal exists to
		// end — the number would say "crossed" about something never run.
		r.lines = append(r.lines, "    ABSENT — the container crossing has NOT happened")
		return r
	}
	for _, v := range rows {
		// A row carrying claimed_peer_id exercises §6.3 step 3 — the §6.1 claim
		// comparison. It is a different entry point, not a flag: only that
		// comparison catches a genuinely valid signature under a false claim,
		// and every other check passes such a blob because nothing about it is
		// forged.
		var signer signaling.VerifiedSigner
		var inner entity.Entity
		var err error
		if v.ClaimedPeerID != "" {
			signer, inner, err = signaling.OpenBlobBytesClaimed(v.Blob, v.RendezvousKey, v.ClaimedPeerID)
		} else {
			signer, inner, err = signaling.OpenBlobBytes(v.Blob, v.RendezvousKey)
		}
		got := classifyEnvelopeOutcome(err)
		if got != v.Expect {
			r.bad(v.Name, fmt.Sprintf("expected %s, got %s (%v)", v.Expect, got, err))
			continue
		}

		// THE SAME ROW THROUGH THE REAL READ PATH, with the claim taken from the
		// PAYLOAD instead of from the vector row. For a §6.1 message the two must
		// agree: the row's `claimed_peer_id` is a convenience for a verifier that
		// has not wired step 3 into its classifier, and if a row could pass one
		// way and fail the other it would be testing the harness rather than the
		// implementation. A §6.5 payload names nobody, so the classifier has no
		// claim to compare and the row-driven check above is the only one —
		// exactly why the §6.1 rows had to exist.
		//
		// EXCLUDING the decode_skip rows, where the two functions disagree BY
		// DESIGN and must: OpenBlobBytes reports "this was never a container",
		// while ClassifyCollected goes on to read it as the bare §6.2 entity it
		// is. That difference is the tolerant framing disposition, not a defect,
		// and it is what keeps a bare depositor readable across the flag day.
		//
		// And only where the PAYLOAD names an author, or where no claim is in
		// play at all. Rows 11-12 wrap a §6.5 offer with a claim that exists
		// solely in the vector row: the classifier has nothing to compare there
		// and correctly returns ok, so cross-checking them would assert that a
		// synthetic claim is a real one.
		classified, classifyErr := signaling.ClassifyCollected(v.Blob, v.RendezvousKey)
		payloadNames := payloadClaim(classified)
		if v.Expect != expectDecodeSkip && (payloadNames != "" || v.ClaimedPeerID == "") {
			gotClassified := classifyEnvelopeOutcome(classifyErr)
			switch {
			case gotClassified == v.Expect:
				// The row reads the same way from the wire as from the row.

			// `signer` is the zero value on this branch — the row-driven open
			// returned the mismatch error — so the verified identity comes from
			// the classified result, which is the one that succeeded.
			case v.Expect == expectSignerMismatch && gotClassified == expectOK &&
				payloadNames != "" && payloadNames == classified.Signer.PeerID:
				// THE ROW'S NEGATIVE IS NOT NEGATIVE ON THE WIRE. The payload
				// names its own true signer, so the only false claim is the one
				// in the vector row's `claimed_peer_id` field. A verifier that
				// takes the claim from the row catches it; a real §6.1 collector,
				// which reads `initiator` out of the signed entity, sees a
				// truthful message and correctly returns ok.
				//
				// So the row cannot distinguish a read path with step 3 wired
				// from one without — which is precisely the gap this repo had.
				// Flagged, not failed: it is a disagreement about what
				// `claimed_peer_id` MEANS on a §6.1 row, and the cohort never
				// pinned that because §6.1 rows did not exist until today.
				r.soft(v.Name, "the payload names its own signer, so only the row's claimed_peer_id is false — "+
					"a payload-driven read path sees a truthful message, and this row cannot catch an unwired step 3")
				continue

			default:
				r.bad(v.Name, fmt.Sprintf("the row's own claim gives %s but the payload's claim gives %s — the two disagree",
					v.Expect, gotClassified))
				continue
			}
			if payloadNames != "" && v.ClaimedPeerID != "" && payloadNames != v.ClaimedPeerID {
				r.bad(v.Name, fmt.Sprintf("payload names %q, row claims %q — the row is self-inconsistent", payloadNames, v.ClaimedPeerID))
				continue
			}
		}

		if v.Expect != expectOK {
			r.ok(v.Name)
			continue
		}
		if v.ExpectSigner != "" && signer.PeerID != v.ExpectSigner {
			r.bad(v.Name, fmt.Sprintf("signer %q, expected %q", signer.PeerID, v.ExpectSigner))
			continue
		}
		// Byte fidelity THROUGH the container: this is where a decode+re-encode
		// would silently invalidate the signature the container carries.
		if len(v.ExpectInnerBlob) > 0 {
			gotInner, encErr := ecf.Encode(inner)
			if encErr != nil {
				r.bad(v.Name, fmt.Sprintf("re-encode inner: %v", encErr))
				continue
			}
			if !bytes.Equal(gotInner, v.ExpectInnerBlob) {
				r.bad(v.Name, "inner entity did not survive the container byte-for-byte")
				continue
			}
		}
		r.ok(v.Name)
	}
	return r
}

// payloadClaim returns the peer-id a classified §6.1 message names as its own
// author, or "" for anything that names nobody (punch-sync and all three §6.5
// payloads). A KindUnknown result names nobody either — it never decoded.
func payloadClaim(m signaling.CollectedMessage) string {
	switch m.Kind {
	case signaling.KindConnectRequest:
		return m.Request.Initiator
	case signaling.KindConnectResponse:
		return m.Response.Responder
	default:
		return ""
	}
}

func classifyEnvelopeOutcome(err error) string {
	switch {
	case err == nil:
		return expectOK
	case errors.Is(err, signaling.ErrUnusableKey):
		return expectUnusableKey
	case errors.Is(err, signaling.ErrBadSignature):
		return expectBadSignature
	case errors.Is(err, signaling.ErrSignerMismatch):
		return expectSignerMismatch
	case errors.Is(err, signaling.ErrNotAContainer):
		return expectDecodeSkip
	default:
		return fmt.Sprintf("unclassified(%v)", err)
	}
}

// --- surface 0: the signing input -------------------------------------------

// Fixed, recognizable, and deliberately not a real key or a real hash: the block
// describes a LAYOUT, not a signature. Same values entity-core-rust uses, so the
// two sample.bytes are directly comparable byte-for-byte rather than only
// mutually recomputable.
var (
	sampleRendezvousKey = bytes.Repeat([]byte{0x5A}, signaling.RendezvousKeyLen)
	sampleContentHash   = bytes.Repeat([]byte{0xC7}, 33)
)

func emitSigningInput() *SigningInputSpec {
	msg := coordinationSigningInput(sampleRendezvousKey, sampleContentHash)
	return &SigningInputSpec{
		Components: []SigningComponent{
			{Name: "domain", Len: uint64(len(signaling.SigningDomain))},
			{Name: "sep", Len: 1},
			{Name: "rendezvous_key", Len: signaling.RendezvousKeyLen},
			{Name: "content_hash", Len: 33},
		},
		Sample: SigningSample{
			Bytes:         msg,
			ContentHash:   sampleContentHash,
			RendezvousKey: sampleRendezvousKey,
		},
		TotalLen: uint64(len(msg)),
	}
}

func verifySigningInput(spec *SigningInputSpec) *report {
	r := &report{surface: "0. signing input"}
	if spec == nil {
		// Absent is not passed, for the same reason a missing container surface
		// is not: it would mean the one field that localizes a signing
		// disagreement was never compared.
		r.lines = append(r.lines, "    ABSENT — the signed message layout was not declared")
		return r
	}

	want := coordinationSigningInput(spec.Sample.RendezvousKey, spec.Sample.ContentHash)
	if !bytes.Equal(want, spec.Sample.Bytes) {
		r.bad("sample/bytes", fmt.Sprintf(
			"recomputing the emitter's own sample inputs gives different bytes — the two impls sign different messages.\n"+
				"        emitter: %x\n        ours:    %x", spec.Sample.Bytes, want))
	} else {
		r.ok("sample/bytes")
	}

	if spec.TotalLen != uint64(len(want)) {
		r.bad("total_len", fmt.Sprintf("emitter signs %d bytes, this build signs %d", spec.TotalLen, len(want)))
	} else {
		r.ok("total_len")
	}

	wantComponents := emitSigningInput().Components
	if len(spec.Components) != len(wantComponents) {
		r.bad("components", fmt.Sprintf("emitter declares %d components, this build has %d",
			len(spec.Components), len(wantComponents)))
		return r
	}
	mismatch := ""
	for i, c := range spec.Components {
		if c.Name != wantComponents[i].Name || c.Len != wantComponents[i].Len {
			mismatch = fmt.Sprintf("component %d: emitter %s(%d), ours %s(%d)",
				i, c.Name, c.Len, wantComponents[i].Name, wantComponents[i].Len)
			break
		}
	}
	if mismatch != "" {
		r.bad("components", mismatch)
	} else {
		r.ok("components")
	}
	return r
}
