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
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
	errSelfNegotiation   = "self_negotiation"
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

	f := VectorFile{
		Schema:        types.WebRTCSignalingSchema,
		Emitter:       "core-go",
		EmitterCommit: headCommit(),
		Entities:      entities,
		Roles:         roles,
		SessionIDs:    emitSessionIDs(),
		Signatures:    sigs,
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
	fmt.Printf("  entities=%d roles=%d session_ids=%d signatures=%d\n",
		len(f.Entities), len(f.Roles), len(f.SessionIDs), len(f.Signatures))
	return nil
}

// headCommit records provenance. "unknown" rather than a failure: a vector file
// emitted from a tarball is still verifiable, it just cannot be re-derived, and
// saying so is better than refusing to emit.
func headCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
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
	fail    int
	lines   []string
}

func (r *report) ok(name string) { r.pass++; r.lines = append(r.lines, "    ok   "+name) }
func (r *report) bad(name, why string) {
	r.fail++
	r.lines = append(r.lines, "    FAIL "+name+" — "+why)
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
		verifyEntities(f.Entities),
		verifyRoles(f.Roles),
		verifySessionIDs(f.SessionIDs),
		verifySignatures(f.Signatures),
	}

	total, failed := 0, 0
	for _, r := range reports {
		fmt.Printf("  %-24s %d pass / %d fail\n", r.surface, r.pass, r.fail)
		for _, l := range r.lines {
			fmt.Println(l)
		}
		total += r.pass + r.fail
		failed += r.fail
	}
	fmt.Println()
	if failed == 0 {
		fmt.Printf("WEBRTC COORDINATION VECTORS: PASS — %d·0F @ %s (%s)\n", total, f.EmitterCommit, f.Emitter)
		fmt.Println("  Coordination layer only. NOT evidence that WebRTC transport works (§11.5.1: S5 is).")
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
