package signaling

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	cbor "github.com/fxamacker/cbor/v2"
)

// deriver returns a t-bound helper that unwraps a (key, err) derivation and
// fails the test on error — a CBOR/hash failure is never expected here. It is a
// closure so `d(TagKey("chess"))` spreads the two-value return legally (Go
// forbids prepending t before a multi-value call).
func deriver(t *testing.T) func([]byte, error) []byte {
	return func(key []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatalf("derivation errored: %v", err)
		}
		return key
	}
}

// §2.2.1 / §6: every key is 33 bytes at the SHA-256 floor. This catches an
// otherwise-correct SHA-384 impl that passes everything else — the digest
// widens to 49 and the format byte flips off 0x00, so two homes never meet.
func TestEveryKeyIsThirtyThreeBytesAtTheSHA256Floor(t *testing.T) {
	d := deriver(t)
	keys := map[string][]byte{
		"tag":    d(TagKey("chess")),
		"secret": d(SecretKey("hunter2")),
		"lobby":  d(LobbyKey(LobbyDefault)),
		"pair":   d(PairKey("alice", "bob")),
	}
	for mode, k := range keys {
		if len(k) != 33 {
			t.Errorf("%s: key is %d bytes, want 33", mode, len(k))
		}
		if k[0] != hash.AlgorithmSHA256 {
			t.Errorf("%s: format byte is 0x%02x, want 0x00 (SHA-256 floor)", mode, k[0])
		}
	}
}

// §2.2.1: pair is order-independent — either peer may derive first.
func TestPairIsOrderIndependent(t *testing.T) {
	d := deriver(t)
	ab := d(PairKey("alice", "bob"))
	ba := d(PairKey("bob", "alice"))
	if !bytes.Equal(ab, ba) {
		t.Fatalf("pair(alice,bob)=%x != pair(bob,alice)=%x", ab, ba)
	}
}

// §2.2.1: the pair separator disambiguates different pairs. Without the SEP,
// bare concatenation makes sorted("ab","c") and sorted("a","bc") both "abc" —
// two different pairs sharing one bucket.
func TestPairSeparatorDisambiguatesDifferentPairs(t *testing.T) {
	d := deriver(t)
	p1 := d(PairKey("ab", "c"))
	p2 := d(PairKey("a", "bc"))
	if bytes.Equal(p1, p2) {
		t.Fatalf("pair(ab,c) and pair(a,bc) collide: %x", p1)
	}
}

// §2.2.1: tags are case-sensitive — byte-exact UTF-8, no case-folding.
func TestTagsAreCaseSensitive(t *testing.T) {
	d := deriver(t)
	lower := d(TagKey("chess"))
	upper := d(TagKey("Chess"))
	if bytes.Equal(lower, upper) {
		t.Fatalf("TagKey folded case: chess and Chess share %x", lower)
	}
}

// §2.2.1: no Unicode normalization — the likeliest accidental import. The same
// grapheme (e-with-acute) as a precomposed code point (U+00E9) and as
// base+combining ("e" + U+0301) is canonically equivalent (NFC/NFD) but
// byte-different; the two MUST derive different keys, proving the text layer
// does not normalize. Built from explicit runes so the byte difference is
// guaranteed independent of how the source file is stored.
func TestNoUnicodeNormalization(t *testing.T) {
	d := deriver(t)
	precomposed := "caf" + string(rune(0x00E9))      // NFC: e-acute = U+00E9
	decomposed := "caf" + "e" + string(rune(0x0301)) // NFD: e + combining acute
	if precomposed == decomposed {
		t.Fatal("test strings are not byte-different")
	}
	a := d(TagKey(precomposed))
	b := d(TagKey(decomposed))
	if bytes.Equal(a, b) {
		t.Fatalf("TagKey normalized: NFC/NFD variants share %x", a)
	}
}

// §2.2.1: modes are separated — the same input under different mode tags derives
// different keys. Without the mode tag in the payload, a `tag` "x" and a
// `secret` "x" would collide.
func TestModesAreSeparated(t *testing.T) {
	d := deriver(t)
	const in = "x"
	keys := [][]byte{
		d(TagKey(in)),
		d(SecretKey(in)),
		d(LobbyKey(in)),
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Fatalf("modes %d and %d collide on input %q: %x", i, j, in, keys[i])
			}
		}
	}
}

// §4.1: the derivation MUST ignore the deriving peer's home hash format. Go's
// process-global is entity.DefaultHashAlgorithm (settable via
// SetDefaultHashAlgorithm) — the analog of Rust's default_hash_format(). This
// test flips it to SHA-384, proves the flip is LIVE and consequential (an
// entity.NewEntity hash actually changes under it, so the test cannot pass
// vacuously), and requires byte-identical keys across the flip.
func TestHomeFormatIndependence(t *testing.T) {
	d := deriver(t)
	orig := entity.DefaultHashAlgorithm()
	t.Cleanup(func() { entity.SetDefaultHashAlgorithm(orig) })

	entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA256)
	k256 := d(TagKey("chess"))
	probeData := cbor.RawMessage([]byte{0x63, 'a', 'b', 'c'}) // CBOR tstr "abc"
	ent256, err := entity.NewEntity("system/nat/rendezvous-key", probeData)
	if err != nil {
		t.Fatalf("NewEntity under SHA-256: %v", err)
	}

	entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA384)
	if entity.DefaultHashAlgorithm() != hash.AlgorithmSHA384 {
		t.Fatal("home-format flip is not live — test would be vacuous")
	}
	ent384, err := entity.NewEntity("system/nat/rendezvous-key", probeData)
	if err != nil {
		t.Fatalf("NewEntity under SHA-384: %v", err)
	}
	// The flip is consequential: an ordinary entity's hash DOES change under it.
	if ent256.ContentHash == ent384.ContentHash {
		t.Fatal("flip did not change entity.NewEntity's hash — global unconsulted, test proves nothing")
	}

	k384 := d(TagKey("chess"))
	// But the rendezvous key is byte-identical across the flip.
	if !bytes.Equal(k256, k384) {
		t.Fatalf("home format leaked into the key: SHA-256-home=%x, SHA-384-home=%x", k256, k384)
	}
	if k256[0] != hash.AlgorithmSHA256 {
		t.Fatalf("key not at the SHA-256 floor: format byte 0x%02x", k256[0])
	}
}

// §4.1 stage bisect: after two impls disagree, this locates the fault. The
// payload and its CBOR-bstr wrapping are pinned; the digest is deliberately
// unpublished (correctness is settled by impls meeting, not by an oracle).
func TestStageBisectMatchesThePublishedBytes(t *testing.T) {
	payload := RendezvousPayload("tag", []byte("chess"))
	const wantPayloadHex = "656e746974793a7264763a76311f7461671f6368657373"
	if got := hex.EncodeToString(payload); got != wantPayloadHex {
		t.Fatalf("payload = %s, want %s", got, wantPayloadHex)
	}
	if len(payload) != 23 {
		t.Fatalf("payload is %d bytes, want 23", len(payload))
	}

	// cbor_bstr = 0x57 (minimal-length bstr head for 23 bytes) ‖ payload.
	wrapped, err := ecf.Encode(payload)
	if err != nil {
		t.Fatalf("ecf.Encode(payload): %v", err)
	}
	want := append([]byte{0x57}, payload...)
	if !bytes.Equal(wrapped, want) {
		t.Fatalf("cbor_bstr = %x, want %x", wrapped, want)
	}
}
