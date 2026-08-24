package types

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
)

func mkHash(t *testing.T, hexFirstByte byte) hash.Hash {
	t.Helper()
	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = hexFirstByte
	// Leave the rest zeroed; only the first few hex chars matter for layout
	// shape checks.
	return h
}

func TestBuildContentURL_Flat(t *testing.T) {
	h := mkHash(t, 0xab)
	got, err := BuildContentURL("https://cdn.example.com/content", ContentLayoutFlat, h)
	if err != nil {
		t.Fatalf("BuildContentURL: %v", err)
	}
	// Full wire form — format byte `00` (SHA-256) INCLUDED, then the digest.
	wire := hex.EncodeToString(h.Bytes())
	want := "https://cdn.example.com/content/" + wire
	if got != want {
		t.Errorf("flat:\n  got  %s\n  want %s", got, want)
	}
	// Guard the shape directly: the URL carries the format byte, not the
	// 64-char digest-only form the pre-ruling code emitted.
	if !strings.HasSuffix(got, "/00ab"+strings.Repeat("00", 31)) {
		t.Errorf("flat URL is not the full wire form (format byte `00` + digest): %s", got)
	}
}

func TestBuildContentURL_Sharded2Flat(t *testing.T) {
	h := mkHash(t, 0xab)
	got, err := BuildContentURL("https://cdn.example.com/content", ContentLayoutSharded2Flat, h)
	if err != nil {
		t.Fatalf("BuildContentURL: %v", err)
	}
	// `[0:2]` is the FORMAT-CODE byte (the algorithm partition, §6.5.3.1), not
	// the first digest byte — the property a digest-only hex silently killed.
	wire := hex.EncodeToString(h.Bytes())
	want := "https://cdn.example.com/content/" + wire[0:2] + "/" + wire
	if got != want {
		t.Errorf("sharded-2-flat:\n  got  %s\n  want %s", got, want)
	}
	if !strings.HasPrefix(wire, "00") {
		t.Errorf("sharded prefix must be the format byte `00`, wire=%s", wire)
	}
}

func TestBuildContentURL_Sharded24(t *testing.T) {
	h := mkHash(t, 0xab)
	h.Digest[1] = 0xcd
	got, err := BuildContentURL("https://cdn.example.com/content", ContentLayoutSharded24, h)
	if err != nil {
		t.Fatalf("BuildContentURL: %v", err)
	}
	// wire = 00 ab cd 00…  →  /00/ab/00abcd00…  ([0:2]=format, [2:4]=digest[0]).
	wire := hex.EncodeToString(h.Bytes())
	want := "https://cdn.example.com/content/" + wire[0:2] + "/" + wire[2:4] + "/" + wire
	if got != want {
		t.Errorf("sharded-2-4:\n  got  %s\n  want %s", got, want)
	}
}

func TestBuildContentURL_Sharded22AliasOf24(t *testing.T) {
	h := mkHash(t, 0xab)
	h.Digest[1] = 0xcd
	got22, err := BuildContentURL("https://cdn.example.com/content", ContentLayoutSharded22, h)
	if err != nil {
		t.Fatalf("BuildContentURL sharded-2-2: %v", err)
	}
	got24, err := BuildContentURL("https://cdn.example.com/content", ContentLayoutSharded24, h)
	if err != nil {
		t.Fatalf("BuildContentURL sharded-2-4: %v", err)
	}
	if got22 != got24 {
		t.Errorf("sharded-2-2 must alias sharded-2-4:\n  got22 %s\n  got24 %s", got22, got24)
	}
}

func TestBuildContentURL_UnknownLayout(t *testing.T) {
	h := mkHash(t, 0xab)
	_, err := BuildContentURL("https://cdn.example.com/content", "bogus-layout", h)
	if err == nil {
		t.Fatalf("expected error on unknown layout, got nil")
	}
}

func TestBuildContentURL_TrimsTrailingSlash(t *testing.T) {
	h := mkHash(t, 0xab)
	got, err := BuildContentURL("https://cdn.example.com/content/", ContentLayoutFlat, h)
	if err != nil {
		t.Fatalf("BuildContentURL: %v", err)
	}
	want := "https://cdn.example.com/content/" + hex.EncodeToString(h.Bytes())
	if got != want {
		t.Errorf("trailing-slash trim:\n  got  %s\n  want %s", got, want)
	}
}

// TestBuildContentURL_FullWireFormLengthPerFormatByte is the teeth for the
// -g ruling (EXTENSION-NETWORK §6.5.3 "Hex strictness"; corrected 2026-08-10):
// the content-hash hex is the FULL wire form (format byte included), and its
// length is the one the leading format byte IMPLIES — never a hardcoded 66.
// Exercising SHA-384 (98 chars, format byte `01`) alongside SHA-256 (66, `00`)
// mutation-guards the 2026-08-10 defect class where a fixed-66 gate 400'd a
// valid SHA-384 hash. A regression to h.EffectiveDigest() (digest-only) makes
// the format-byte prefix and the length assertions both fail.
func TestBuildContentURL_FullWireFormLengthPerFormatByte(t *testing.T) {
	cases := []struct {
		name       string
		h          hash.Hash
		formatByte string
		wantLen    int // 2 (format byte) + 2*digestLen
	}{
		{"sha256", hash.Hash{Algorithm: hash.AlgorithmSHA256}, "00", 2 + 2*hash.SHA256DigestSize},
		{"sha384", hash.Hash{Algorithm: hash.AlgorithmSHA384}, "01", 2 + 2*hash.SHA384DigestSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.h.Digest[0] = 0xab
			got, err := BuildContentURL("https://cdn.example.com/content", ContentLayoutFlat, tc.h)
			if err != nil {
				t.Fatalf("BuildContentURL: %v", err)
			}
			hexPart := strings.TrimPrefix(got, "https://cdn.example.com/content/")
			if !strings.HasPrefix(hexPart, tc.formatByte) {
				t.Errorf("%s: hex must begin with format byte %q (full wire form), got %s", tc.name, tc.formatByte, hexPart)
			}
			if len(hexPart) != tc.wantLen {
				t.Errorf("%s: hex length %d, want %d (= 2 + 2*digestLen, byte-implied — NOT a hardcoded 66)",
					tc.name, len(hexPart), tc.wantLen)
			}
			// It must equal the full wire form, and NOT the digest-only form.
			if hexPart != hex.EncodeToString(tc.h.Bytes()) {
				t.Errorf("%s: hex is not hex(H.Bytes()) — full wire form required", tc.name)
			}
			if hexPart == hex.EncodeToString(tc.h.EffectiveDigest()) {
				t.Errorf("%s: hex is the 64/96-char digest-only form — the -g ruling forbids it", tc.name)
			}
		})
	}
}

func TestBuildTreeLeafURL_Default(t *testing.T) {
	got := BuildTreeLeafURL("https://cdn.example.com/peers/abc", "docs/readme", "")
	want := "https://cdn.example.com/peers/abc/docs/readme.bin"
	if got != want {
		t.Errorf("default suffix:\n  got  %s\n  want %s", got, want)
	}
}

func TestBuildTreeLeafURL_CustomSuffix(t *testing.T) {
	got := BuildTreeLeafURL("https://cdn.example.com/peers/abc", "docs/readme", ".ent")
	want := "https://cdn.example.com/peers/abc/docs/readme.ent"
	if got != want {
		t.Errorf("custom suffix:\n  got  %s\n  want %s", got, want)
	}
}

func TestBuildTreeLeafURL_TrimsLeadingPathSlash(t *testing.T) {
	got := BuildTreeLeafURL("https://cdn.example.com/peers/abc", "/docs/readme", ".bin")
	want := "https://cdn.example.com/peers/abc/docs/readme.bin"
	if got != want {
		t.Errorf("leading-slash trim:\n  got  %s\n  want %s", got, want)
	}
}

func TestBuildTreeLeafURL_EmptyPathSuffixOnly(t *testing.T) {
	got := BuildTreeLeafURL("https://cdn.example.com/peers/abc", "", ".bin")
	want := "https://cdn.example.com/peers/abc.bin"
	if got != want {
		t.Errorf("empty path:\n  got  %s\n  want %s", got, want)
	}
}

func TestEffectiveContentURLPrefix_ExplicitWins(t *testing.T) {
	// When content_url_prefix is set, it wins regardless of tree_url_prefix.
	ep := TransportEndpoint{
		TreeURLPrefix:    "https://cdn.example.com/peers/abc",
		ContentURLPrefix: "https://other.example.com/dedup",
	}
	got := EffectiveContentURLPrefix(ep)
	want := "https://other.example.com/dedup"
	if got != want {
		t.Errorf("explicit prefix:\n  got  %s\n  want %s", got, want)
	}
}

// TestEffectiveContentURLPrefix_NeverDerivesFromTree is the INVARIANT that
// replaced two tests asserting the opposite (`_DefaultsFromTree` and
// `_TrimsTrailingSlash`, both removed 2026-08-13).
//
// They pinned a derivation — `{tree_url_prefix}/content` when
// `content_url_prefix` is absent — citing "EXTENSION-NETWORK §6.4 D-14",
// a rule that exists nowhere in the landed corpus. EXTENSION-SUBSTITUTE
// §2.2 rules the opposite explicitly: "there is no default — the publisher
// MUST state it. An impl that treats it as optional-with-derivation is
// non-conformant."
//
// Converted rather than deleted, per this repo's no-backward-compat-shims
// rule: a removed convention becomes a negative assertion, so re-introducing
// the derivation fails loudly instead of silently restoring it.
//
// What it protects: deployment scenario S4 — tree on one host, dedup'd
// content on a shared bucket. A consumer that derives fetches from an origin
// the publisher never committed to, which either 404s or, worse, exists and
// serves a different peer's bytes.
func TestEffectiveContentURLPrefix_NeverDerivesFromTree(t *testing.T) {
	for _, tree := range []string{
		"https://cdn.example.com/peers/abc",
		"https://cdn.example.com/peers/abc/", // the trailing-slash case
	} {
		ep := TransportEndpoint{TreeURLPrefix: tree}
		if got := EffectiveContentURLPrefix(ep); got != "" {
			t.Errorf("derived %q from tree_url_prefix %q — content_url_prefix is REQUIRED with no "+
				"default (EXTENSION-SUBSTITUTE §2.2, pinned ruling)", got, tree)
		}
	}
}

// An explicit content_url_prefix is returned verbatim even when a tree
// prefix is also present — the two are independent publisher commitments
// (NETWORK §6.5.3 Amendment 5: they "MAY be entirely separate origins").
func TestEffectiveContentURLPrefix_ExplicitWinsAndIsVerbatim(t *testing.T) {
	ep := TransportEndpoint{
		TreeURLPrefix:    "https://cdn.example.com/peers/abc",
		ContentURLPrefix: "https://shared.example.com/content",
	}
	if got := EffectiveContentURLPrefix(ep); got != ep.ContentURLPrefix {
		t.Errorf("content prefix: got %q want %q (the S4 dedup case — the two prefixes are independent)",
			got, ep.ContentURLPrefix)
	}
}

func TestEffectiveContentURLPrefix_BothAbsent(t *testing.T) {
	// Malformed endpoint — both prefixes missing — returns empty.
	got := EffectiveContentURLPrefix(TransportEndpoint{})
	if got != "" {
		t.Errorf("both absent: got %q want empty", got)
	}
}

// EXTENSION-NETWORK §6.5.3.1 Amendment 5: listings are named objects with
// suffix ".list" by default; URL shape mirrors the leaf URL.
func TestBuildTreeListingURL_Default(t *testing.T) {
	got := BuildTreeListingURL("https://cdn.example.com/peers/abc", "docs", "")
	want := "https://cdn.example.com/peers/abc/docs.list"
	if got != want {
		t.Errorf("default listing suffix:\n  got  %s\n  want %s", got, want)
	}
}

func TestBuildTreeListingURL_CustomSuffix(t *testing.T) {
	got := BuildTreeListingURL("https://cdn.example.com/peers/abc", "docs", ".dir")
	want := "https://cdn.example.com/peers/abc/docs.dir"
	if got != want {
		t.Errorf("custom listing suffix:\n  got  %s\n  want %s", got, want)
	}
}

// Peer-root listing: empty path → suffix attaches directly to the prefix
// tail (matching the leaf-URL convention).
func TestBuildTreeListingURL_PeerRoot(t *testing.T) {
	got := BuildTreeListingURL("https://cdn.example.com/peers/abc", "", "")
	want := "https://cdn.example.com/peers/abc.list"
	if got != want {
		t.Errorf("peer-root listing:\n  got  %s\n  want %s", got, want)
	}
}

// EXTENSION-NETWORK §6.5.3 Amendment 5: leaf/listing suffix REQUIRED
// distinct. Default-vs-default succeeds (".bin" vs ".list").
func TestTransportEndpoint_Validate_DefaultsDistinct(t *testing.T) {
	if err := (TransportEndpoint{}).Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestTransportEndpoint_Validate_RejectsSameSuffix(t *testing.T) {
	ep := TransportEndpoint{TreeLeafSuffix: ".ent", TreeListingSuffix: ".ent"}
	if err := ep.Validate(); err == nil {
		t.Fatalf("expected error on identical suffixes")
	}
}

// One override against the other's default still requires distinctness:
// e.g. an operator overriding tree_leaf_suffix to ".list" collides with
// the default listing suffix.
func TestTransportEndpoint_Validate_OverrideCollidesWithDefault(t *testing.T) {
	ep := TransportEndpoint{TreeLeafSuffix: ".list"}
	if err := ep.Validate(); err == nil {
		t.Fatalf("expected error when override collides with default listing suffix")
	}
}

// ECF round-trip for the Amendment-5 fields. Old four-field decoders see
// the new fields as unknown (drop them); new decoders preserve them.
func TestTransportEndpoint_RoundTripAmendment5(t *testing.T) {
	ep := TransportEndpoint{
		TreeURLPrefix:     "https://cdn.example.com/peers/abc",
		ContentURLPrefix:  "https://cdn.example.com/content",
		ManifestURLPrefix: "https://cdn.example.com/peers/abc/manifest",
		ContentLayout:     ContentLayoutSharded2Flat,
		TreeLeafSuffix:    ".bin",
		TreeListingSuffix: ".list",
	}
	enc, err := ecf.Encode(ep)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got TransportEndpoint
	if err := ecf.Decode(enc, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != ep {
		t.Fatalf("round-trip mismatch:\n  got  %+v\n  want %+v", got, ep)
	}
	// ECF is deterministic — re-encoding yields identical bytes.
	enc2, err := ecf.Encode(got)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(enc, enc2) {
		t.Fatalf("ecf not stable across round-trip")
	}
}

// Pre-Amendment-5 emitter (no manifest_url_prefix, no tree_listing_suffix)
// still decodes. New fields land as empty; the Effective* accessors apply
// the Amendment 5 defaults at the call site.
func TestTransportEndpoint_BackwardDecodeOldShape(t *testing.T) {
	old := struct {
		TreeURLPrefix    string `cbor:"tree_url_prefix"`
		ContentURLPrefix string `cbor:"content_url_prefix"`
		ContentLayout    string `cbor:"content_layout"`
		TreeLeafSuffix   string `cbor:"tree_leaf_suffix,omitempty"`
	}{
		TreeURLPrefix:    "https://cdn.example.com/peers/abc",
		ContentURLPrefix: "https://cdn.example.com/content",
		ContentLayout:    ContentLayoutFlat,
		TreeLeafSuffix:   ".bin",
	}
	enc, err := ecf.Encode(old)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got TransportEndpoint
	if err := ecf.Decode(enc, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ManifestURLPrefix != "" || got.TreeListingSuffix != "" {
		t.Fatalf("expected new fields empty on old-shape decode: %+v", got)
	}
	if got.EffectiveTreeListingSuffix() != DefaultTreeListingSuffix {
		t.Fatalf("effective listing suffix should default: got %q", got.EffectiveTreeListingSuffix())
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("decoded old-shape endpoint must validate: %v", err)
	}
}
