package main

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestEmissionRoundTrip: load the emission file we just produced and
// spot-check that the key vectors landed where expected, with the
// shapes Appendix E §E.2 prescribes.
func TestEmissionRoundTrip(t *testing.T) {
	data, err := os.ReadFile("../../../test-vectors/v1/emit-go.cbor")
	if err != nil {
		t.Skipf("emit-go.cbor not present; skipping (run emit-canonical first): %v", err)
	}
	var em emission
	if err := cbor.Unmarshal(data, &em); err != nil {
		t.Fatalf("decode emission: %v", err)
	}
	if em.Impl != "core-go" {
		t.Errorf("impl mismatch: %s", em.Impl)
	}
	if em.CorpusVersion != "v1" {
		t.Errorf("corpus_version mismatch: %s", em.CorpusVersion)
	}
	if em.SpecVersion != "1.5" {
		t.Errorf("spec_version mismatch: %s", em.SpecVersion)
	}

	// Class A float spot-checks: minimization per RFC 8949 §4.2 Rule 4.
	classAFloats := map[string]string{
		"float.1":  "f90000",         // 0.0 → f16
		"float.7":  "f97e00",         // NaN → canonical f16 NaN
		"float.10": "f97bff",         // 65504.0 → max f16
		"float.12": "fa477fdf00",     // 65503.0 → must encode as f32 (one f32 ULP below max f16)
		"float.14": "fb3ff199999999999a", // 1.1 → f64
	}
	for id, want := range classAFloats {
		got, ok := em.EncodeResults[id]
		if !ok {
			t.Errorf("missing %s", id)
			continue
		}
		if hex.EncodeToString(got) != want {
			t.Errorf("%s: got %s want %s", id, hex.EncodeToString(got), want)
		}
	}

	// Class A int boundaries.
	classAInts := map[string]string{
		"int.1":  "00",                 // 0
		"int.2":  "17",                 // 23
		"int.3":  "1818",               // 24
		"int.10": "1b7fffffffffffffff", // MaxInt64
		"int.11": "20",                 // -1
	}
	for id, want := range classAInts {
		got, ok := em.EncodeResults[id]
		if !ok {
			t.Errorf("missing %s", id)
			continue
		}
		if hex.EncodeToString(got) != want {
			t.Errorf("%s: got %s want %s", id, hex.EncodeToString(got), want)
		}
	}

	// Class B content_hash.1 — the F5 vector. SHA256(ECF({type:"system/empty",
	// data:{}})) prefixed with varint(0). The ECF input is a 2-key map with
	// canonical-sorted keys "data" (4) < "type" (4 lex). Length should be
	// 33 bytes (1 varint + 32 digest).
	ch1, ok := em.EncodeResults["content_hash.1"]
	if !ok {
		t.Fatal("missing content_hash.1")
	}
	if len(ch1) != 33 {
		t.Errorf("content_hash.1 len: got %d want 33", len(ch1))
	}
	if ch1[0] != 0x00 {
		t.Errorf("content_hash.1 varint: got 0x%02x want 0x00", ch1[0])
	}

	// content_hash.4 has format_code=128 → 2-byte varint 0x80 0x01.
	ch4, ok := em.EncodeResults["content_hash.4"]
	if !ok {
		t.Fatal("missing content_hash.4")
	}
	if len(ch4) != 34 {
		t.Errorf("content_hash.4 len: got %d want 34 (2-byte varint + 32 digest)", len(ch4))
	}
	if ch4[0] != 0x80 || ch4[1] != 0x01 {
		t.Errorf("content_hash.4 varint: got 0x%02x 0x%02x want 0x80 0x01", ch4[0], ch4[1])
	}

	// peer_id.1 — Base58 of [0x01, 0x01, 0x00..0x00]. ECF-encoded as a
	// text string (major type 3 + length). The Base58 string is 46 chars,
	// so the encoding is 0x78 0x2e <46 bytes>.
	pid1, ok := em.EncodeResults["peer_id.1"]
	if !ok {
		t.Fatal("missing peer_id.1")
	}
	if pid1[0] != 0x78 || pid1[1] != 0x2e {
		t.Errorf("peer_id.1 header: got %02x%02x want 782e (tstr-46)", pid1[0], pid1[1])
	}
	if len(pid1) != 2+46 {
		t.Errorf("peer_id.1 len: got %d want 48", len(pid1))
	}

	// signature.1 — Ed25519 sig over canonical entity bytes is exactly
	// 64 bytes; the emission stores it raw (the canonical field in the
	// .diag holds the 64-byte sig directly, not an ECF-wrapped form).
	sig1, ok := em.EncodeResults["signature.1"]
	if !ok {
		t.Fatal("missing signature.1")
	}
	if len(sig1) != ed25519SigSize {
		t.Errorf("signature.1 len: got %d want %d", len(sig1), ed25519SigSize)
	}

	// All decode_reject vectors must be rejected, and each rejection must
	// carry the spec error code (tag_reject → non_canonical_ecf, §6.3).
	for id, rejected := range em.DecodeResults {
		if !rejected {
			t.Errorf("%s: accepted non-canonical input (should reject)", id)
			continue
		}
		code, ok := em.DecodeCodes[id]
		if !ok {
			t.Errorf("%s: rejected but no decode_codes entry emitted", id)
			continue
		}
		if strings.HasPrefix(id, "tag_reject.") && code != "non_canonical_ecf" {
			t.Errorf("%s: code = %q, want non_canonical_ecf", id, code)
		}
	}
}

const ed25519SigSize = 64
