package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"go.entitychurch.org/entity-core-go/cmd/internal/diagcodec"
)

// The frozen encoder proof. SEEDS.md §4.3 requires this pair be pinned to a
// FROZEN source and never re-pointed at a moving one:
//
//	"Re-pointing the proof at HEAD would make it assert only that today's
//	 source produces today's output — a tautology wearing the costume of an
//	 encoder proof."
//
// WHY THE INPUT IS NOW COMMITTED. It was not, until 2026-08-13. §4.3 described
// the pair as frozen while the input existed nowhere on disk: it had to be
// reconstructed by hand — `git show 56d4de4:…conformance-vectors-v1.diag` out
// of a repo this one must not run git in, plus the six F16 width corrections
// re-applied from a table in a routing doc. That is not a frozen pair, it is a
// procedure, and a procedure that has to be re-derived from prose before it can
// run is a proof that will eventually not be run at all. It was skipped once
// already for exactly that reason.
//
// So the reconstruction is committed here, and the proof is a test instead of a
// command someone has to remember to invoke with two arguments they must first
// go and find.
//
// THE INPUT MUST NEVER BE REGENERATED FROM THE LIVE CORPUS. Its whole value is
// that it is bytes this encoder did not author: it is the only evidence the
// encoder reproduces output it did not itself produce. Re-deriving it from the
// current `.diag` would make this test pass unconditionally and prove nothing.
const (
	legacyDiag = "testdata/legacy-56d4de4-f16-corrected.diag"

	// The June artifact, as it shipped. entity-core-protocol `56d4de4`,
	// 9236 B.
	legacySHA = "8e7c5232f64bee83d628679f930c771e4e49f2f1e37d19e41e0d7838e31f982e"

	legacySize = 9236
)

// TestEncoderReproducesPinnedLegacyArtifact is the gate on every re-pin. Before
// the corpus registry's ExpectedSHA may be moved to whatever this encoder now
// emits, this must be green — otherwise a build tool is minting its own oracle:
// whatever bytes it produced would become "the corpus," and a divergence from
// the hand-built original would be indistinguishable from a legitimate re-stamp.
func TestEncoderReproducesPinnedLegacyArtifact(t *testing.T) {
	src, err := os.ReadFile(legacyDiag)
	if err != nil {
		t.Fatalf("the frozen proof input is missing: %v\n"+
			"It must not be regenerated from the live corpus — see the comment above.", err)
	}

	val, err := diagcodec.ParseDiag(string(src))
	if err != nil {
		t.Fatalf("parse frozen .diag: %v", err)
	}
	arr, ok := val.([]interface{})
	if !ok {
		t.Fatalf("frozen .diag top-level is %T, want an array of vectors", val)
	}
	got, err := diagcodec.EncodeCanonical(arr)
	if err != nil {
		t.Fatalf("encode frozen .diag: %v", err)
	}

	if len(got) != legacySize {
		t.Errorf("re-encoded %d B, want %d B", len(got), legacySize)
	}
	sum := sha256.Sum256(got)
	if h := hex.EncodeToString(sum[:]); h != legacySHA {
		t.Fatalf("ENCODER MISMATCH\n  got  %s\n  want %s\n\n"+
			"This encoder no longer reproduces the pinned June artifact, so nothing it\n"+
			"produces can be trusted as the corpus. Do NOT re-pin the registry to its\n"+
			"current output — find what changed in the encoder first.", h, legacySHA)
	}
}

// The six F16 input-width corrections are part of the frozen input, and a
// silent revert of any of them would change the bytes without changing the
// story. Asserted structurally so a failure names the width rather than only
// the digest.
func TestFrozenProofInputCarriesF16Widths(t *testing.T) {
	src, err := os.ReadFile(legacyDiag)
	if err != nil {
		t.Fatalf("read frozen .diag: %v", err)
	}
	val, err := diagcodec.ParseDiag(string(src))
	if err != nil {
		t.Fatalf("parse frozen .diag: %v", err)
	}
	arr, _ := val.([]interface{})

	// The preflight the builder runs on live sources applies equally here: if
	// the frozen input ever carried a pre-F16 width, it would be reproducing
	// the wrong artifact for the right digest.
	var problems int
	for _, v := range arr {
		m, ok := v.(map[interface{}]interface{})
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		idIsEd448 := len(id) > 15 && id[:15] == "key-type-ed448."
		walkMaps(m, func(mm map[interface{}]interface{}) {
			seed, hasSeed := mm["secret_seed"].([]byte)
			kt, _ := mm["key_type"].(string)
			if hasSeed && (kt == "ed448" || (kt == "" && idIsEd448)) && len(seed) != 57 {
				t.Errorf("%s: ed448 secret_seed is %d B, want 57 (RFC 8032 SeedSize; F16)", id, len(seed))
				problems++
			}
			if pub, ok := mm["public_key"].([]byte); ok && len(pub) == 63 {
				t.Errorf("%s: public_key is 63 B, want 64 (v7.66 §4.2 experimental-test; F16)", id)
				problems++
			}
		})
		if id == "key-type-ed448.1.pubkey" {
			if in, ok := m["input"].([]byte); ok && len(in) != 57 {
				t.Errorf("%s: input (ed448 seed) is %d B, want 57 (F16)", id, len(in))
				problems++
			}
		}
	}
	if problems > 0 {
		t.Logf("the frozen proof input has been altered — it is meant to be immutable")
	}
}
