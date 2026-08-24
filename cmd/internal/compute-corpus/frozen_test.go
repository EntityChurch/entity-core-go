package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// goldenCorpusSHA256 pins the frozen compute-conformance corpus (§7c.4(5)(e)).
// This is the SHA "beside the bytes" — the mechanical guard C-8 was filed for:
// TestCorpusIsReproducible only proves same-process determinism (two builds in
// one run agree), so a gen.go / builder / vector change that SHIFTS the corpus
// passes it (both builds shift together). Nothing caught that the corpus had
// already drifted 330 → 343 since the 2026-07-23 cross-bless; the SHA that
// would have caught it lived in a spec header, not in a test. It does now.
//
// If this constant needs updating, the corpus changed: the old value described
// a DIFFERENT set of inputs, so re-pin here AND re-run the three-way cross-bless
// — a fresh SHA invalidates the prior emissions.
const goldenCorpusSHA256 = "c1fb657841fd5a3ec67530b9d60573a714b7fad7a310207bfa32b1d4eda9f6e6"

const frozenCorpusPath = "testdata/compute-corpus-v1.cbor"

// TestFrozenCorpusSHAPinned is the drift guard: (1) regenerating the corpus from
// the seed MUST hash to the pinned SHA — so any generator change that shifts the
// bytes fails here, deliberately; and (2) the committed frozen artifact MUST
// match that same SHA — so the bytes on disk are the bytes the SHA names.
func TestFrozenCorpusSHAPinned(t *testing.T) {
	c := buildTestCorpusProfile(t, profileInproc)
	raw, sum, err := encodeCorpus(c)
	if err != nil {
		t.Fatalf("encode corpus: %v", err)
	}
	got := hex.EncodeToString(sum[:])
	if got != goldenCorpusSHA256 {
		t.Fatalf("corpus SHA drifted: got %s (%d vectors, %d bytes), pinned %s\n"+
			"a generator/builder/vector change shifted the frozen corpus. If deliberate:\n"+
			"  1. re-freeze:  go run ./cmd/internal/compute-corpus generate --out %s\n"+
			"  2. re-pin goldenCorpusSHA256 to the new value\n"+
			"  3. re-run the three-way cross-bless — the old SHA meant different inputs",
			got, len(c.Vectors), len(raw), goldenCorpusSHA256, frozenCorpusPath)
	}

	frozen, err := os.ReadFile(frozenCorpusPath)
	if err != nil {
		t.Fatalf("read frozen artifact %s: %v", frozenCorpusPath, err)
	}
	fsum := sha256.Sum256(frozen)
	if fgot := hex.EncodeToString(fsum[:]); fgot != goldenCorpusSHA256 {
		t.Fatalf("committed %s SHA %s != pinned %s — the frozen bytes are stale; re-run:\n"+
			"  go run ./cmd/internal/compute-corpus generate --out %s",
			frozenCorpusPath, fgot, goldenCorpusSHA256, frozenCorpusPath)
	}
}
