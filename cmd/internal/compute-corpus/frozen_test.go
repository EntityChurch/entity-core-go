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
// Re-pinned 2026-08-21 (COMPUTE v3.26 -f): CV-4a + CV-5 moved from held into the
// seeded corner set (350 → 352) once the contained-error carve-out landed in
// materialize().
// Re-pinned again 2026-08-21 (collection-operand §7.2 fix): CV-7a/b/c added
// (352 → 355) after core-rust + core-py caught go answering type_mismatch where a
// consumed collection/sub-collection error must short-circuit — the exact
// discriminator the corpus lacked, which is why go LOCKED three-way with the bug
// live.
// Re-pinned again 2026-08-21 (COMPUTE Corner 1, arch C-8 ruling 172589e): CV-8a/b/c
// added (355 → 358) for the CLOSURE-RESULT dispositions. That freeze encoded fold as
// PROPAGATE — WRONG: arch's ruling makes fold's accumulator CONTAINED (a closure that
// ignores its accumulator recovers), and go had read arch's word "propagates" (=
// threads onward) as short-circuit. rust and py both measured the go peer and caught
// it. The freeze also lacked CV-8d — the fold recovery discriminator — which is why
// the 358 LOCK passed go-on-go with the bug live ("the two readings agree everywhere
// your fixtures live").
// Re-pinned again 2026-08-21 (Corner 1 fold fix + CV-8 reconcile to arch's §6 set,
// 358 → 359): fold now CONTAINS/recovers (ext/compute builtinFold). Vectors realigned
// to arch's numbering — CV-8a map MINTED, CV-8b map VALUE-FORM (the provenance pair,
// newly added), CV-8c filter short-circuit, CV-8d fold ignores-accumulator RECOVERS
// (replacing the old fold-propagates vector, which asserted the defect). The eval-limit
// codes (budget/depth/cascade) remain OUT of the corpus — their disposition is the open
// carve-out routed to arch (spec-issue 2026-08-21-b; depth vs budget/cascade split
// contested cross-impl), held until ruled.
// A fresh SHA is a fresh cross-bless obligation: the 359 set has not yet been
// three-way'd (rust/py locked the 352 set; 355/358 were never three-way'd either).
const goldenCorpusSHA256 = "1844d231ffe52447afa5443336c11b56bd42d3ace02e7fb3e1f1ed0768799927"

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
