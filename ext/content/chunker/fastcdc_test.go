package chunker

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"testing"
)

// TestGearTableFirst16 — sanity check on §3.6.1 derivation. The first 16
// gear-table entries match an independent recomputation from the formula
// (this is the cross-impl conformance vector surface from §3.6.5; the
// formula is the source of truth, so a divergence here means our init()
// is broken, not the spec). This test guards against bit-twiddling
// regressions.
func TestGearTableFirst16(t *testing.T) {
	for i := 0; i < 16; i++ {
		input := append([]byte("FastCDC"), byte(i))
		sum := sha256.Sum256(input)
		want := binary.LittleEndian.Uint64(sum[0:8])
		if got := GearTable[i]; got != want {
			t.Errorf("GearTable[%d] = %#016x, want %#016x", i, got, want)
		}
	}
}

// TestDeriveFastCDCParams4MiB — §3.6.2 parameter derivation at the 4 MiB
// target. The expected values are pinned in the spec table:
// min=1 MiB, max=8 MiB, mask_s=0x00FFFFFF, mask_l=0x000FFFFF.
// Retained post-v3.6 A2 cutover: existing 4 MiB-chunked blobs remain valid
// per §5.5; the algorithm still applies at the 4 MiB target.
func TestDeriveFastCDCParams4MiB(t *testing.T) {
	p := DeriveFastCDC(4 * 1024 * 1024)

	if p.Target != 4*1024*1024 {
		t.Errorf("Target = %d, want %d", p.Target, 4*1024*1024)
	}
	if p.Min != 1*1024*1024 {
		t.Errorf("Min = %d, want %d", p.Min, 1*1024*1024)
	}
	if p.Max != 8*1024*1024 {
		t.Errorf("Max = %d, want %d", p.Max, 8*1024*1024)
	}
	if p.MaskS != 0x00FFFFFF {
		t.Errorf("MaskS = %#x, want %#x", p.MaskS, 0x00FFFFFF)
	}
	if p.MaskL != 0x000FFFFF {
		t.Errorf("MaskL = %#x, want %#x", p.MaskL, 0x000FFFFF)
	}
}

// TestDeriveFastCDCParams1MiB — §3.6.2 parameter derivation at the v3.6
// default 1 MiB target. Pins min=256 KiB, max=2 MiB, mask_s=0x003FFFFF,
// mask_l=0x0003FFFF.
func TestDeriveFastCDCParams1MiB(t *testing.T) {
	p := DeriveFastCDC(1 * 1024 * 1024)

	if p.Target != 1*1024*1024 {
		t.Errorf("Target = %d, want %d", p.Target, 1*1024*1024)
	}
	if p.Min != 256*1024 {
		t.Errorf("Min = %d, want %d", p.Min, 256*1024)
	}
	if p.Max != 2*1024*1024 {
		t.Errorf("Max = %d, want %d", p.Max, 2*1024*1024)
	}
	if p.MaskS != 0x003FFFFF {
		t.Errorf("MaskS = %#x, want %#x", p.MaskS, 0x003FFFFF)
	}
	if p.MaskL != 0x0003FFFF {
		t.Errorf("MaskL = %#x, want %#x", p.MaskL, 0x0003FFFF)
	}
}

// TestChunkFastCDCEmpty — empty input → zero ranges.
func TestChunkFastCDCEmpty(t *testing.T) {
	if got := ChunkFastCDC(nil, 4*1024*1024); got != nil {
		t.Errorf("ChunkFastCDC(nil) = %v, want nil", got)
	}
}

// TestChunkFastCDCSingleChunk — input ≤ min_size → single range covering
// the whole input (the final-piece branch).
func TestChunkFastCDCSingleChunk(t *testing.T) {
	data := make([]byte, 100*1024) // 100 KiB, well below 1 MiB min
	ranges := ChunkFastCDC(data, 4*1024*1024)
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if ranges[0].Start != 0 || ranges[0].End != uint64(len(data)) {
		t.Errorf("range = %+v, want {0, %d}", ranges[0], len(data))
	}
}

// TestChunkFastCDCCoverage — chunks fully cover the input with no gaps or
// overlaps. Property guard for any input size + target.
func TestChunkFastCDCCoverage(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC047))
	data := make([]byte, 16*1024*1024) // 16 MiB
	rng.Read(data)

	ranges := ChunkFastCDC(data, 4*1024*1024)
	if len(ranges) == 0 {
		t.Fatal("expected at least one range")
	}

	if ranges[0].Start != 0 {
		t.Errorf("first range Start = %d, want 0", ranges[0].Start)
	}
	if last := ranges[len(ranges)-1]; last.End != uint64(len(data)) {
		t.Errorf("last range End = %d, want %d", last.End, len(data))
	}
	for i := 1; i < len(ranges); i++ {
		if ranges[i].Start != ranges[i-1].End {
			t.Errorf("gap or overlap at boundary %d: prev.End=%d next.Start=%d",
				i, ranges[i-1].End, ranges[i].Start)
		}
	}
}

// TestChunkFastCDCDeterminism — same input + target → same boundaries.
// This is the cross-impl conformance gate at the Go-vs-Go level (the
// cross-impl-vs-Rust/Python gate runs in cmd/internal/validate at T5).
func TestChunkFastCDCDeterminism(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5EED))
	data := make([]byte, 8*1024*1024)
	rng.Read(data)

	a := ChunkFastCDC(data, 4*1024*1024)
	b := ChunkFastCDC(data, 4*1024*1024)

	if len(a) != len(b) {
		t.Fatalf("non-deterministic chunk count: a=%d b=%d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("non-deterministic boundary at %d: a=%+v b=%+v", i, a[i], b[i])
		}
	}
}

// TestChunkFastCDCEditStability — the load-bearing cross-impl vector
// (§3.6.5). A 1-byte insertion mid-stream shifts only the affected region.
// Chunks before the insertion point retain their boundaries; chunks after
// the insertion eventually realign on a content-defined boundary. At least
// half the original chunks (by count) should survive — well above what
// fixed-size chunking achieves (which is zero post-insertion).
func TestChunkFastCDCEditStability(t *testing.T) {
	rng := rand.New(rand.NewSource(0xED17))
	const size = 16 * 1024 * 1024 // 16 MiB
	original := make([]byte, size)
	rng.Read(original)

	// Insert one byte at offset 4 MiB (middle of input).
	const insertAt = 4 * 1024 * 1024
	edited := make([]byte, size+1)
	copy(edited[:insertAt], original[:insertAt])
	edited[insertAt] = 0xAB
	copy(edited[insertAt+1:], original[insertAt:])

	target := uint64(1 * 1024 * 1024) // smaller target for more chunks
	origRanges := ChunkFastCDC(original, target)
	editRanges := ChunkFastCDC(edited, target)

	// Collect chunk byte contents and check overlap. A surviving chunk is
	// one whose byte payload matches between the two chunkings.
	origPayloads := make(map[string]int, len(origRanges))
	for _, r := range origRanges {
		origPayloads[string(original[r.Start:r.End])]++
	}
	survived := 0
	for _, r := range editRanges {
		if origPayloads[string(edited[r.Start:r.End])] > 0 {
			survived++
			origPayloads[string(edited[r.Start:r.End])]--
		}
	}

	// Lower bound: at least 50% of original chunks survive. Fixed-size
	// chunking would survive only chunks fully before the insertion point
	// — ~25% in this case. FastCDC should do much better.
	floor := len(origRanges) / 2
	if survived < floor {
		t.Errorf("edit-stability: %d/%d chunks survived (floor %d) — "+
			"boundaries are not content-defined",
			survived, len(origRanges), floor)
	}
}
