package chunker

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// This file is a broad coverage sweep for the FastCDC chunker:
//
//   - Size sweep: empty, 1 B, just below / at / just above each significant
//     boundary (MIN_CHUNK_SIZE, derived min_size, target_size, max_size, and
//     beyond). Pinned at a small 256 KiB target so the sweep stays fast
//     while still exercising the two-phase scan and the forced boundary.
//
//   - Content patterns: degenerate cases (zeros, 0xFF, single-byte
//     repeats), structured cyclic input, multiple pseudo-random seeds, and
//     a mixed input that concatenates structured + random regions.
//
//   - Target sweep: 256 KiB, 1 MiB, 4 MiB targets. We don't go larger than
//     4 MiB targets in this file (the existing edit-stability test in
//     fastcdc_test.go does the 16 MiB / 1 MiB target case).
//
//   - Property assertions (across the matrix):
//       (a) chunks fully cover the input — no gaps, no overlaps;
//       (b) non-final chunks satisfy min < len ≤ max (§3.6.3 invariant);
//       (c) the final chunk is non-empty and ≤ max;
//       (d) the reassembled bytes equal the input.
//
//   - Edit stability sweep: 1-byte insertion at start, mid-stream, and
//     near end. Documents the §3.6.5 vector across positions, not just
//     the offset already covered in fastcdc_test.go.
//
//   - Determinism across many invocations.
//
// Tests stay within ~32 MiB of total allocation and complete in seconds.

// makePattern produces deterministic test inputs by category.
func makePattern(kind string, size int) []byte {
	out := make([]byte, size)
	switch kind {
	case "zeros":
		// already zeroed
	case "ones":
		for i := range out {
			out[i] = 0xFF
		}
	case "single_byte_0x42":
		for i := range out {
			out[i] = 0x42
		}
	case "cyclic_256":
		for i := range out {
			out[i] = byte(i)
		}
	case "rand_seed_1":
		rand.New(rand.NewSource(1)).Read(out)
	case "rand_seed_42":
		rand.New(rand.NewSource(42)).Read(out)
	case "rand_seed_0xC0FFEE":
		rand.New(rand.NewSource(0xC0FFEE)).Read(out)
	case "structured_then_random":
		// First half: cyclic 0..255; second half: pseudo-random.
		for i := 0; i < size/2; i++ {
			out[i] = byte(i)
		}
		rand.New(rand.NewSource(0xBADF00D)).Read(out[size/2:])
	default:
		panic("unknown pattern: " + kind)
	}
	return out
}

// assertCoverage checks (a) gap-free + overlap-free coverage and (d)
// reassembly equality.
func assertCoverage(t *testing.T, label string, data []byte, ranges []ChunkRange) {
	t.Helper()
	if len(data) == 0 {
		if ranges != nil {
			t.Errorf("[%s] empty input produced %d ranges, want nil", label, len(ranges))
		}
		return
	}
	if len(ranges) == 0 {
		t.Fatalf("[%s] non-empty input produced zero ranges (len=%d)", label, len(data))
	}
	if ranges[0].Start != 0 {
		t.Errorf("[%s] first range Start = %d, want 0", label, ranges[0].Start)
	}
	if last := ranges[len(ranges)-1]; last.End != uint64(len(data)) {
		t.Errorf("[%s] last range End = %d, want %d", label, last.End, len(data))
	}
	for i := 1; i < len(ranges); i++ {
		if ranges[i].Start != ranges[i-1].End {
			t.Errorf("[%s] gap or overlap at boundary %d: prev.End=%d next.Start=%d",
				label, i, ranges[i-1].End, ranges[i].Start)
		}
	}

	// Reassembly equality.
	var buf bytes.Buffer
	buf.Grow(len(data))
	for _, r := range ranges {
		buf.Write(data[r.Start:r.End])
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Errorf("[%s] reassembled bytes do not match input", label)
	}
}

// assertSizeInvariants checks §3.6.3 chunk-size invariants:
//
//	non-final chunks: min < len ≤ max
//	final chunk:      0 < len ≤ max
//
// The strict-greater-than on min for non-final chunks comes from the
// algorithm: a boundary in phase 1/phase 2 is returned as i+1 with
// i ≥ offset+min, so a non-final chunk has length ≥ min+1. A forced
// boundary at max produces a chunk of length exactly max.
func assertSizeInvariants(t *testing.T, label string, ranges []ChunkRange, min, max uint64) {
	t.Helper()
	for i, r := range ranges {
		length := r.End - r.Start
		if length == 0 {
			t.Errorf("[%s] chunk[%d] has zero length", label, i)
			continue
		}
		if length > max {
			t.Errorf("[%s] chunk[%d] length %d > max %d", label, i, length, max)
		}
		if i < len(ranges)-1 && length <= min {
			t.Errorf("[%s] non-final chunk[%d] length %d ≤ min %d (algorithm invariant: non-final chunks are strictly above min)",
				label, i, length, min)
		}
	}
}

// TestSizeSweep — boundary cases around the FastCDC parameter table at a
// 256 KiB target (min=64 KiB, max=512 KiB). Tests every significant size
// boundary: empty, 1 B, just below / at / just above min_size, target,
// and max_size, plus beyond-max sizes that force the algorithm to take
// multiple chunks.
func TestSizeSweep(t *testing.T) {
	const target = uint64(256 * 1024) // 256 KiB
	p := DeriveFastCDC(target)
	// Sanity: at 256 KiB target, min=64 KiB, max=512 KiB.
	if p.Min != 64*1024 || p.Max != 512*1024 {
		t.Fatalf("256 KiB target derives min=%d max=%d; want min=65536 max=524288", p.Min, p.Max)
	}

	sizes := []uint64{
		0,
		1,
		1024,             // 1 KiB
		32 * 1024,        // 32 KiB — below min
		p.Min - 1,        // 65,535 — just below min
		p.Min,            // 65,536 — exactly min (the §10.1 MIN_CHUNK_SIZE)
		p.Min + 1,        // 65,537 — just above min
		128 * 1024,       // 128 KiB — between min and target
		p.Target - 1,     // just below target
		p.Target,         // exactly target
		p.Target + 1,     // just above target
		384 * 1024,       // 384 KiB — between target and max
		p.Max - 1,        // just below max — single-chunk forced boundary
		p.Max,            // exactly max
		p.Max + 1,        // just above max — forces at least 2 chunks
		2 * p.Target,     // 512 KiB
		4 * p.Target,     // 1 MiB
		8 * p.Target,     // 2 MiB
	}

	patterns := []string{"rand_seed_1", "cyclic_256"}

	for _, size := range sizes {
		for _, pattern := range patterns {
			label := fmt.Sprintf("size=%d/pattern=%s", size, pattern)
			data := makePattern(pattern, int(size))
			ranges := ChunkFastCDC(data, target)
			assertCoverage(t, label, data, ranges)
			if size > 0 {
				assertSizeInvariants(t, label, ranges, p.Min, p.Max)
			}
		}
	}
}

// TestDegenerateContent — degenerate fingerprint patterns. Constant-byte
// inputs (zeros, ones, single-byte repeats) produce a constant
// fingerprint evolution; mask matches happen at deterministic offsets or
// not at all, exercising the forced-boundary branch. The algorithm must
// still produce a complete, gap-free chunking with valid size invariants.
func TestDegenerateContent(t *testing.T) {
	const target = uint64(1 * 1024 * 1024) // 1 MiB target
	p := DeriveFastCDC(target)

	// 4 MiB of degenerate input — large enough to require multiple
	// max-sized chunks if mask matches never trigger.
	const size = 4 * 1024 * 1024
	patterns := []string{"zeros", "ones", "single_byte_0x42"}

	for _, pattern := range patterns {
		label := fmt.Sprintf("degenerate/%s", pattern)
		data := makePattern(pattern, size)
		ranges := ChunkFastCDC(data, target)
		assertCoverage(t, label, data, ranges)
		assertSizeInvariants(t, label, ranges, p.Min, p.Max)
	}
}

// TestMixedContent — structured prefix followed by pseudo-random suffix.
// Real-world content (file headers + payloads, archives, container
// formats) often has this shape. The chunker must transition cleanly
// across the boundary without producing pathological chunks.
func TestMixedContent(t *testing.T) {
	const target = uint64(1 * 1024 * 1024)
	p := DeriveFastCDC(target)
	data := makePattern("structured_then_random", 8*1024*1024)
	ranges := ChunkFastCDC(data, target)
	assertCoverage(t, "mixed", data, ranges)
	assertSizeInvariants(t, "mixed", ranges, p.Min, p.Max)
}

// TestTargetSweep — same input across 256 KiB / 1 MiB / 4 MiB targets.
// Different targets produce different boundaries (no cross-target dedup
// — §2.1), but each independently satisfies coverage + size invariants.
func TestTargetSweep(t *testing.T) {
	data := makePattern("rand_seed_0xC0FFEE", 8*1024*1024)
	targets := []uint64{
		256 * 1024,        // 256 KiB
		1 * 1024 * 1024,   // 1 MiB
		4 * 1024 * 1024,   // 4 MiB (default)
	}
	for _, target := range targets {
		p := DeriveFastCDC(target)
		label := fmt.Sprintf("target=%dKiB", target/1024)
		ranges := ChunkFastCDC(data, target)
		assertCoverage(t, label, data, ranges)
		assertSizeInvariants(t, label, ranges, p.Min, p.Max)

		// Per-target sanity: average chunk size is in the same order of
		// magnitude as target. Tight bound: avg in [min/2, max].
		if len(ranges) == 0 {
			continue
		}
		avg := uint64(len(data)) / uint64(len(ranges))
		if avg < p.Min/2 || avg > p.Max {
			t.Errorf("[%s] average chunk size %d outside [min/2=%d, max=%d]",
				label, avg, p.Min/2, p.Max)
		}
	}
}

// TestEditStabilitySweep — 1-byte insertion at three positions (start,
// middle, end). Expands the §3.6.5 vector beyond the single offset in
// fastcdc_test.go. At each position, the chunks BEFORE the edit retain
// their identity exactly; chunks AFTER eventually realign. Overall
// survival floor: ≥ 40% (looser than the mid-stream test's 50% because
// edits near the start invalidate more chunks).
func TestEditStabilitySweep(t *testing.T) {
	const size = 8 * 1024 * 1024
	const target = uint64(512 * 1024) // smaller target for more chunks
	original := makePattern("rand_seed_1", size)

	positions := map[string]int{
		"start":   1024,             // 1 KiB in
		"mid":     size / 2,         // middle
		"end":     size - 256*1024,  // 256 KiB from end
	}

	origRanges := ChunkFastCDC(original, target)
	origPayloads := make(map[string]struct{}, len(origRanges))
	for _, r := range origRanges {
		origPayloads[string(original[r.Start:r.End])] = struct{}{}
	}

	for label, insertAt := range positions {
		edited := make([]byte, size+1)
		copy(edited[:insertAt], original[:insertAt])
		edited[insertAt] = 0xAB
		copy(edited[insertAt+1:], original[insertAt:])

		editRanges := ChunkFastCDC(edited, target)
		survived := 0
		for _, r := range editRanges {
			if _, ok := origPayloads[string(edited[r.Start:r.End])]; ok {
				survived++
			}
		}
		floor := (len(origRanges) * 40) / 100
		if survived < floor {
			t.Errorf("edit-stability/%s @ offset %d: %d/%d chunks survived (floor %d)",
				label, insertAt, survived, len(origRanges), floor)
		}
	}
}

// TestSingleByteModificationStability — replace one byte in place (no
// length change). The chunker should rebuild only the chunk containing
// the modified byte (and possibly a few chunks downstream until the
// fingerprint state realigns). Total invalidated chunks are bounded.
func TestSingleByteModificationStability(t *testing.T) {
	const size = 4 * 1024 * 1024
	const target = uint64(512 * 1024)
	original := makePattern("rand_seed_42", size)
	modified := make([]byte, size)
	copy(modified, original)
	modified[size/2] ^= 0xFF

	origRanges := ChunkFastCDC(original, target)
	modRanges := ChunkFastCDC(modified, target)
	origPayloads := make(map[string]int, len(origRanges))
	for _, r := range origRanges {
		origPayloads[string(original[r.Start:r.End])]++
	}
	survived := 0
	for _, r := range modRanges {
		key := string(modified[r.Start:r.End])
		if origPayloads[key] > 0 {
			survived++
			origPayloads[key]--
		}
	}
	// In-place modification (same length) should leave ≥ 60% of chunks
	// untouched — even more stable than insertion since downstream
	// alignment isn't shifted.
	floor := (len(origRanges) * 60) / 100
	if survived < floor {
		t.Errorf("single-byte modification: %d/%d chunks survived (floor %d)",
			survived, len(origRanges), floor)
	}
}

// TestDeterminismMany — invoke ChunkFastCDC 32 times on the same input
// and assert every result is identical. Catches accidental state leakage
// (a global var being written, an RNG being seeded inside the algorithm,
// etc.).
func TestDeterminismMany(t *testing.T) {
	data := makePattern("rand_seed_1", 4*1024*1024)
	const target = uint64(1 * 1024 * 1024)
	baseline := ChunkFastCDC(data, target)
	for i := 0; i < 32; i++ {
		got := ChunkFastCDC(data, target)
		if len(got) != len(baseline) {
			t.Fatalf("iter %d: len=%d, want %d", i, len(got), len(baseline))
		}
		for j := range got {
			if got[j] != baseline[j] {
				t.Errorf("iter %d: chunk[%d] = %+v, want %+v", i, j, got[j], baseline[j])
			}
		}
	}
}

// TestConcurrentDeterminism — invoke ChunkFastCDC from multiple
// goroutines on independent inputs. The gear table is read-only after
// init; this test would catch a race if anything mutated it.
func TestConcurrentDeterminism(t *testing.T) {
	const target = uint64(1 * 1024 * 1024)
	patterns := []string{"rand_seed_1", "rand_seed_42", "cyclic_256", "rand_seed_0xC0FFEE"}
	results := make([][]ChunkRange, len(patterns))

	// Compute serial baselines.
	for i, p := range patterns {
		results[i] = ChunkFastCDC(makePattern(p, 2*1024*1024), target)
	}

	// Now run concurrently; each goroutine re-chunks its own input and
	// compares against the serial baseline.
	done := make(chan int, len(patterns)*4)
	for round := 0; round < 4; round++ {
		for i, p := range patterns {
			i, p := i, p
			go func() {
				data := makePattern(p, 2*1024*1024)
				got := ChunkFastCDC(data, target)
				if len(got) != len(results[i]) {
					t.Errorf("concurrent/%s: len=%d, want %d", p, len(got), len(results[i]))
				}
				for j := range got {
					if j >= len(results[i]) || got[j] != results[i][j] {
						t.Errorf("concurrent/%s: chunk[%d] differs", p, j)
						return
					}
				}
				done <- 1
			}()
		}
	}
	for range patterns {
		for round := 0; round < 4; round++ {
			<-done
		}
	}
}
