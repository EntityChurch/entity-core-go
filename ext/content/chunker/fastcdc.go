package chunker

import "math/bits"

// FastCDCParams holds the derived FastCDC parameters per §3.6.2.
type FastCDCParams struct {
	Target uint64
	Min    uint64
	Max    uint64
	MaskS  uint64
	MaskL  uint64
}

// DeriveFastCDC derives the FastCDC parameters from the target chunk size
// per §3.6.2:
//
//	min_size = target / 4
//	max_size = target * 2
//	bits     = floor(log2(target))
//	mask_s   = (1 << (bits + NC)) - 1   (NC = 2)
//	mask_l   = (1 << (bits - NC)) - 1
//
// For the default 4 MiB target, the spec's expected values are:
// min=1 MiB, max=8 MiB, mask_s=0x00FFFFFF (24 bits), mask_l=0x000FFFFF (20 bits).
func DeriveFastCDC(target uint64) FastCDCParams {
	if target == 0 {
		return FastCDCParams{}
	}
	logBits := uint64(bits.Len64(target) - 1)
	const nc = uint64(2)
	return FastCDCParams{
		Target: target,
		Min:    target / 4,
		Max:    target * 2,
		MaskS:  (uint64(1) << (logBits + nc)) - 1,
		MaskL:  (uint64(1) << (logBits - nc)) - 1,
	}
}

// ChunkFastCDC applies the §3.6.3 FastCDC boundary algorithm and returns
// the resulting chunk byte ranges. Empty input → zero ranges. Input of
// length ≤ min_size is emitted as a single range (the final-piece branch).
//
// Implementations producing chunking: 1 (FastCDC/NC2) blobs MUST produce
// byte-identical chunk boundaries for the same input + target_size.
func ChunkFastCDC(data []byte, target uint64) []ChunkRange {
	if len(data) == 0 {
		return nil
	}
	p := DeriveFastCDC(target)
	var out []ChunkRange
	offset := uint64(0)
	n := uint64(len(data))
	for offset < n {
		var end uint64
		remaining := n - offset
		if remaining <= p.Min {
			end = offset + remaining
		} else {
			end = findBoundary(data, offset, p)
		}
		out = append(out, ChunkRange{Start: offset, End: end})
		offset = end
	}
	return out
}

// findBoundary implements the two-phase normalized scan from §3.6.3.
// Returns the boundary index (an exclusive end offset). The fingerprint is
// updated starting at offset+min_size — the min_size skip avoids producing
// undersized chunks.
func findBoundary(data []byte, offset uint64, p FastCDCParams) uint64 {
	n := uint64(len(data))
	fp := uint64(0)
	i := offset + p.Min

	// Phase 1: harder mask (below target — fewer boundaries, push toward target).
	limit1 := offset + p.Target
	if limit1 > n {
		limit1 = n
	}
	for i < limit1 {
		fp = (fp << 1) + GearTable[data[i]]
		if (fp & p.MaskS) == 0 {
			return i + 1
		}
		i++
	}

	// Phase 2: easier mask (above target — more boundaries, pull back toward target).
	limit2 := offset + p.Max
	if limit2 > n {
		limit2 = n
	}
	for i < limit2 {
		fp = (fp << 1) + GearTable[data[i]]
		if (fp & p.MaskL) == 0 {
			return i + 1
		}
		i++
	}

	// Reached max_size (or end of data) — forced boundary.
	return i
}
