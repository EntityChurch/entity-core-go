package chunker

// ChunkRange identifies a chunk's half-open byte range [Start, End) within
// the original input buffer.
type ChunkRange struct {
	Start uint64
	End   uint64
}

// ChunkFixed applies the §3.2 fixed-size algorithm. Splits at every
// chunkSize bytes; the final chunk may be shorter. Empty input → zero
// ranges. chunkSize of zero is invalid and returns nil.
//
// Implementations producing chunking: 0 (fixed-size) blobs MUST produce
// byte-identical chunks for the same input + chunk_size (§3.7 Conformance).
func ChunkFixed(data []byte, chunkSize uint64) []ChunkRange {
	if chunkSize == 0 || len(data) == 0 {
		return nil
	}
	n := uint64(len(data))
	var out []ChunkRange
	for offset := uint64(0); offset < n; offset += chunkSize {
		end := offset + chunkSize
		if end > n {
			end = n
		}
		out = append(out, ChunkRange{Start: offset, End: end})
	}
	return out
}
