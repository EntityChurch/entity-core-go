package chunker

import "testing"

func TestChunkFixedEmpty(t *testing.T) {
	if got := ChunkFixed(nil, 4*1024*1024); got != nil {
		t.Errorf("ChunkFixed(nil) = %v, want nil", got)
	}
}

func TestChunkFixedZeroSize(t *testing.T) {
	data := make([]byte, 100)
	if got := ChunkFixed(data, 0); got != nil {
		t.Errorf("ChunkFixed(data, 0) = %v, want nil", got)
	}
}

func TestChunkFixedSingleChunk(t *testing.T) {
	data := make([]byte, 100)
	ranges := ChunkFixed(data, 1024)
	if len(ranges) != 1 {
		t.Fatalf("len(ranges) = %d, want 1", len(ranges))
	}
	if ranges[0] != (ChunkRange{Start: 0, End: 100}) {
		t.Errorf("ranges[0] = %+v, want {0, 100}", ranges[0])
	}
}

func TestChunkFixedExactMultiple(t *testing.T) {
	data := make([]byte, 1024)
	ranges := ChunkFixed(data, 256)
	if len(ranges) != 4 {
		t.Fatalf("len(ranges) = %d, want 4", len(ranges))
	}
	for i, r := range ranges {
		want := ChunkRange{Start: uint64(i * 256), End: uint64((i + 1) * 256)}
		if r != want {
			t.Errorf("ranges[%d] = %+v, want %+v", i, r, want)
		}
	}
}

func TestChunkFixedFinalShort(t *testing.T) {
	data := make([]byte, 1000)
	ranges := ChunkFixed(data, 256)
	if len(ranges) != 4 {
		t.Fatalf("len(ranges) = %d, want 4", len(ranges))
	}
	if last := ranges[3]; last != (ChunkRange{Start: 768, End: 1000}) {
		t.Errorf("final range = %+v, want {768, 1000}", last)
	}
}
