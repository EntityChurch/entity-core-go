package validate

// FastCDC / ECF-byte-equality library self-tests.
//
// These were previously entries in the over-the-wire `content` validate
// category, but they exercise THIS repo's chunker/encoder libraries
// (ext/content/chunker, core/types ECF encode) — never the peer under
// validation. Running them in -category content reported Go-library
// results into a *peer's* conformance report (e.g. validating a Rust peer
// would still show "fastcdc_gear_table_first16 PASS" about Go). Per the
// validate-peer audit (S-series, "content.go library self-tests split
// out") they live here as ordinary Go unit tests.
//
// NOTE: the FastCDC gear table + the edit-stability vector ARE genuine
// cross-impl conformance surfaces — but the spec-correct place to assert
// them across impls is the offline conformance corpus (a vector) or an
// over-the-wire ingest check, NOT a Go-library call in the peer category.
// Promoting them is tracked as de-Go-coupling follow-up (GUIDE-CONFORMANCE
// §8); these tests keep Go's own derivation pinned in the meantime.

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"
)

func TestFastCDCGearTableFirst16(t *testing.T) {
	for i := 0; i < 16; i++ {
		input := append([]byte("FastCDC"), byte(i))
		sum := sha256.Sum256(input)
		want := binary.LittleEndian.Uint64(sum[0:8])
		if got := chunker.GearTable[i]; got != want {
			t.Errorf("gear[%d] = %#016x, want %#016x (CONTENT §3.6.1)", i, got, want)
		}
	}
}

func TestFastCDCParams4MiB(t *testing.T) {
	p := chunker.DeriveFastCDC(4 * 1024 * 1024)
	if p.Min != 1*1024*1024 || p.Max != 8*1024*1024 || p.MaskS != 0x00FFFFFF || p.MaskL != 0x000FFFFF {
		t.Errorf("derive(4 MiB) = {min=%d max=%d mask_s=%#x mask_l=%#x}; want §3.6.2 pinned values",
			p.Min, p.Max, p.MaskS, p.MaskL)
	}
}

func TestFastCDCParams1MiB(t *testing.T) {
	p := chunker.DeriveFastCDC(1 * 1024 * 1024)
	if p.Min != 256*1024 || p.Max != 2*1024*1024 || p.MaskS != 0x003FFFFF || p.MaskL != 0x0003FFFF {
		t.Errorf("derive(1 MiB) = {min=%d max=%d mask_s=%#x mask_l=%#x}; want §3.6.2 pinned values (v3.6 A2 default)",
			p.Min, p.Max, p.MaskS, p.MaskL)
	}
}

func TestFastCDCDeterminism(t *testing.T) {
	data := canonicalRandomInput(0x5EED, 8*1024*1024)
	a := chunker.ChunkFastCDC(data, 4*1024*1024)
	b := chunker.ChunkFastCDC(data, 4*1024*1024)
	if len(a) == 0 {
		t.Fatal("FastCDC produced zero ranges over 8 MiB input")
	}
	if !rangesEqual(a, b) {
		t.Error("FastCDC non-deterministic over identical input + target (CONTENT §3.6.3)")
	}
}

func TestFastCDCEditStability(t *testing.T) {
	const size = 16 * 1024 * 1024
	const insertAt = 4 * 1024 * 1024
	original := canonicalRandomInput(0xED17, size)
	edited := make([]byte, size+1)
	copy(edited[:insertAt], original[:insertAt])
	edited[insertAt] = 0xAB
	copy(edited[insertAt+1:], original[insertAt:])

	target := uint64(1 * 1024 * 1024)
	origRanges := chunker.ChunkFastCDC(original, target)
	editRanges := chunker.ChunkFastCDC(edited, target)
	if len(origRanges) == 0 {
		t.Fatal("FastCDC produced zero ranges over original input")
	}
	origPayloads := make(map[string]int, len(origRanges))
	for _, rg := range origRanges {
		origPayloads[string(original[rg.Start:rg.End])]++
	}
	survived := 0
	for _, rg := range editRanges {
		key := string(edited[rg.Start:rg.End])
		if origPayloads[key] > 0 {
			survived++
			origPayloads[key]--
		}
	}
	floor := len(origRanges) / 2
	if survived < floor {
		t.Errorf("%d/%d chunks survived 1-byte insertion (floor %d) — boundaries not content-defined (CONTENT §3.6.5)",
			survived, len(origRanges), floor)
	}
}

func TestContentECFByteEqualityChunk(t *testing.T) {
	payload := []byte("hello, fastcdc")
	ent1, err := types.ContentChunkData{Payload: payload}.ToEntity()
	if err != nil {
		t.Fatal("encode chunk: " + err.Error())
	}
	ent2, err := types.ContentChunkData{Payload: payload}.ToEntity()
	if err != nil {
		t.Fatal("re-encode chunk: " + err.Error())
	}
	if ent1.ContentHash != ent2.ContentHash {
		t.Error("chunk encode is non-deterministic — ECF byte-equality broken (CONTENT §3.7)")
	}
}

func TestContentECFByteEqualityBlob(t *testing.T) {
	chunkEnt, err := types.ContentChunkData{Payload: []byte("abc")}.ToEntity()
	if err != nil {
		t.Fatal("encode chunk: " + err.Error())
	}
	blob := types.ContentBlobData{
		TotalSize: 3,
		ChunkSize: 4 * 1024 * 1024,
		Chunking:  types.ChunkingFastCDC,
		Chunks:    []hash.Hash{chunkEnt.ContentHash},
	}
	ent1, err := blob.ToEntity()
	if err != nil {
		t.Fatal("encode blob: " + err.Error())
	}
	ent2, err := blob.ToEntity()
	if err != nil {
		t.Fatal("re-encode blob: " + err.Error())
	}
	if ent1.ContentHash != ent2.ContentHash {
		t.Error("blob encode is non-deterministic — ECF byte-equality broken (CONTENT §3.7)")
	}
}

// --- helpers (moved from content.go with the self-tests) ---

func rangesEqual(a, b []chunker.ChunkRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func canonicalRandomInput(seed int64, size int) []byte {
	rng := rand.New(rand.NewSource(seed))
	buf := make([]byte, size)
	rng.Read(buf)
	return buf
}
