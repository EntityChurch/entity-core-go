package content

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"
)

// BuildBlob constructs the blob + chunk entities for the given input
// bytes using the supplied chunk ranges (produced by chunker.ChunkFixed
// or chunker.ChunkFastCDC). Returns the blob entity and the chunk
// entities in iteration order; callers persist them via ContentStore.Put
// (typically through IngestBlob which does both at once).
//
// chunking identifies the algorithm used (§2.1): ChunkingFixed (0) or
// ChunkingFastCDC (1). chunkSize is the algorithm's target/configured
// chunk size — recorded in the blob's chunk_size field. For FastCDC, the
// effective chunk sizes vary; chunkSize is the target_size from §3.6.2.
func BuildBlob(
	data []byte,
	ranges []chunker.ChunkRange,
	chunking uint64,
	chunkSize uint64,
) (entity.Entity, []entity.Entity, error) {
	chunkEntities := make([]entity.Entity, 0, len(ranges))
	chunkHashes := make([]hash.Hash, 0, len(ranges))

	for _, r := range ranges {
		payload := make([]byte, r.End-r.Start)
		copy(payload, data[r.Start:r.End])

		chunkData := types.ContentChunkData{Payload: payload}
		chunkEnt, err := chunkData.ToEntity()
		if err != nil {
			return entity.Entity{}, nil, err
		}
		chunkEntities = append(chunkEntities, chunkEnt)
		chunkHashes = append(chunkHashes, chunkEnt.ContentHash)
	}

	blobData := types.ContentBlobData{
		TotalSize: uint64(len(data)),
		ChunkSize: chunkSize,
		Chunking:  chunking,
		Chunks:    chunkHashes,
	}
	blobEnt, err := blobData.ToEntity()
	if err != nil {
		return entity.Entity{}, nil, err
	}
	return blobEnt, chunkEntities, nil
}

// IngestBlob is a convenience wrapper: builds the blob + chunks and
// stores them in the content store. Returns the blob's entity hash on
// success. Persistence-by-default per §6.6 — the content store retains
// these until an out-of-band GC pass (or EXTENSION-GC when it lands).
func IngestBlob(
	data []byte,
	ranges []chunker.ChunkRange,
	chunking uint64,
	chunkSize uint64,
	contentStore store.ContentStore,
) (hash.Hash, error) {
	blobEnt, chunkEntities, err := BuildBlob(data, ranges, chunking, chunkSize)
	if err != nil {
		return hash.Hash{}, err
	}
	for _, c := range chunkEntities {
		if _, err := contentStore.Put(c); err != nil {
			return hash.Hash{}, err
		}
	}
	return contentStore.Put(blobEnt)
}

// Reassemble loads a blob's full closure from the local content store
// and returns the concatenated payload bytes. Per CONTENT v3.6 §3.4,
// reassembly is byte-concatenation in chunks-list order; FastCDC is
// symmetric and produces no boundary metadata to interpret.
//
// Reassemble is substrate-internal trusted code per L10 framing — it
// reads from the local content store after closure completion. The
// cap-checked wrapper (EnsureClosure) guards the closure-completion
// side; reassembly itself is a pure local function with no protocol
// surface. Callers MUST ensure the closure is locally complete (e.g.
// via EnsureClosure) before calling Reassemble.
//
// SDK-EXTENSION-OPERATIONS v0.8 §11 pins this location: Go's Reassemble
// lives publicly in ext/content/builder.go.
func Reassemble(cs store.ContentStore, blobHash hash.Hash) ([]byte, error) {
	blobEnt, ok := cs.Get(blobHash)
	if !ok {
		return nil, fmt.Errorf("reassemble: blob entity not in local store: %s", blobHash)
	}
	if blobEnt.Type != types.TypeContentBlob {
		return nil, fmt.Errorf("reassemble: hash %s does not refer to a blob (got type %q)", blobHash, blobEnt.Type)
	}
	var blob types.ContentBlobData
	if err := ecf.Decode(blobEnt.Data, &blob); err != nil {
		return nil, fmt.Errorf("reassemble: decode blob: %w", err)
	}
	buf := make([]byte, 0, blob.TotalSize)
	for i, chunkHash := range blob.Chunks {
		ent, ok := cs.Get(chunkHash)
		if !ok {
			return nil, fmt.Errorf("reassemble: chunk %d (%s) missing from local store", i, chunkHash)
		}
		var chunk types.ContentChunkData
		if err := ecf.Decode(ent.Data, &chunk); err != nil {
			return nil, fmt.Errorf("reassemble: decode chunk %d: %w", i, err)
		}
		buf = append(buf, chunk.Payload...)
	}
	if uint64(len(buf)) != blob.TotalSize {
		return nil, fmt.Errorf("reassemble: size %d does not match blob total_size %d", len(buf), blob.TotalSize)
	}
	return buf, nil
}
