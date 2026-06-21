package localfiles

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"
)

const recentWriteWindow = 5 * time.Second

// reverseTracker tracks recently-written paths to prevent loops.
type reverseTracker struct {
	mu      sync.Mutex
	written map[string]time.Time
}

func newReverseTracker() *reverseTracker {
	return &reverseTracker{written: make(map[string]time.Time)}
}

func (rt *reverseTracker) markWritten(path string) {
	rt.mu.Lock()
	rt.written[path] = time.Now()
	rt.mu.Unlock()
}

func (rt *reverseTracker) isRecentlyWritten(path string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	t, ok := rt.written[path]
	if !ok {
		return false
	}
	if time.Since(t) > recentWriteWindow {
		delete(rt.written, path)
		return false
	}
	return true
}

// StartReverseWrite begins processing tree change events to write files to disk (§5).
// This should be called after peer construction. The localPeerID is used to filter
// out events from remote peers (only local tree changes should write to disk).
func (h *Handler) StartReverseWrite(ctx context.Context, events <-chan store.TreeChangeEvent,
	cs store.ContentStore, li store.LocationIndex, localPeerID string) {
	tracker := newReverseTracker()

	h.mu.Lock()
	h.reverseTracker = tracker
	h.localNS = localPeerID
	h.mu.Unlock()

	go h.reverseWriteLoop(ctx, events, cs, li, tracker)
}

// reverseWriteLoop processes tree change events.
func (h *Handler) reverseWriteLoop(ctx context.Context, events <-chan store.TreeChangeEvent,
	cs store.ContentStore, li store.LocationIndex, tracker *reverseTracker) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}

			peerID, barePath := store.SplitNamespace(evt.Path)

			// Only sync local tree to disk.
			if peerID != "" && peerID != h.localNS {
				continue
			}

			h.mu.Lock()
			root := h.findRootMapping(barePath)
			h.mu.Unlock()
			if root == nil {
				continue
			}
			if root.ReadOnly {
				continue
			}

			if strings.HasPrefix(barePath, "system/") {
				continue
			}

			if tracker.isRecentlyWritten(barePath) {
				continue
			}

			if evt.ChangeType == store.ChangeDeleted {
				h.reverseDelete(root, barePath)
				continue
			}

			ent, ok := cs.Get(evt.Hash)
			if !ok {
				continue
			}
			if ent.Type != TypeFile {
				continue
			}

			h.reverseWrite(root, barePath, ent, cs, tracker)
		}
	}
}

// reverseWrite resolves the file entity's blob from the content store
// and writes the reassembled bytes to disk (§5.3). Skips when the
// on-disk content already matches the blob hash — the circuit breaker
// for write/notify loops.
//
// Per DOMAIN-LOCAL-FILES v1.3 Amendment 3 (§5.5 chunk_size MUST): the
// circuit-breaker recompute MUST use the incoming blob's chunk_size
// field, not the local default. Mixed-default peers exchanging content
// would otherwise spuriously trigger rewrites (e.g., a 1 MiB peer
// recomputing a 4 MiB peer's content at 1 MiB → different hash →
// "diverges" verdict on identical content). Spec restructure: fetch
// blob early, extract chunk_size, pass through to circuit breaker.
func (h *Handler) reverseWrite(root *RootMapping, treePath string, fileEntity entity.Entity,
	cs store.ContentStore, tracker *reverseTracker) {
	fileData, err := FileDataFromEntity(fileEntity)
	if err != nil {
		h.logf("localfiles: reverse write decode error for %s: %v", treePath, err)
		return
	}
	if fileData.Content.IsZero() {
		return
	}

	fsPath, _, err := resolveFSPath(root, treePath)
	if err != nil {
		h.logf("localfiles: reverse write resolve error for %s: %v", treePath, err)
		return
	}

	// §5.3 restructure: fetch incoming blob early so we can extract its
	// chunk_size for the §5.5 circuit-breaker recompute. Missing blob
	// surfaces as silent return per the existing partial-sync convention
	// (CONTENT v3.6 503 blob_pending_sync semantic; reverse-write is
	// event-driven, not request-shaped — next subscription event retries).
	blobEnt, ok := cs.Get(fileData.Content)
	if !ok {
		h.logf("localfiles: reverse write blob not found for %s (partial sync — will retry on next event)", treePath)
		return
	}
	var blobData types.ContentBlobData
	if err := ecf.Decode(blobEnt.Data, &blobData); err != nil {
		h.logf("localfiles: reverse write decode blob error for %s: %v", treePath, err)
		return
	}
	incomingChunkSize := blobData.ChunkSize
	if incomingChunkSize == 0 {
		// Defensive: a blob entity missing chunk_size falls back to the
		// handler's local default rather than producing a zero-chunk
		// rechunk. Legitimate v1.3+ blobs always carry chunk_size.
		incomingChunkSize = types.DefaultChunkSize
	}

	if currentHash, err := h.currentDiskBlobHash(fsPath, incomingChunkSize); err == nil {
		if currentHash == fileData.Content {
			return // already matches
		}
	}

	if err := os.MkdirAll(filepath.Dir(fsPath), 0755); err != nil {
		h.logf("localfiles: reverse write mkdir error: %v", err)
		return
	}

	tracker.markWritten(treePath)
	// Stream chunks directly to the temp file rather than materializing
	// the full payload buffer. For 64 MiB+ content this drops peak heap
	// from ~2× file size (chunks in store + reassembled buffer) to
	// ~1× + one chunk in flight — addresses workbench's Stage 3 Case 5
	// heap delta observation and satisfies CONTENT v3.6 §7.2 streaming
	// reassembly SHOULD ≥ 64 MiB.
	if err := streamReassembleToFile(cs, blobEnt, fsPath); err != nil {
		h.logf("localfiles: reverse write error for %s: %v", fsPath, err)
		return
	}
	// L7: cache the newly-written file's stat → blob_hash so the next
	// circuit-breaker check hits the cache and skips the full rechunk.
	// Per §5.5 the cache records the chunk_size used so a future cache
	// hit only fires when the incoming blob's chunk_size matches.
	if info, err := os.Stat(fsPath); err == nil {
		h.statCache.Update(fsPath, info, fileData.Content, incomingChunkSize)
	}
}

// reverseDelete removes a file from the filesystem (§5.4).
func (h *Handler) reverseDelete(root *RootMapping, treePath string) {
	fsPath, _, err := resolveFSPath(root, treePath)
	if err != nil {
		h.logf("localfiles: reverse delete resolve error for %s: %v", treePath, err)
		return
	}

	if err := os.Remove(fsPath); err != nil && !os.IsNotExist(err) {
		h.logf("localfiles: reverse delete error for %s: %v", fsPath, err)
	}
	// L7: drop the cache entry — the path no longer maps to a blob_hash.
	h.statCache.Invalidate(fsPath)
}

// currentDiskBlobHash returns the blob_hash for the on-disk file,
// consulting the L7 stat-cache before falling back to a full FastCDC
// rechunk. Used by reverseWrite as the loop-prevention circuit breaker:
// if the on-disk content would hash to the same blob, the write is a
// no-op. Cache hits skip the read + chunk entirely (single stat
// syscall); cache misses do the full rechunk and update the cache.
//
// Per DOMAIN-LOCAL-FILES v1.3 Amendment 3 §5.5 (chunk_size MUST), the
// chunk_size is the incoming blob's chunk_size field — NOT the local
// default. The cache only returns a hit when the cached chunk_size
// matches the requested chunk_size; otherwise the cached value would
// be computed under a different chunking and would mismatch the
// incoming blob's hash even on identical content.
func (h *Handler) currentDiskBlobHash(fsPath string, chunkSize uint64) (hash.Hash, error) {
	info, statErr := os.Stat(fsPath)
	if statErr != nil {
		return hash.Hash{}, statErr
	}
	if bh, ok := h.statCache.Lookup(fsPath, info, chunkSize); ok {
		return bh, nil
	}
	bh, err := computeBlobHashFromDisk(fsPath, chunkSize)
	if err != nil {
		return hash.Hash{}, err
	}
	h.statCache.Update(fsPath, info, bh, chunkSize)
	return bh, nil
}

// computeBlobHashFromDisk is the cache-miss path: read + FastCDC chunk
// + BuildBlob at the specified chunk_size, returning the blob entity
// hash. The chunk_size MUST be the incoming blob's chunk_size per
// DOMAIN-LOCAL-FILES v1.3 Amendment 3 §5.5; same algorithm as v1.2 but
// parameterized.
func computeBlobHashFromDisk(fsPath string, chunkSize uint64) (hash.Hash, error) {
	rawBytes, err := os.ReadFile(fsPath)
	if err != nil {
		return hash.Hash{}, err
	}
	ranges := chunker.ChunkFastCDC(rawBytes, chunkSize)
	blobEnt, _, err := content.BuildBlob(rawBytes, ranges, types.ChunkingFastCDC, chunkSize)
	if err != nil {
		return hash.Hash{}, err
	}
	return blobEnt.ContentHash, nil
}
