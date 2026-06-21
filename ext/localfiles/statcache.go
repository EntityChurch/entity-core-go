package localfiles

import (
	"os"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// statCache implements the L7 stat-cache shape per DOMAIN-LOCAL-FILES
// v1.3 §10.2 SHOULD. Path-keyed cache of
//
//	(dev, ino, mtime_ns, ctime_ns, size, mode_bits, blob_hash)
//
// with Git's racy-clean rule (mtime_ns < cache_write_time_ns ⇒ hit)
// and Git's smudge-to-zero discipline (cache writes with mtime_ns at
// or after the cache_write_time_ns smudge size=0, forcing the next
// lookup to miss).
//
// The cache eliminates the dominant reverse-write / watcher-flush cost
// — full FastCDC rechunk on every event for unchanged files. With the
// cache, same-content sync events return blob_hash from the cache
// after a single stat syscall.
//
// Persistence + eviction are implementation-defined; this is in-memory
// scoped to handler lifetime. Restart pays one rechunk per touched path
// to repopulate.
type statCache struct {
	mu      sync.RWMutex
	entries map[string]statCacheEntry
}

type statCacheEntry struct {
	dev          uint64
	ino          uint64
	mtimeNs      int64
	ctimeNs      int64
	size         int64
	modeBits     uint32
	blobHash     hash.Hash
	chunkSize    uint64 // §5.5 Amendment 3 — cache hit requires chunk_size match
	cacheWriteNs int64  // for racy-clean rule per §10.2
}

func newStatCache() *statCache {
	return &statCache{entries: make(map[string]statCacheEntry)}
}

// statFields extracts the normative cache shape from os.FileInfo.
// mtime/size/mode are cross-platform; dev/ino/ctime are POSIX-specific
// and come from platform-tagged helpers (statcache_posix.go /
// statcache_windows.go). On Windows the extras degrade to zero and the
// predicate falls back to mtime+size+mode (still sufficient for the
// common case — Git's index uses the same degradation).
func statFields(info os.FileInfo) (dev, ino uint64, mtimeNs, ctimeNs int64, size int64, modeBits uint32) {
	size = info.Size()
	mtimeNs = info.ModTime().UnixNano()
	modeBits = uint32(info.Mode())
	dev, ino, ctimeNs = extraStatFields(info)
	return
}

// Lookup returns (blob_hash, true) on cache-hit-with-stat-match per
// Git's racy-clean rule: every stat field matches AND
// mtime_ns < cache_write_time_ns AND the requested chunk_size matches
// the cached chunk_size (Amendment 3 §5.5 — different chunk_size would
// produce a different blob hash on the same content, so the cached
// value is invalid for the wrong chunk_size). Otherwise (zero, false).
// Caller already holds the os.FileInfo (cheap stat); the cache adds no
// extra syscall on the hot path.
func (c *statCache) Lookup(fsPath string, info os.FileInfo, chunkSize uint64) (hash.Hash, bool) {
	c.mu.RLock()
	entry, ok := c.entries[fsPath]
	c.mu.RUnlock()
	if !ok {
		return hash.Hash{}, false
	}
	if entry.chunkSize != chunkSize {
		return hash.Hash{}, false
	}
	dev, ino, mtimeNs, ctimeNs, size, modeBits := statFields(info)
	if entry.dev != dev || entry.ino != ino || entry.size != size ||
		entry.modeBits != modeBits || entry.mtimeNs != mtimeNs || entry.ctimeNs != ctimeNs {
		return hash.Hash{}, false
	}
	// Racy-clean rule: if the cached mtime is at or after the cache
	// write time, we can't tell whether the modification that produced
	// the cached blob_hash was the same modification as the latest one.
	// The Update path below smudges size=0 for entries in that window;
	// a size=0 entry will already have failed the size match above.
	// This redundant check defends against future mutations that bypass
	// the smudge invariant.
	if entry.mtimeNs >= entry.cacheWriteNs {
		return hash.Hash{}, false
	}
	return entry.blobHash, true
}

// Update writes a fresh cache entry for fsPath. Implements Git's
// smudge-to-zero discipline: if the file's mtime is at or after the
// cache_write_time, smudge size=0 so the next Lookup is a forced miss.
// Closes the within-same-tick-write window on filesystems with coarse
// mtime (FAT) or on rapid back-to-back writes that fall inside the same
// ns tick. The chunkSize is recorded so a future Lookup with a
// different chunk_size sees a miss (Amendment 3 §5.5).
func (c *statCache) Update(fsPath string, info os.FileInfo, blobHash hash.Hash, chunkSize uint64) {
	dev, ino, mtimeNs, ctimeNs, size, modeBits := statFields(info)
	now := time.Now().UnixNano()
	if mtimeNs >= now {
		size = 0 // smudge
	}
	c.mu.Lock()
	c.entries[fsPath] = statCacheEntry{
		dev: dev, ino: ino,
		mtimeNs: mtimeNs, ctimeNs: ctimeNs,
		size: size, modeBits: modeBits,
		blobHash:     blobHash,
		chunkSize:    chunkSize,
		cacheWriteNs: now,
	}
	c.mu.Unlock()
}

// Invalidate removes a cache entry. Used on reverse-delete and on
// any deleted-event flush. Idempotent for absent paths.
func (c *statCache) Invalidate(fsPath string) {
	c.mu.Lock()
	delete(c.entries, fsPath)
	c.mu.Unlock()
}

// len returns the number of cached entries; used by tests.
func (c *statCache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
