package localfiles

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"

	"github.com/fsnotify/fsnotify"
)

// fsEventType represents the coalesced type of a filesystem event.
type fsEventType int

const (
	fsCreated fsEventType = iota
	fsUpdated
	fsDeleted
)

// watcher monitors a filesystem directory for changes and translates them
// into entity tree writes (§6).
type watcher struct {
	mu         sync.Mutex
	root       *RootMapping
	debounceMs uint64
	fsw        *fsnotify.Watcher
	cs         store.ContentStore
	li         store.LocationIndex
	logger     *log.Logger
	cancel     context.CancelFunc
	bgCtx      *store.MutationContext // background context for watcher writes
	cache      *statCache             // L7 fast-path; shared with handler

	// Debounce buffer: relative path → latest event type.
	pending map[string]fsEventType
	timer   *time.Timer
}

func newWatcher(root *RootMapping, debounceMs uint64, cs store.ContentStore, li store.LocationIndex, logger *log.Logger, cache *statCache) (*watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Add the root directory and subdirectories.
	err = filepath.Walk(root.FSRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if matchesExclude(name, root.Exclude) {
				return filepath.SkipDir
			}
			return fsw.Add(path)
		}
		return nil
	})
	if err != nil {
		fsw.Close()
		return nil, err
	}

	return &watcher{
		root:       root,
		debounceMs: debounceMs,
		fsw:        fsw,
		cs:         cs,
		li:         li,
		logger:     logger,
		cache:      cache,
		pending:    make(map[string]fsEventType),
	}, nil
}

// Start begins the watcher event loop.
func (w *watcher) Start(ctx context.Context) {
	wctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	// Seed an initial scan: fsnotify only reports future events, so
	// pre-existing files in the watched directory would otherwise
	// never reach the tree. Walk the root once, mark every regular
	// file as fsCreated, and flush so the existing content gets
	// ingested at mount time. Future modifications come through the
	// event loop as usual.
	w.initialScan()
	go w.eventLoop(wctx)
}

// initialScan walks the watched root and queues an fsCreated event
// for every regular file currently on disk, then flushes. Idempotent
// for repeated calls (debounce coalescing collapses any overlap with
// inflight events).
func (w *watcher) initialScan() {
	w.mu.Lock()
	_ = filepath.Walk(w.root.FSRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			if matchesExclude(info.Name(), w.root.Exclude) {
				return filepath.SkipDir
			}
			return nil
		}
		if fileSkipped(info.Name(), w.root.Exclude, w.root.Include) {
			return nil
		}
		relPath, relErr := filepath.Rel(w.root.FSRoot, path)
		if relErr != nil {
			return nil
		}
		w.pending[relPath] = fsCreated
		return nil
	})
	hasPending := len(w.pending) > 0
	w.mu.Unlock()
	if hasPending {
		w.flush()
	}
}

// Stop stops the watcher.
func (w *watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.fsw.Close()
}

func (w *watcher) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			w.flush()
			return
		case event, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.logf("localfiles: fs event: %s %s", event.Op, event.Name)
			w.handleFSEvent(event)
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			w.logf("localfiles: watcher error: %v", err)
		}
	}
}

func (w *watcher) handleFSEvent(event fsnotify.Event) {
	// Compute relative path.
	relPath, err := filepath.Rel(w.root.FSRoot, event.Name)
	if err != nil {
		return
	}

	// Apply exclude patterns (filename match — applies to files + dirs).
	baseName := filepath.Base(event.Name)
	if matchesExclude(baseName, w.root.Exclude) {
		return
	}

	// Skip directories (tracked implicitly via their contents). Include
	// filter does NOT apply to dirs — otherwise an Include of "*.md"
	// would refuse to add a subdir watch.
	info, err := os.Stat(event.Name)
	if err == nil && info.IsDir() {
		// If a new directory is created, add it to the watcher.
		if event.Has(fsnotify.Create) {
			w.fsw.Add(event.Name)
		}
		return
	}

	// Apply include patterns (file-only). When stat fails (e.g. a
	// delete event after the file is gone), apply Include on the
	// basename anyway — a deleted non-included file shouldn't trigger
	// downstream ingest cleanup since it was never ingested.
	if !matchesInclude(baseName, w.root.Include) {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Determine event type and coalesce with existing pending events (§6.3).
	var evtType fsEventType
	if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
		evtType = fsDeleted
	} else if event.Has(fsnotify.Create) {
		evtType = fsCreated
	} else {
		evtType = fsUpdated
	}

	prev, hasPrev := w.pending[relPath]
	if hasPrev {
		evtType = coalesce(prev, evtType)
		if evtType == -1 {
			// created → deleted = no-op
			delete(w.pending, relPath)
			return
		}
	}
	w.pending[relPath] = evtType

	// Reset debounce timer.
	if w.timer != nil {
		w.timer.Stop()
	}
	w.timer = time.AfterFunc(time.Duration(w.debounceMs)*time.Millisecond, func() {
		w.flush()
	})
}

// coalesce applies debounce coalescing rules (§6.3).
func coalesce(prev, next fsEventType) fsEventType {
	switch {
	case prev == fsCreated && next == fsDeleted:
		return -1 // no-op
	case prev == fsCreated && next == fsUpdated:
		return fsCreated
	case prev == fsUpdated && next == fsDeleted:
		return fsDeleted
	case prev == fsUpdated && next == fsUpdated:
		return fsUpdated
	case prev == fsDeleted && next == fsCreated:
		return fsUpdated
	default:
		return next
	}
}

// flush processes all pending events.
func (w *watcher) flush() {
	w.mu.Lock()
	pending := w.pending
	w.pending = make(map[string]fsEventType)
	w.mu.Unlock()
	w.logf("localfiles: flush %d pending events", len(pending))

	for relPath, evtType := range pending {
		treePath := w.root.Prefix + filepath.ToSlash(relPath)

		if evtType == fsDeleted {
			if cw, ok := w.li.(store.ContextualWriter); ok && w.bgCtx != nil {
				cw.RemoveWithContext(treePath, w.bgCtx)
			} else {
				w.li.Remove(treePath)
			}
			// L7: drop cache entry; the path no longer maps to a blob.
			if w.cache != nil {
				w.cache.Invalidate(filepath.Join(w.root.FSRoot, relPath))
			}
			continue
		}

		fsPath := filepath.Join(w.root.FSRoot, relPath)

		// Lstat first: refuse to follow leaf symlinks. An attacker who can
		// write into the watched root could plant a symlink to a path
		// outside the root; without this check, the watcher would ingest
		// that file's contents into the content store + tree and propagate
		// them cross-peer. Convergent with the resolveFSPath leaf-symlink
		// check on the EXECUTE side.
		linfo, err := os.Lstat(fsPath)
		if err != nil {
			// File may have been deleted between event and flush.
			continue
		}
		if linfo.Mode()&os.ModeSymlink != 0 {
			w.logf("localfiles: watcher refusing leaf symlink at %s", fsPath)
			continue
		}

		// Skip directories.
		info, err := os.Stat(fsPath)
		if err != nil {
			// File may have been deleted between event and flush.
			continue
		}
		if info.IsDir() {
			continue
		}

		// L7 §10.2 fast path: if the cache holds a fresh blob_hash for
		// this path whose stat matches disk, we already ingested the
		// content the last time we saw it. Skip the read + chunk + put;
		// reuse the cached hash to construct the file entity below.
		// Common case for spurious notification storms (touch, attr
		// change, large directory recursion) — cuts the ingest cost
		// from "full FastCDC pass + blob/chunk put" to "single stat".
		// Watcher ingests at the local default chunk_size (no incoming
		// blob to consult); cache lookup is keyed by that chunk_size
		// per Amendment 3 §5.5.
		var blobHash hash.Hash
		if w.cache != nil {
			if bh, ok := w.cache.Lookup(fsPath, info, types.DefaultChunkSize); ok {
				blobHash = bh
			}
		}
		if blobHash.IsZero() {
			rawBytes, err := os.ReadFile(fsPath)
			if err != nil {
				w.logf("localfiles: watcher read error for %s: %v", fsPath, err)
				continue
			}

			// CONTENT v3.6 §3.6 — chunk + persist via shared chunker. Edit
			// stability does the cost-of-edit work: a 1-byte change re-uses
			// almost all chunks; only the boundary-disturbed chunk is new.
			ranges := chunker.ChunkFastCDC(rawBytes, types.DefaultChunkSize)
			blobEnt, chunkEntities, err := content.BuildBlob(rawBytes, ranges, types.ChunkingFastCDC, types.DefaultChunkSize)
			if err != nil {
				w.logf("localfiles: watcher build blob error for %s: %v", fsPath, err)
				continue
			}
			for _, c := range chunkEntities {
				if _, err := w.cs.Put(c); err != nil {
					w.logf("localfiles: watcher chunk put error for %s: %v", fsPath, err)
					continue
				}
			}
			bh, err := w.cs.Put(blobEnt)
			if err != nil {
				w.logf("localfiles: watcher blob put error for %s: %v", fsPath, err)
				continue
			}
			blobHash = bh
			if w.cache != nil {
				w.cache.Update(fsPath, info, blobHash, types.DefaultChunkSize)
			}
		}

		relativePath := strings.TrimPrefix(treePath, w.root.Prefix)
		modTime := uint64(info.ModTime().UnixMilli())
		fileData := FileData{
			Path:       relativePath,
			Size:       uint64(info.Size()),
			ModifiedAt: &modTime,
			Content:    blobHash,
			MediaType:  guessMediaType(relativePath),
		}
		fileEntity, err := fileData.ToEntity()
		if err != nil {
			w.logf("localfiles: watcher file entity error: %v", err)
			continue
		}
		fh, err := w.cs.Put(fileEntity)
		if err != nil {
			w.logf("localfiles: watcher store error: %v", err)
			continue
		}
		var setErr error
		if cw, ok := w.li.(store.ContextualWriter); ok && w.bgCtx != nil {
			_, setErr = cw.SetWithContext(treePath, fh, w.bgCtx)
		} else {
			setErr = w.li.Set(treePath, fh)
		}
		if setErr != nil {
			// Watcher is a background goroutine — no caller to propagate to.
			// Loud log is the contract: the operator must see that ingest
			// state diverged from the filesystem. Per V7 §2688 the binding
			// did not commit; the file is effectively absent from the tree.
			w.logf("localfiles: watcher bind error for %s: %v", treePath, setErr)
			continue
		}
	}
}

func (w *watcher) logf(format string, args ...any) {
	if w.logger != nil {
		w.logger.Printf(format, args...)
	}
}
