package localfiles

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"runtime"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"
)

// handleRead reads a file from the filesystem, stores it in the tree, and returns it (§4.1).
func (h *Handler) handleRead(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	treePath, err := extractResourcePath(hctx)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_resource", err.Error())
	}

	h.mu.Lock()
	root := h.findRootMapping(treePath)
	h.mu.Unlock()
	if root == nil {
		return handler.NewErrorResponse(404, "no_root_mapping", "no root mapping for path: "+treePath)
	}

	fsPath, relativePath, err := resolveFSPath(root, treePath)
	if err != nil {
		return handler.NewErrorResponse(403, "path_traversal_rejected", err.Error())
	}

	info, err := os.Stat(fsPath)
	if os.IsNotExist(err) {
		return handler.NewErrorResponse(404, "file_not_found", "file not found: "+relativePath)
	}
	if err != nil {
		return handler.NewErrorResponse(500, "io_error", "stat: "+err.Error())
	}
	if info.IsDir() {
		return handler.NewErrorResponse(400, "use_list_for_directories", "use list operation for directories")
	}

	rawBytes, err := os.ReadFile(fsPath)
	if err != nil {
		return handler.NewErrorResponse(500, "io_error", "read: "+err.Error())
	}

	// CONTENT v3.6 §3.6 — chunk + persist via shared chunker. BuildBlob
	// returns chunk entities by reference so we can compose the §4.3
	// inline-include map below without re-decoding the blob.
	ranges := chunker.ChunkFastCDC(rawBytes, types.DefaultChunkSize)
	blobEnt, chunkEntities, err := content.BuildBlob(rawBytes, ranges, types.ChunkingFastCDC, types.DefaultChunkSize)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "build blob: "+err.Error())
	}
	for _, c := range chunkEntities {
		if _, err := hctx.Store.Put(c); err != nil {
			return handler.NewErrorResponse(500, "internal_error", "store chunk: "+err.Error())
		}
	}
	blobHash, err := hctx.Store.Put(blobEnt)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "store blob: "+err.Error())
	}

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
		return handler.NewErrorResponse(500, "internal_error", "create file entity: "+err.Error())
	}

	fh, err := hctx.Store.Put(fileEntity)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "store file entity: "+err.Error())
	}
	if _, err := hctx.TreeSet(treePath, fh, "read"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind file entity: "+err.Error())
	}

	// DOMAIN-LOCAL-FILES v1.3 §10.5 V3 — when the root is configured with
	// publish_descriptors=true, every successful read also publishes a
	// system/content/descriptor entity for the blob at the §5.3 dual-level
	// invariant-pointer path
	// /{local_peer_id}/system/content/descriptor/{B_hex}/{D_hex}, so cohort
	// consumers can dereference media-type/name metadata for the blob
	// without re-reading the file. Failures are logged but do not fault the
	// read — the file entity is the load-bearing result.
	if root.PublishDescriptors {
		mediaType := fileData.MediaType
		if mediaType == nil {
			fallback := "application/octet-stream"
			mediaType = &fallback
		}
		descriptor := types.ContentDescriptorData{
			Content:   blobHash,
			MediaType: mediaType,
		}
		if descEnt, err := descriptor.ToEntity(); err == nil {
			if _, err := content.PublishDescriptor(hctx.LocalPeerID, descEnt, hctx.Store, hctx.LocationIndex); err != nil {
				h.logf("publish_descriptors: %s: %v", treePath, err)
			}
		}
	}

	// CONTENT §4.3 inline-include: always include the blob; include the
	// chunks too when total_size ≤ MIN_CHUNK_SIZE (64 KiB).
	included := map[hash.Hash]entity.Entity{blobHash: blobEnt}
	if uint64(len(rawBytes)) <= types.MinChunkSize {
		for _, c := range chunkEntities {
			included[c.ContentHash] = c
		}
	}

	return &handler.Response{Status: 200, Result: fileEntity, Included: included}, nil
}

// handleWrite writes content to the filesystem and updates the tree
// (v1.2 §5.4). Two input modes: Bytes (raw payload — handler chunks
// via FastCDC) or Content (existing blob hash — first-class dedup
// write; reassemble from chunks already in the content store).
func (h *Handler) handleWrite(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	treePath, err := extractResourcePath(hctx)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_resource", err.Error())
	}

	h.mu.Lock()
	root := h.findRootMapping(treePath)
	h.mu.Unlock()
	if root == nil {
		return handler.NewErrorResponse(404, "no_root_mapping", "no root mapping for path: "+treePath)
	}
	if root.ReadOnly {
		return handler.NewErrorResponse(403, "read_only_root", "root mapping is read-only")
	}

	fsPath, relativePath, err := resolveFSPath(root, treePath)
	if err != nil {
		return handler.NewErrorResponse(403, "path_traversal_rejected", err.Error())
	}

	params, err := WriteRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params", "decode write request: "+err.Error())
	}

	// Presence, not non-emptiness — an empty byte slice is a valid
	// zero-length write. CBOR omitempty makes absent fields decode to
	// nil; present-but-empty decodes to []byte{} (length 0, non-nil).
	// Per Rust N-2 / 3-of-3 latent bug surfaced in the cycle.
	hasBytes := params.Bytes != nil
	hasContent := params.Content != nil
	if hasBytes == hasContent {
		return handler.NewErrorResponse(400, "invalid_params", "exactly one of bytes / content must be set")
	}

	var (
		rawBytes      []byte
		blobHash      hash.Hash
		blobEnt       entity.Entity
		chunkEntities []entity.Entity
	)

	if hasBytes {
		rawBytes = params.Bytes
		ranges := chunker.ChunkFastCDC(rawBytes, types.DefaultChunkSize)
		blobEnt, chunkEntities, err = content.BuildBlob(rawBytes, ranges, types.ChunkingFastCDC, types.DefaultChunkSize)
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "build blob: "+err.Error())
		}
		for _, c := range chunkEntities {
			if _, err := hctx.Store.Put(c); err != nil {
				return handler.NewErrorResponse(500, "internal_error", "store chunk: "+err.Error())
			}
		}
		blobHash, err = hctx.Store.Put(blobEnt)
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "store blob: "+err.Error())
		}
	} else {
		blobHash = *params.Content
		var ok bool
		blobEnt, ok = hctx.Store.Get(blobHash)
		if !ok {
			return handler.NewErrorResponse(404, "content_not_found", "blob not found in content store")
		}
	}

	if params.CreateDirs {
		if err := os.MkdirAll(filepath.Dir(fsPath), 0755); err != nil {
			return handler.NewErrorResponse(500, "io_error", "mkdir: "+err.Error())
		}
	}

	// F9 fix (workbench Round 6 handoff): mark the path as
	// recently-written BEFORE the disk write so the watcher event fired
	// by atomicWriteFile / streamReassembleToFile is suppressed by the
	// loop-prevention tracker. Symmetric to reverse.go:185. Without this
	// the dispatch-driven write path bypasses the circuit breaker that
	// the tree-event-driven reverse-write path uses, and a same-path
	// subscription loop runs unbounded (single-peer self-loop
	// reproducer: 2169 entities/5s from one user write).
	h.mu.Lock()
	tracker := h.reverseTracker
	h.mu.Unlock()
	if tracker != nil {
		tracker.markWritten(treePath)
	}

	// Bytes mode keeps rawBytes (input already in hand); content mode
	// streams reassembly chunk-by-chunk to avoid double-buffering the
	// payload. Heap stays bounded under large content-mode writes.
	if hasBytes {
		if err := atomicWriteFile(fsPath, rawBytes); err != nil {
			return handler.NewErrorResponse(500, "io_error", "write: "+err.Error())
		}
	} else {
		if err := streamReassembleToFile(hctx.Store, blobEnt, fsPath); err != nil {
			return handler.NewErrorResponse(500, "io_error", "write: "+err.Error())
		}
	}

	info, _ := os.Stat(fsPath)
	var modTime *uint64
	var size uint64
	if hasBytes {
		size = uint64(len(rawBytes))
	} else {
		var blob types.ContentBlobData
		_ = ecf.Decode(blobEnt.Data, &blob)
		size = blob.TotalSize
	}
	if info != nil {
		mt := uint64(info.ModTime().UnixMilli())
		modTime = &mt
		size = uint64(info.Size())
	}

	fileData := FileData{
		Path:       relativePath,
		Size:       size,
		ModifiedAt: modTime,
		Content:    blobHash,
		MediaType:  pickMediaType(params.MediaType, relativePath),
		Written:    true,
	}
	fileEntity, err := fileData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "create file entity: "+err.Error())
	}

	fh, err := hctx.Store.Put(fileEntity)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "store file entity: "+err.Error())
	}
	if _, err := hctx.TreeSet(treePath, fh, "write"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind file entity: "+err.Error())
	}

	// §4.3 inline-include: blob always, chunks when small. Bytes-mode
	// has chunkEntities in hand; content-mode reuses the chunks already
	// in the store (decode the blob to enumerate, skip re-fetch if absent).
	included := map[hash.Hash]entity.Entity{blobHash: blobEnt}
	if size <= types.MinChunkSize {
		if hasBytes {
			for _, c := range chunkEntities {
				included[c.ContentHash] = c
			}
		} else {
			var blob types.ContentBlobData
			if ecf.Decode(blobEnt.Data, &blob) == nil {
				for _, ch := range blob.Chunks {
					if ent, ok := hctx.Store.Get(ch); ok {
						included[ch] = ent
					}
				}
			}
		}
	}

	return &handler.Response{Status: 200, Result: fileEntity, Included: included}, nil
}

// handleList lists directory contents from the filesystem (§4.2).
func (h *Handler) handleList(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	treePath, err := extractResourcePath(hctx)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_resource", err.Error())
	}

	h.mu.Lock()
	root := h.findRootMapping(treePath)
	h.mu.Unlock()
	if root == nil {
		return handler.NewErrorResponse(404, "no_root_mapping", "no root mapping for path: "+treePath)
	}

	fsPath, relativePath, err := resolveFSPath(root, treePath)
	if err != nil {
		return handler.NewErrorResponse(403, "path_traversal_rejected", err.Error())
	}

	entries, err := os.ReadDir(fsPath)
	if os.IsNotExist(err) {
		return handler.NewErrorResponse(404, "directory_not_found", "directory not found: "+relativePath)
	}
	if err != nil {
		return handler.NewErrorResponse(500, "io_error", "readdir: "+err.Error())
	}

	var children []DirectoryEntryData
	for _, entry := range entries {
		if matchesExclude(entry.Name(), root.Exclude) {
			continue
		}
		// Include filter applies to files only — dirs are always shown
		// so the user can navigate down to included files in subtrees.
		if !entry.IsDir() && !matchesInclude(entry.Name(), root.Include) {
			continue
		}

		childEntry := DirectoryEntryData{
			Name:       entry.Name(),
			EntityPath: treePath + entry.Name(),
			EntryType:  "file",
		}
		if entry.IsDir() {
			childEntry.EntryType = "directory"
		}

		info, err := entry.Info()
		if err == nil {
			mt := uint64(info.ModTime().UnixMilli())
			childEntry.ModifiedAt = &mt
			if !entry.IsDir() {
				sz := uint64(info.Size())
				childEntry.Size = &sz
			}
		}

		children = append(children, childEntry)
	}

	dirData := DirectoryData{
		Path:     relativePath,
		Children: children,
	}
	dirEntity, err := dirData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "create directory entity: "+err.Error())
	}

	return &handler.Response{Status: 200, Result: dirEntity}, nil
}

// handleDelete removes a file from the filesystem and the tree (§4.4).
func (h *Handler) handleDelete(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	treePath, err := extractResourcePath(hctx)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_resource", err.Error())
	}

	h.mu.Lock()
	root := h.findRootMapping(treePath)
	h.mu.Unlock()
	if root == nil {
		return handler.NewErrorResponse(404, "no_root_mapping", "no root mapping for path: "+treePath)
	}
	if root.ReadOnly {
		return handler.NewErrorResponse(403, "read_only_root", "root mapping is read-only")
	}

	fsPath, relativePath, err := resolveFSPath(root, treePath)
	if err != nil {
		return handler.NewErrorResponse(403, "path_traversal_rejected", err.Error())
	}

	existed := true
	if err := os.Remove(fsPath); err != nil {
		if os.IsNotExist(err) {
			existed = false
		} else {
			return handler.NewErrorResponse(500, "io_error", "delete: "+err.Error())
		}
	}

	// Remove from tree.
	hctx.TreeRemove(treePath, "delete")

	deletedData := DeletedData{Path: relativePath, Existed: existed}
	deletedEntity, err := deletedData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "create deleted entity: "+err.Error())
	}

	return &handler.Response{Status: 200, Result: deletedEntity}, nil
}

// handleWatch starts or stops filesystem monitoring for a root mapping (§4.5).
func (h *Handler) handleWatch(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	params, err := WatchRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params", "decode watch request: "+err.Error())
	}

	rootName := params.RootName
	action := params.Action
	if action == "" {
		action = "start"
	}

	h.mu.Lock()
	root, exists := h.roots[rootName]
	h.mu.Unlock()
	if !exists {
		return handler.NewErrorResponse(404, "root_mapping_not_found", "no root mapping named: "+rootName)
	}

	watcherPath := "system/config/local/files/watch/" + rootName

	if action == "stop" {
		h.mu.Lock()
		w, ok := h.watchers[rootName]
		if ok {
			w.Stop()
			delete(h.watchers, rootName)
		}
		h.mu.Unlock()

		if !ok {
			return handler.NewErrorResponse(404, "watcher_not_found", "no active watcher for: "+rootName)
		}

		wcData := WatcherConfigData{RootName: rootName, Status: "stopped"}
		wcEntity, err := wcData.ToEntity()
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "create watcher config: "+err.Error())
		}
		wh, _ := hctx.Store.Put(wcEntity)
		if _, err := hctx.TreeSet(watcherPath, wh, "watch"); err != nil {
			return handler.NewErrorResponse(500, "storage_error", "bind watcher config: "+err.Error())
		}

		return &handler.Response{Status: 200, Result: wcEntity}, nil
	}

	// action == "start"
	var debounceMs uint64 = 2000
	if params.DebounceMs != nil {
		debounceMs = *params.DebounceMs
	}

	w, err := newWatcher(root, debounceMs, hctx.Store, hctx.LocationIndex, h.logger, h.statCache)
	if err != nil {
		errMsg := err.Error()
		wcData := WatcherConfigData{RootName: rootName, Status: "error", ErrorMessage: errMsg}
		wcEntity, _ := wcData.ToEntity()
		if wcEntity.Type != "" {
			wh, _ := hctx.Store.Put(wcEntity)
			// Best-effort: we're already returning an error, so we don't
			// fail harder if the error-status bind itself fails — but log it.
			if _, err := hctx.TreeSet(watcherPath, wh, "watch"); err != nil && h.logger != nil {
				h.logger.Printf("localfiles: bind watcher error status failed: %v", err)
			}
		}
		return handler.NewErrorResponse(500, "watcher_error", "start watcher: "+errMsg)
	}

	h.mu.Lock()
	// Stop existing watcher if any.
	if old, ok := h.watchers[rootName]; ok {
		old.Stop()
	}
	h.watchers[rootName] = w
	h.mu.Unlock()

	w.Start(ctx)

	dms := debounceMs
	wcData := WatcherConfigData{RootName: rootName, Status: "active", DebounceMs: &dms}
	wcEntity, err := wcData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "create watcher config: "+err.Error())
	}
	wh, _ := hctx.Store.Put(wcEntity)
	if _, err := hctx.TreeSet(watcherPath, wh, "watch"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind watcher config: "+err.Error())
	}

	return &handler.Response{Status: 200, Result: wcEntity}, nil
}

// extractResourcePath gets the first target path from the handler context resource.
func extractResourcePath(hctx *handler.HandlerContext) (string, error) {
	if hctx == nil || hctx.Resource == nil || len(hctx.Resource.Targets) == 0 {
		return "", errorf("missing resource target")
	}
	return hctx.Resource.Targets[0], nil
}

func errorf(msg string) error {
	return &simpleError{msg: msg}
}

type simpleError struct{ msg string }

func (e *simpleError) Error() string { return e.msg }

// guessMediaType derives an IANA media type from the path extension via
// Go's mime registry. Returns nil when the extension is unknown — the
// FileData.MediaType field is optional per v1.2 §5.1 and absence is
// preferred over a guessed-wrong value.
func guessMediaType(path string) *string {
	mt := mime.TypeByExtension(filepath.Ext(path))
	if mt == "" {
		return nil
	}
	return &mt
}

// pickMediaType prefers the caller-supplied media type, falling back to
// the path-extension guess.
func pickMediaType(supplied *string, path string) *string {
	if supplied != nil && *supplied != "" {
		return supplied
	}
	return guessMediaType(path)
}

// reassembleBlob loads a blob entity's chunks from the content store and
// returns the concatenated payload bytes. Per CONTENT v3.6 §3.4,
// reassembly is byte-concatenation in chunks-list order; FastCDC is
// symmetric and produces no boundary metadata to interpret.
func reassembleBlob(cs store.ContentStore, blobEnt entity.Entity) ([]byte, error) {
	var blob types.ContentBlobData
	if err := ecf.Decode(blobEnt.Data, &blob); err != nil {
		return nil, fmt.Errorf("decode blob: %w", err)
	}
	buf := make([]byte, 0, blob.TotalSize)
	for i, chunkHash := range blob.Chunks {
		ent, ok := cs.Get(chunkHash)
		if !ok {
			return nil, fmt.Errorf("chunk %d (%x) missing from content store", i, chunkHash.Digest[:8])
		}
		var chunk types.ContentChunkData
		if err := ecf.Decode(ent.Data, &chunk); err != nil {
			return nil, fmt.Errorf("decode chunk %d: %w", i, err)
		}
		buf = append(buf, chunk.Payload...)
	}
	if uint64(len(buf)) != blob.TotalSize {
		return nil, fmt.Errorf("reassembled size %d does not match blob total_size %d", len(buf), blob.TotalSize)
	}
	return buf, nil
}

// atomicWriteFile writes data to fsPath via a sibling temp file +
// fsync + rename + parent-dir fsync (POSIX). On POSIX, the rename is
// atomic within the same directory; the parent-dir fsync after rename
// closes a crash-consistency hole — per POSIX fsync(2) and ext4/xfs/btrfs
// semantics, rename() returning success means the kernel has *queued*
// the directory-entry update, not that it is on stable storage. Without
// the parent-dir fsync, a power loss within the writeback window can
// silently drop the rename even though the temp file was fsync'd.
// Per DOMAIN-LOCAL-FILES v1.3 §4.3. Windows MoveFileEx with
// MOVEFILE_REPLACE_EXISTING provides equivalent semantics without the
// parent-dir step; os.Rename uses MoveFileEx on Windows.
func atomicWriteFile(fsPath string, data []byte) error {
	return atomicWriteFileFrom(fsPath, bytes.NewReader(data))
}

// atomicWriteFileFrom is the streaming variant of atomicWriteFile. It
// copies bytes from r into the temp file via io.Copy (default 32 KiB
// staging buffer) instead of materializing the full payload in memory.
// Used by reverse-write paths for content >MIN_CHUNK_SIZE so reassembly
// streams chunk-by-chunk to disk — heap stays at one chunk in flight
// rather than the full file size (workbench's Case 5 64 MiB heap delta
// observation: full-buffer reassembly cost ~2× file size on the receiver).
//
// Durability semantics are identical to atomicWriteFile: sibling temp
// file + fsync + rename + parent-dir fsync.
func atomicWriteFileFrom(fsPath string, r io.Reader) error {
	dir := filepath.Dir(fsPath)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(fsPath)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, fsPath); err != nil {
		cleanup()
		return err
	}
	_ = os.Chmod(fsPath, 0644)
	if runtime.GOOS != "windows" {
		if d, derr := os.Open(dir); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}

// streamReassembleToFile writes a blob's reassembled payload to fsPath
// chunk-by-chunk, holding at most one chunk in memory at a time. The
// existing reassembleBlob helper materializes the whole []byte and is
// kept for the small-content paths (<= MIN_CHUNK_SIZE) where the full
// buffer is cheap. For larger content, this streaming variant pairs
// with atomicWriteFileFrom to keep receiver-side heap bounded.
//
// Per CONTENT v3.6 §7.2 streaming-reassembly SHOULD ≥ 64 MiB; this
// closes the "10 GB OOMs the receiver" cliff DOMAIN-LOCAL-FILES v1.3
// Amendment 1 L4 named.
func streamReassembleToFile(cs store.ContentStore, blobEnt entity.Entity, fsPath string) error {
	var blob types.ContentBlobData
	if err := ecf.Decode(blobEnt.Data, &blob); err != nil {
		return fmt.Errorf("decode blob: %w", err)
	}
	dir := filepath.Dir(fsPath)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(fsPath)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	var written uint64
	for i, chunkHash := range blob.Chunks {
		ent, ok := cs.Get(chunkHash)
		if !ok {
			tmp.Close()
			cleanup()
			return fmt.Errorf("chunk %d (%s) missing from content store", i, chunkHash)
		}
		var chunk types.ContentChunkData
		if err := ecf.Decode(ent.Data, &chunk); err != nil {
			tmp.Close()
			cleanup()
			return fmt.Errorf("decode chunk %d: %w", i, err)
		}
		n, werr := tmp.Write(chunk.Payload)
		if werr != nil {
			tmp.Close()
			cleanup()
			return werr
		}
		written += uint64(n)
	}
	if written != blob.TotalSize {
		tmp.Close()
		cleanup()
		return fmt.Errorf("streamed size %d does not match blob total_size %d", written, blob.TotalSize)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, fsPath); err != nil {
		cleanup()
		return err
	}
	_ = os.Chmod(fsPath, 0644)
	if runtime.GOOS != "windows" {
		if d, derr := os.Open(dir); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}
