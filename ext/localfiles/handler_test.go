package localfiles

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"

	"github.com/fxamacker/cbor/v2"
)

func newTestHandler(t *testing.T) (*Handler, *handler.HandlerContext, string) {
	t.Helper()
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	h := NewHandler(nil)
	cfg := RootConfigData{
		Prefix:         "local/files/test/",
		FilesystemRoot: tmpDir,
	}
	if err := h.AddRoot("test", cfg, cs, li); err != nil {
		t.Fatalf("add root: %v", err)
	}

	hctx := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  li,
		HandlerPattern: "local/files",
	}
	return h, hctx, tmpDir
}

func withResource(hctx *handler.HandlerContext, path string) *handler.HandlerContext {
	cp := *hctx
	cp.Resource = &types.ResourceTarget{Targets: []string{path}}
	return &cp
}

func makeWriteParams(data []byte, createDirs bool) entity.Entity {
	d := WriteRequestData{Bytes: data, CreateDirs: createDirs}
	raw, _ := ecf.Encode(d)
	ent, _ := entity.NewEntity(TypeWriteRequest, cbor.RawMessage(raw))
	return ent
}

func makeWriteParamsContent(blobHash hash.Hash, createDirs bool) entity.Entity {
	d := WriteRequestData{Content: &blobHash, CreateDirs: createDirs}
	raw, _ := ecf.Encode(d)
	ent, _ := entity.NewEntity(TypeWriteRequest, cbor.RawMessage(raw))
	return ent
}

// ingestTestBlob chunks data via FastCDC and persists the blob + chunks
// in the content store, returning the blob hash. Tests use this when
// they need a pre-existing blob to drive a `content`-mode write or to
// stage a reverse-write file entity.
func ingestTestBlob(t *testing.T, cs store.ContentStore, data []byte) hash.Hash {
	t.Helper()
	ranges := chunker.ChunkFastCDC(data, types.DefaultChunkSize)
	blobEnt, chunkEntities, err := content.BuildBlob(data, ranges, types.ChunkingFastCDC, types.DefaultChunkSize)
	if err != nil {
		t.Fatalf("build blob: %v", err)
	}
	for _, c := range chunkEntities {
		if _, err := cs.Put(c); err != nil {
			t.Fatalf("put chunk: %v", err)
		}
	}
	h, err := cs.Put(blobEnt)
	if err != nil {
		t.Fatalf("put blob: %v", err)
	}
	return h
}

// TestReadUTF8 writes a UTF-8 file and reads it via the handler.
// Verifies the v1.2 file entity shape (Content as blob hash), the
// CONTENT v3.6 substrate plumbing (blob + chunks in store), and the
// §4.3 small-file inline-include in the response envelope.
func TestReadUTF8(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)
	body := "Hello, world!\nLine 2\n"

	if err := os.WriteFile(filepath.Join(tmpDir, "hello.txt"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "read",
		Context:   withResource(hctx, "local/files/test/hello.txt"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	if resp.Result.Type != TypeFile {
		t.Fatalf("expected type %s, got %s", TypeFile, resp.Result.Type)
	}

	fileData, err := FileDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fileData.Path != "hello.txt" {
		t.Errorf("expected path 'hello.txt', got %q", fileData.Path)
	}
	if fileData.Content.IsZero() {
		t.Fatal("expected non-zero content blob hash")
	}
	if fileData.Size != uint64(len(body)) {
		t.Errorf("expected size %d, got %d", len(body), fileData.Size)
	}
	if fileData.MediaType == nil || *fileData.MediaType == "" {
		t.Error("expected media_type to be guessed for .txt")
	}

	// Blob is in the content store and reassembles to the original bytes.
	blobEnt, ok := hctx.Store.Get(fileData.Content)
	if !ok {
		t.Fatal("blob entity not found in store")
	}
	got, err := reassembleBlob(hctx.Store, blobEnt)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if string(got) != body {
		t.Errorf("reassembled body mismatch: got %q", string(got))
	}

	// §4.3 inline-include: small files carry the blob + chunks alongside
	// the result so the caller can verify without a follow-up get.
	if _, ok := resp.Included[fileData.Content]; !ok {
		t.Error("expected blob in resp.Included for small file")
	}

	// File entity is bound in the tree.
	fh, ok := hctx.LocationIndex.Get("local/files/test/hello.txt")
	if !ok {
		t.Fatal("file entity not in location index")
	}
	if fh.IsZero() {
		t.Fatal("file hash is zero")
	}
}

// TestReadBinary verifies binary bytes round-trip without any encoding
// indirection. v1.2 carries raw bytes through the content substrate;
// there is no utf8/base64 split on the file entity itself.
func TestReadBinary(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	binData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	if err := os.WriteFile(filepath.Join(tmpDir, "data.bin"), binData, 0644); err != nil {
		t.Fatal(err)
	}

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "read",
		Context:   withResource(hctx, "local/files/test/data.bin"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status: %d", resp.Status)
	}

	fileData, _ := FileDataFromEntity(resp.Result)
	blobEnt, ok := hctx.Store.Get(fileData.Content)
	if !ok {
		t.Fatal("blob entity not in store")
	}
	got, err := reassembleBlob(hctx.Store, blobEnt)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if string(got) != string(binData) {
		t.Errorf("binary content mismatch: got %x", got)
	}
}

// TestReadNotFound verifies 404 for missing files.
func TestReadNotFound(t *testing.T) {
	h, hctx, _ := newTestHandler(t)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "read",
		Context:   withResource(hctx, "local/files/test/nonexistent.txt"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404, got %d", resp.Status)
	}
}

// TestReadNoRootMapping verifies 404 for paths outside any root.
func TestReadNoRootMapping(t *testing.T) {
	h, hctx, _ := newTestHandler(t)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "read",
		Context:   withResource(hctx, "other/path/file.txt"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404, got %d", resp.Status)
	}
}

// TestWrite writes content via Bytes mode and verifies it appears on disk.
func TestWrite(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	body := []byte("Written content\n")
	params := makeWriteParams(body, false)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "write",
		Params:    params,
		Context:   withResource(hctx, "local/files/test/output.txt"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	fileData, _ := FileDataFromEntity(resp.Result)
	if !fileData.Written {
		t.Error("expected written=true")
	}
	if fileData.Path != "output.txt" {
		t.Errorf("expected path 'output.txt', got %q", fileData.Path)
	}
	if fileData.Content.IsZero() {
		t.Error("expected non-zero content blob hash on write")
	}

	diskContent, err := os.ReadFile(filepath.Join(tmpDir, "output.txt"))
	if err != nil {
		t.Fatalf("read disk: %v", err)
	}
	if string(diskContent) != string(body) {
		t.Errorf("disk content mismatch: %q", string(diskContent))
	}

	if _, ok := hctx.LocationIndex.Get("local/files/test/output.txt"); !ok {
		t.Fatal("file not in location index after write")
	}
}

// TestWriteContentMode exercises the v1.2 dedup write: a blob already
// in the content store can be projected to disk by hash reference,
// without re-sending the bytes.
func TestWriteContentMode(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	body := []byte("dedup write payload\n")
	blobHash := ingestTestBlob(t, hctx.Store, body)

	params := makeWriteParamsContent(blobHash, false)
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "write",
		Params:    params,
		Context:   withResource(hctx, "local/files/test/dedup.txt"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	fileData, _ := FileDataFromEntity(resp.Result)
	if fileData.Content != blobHash {
		t.Errorf("content mode should round-trip the input blob hash; got %v want %v", fileData.Content, blobHash)
	}

	disk, err := os.ReadFile(filepath.Join(tmpDir, "dedup.txt"))
	if err != nil {
		t.Fatalf("read disk: %v", err)
	}
	if string(disk) != string(body) {
		t.Errorf("dedup-mode disk content mismatch: %q", string(disk))
	}
}

// TestWriteRejectsBothInputs guards the §5.4 invariant: exactly one
// of bytes / content MUST be set.
func TestWriteRejectsBothInputs(t *testing.T) {
	h, hctx, _ := newTestHandler(t)

	blobHash := ingestTestBlob(t, hctx.Store, []byte("x"))
	d := WriteRequestData{Bytes: []byte("y"), Content: &blobHash}
	raw, _ := ecf.Encode(d)
	params, _ := entity.NewEntity(TypeWriteRequest, cbor.RawMessage(raw))

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "write",
		Params:    params,
		Context:   withResource(hctx, "local/files/test/both.txt"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 400 {
		t.Errorf("expected 400 when both bytes+content set, got %d", resp.Status)
	}
}

// TestWriteCreateDirs verifies that create_dirs creates parent directories.
func TestWriteCreateDirs(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	params := makeWriteParams([]byte("nested content"), true)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "write",
		Params:    params,
		Context:   withResource(hctx, "local/files/test/a/b/c/deep.txt"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	diskContent, err := os.ReadFile(filepath.Join(tmpDir, "a", "b", "c", "deep.txt"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(diskContent) != "nested content" {
		t.Errorf("content mismatch: %q", string(diskContent))
	}
}

// TestWriteReadOnly verifies that writes to read-only roots are rejected.
func TestWriteReadOnly(t *testing.T) {
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	h := NewHandler(nil)
	cfg := RootConfigData{
		Prefix:         "local/files/ro/",
		FilesystemRoot: tmpDir,
		ReadOnly:       true,
	}
	h.AddRoot("ro", cfg, cs, li)

	hctx := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  li,
		HandlerPattern: "local/files",
		Resource:       &types.ResourceTarget{Targets: []string{"local/files/ro/file.txt"}},
	}

	params := makeWriteParams([]byte("test"), false)
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "write",
		Params:    params,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403, got %d", resp.Status)
	}
}

// TestList verifies directory listing.
func TestList(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("bb"), 0644)
	os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "list",
		Context:   withResource(hctx, "local/files/test/"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	dirData, err := DirectoryDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dirData.Children) != 3 {
		t.Fatalf("expected 3 children, got %d", len(dirData.Children))
	}

	entries := make(map[string]string)
	for _, c := range dirData.Children {
		entries[c.Name] = c.EntryType
	}
	if entries["file1.txt"] != "file" {
		t.Errorf("expected file1.txt to be 'file', got %q", entries["file1.txt"])
	}
	if entries["subdir"] != "directory" {
		t.Errorf("expected subdir to be 'directory', got %q", entries["subdir"])
	}
}

// TestListExclude verifies exclude patterns filter directory entries.
func TestListExclude(t *testing.T) {
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	h := NewHandler(nil)
	cfg := RootConfigData{
		Prefix:         "local/files/ex/",
		FilesystemRoot: tmpDir,
		Exclude:        []string{"*.tmp", ".git"},
	}
	h.AddRoot("ex", cfg, cs, li)

	os.WriteFile(filepath.Join(tmpDir, "keep.txt"), []byte("keep"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "skip.tmp"), []byte("skip"), 0644)
	os.Mkdir(filepath.Join(tmpDir, ".git"), 0755)

	hctx := &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  li,
		HandlerPattern: "local/files",
		Resource:       &types.ResourceTarget{Targets: []string{"local/files/ex/"}},
	}

	resp, _ := h.Handle(context.Background(), &handler.Request{
		Operation: "list",
		Context:   hctx,
	})
	dirData, _ := DirectoryDataFromEntity(resp.Result)
	if len(dirData.Children) != 1 {
		t.Fatalf("expected 1 child after exclude, got %d", len(dirData.Children))
	}
	if dirData.Children[0].Name != "keep.txt" {
		t.Errorf("expected 'keep.txt', got %q", dirData.Children[0].Name)
	}
}

// TestDelete verifies file deletion.
func TestDelete(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	filePath := filepath.Join(tmpDir, "to-delete.txt")
	os.WriteFile(filePath, []byte("bye"), 0644)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "delete",
		Context:   withResource(hctx, "local/files/test/to-delete.txt"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	if resp.Result.Type != TypeDeleted {
		t.Fatalf("expected type %s, got %s", TypeDeleted, resp.Result.Type)
	}

	var d DeletedData
	ecf.Decode(resp.Result.Data, &d)
	if !d.Existed {
		t.Error("expected existed=true")
	}
	if d.Path != "to-delete.txt" {
		t.Errorf("expected path 'to-delete.txt', got %q", d.Path)
	}

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("file should be deleted from disk")
	}
}

// TestDeleteNonExistent verifies deleting a file that doesn't exist.
func TestDeleteNonExistent(t *testing.T) {
	h, hctx, _ := newTestHandler(t)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "delete",
		Context:   withResource(hctx, "local/files/test/no-such-file.txt"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	var d DeletedData
	ecf.Decode(resp.Result.Data, &d)
	if d.Existed {
		t.Error("expected existed=false")
	}
}

// TestPathTraversal verifies that path traversal attempts are rejected.
func TestPathTraversal(t *testing.T) {
	h, hctx, _ := newTestHandler(t)

	for _, path := range []string{
		"local/files/test/../../../etc/passwd",
		"local/files/test/../../etc/shadow",
	} {
		resp, err := h.Handle(context.Background(), &handler.Request{
			Operation: "read",
			Context:   withResource(hctx, path),
		})
		if err != nil {
			t.Fatalf("error for %s: %v", path, err)
		}
		if resp.Status != 403 && resp.Status != 404 {
			t.Errorf("expected 403 or 404 for path %q, got %d", path, resp.Status)
		}
	}
}

// TestContentDedup verifies that identical content produces the same content entity hash.
func TestContentDedup(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	content := "duplicate content\n"
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte(content), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte(content), 0644)

	resp1, _ := h.Handle(context.Background(), &handler.Request{
		Operation: "read",
		Context:   withResource(hctx, "local/files/test/file1.txt"),
	})
	resp2, _ := h.Handle(context.Background(), &handler.Request{
		Operation: "read",
		Context:   withResource(hctx, "local/files/test/file2.txt"),
	})

	fd1, _ := FileDataFromEntity(resp1.Result)
	fd2, _ := FileDataFromEntity(resp2.Result)

	if fd1.Content != fd2.Content {
		t.Errorf("content blob hashes should be equal for identical content: %v != %v", fd1.Content, fd2.Content)
	}
}

// TestReverseWrite verifies that tree events cause filesystem writes.
func TestReverseWrite(t *testing.T) {
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	h := NewHandler(nil)
	cfg := RootConfigData{
		Prefix:         "local/files/rev/",
		FilesystemRoot: tmpDir,
	}
	h.AddRoot("rev", cfg, cs, li)

	const testPeerID = "TestPeer1234567890abcdefghijklmnopqrstuvwxyz01"
	events := make(chan store.TreeChangeEvent, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h.StartReverseWrite(ctx, events, cs, li, testPeerID)

	body := []byte("reverse written content")
	blobHash := ingestTestBlob(t, cs, body)

	fileData := FileData{
		Path:    "reverse.txt",
		Size:    uint64(len(body)),
		Content: blobHash,
	}
	fileEntity, _ := fileData.ToEntity()
	fh, _ := cs.Put(fileEntity)
	li.Set("local/files/rev/reverse.txt", fh)

	// Send tree event (qualified path — as fan-out delivers it).
	events <- store.TreeChangeEvent{
		Path:       "/" + testPeerID + "/local/files/rev/reverse.txt",
		PeerID:     testPeerID,
		Hash:       fh,
		ChangeType: store.ChangeCreated,
	}

	// Wait for the reverse write loop to process.
	time.Sleep(200 * time.Millisecond)

	diskContent, err := os.ReadFile(filepath.Join(tmpDir, "reverse.txt"))
	if err != nil {
		t.Fatalf("read reverse-written file: %v", err)
	}
	if string(diskContent) != "reverse written content" {
		t.Errorf("reverse write content mismatch: %q", string(diskContent))
	}
}

// TestReverseWriteSkipsIdentical verifies loop prevention (§5.3).
func TestReverseWriteSkipsIdentical(t *testing.T) {
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	h := NewHandler(nil)
	cfg := RootConfigData{
		Prefix:         "local/files/skip/",
		FilesystemRoot: tmpDir,
	}
	h.AddRoot("skip", cfg, cs, li)

	// Write file to disk first.
	content := "already here"
	os.WriteFile(filepath.Join(tmpDir, "existing.txt"), []byte(content), 0644)

	const testPeerID = "TestPeer1234567890abcdefghijklmnopqrstuvwxyz01"
	events := make(chan store.TreeChangeEvent, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h.StartReverseWrite(ctx, events, cs, li, testPeerID)

	blobHash := ingestTestBlob(t, cs, []byte(content))

	fileData := FileData{
		Path:    "existing.txt",
		Size:    uint64(len(content)),
		Content: blobHash,
	}
	fileEntity, _ := fileData.ToEntity()
	fh, _ := cs.Put(fileEntity)

	// Record mtime before.
	infoBefore, _ := os.Stat(filepath.Join(tmpDir, "existing.txt"))
	mtimeBefore := infoBefore.ModTime()

	// Send event (qualified path) — should be skipped due to content hash match.
	events <- store.TreeChangeEvent{
		Path:       "/" + testPeerID + "/local/files/skip/existing.txt",
		PeerID:     testPeerID,
		Hash:       fh,
		ChangeType: store.ChangeModified,
	}

	time.Sleep(200 * time.Millisecond)

	infoAfter, _ := os.Stat(filepath.Join(tmpDir, "existing.txt"))
	if infoAfter.ModTime() != mtimeBefore {
		t.Error("file should not have been rewritten (content hash match)")
	}
}

// TestManifest verifies the handler manifest has expected operations.
func TestManifest(t *testing.T) {
	h := NewHandler(nil)
	m := h.Manifest()

	if m.Pattern != "local/files" {
		t.Errorf("expected pattern 'local/files', got %q", m.Pattern)
	}
	if m.Name != "local-files" {
		t.Errorf("expected name 'local-files', got %q", m.Name)
	}

	expectedOps := []string{"read", "write", "list", "delete", "watch"}
	for _, op := range expectedOps {
		if _, ok := m.Operations[op]; !ok {
			t.Errorf("missing operation %q in manifest", op)
		}
	}
}

// TestLoadRehydratesRootsFromTree verifies the restart-equivalence shape:
// a fresh Handler bound to a content store + location index that already
// contains a system/config/local/files/{name} entity recovers the root
// mapping via Load and can serve operations against it without needing
// AddRoot to be re-invoked.
func TestLoadRehydratesRootsFromTree(t *testing.T) {
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// First Handler: register a root and persist its config to the tree.
	h1 := NewHandler(nil)
	cfg := RootConfigData{
		Prefix:         "local/files/test/",
		FilesystemRoot: tmpDir,
	}
	if err := h1.AddRoot("test", cfg, cs, li); err != nil {
		t.Fatalf("add root: %v", err)
	}

	// Simulate a restart: drop the handler, build a fresh one against the
	// same store + index, call Load. The new handler should see the root.
	h2 := NewHandler(nil)
	var zero hash.Hash
	if err := h2.Load(context.Background(), cs, li, zero); err != nil {
		t.Fatalf("load: %v", err)
	}

	h2.mu.Lock()
	got, ok := h2.roots["test"]
	h2.mu.Unlock()
	if !ok {
		t.Fatalf("root %q not loaded", "test")
	}
	if got.Prefix != "local/files/test/" {
		t.Fatalf("loaded prefix = %q, want %q", got.Prefix, "local/files/test/")
	}
	absRoot, _ := filepath.Abs(tmpDir)
	if got.FSRoot != absRoot {
		t.Fatalf("loaded FSRoot = %q, want %q", got.FSRoot, absRoot)
	}

	// Calling Load again must be idempotent — no error, same root present.
	if err := h2.Load(context.Background(), cs, li, zero); err != nil {
		t.Fatalf("second load: %v", err)
	}
	h2.mu.Lock()
	if _, ok := h2.roots["test"]; !ok {
		h2.mu.Unlock()
		t.Fatalf("root %q lost on second load", "test")
	}
	h2.mu.Unlock()

	// Stop any watchers spun up by Load before tear-down.
	h2.mu.Lock()
	for name, w := range h2.watchers {
		w.Stop()
		delete(h2.watchers, name)
	}
	h2.mu.Unlock()
}

// TestReadRejectsLeafSymlink verifies the L5 leaf-symlink defense (per
// DOMAIN-LOCAL-FILES v1.3 Amendment 1, pending normative landing): a
// symlink planted inside the root pointing to an arbitrary outside path
// MUST NOT be followed. Convergent with Rust C-1 and Python F-4 PoCs.
func TestReadRejectsLeafSymlink(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("OUTSIDE THE SANDBOX"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tmpDir, "escape")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "read",
		Context:   withResource(hctx, "local/files/test/escape"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403 path_traversal_rejected, got %d (result: %+v)", resp.Status, resp.Result)
	}
}

// TestWriteRejectsLeafSymlink — same defense on the write path.
func TestWriteRejectsLeafSymlink(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	outside := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(outside, []byte("untouched"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tmpDir, "escape")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "write",
		Context:   withResource(hctx, "local/files/test/escape"),
		Params:    makeWriteParams([]byte("overwritten"), false),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 403 {
		t.Fatalf("expected 403 path_traversal_rejected, got %d", resp.Status)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "untouched" {
		t.Fatalf("symlink target was modified: %q", string(got))
	}
}

// TestWriteRequestDataToEntityRoundtrip verifies the F6 ergonomic
// helper roundtrips through CBOR cleanly. Per workbench-go's
// consumer-integration feedback (Round 1), every consumer otherwise
// rewrites the ecf.Encode + entity.NewEntity + cbor.RawMessage boilerplate.
func TestWriteRequestDataToEntityRoundtrip(t *testing.T) {
	mt := "text/plain"
	original := WriteRequestData{
		Bytes:      []byte("hello world"),
		MediaType:  &mt,
		CreateDirs: true,
	}
	ent, err := original.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if ent.Type != TypeWriteRequest {
		t.Fatalf("expected type %s, got %s", TypeWriteRequest, ent.Type)
	}
	got, err := WriteRequestDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if string(got.Bytes) != string(original.Bytes) {
		t.Errorf("bytes mismatch: got %q", string(got.Bytes))
	}
	if got.MediaType == nil || *got.MediaType != mt {
		t.Errorf("media_type mismatch: %v", got.MediaType)
	}
	if !got.CreateDirs {
		t.Error("create_dirs lost in roundtrip")
	}
}

// TestWatchRequestDataToEntityRoundtrip — same shape, same fix.
func TestWatchRequestDataToEntityRoundtrip(t *testing.T) {
	debounce := uint64(1500)
	original := WatchRequestData{
		RootName:   "test",
		Action:     "start",
		DebounceMs: &debounce,
	}
	ent, err := original.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if ent.Type != TypeWatchRequest {
		t.Fatalf("expected type %s, got %s", TypeWatchRequest, ent.Type)
	}
	got, err := WatchRequestDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.RootName != "test" || got.Action != "start" {
		t.Errorf("string fields mismatched: %+v", got)
	}
	if got.DebounceMs == nil || *got.DebounceMs != 1500 {
		t.Errorf("debounce_ms mismatch: %v", got.DebounceMs)
	}
}

// TestUnknownOperation verifies that unknown operations return 400.
func TestUnknownOperation(t *testing.T) {
	h := NewHandler(nil)
	hctx := &handler.HandlerContext{}

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "bogus",
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d", resp.Status)
	}
}
