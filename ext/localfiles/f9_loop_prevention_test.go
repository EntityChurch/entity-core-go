package localfiles

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/store"
)

// The reverse-write loop's echo guard is CONTENT identity, not a recent-write
// clock (workbench-go row 2). These tests pin the two behaviours the old clock
// got wrong — a genuine second update and a genuine delete within a burst — and
// the F9 loop-closure property the content check now carries.

// sendReverseWriteEvent stages a file entity + tree binding and delivers a
// ChangeCreated/Modified tree event to a running reverse-write loop, returning
// once the loop has processed it (observed via a settle poll on disk).
func stageFile(t *testing.T, cs store.ContentStore, li store.LocationIndex, treePath string, body []byte) store.TreeChangeEvent {
	t.Helper()
	blobHash := ingestTestBlob(t, cs, body)
	fileData := FileData{Path: filepath.Base(treePath), Size: uint64(len(body)), Content: blobHash}
	fileEntity, _ := fileData.ToEntity()
	fh, _ := cs.Put(fileEntity)
	li.Set(treePath, fh)
	return store.TreeChangeEvent{
		Path:       "/" + revTestPeerID + "/" + treePath,
		PeerID:     revTestPeerID,
		Hash:       fh,
		ChangeType: store.ChangeModified,
	}
}

const revTestPeerID = "TestPeer1234567890abcdefghijklmnopqrstuvwxyz01"

// TestReverseWrite_GenuineSecondUpdateLands is the row-2 teeth for the write
// path: a genuine second update to a path shortly after the first MUST reach
// disk. The old 5s clock dropped it (event discarded, not deferred), so tree
// and disk diverged permanently. The content check lets it through because the
// disk content differs from the new blob.
//
// Mutation witness: re-introduce a recent-write drop-gate keyed on the path and
// this test reds (disk stays at "first").
func TestReverseWrite_GenuineSecondUpdateLands(t *testing.T) {
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	h := NewHandler(nil)
	if err := h.AddRoot("rev", RootConfigData{Prefix: "local/files/rev/", FilesystemRoot: tmpDir}, cs, li); err != nil {
		t.Fatalf("AddRoot: %v", err)
	}
	events := make(chan store.TreeChangeEvent, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.StartReverseWrite(ctx, events, cs, li, revTestPeerID)

	const treePath = "local/files/rev/burst.txt"
	fsPath := filepath.Join(tmpDir, "burst.txt")

	events <- stageFile(t, cs, li, treePath, []byte("first"))
	waitForDisk(t, fsPath, "first")

	// A genuine second update immediately after — must land, not be dropped.
	events <- stageFile(t, cs, li, treePath, []byte("second"))
	waitForDisk(t, fsPath, "second")
}

// TestReverseWrite_DeleteWithinBurstLands is the row-2 teeth for the delete
// path: a delete shortly after a write MUST remove the file. The old clock had
// no second line of defence on the delete path, so a delete inside the window
// was dropped for good.
func TestReverseWrite_DeleteWithinBurstLands(t *testing.T) {
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	h := NewHandler(nil)
	if err := h.AddRoot("rev", RootConfigData{Prefix: "local/files/rev/", FilesystemRoot: tmpDir}, cs, li); err != nil {
		t.Fatalf("AddRoot: %v", err)
	}
	events := make(chan store.TreeChangeEvent, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.StartReverseWrite(ctx, events, cs, li, revTestPeerID)

	const treePath = "local/files/rev/gone.txt"
	fsPath := filepath.Join(tmpDir, "gone.txt")

	events <- stageFile(t, cs, li, treePath, []byte("here"))
	waitForDisk(t, fsPath, "here")

	// Delete immediately after — must remove the file, not be dropped.
	events <- store.TreeChangeEvent{
		Path:       "/" + revTestPeerID + "/" + treePath,
		PeerID:     revTestPeerID,
		ChangeType: store.ChangeDeleted,
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(fsPath); os.IsNotExist(err) {
			return // deleted — good
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("delete within burst did not reach disk — the file survives (row 2 delete path)")
}

// TestF9_LoopClosedByContentCheck pins the F9 loop-closure property on the
// content check that replaced the clock: re-delivering the SAME content event
// is a no-op (no rewrite, mtime unchanged), so the write/notify loop converges.
// This is the guard that closes the reverse-write side of the F9 self-loop; the
// clock is gone but the loop stays closed.
func TestF9_LoopClosedByContentCheck(t *testing.T) {
	tmpDir := t.TempDir()
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	h := NewHandler(nil)
	if err := h.AddRoot("rev", RootConfigData{Prefix: "local/files/rev/", FilesystemRoot: tmpDir}, cs, li); err != nil {
		t.Fatalf("AddRoot: %v", err)
	}
	events := make(chan store.TreeChangeEvent, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.StartReverseWrite(ctx, events, cs, li, revTestPeerID)

	const treePath = "local/files/rev/echo.txt"
	fsPath := filepath.Join(tmpDir, "echo.txt")

	echo := stageFile(t, cs, li, treePath, []byte("same content"))
	events <- echo
	waitForDisk(t, fsPath, "same content")
	info1, err := os.Stat(fsPath)
	if err != nil {
		t.Fatalf("stat after first write: %v", err)
	}

	// Re-deliver the identical event (the echo the loop would otherwise chase).
	time.Sleep(30 * time.Millisecond)
	events <- echo
	// Settle: send a sentinel event on another path and wait for its effect,
	// so the echo has provably been processed to a decision.
	events <- stageFile(t, cs, li, "local/files/rev/sentinel.txt", []byte("sentinel"))
	waitForDisk(t, filepath.Join(tmpDir, "sentinel.txt"), "sentinel")

	info2, err := os.Stat(fsPath)
	if err != nil {
		t.Fatalf("stat after echo: %v", err)
	}
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatal("echo re-wrote the file (mtime changed) — the content check did not close the loop")
	}
}

func waitForDisk(t *testing.T, fsPath, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(fsPath); err == nil && string(b) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := "<absent>"
	if b, err := os.ReadFile(fsPath); err == nil {
		got = string(b)
	}
	t.Fatalf("disk at %s did not reach %q in time; got %q", fsPath, want, got)
}
