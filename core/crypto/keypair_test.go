package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadIdentity(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := SaveIdentityToDir(dir, "test-id", kp); err != nil {
		t.Fatal(err)
	}

	// Private key file should exist with restrictive permissions.
	info, err := os.Stat(filepath.Join(dir, "test-id"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	// Public key file should exist.
	if _, err := os.Stat(filepath.Join(dir, "test-id.pub")); err != nil {
		t.Fatal(err)
	}

	// Round-trip: load and verify same keys.
	loaded, err := LoadIdentityFromFile(filepath.Join(dir, "test-id"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PeerID() != kp.PeerID() {
		t.Fatalf("PeerID mismatch after round-trip: %s != %s", loaded.PeerID(), kp.PeerID())
	}
}

func TestListIdentitiesInDir(t *testing.T) {
	dir := t.TempDir()

	// Create a few identities.
	for _, name := range []string{"alice", "bob"} {
		kp, _ := Generate()
		if err := SaveIdentityToDir(dir, name, kp); err != nil {
			t.Fatal(err)
		}
	}

	names, err := ListIdentitiesInDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(names) != 2 {
		t.Fatalf("expected 2 identities, got %d: %v", len(names), names)
	}

	// Should not include .pub files.
	for _, n := range names {
		if n != "alice" && n != "bob" {
			t.Fatalf("unexpected identity name: %s", n)
		}
	}
}

func TestListIdentitiesInDir_Empty(t *testing.T) {
	dir := t.TempDir()
	names, err := ListIdentitiesInDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected 0 identities, got %d", len(names))
	}
}
