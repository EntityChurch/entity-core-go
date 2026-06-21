package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapNewIdentity_Simple(t *testing.T) {
	tmp := t.TempDir()
	dir, b, err := BootstrapNewIdentity(BootstrapOptions{
		Name:           "alice",
		Simple:         true,
		IdentitiesRoot: tmp,
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if b.Mode != "simple" {
		t.Errorf("expected mode=simple, got %s", b.Mode)
	}
	if len(b.QuorumPeerIDs) != 1 {
		t.Errorf("expected 1 quorum peer, got %d", len(b.QuorumPeerIDs))
	}
	if b.QuorumPeerIDs[0] != b.PublicIdentityID || b.PublicIdentityID != b.OpPeerIDs[0] {
		t.Errorf("simple mode should collapse all roles to one peer ID")
	}
	for _, want := range []string{
		"bundle.json",
		"quorum/definition.json",
		"quorum/members/member-1/keypair",
		"quorum/members/member-1/keypair.json",
		"ops/op-1/keypair",
		"public-identity.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("missing %s: %v", want, err)
		}
	}
}

func TestBootstrapNewIdentity_FullKofN(t *testing.T) {
	tmp := t.TempDir()
	dir, b, err := BootstrapNewIdentity(BootstrapOptions{
		Name:            "alice",
		Simple:          false,
		QuorumMembers:   3,
		QuorumThreshold: 2,
		IdentitiesRoot:  tmp,
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if b.Mode != "full-4-layer" {
		t.Errorf("expected mode=full-4-layer, got %s", b.Mode)
	}
	if len(b.QuorumPeerIDs) != 3 {
		t.Errorf("expected 3 quorum members, got %d", len(b.QuorumPeerIDs))
	}
	if b.QuorumThreshold != 2 {
		t.Errorf("expected threshold=2, got %d", b.QuorumThreshold)
	}
	// Public_alice is a separate keypair (not collapsed).
	if b.PublicIdentityID == b.OpPeerIDs[0] {
		t.Error("full-4-layer should have distinct PI and Op")
	}
	for i := 1; i <= 3; i++ {
		if _, err := os.Stat(filepath.Join(dir, "quorum", "members", "member-"+itoa(i), "keypair")); err != nil {
			t.Errorf("missing member-%d keypair", i)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "public-identity", "keypair")); err != nil {
		t.Errorf("missing public-identity keypair: %v", err)
	}
}

func TestBootstrapNewIdentity_RefusesExistingBundle(t *testing.T) {
	tmp := t.TempDir()
	if _, _, err := BootstrapNewIdentity(BootstrapOptions{
		Name: "alice", Simple: true, IdentitiesRoot: tmp,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := BootstrapNewIdentity(BootstrapOptions{
		Name: "alice", Simple: true, IdentitiesRoot: tmp,
	}); err == nil {
		t.Error("second bootstrap with same name should error")
	}
}

func TestLoadBundle_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	_, written, err := BootstrapNewIdentity(BootstrapOptions{
		Name: "alice", Simple: true, IdentitiesRoot: tmp,
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, _, err := LoadBundle("alice", tmp)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Name != "alice" || loaded.Mode != written.Mode || loaded.PublicIdentityID != written.PublicIdentityID {
		t.Errorf("loaded bundle mismatch: got %+v want %+v", loaded, written)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
