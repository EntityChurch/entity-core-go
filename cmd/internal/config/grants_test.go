package config

import (
	"os"
	"path/filepath"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// Test peer IDs — proper 46-char Base58 format.
const (
	testAdminPeer   = "2KS7wDt4QQhFph3BrGbrwrgtx28DkphxsbbWSVCea5JnPt"
	testReaderPeer  = "3MbGtargetPeerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	testUnknownPeer = "4NcHremotePeerCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

const testGrantsTOML = `[groups.admin]
resources = ["*"]
operations = ["*"]
description = "Full access to all resources"
members = ["2KS7wDt4QQhFph3BrGbrwrgtx28DkphxsbbWSVCea5JnPt"]

[groups.readers]
resources = ["system/type/*"]
operations = ["get"]
description = "Read-only access to types"
members = ["2ABC123"]
`

func TestLoadGrantsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grants.toml")
	if err := os.WriteFile(path, []byte(testGrantsTOML), 0644); err != nil {
		t.Fatal(err)
	}

	var gf GrantsFile
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Use the toml package directly since LoadGrants depends on PeerDir.
	if err := parseGrantsTOML(data, &gf); err != nil {
		t.Fatal(err)
	}

	if len(gf.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(gf.Groups))
	}

	admin := gf.Groups["admin"]
	if len(admin.Members) != 1 {
		t.Fatalf("expected 1 admin member, got %d", len(admin.Members))
	}
	if admin.Members[0] != "2KS7wDt4QQhFph3BrGbrwrgtx28DkphxsbbWSVCea5JnPt" {
		t.Fatalf("unexpected admin member: %s", admin.Members[0])
	}
}

func TestBuildGrantResolver_Admin(t *testing.T) {
	gf := &GrantsFile{
		Groups: map[string]GrantGroup{
			"admin": {
				Resources:  []string{"*"},
				Operations: []string{"*"},
				Members:    []string{testAdminPeer},
			},
		},
	}

	resolver := gf.BuildGrantResolver()

	// Admin peer should get wildcard grants.
	grants := resolver(crypto.PeerID(testAdminPeer), hash.Hash{})
	if grants == nil {
		t.Fatal("expected grants for admin peer")
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant entry, got %d", len(grants))
	}
	if grants[0].Handlers.Include[0] != "*" {
		t.Fatalf("expected wildcard handler, got %s", grants[0].Handlers.Include[0])
	}
	if grants[0].Resources.Include[0] != "*" {
		t.Fatalf("expected wildcard resource, got %s", grants[0].Resources.Include[0])
	}
}

func TestBuildGrantResolver_ScopedGroup(t *testing.T) {
	gf := &GrantsFile{
		Groups: map[string]GrantGroup{
			"readers": {
				Resources:  []string{"system/type/*"},
				Operations: []string{"get"},
				Members:    []string{testReaderPeer},
			},
		},
	}

	resolver := gf.BuildGrantResolver()

	grants := resolver(crypto.PeerID(testReaderPeer), hash.Hash{})
	if grants == nil {
		t.Fatal("expected grants for reader peer")
	}
	if grants[0].Resources.Include[0] != "system/type/*" {
		t.Fatalf("expected scoped resource, got %s", grants[0].Resources.Include[0])
	}
	if grants[0].Operations.Include[0] != "get" {
		t.Fatalf("expected get operation, got %s", grants[0].Operations.Include[0])
	}
}

func TestBuildGrantResolver_UnknownPeer(t *testing.T) {
	gf := &GrantsFile{
		Groups: map[string]GrantGroup{
			"admin": {
				Resources:  []string{"*"},
				Operations: []string{"*"},
				Members:    []string{testAdminPeer},
			},
		},
	}

	resolver := gf.BuildGrantResolver()

	// Unknown peer should get nil (fall through to defaults).
	grants := resolver(crypto.PeerID(testUnknownPeer), hash.Hash{})
	if grants != nil {
		t.Fatal("expected nil grants for unknown peer")
	}
}

func TestSummary(t *testing.T) {
	gf := &GrantsFile{
		Groups: map[string]GrantGroup{
			"admin": {Members: []string{"a", "b"}},
		},
	}
	s := gf.Summary()
	if s != "admin: 2 members" {
		t.Fatalf("unexpected summary: %s", s)
	}
}

func TestSummary_Empty(t *testing.T) {
	gf := &GrantsFile{}
	if gf.Summary() != "no grant groups" {
		t.Fatalf("unexpected summary: %s", gf.Summary())
	}
}

// parseGrantsTOML is a test helper that wraps toml.Unmarshal.
func parseGrantsTOML(data []byte, gf *GrantsFile) error {
	return parseGrants(data, gf)
}
