package peer

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWithSeedPolicyFromFile_KeystoneCanonical locks go's seed-policy reader to
// the keystone-owned canonical §6.9a format
// (protocol-generator/shared/seed-policy/seed-policy.schema.json):
//
//	{"version":1,"entries":[{"grantee":"<self|default|hex|base58>",
//	                         "grants":[<§3.6 grant-entry, lowercase fields>...]}]}
//
// It replaced go's earlier non-canonical shape ([{pattern,grants}] with
// capitalized Go grant fields). If this fails, go has drifted off the cross-impl
// format again — the exact divergence routed to the peers on 2026-08-14.
func TestWithSeedPolicyFromFile_KeystoneCanonical(t *testing.T) {
	doc := `{
	  "version": 1,
	  "entries": [
	    { "grantee": "self", "grants": [] },
	    { "grantee": "0098ddb68a95829a86dd50f328062fadb1926c3667866e4b389b161dfcf3c2a556",
	      "grants": [
	        { "handlers": {"include": ["*"]},
	          "resources": {"include": ["*", "/*/*"]},
	          "operations": {"include": ["*"]} }
	      ] },
	    { "grantee": "default",
	      "grants": [
	        { "handlers": {"include": ["system/tree"]},
	          "resources": {"include": ["system/type/*", "system/handler/*"]},
	          "operations": {"include": ["get"]} }
	      ] }
	  ]
	}`
	p := filepath.Join(t.TempDir(), "seed.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &config{}
	WithSeedPolicyFromFile(p)(c)

	// "self" is materialized from the owner identity, not the file, so it is
	// skipped: 3 entries in → 2 seeded.
	if len(c.seedPolicy) != 2 {
		t.Fatalf("expected 2 seed entries (self skipped), got %d", len(c.seedPolicy))
	}

	// grantee → Pattern, and the lowercase §3.6 grant fields must have parsed.
	admin := c.seedPolicy[0]
	if admin.Pattern != "0098ddb68a95829a86dd50f328062fadb1926c3667866e4b389b161dfcf3c2a556" {
		t.Fatalf("admin grantee not mapped to Pattern: %q", admin.Pattern)
	}
	if len(admin.Grants) != 1 ||
		len(admin.Grants[0].Handlers.Include) != 1 || admin.Grants[0].Handlers.Include[0] != "*" ||
		len(admin.Grants[0].Operations.Include) != 1 || admin.Grants[0].Operations.Include[0] != "*" {
		t.Fatalf("admin grant did not parse from lowercase §3.6 fields: %+v", admin.Grants)
	}
	if c.seedPolicy[1].Pattern != "default" {
		t.Fatalf("second entry should be the default floor, got %q", c.seedPolicy[1].Pattern)
	}
}

// TestWithSeedPolicyFromFile_RejectsWrongVersion asserts the schema's version
// gate: a non-1 version is refused rather than silently mis-read.
func TestWithSeedPolicyFromFile_RejectsWrongVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "seed.json")
	if err := os.WriteFile(p, []byte(`{"version":2,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on unsupported schema version, got none")
		}
	}()
	WithSeedPolicyFromFile(p)(&config{})
}
