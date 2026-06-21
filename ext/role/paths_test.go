package role

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// peerHex is the 66-char hex form of makeFakeHash(0xab).
const peerHex = "00abababababababababababababababababababababababababababababababab"
const peerHexB = "00cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

func TestParseAssignmentPath(t *testing.T) {
	cases := []struct {
		path        string
		wantOK      bool
		wantContext string
		wantPeerHex string
		wantRole    string
	}{
		{"system/role/admin/assignment/" + peerHex + "/operator", true, "admin", peerHex, "operator"},
		{"system/role/group/team-alpha/assignment/" + peerHexB + "/member", true, "group/team-alpha", peerHexB, "member"},
		{"system/role/admin/assignment/" + peerHex, true, "admin", peerHex, ""},
		{"system/role/admin/excluded/" + peerHex, false, "", "", ""},
		{"system/role//assignment/" + peerHex + "/role", false, "", "", ""},
		{"system/role/admin/assignment/", false, "", "", ""},
		{"system/role/admin/assignment", false, "", "", ""},
		{"system/role/admin/assignment/Z123/role", false, "", "", ""}, // not hex
		{"foo/bar", false, "", "", ""},
	}
	for _, c := range cases {
		got, ok := ParseAssignmentPath(c.path)
		if ok != c.wantOK {
			t.Errorf("ParseAssignmentPath(%q) ok=%v, want %v", c.path, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if got.Context != c.wantContext || HashHex(got.PeerHash) != c.wantPeerHex || got.Role != c.wantRole {
			t.Errorf("ParseAssignmentPath(%q) = {ctx=%q peer=%s role=%q}, want {ctx=%q peer=%s role=%q}",
				c.path, got.Context, HashHex(got.PeerHash), got.Role,
				c.wantContext, c.wantPeerHex, c.wantRole)
		}
	}
}

func TestParseExclusionPath(t *testing.T) {
	cases := []struct {
		path        string
		wantOK      bool
		wantContext string
		wantPeerHex string
	}{
		{"system/role/admin/excluded/" + peerHex, true, "admin", peerHex},
		{"system/role/group/team-alpha/excluded/" + peerHexB, true, "group/team-alpha", peerHexB},
		{"system/role/admin/excluded/" + peerHex + "/extra", false, "", ""},
		{"system/role/admin/excluded/", false, "", ""},
		{"system/role/admin/excluded", false, "", ""},
		{"system/role/admin/excluded/Z123", false, "", ""}, // not hex
		{"system/role/admin/assignment/" + peerHex + "/role", false, "", ""},
	}
	for _, c := range cases {
		got, ok := ParseExclusionPath(c.path)
		if ok != c.wantOK {
			t.Errorf("ParseExclusionPath(%q) ok=%v, want %v", c.path, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if got.Context != c.wantContext || HashHex(got.PeerHash) != c.wantPeerHex {
			t.Errorf("ParseExclusionPath(%q) = {ctx=%q peer=%s}, want {ctx=%q peer=%s}",
				c.path, got.Context, HashHex(got.PeerHash),
				c.wantContext, c.wantPeerHex)
		}
	}
}

func TestParseRoleDefinitionPath(t *testing.T) {
	cases := []struct {
		path        string
		wantOK      bool
		wantContext string
		wantRole    string
	}{
		{"system/role/admin/operator", true, "admin", "operator"},
		{"system/role/group/team-alpha/member", true, "group/team-alpha", "member"},
		{"system/role/admin/assignment", false, "", ""},     // R10 reserved
		{"system/role/admin/excluded", false, "", ""},       // R10 reserved
		{"system/role/admin/derived-tokens", false, "", ""}, // R10 reserved (v1.6 SI-5)
		{"system/role/admin/assignment/abc/role", false, "", ""},
		{"system/role/admin/excluded/abc", false, "", ""},
		{"system/role/admin/derived-tokens/abc/role", false, "", ""},
		{"system/role/admin", false, "", ""},
		{"system/role/", false, "", ""},
		{"system/role", false, "", ""},
		{"foo/bar/baz", false, "", ""},
	}
	for _, c := range cases {
		got, ok := ParseRoleDefinitionPath(c.path)
		if ok != c.wantOK {
			t.Errorf("ParseRoleDefinitionPath(%q) ok=%v, want %v", c.path, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if got.Context != c.wantContext || got.RoleName != c.wantRole {
			t.Errorf("ParseRoleDefinitionPath(%q) = %+v, want context=%q role=%q",
				c.path, got, c.wantContext, c.wantRole)
		}
	}
}

func TestIsReservedRoleName(t *testing.T) {
	if !IsReservedRoleName("assignment") {
		t.Error("assignment must be reserved (R10)")
	}
	if !IsReservedRoleName("excluded") {
		t.Error("excluded must be reserved (R10)")
	}
	if !IsReservedRoleName("derived-tokens") {
		t.Error("derived-tokens must be reserved (v1.6 SI-5)")
	}
	if IsReservedRoleName("operator") {
		t.Error("operator is not a reserved name")
	}
	if IsReservedRoleName("") {
		t.Error("empty string is not a reserved name")
	}
}

func TestIsRoleManagedPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"system/role", true},
		{"system/role/admin/operator", true},
		{"system/role/group/team-alpha/excluded/xyz", true},
		{"system/role/group/team-alpha/derived-tokens/xyz/member", true},
		{"system/capability/grants/role-derived/admin/abc/hash", false},
		{"system/role-manager", false},
		{"foo", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsRoleManagedPath(c.path); got != c.want {
			t.Errorf("IsRoleManagedPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestPathBuildersUseHexEncoding(t *testing.T) {
	// Per v1.6 SI-1 / SI-2, all non-root path segments encoding peer
	// references or hashes use lowercase hex of system/hash (66 chars
	// starting with 00 for ECFv1-SHA-256). Verify the path builders
	// produce that form.
	peer := makeFakeHash(0xab)
	tok := makeFakeHash(0xcd)

	asn := AssignmentPath("admin", peer, "operator")
	if asn != "system/role/admin/assignment/"+peerHex+"/operator" {
		t.Errorf("AssignmentPath = %q", asn)
	}
	excl := ExclusionPath("admin", peer)
	if excl != "system/role/admin/excluded/"+peerHex {
		t.Errorf("ExclusionPath = %q", excl)
	}
	link := DerivedTokenLinkPath("admin", peer, "operator")
	if link != "system/role/admin/derived-tokens/"+peerHex+"/operator" {
		t.Errorf("DerivedTokenLinkPath = %q", link)
	}
	cap := RoleDerivedTokenPath("admin", peer, tok)
	wantTokHex := HashHex(tok)
	want := "system/capability/grants/role-derived/admin/" + peerHex + "/" + wantTokHex
	if cap != want {
		t.Errorf("RoleDerivedTokenPath = %q, want %q", cap, want)
	}
}

// ensure we don't accidentally re-import crypto.PeerID elsewhere
var _ = hash.AlgorithmSHA256
