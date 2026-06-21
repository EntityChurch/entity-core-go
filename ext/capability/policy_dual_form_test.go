package capability

import (
	"crypto/sha256"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"

	"github.com/mr-tron/base58"
)

// POL-DF-6 (invalid peer_pattern): attempt to configure with a peer_pattern
// that's neither hex nor Base58 nor `default`; expect rejection.
func TestPOLDF6_ValidatePeerPattern_InvalidRejected(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		wantErr string
	}{
		{"empty", "", "invalid_peer_pattern"},
		{"glob_star", "*", "wildcards are rejected"},
		{"glob_in_hex", "ab*ef", "wildcards are rejected"},
		{"short_garbage", "deadbeef", "neither valid hex"},
		{"hex_wrong_length", strings.Repeat("a", 60), "neither valid hex"},
		{"non_hex_at_hex_length", strings.Repeat("z", 66), "non-hex character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePeerPattern(tc.pattern)
			if err == nil {
				t.Fatalf("validatePeerPattern(%q): want error, got nil", tc.pattern)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validatePeerPattern(%q): error %q does not mention %q", tc.pattern, err.Error(), tc.wantErr)
			}
		})
	}
}

// POL-DF accepted shapes (the dual-form expansion): hex, Base58, default.
func TestValidatePeerPattern_AcceptedShapes(t *testing.T) {
	// 66-char hex
	hex66 := strings.Repeat("0a", 33)
	if err := validatePeerPattern(hex66); err != nil {
		t.Fatalf("validatePeerPattern(hex66): %v", err)
	}
	// default literal
	if err := validatePeerPattern("default"); err != nil {
		t.Fatalf("validatePeerPattern(\"default\"): %v", err)
	}
	// Base58 PeerID from a real identity-form keypair (v7.64 default).
	kp, _ := crypto.Generate()
	pid := string(kp.PeerID())
	if err := validatePeerPattern(pid); err != nil {
		t.Fatalf("validatePeerPattern(Base58 PeerID): %v", err)
	}
	// SHA-256-form PeerID (legacy) should also be accepted at the policy
	// validation boundary per v7.65 §5 wire-acceptance carve-out (MAY decode).
	// v7.66 §3.4: SHA-256-form is constructed inline as an opaque wire
	// input — no mint API post-§3 legacy rip. Layout per V7 §1.5:
	// Base58(0x01 || 0x01 || sha256(pub)).
	sum := sha256.Sum256(kp.PublicKey)
	sha256PidBytes := append([]byte{crypto.KeyTypeEd25519, crypto.HashTypeSHA256}, sum[:]...)
	sha256Pid := crypto.PeerID(base58.Encode(sha256PidBytes))
	if err := validatePeerPattern(string(sha256Pid)); err != nil {
		t.Fatalf("validatePeerPattern(SHA-256 PeerID): %v", err)
	}
}
