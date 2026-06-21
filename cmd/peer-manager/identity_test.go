package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// V7 v7.66 §4.4 canonical guard. Pre-cleanup stores held Ed25519
// peer_ids under hash_type=0x01 (SHA-256-form) while v7.66 pins
// hash_type=0x00 (identity-form) for Ed25519. validateStoredPeerIDCanonical
// must reject the stale form so callers regenerate before chain-walk
// rejects the resulting cap as "root not granted by local peer".
func TestValidateStoredPeerIDCanonical(t *testing.T) {
	tests := []struct {
		name       string
		meta       map[string]string
		wantErrSub string // empty → expect nil
	}{
		{
			name: "canonical Ed25519 identity-form (passes)",
			meta: map[string]string{
				"key_type":   "ed25519",
				"peer_id":    "2K8Yx7iGyDhmsPBi9rrVGe92KDLUREruayDFQfQv8UPAi2", // hash_type=0x00
				"public_key": "Ru0avmuLYdubAp3CR/Idpnt6E28GpWGO9XW77VzJR88=",
			},
		},
		{
			name: "stale Ed25519 SHA-256-form (rejected)",
			meta: map[string]string{
				"key_type":   "ed25519",
				"peer_id":    "2KXjSkTvqZU8yp6HpaTmSzXhSxaqi5X7BAymXUugT1dtoj", // hash_type=0x01
				"public_key": "Ru0avmuLYdubAp3CR/Idpnt6E28GpWGO9XW77VzJR88=",
			},
			wantErrSub: "non-canonical for key_type=ed25519",
		},
		{
			name: "missing key_type field (defers to runtime, passes)",
			meta: map[string]string{
				"peer_id": "2K8Yx7iGyDhmsPBi9rrVGe92KDLUREruayDFQfQv8UPAi2",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "test.json")
			data, err := json.Marshal(tc.meta)
			if err != nil {
				t.Fatalf("marshal meta: %v", err)
			}
			if err := os.WriteFile(path, data, 0644); err != nil {
				t.Fatalf("write meta: %v", err)
			}
			err = validateStoredPeerIDCanonical(path)
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErrSub)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErrSub)
			}
		})
	}
}
