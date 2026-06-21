package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"

	"github.com/mr-tron/base58"
)

// ensureIdentity creates a peer identity at ~/.entity/identities/<name>
// if it doesn't already exist. The PEM seed file + .pub sidecar match
// what every cross-impl loader recognizes. keyType selects the
// cryptosystem: "ed25519" (default) or "ed448" (v7.67 §3).
func ensureIdentity(name, keyType string) error {
	if keyType == "" {
		keyType = "ed25519"
	}
	ktByte, ok := crypto.KeyTypeByte(keyType)
	if !ok {
		return fmt.Errorf("ensureIdentity: unsupported key_type %q (want ed25519 or ed448)", keyType)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	identDir := filepath.Join(home, ".entity", "identities")
	jsonPath := filepath.Join(identDir, name+".json")

	if _, err := os.Stat(jsonPath); err == nil {
		// V7 v7.66 §4.4 guard: an existing identity file may carry a
		// non-canonical peer_id from a pre-canonical-cleanup era. The
		// running peer derives its peer_id one way; consumers reading
		// the .json get the stored form. If they diverge, chain-walk
		// rejects ("Root capability not granted by local peer"). Detect
		// + refuse here so the user explicitly regenerates rather than
		// silently propagating staleness.
		if err := validateStoredPeerIDCanonical(jsonPath); err != nil {
			return fmt.Errorf("stale identity %q: %w (recovery: move %s and rerun to mint fresh under v7.66 §4.4 canonical form)",
				name, err, jsonPath)
		}
		return nil
	}

	if err := os.MkdirAll(identDir, 0755); err != nil {
		return err
	}

	kp, err := crypto.GenerateForKeyType(ktByte)
	if err != nil {
		return fmt.Errorf("generate %s keypair: %w", keyType, err)
	}

	if err := crypto.SaveIdentityToDir(identDir, name, kp); err != nil {
		return fmt.Errorf("save identity: %w", err)
	}

	peerID := string(kp.PeerID())
	pubB64 := base64.StdEncoding.EncodeToString(kp.PublicKeyBytes())

	// JSON metadata sidecar — informational, consumed by `peer-manager
	// identity show`. The PEM file is the source of truth for loading.
	meta := map[string]any{
		"created_at": time.Now().Unix(),
		"key_type":   keyType,
		"peer_id":    peerID,
		"public_key": pubB64,
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Created identity %q (peer_id=%s, key_type=%s)\n", name, peerID, keyType)
	return nil
}

// validateStoredPeerIDCanonical loads name.json and verifies the stored
// peer_id matches the canonical form V7 v7.66 §4.4 + crypto.CanonicalHashType
// requires for the file's key_type. Returns nil iff canonical. The check
// is purely structural — it decodes the stored peer_id, compares the
// hash_type byte to the canonical pair for the key_type, and reports any
// mismatch. Non-canonical files were widespread in pre-v7.66 stores;
// re-using them surfaces as cross-impl chain-root mismatches.
func validateStoredPeerIDCanonical(jsonPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("read identity metadata: %w", err)
	}
	var m struct {
		PeerID  string `json:"peer_id"`
		KeyType string `json:"key_type"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse identity metadata: %w", err)
	}
	if m.PeerID == "" || m.KeyType == "" {
		return nil // missing fields — skip (not stale, just incomplete metadata)
	}
	pidBytes, err := base58.Decode(m.PeerID)
	if err != nil || len(pidBytes) < 2 {
		return fmt.Errorf("decode peer_id: %v", err)
	}
	storedHT := pidBytes[1]
	ktByte, ok := crypto.KeyTypeByte(m.KeyType)
	if !ok {
		return nil // unknown key_type — defer to runtime
	}
	canonicalHT, err := crypto.CanonicalHashType(ktByte)
	if err != nil {
		return nil // canonical not defined — defer
	}
	if storedHT != canonicalHT {
		return fmt.Errorf("stored peer_id hash_type=0x%02x is non-canonical for key_type=%s (canonical=0x%02x per V7 v7.66 §4.4)",
			storedHT, m.KeyType, canonicalHT)
	}
	return nil
}

// ensurePeerKeypair creates a keypair at ~/.entity/peers/<name>/keypair
// if it doesn't already exist. Used by startGoPeer so the peer has a stable
// identity that external tools (e.g., validate-peer multi-sig convergence
// tests) can load to produce attributable signatures.
//
// keyType selects the algorithm: "ed25519" (default) or "ed448" (v7.67).
// The PEM header tracks the algorithm so a Go peer reading the file
// (LoadPeerKeypair → LoadIdentityFromFile) dispatches correctly.
func ensurePeerKeypair(name, keyType string) error {
	if keyType == "" {
		keyType = "ed25519"
	}
	ktByte, ok := crypto.KeyTypeByte(keyType)
	if !ok {
		return fmt.Errorf("ensurePeerKeypair: unsupported key_type %q", keyType)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	peerDir := filepath.Join(home, ".entity", "peers", name)
	keyPath := filepath.Join(peerDir, "keypair")

	if _, err := os.Stat(keyPath); err == nil {
		return nil
	}

	if err := os.MkdirAll(peerDir, 0755); err != nil {
		return err
	}

	kp, err := crypto.GenerateForKeyType(ktByte)
	if err != nil {
		return fmt.Errorf("generate %s keypair: %w", keyType, err)
	}

	if err := crypto.SaveIdentityToDir(peerDir, "keypair", kp); err != nil {
		return fmt.Errorf("save peer keypair: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Created peer keypair %q (peer_id=%s, key_type=%s)\n", name, kp.PeerID(), keyType)
	return nil
}
