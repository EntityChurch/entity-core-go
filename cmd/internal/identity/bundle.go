// Package identity provides on-disk identity-bundle helpers for
// EXTENSION-IDENTITY-aware peers, per
// docs/architecture/proposals/active/DESIGN-IDENTITY-CONFIG-AND-PEER-MANAGEMENT.md
// §2.2 (Option C: SDK helper library both peer-manager and entity-cli call into).
//
// Bundle layout:
//
//	~/.entity/identities/<name>/
//	├── bundle.json              # which-is-which: pointers + metadata
//	├── quorum/
//	│   ├── definition.json      # K, signer_resolution mode
//	│   └── members/
//	│       └── <m1>/keypair     # PEM-like private key file
//	├── ops/
//	│   └── <op_v1>/keypair
//	└── public-identity.json     # Public_alice peer_id, attestation refs
//
// The flat legacy layout (`~/.entity/identities/<name>{,.json,.pub}`) coexists
// in the same parent. Identity-aware tools resolve `<name>/` as a directory;
// V7-only tools see it as a non-keypair file and skip.
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Bundle is an on-disk identity bundle's manifest. It points at the keypairs
// and attestation files that compose a single user's identity (per
// EXTENSION-IDENTITY §2 four-layer model).
type Bundle struct {
	Name             string         `json:"name"`
	Version          string         `json:"version"` // bundle-format version, currently "1"
	Mode             string         `json:"mode"`    // "simple" | "full-4-layer"
	CreatedAt        int64          `json:"created_at"`
	QuorumPeerIDs    []string       `json:"quorum_peer_ids"` // base58 peer IDs
	QuorumThreshold  int            `json:"quorum_threshold"`
	OpPeerIDs        []string       `json:"op_peer_ids"`        // base58 peer IDs
	PublicIdentityID string         `json:"public_identity_id"` // base58 peer ID
	Notes            string         `json:"notes,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// BootstrapOptions controls a fresh identity creation.
type BootstrapOptions struct {
	// Name is the bundle directory name under ~/.entity/identities/.
	Name string
	// Simple, when true, produces the §11.3 collapse: 1-of-1 quorum +
	// Op == Public_alice. The simplest valid identity-extension shape; one
	// keypair plays all four roles. Trades privacy/recovery for ergonomics.
	Simple bool
	// QuorumMembers, ignored when Simple is true, specifies how many quorum
	// constituent keypairs to generate. The on-disk member dirs are named
	// member-1, member-2, etc. for ergonomics; the actual identity is the
	// keypair's peer ID.
	QuorumMembers int
	// QuorumThreshold, ignored when Simple is true. Must be in [1, QuorumMembers].
	QuorumThreshold int
	// IdentitiesRoot overrides ~/.entity/identities/ for tests. Empty = default.
	IdentitiesRoot string
}

// BootstrapNewIdentity generates fresh keypairs and writes the on-disk bundle
// per the layout above. Returns the persisted bundle's absolute path and the
// in-memory Bundle metadata.
//
// Per the DESIGN doc Option C, this helper is invariant to which CLI calls it
// (peer-manager `identity init`, future entity-cli, application UI) — all paths
// produce the same on-disk shape.
func BootstrapNewIdentity(opts BootstrapOptions) (string, Bundle, error) {
	if opts.Name == "" {
		return "", Bundle{}, fmt.Errorf("bundle name required")
	}
	root, err := resolveIdentitiesRoot(opts.IdentitiesRoot)
	if err != nil {
		return "", Bundle{}, err
	}
	bundleDir := filepath.Join(root, opts.Name)
	if _, err := os.Stat(bundleDir); err == nil {
		return "", Bundle{}, fmt.Errorf("bundle %q already exists at %s", opts.Name, bundleDir)
	}
	if err := os.MkdirAll(bundleDir, 0700); err != nil {
		return "", Bundle{}, err
	}

	bundle := Bundle{
		Name:      opts.Name,
		Version:   "1",
		CreatedAt: time.Now().Unix(),
	}

	if opts.Simple {
		bundle.Mode = "simple"
		// Single keypair plays quorum (1-of-1), Op, and Public_alice.
		seed, peerID, err := writeKeypair(filepath.Join(bundleDir, "quorum", "members", "member-1"))
		if err != nil {
			return "", Bundle{}, err
		}
		bundle.QuorumPeerIDs = []string{peerID}
		bundle.QuorumThreshold = 1
		// Op + Public_alice both reuse the quorum keypair (collapse).
		// Persist the seed under ops/op-1/keypair too so the path layout is
		// uniform for tools.
		if err := writePrivateKeyFile(filepath.Join(bundleDir, "ops", "op-1", "keypair"), seed); err != nil {
			return "", Bundle{}, err
		}
		bundle.OpPeerIDs = []string{peerID}
		bundle.PublicIdentityID = peerID
	} else {
		bundle.Mode = "full-4-layer"
		if opts.QuorumMembers < 1 {
			opts.QuorumMembers = 1
		}
		if opts.QuorumThreshold < 1 || opts.QuorumThreshold > opts.QuorumMembers {
			opts.QuorumThreshold = opts.QuorumMembers
		}
		for i := 0; i < opts.QuorumMembers; i++ {
			memberName := fmt.Sprintf("member-%d", i+1)
			_, peerID, err := writeKeypair(filepath.Join(bundleDir, "quorum", "members", memberName))
			if err != nil {
				return "", Bundle{}, err
			}
			bundle.QuorumPeerIDs = append(bundle.QuorumPeerIDs, peerID)
		}
		bundle.QuorumThreshold = opts.QuorumThreshold
		// One Op keypair (additional Ops via add-op later).
		_, opPeerID, err := writeKeypair(filepath.Join(bundleDir, "ops", "op-1"))
		if err != nil {
			return "", Bundle{}, err
		}
		bundle.OpPeerIDs = []string{opPeerID}
		// Public_alice is a separate Alice-held keypair (§6.1 default custody).
		_, paPeerID, err := writeKeypair(filepath.Join(bundleDir, "public-identity"))
		if err != nil {
			return "", Bundle{}, err
		}
		bundle.PublicIdentityID = paPeerID
	}

	// Quorum definition (per the DESIGN doc; mirrors EXTENSION-IDENTITY §3.1).
	if err := writeJSON(filepath.Join(bundleDir, "quorum", "definition.json"), map[string]any{
		"signers":           bundle.QuorumPeerIDs,
		"threshold":         bundle.QuorumThreshold,
		"signer_resolution": "concrete",
	}); err != nil {
		return "", Bundle{}, err
	}

	// Public-identity sidecar.
	if err := writeJSON(filepath.Join(bundleDir, "public-identity.json"), map[string]any{
		"peer_id": bundle.PublicIdentityID,
		"label":   opts.Name,
	}); err != nil {
		return "", Bundle{}, err
	}

	// bundle.json — top-level manifest.
	if err := writeJSON(filepath.Join(bundleDir, "bundle.json"), bundle); err != nil {
		return "", Bundle{}, err
	}

	return bundleDir, bundle, nil
}

// LoadBundle reads a bundle from disk. Returns Bundle and the absolute
// directory path. Used by tools that consume an existing bundle.
func LoadBundle(name string, identitiesRoot string) (Bundle, string, error) {
	root, err := resolveIdentitiesRoot(identitiesRoot)
	if err != nil {
		return Bundle{}, "", err
	}
	bundleDir := filepath.Join(root, name)
	manifestPath := filepath.Join(bundleDir, "bundle.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return Bundle{}, "", fmt.Errorf("read bundle manifest at %s: %w", manifestPath, err)
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, "", fmt.Errorf("decode bundle manifest: %w", err)
	}
	return b, bundleDir, nil
}

// resolveIdentitiesRoot returns the configured identities root directory
// (override, or ~/.entity/identities/ by default).
func resolveIdentitiesRoot(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".entity", "identities"), nil
}

// writeKeypair generates a fresh Ed25519 keypair, writes
// {dir}/keypair (PEM-like seed) + {dir}/keypair.json (metadata), and returns
// the seed and computed peer ID.
func writeKeypair(dir string) ([]byte, string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, "", fmt.Errorf("generate keypair: %w", err)
	}
	seed := priv.Seed()
	peerID := derivePeerID(pub)

	if err := writePrivateKeyFile(filepath.Join(dir, "keypair"), seed); err != nil {
		return nil, "", err
	}
	if err := writeJSON(filepath.Join(dir, "keypair.json"), map[string]any{
		"created_at": time.Now().Unix(),
		"key_type":   "ed25519",
		"peer_id":    peerID,
		"public_key": base64.StdEncoding.EncodeToString(pub),
	}); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "keypair.pub"),
		[]byte(fmt.Sprintf("entity-ed25519 %s %s\n", base64.StdEncoding.EncodeToString(pub), peerID)),
		0644); err != nil {
		return nil, "", err
	}
	return seed, peerID, nil
}

func writePrivateKeyFile(path string, seed []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	content := fmt.Sprintf("-----BEGIN ENTITY PRIVATE KEY-----\n%s\n-----END ENTITY PRIVATE KEY-----\n",
		base64.StdEncoding.EncodeToString(seed))
	return os.WriteFile(path, []byte(content), 0600)
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

// derivePeerID builds the base58 peer ID from a public key.
// Format matches the existing convention in cmd/peer-manager/identity.go:
// Base58(0x01 || 0x01 || SHA256(public_key)).
func derivePeerID(pub ed25519.PublicKey) string {
	digest := sha256.Sum256(pub)
	pid := make([]byte, 34)
	pid[0] = 0x01 // key type: Ed25519
	pid[1] = 0x01 // hash type: SHA256
	copy(pid[2:], digest[:])
	return base58Encode(pid)
}

func base58Encode(input []byte) string {
	zeros := 0
	for _, b := range input {
		if b != 0 {
			break
		}
		zeros++
	}
	n := new(big.Int).SetBytes(input)
	mod := new(big.Int)
	base := big.NewInt(58)
	var result []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	prefix := make([]byte, zeros)
	for i := range prefix {
		prefix[i] = '1'
	}
	return string(append(prefix, result...))
}
