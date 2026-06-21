package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
)

// Keypair is the algorithm-agnostic peer signing keypair. KeyType selects
// the underlying cryptosystem; PrivateKey/PublicKey hold raw bytes whose
// length is determined by KeyType per the V7 crypto-agility model
// (V7 §1.5 / v7.66 §2 / v7.67 §3).
//
// V7.67 cohort decision: a single Keypair value type with runtime KeyType
// dispatch replaces the previous Ed25519-only Keypair + separate
// Ed448Keypair split. Sign/Verify/PeerID derivation route through the
// KeyType byte so the protocol surface is key-type-uniform end-to-end.
type Keypair struct {
	// KeyType selects the signing algorithm. One of KeyTypeEd25519 (0x01)
	// or KeyTypeEd448 (0x02). Zero value (0x00) indicates an unset keypair.
	KeyType byte

	// PrivateKey holds the expanded library-form private key bytes:
	//   Ed25519: 64 bytes (seed | public), per crypto/ed25519
	//   Ed448:   ed448.PrivateKeySize bytes, per cloudflare/circl
	PrivateKey []byte

	// PublicKey holds the raw public key bytes:
	//   Ed25519: 32 bytes
	//   Ed448:   57 bytes
	PublicKey []byte
}

// IsZero reports whether the keypair is the zero value (no KeyType set).
// Used as a sentinel for "no keypair available" returns from authority lookups.
func (k Keypair) IsZero() bool {
	return k.KeyType == 0 && len(k.PrivateKey) == 0 && len(k.PublicKey) == 0
}

// Generate creates a new random Ed25519 keypair. Retained for source-compat
// with the common-case ephemeral-peer path; use GenerateForKeyType to pick
// a non-default algorithm.
func Generate() (Keypair, error) {
	return GenerateForKeyType(KeyTypeEd25519)
}

// GenerateForKeyType creates a new random keypair for the given key_type.
// Supported: KeyTypeEd25519, KeyTypeEd448.
func GenerateForKeyType(keyType byte) (Keypair, error) {
	switch keyType {
	case KeyTypeEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Keypair{}, fmt.Errorf("crypto generate ed25519: %w", err)
		}
		return Keypair{
			KeyType:    KeyTypeEd25519,
			PrivateKey: []byte(priv),
			PublicKey:  []byte(pub),
		}, nil
	case KeyTypeEd448:
		pub, priv, err := ed448.GenerateKey(rand.Reader)
		if err != nil {
			return Keypair{}, fmt.Errorf("crypto generate ed448: %w", err)
		}
		return Keypair{
			KeyType:    KeyTypeEd448,
			PrivateKey: []byte(priv),
			PublicKey:  []byte(pub),
		}, nil
	default:
		return Keypair{}, fmt.Errorf("GenerateForKeyType: unsupported key_type 0x%02x", keyType)
	}
}

// FromSeed creates a deterministic Ed25519 keypair from a 32-byte seed.
// Retained for source-compat; use Ed448FromSeed for Ed448 seeds.
func FromSeed(seed [32]byte) Keypair {
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return Keypair{
		KeyType:    KeyTypeEd25519,
		PrivateKey: []byte(priv),
		PublicKey:  []byte(pub),
	}
}

// LoadIdentity loads a keypair from the ~/.entity/identities/ directory.
// The name parameter is the identity name (e.g., "framework-admin").
// Supports two on-disk layouts:
//
//   - Flat:   ~/.entity/identities/<name>            (PEM-like seed file)
//   - Bundle: ~/.entity/identities/<name>/ops/op-1/keypair
//
// Bundle layout is used by multi-layer identities (framework-admin et al.)
// where the op-layer keypair is the active signing key.
func LoadIdentity(name string) (Keypair, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Keypair{}, fmt.Errorf("get home dir: %w", err)
	}
	base := filepath.Join(home, ".entity", "identities", name)
	info, err := os.Stat(base)
	if err != nil {
		return Keypair{}, fmt.Errorf("stat identity %q: %w", name, err)
	}
	if info.IsDir() {
		return LoadIdentityFromFile(filepath.Join(base, "ops", "op-1", "keypair"))
	}
	return LoadIdentityFromFile(base)
}

// PEM headers for on-disk keypair seed files. v7.67 §6 (Phase 2 cohort
// convention): Ed25519 keeps the untagged header for source-compat with
// existing identities; new algorithms add a tag.
const (
	pemHeaderEd25519 = "-----BEGIN ENTITY PRIVATE KEY-----"
	pemFooterEd25519 = "-----END ENTITY PRIVATE KEY-----"
	pemHeaderEd448   = "-----BEGIN ENTITY ED448 PRIVATE KEY-----"
	pemFooterEd448   = "-----END ENTITY ED448 PRIVATE KEY-----"
)

// LoadIdentityFromFile loads a keypair from a PEM-like entity key file.
// Header tag selects the algorithm: untagged "ENTITY PRIVATE KEY" is
// Ed25519 (32-byte seed); "ENTITY ED448 PRIVATE KEY" is Ed448 (57-byte seed).
func LoadIdentityFromFile(path string) (Keypair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Keypair{}, fmt.Errorf("read key file: %w", err)
	}
	content := strings.TrimSpace(string(data))
	lines := strings.Split(content, "\n")
	if len(lines) < 3 {
		return Keypair{}, fmt.Errorf("invalid key file format: expected at least 3 lines")
	}
	header := strings.TrimSpace(lines[0])
	footer := strings.TrimSpace(lines[len(lines)-1])

	var b64Lines []string
	for _, line := range lines[1 : len(lines)-1] {
		b64Lines = append(b64Lines, strings.TrimSpace(line))
	}
	seed, err := base64.StdEncoding.DecodeString(strings.Join(b64Lines, ""))
	if err != nil {
		return Keypair{}, fmt.Errorf("decode key: %w", err)
	}

	switch header {
	case pemHeaderEd25519:
		if footer != pemFooterEd25519 {
			return Keypair{}, fmt.Errorf("PEM footer %q does not match header %q", footer, header)
		}
		if len(seed) != ed25519.SeedSize {
			return Keypair{}, fmt.Errorf("invalid Ed25519 seed size: got %d, want %d", len(seed), ed25519.SeedSize)
		}
		var seedArr [32]byte
		copy(seedArr[:], seed)
		return FromSeed(seedArr), nil
	case pemHeaderEd448:
		if footer != pemFooterEd448 {
			return Keypair{}, fmt.Errorf("PEM footer %q does not match header %q", footer, header)
		}
		if len(seed) != Ed448SeedLen {
			return Keypair{}, fmt.Errorf("invalid Ed448 seed size: got %d, want %d", len(seed), Ed448SeedLen)
		}
		var seedArr [Ed448SeedLen]byte
		copy(seedArr[:], seed)
		return Ed448FromSeed(seedArr), nil
	default:
		return Keypair{}, fmt.Errorf("unrecognized PEM header %q (supported: Ed25519, Ed448)", header)
	}
}

// LoadPeerKeypair loads a keypair from ~/.entity/peers/{name}/keypair.
func LoadPeerKeypair(name string) (Keypair, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Keypair{}, fmt.Errorf("get home dir: %w", err)
	}
	keyPath := filepath.Join(home, ".entity", "peers", name, "keypair")
	return LoadIdentityFromFile(keyPath)
}

// LookupKeypairByPeerID searches the standard on-disk identity locations for
// a keypair whose derived peer_id matches the given peerID, and returns it.
// Locations searched (in order):
//
//   - ~/.entity/peers/<name>/keypair  (Go entity-peer --name, Rust entity-cli)
//   - ~/.entity/identities/<name>     (Python and peer-manager identity scheme)
//
// Returns the matching keypair and the on-disk name used to reach it. The
// helper exists so cross-impl validation tools can find the on-disk private
// key for any peer they're connected to without needing the operator to
// supply names manually.
func LookupKeypairByPeerID(peerID string) (Keypair, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Keypair{}, "", fmt.Errorf("get home dir: %w", err)
	}

	// 1. ~/.entity/peers/*/keypair
	peersDir := filepath.Join(home, ".entity", "peers")
	if entries, err := os.ReadDir(peersDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			path := filepath.Join(peersDir, e.Name(), "keypair")
			kp, err := LoadIdentityFromFile(path)
			if err != nil {
				continue
			}
			if string(kp.PeerID()) == peerID {
				return kp, e.Name(), nil
			}
		}
	}

	// 2. ~/.entity/identities/*
	identsDir := filepath.Join(home, ".entity", "identities")
	if entries, err := os.ReadDir(identsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.ContainsAny(name, ".") {
				// Skip *.pub, *.json sidecars; only the bare-name file is the keypair.
				continue
			}
			path := filepath.Join(identsDir, name)
			kp, err := LoadIdentityFromFile(path)
			if err != nil {
				continue
			}
			if string(kp.PeerID()) == peerID {
				return kp, name, nil
			}
		}
	}

	return Keypair{}, "", fmt.Errorf("no on-disk keypair matched peer_id %s", peerID)
}

// SaveIdentity writes a keypair to ~/.entity/identities/{name} in PEM format.
// Creates the directory if needed. Private key file is mode 0600.
func SaveIdentity(name string, kp Keypair) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, ".entity", "identities")
	return SaveIdentityToDir(dir, name, kp)
}

// SaveIdentityToDir writes a keypair to dir/{name} in PEM format.
// Creates the directory if needed. Private key file is mode 0600. The
// PEM header tag tracks kp.KeyType so a round-trip through
// LoadIdentityFromFile reproduces the same algorithm.
func SaveIdentityToDir(dir, name string, kp Keypair) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create identity dir: %w", err)
	}

	seed := kp.Seed()
	if seed == nil {
		return fmt.Errorf("SaveIdentityToDir: keypair has no recoverable seed for key_type 0x%02x", kp.KeyType)
	}

	var header, footer string
	switch kp.KeyType {
	case KeyTypeEd25519:
		header, footer = pemHeaderEd25519, pemFooterEd25519
	case KeyTypeEd448:
		header, footer = pemHeaderEd448, pemFooterEd448
	default:
		return fmt.Errorf("SaveIdentityToDir: unsupported key_type 0x%02x", kp.KeyType)
	}

	pem := header + "\n" +
		base64.StdEncoding.EncodeToString(seed) + "\n" +
		footer + "\n"
	keyPath := filepath.Join(dir, name)
	if err := os.WriteFile(keyPath, []byte(pem), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// Public key sidecar (untagged — the .pub file is purely informational
	// and never consumed by Load; readers go through the private key file).
	pubB64 := base64.StdEncoding.EncodeToString(kp.PublicKeyBytes())
	pubPath := keyPath + ".pub"
	pubContent := "-----BEGIN ENTITY PUBLIC KEY-----\n" + pubB64 + "\n-----END ENTITY PUBLIC KEY-----\n"
	if err := os.WriteFile(pubPath, []byte(pubContent), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

// ListIdentities returns the names of all identities in ~/.entity/identities/.
func ListIdentities() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	return ListIdentitiesInDir(filepath.Join(home, ".entity", "identities"))
}

// ListIdentitiesInDir returns identity names from a directory.
// Identities are files without extensions (excludes .pub, .json, etc.).
func ListIdentitiesInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read identities dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.Contains(name, ".") {
			continue // skip .pub, .json sidecars
		}
		names = append(names, name)
	}
	return names, nil
}

// Sign signs the message with the keypair's algorithm. The message is
// typically the full content_hash wire bytes (algorithm + digest). Panics
// on an unset KeyType — well-formed keypairs from Generate / FromSeed /
// Ed448FromSeed / LoadIdentityFromFile always carry a valid KeyType.
func (k Keypair) Sign(message []byte) []byte {
	switch k.KeyType {
	case KeyTypeEd25519:
		return ed25519.Sign(ed25519.PrivateKey(k.PrivateKey), message)
	case KeyTypeEd448:
		return ed448.Sign(ed448.PrivateKey(k.PrivateKey), message, "")
	default:
		panic(fmt.Sprintf("Keypair.Sign: unsupported key_type 0x%02x", k.KeyType))
	}
}

// Verify checks a signature against (keyType, publicKey, message). The
// verifier dispatches on keyType — callers obtain it from the signer's
// PeerData.KeyType (entity-data string converted via KeyTypeByte) or the
// peer_id's leading varint via Decode().
func Verify(keyType byte, publicKey, message, signature []byte) bool {
	switch keyType {
	case KeyTypeEd25519:
		if len(publicKey) != Ed25519PublicKeyLen {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
	case KeyTypeEd448:
		if len(publicKey) != Ed448PublicKeyLen {
			return false
		}
		if len(signature) != Ed448SignatureLen {
			return false
		}
		return ed448.Verify(ed448.PublicKey(publicKey), message, signature, "")
	default:
		return false
	}
}

// PublicKeyBytes returns the raw public key bytes (32 for Ed25519, 57 for
// Ed448).
func (k Keypair) PublicKeyBytes() []byte {
	return k.PublicKey
}

// Seed returns the raw seed bytes for on-disk serialization. 32 bytes for
// Ed25519, 57 bytes for Ed448. Returns nil if KeyType is unset / unknown.
func (k Keypair) Seed() []byte {
	switch k.KeyType {
	case KeyTypeEd25519:
		if len(k.PrivateKey) != ed25519.PrivateKeySize {
			return nil
		}
		return ed25519.PrivateKey(k.PrivateKey).Seed()
	case KeyTypeEd448:
		if len(k.PrivateKey) < Ed448SeedLen {
			return nil
		}
		out := make([]byte, Ed448SeedLen)
		copy(out, k.PrivateKey[:Ed448SeedLen])
		return out
	default:
		return nil
	}
}
