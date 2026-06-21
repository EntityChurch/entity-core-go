package config

import (
	"fmt"
	"os"
	"path/filepath"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/BurntSushi/toml"
)

// GrantGroup defines a named group of grants with member peer IDs.
type GrantGroup struct {
	Resources   []string `toml:"resources"`
	Operations  []string `toml:"operations"`
	Description string   `toml:"description"`
	Members     []string `toml:"members"`
}

// GrantsFile is the top-level structure of grants.toml.
type GrantsFile struct {
	Groups map[string]GrantGroup `toml:"groups"`
}

// LoadGrants loads grants.toml from ~/.entity/peers/{name}/.
func LoadGrants(name string) (*GrantsFile, error) {
	dir, err := PeerDir(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "grants.toml")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}

	var gf GrantsFile
	if err := parseGrants(data, &gf); err != nil {
		return nil, err
	}
	return &gf, nil
}

func parseGrants(data []byte, gf *GrantsFile) error {
	if err := toml.Unmarshal(data, gf); err != nil {
		return fmt.Errorf("parse grants.toml: %w", err)
	}
	return nil
}

// BuildGrantResolver creates a GrantResolver from a GrantsFile.
// Admin group members get full wildcard grants. Other group members get
// grants scoped to the group's resources and operations. Unknown peers
// return nil (fall through to default grants).
func (gf *GrantsFile) BuildGrantResolver() protocol.GrantResolver {
	// Build peer ID → grants mapping.
	peerGrants := make(map[crypto.PeerID][]types.GrantEntry)

	for groupName, group := range gf.Groups {
		var entries []types.GrantEntry
		if groupName == "admin" {
			// Admin gets full wildcard access.
			entries = []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}}
		} else {
			// Non-admin groups get scoped access.
			entries = []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: group.Resources},
				Operations: types.CapabilityScope{Include: group.Operations},
			}}
		}
		for _, memberID := range group.Members {
			peerGrants[crypto.PeerID(memberID)] = entries
		}
	}

	return func(remotePeerID crypto.PeerID, _ hash.Hash) []types.GrantEntry {
		if grants, ok := peerGrants[remotePeerID]; ok {
			return grants
		}
		return nil // fall through to defaults
	}
}

// Summary returns a human-readable summary of the grant groups.
func (gf *GrantsFile) Summary() string {
	if len(gf.Groups) == 0 {
		return "no grant groups"
	}
	s := ""
	for name, group := range gf.Groups {
		if s != "" {
			s += ", "
		}
		s += fmt.Sprintf("%s: %d members", name, len(group.Members))
	}
	return s
}
