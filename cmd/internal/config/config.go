package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// PeerConfig holds the peer configuration from config.toml.
// Only the fields the Go peer uses are decoded; the rest are ignored.
type PeerConfig struct {
	Peer struct {
		ListenAddr string `toml:"listen_addr"`
	} `toml:"peer"`
}

// LoadPeerConfig loads config.toml from ~/.entity/peers/{name}/.
func LoadPeerConfig(name string) (*PeerConfig, error) {
	dir, err := PeerDir(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "config.toml")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg PeerConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config.toml: %w", err)
	}
	return &cfg, nil
}
