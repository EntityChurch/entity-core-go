package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

func TestParsePeerConfig(t *testing.T) {
	data := `[peer]
listen_addr = "127.0.0.1:9000"
bootstrap_peers = []
max_connections = 100
`
	var cfg PeerConfig
	if err := toml.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Peer.ListenAddr != "127.0.0.1:9000" {
		t.Fatalf("expected 127.0.0.1:9000, got %s", cfg.Peer.ListenAddr)
	}
}

func TestParsePeerConfig_ExtraFields(t *testing.T) {
	// Unknown fields should be silently ignored.
	data := `[peer]
listen_addr = ":9005"

[storage]
backend = "memory"
`
	var cfg PeerConfig
	if err := toml.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Peer.ListenAddr != ":9005" {
		t.Fatalf("expected :9005, got %s", cfg.Peer.ListenAddr)
	}
}
