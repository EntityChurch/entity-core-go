package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
)

// PeerEntry tracks a running peer process.
type PeerEntry struct {
	PID       int    `json:"pid"`
	Addr      string `json:"addr"`
	WSAddr    string `json:"ws_addr,omitempty"` // Thread F (NETWORK §6.5.2b) — present iff peer started with --ws-addr
	PeerID    string `json:"peer_id"`
	Name      string `json:"name"`
	Type      string `json:"type"`                // "go", "rust", "python"
	Storage   string `json:"storage,omitempty"`   // "memory", "sqlite"
	Container string `json:"container,omitempty"` // podman container name (rust/python run as containers; empty for host-process go peer)
	ReadyFile string `json:"ready_file"`
	LogFile   string `json:"log_file"`
	StartedAt string `json:"started_at"`
}

// State is the peer-manager state file.
type State struct {
	Peers map[string]*PeerEntry `json:"peers"`
}

func stateDir() string {
	dir := os.Getenv("ENTITY_STATE_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".entity")
	}
	return dir
}

func stateFilePath() string {
	return filepath.Join(stateDir(), "peer-manager.json")
}

func loadState() (*State, error) {
	path := stateFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{Peers: make(map[string]*PeerEntry)}, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.Peers == nil {
		s.Peers = make(map[string]*PeerEntry)
	}
	return &s, nil
}

func saveState(s *State) error {
	path := stateFilePath()
	os.MkdirAll(filepath.Dir(path), 0755)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// isAlive checks if a process is still running.
func isAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 checks for process existence without sending a signal.
	return proc.Signal(syscall.Signal(0)) == nil
}
