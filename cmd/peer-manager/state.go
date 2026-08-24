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

	// Owner tags the session that started this peer, from ENTITY_PEER_OWNER.
	//
	// WHY (2026-08-12): the state file is ONE file per host —
	// ~/.entity/peer-manager.json — and go, rust and py sessions all drive this
	// same tool against it. `stop --all` iterated every entry, so any session's
	// teardown killed every other session's peers. That is not hypothetical: a
	// core-rust session's `stop --all` stopped a peer named `pyf1` belonging to
	// the core-py session mid-run, and reported it.
	//
	// Empty means unattributed — a peer started before this field existed, or
	// by a session that set no owner. `stop --all` will not touch a peer whose
	// owner does not match the caller's; see cmdStop.
	Owner string `json:"owner,omitempty"`
}

// currentOwner is the caller's session tag. Empty is a legitimate value and
// means "unattributed": the caller cannot claim any peer, and `stop --all`
// degrades to refusing rather than to killing everything.
func currentOwner() string { return os.Getenv("ENTITY_PEER_OWNER") }

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
