package main

import (
	"fmt"
	"os"
	"strings"
)

func cmdList() {
	state, err := loadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading state: %v\n", err)
		os.Exit(1)
	}

	if len(state.Peers) == 0 {
		fmt.Println("No managed peers.")
		return
	}

	fmt.Printf("%-15s %-6s %-8s %-25s %-50s %7s  %-8s\n", "NAME", "TYPE", "STORAGE", "ADDR", "PEER_ID", "PID", "STATUS")
	fmt.Printf("%-15s %-6s %-8s %-25s %-50s %7s  %-8s\n", "----", "----", "-------", "----", "-------", "---", "------")

	for name, entry := range state.Peers {
		status := "running"
		if !isAlive(entry.PID) {
			status = "dead"
		}
		peerType := entry.Type
		if peerType == "" {
			peerType = "go"
		}
		storage := entry.Storage
		if storage == "" {
			storage = "memory"
		}
		fmt.Printf("%-15s %-6s %-8s %-25s %-50s %7d  %-8s\n", name, peerType, storage, entry.Addr, entry.PeerID, entry.PID, status)
		_ = name
	}
}

func cmdAddr(name string) {
	state, err := loadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	entry, ok := state.Peers[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "Peer %q not found\n", name)
		os.Exit(1)
	}
	fmt.Print(entry.Addr)
}

func cmdPeerID(name string) {
	state, err := loadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	entry, ok := state.Peers[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "Peer %q not found\n", name)
		os.Exit(1)
	}
	fmt.Print(entry.PeerID)
}

func cmdLogs(name string) {
	state, err := loadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	entry, ok := state.Peers[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "Peer %q not found\n", name)
		os.Exit(1)
	}
	if entry.LogFile == "" {
		fmt.Fprintf(os.Stderr, "No log file for peer %q\n", name)
		os.Exit(1)
	}
	fmt.Println(entry.LogFile)
}

func cmdAddrs(names string) {
	state, err := loadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	parts := strings.Split(names, ",")
	var addrs []string
	for _, name := range parts {
		name = strings.TrimSpace(name)
		entry, ok := state.Peers[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "Peer %q not found\n", name)
			os.Exit(1)
		}
		addrs = append(addrs, entry.Addr)
	}
	fmt.Print(strings.Join(addrs, ","))
}

// cmdWSAddrs prints the comma-separated WebSocket URLs (ws://addr/ws)
// for the named peers, in input order. Skips peers without --ws-addr
// by emitting an empty slot so the index alignment with `addrs` is
// preserved — `validate-peer -peers $A,$B,$C -ws-peers $WA,$WB,$WC`
// pairs by index.
func cmdWSAddrs(names string) {
	state, err := loadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	parts := strings.Split(names, ",")
	var urls []string
	for _, name := range parts {
		name = strings.TrimSpace(name)
		entry, ok := state.Peers[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "Peer %q not found\n", name)
			os.Exit(1)
		}
		if entry.WSAddr == "" {
			urls = append(urls, "")
			continue
		}
		urls = append(urls, "ws://"+entry.WSAddr+"/ws")
	}
	fmt.Print(strings.Join(urls, ","))
}
