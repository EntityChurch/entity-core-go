package main

import (
	"fmt"
	"sort"
)

func cmdInfo(sh *Shell, args []string) error {
	// If alias specified, show that peer.
	if len(args) > 0 {
		alias := args[0]
		pc, ok := sh.conns[alias]
		if !ok {
			return fmt.Errorf("not connected: %s", alias)
		}
		printPeerInfo(pc)
		return nil
	}

	// If inside a peer, show that peer.
	if pc := sh.connForWD(); pc != nil {
		printPeerInfo(pc)
		return nil
	}

	// At root: show all connections.
	if len(sh.conns) == 0 {
		fmt.Println("No connections")
		return nil
	}

	aliases := make([]string, 0, len(sh.conns))
	for a := range sh.conns {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)

	for _, a := range aliases {
		printPeerInfo(sh.conns[a])
		fmt.Println()
	}
	return nil
}

func printPeerInfo(pc *PeerConn) {
	fmt.Printf("Alias:   %s\n", pc.Alias)
	fmt.Printf("Address: %s\n", pc.Addr)
	fmt.Printf("PeerID:  %s\n", pc.PeerID)

	grants := pc.Client.Grants()
	if len(grants) == 0 {
		fmt.Println("Grants:  (none)")
		return
	}

	fmt.Printf("Grants:  %d\n", len(grants))
	for i, g := range grants {
		fmt.Printf("  [%d] handlers=%v ops=%v resources=%v\n",
			i, g.Handlers.Include, g.Operations.Include, g.Resources.Include)
	}
}

func cmdHelp(sh *Shell, args []string) error {
	if len(args) > 0 {
		name := args[0]
		entry, ok := commandMap[name]
		if !ok {
			return fmt.Errorf("unknown command: %s", name)
		}
		fmt.Printf("  %s\n    %s\n", entry.usage, entry.help)
		return nil
	}

	fmt.Println("Commands:")
	for _, c := range commands {
		fmt.Printf("  %-35s %s\n", c.usage, c.help)
	}
	fmt.Println()
	fmt.Println("Path navigation:")
	fmt.Println("  /                     Root (lists connected peers)")
	fmt.Println("  /system/handler/      Absolute path within current peer")
	fmt.Println("  ..                    Parent directory")
	fmt.Println("  cd alias:             Jump to peer's root")
	return nil
}
