package main

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
)

func cmdConnect(sh *Shell, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: connect <alias> <host:port>")
	}
	alias := args[0]
	addr := args[1]

	if _, exists := sh.conns[alias]; exists {
		return fmt.Errorf("alias %q already connected (disconnect first)", alias)
	}

	// Create client.
	var client *validate.PeerClient
	var err error
	if sh.identity != "" {
		client, err = validate.NewPeerClientWithIdentity(addr, sh.identity)
	} else {
		client, err = validate.NewPeerClient(addr)
	}
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	// Connect + handshake.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	checks := client.PerformHandshake(ctx)
	for _, c := range checks {
		if c.Severity == validate.Fail {
			client.Close()
			return fmt.Errorf("handshake failed: %s: %s", c.Name, c.Message)
		}
	}
	if !client.Connected() {
		client.Close()
		return fmt.Errorf("handshake failed")
	}

	peerID := client.RemotePeerID()
	pc := &PeerConn{
		Alias:  alias,
		Addr:   addr,
		Client: client,
		PeerID: peerID,
	}
	sh.conns[alias] = pc
	sh.peerMap[string(peerID)] = alias

	// Auto-cd to peer's namespace.
	sh.wd = Path("/" + string(peerID) + "/")

	short := string(peerID)
	if len(short) > 12 {
		short = short[:12] + "..."
	}
	fmt.Printf("Connected to %s (%s)\n", alias, short)
	return nil
}

func cmdDisconnect(sh *Shell, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: disconnect <alias>")
	}
	alias := args[0]

	pc, ok := sh.conns[alias]
	if !ok {
		return fmt.Errorf("not connected: %s", alias)
	}

	pc.Client.Close()
	delete(sh.peerMap, string(pc.PeerID))
	delete(sh.conns, alias)

	// If working directory was inside this peer, go to root.
	if sh.wd.PeerID() == string(pc.PeerID) {
		sh.wd = "/"
	}

	fmt.Printf("Disconnected from %s\n", alias)
	return nil
}
