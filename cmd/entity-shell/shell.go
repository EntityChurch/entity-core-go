package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/crypto"
)

// PeerConn represents one connected peer.
type PeerConn struct {
	Alias  string
	Addr   string
	Client *validate.PeerClient
	PeerID crypto.PeerID
}

// Shell holds the REPL state.
type Shell struct {
	conns    map[string]*PeerConn // alias → connection
	peerMap  map[string]string    // peerID → alias (reverse lookup)
	wd       Path
	identity string
}

// NewShell creates a new shell instance.
func NewShell(identity string) *Shell {
	return &Shell{
		conns:    make(map[string]*PeerConn),
		peerMap:  make(map[string]string),
		wd:       "/",
		identity: identity,
	}
}

// Run starts the interactive REPL loop.
func (sh *Shell) Run() error {
	fmt.Println("Entity Shell v0.1 — type 'help' for commands")
	if sh.identity != "" {
		fmt.Printf("Using identity: %s\n", sh.identity)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(sh.prompt())
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		args := splitArgs(line)
		if len(args) == 0 {
			continue
		}

		cmd := args[0]
		if cmd == "quit" || cmd == "exit" {
			sh.closeAll()
			return nil
		}

		if err := sh.dispatch(cmd, args[1:]); err != nil {
			fmt.Printf("error: %v\n", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	sh.closeAll()
	return nil
}

// prompt builds the shell prompt string.
func (sh *Shell) prompt() string {
	p := string(sh.wd)
	peerID := sh.wd.PeerID()
	alias := ""
	if peerID != "" {
		if a, ok := sh.peerMap[peerID]; ok {
			alias = a
		}
	}

	if alias != "" {
		bare := sh.wd.BarePath()
		if bare == "" {
			p = "/"
		} else {
			p = "/" + bare
		}
		return fmt.Sprintf("entity:%s:%s > ", alias, p)
	}
	return fmt.Sprintf("entity:%s > ", p)
}

// connForWD returns the PeerConn for the current working directory, or nil if at root.
func (sh *Shell) connForWD() *PeerConn {
	peerID := sh.wd.PeerID()
	if peerID == "" {
		return nil
	}
	alias, ok := sh.peerMap[peerID]
	if !ok {
		return nil
	}
	return sh.conns[alias]
}

// connForPath returns the PeerConn for a resolved path, or nil if at root.
func (sh *Shell) connForPath(p Path) *PeerConn {
	peerID := p.PeerID()
	if peerID == "" {
		return nil
	}
	alias, ok := sh.peerMap[peerID]
	if !ok {
		return nil
	}
	return sh.conns[alias]
}

// closeAll disconnects all peers.
func (sh *Shell) closeAll() {
	for alias, pc := range sh.conns {
		pc.Client.Close()
		fmt.Printf("Disconnected from %s\n", alias)
	}
}

// splitArgs splits a line on whitespace, respecting quoted strings.
func splitArgs(line string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		} else if c == '"' || c == '\'' {
			inQuote = true
			quoteChar = c
		} else if c == ' ' || c == '\t' {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
