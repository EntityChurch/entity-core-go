// Command peer-manager starts, stops, and lists managed peers for local
// validation and interop runs.
//
// Go peers build and run from source on the host. Rust and Python peers run as
// podman containers built from their sibling repos' make+podman images
// (entity-core-rust / entity-core-py), launched with --network host, a
// bind-mounted ~/.entity, and per-container resource caps (memory/cpu/pids, the
// runtime arm of RESOURCE-CAPS.md — so a runaway peer can't take the host down).
// State is tracked in ~/.entity/peer-manager.json. The validate-peers*.sh
// scripts drive this tool. See podman.go for the container launch model.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "start":
		cmdStart(args)
	case "stop":
		cmdStop(args)
	case "list":
		cmdList()
	case "addr":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: peer-manager addr <name>\n")
			os.Exit(2)
		}
		cmdAddr(args[0])
	case "addrs":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: peer-manager addrs <name1,name2,...>\n")
			os.Exit(2)
		}
		cmdAddrs(args[0])
	case "ws-addrs":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: peer-manager ws-addrs <name1,name2,...>\n")
			os.Exit(2)
		}
		cmdWSAddrs(args[0])
	case "peer-id":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: peer-manager peer-id <name>\n")
			os.Exit(2)
		}
		cmdPeerID(args[0])
	case "logs":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: peer-manager logs <name>\n")
			os.Exit(2)
		}
		cmdLogs(args[0])
	case "identity":
		cmdIdentity(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: peer-manager <command> [args]

Commands:
  start [--name NAME] [--type go|rust|python] [--addr ADDR] [--debug] [--remote NAME]
      Start a managed peer process.

  stop NAME | --all
      Stop a running peer by name, or stop all peers.

  list
      Show running peers with status.

  addr NAME
      Print the address of a running peer.

  addrs NAME1,NAME2,...
      Print comma-separated addresses for multiple peers.

  peer-id NAME
      Print the peer ID of a running peer.

  logs NAME
      Print the log file path for a peer (use with tail -f).

  identity init NAME [--simple] [--quorum K-of-N]
      Provision a new identity bundle under ~/.entity/identities/NAME/
      per EXTENSION-IDENTITY v1.2. --simple: 1-of-1 quorum, Op = Public_alice
      collapse (§11.3). Default: full 4-layer (1-of-1 quorum, separate Op,
      separate Public_alice). --quorum K-of-N: e.g., 2-of-3 for a multi-key
      quorum.

  identity show NAME
      Print the bundle manifest for an existing identity.
`)
}
