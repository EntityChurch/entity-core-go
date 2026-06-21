// Command entity-shell is an interactive REPL for exploring and operating
// peers by hand.
//
// -identity selects a named identity from ~/.entity/identities/ (default: an
// ephemeral keypair).
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	identity := flag.String("identity", "", "identity name from ~/.entity/identities/ (default: ephemeral)")
	flag.Parse()

	sh := NewShell(*identity)

	if err := sh.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
