package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
)

func cmdLs(sh *Shell, args []string) error {
	target := sh.wd
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target = Resolve(args[0], sh.wd)
	}

	// At root: list connected peers.
	if target.IsRoot() {
		if len(sh.conns) == 0 {
			fmt.Println("  (no connections — use 'connect <alias> <host:port>')")
			return nil
		}
		// Sort by alias.
		aliases := make([]string, 0, len(sh.conns))
		for a := range sh.conns {
			aliases = append(aliases, a)
		}
		sort.Strings(aliases)
		for _, a := range aliases {
			pc := sh.conns[a]
			fmt.Printf("  %-12s %s\n", a, pc.Addr)
		}
		return nil
	}

	// Need a connection.
	pc := sh.connForPath(target)
	if pc == nil {
		return fmt.Errorf("no connection for path %s", target)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	barePath := target.BarePath()
	// Ensure trailing slash for listing.
	if barePath != "" && !strings.HasSuffix(barePath, "/") {
		barePath += "/"
	}

	entries, _, err := pc.Client.TreeListing(ctx, barePath)
	if err != nil {
		return fmt.Errorf("listing %s: %w", barePath, err)
	}

	if len(entries) == 0 {
		fmt.Println("  (empty)")
		return nil
	}

	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		kind := classifyEntry(entries[k])
		fmt.Printf("  %-30s %s\n", k, kind)
	}
	return nil
}

// classifyEntry determines if a listing entry is a directory, entity, or both
// based on the entry's metadata (has_children, hash fields).
func classifyEntry(v interface{}) string {
	m, ok := v.(map[interface{}]interface{})
	if !ok {
		return ""
	}

	hasChildren := false
	if hc, ok := m["has_children"]; ok {
		if b, ok := hc.(bool); ok {
			hasChildren = b
		}
	}

	hasHash := false
	if h, ok := m["hash"]; ok && h != nil {
		hasHash = true
	}

	switch {
	case hasChildren && hasHash:
		return "dir+entity"
	case hasChildren:
		return "dir"
	case hasHash:
		return "entity"
	default:
		return ""
	}
}

func cmdCd(sh *Shell, args []string) error {
	if len(args) == 0 {
		sh.wd = "/"
		return nil
	}

	input := args[0]

	// Allow "cd alias:" shorthand to jump to a connected peer's root.
	if strings.HasSuffix(input, ":") {
		alias := strings.TrimSuffix(input, ":")
		pc, ok := sh.conns[alias]
		if !ok {
			return fmt.Errorf("not connected: %s", alias)
		}
		sh.wd = Path("/" + string(pc.PeerID) + "/")
		return nil
	}

	target := Resolve(input, sh.wd)

	// Validate the target if it references a peer.
	if pc := sh.connForPath(target); pc == nil && !target.IsRoot() {
		return fmt.Errorf("no connection for path %s", target)
	}

	sh.wd = target
	return nil
}

func cmdPwd(sh *Shell, _ []string) error {
	fmt.Println(sh.wd)
	return nil
}

func cmdTree(sh *Shell, args []string) error {
	target := sh.wd
	maxDepth := 3
	verbose := false

	for i := 0; i < len(args); i++ {
		if args[i] == "-depth" && i+1 < len(args) {
			d, err := strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid depth: %s", args[i+1])
			}
			maxDepth = d
			i++
		} else if args[i] == "-v" || args[i] == "-verbose" {
			verbose = true
		} else if !strings.HasPrefix(args[i], "-") {
			target = Resolve(args[i], sh.wd)
		}
	}

	if target.IsRoot() {
		return fmt.Errorf("tree requires a peer path (cd into a peer first, or specify a path)")
	}

	pc := sh.connForPath(target)
	if pc == nil {
		return fmt.Errorf("no connection for path %s", target)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return printTree(ctx, pc, target.BarePath(), "", maxDepth, verbose)
}

// printTree recursively lists tree entries.
func printTree(ctx context.Context, pc *PeerConn, prefix, indent string, remaining int, verbose bool) error {
	if remaining <= 0 {
		return nil
	}

	// Ensure trailing slash for listing.
	listPath := prefix
	if listPath != "" && !strings.HasSuffix(listPath, "/") {
		listPath += "/"
	}

	entries, _, err := pc.Client.TreeListing(ctx, listPath)
	if err != nil {
		fmt.Printf("%s(error: %v)\n", indent, err)
		return nil // don't abort the whole tree
	}

	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		kind := classifyEntry(entries[k])
		isDir := kind == "dir" || kind == "dir+entity"
		hasEntity := kind == "entity" || kind == "dir+entity"
		suffix := ""
		if isDir {
			suffix = "/"
		}

		if !verbose {
			fmt.Printf("%s%s%s\n", indent, k, suffix)
		} else {
			// Verbose: fetch entity details for leaf nodes.
			if hasEntity {
				entPath := listPath + k
				ent, _, err := pc.Client.TreeGet(ctx, entPath)
				if err != nil {
					fmt.Printf("%s%s%s  (get error: %v)\n", indent, k, suffix, err)
				} else {
					fmt.Printf("%s%s%s  [%s] %s\n", indent, k, suffix, ent.Type, ent.ContentHash)
					printEntityData(indent+"    ", ent)
				}
			} else {
				fmt.Printf("%s%s%s\n", indent, k, suffix)
			}
		}

		if isDir && remaining > 1 {
			childPath := listPath + k + "/"
			printTree(ctx, pc, childPath, indent+"  ", remaining-1, verbose)
		}
	}
	return nil
}

// printEntityData decodes and prints entity data inline under tree output.
func printEntityData(indent string, ent entity.Entity) {
	var decoded interface{}
	if err := ecf.Decode(ent.Data, &decoded); err != nil {
		return
	}
	var b strings.Builder
	entity.FormatCBORValue(&b, indent, decoded)
	fmt.Print(b.String())
}
