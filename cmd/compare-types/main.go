// compare-types connects to two peers, fetches all type definitions from each,
// and compares them field-by-field. Also compares against locally-generated types.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: compare-types <peer1-addr> <peer2-addr>\n")
		os.Exit(1)
	}
	peer1Addr := os.Args[1]
	peer2Addr := os.Args[2]

	ctx := context.Background()

	// Fetch from both peers.
	fmt.Printf("Fetching types from peer1 (%s)...\n", peer1Addr)
	peer1Types, err := fetchTypes(ctx, peer1Addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "peer1: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  got %d types\n", len(peer1Types))

	fmt.Printf("Fetching types from peer2 (%s)...\n", peer2Addr)
	peer2Types, err := fetchTypes(ctx, peer2Addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "peer2: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  got %d types\n", len(peer2Types))

	// Generate local types for ground truth.
	fmt.Printf("Generating local types...\n")
	localTypes := generateLocalTypes()
	fmt.Printf("  got %d types\n", len(localTypes))

	// Collect all type names.
	allNames := map[string]bool{}
	for name := range peer1Types {
		allNames[name] = true
	}
	for name := range peer2Types {
		allNames[name] = true
	}
	for name := range localTypes {
		allNames[name] = true
	}
	names := make([]string, 0, len(allNames))
	for name := range allNames {
		names = append(names, name)
	}
	sort.Strings(names)

	// Compare.
	fmt.Printf("\n=== Type Comparison ===\n\n")
	fmt.Printf("%-45s  %-8s  %-8s  %-8s  %s\n", "TYPE", "PEER1", "PEER2", "LOCAL", "STATUS")
	fmt.Printf("%s\n", repeat("-", 110))

	mismatches := 0
	missing := 0

	for _, name := range names {
		p1, hasP1 := peer1Types[name]
		p2, hasP2 := peer2Types[name]
		loc, hasLocal := localTypes[name]

		p1Hash := "-"
		p2Hash := "-"
		locHash := "-"
		if hasP1 {
			p1Hash = p1.hash[:12]
		}
		if hasP2 {
			p2Hash = p2.hash[:12]
		}
		if hasLocal {
			locHash = loc.hash[:12]
		}

		status := "OK"
		if !hasP1 || !hasP2 || !hasLocal {
			status = "MISSING"
			missing++
			if !hasP1 {
				status += " (peer1)"
			}
			if !hasP2 {
				status += " (peer2)"
			}
			if !hasLocal {
				status += " (local)"
			}
		} else if p1Hash != p2Hash || p1Hash != locHash {
			status = "MISMATCH"
			mismatches++
		}

		fmt.Printf("%-45s  %-8s  %-8s  %-8s  %s\n", name, p1Hash, p2Hash, locHash, status)
	}

	fmt.Printf("\n%d types, %d mismatches, %d missing\n", len(names), mismatches, missing)

	// For any mismatches, show the diff.
	if mismatches > 0 {
		fmt.Printf("\n=== Mismatched Types Detail ===\n")
		for _, name := range names {
			p1, hasP1 := peer1Types[name]
			p2, hasP2 := peer2Types[name]
			loc, hasLocal := localTypes[name]
			if !hasP1 || !hasP2 || !hasLocal {
				continue
			}
			if p1.hash == p2.hash && p1.hash == loc.hash {
				continue
			}

			fmt.Printf("\n--- %s ---\n", name)
			if p1.hash != loc.hash {
				fmt.Printf("  PEER1 vs LOCAL differ:\n")
				fmt.Printf("    peer1: %s\n", p1.json)
				fmt.Printf("    local: %s\n", loc.json)
			}
			if p2.hash != loc.hash {
				fmt.Printf("  PEER2 vs LOCAL differ:\n")
				fmt.Printf("    peer2: %s\n", p2.json)
				fmt.Printf("    local: %s\n", loc.json)
			}
			if p1.hash != p2.hash {
				fmt.Printf("  PEER1 vs PEER2 differ:\n")
				fmt.Printf("    peer1: %s\n", p1.json)
				fmt.Printf("    peer2: %s\n", p2.json)
			}
		}
	}

	// Show a few sample type definitions for review.
	fmt.Printf("\n=== Sample Type Definitions (from peer1) ===\n")
	samples := []string{
		"system/capability/grant-entry",
		"system/capability/token",
		"system/peer",
		"system/handler",
	}
	for _, name := range samples {
		if td, ok := peer1Types[name]; ok {
			fmt.Printf("\n%s (hash: %s):\n%s\n", name, td.hash, td.json)
		}
	}

	fmt.Printf("\n=== Same Types (from peer2) ===\n")
	for _, name := range samples {
		if td, ok := peer2Types[name]; ok {
			fmt.Printf("\n%s (hash: %s):\n%s\n", name, td.hash, td.json)
		}
	}

	if mismatches > 0 {
		os.Exit(1)
	}
}

type typeInfo struct {
	hash string
	json string
	def  types.TypeDefinition
}

func fetchTypes(ctx context.Context, addr string) (map[string]typeInfo, error) {
	client, err := validate.NewPeerClient(addr)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	checks := client.PerformHandshake(ctx)
	for _, c := range checks {
		if c.Severity == validate.Fail {
			return nil, fmt.Errorf("connect failed: %s: %s", c.Name, c.Message)
		}
	}

	// Recursively list type definitions.
	result := make(map[string]typeInfo)
	if err := fetchTypesRecursive(ctx, client, "system/type/", result); err != nil {
		return nil, err
	}
	return result, nil
}

func generateLocalTypes() map[string]typeInfo {
	reg := types.NewTypeRegistry()
	types.RegisterCoreTypes(reg)

	// Simulate handler registrations.
	registerConnectTypes(reg)
	registerTreeTypes(reg)

	result := make(map[string]typeInfo)
	for _, td := range reg.All() {
		ent, err := td.ToEntity()
		if err != nil {
			continue
		}
		j, _ := json.MarshalIndent(td, "  ", "  ")
		result[td.Name] = typeInfo{
			hash: ent.ContentHash.String(),
			json: string(j),
			def:  td,
		}
	}
	return result
}

func fetchTypesRecursive(ctx context.Context, client *validate.PeerClient, prefix string, result map[string]typeInfo) error {
	entries, _, err := client.TreeListing(ctx, prefix)
	if err != nil {
		return fmt.Errorf("list %s: %w", prefix, err)
	}

	for name, info := range entries {
		path := prefix + name

		// Try fetching as entity.
		ent, _, err := client.TreeGet(ctx, path)
		if err == nil && ent.Type == types.TypeType {
			var td types.TypeDefinition
			if err := ecf.Decode(ent.Data, &td); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: could not decode %s: %v\n", path, err)
			} else {
				j, _ := json.MarshalIndent(td, "  ", "  ")
				result[td.Name] = typeInfo{
					hash: ent.ContentHash.String(),
					json: string(j),
					def:  td,
				}
			}
		}

		// Also recurse into children if present.
		// The listing entry is map[string]interface{} with "has_children" key.
		if infoMap, ok := info.(map[interface{}]interface{}); ok {
			if hc, ok := infoMap["has_children"]; ok {
				if hasChildren, ok := hc.(bool); ok && hasChildren {
					fetchTypesRecursive(ctx, client, path+"/", result)
				}
			}
		}
		// Also handle map[string]interface{} (depends on CBOR decode).
		if infoMap, ok := info.(map[string]interface{}); ok {
			if hasChildren, ok := infoMap["has_children"].(bool); ok && hasChildren {
				fetchTypesRecursive(ctx, client, path+"/", result)
			}
		}
	}
	return nil
}

func registerConnectTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeHello, reflect.TypeOf(types.HelloData{}))
	r.ReflectType(types.TypeAuthenticate, reflect.TypeOf(types.AuthenticateData{}))
	r.OverrideField(types.TypeHello, "peer_id", types.FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(types.TypeAuthenticate, "peer_id", types.FieldSpec{TypeRef: "system/peer-id"})
}

func registerTreeTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeTreeGetRequest, reflect.TypeOf(types.GetRequestData{}))
	r.ReflectType(types.TypeTreePutRequest, reflect.TypeOf(types.PutRequestData{}))
	r.ReflectType(types.TypeTreeListing, reflect.TypeOf(types.ListingData{}))
	r.OverrideField(types.TypeTreeListing, "entries",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: "system/tree/listing-entry"}})
	r.OverrideField(types.TypeTreeListing, "path",
		types.FieldSpec{TypeRef: "system/tree/path"})
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
