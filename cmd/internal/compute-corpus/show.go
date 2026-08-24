package main

// `show` — render one vector's IR so a divergence can be triaged.
//
// §7c.4(6) requires that a failure reproduce from (seed, case-index). Reproducing
// it is only half the job: cross-bless reports "sweep/0124 ALL-DIFFER" with two
// boundary hashes, and a hash tells you nothing about which expression produced
// it. Without this, triage means hand-decoding CBOR out of a 500 KB artifact.
//
// It prints the expression graph, not the entity list. The artifact stores a flat
// content-addressed set in hash order — correct for reproducibility, unreadable
// for diagnosis, because the structure is entirely in the hash references. So the
// graph is walked from the root and printed as a tree.

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

func runShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	corpusPath := fs.String("corpus", "", "path to the frozen corpus")
	id := fs.String("id", "", "vector id, e.g. sweep/0124")
	var emissions multiFlag
	fs.Var(&emissions, "emission", "emission to show this vector's outcome from (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *id == "" {
		return fmt.Errorf("show: --corpus and --id are required")
	}

	c, sum, err := loadCorpus(*corpusPath)
	if err != nil {
		return err
	}
	var v *Vector
	for i := range c.Vectors {
		if c.Vectors[i].ID == *id {
			v = &c.Vectors[i]
			break
		}
	}
	if v == nil {
		return fmt.Errorf("no vector %q in corpus", *id)
	}

	fmt.Printf("vector   %s\n", v.ID)
	fmt.Printf("profile  %s   seed %d   case_index %d   generator v%s (%s)\n",
		c.Profile, c.Seed, v.CaseIndex, c.GeneratorVersion, c.PRNG)
	fmt.Printf("budget   operations=%d depth=%d\n", v.Budget.Operations, v.Budget.Depth)
	if len(v.Requires) > 0 {
		fmt.Printf("requires %s\n", strings.Join(v.Requires, " "))
	}
	var bindings map[string]interface{}
	if err := ecf.Decode(v.Bindings, &bindings); err == nil && len(bindings) > 0 {
		fmt.Printf("bindings %s\n", renderValue(bindings))
	}
	for _, p := range sortedTreePaths(v.Tree) {
		fmt.Printf("tree     %s → %s\n", p, v.Tree[p])
	}

	byHash := map[hash.Hash]entity.Entity{}
	for _, ve := range v.Entities {
		ent, err := entity.NewEntity(ve.Type, ve.Data)
		if err != nil {
			return err
		}
		byHash[ent.ContentHash] = ent
	}
	fmt.Printf("\nIR (%d entities):\n", len(v.Entities))
	printNode(byHash, v.Root, "", map[hash.Hash]bool{})

	for _, p := range emissions {
		em, err := loadEmission(p, sum)
		if err != nil {
			return err
		}
		fmt.Printf("\n%s/%s:\n", em.Impl, em.Engine)
		if o, ok := em.Results[v.ID]; ok {
			fmt.Printf("  %s\n", o)
			if o.Kind == OutcomeError && o.Message != "" {
				fmt.Printf("  message: %q\n", o.Message)
			}
		} else if why, ok := em.Skipped[v.ID]; ok {
			fmt.Printf("  SKIPPED: %s\n", why)
		} else {
			fmt.Printf("  (no answer)\n")
		}
	}
	return nil
}

func sortedTreePaths(m map[string]hash.Hash) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// printNode renders one IR node and recurses into its children.
//
// Shared sub-expressions are printed once and then referenced — the corpus
// deduplicates by content address, so a graph can revisit the same node many
// times and expanding it every time would turn a small expression into pages of
// output. The `seen` set is per-path rather than global so a node reached twice
// down different branches still shows its position in each.
func printNode(byHash map[hash.Hash]entity.Entity, h hash.Hash, indent string, seen map[hash.Hash]bool) {
	ent, ok := byHash[h]
	if !ok {
		fmt.Printf("%s<missing %s>\n", indent, h)
		return
	}
	if seen[h] {
		fmt.Printf("%s%s ↩ (shared)\n", indent, ent.Type)
		return
	}
	seen[h] = true
	defer delete(seen, h)

	label, kids := describe(ent)
	fmt.Printf("%s%s\n", indent, label)
	for _, k := range kids {
		if k.label != "" {
			fmt.Printf("%s  %s:\n", indent, k.label)
			printNode(byHash, k.hash, indent+"    ", seen)
		} else {
			printNode(byHash, k.hash, indent+"  ", seen)
		}
	}
}

type childRef struct {
	label string
	hash  hash.Hash
}

// describe renders a node's own content and returns its children. Every compute
// expression type is handled; anything else prints as a bare type name, which is
// correct for the hand-built app/* entities a tree precondition carries.
func describe(ent entity.Entity) (string, []childRef) {
	dec := func(v interface{}) bool { return ecf.Decode(ent.Data, v) == nil }

	switch ent.Type {
	case types.TypeComputeLiteral:
		var d types.ComputeLiteralData
		if dec(&d) {
			return "literal " + renderValue(d.Value), nil
		}
	case types.TypeComputeLookupScope:
		var d types.ComputeLookupScopeData
		if dec(&d) {
			return "lookup/scope " + d.Name, nil
		}
	case types.TypeComputeLookupTree:
		var d types.ComputeLookupTreeData
		if dec(&d) {
			return "lookup/tree " + d.Path, nil
		}
	case types.TypeComputeArithmetic:
		var d types.ComputeArithmeticData
		if dec(&d) {
			return "arithmetic " + d.Op, []childRef{{"left", d.Left}, {"right", d.Right}}
		}
	case types.TypeComputeCompare:
		var d types.ComputeCompareData
		if dec(&d) {
			return "compare " + d.Op, []childRef{{"left", d.Left}, {"right", d.Right}}
		}
	case types.TypeComputeLogic:
		var d types.ComputeLogicData
		if dec(&d) {
			kids := []childRef{{"left", d.Left}}
			if d.Right != nil {
				kids = append(kids, childRef{"right", *d.Right})
			}
			return "logic " + d.Op, kids
		}
	case types.TypeComputeIf:
		var d types.ComputeIfData
		if dec(&d) {
			kids := []childRef{{"cond", d.Condition}, {"then", d.Then}}
			if d.Else != nil {
				kids = append(kids, childRef{"else", *d.Else})
			}
			return "if", kids
		}
	case types.TypeComputeLet:
		var d types.ComputeLetData
		if dec(&d) {
			kids := make([]childRef, 0, len(d.Bindings)+1)
			for _, b := range d.Bindings {
				kids = append(kids, childRef{"let " + b.Name, b.Value})
			}
			return "let", append(kids, childRef{"body", d.Body})
		}
	case types.TypeComputeLambda:
		var d types.ComputeLambdaData
		if dec(&d) {
			return "lambda(" + strings.Join(d.Params, ", ") + ")", []childRef{{"body", d.Body}}
		}
	case types.TypeComputeIndex:
		var d types.ComputeIndexData
		if dec(&d) {
			return "index", []childRef{{"array", d.Array}, {"index", d.Index}}
		}
	case types.TypeComputeLength:
		var d types.ComputeLengthData
		if dec(&d) {
			return "length", []childRef{{"array", d.Array}}
		}
	case types.TypeComputeNumericCast:
		var d types.ComputeNumericCastData
		if dec(&d) {
			return "numeric-cast → " + d.ToType, []childRef{{"value", d.Value}}
		}
	case types.TypeComputeField:
		var d types.ComputeFieldData
		if dec(&d) {
			return "field " + d.Name, []childRef{{"entity", d.Entity}}
		}
	case types.TypeComputeConstruct:
		var d types.ComputeConstructData
		if dec(&d) {
			return "construct " + d.EntityType, sortedFields(d.Fields)
		}
	case types.TypeComputeApply:
		var d types.ComputeApplyData
		if dec(&d) {
			head := "apply"
			if d.Path != "" {
				head += " " + d.Path + ":" + d.Operation
			}
			kids := sortedFields(d.Args)
			if !d.Fn.IsZero() {
				kids = append([]childRef{{"fn", d.Fn}}, kids...)
			}
			return head, kids
		}
	}
	return ent.Type, nil
}

// sortedFields renders a hash-valued map in the canonical order the evaluator
// uses (length, then lexicographic) rather than Go map order, so two runs of
// `show` on the same vector print identically.
func sortedFields(m map[string]hash.Hash) []childRef {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})
	out := make([]childRef, 0, len(keys))
	for _, k := range keys {
		out = append(out, childRef{k, m[k]})
	}
	return out
}

// renderValue prints a decoded CBOR value with its numeric kind visible.
// int64(5) and uint64(5) format identically in Go, and telling them apart is the
// entire point of the signed/unsigned model — so the kind is annotated.
func renderValue(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case int64:
		return fmt.Sprintf("%di", t)
	case uint64:
		return fmt.Sprintf("%du", t)
	case float64:
		return fmt.Sprintf("%gf", t)
	case string:
		return fmt.Sprintf("%q", t)
	case bool:
		return fmt.Sprintf("%t", t)
	case []byte:
		return fmt.Sprintf("h'%x'", t)
	case []interface{}:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = renderValue(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+": "+renderValue(t[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprintf("%v", v)
	}
}
