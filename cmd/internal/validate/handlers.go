package validate

import (
	"context"
	"fmt"
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catHandlers = "handlers"

// expectedHandlers defines the handlers every spec-compliant peer must expose.
// Tree operations per EXTENSION-TREE.md §9. Subscribe/unsubscribe are NOT tree
// operations — they come from EXTENSION-SUBSCRIPTION.md §3.3 as handler-agnostic
// ops that any handler MAY add to its manifest.
//
// V7 §6.2:2516 marks `system/capability` as SHOULD, not MUST — but §4.4:1521
// puts `system/capability:request` into the default connection grants, so any
// peer advertising the default grant set MUST register the handler or violate
// the grant-discipline pin in RULING-CAPABILITY-HANDLER-ADVERTISEMENT.
// Until that ruling is folded into the spec, this category flags peers that
// advertise the grant without registering the handler.
// coreProfile=true marks a handler that belongs to the V7 v7.72 §9.0 core
// handler set (the spec lists system/tree, system/handler, system/capability,
// system/protocol/connect, and SHOULD system/type). coreOps narrows the
// expected op-set under --profile core to just the core ops; nil means
// "use operations" (i.e., the same set under both profiles).
//
// For tree: operations holds the full set including EXTENSION-TREE §9 ops
// (snapshot/diff/merge/extract); coreOps holds {get, put} per V7 §9.5a.
// For inbox/continuation/subscription/revision: coreProfile=false → skip
// under --profile core (extension handlers, V7 v7.72 §9.0 over-demand).
var expectedHandlers = []struct {
	name        string
	pattern     string
	operations  []string // scored under --profile full
	coreOps     []string // scored under --profile core; nil = fall back to operations
	coreProfile bool     // false = extension handler; skip the whole entry under --profile core
}{
	{"connect", "system/protocol/connect", []string{"hello", "authenticate"}, nil, true},
	{"tree", "system/tree", []string{"get", "put", "snapshot", "diff", "merge", "extract"}, []string{"get", "put"}, true},
	{"capability", "system/capability", []string{"request", "delegate", "revoke"}, nil, true},
	{"inbox", "system/inbox", []string{"receive"}, nil, false},
	{"continuation", "system/continuation", []string{"advance", "resume", "abandon"}, nil, false},
	{"subscription", "system/subscription", []string{"subscribe", "unsubscribe"}, nil, false},
	{"revision", "system/revision", []string{"commit", "log", "status", "find-ancestor", "merge", "resolve", "branch", "checkout", "tag", "diff", "cherry-pick", "revert", "fetch", "fetch-entities", "push", "config"}, nil, false},
}

// runHandlers compares handler manifests from the remote peer against expectations.
func runHandlers(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catHandlers)
	coreOnly := client.Profile() == ProfileCore

	// --- Declare all checks ---

	r.Declare("handlers_listing_available", "V7 §6")

	for _, expected := range expectedHandlers {
		r.Declare("handler_"+expected.name+"_present", "V7 §4")
		r.Declare("handler_"+expected.name+"_interface_type", "V7 §6.2 N3")
		r.Declare("handler_"+expected.name+"_pattern_match", "V7 §6")
		r.Declare("handler_"+expected.name+"_operations_match", "V7 §6")
		r.Declare("handler_"+expected.name+"_io_types_valid", "V7 §6")
		r.Declare("handler_"+expected.name+"_dispatch_entity", "V7 §6.2 N2")
		r.Declare("handler_"+expected.name+"_dispatch_type", "V7 §6.2 N2")
		r.Declare("handler_"+expected.name+"_interface_ref", "V7 §6.2 N5")
	}

	// --- Run checks ---

	r.Run("handlers_listing_available", func() CheckOutcome {
		entries, _, err := client.TreeListing(ctx, "system/handler/")
		if err != nil {
			return FailCheck("failed to fetch system/handler/ listing: " + err.Error())
		}
		return PassCheck(fmt.Sprintf("system/handler/ listing returned %d entries", len(entries)))
	})

	for _, expected := range expectedHandlers {
		expected := expected

		// V7 v7.72 §9.0: under --profile core, skip non-core handler
		// entries (inbox/continuation/subscription/revision) — they're
		// extension surfaces, absent on a core peer is conformant.
		if coreOnly && !expected.coreProfile {
			reason := "outside --profile core (V7 v7.72 §9.0 — extension handler)"
			for _, suffix := range []string{"_present", "_interface_type", "_pattern_match", "_operations_match", "_io_types_valid", "_dispatch_entity", "_dispatch_type", "_interface_ref"} {
				name := "handler_" + expected.name + suffix
				r.Run(name, func() CheckOutcome { return SkipCheck(reason) })
			}
			continue
		}

		r.Run("handler_"+expected.name+"_present", func() CheckOutcome {
			path := "system/handler/" + expected.pattern
			ent, _, err := client.TreeGet(ctx, path)
			if err != nil {
				return FailCheck(fmt.Sprintf("failed to fetch handler interface at %s: %v", path, err))
			}
			r.Store("handler_"+expected.name+"_entity", ent)
			return PassCheck(fmt.Sprintf("handler %q interface entity present", expected.name))
		})

		r.Run("handler_"+expected.name+"_interface_type", func() CheckOutcome {
			if out, ok := r.Require("handler_" + expected.name + "_present"); !ok {
				return out
			}
			ent := r.Load("handler_" + expected.name + "_entity").(entity.Entity)
			if ent.Type == types.TypeHandlerInterface {
				return PassCheck(fmt.Sprintf("type=%q", ent.Type))
			}
			if ent.Type == types.TypeHandler {
				return WarnCheck(fmt.Sprintf("type=%q (pre-normalization: full handler at interface path, expected %q)", ent.Type, types.TypeHandlerInterface))
			}
			return FailCheck(fmt.Sprintf("type=%q (expected %q)", ent.Type, types.TypeHandlerInterface))
		})

		r.Run("handler_"+expected.name+"_pattern_match", func() CheckOutcome {
			if out, ok := r.Require("handler_" + expected.name + "_present"); !ok {
				return out
			}
			ent := r.Load("handler_" + expected.name + "_entity").(entity.Entity)
			var ifaceData types.HandlerInterfaceData
			if err := ecf.Decode(ent.Data, &ifaceData); err != nil {
				return FailCheck("failed to decode handler interface: " + err.Error())
			}
			r.Store("handler_"+expected.name+"_data", ifaceData)
			if ifaceData.Pattern == expected.pattern {
				return PassCheck(fmt.Sprintf("pattern=%q matches", ifaceData.Pattern))
			}
			return FailCheck(fmt.Sprintf("pattern=%q (expected %q)", ifaceData.Pattern, expected.pattern))
		})

		r.Run("handler_"+expected.name+"_operations_match", func() CheckOutcome {
			if out, ok := r.Require("handler_" + expected.name + "_pattern_match"); !ok {
				return out
			}
			ifaceData := r.Load("handler_" + expected.name + "_data").(types.HandlerInterfaceData)

			remoteOps := make(map[string]bool, len(ifaceData.Operations))
			for op := range ifaceData.Operations {
				remoteOps[op] = true
			}

			// V7 v7.72 §9.5a: under --profile core, score the tree handler
			// against {get, put} only; EXTENSION-TREE §9 ops (snapshot/diff/
			// merge/extract/tracked) are matched-if-present, not-a-FAIL-if-
			// absent. Generalizes to any handler with a non-nil coreOps set.
			requiredOps := expected.operations
			if coreOnly && expected.coreOps != nil {
				requiredOps = expected.coreOps
			}

			var missing []string
			for _, op := range requiredOps {
				if !remoteOps[op] {
					missing = append(missing, op)
				}
			}

			remoteList := make([]string, 0, len(remoteOps))
			for op := range remoteOps {
				remoteList = append(remoteList, op)
			}
			sort.Strings(remoteList)

			if len(missing) > 0 {
				sort.Strings(missing)
				return FailCheck(fmt.Sprintf("missing required operations %v (has %v)", missing, remoteList))
			}
			profileNote := ""
			if coreOnly && expected.coreOps != nil {
				profileNote = " [--profile core scored against §9.5a coreOps]"
			}
			return PassCheck(fmt.Sprintf("all required operations present (%v)%s", remoteList, profileNote))
		})

		r.Run("handler_"+expected.name+"_io_types_valid", func() CheckOutcome {
			if out, ok := r.Require("handler_" + expected.name + "_pattern_match"); !ok {
				return out
			}
			ifaceData := r.Load("handler_" + expected.name + "_data").(types.HandlerInterfaceData)

			var badTypes []string
			for opName, spec := range ifaceData.Operations {
				if spec.InputType != "" && !isKnownTypeRef(spec.InputType) {
					badTypes = append(badTypes, fmt.Sprintf("%s.input=%s", opName, spec.InputType))
				}
				if spec.OutputType != "" && !isKnownTypeRef(spec.OutputType) {
					badTypes = append(badTypes, fmt.Sprintf("%s.output=%s", opName, spec.OutputType))
				}
			}
			if len(badTypes) > 0 {
				sort.Strings(badTypes)
				return WarnCheck(fmt.Sprintf("unrecognized type refs: %v", badTypes))
			}
			return PassCheck(fmt.Sprintf("all %d I/O type refs are known types", len(ifaceData.Operations)))
		})

		r.Run("handler_"+expected.name+"_dispatch_entity", func() CheckOutcome {
			ent, _, err := client.TreeGet(ctx, expected.pattern)
			if err != nil {
				return WarnCheck(fmt.Sprintf("no handler entity at pattern path %s: %v (pre-normalization peer)", expected.pattern, err))
			}
			r.Store("handler_"+expected.name+"_dispatch", ent)
			return PassCheck(fmt.Sprintf("handler entity present at %s", expected.pattern))
		})

		r.Run("handler_"+expected.name+"_dispatch_type", func() CheckOutcome {
			v := r.Load("handler_" + expected.name + "_dispatch")
			if v == nil {
				return SkipCheck("no dispatch entity (pre-normalization peer)")
			}
			ent := v.(entity.Entity)
			if ent.Type == types.TypeHandler {
				return PassCheck(fmt.Sprintf("type=%q", ent.Type))
			}
			return FailCheck(fmt.Sprintf("type=%q (expected %q)", ent.Type, types.TypeHandler))
		})

		r.Run("handler_"+expected.name+"_interface_ref", func() CheckOutcome {
			v := r.Load("handler_" + expected.name + "_dispatch")
			if v == nil {
				return SkipCheck("no dispatch entity (pre-normalization peer)")
			}
			ent := v.(entity.Entity)
			var handlerData types.HandlerData
			if err := ecf.Decode(ent.Data, &handlerData); err != nil {
				return FailCheck("failed to decode handler entity: " + err.Error())
			}
			expectedPath := "system/handler/" + expected.pattern
			if handlerData.Interface == expectedPath {
				return PassCheck(fmt.Sprintf("interface=%q", handlerData.Interface))
			}
			return FailCheck(fmt.Sprintf("interface=%q (expected %q)", handlerData.Interface, expectedPath))
		})
	}

	// §10.1 of PROPOSAL-V7-V7.74-CORE-EXTENSIBILITY-BOUNDARY: the
	// core-tier dynamic-register gate. Runs under `--profile core`
	// only — under `--profile full`, the more elaborate entity-native
	// category (scope_params, lookup_tree_*, dual_check_*, etc.) covers
	// the same surface plus extension behavior.
	if coreOnly {
		runCoreRegisterGate(ctx, client, r)
	}

	return r.Results()
}

// isKnownTypeRef returns true if the type reference uses a recognized prefix.
func isKnownTypeRef(typeRef string) bool {
	for _, p := range []string{"system/", "primitive/", "core/"} {
		if len(typeRef) > len(p) && typeRef[:len(p)] == p {
			return true
		}
	}
	return false
}

