package revision

import (
	"context"
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Tests for the two halves of the §5.1 merge cascade that had no coverage in
// any implementation until 2026-08-14: step 1 (per-TYPE merge config, G-21) and
// the `handler` sentinel's delegation to a custom merge driver (§5.3, G-18).
//
// Both gaps were invisible to a 1574-check, 0-FAIL conformance gate because the
// suite drove per-PATH config only. These tests plus the cmd/internal/validate
// vectors are the coverage that makes the gate able to see them at all.

// encodeForTest ECF-encodes a value for use as entity data.
func encodeForTest(t *testing.T, v interface{}) cbor.RawMessage {
	t.Helper()
	raw, err := ecf.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return cbor.RawMessage(raw)
}

// putDoc stores a two-field document entity of the given type and returns its
// hash. The `v` field is what the built-in three-way merge would compare.
func putDoc(t *testing.T, hctx *handler.HandlerContext, typeName, v string) hash.Hash {
	t.Helper()
	return storeEntity(t, hctx, "", typeName, map[string]string{"v": v})
}

// withMergeHandler installs an Execute stub standing in for a custom merge
// driver at handlerPath. fn receives the decoded merge-request and returns the
// response the driver would produce.
func withMergeHandler(
	t *testing.T,
	hctx *handler.HandlerContext,
	handlerPath string,
	fn func(req types.RevisionMergeRequestData) (types.RevisionMergeResponseData, error),
) *int {
	t.Helper()
	calls := 0
	hctx.Execute = func(ctx context.Context, uri, operation string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		calls++
		if uri != handlerPath {
			t.Fatalf("dispatched to %q, want the config's handler path %q", uri, handlerPath)
		}
		// §5.3 pins the operation name as "merge".
		if operation != "merge" {
			t.Fatalf("dispatched operation %q, §5.3 requires \"merge\"", operation)
		}
		// §5.3 pins the request type. A driver that validates its input — the
		// ordinary thing for a handler to do — rejects anything else, which is
		// exactly the cross-impl hazard A-6 E1 is about.
		if params.Type != types.TypeRevisionMergeRequest {
			t.Fatalf("dispatched params type %q, §5.3 requires %q", params.Type, types.TypeRevisionMergeRequest)
		}
		req, err := types.RevisionMergeRequestDataFromEntity(params)
		if err != nil {
			t.Fatalf("merge-request did not decode: %v", err)
		}
		out, err := fn(req)
		if err != nil {
			return nil, err
		}
		respEnt, err := out.ToEntity()
		if err != nil {
			t.Fatal(err)
		}
		return &handler.Response{Status: 200, Result: respEnt}, nil
	}
	return &calls
}

// --- Step 1: per-type merge config (G-21) ---

// The write path has always accepted `scope: "type"` and answered 200 "set";
// nothing read the namespace, so the config was silently inert. This is the
// check that would have failed before the build.
func TestPerTypeMergeConfigIsConsulted(t *testing.T) {
	hctx := newTestContext()

	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")

	storeEntity(t, hctx, mergeConfigTypeScope("app/doc"), types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Strategy: "source-wins"})

	choice := findMergeStrategy(hctx, "data/", "any/path", "", local, remote)
	if choice.strategy != strategySourceWins {
		t.Fatalf("per-type config not consulted: got strategy %q, want source-wins", choice.strategy)
	}
}

// §5.1 orders the cascade per-type BEFORE per-path. A per-path config that
// matches must not outrank a per-type config that also matches — otherwise
// type-keyed dispatch is unreachable whenever a wildcard path config exists,
// which is the common deployment.
func TestPerTypeMergeConfigOutranksPerPath(t *testing.T) {
	hctx := newTestContext()

	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")

	storeEntity(t, hctx, "system/revision/config/merge/path/all", types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Pattern: "*", Strategy: "target-wins"})
	storeEntity(t, hctx, mergeConfigTypeScope("app/doc"), types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Strategy: "source-wins"})

	choice := findMergeStrategy(hctx, "data/", "any/path", "", local, remote)
	if choice.strategy != strategySourceWins {
		t.Fatalf("cascade order wrong: got %q, want source-wins (per-type precedes per-path per §5.1)", choice.strategy)
	}
}

// "Check local type first (existing entity), then remote type (incoming)."
// The order is normative, not incidental: it is what makes two peers merging
// the same pair select the same config.
func TestPerTypeLocalTypeWinsOverRemoteType(t *testing.T) {
	hctx := newTestContext()

	local := putDoc(t, hctx, "app/local-type", "L")
	remote := putDoc(t, hctx, "app/remote-type", "R")

	storeEntity(t, hctx, mergeConfigTypeScope("app/local-type"), types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Strategy: "source-wins"})
	storeEntity(t, hctx, mergeConfigTypeScope("app/remote-type"), types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Strategy: "target-wins"})

	choice := findMergeStrategy(hctx, "data/", "any/path", "", local, remote)
	if choice.strategy != strategySourceWins {
		t.Fatalf("local type must be checked first: got %q, want source-wins", choice.strategy)
	}
}

// When local carries no config, the remote type gets its chance — "either
// side's handler may understand cross-type merge."
func TestPerTypeFallsThroughToRemoteType(t *testing.T) {
	hctx := newTestContext()

	local := putDoc(t, hctx, "app/local-type", "L")
	remote := putDoc(t, hctx, "app/remote-type", "R")

	storeEntity(t, hctx, mergeConfigTypeScope("app/remote-type"), types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Strategy: "target-wins"})

	choice := findMergeStrategy(hctx, "data/", "any/path", "", local, remote)
	if choice.strategy != strategyTargetWins {
		t.Fatalf("remote type not consulted when local has no config: got %q", choice.strategy)
	}
}

// A per-type config carrying a value the write path would have rejected can
// only have arrived by a raw tree:put bypassing the handler op — §2.3 (v3.3,
// D1) calls that a deployment misconfiguration. It must not silently outrank a
// valid per-path config; the cascade continues past it.
func TestPerTypeInvalidStrategyDoesNotOutrankPerPath(t *testing.T) {
	hctx := newTestContext()

	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")

	storeEntity(t, hctx, mergeConfigTypeScope("app/doc"), types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Strategy: "field-level"}) // removed by v3.10
	storeEntity(t, hctx, "system/revision/config/merge/path/all", types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Pattern: "*", Strategy: "target-wins"})

	choice := findMergeStrategy(hctx, "data/", "any/path", "", local, remote)
	if choice.strategy != strategyTargetWins {
		t.Fatalf("invalid per-type config should be skipped, got %q", choice.strategy)
	}
}

// No config anywhere → §5.1 step 3, the documented default.
func TestNoMergeConfigYieldsThreeWay(t *testing.T) {
	hctx := newTestContext()
	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")

	if choice := findMergeStrategy(hctx, "data/", "any/path", "", local, remote); choice.strategy != strategyThreeWay {
		t.Fatalf("default should be three-way, got %q", choice.strategy)
	}
}

// --- §5.3: the `handler` sentinel (G-18) ---

// The whole delegation, end to end: config selects the sentinel, the named
// driver receives base/local/remote, returns a merged entity, and the merge
// takes it. Before the build this returned {resolved: false} unconditionally.
func TestHandlerSentinelDispatchesAndTakesMergedEntity(t *testing.T) {
	hctx := newTestContext()

	base := putDoc(t, hctx, "app/doc", "B")
	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")
	merged := putDoc(t, hctx, "app/doc", "MERGED")

	var seen types.RevisionMergeRequestData
	calls := withMergeHandler(t, hctx, "app/merge/text", func(req types.RevisionMergeRequestData) (types.RevisionMergeResponseData, error) {
		seen = req
		return types.RevisionMergeResponseData{Resolved: true, Entity: merged}, nil
	})

	choice := strategyChoice{strategy: strategyHandler, handlerPath: "app/merge/text"}
	result := applyMergeStrategy(context.Background(), hctx, hctx.Store, choice, "docs/readme", base, local, remote)

	if *calls != 1 {
		t.Fatalf("handler dispatched %d times, want exactly 1", *calls)
	}
	if !result.resolved {
		t.Fatal("handler resolved the merge but the strategy reported unresolved")
	}
	if result.hash != merged {
		t.Fatalf("merged hash = %v, want the handler's entity %v", result.hash, merged)
	}
	// The request must carry all three hashes the driver needs to do its job.
	if seen.Base != base || seen.Local != local || seen.Remote != remote {
		t.Fatalf("merge-request carried {base:%v local:%v remote:%v}, want {%v %v %v}",
			seen.Base, seen.Local, seen.Remote, base, local, remote)
	}
}

// §5.3: base is optional, "null if no ancestor". A create/create conflict has
// no ancestor and the driver must still be reached — the built-in three-way
// gives up in that case, which is precisely when a custom driver earns its keep.
func TestHandlerSentinelDispatchesWithNoAncestor(t *testing.T) {
	hctx := newTestContext()

	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")
	merged := putDoc(t, hctx, "app/doc", "MERGED")

	var seen types.RevisionMergeRequestData
	withMergeHandler(t, hctx, "app/merge/text", func(req types.RevisionMergeRequestData) (types.RevisionMergeResponseData, error) {
		seen = req
		return types.RevisionMergeResponseData{Resolved: true, Entity: merged}, nil
	})

	choice := strategyChoice{strategy: strategyHandler, handlerPath: "app/merge/text"}
	result := applyMergeStrategy(context.Background(), hctx, hctx.Store, choice, "docs/readme", hash.Hash{}, local, remote)

	if !result.resolved || result.hash != merged {
		t.Fatalf("no-ancestor dispatch did not resolve: resolved=%v hash=%v", result.resolved, result.hash)
	}
	if !seen.Base.IsZero() {
		t.Fatalf("base should be absent with no ancestor, got %v", seen.Base)
	}
}

// A driver that declines produces a conflict entity — the divergence is
// recorded for an operator rather than auto-resolved on a basis nobody chose.
func TestHandlerSentinelUnresolvedYieldsConflict(t *testing.T) {
	hctx := newTestContext()

	base := putDoc(t, hctx, "app/doc", "B")
	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")

	withMergeHandler(t, hctx, "app/merge/text", func(types.RevisionMergeRequestData) (types.RevisionMergeResponseData, error) {
		return types.RevisionMergeResponseData{Resolved: false, Reason: "semantic conflict in field v"}, nil
	})

	choice := strategyChoice{strategy: strategyHandler, handlerPath: "app/merge/text"}
	if result := applyMergeStrategy(context.Background(), hctx, hctx.Store, choice, "docs/readme", base, local, remote); result.resolved {
		t.Fatal("a declining handler must not resolve the merge")
	}
}

// Disposition 3 (A-6 E4), and the one that protects state rather than merely
// recording a conflict: a handler claiming `resolved: true` for a hash the
// store cannot resolve must NOT get that hash bound into the merged tree.
func TestHandlerSentinelMalformedResponsesDoNotBind(t *testing.T) {
	hctx := newTestContext()

	base := putDoc(t, hctx, "app/doc", "B")
	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")

	// A syntactically valid hash that was deliberately never stored: build the
	// entity, compute its hash, and do NOT Put it.
	phantom := encodeForTest(t, map[string]string{"v": "PHANTOM"})
	unstored, err := hash.Compute("app/doc", phantom)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hctx.Store.Get(unstored); ok {
		t.Fatal("fixture broken: the phantom entity is in the store, so this cannot test the unresolvable case")
	}

	cases := []struct {
		name string
		resp types.RevisionMergeResponseData
	}{
		{"resolved true with no entity", types.RevisionMergeResponseData{Resolved: true}},
		{"resolved true naming an unstored hash", types.RevisionMergeResponseData{Resolved: true, Entity: unstored}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withMergeHandler(t, hctx, "app/merge/text", func(types.RevisionMergeRequestData) (types.RevisionMergeResponseData, error) {
				return tc.resp, nil
			})
			choice := strategyChoice{strategy: strategyHandler, handlerPath: "app/merge/text"}
			result := applyMergeStrategy(context.Background(), hctx, hctx.Store, choice, "docs/readme", base, local, remote)
			if result.resolved {
				t.Fatalf("malformed response resolved the merge with hash %v — an unresolvable hash reached the merged tree", result.hash)
			}
		})
	}
}

// A response of the wrong type is not a merge-response, however well-formed it
// is in isolation. This is the receive-side half of the A-6 E1 hazard.
func TestHandlerSentinelWrongResponseTypeDoesNotResolve(t *testing.T) {
	hctx := newTestContext()

	base := putDoc(t, hctx, "app/doc", "B")
	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")
	merged := putDoc(t, hctx, "app/doc", "MERGED")

	hctx.Execute = func(ctx context.Context, uri, operation string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		wrong, err := entity.NewEntity("app/some-other-result", encodeForTest(t, map[string]interface{}{"resolved": true, "entity": merged}))
		if err != nil {
			t.Fatal(err)
		}
		return &handler.Response{Status: 200, Result: wrong}, nil
	}

	choice := strategyChoice{strategy: strategyHandler, handlerPath: "app/merge/text"}
	if result := applyMergeStrategy(context.Background(), hctx, hctx.Store, choice, "docs/readme", base, local, remote); result.resolved {
		t.Fatal("a response of the wrong type must not resolve the merge")
	}
}

// Disposition 2 (A-6 E4): a handler path that does not resolve, or errors, is a
// misconfiguration whose blast radius is one path's conflict — never a failed
// merge of the whole prefix.
func TestHandlerSentinelMissingOrErroringHandlerYieldsConflict(t *testing.T) {
	base := hash.Hash{}
	cases := []struct {
		name  string
		setup func(hctx *handler.HandlerContext)
		path  string
	}{
		{
			name: "handler errors",
			path: "app/merge/text",
			setup: func(hctx *handler.HandlerContext) {
				hctx.Execute = func(context.Context, string, string, entity.Entity, ...handler.ExecuteOption) (*handler.Response, error) {
					return nil, errors.New("no handler at that path")
				}
			},
		},
		{
			name: "handler returns non-200",
			path: "app/merge/text",
			setup: func(hctx *handler.HandlerContext) {
				hctx.Execute = func(context.Context, string, string, entity.Entity, ...handler.ExecuteOption) (*handler.Response, error) {
					return &handler.Response{Status: 404}, nil
				}
			},
		},
		{
			name:  "empty handler path (config bypassed the write op)",
			path:  "",
			setup: func(hctx *handler.HandlerContext) {},
		},
		{
			name:  "no dispatcher wired",
			path:  "app/merge/text",
			setup: func(hctx *handler.HandlerContext) { hctx.Execute = nil },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hctx := newTestContext()
			local := putDoc(t, hctx, "app/doc", "L")
			remote := putDoc(t, hctx, "app/doc", "R")
			tc.setup(hctx)

			choice := strategyChoice{strategy: strategyHandler, handlerPath: tc.path}
			result := applyMergeStrategy(context.Background(), hctx, hctx.Store, choice, "docs/readme", base, local, remote)
			if result.resolved {
				t.Fatalf("%s must degrade to a conflict entity, got resolved with %v", tc.name, result.hash)
			}
		})
	}
}

// The two halves composed, which is the deployment shape that was unreachable
// twice over: a per-TYPE config selecting the `handler` sentinel. Step 1 had to
// find the config AND the sentinel had to dispatch for this to pass.
func TestPerTypeConfigSelectingHandlerSentinelDispatches(t *testing.T) {
	hctx := newTestContext()

	base := putDoc(t, hctx, "app/doc", "B")
	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")
	merged := putDoc(t, hctx, "app/doc", "MERGED")

	storeEntity(t, hctx, mergeConfigTypeScope("app/doc"), types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Strategy: "handler", Handler: "app/merge/doc-driver"})

	calls := withMergeHandler(t, hctx, "app/merge/doc-driver", func(types.RevisionMergeRequestData) (types.RevisionMergeResponseData, error) {
		return types.RevisionMergeResponseData{Resolved: true, Entity: merged}, nil
	})

	choice := findMergeStrategy(hctx, "data/", "docs/readme", "", local, remote)
	if choice.strategy != strategyHandler {
		t.Fatalf("per-type config did not select the sentinel: got %q", choice.strategy)
	}
	if choice.handlerPath != "app/merge/doc-driver" {
		t.Fatalf("companion handler path lost in the cascade: got %q", choice.handlerPath)
	}

	result := applyMergeStrategy(context.Background(), hctx, hctx.Store, choice, "docs/readme", base, local, remote)
	if *calls != 1 || !result.resolved || result.hash != merged {
		t.Fatalf("composed dispatch failed: calls=%d resolved=%v hash=%v", *calls, result.resolved, result.hash)
	}
}

// --- §5.1 pattern scope (G-22) ---

// §5.1: "A config with `pattern: \"*\"` matches all paths within any merge,
// regardless of prefix." Go's path.Match gives `*` single-segment semantics, so
// the shared globMatch silently narrowed a peer-wide operator config to
// top-level keys. The one conformance vector using `pattern: "*"` exercised a
// single-segment key and so passed for the wrong reason.
func TestMergePatternStarMatchesNestedPaths(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*", "readme", true},
		{"*", "docs/readme", true},           // form 1 match-all crosses /
		{"*", "docs/deep/nested/file", true}, // form 1 match-all, any depth
		// `**` is no longer a glob token (arch 9ee84f3, §2.4 four forms). It is
		// not one of the four forms, so the matcher treats it as a non-matching
		// literal rather than a wildcard — subtree matching is form 2 (`docs/*`),
		// which already crosses / at any depth.
		{"**", "docs/readme", false},
		{"docs/**", "docs/readme", false},
		{"docs/**", "other/readme", false},
		{"docs/*", "docs/readme", true},           // form 2 subtree, crosses /
		{"docs/*", "docs/deep/nested/file", true}, // form 2 subtree, any depth
		{"docs/*", "other/readme", false},         // retained / prevents sibling match
		{"*.cache", "a/b/foo.cache", true},        // form 3 suffix, / not special
		{"*.cache", "a/cache/b", false},           // form 3 must terminate subject
		{"docs", "docs", true},                    // form 4 exact
		{"docs", "docs/x", false},                 // form 4 is not a prefix
	}
	for _, tc := range cases {
		if got := mergePatternMatch(tc.pattern, tc.path); got != tc.want {
			t.Errorf("mergePatternMatch(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// The narrowing was behaviourally reachable, not merely theoretical: a
// peer-wide `pattern: "*"` config must actually select its strategy for a
// nested path during a merge-strategy lookup.
func TestStarPatternConfigAppliesToNestedPath(t *testing.T) {
	hctx := newTestContext()
	local := putDoc(t, hctx, "app/doc", "L")
	remote := putDoc(t, hctx, "app/doc", "R")

	storeEntity(t, hctx, "system/revision/config/merge/path/peerwide", types.TypeRevisionMergeConfig,
		types.RevisionMergeConfigData{Pattern: "*", Strategy: "source-wins"})

	if choice := findMergeStrategy(hctx, "data/", "docs/deep/readme", "", local, remote); choice.strategy != strategySourceWins {
		t.Fatalf("peer-wide `*` config did not reach a nested path: got %q, want source-wins", choice.strategy)
	}
}
