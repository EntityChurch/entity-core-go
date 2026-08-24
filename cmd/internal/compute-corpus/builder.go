package main

// A minimal IR builder, local to the corpus tool.
//
// The workbench harness builds its graphs with entitysdk.ComputeBuilder. That
// builder is not available here and should not be: it lives in workbench-go, it
// is a peer-attached convenience (Build() writes through a live peer), and
// PROPOSAL-COMPUTE-LOWERING-TOOLKIT §2 is explicit that the builder surface is
// impl-local and NOT part of the cross-impl contract — only the resulting IR
// graph is. So the corpus builds IR entities directly from core/types, which is
// also the honest shape: what gets frozen is entities, not builder calls.
//
// Errors are sticky rather than returned per call. Expression construction is
// deeply nested (`arith("add", lit(1), index(arr, lit(0)))`), and threading an
// error through every argument position would bury the grammar the generator is
// supposed to make readable. Nothing here can fail on well-formed input — the
// only error source is ECF encoding — so the sticky error is checked once at
// freeze time and a real failure still aborts the build loudly.

import (
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/compute"

	"github.com/fxamacker/cbor/v2"
)

// toEntity is satisfied by every types.Compute*Data struct.
type toEntity interface {
	ToEntity() (entity.Entity, error)
}

// irBuilder accumulates the entity closure for one vector.
type irBuilder struct {
	err   error
	seen  map[hash.Hash]entity.Entity
	tree  map[string]hash.Hash
	feats map[string]bool
	// inlineRoots, when non-nil, replaces a root-scope lookup with a literal
	// of the bound value — the `wire` profile. See lookupScope.
	inlineRoots map[string]interface{}
}

func newIRBuilder(inlineRoots map[string]interface{}) *irBuilder {
	return &irBuilder{
		seen:        make(map[hash.Hash]entity.Entity),
		feats:       make(map[string]bool),
		inlineRoots: inlineRoots,
	}
}

// add encodes a data struct to an entity, records it in the closure, and
// returns its content hash. Deduplicates by content address, which is what
// makes a shared sub-expression appear once in the frozen artifact.
func (b *irBuilder) add(d toEntity) hash.Hash {
	if b.err != nil {
		return hash.Hash{}
	}
	ent, err := d.ToEntity()
	if err != nil {
		b.err = err
		return hash.Hash{}
	}
	b.seen[ent.ContentHash] = ent
	return ent.ContentHash
}

// addRaw records an already-built entity in the closure. Used for the
// non-compute entities a tree precondition needs — a hand-built app/* entity
// has no Compute*Data struct to go through, and the materialized-hash-readback
// vector specifically needs an entity that was NOT produced by compute.
func (b *irBuilder) addRaw(ent entity.Entity) hash.Hash {
	if b.err != nil {
		return hash.Hash{}
	}
	b.seen[ent.ContentHash] = ent
	return ent.ContentHash
}

// feature marks a capability this vector exercises; surfaces as Requires.
func (b *irBuilder) feature(tags ...string) {
	for _, t := range tags {
		b.feats[t] = true
	}
}

// at registers a tree precondition: the entity must be resolvable at path
// before evaluation. Used by the `recurse` decomposition, whose stored lambda
// self-references through compute/lookup/tree.
func (b *irBuilder) at(path string, h hash.Hash) {
	if b.tree == nil {
		b.tree = make(map[string]hash.Hash)
	}
	b.tree[path] = h
}

// --- Expression constructors ---

func (b *irBuilder) lit(v interface{}) hash.Hash {
	return b.add(types.ComputeLiteralData{Value: v})
}

// lookupScope emits a compute/lookup/scope — except in the `wire` profile, where
// a name bound in the ROOT scope is replaced by a literal of its value.
//
// This exists because EXTENSION-COMPUTE §3.2 is normative that explicit eval over
// the wire starts from `scope = empty_scope()`: there is no request field that
// carries root bindings to a peer. A vector referencing `n` therefore cannot be
// evaluated by a live peer at all — it returns not_found for every free
// variable. Inlining closes the expression so the same semantics are reachable
// through the handler.
//
// Only ROOT names are inlined. Names bound by compute/let or a lambda parameter
// are not in inlineRoots and stay as real scope lookups, so the `wire` profile
// still exercises compute/lookup/scope, closure capture, and the let* ordering
// rule. What it gives up is the root-binding half of §7c.3's `(IR, root
// bindings, budget)` shape — which is why it is a SECOND artifact rather than a
// replacement for the in-process one.
func (b *irBuilder) lookupScope(name string) hash.Hash {
	if b.inlineRoots != nil {
		if v, ok := b.inlineRoots[name]; ok {
			return b.lit(v)
		}
	}
	return b.add(types.ComputeLookupScopeData{Name: name})
}

func (b *irBuilder) lookupTree(path string) hash.Hash {
	return b.add(types.ComputeLookupTreeData{Path: path})
}

func (b *irBuilder) arith(op string, l, r hash.Hash) hash.Hash {
	return b.add(types.ComputeArithmeticData{Op: op, Left: l, Right: r})
}

func (b *irBuilder) compare(op string, l, r hash.Hash) hash.Hash {
	return b.add(types.ComputeCompareData{Op: op, Left: l, Right: r})
}

// logic builds and/or/not. `not` passes a zero right hash, which is omitted.
func (b *irBuilder) logic(op string, l hash.Hash, r *hash.Hash) hash.Hash {
	return b.add(types.ComputeLogicData{Op: op, Left: l, Right: r})
}

func (b *irBuilder) ifE(cond, then hash.Hash, els *hash.Hash) hash.Hash {
	return b.add(types.ComputeIfData{Condition: cond, Then: then, Else: els})
}

// letE builds a compute/let with bindings sorted by name.
//
// The sort is load-bearing, not tidiness. core's evalLet evaluates bindings in
// SLICE order and each binding sees the ones before it, so an unsorted slice
// makes the graph's meaning depend on Go map iteration order — which is
// randomized per run and would produce a different corpus on every build. Sorted
// name order is also the convention the workbench builder normalizes to, so the
// "a is visible to b but not vice versa" footgun the generator exercises on
// purpose behaves identically here.
func (b *irBuilder) letE(bindings map[string]hash.Hash, body hash.Hash) hash.Hash {
	names := make([]string, 0, len(bindings))
	for n := range bindings {
		names = append(names, n)
	}
	sort.Strings(names)
	bs := make([]types.ComputeLetBinding, 0, len(bindings))
	for _, n := range names {
		bs = append(bs, types.ComputeLetBinding{Name: n, Value: bindings[n]})
	}
	return b.add(types.ComputeLetData{Bindings: bs, Body: body})
}

func (b *irBuilder) lambda(params []string, body hash.Hash) hash.Hash {
	return b.add(types.ComputeLambdaData{Params: params, Body: body})
}

func (b *irBuilder) index(arr, idx hash.Hash) hash.Hash {
	return b.add(types.ComputeIndexData{Array: arr, Index: idx})
}

func (b *irBuilder) length(arr hash.Hash) hash.Hash {
	return b.add(types.ComputeLengthData{Array: arr})
}

func (b *irBuilder) cast(v hash.Hash, toType string) hash.Hash {
	return b.add(types.ComputeNumericCastData{Value: v, ToType: toType})
}

func (b *irBuilder) field(name string, ent hash.Hash) hash.Hash {
	return b.add(types.ComputeFieldData{Name: name, Entity: ent})
}

func (b *irBuilder) construct(entityType string, fields map[string]hash.Hash) hash.Hash {
	return b.add(types.ComputeConstructData{EntityType: entityType, Fields: fields})
}

// builtin builds a compute/apply against a system/compute/builtins/* path.
// Operation is always "eval" per §9.2.
func (b *irBuilder) builtin(path string, args map[string]hash.Hash) hash.Hash {
	return b.add(types.ComputeApplyData{Path: path, Operation: "eval", Args: args})
}

// builtinCarrying builds a compute/apply on a builtin path that ILLEGALLY carries a
// capability or resource field — the Q23 negative case (§2.1, arch 7fdeea7). Both
// fields are parameters of the dispatched EXECUTE, which a builtin never dispatches,
// so a conformant impl MUST return invalid_expression. Each carried hash references a
// BENIGN literal that evaluates cleanly, so the vector locks identically under either
// rejection ordering — early (all three impls today: reject on presence) or the
// pseudocode's late placement (evaluate the benign field, it does not short-circuit,
// then reject). It therefore gates the rejection WITHOUT entangling spec-issue
// 2026-08-16-d, which needs an error-valued field to tell the two orderings apart.
func (b *irBuilder) builtinCarrying(path string, args map[string]hash.Hash, capability, resource *hash.Hash) hash.Hash {
	d := types.ComputeApplyData{Path: path, Operation: "eval", Args: args}
	if capability != nil {
		d.Capability = *capability
	}
	if resource != nil {
		d.Resource = *resource
	}
	return b.add(d)
}

func (b *irBuilder) mapB(collection, fn hash.Hash) hash.Hash {
	b.feature("closure")
	return b.builtin(compute.BuiltinMap, map[string]hash.Hash{"collection": collection, "fn": fn})
}

func (b *irBuilder) filterB(collection, fn hash.Hash) hash.Hash {
	b.feature("closure")
	return b.builtin(compute.BuiltinFilter, map[string]hash.Hash{"collection": collection, "fn": fn})
}

func (b *irBuilder) foldB(collection, initial, fn hash.Hash) hash.Hash {
	b.feature("closure")
	return b.builtin(compute.BuiltinFold, map[string]hash.Hash{
		"collection": collection, "initial": initial, "fn": fn,
	})
}

// applyClosure invokes a closure/lambda by hash with args keyed by param name.
func (b *irBuilder) applyClosure(fn hash.Hash, args map[string]hash.Hash) hash.Hash {
	return b.add(types.ComputeApplyData{Fn: fn, Args: args})
}

// storeB is the SA-9 store builtin — writes `value` to `path` via
// system/tree:put (the harness wires corpusTreePut for it). Used by the §2.4
// write-site vectors: a compute/error stored here materializes code-only.
func (b *irBuilder) storeB(path, value hash.Hash) hash.Hash {
	return b.builtin(compute.BuiltinStore, map[string]hash.Hash{"path": path, "value": value})
}

// --- Freezing ---

// freeze turns the accumulated closure into a Vector.
//
// Entities are emitted sorted by content hash. Any deterministic total order
// would do; sorting by the hash is the one that needs no bookkeeping and cannot
// drift — insertion order would depend on evaluation order inside the generator,
// which is exactly the kind of incidental coupling that makes an artifact
// unreproducible between two builds of the same seed.
func (b *irBuilder) freeze(id string, caseIndex int, root hash.Hash, bindings map[string]interface{}, budget VecBudget) (Vector, error) {
	if b.err != nil {
		return Vector{}, b.err
	}
	hashes := make([]hash.Hash, 0, len(b.seen))
	for h := range b.seen {
		hashes = append(hashes, h)
	}
	sort.Slice(hashes, func(i, j int) bool {
		return string(hashes[i].Bytes()) < string(hashes[j].Bytes())
	})
	ents := make([]VecEntity, 0, len(hashes))
	for _, h := range hashes {
		e := b.seen[h]
		ents = append(ents, VecEntity{Type: e.Type, Data: e.Data})
	}

	raw, err := ecf.Encode(bindings)
	if err != nil {
		return Vector{}, err
	}

	feats := make([]string, 0, len(b.feats))
	for f := range b.feats {
		feats = append(feats, f)
	}
	sort.Strings(feats)

	v := Vector{
		ID:        id,
		CaseIndex: caseIndex,
		Entities:  ents,
		Root:      root,
		Bindings:  cbor.RawMessage(raw),
		Tree:      b.tree,
		Budget:    budget,
		Requires:  feats,
	}
	if err := v.verifyClosure(); err != nil {
		return Vector{}, err
	}
	return v, nil
}
