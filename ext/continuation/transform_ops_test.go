package continuation

import (
	"context"
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func ops(o ...types.ContinuationTransformOpData) []types.ContinuationTransformOpData { return o }

func TestTransformOps_EachOp(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]interface{}
		op   types.ContinuationTransformOpData
		want map[string]interface{}
	}{
		{
			"strip_prefix present",
			map[string]interface{}{"p": "/peerA/data/x"},
			types.ContinuationTransformOpData{Op: "strip_prefix", Field: "p", Prefix: "/peerA/data/"},
			map[string]interface{}{"p": "x"},
		},
		{
			"strip_prefix absent is no-op",
			map[string]interface{}{"p": "x"},
			types.ContinuationTransformOpData{Op: "strip_prefix", Field: "p", Prefix: "/nope/"},
			map[string]interface{}{"p": "x"},
		},
		{
			"prepend",
			map[string]interface{}{"p": "x"},
			types.ContinuationTransformOpData{Op: "prepend", Field: "p", Literal: "/local/data/"},
			map[string]interface{}{"p": "/local/data/x"},
		},
		{
			"append",
			map[string]interface{}{"p": "x"},
			types.ContinuationTransformOpData{Op: "append", Field: "p", Literal: ".json"},
			map[string]interface{}{"p": "x.json"},
		},
		{
			"join",
			map[string]interface{}{"a": "x", "b": "y"},
			types.ContinuationTransformOpData{Op: "join", Fields: []string{"a", "b"}, Sep: "/", Into: "c"},
			map[string]interface{}{"a": "x", "b": "y", "c": "x/y"},
		},
		{
			"replace_literal",
			map[string]interface{}{"p": "a.b.c"},
			types.ContinuationTransformOpData{Op: "replace_literal", Field: "p", From: ".", To: "/"},
			map[string]interface{}{"p": "a/b/c"},
		},
		{
			"slice mid",
			map[string]interface{}{"p": "abcdef"},
			types.ContinuationTransformOpData{Op: "slice", Field: "p", Range: "1:4", Into: "q"},
			map[string]interface{}{"p": "abcdef", "q": "bcd"},
		},
		{
			"slice open end clamps",
			map[string]interface{}{"p": "abc"},
			types.ContinuationTransformOpData{Op: "slice", Field: "p", Range: "1:99", Into: "q"},
			map[string]interface{}{"p": "abc", "q": "bc"},
		},
		{
			"slice malformed range is no-op passthrough",
			map[string]interface{}{"p": "abc"},
			types.ContinuationTransformOpData{Op: "slice", Field: "p", Range: "bogus", Into: "q"},
			map[string]interface{}{"p": "abc", "q": "abc"},
		},
		{
			"missing field is total no-op (empty string)",
			map[string]interface{}{},
			types.ContinuationTransformOpData{Op: "prepend", Field: "x", Literal: "P"},
			map[string]interface{}{"x": "P"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := applyTransformOps(tc.in, ops(tc.op))
			gm, ok := got.(map[string]interface{})
			if !ok {
				t.Fatalf("expected map result, got %T", got)
			}
			// split produces []interface{}; compare with reflect for the rest.
			if !reflect.DeepEqual(gm, tc.want) {
				t.Fatalf("op %s: got %#v, want %#v", tc.op.Op, gm, tc.want)
			}
		})
	}
}

// TestTransformOps_EdgeCases locks the totality boundaries: degenerate
// inputs are documented no-ops, never panics or garbage (§2.2 admissibility:
// total / pure / bounded).
func TestTransformOps_EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]interface{}
		op   types.ContinuationTransformOpData
		want map[string]interface{}
	}{
		{
			// Go's strings.ReplaceAll(s,"",to) would splice `to` around every
			// byte — guarded to a total no-op.
			"replace_literal empty from is no-op",
			map[string]interface{}{"p": "abc"},
			types.ContinuationTransformOpData{Op: "replace_literal", Field: "p", From: "", To: "X"},
			map[string]interface{}{"p": "abc"},
		},
		{
			"slice start>end clamps to empty",
			map[string]interface{}{"p": "abcdef"},
			types.ContinuationTransformOpData{Op: "slice", Field: "p", Range: "5:2", Into: "q"},
			map[string]interface{}{"p": "abcdef", "q": ""},
		},
		{
			"slice negative index parses-or-noops (Atoi succeeds, clamps to 0)",
			map[string]interface{}{"p": "abc"},
			types.ContinuationTransformOpData{Op: "slice", Field: "p", Range: "-9:2", Into: "q"},
			map[string]interface{}{"p": "abc", "q": "ab"},
		},
		{
			"op on nil field value (select-all-null) is total no-op",
			map[string]interface{}{"p": nil},
			types.ContinuationTransformOpData{Op: "prepend", Field: "p", Literal: "/x/"},
			map[string]interface{}{"p": "/x/"},
		},
		{
			"unknown op on the apply path is a defensive no-op (install rejects it first)",
			map[string]interface{}{"p": "v"},
			types.ContinuationTransformOpData{Op: "definitely_unknown", Field: "p"},
			map[string]interface{}{"p": "v"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyTransformOps(tc.in, ops(tc.op)).(map[string]interface{})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestTransformOps_CollectKeys exercises both singular (`field`) and plural
// (`fields: [...]`) forms of the new op, plus the edge cases the proposal's
// §3 admissibility analysis pins as total/bounded.
func TestTransformOps_CollectKeys(t *testing.T) {
	// Helper to compare key sets independent of iteration order.
	asSet := func(arr interface{}) map[string]bool {
		s := map[string]bool{}
		for _, v := range arr.([]interface{}) {
			s[v.(string)] = true
		}
		return s
	}

	t.Run("singular field projects map keys", func(t *testing.T) {
		got := applyTransformOps(
			map[string]interface{}{
				"added": map[string]interface{}{
					"/peerA/a.md": []byte{1},
					"/peerA/b.md": []byte{2},
				},
			},
			ops(types.ContinuationTransformOpData{Op: "collect_keys", Field: "added", Into: "paths"}),
		).(map[string]interface{})
		want := map[string]bool{"/peerA/a.md": true, "/peerA/b.md": true}
		if !reflect.DeepEqual(asSet(got["paths"]), want) {
			t.Fatalf("singular: got %#v, want %#v", got["paths"], want)
		}
	})

	t.Run("plural fields concatenate keys from each map", func(t *testing.T) {
		got := applyTransformOps(
			map[string]interface{}{
				"added":   map[string]interface{}{"/a": []byte{1}},
				"changed": map[string]interface{}{"/b": []byte{2}, "/c": []byte{3}},
			},
			ops(types.ContinuationTransformOpData{
				Op: "collect_keys", Fields: []string{"added", "changed"}, Into: "paths",
			}),
		).(map[string]interface{})
		want := map[string]bool{"/a": true, "/b": true, "/c": true}
		if !reflect.DeepEqual(asSet(got["paths"]), want) {
			t.Fatalf("plural: got %#v, want %#v", got["paths"], want)
		}
	})

	t.Run("dotted-path navigation per extract", func(t *testing.T) {
		got := applyTransformOps(
			map[string]interface{}{
				"data": map[string]interface{}{
					"added": map[string]interface{}{"/x": "1"},
				},
			},
			ops(types.ContinuationTransformOpData{Op: "collect_keys", Field: "data.added", Into: "paths"}),
		).(map[string]interface{})
		if !reflect.DeepEqual(asSet(got["paths"]), map[string]bool{"/x": true}) {
			t.Fatalf("dotted: got %#v", got["paths"])
		}
	})

	t.Run("missing field is empty array (total no-op)", func(t *testing.T) {
		got := applyTransformOps(
			map[string]interface{}{},
			ops(types.ContinuationTransformOpData{Op: "collect_keys", Field: "nope", Into: "paths"}),
		).(map[string]interface{})
		arr, ok := got["paths"].([]interface{})
		if !ok || len(arr) != 0 {
			t.Fatalf("missing-field: got %#v, want []", got["paths"])
		}
	})

	t.Run("non-map field is empty array (total no-op)", func(t *testing.T) {
		got := applyTransformOps(
			map[string]interface{}{"x": "scalar"},
			ops(types.ContinuationTransformOpData{Op: "collect_keys", Field: "x", Into: "paths"}),
		).(map[string]interface{})
		arr, _ := got["paths"].([]interface{})
		if len(arr) != 0 {
			t.Fatalf("non-map: got %#v, want []", got["paths"])
		}
	})

	t.Run("plural with one missing field skips that entry", func(t *testing.T) {
		got := applyTransformOps(
			map[string]interface{}{
				"added": map[string]interface{}{"/a": "1"},
				// "changed" intentionally absent
			},
			ops(types.ContinuationTransformOpData{
				Op: "collect_keys", Fields: []string{"added", "changed"}, Into: "paths",
			}),
		).(map[string]interface{})
		if !reflect.DeepEqual(asSet(got["paths"]), map[string]bool{"/a": true}) {
			t.Fatalf("plural-missing: got %#v", got["paths"])
		}
	})

	t.Run("CBOR-generic map keys are projected as strings", func(t *testing.T) {
		got := applyTransformOps(
			map[string]interface{}{
				"added": map[interface{}]interface{}{"/p": "1"},
			},
			ops(types.ContinuationTransformOpData{Op: "collect_keys", Field: "added", Into: "paths"}),
		).(map[string]interface{})
		if !reflect.DeepEqual(asSet(got["paths"]), map[string]bool{"/p": true}) {
			t.Fatalf("cbor-generic: got %#v", got["paths"])
		}
	})
}

// TestInstallRejectsCollectKeysBothFieldAndFields — install-time
// mutual-exclusivity check for the new op (proposal §2 "Mutual
// exclusivity").
func TestInstallRejectsCollectKeysBothFieldAndFields(t *testing.T) {
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)

	contEnt, err := types.ContinuationData{
		Target:             "/peer/system/tree",
		Operation:          "put",
		DispatchCapability: cap.ContentHash,
		ResultTransform: &types.ContinuationTransformData{
			TransformOps: ops(types.ContinuationTransformOpData{
				Op: "collect_keys", Field: "added", Fields: []string{"changed"}, Into: "paths",
			}),
		},
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/badargs", contEnt))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400 for mutually-exclusive collect_keys args, got %d", resp.Status)
	}
	// EXTENSION-CONTINUATION v1.15 §2.2 pins the error code for
	// recognized-op-but-bad-args as `400 invalid_transform_args`.
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "invalid_transform_args" {
		t.Fatalf("expected error code invalid_transform_args, got %q", errData.Code)
	}
}

func TestTransformOps_Split(t *testing.T) {
	got := applyTransformOps(
		map[string]interface{}{"csv": "a,b,c"},
		ops(types.ContinuationTransformOpData{Op: "split", Field: "csv", Sep: ",", Into: "parts"}),
	).(map[string]interface{})
	want := []interface{}{"a", "b", "c"}
	if !reflect.DeepEqual(got["parts"], want) {
		t.Fatalf("split: got %#v, want %#v", got["parts"], want)
	}
}

// TestTransformOps_CrossPeerRewrite is the motivating case from §2.2: the
// cross-peer-notification → local-path rewrite (strip one statically-known
// prefix, prepend one statically-known prefix), ordered.
func TestTransformOps_CrossPeerRewrite(t *testing.T) {
	got := applyTransformOps(
		map[string]interface{}{"path": "/peerB/data/shared/doc-1"},
		ops(
			types.ContinuationTransformOpData{Op: "strip_prefix", Field: "path", Prefix: "/peerB/data/shared/"},
			types.ContinuationTransformOpData{Op: "prepend", Field: "path", Literal: "/local/mirror/"},
		),
	).(map[string]interface{})
	if got["path"] != "/local/mirror/doc-1" {
		t.Fatalf("cross-peer rewrite: got %q, want %q", got["path"], "/local/mirror/doc-1")
	}
}

// TestTransformOps_NonMapPassthrough — ops on a scalar value are a total
// no-op (field plumbing has nothing to plumb), value unchanged.
func TestTransformOps_NonMapPassthrough(t *testing.T) {
	got := applyTransformOps("just-a-string",
		ops(types.ContinuationTransformOpData{Op: "prepend", Field: "x", Literal: "P"}))
	if got != "just-a-string" {
		t.Fatalf("non-map passthrough: got %#v", got)
	}
}

// deref_included resolves a hash field from envelope.included to the entity
// at that hash, encoded as cbor.RawMessage. Test covers the happy path plus
// total-no-op cases per §2.2: missing field, wrong shape/length, hash not in
// included, and nil included map.
func TestDerefIncluded_HappyPath(t *testing.T) {
	rawData, _ := ecf.Encode(map[string]string{"k": "payload"})
	ent, err := entity.NewEntity("test/payload", cbor.RawMessage(rawData))
	if err != nil {
		t.Fatal(err)
	}
	included := map[hash.Hash]entity.Entity{ent.ContentHash: ent}

	value := map[string]interface{}{"entity": ent.ContentHash.Bytes()}
	got := applyTransformOpsWithIncluded(value,
		ops(types.ContinuationTransformOpData{Op: "deref_included", Field: "entity"}),
		included,
	).(map[string]interface{})

	rawMsg, ok := got["entity"].(cbor.RawMessage)
	if !ok {
		t.Fatalf("expected cbor.RawMessage after deref, got %T", got["entity"])
	}
	var decoded entity.Entity
	if err := cbor.Unmarshal(rawMsg, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ContentHash != ent.ContentHash {
		t.Fatalf("entity hash mismatch after deref")
	}
	if decoded.Type != "test/payload" {
		t.Fatalf("entity type mismatch: %s", decoded.Type)
	}
}

func TestDerefIncluded_NoOpCases(t *testing.T) {
	rawData, _ := ecf.Encode(map[string]string{"k": "payload"})
	ent, _ := entity.NewEntity("test/payload", cbor.RawMessage(rawData))
	included := map[hash.Hash]entity.Entity{ent.ContentHash: ent}

	t.Run("missing field is no-op", func(t *testing.T) {
		value := map[string]interface{}{"other": "thing"}
		got := applyTransformOpsWithIncluded(value,
			ops(types.ContinuationTransformOpData{Op: "deref_included", Field: "entity"}),
			included,
		).(map[string]interface{})
		if _, present := got["entity"]; present {
			t.Fatal("missing field should remain absent")
		}
	})

	t.Run("non-byte-shape field is no-op", func(t *testing.T) {
		value := map[string]interface{}{"entity": "not-bytes"}
		got := applyTransformOpsWithIncluded(value,
			ops(types.ContinuationTransformOpData{Op: "deref_included", Field: "entity"}),
			included,
		).(map[string]interface{})
		if got["entity"] != "not-bytes" {
			t.Fatalf("non-byte field should pass through, got %v", got["entity"])
		}
	})

	t.Run("wrong-length hash is no-op", func(t *testing.T) {
		value := map[string]interface{}{"entity": []byte{0x01, 0x02}}
		got := applyTransformOpsWithIncluded(value,
			ops(types.ContinuationTransformOpData{Op: "deref_included", Field: "entity"}),
			included,
		).(map[string]interface{})
		b, _ := got["entity"].([]byte)
		if len(b) != 2 {
			t.Fatalf("wrong-length hash should pass through, got %v", got["entity"])
		}
	})

	t.Run("unresolved hash is no-op", func(t *testing.T) {
		other := hash.Hash{Algorithm: 0x00, Digest: hash.ExtendDigest([32]byte{0xDE, 0xAD})}
		value := map[string]interface{}{"entity": other.Bytes()}
		got := applyTransformOpsWithIncluded(value,
			ops(types.ContinuationTransformOpData{Op: "deref_included", Field: "entity"}),
			included,
		).(map[string]interface{})
		b, ok := got["entity"].([]byte)
		if !ok || len(b) != hash.HashSize {
			t.Fatalf("unresolved hash should pass through, got %T %v", got["entity"], got["entity"])
		}
	})

	t.Run("nil included is no-op", func(t *testing.T) {
		value := map[string]interface{}{"entity": ent.ContentHash.Bytes()}
		got := applyTransformOpsWithIncluded(value,
			ops(types.ContinuationTransformOpData{Op: "deref_included", Field: "entity"}),
			nil,
		).(map[string]interface{})
		b, ok := got["entity"].([]byte)
		if !ok || len(b) != hash.HashSize {
			t.Fatalf("nil included should leave field unchanged, got %T %v", got["entity"], got["entity"])
		}
	})
}

// TestApplyTransform_PipelineOrder verifies extract -> select -> transform_ops
// ordering (§2.2): select builds {p: <path>}, then strip_prefix+prepend
// rewrite it.
func TestApplyTransform_PipelineOrder(t *testing.T) {
	raw, _ := cbor.Marshal(map[string]interface{}{
		"data": map[string]interface{}{"path": "/peerB/x/doc"},
	})
	tr := &types.ContinuationTransformData{
		Select: map[string]string{"p": "data.path"},
		TransformOps: ops(
			types.ContinuationTransformOpData{Op: "strip_prefix", Field: "p", Prefix: "/peerB/x/"},
			types.ContinuationTransformOpData{Op: "prepend", Field: "p", Literal: "/local/"},
		),
	}
	out := applyTransform(cbor.RawMessage(raw), tr, nil)
	var decoded map[string]interface{}
	if err := cbor.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded["p"] != "/local/doc" {
		t.Fatalf("pipeline: got %q, want %q", decoded["p"], "/local/doc")
	}
}

// TestInstallRejectsUnknownTransformOp — G1 fail-closed (§2.2/§8.1):
// installing a continuation whose transform carries an unrecognized op
// is rejected 400, never silently skipped.
func TestInstallRejectsUnknownTransformOp(t *testing.T) {
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)

	contEnt, err := types.ContinuationData{
		Target:             "/peer/system/tree",
		Operation:          "put",
		DispatchCapability: cap.ContentHash,
		ResultTransform: &types.ContinuationTransformData{
			TransformOps: ops(types.ContinuationTransformOpData{Op: "exec_shell", Field: "p"}),
		},
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/badop", contEnt))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected 400 for unknown transform op, got %d", resp.Status)
	}
	errData, _ := types.ErrorDataFromEntity(resp.Result)
	if errData.Code != "unknown_transform_op" {
		t.Fatalf("expected unknown_transform_op, got %q", errData.Code)
	}
}

// TestInstallAcceptsKnownTransformOps — the converse: a transform with only
// recognized ops installs cleanly.
func TestInstallAcceptsKnownTransformOps(t *testing.T) {
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)

	contEnt, _ := types.ContinuationData{
		Target:             "/peer/system/tree",
		Operation:          "put",
		DispatchCapability: cap.ContentHash,
		ResultTransform: &types.ContinuationTransformData{
			TransformOps: ops(
				types.ContinuationTransformOpData{Op: "strip_prefix", Field: "p", Prefix: "/a/"},
				types.ContinuationTransformOpData{Op: "prepend", Field: "p", Literal: "/b/"},
			),
		},
	}.ToEntity()
	resp, err := env.h.handleInstall(context.Background(),
		makeInstallRequest(t, env.hctx, "/peer/system/continuation/okop", contEnt))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		errData, _ := types.ErrorDataFromEntity(resp.Result)
		t.Fatalf("expected 200 for known ops, got %d %q", resp.Status, errData.Code)
	}
}
