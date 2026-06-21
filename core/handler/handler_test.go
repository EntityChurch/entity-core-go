package handler

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

// testHandler is a simple handler for testing.
type testHandler struct {
	name string
}

func (h *testHandler) Handle(ctx context.Context, req *Request) (*Response, error) {
	return NewResponse(200, "test/result", map[string]string{
		"handler": h.name,
		"path":    req.Path,
		"op":      req.Operation,
	})
}

func (h *testHandler) Name() string { return h.name }

func TestRegistryResolveExact(t *testing.T) {
	reg := NewRegistry()
	reg.Register("system/tree", &testHandler{name: "tree"})

	h, pattern, ok := reg.Resolve("system/tree")
	if !ok {
		t.Fatal("expected to resolve system/tree")
	}
	if pattern != "system/tree" {
		t.Fatalf("expected pattern system/tree, got %s", pattern)
	}
	if h.Name() != "tree" {
		t.Fatalf("expected handler tree, got %s", h.Name())
	}
}

func TestRegistryResolvePrefixMatch(t *testing.T) {
	reg := NewRegistry()
	reg.Register("system/tree", &testHandler{name: "tree"})

	h, pattern, ok := reg.Resolve("system/tree/instances/backup")
	if !ok {
		t.Fatal("expected to resolve prefix match")
	}
	if pattern != "system/tree" {
		t.Fatalf("expected pattern system/tree, got %s", pattern)
	}
	if h.Name() != "tree" {
		t.Fatalf("expected handler tree, got %s", h.Name())
	}
}

func TestRegistryResolveLongestPrefix(t *testing.T) {
	reg := NewRegistry()
	reg.Register("local", &testHandler{name: "local"})
	reg.Register("local/files", &testHandler{name: "files"})

	h, _, ok := reg.Resolve("local/files/readme.md")
	if !ok {
		t.Fatal("expected to resolve")
	}
	if h.Name() != "files" {
		t.Fatalf("expected longest match 'files', got %s", h.Name())
	}
}

func TestRegistryResolveNoMatch(t *testing.T) {
	reg := NewRegistry()
	reg.Register("system/tree", &testHandler{name: "tree"})

	_, _, ok := reg.Resolve("local/files")
	if ok {
		t.Fatal("expected no match")
	}
}

func TestRegistryUnregister(t *testing.T) {
	reg := NewRegistry()
	reg.Register("system/tree", &testHandler{name: "tree"})
	reg.Register("system/clock", &testHandler{name: "clock"})

	// Unregister existing handler returns true.
	if !reg.Unregister("system/tree") {
		t.Fatal("expected Unregister to return true for existing handler")
	}

	// Handler should no longer resolve.
	if _, _, ok := reg.Resolve("system/tree"); ok {
		t.Fatal("expected no resolution after Unregister")
	}

	// Other handler should be unaffected.
	if _, _, ok := reg.Resolve("system/clock"); !ok {
		t.Fatal("expected system/clock to still resolve")
	}

	// Unregister non-existent pattern returns false.
	if reg.Unregister("system/tree") {
		t.Fatal("expected Unregister to return false for already-removed handler")
	}

	// Unregister never-registered pattern returns false.
	if reg.Unregister("system/nonexistent") {
		t.Fatal("expected Unregister to return false for never-registered handler")
	}
}

func TestRegistryDispatch(t *testing.T) {
	reg := NewRegistry()
	reg.Register("system/tree", &testHandler{name: "tree"})

	raw, _ := ecf.Encode("test")
	params, _ := entity.NewEntity("test/params", cbor.RawMessage(raw))

	req := &Request{
		Path:      "system/tree/foo",
		Operation: "get",
		Params:    params,
		Context:   &HandlerContext{},
	}

	resp, err := reg.Dispatch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if req.Context.HandlerPattern != "system/tree" {
		t.Fatalf("expected pattern set to system/tree, got %s", req.Context.HandlerPattern)
	}
}

func TestRegistryDispatchNotFound(t *testing.T) {
	reg := NewRegistry()
	req := &Request{
		Path:      "nonexistent",
		Operation: "get",
	}

	_, err := reg.Dispatch(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unregistered path")
	}
}

func TestNewResponse(t *testing.T) {
	resp, err := NewResponse(200, "test/type", map[string]string{"key": "value"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if resp.Result.Type != "test/type" {
		t.Fatalf("expected type test/type, got %s", resp.Result.Type)
	}
}

func TestNewErrorResponse(t *testing.T) {
	resp, err := NewErrorResponse(404, "not_found", "entity not found")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected status 404, got %d", resp.Status)
	}
}
