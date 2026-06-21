package store

import (
	"strings"
	"testing"
)

func TestContextFieldRegistry_Register(t *testing.T) {
	r := NewContextFieldRegistry()

	err := r.Register(ContextFieldRegistration{
		Name:     "clock",
		TypeName: "system/clock/state",
		Owner:    "system/clock",
	})
	if err != nil {
		t.Fatalf("register clock: %v", err)
	}

	reg, ok := r.Get("clock")
	if !ok {
		t.Fatal("expected clock field to be registered")
	}
	if reg.TypeName != "system/clock/state" {
		t.Fatalf("expected type system/clock/state, got %s", reg.TypeName)
	}
	if reg.Owner != "system/clock" {
		t.Fatalf("expected owner system/clock, got %s", reg.Owner)
	}
}

func TestContextFieldRegistry_RejectCoreField(t *testing.T) {
	r := NewContextFieldRegistry()

	for _, name := range []string{"chain_id", "author", "bounds", "operation"} {
		err := r.Register(ContextFieldRegistration{
			Name:     name,
			TypeName: "test/type",
			Owner:    "test/handler",
		})
		if err == nil {
			t.Fatalf("expected error registering core field %q", name)
		}
		if !strings.Contains(err.Error(), "conflicts with core field") {
			t.Fatalf("unexpected error for %q: %v", name, err)
		}
	}
}

func TestContextFieldRegistry_RejectDuplicate(t *testing.T) {
	r := NewContextFieldRegistry()

	err := r.Register(ContextFieldRegistration{
		Name:     "clock",
		TypeName: "system/clock/state",
		Owner:    "system/clock",
	})
	if err != nil {
		t.Fatalf("register clock: %v", err)
	}

	err = r.Register(ContextFieldRegistration{
		Name:     "clock",
		TypeName: "other/type",
		Owner:    "other/handler",
	})
	if err == nil {
		t.Fatal("expected error registering duplicate field")
	}
	if !strings.Contains(err.Error(), "already registered by system/clock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestContextFieldRegistry_GetNotFound(t *testing.T) {
	r := NewContextFieldRegistry()

	_, ok := r.Get("nonexistent")
	if ok {
		t.Fatal("expected false for unregistered field")
	}
}

func TestContextFieldRegistry_All(t *testing.T) {
	r := NewContextFieldRegistry()

	r.Register(ContextFieldRegistration{Name: "clock", TypeName: "system/clock/state", Owner: "system/clock"})
	r.Register(ContextFieldRegistration{Name: "metrics", TypeName: "system/metrics/state", Owner: "system/metrics"})

	all := r.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(all))
	}

	names := map[string]bool{}
	for _, reg := range all {
		names[reg.Name] = true
	}
	if !names["clock"] || !names["metrics"] {
		t.Fatalf("expected clock and metrics, got %v", names)
	}
}
