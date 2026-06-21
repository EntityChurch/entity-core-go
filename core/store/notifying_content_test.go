package store

import (
	"sync"
	"testing"
)

func TestNotifyingContentNewEntityFiresEvent(t *testing.T) {
	inner := NewMemoryContentStore()
	ncs := NewNotifyingContentStore(inner)

	var received []ContentStoreEvent
	ncs.AddNamedContentHook("test", func(evt ContentStoreEvent) *ContentConsumerResult {
		received = append(received, evt)
		return nil
	})

	e := makeEntity(t, "test/thing", "hello")
	h, err := ncs.Put(e)
	if err != nil {
		t.Fatal(err)
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received))
	}
	if received[0].Hash != h {
		t.Fatal("event hash mismatch")
	}
	if received[0].Entity.Type != "test/thing" {
		t.Fatalf("event entity type: got %s, want test/thing", received[0].Entity.Type)
	}
}

func TestNotifyingContentDuplicatePutNoEvent(t *testing.T) {
	inner := NewMemoryContentStore()
	ncs := NewNotifyingContentStore(inner)

	var count int
	ncs.AddNamedContentHook("counter", func(evt ContentStoreEvent) *ContentConsumerResult {
		count++
		return nil
	})

	e := makeEntity(t, "test/thing", "hello")

	// First put — event fires.
	if _, err := ncs.Put(e); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event after first put, got %d", count)
	}

	// Second put of same entity — no event (no-op suppression).
	if _, err := ncs.Put(e); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event after second put, got %d", count)
	}
}

func TestNotifyingContentHaltSemantics(t *testing.T) {
	inner := NewMemoryContentStore()
	ncs := NewNotifyingContentStore(inner)

	var order []string
	ncs.AddNamedContentHook("first", func(evt ContentStoreEvent) *ContentConsumerResult {
		order = append(order, "first")
		return nil // success
	})
	ncs.AddNamedContentHook("halter", func(evt ContentStoreEvent) *ContentConsumerResult {
		order = append(order, "halter")
		return &ContentConsumerResult{Status: 500, ErrorCode: "halt", Message: "stop"}
	})
	ncs.AddNamedContentHook("third", func(evt ContentStoreEvent) *ContentConsumerResult {
		order = append(order, "third")
		return nil
	})

	e := makeEntity(t, "test/halt", "data")
	if _, err := ncs.Put(e); err != nil {
		t.Fatal(err)
	}

	// Entity should still be stored despite halt.
	if !ncs.Has(e.ContentHash) {
		t.Fatal("entity should be stored despite consumer halt")
	}

	// First and halter ran; third was skipped.
	if len(order) != 2 {
		t.Fatalf("expected 2 hooks to run, got %d: %v", len(order), order)
	}
	if order[0] != "first" || order[1] != "halter" {
		t.Fatalf("unexpected hook order: %v", order)
	}
}

func TestNotifyingContentPassthroughOps(t *testing.T) {
	inner := NewMemoryContentStore()
	ncs := NewNotifyingContentStore(inner)

	e := makeEntity(t, "test/pass", "value")
	h, err := ncs.Put(e)
	if err != nil {
		t.Fatal(err)
	}

	// Has.
	if !ncs.Has(h) {
		t.Fatal("Has should return true")
	}

	// Get.
	got, ok := ncs.Get(h)
	if !ok {
		t.Fatal("Get should find entity")
	}
	if got.Type != "test/pass" {
		t.Fatalf("wrong type: %s", got.Type)
	}

	// Len.
	if ncs.Len() != 1 {
		t.Fatalf("expected Len 1, got %d", ncs.Len())
	}

	// Remove.
	if !ncs.Remove(h) {
		t.Fatal("Remove should succeed")
	}
	if ncs.Has(h) {
		t.Fatal("should not have entity after remove")
	}
	if ncs.Len() != 0 {
		t.Fatalf("expected Len 0, got %d", ncs.Len())
	}
}

func TestNotifyingContentNoHooksStillWorks(t *testing.T) {
	inner := NewMemoryContentStore()
	ncs := NewNotifyingContentStore(inner)

	// No hooks registered — Put should work without error.
	e := makeEntity(t, "test/nohook", "data")
	h, err := ncs.Put(e)
	if err != nil {
		t.Fatal(err)
	}
	if !ncs.Has(h) {
		t.Fatal("entity should be stored")
	}
}

func TestNotifyingContentConcurrentAccess(t *testing.T) {
	inner := NewMemoryContentStore()
	ncs := NewNotifyingContentStore(inner)

	var mu sync.Mutex
	var count int
	ncs.AddNamedContentHook("counter", func(evt ContentStoreEvent) *ContentConsumerResult {
		mu.Lock()
		count++
		mu.Unlock()
		return nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := makeEntity(t, "test/concurrent", i)
			ncs.Put(e)
			ncs.Has(e.ContentHash)
			ncs.Get(e.ContentHash)
		}(i)
	}
	wg.Wait()

	// Each unique entity should fire exactly one event.
	mu.Lock()
	if count != 100 {
		t.Fatalf("expected 100 events, got %d", count)
	}
	mu.Unlock()
}

func TestNotifyingContentDifferentEntitiesBothFire(t *testing.T) {
	inner := NewMemoryContentStore()
	ncs := NewNotifyingContentStore(inner)

	var hashes []string
	ncs.AddNamedContentHook("collector", func(evt ContentStoreEvent) *ContentConsumerResult {
		hashes = append(hashes, evt.Entity.Type)
		return nil
	})

	e1 := makeEntity(t, "test/a", "alpha")
	e2 := makeEntity(t, "test/b", "beta")

	if _, err := ncs.Put(e1); err != nil {
		t.Fatal(err)
	}
	if _, err := ncs.Put(e2); err != nil {
		t.Fatal(err)
	}

	if len(hashes) != 2 {
		t.Fatalf("expected 2 events, got %d", len(hashes))
	}
	if hashes[0] != "test/a" || hashes[1] != "test/b" {
		t.Fatalf("unexpected types: %v", hashes)
	}
}

func TestNotifyingContentRemoveAndReput(t *testing.T) {
	inner := NewMemoryContentStore()
	ncs := NewNotifyingContentStore(inner)

	var count int
	ncs.AddNamedContentHook("counter", func(evt ContentStoreEvent) *ContentConsumerResult {
		count++
		return nil
	})

	e := makeEntity(t, "test/reput", "data")

	// First put — event fires.
	h, err := ncs.Put(e)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event after first put, got %d", count)
	}

	// Remove.
	ncs.Remove(h)

	// Re-put after removal — entity is new again, event fires.
	if _, err := ncs.Put(e); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected 2 events after re-put, got %d", count)
	}
}
