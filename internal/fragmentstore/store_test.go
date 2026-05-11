package fragmentstore

import (
	"testing"
	"time"
)

func TestCollectSingleFragmentMarksCompletedWithinRetention(t *testing.T) {
	store := New[string](4)
	now := time.Unix(1700000000, 0)

	assembled, ready, completed := store.Collect("req", []byte("hello"), 0, 1, now, 5*time.Minute)
	if !ready || completed {
		t.Fatalf("expected first single-fragment collect to complete once, ready=%v completed=%v", ready, completed)
	}
	if string(assembled) != "hello" {
		t.Fatalf("unexpected assembled payload: %q", string(assembled))
	}

	assembled, ready, completed = store.Collect("req", []byte("hello"), 0, 1, now.Add(time.Second), 5*time.Minute)
	if ready || !completed || assembled != nil {
		t.Fatalf("expected duplicate single-fragment collect to be completed-only, ready=%v completed=%v payload=%v", ready, completed, assembled)
	}
}

func TestRemoveIfClearsItemsAndCompletedEntries(t *testing.T) {
	store := New[int](4)
	now := time.Unix(1700000000, 0)

	if _, ready, _ := store.Collect(1, []byte("a"), 0, 2, now, 5*time.Minute); ready {
		t.Fatal("expected first fragment to stay incomplete")
	}
	if _, ready, completed := store.Collect(2, []byte("b"), 0, 1, now, 5*time.Minute); !ready || completed {
		t.Fatal("expected single fragment key to complete")
	}

	store.RemoveIf(func(key int) bool { return key == 1 || key == 2 })

	if _, ready, completed := store.Collect(1, []byte("c"), 1, 2, now.Add(time.Second), 5*time.Minute); ready || completed {
		t.Fatalf("expected removed incomplete key to behave as empty state, ready=%v completed=%v", ready, completed)
	}
	if payload, ready, completed := store.Collect(2, []byte("d"), 0, 1, now.Add(time.Second), 5*time.Minute); !ready || completed || string(payload) != "d" {
		t.Fatalf("expected removed completed key to accept new data, ready=%v completed=%v payload=%q", ready, completed, string(payload))
	}
}

func TestStoreCapacityEvictsOldestIncompleteEntry(t *testing.T) {
	store := New[int](1)
	now := time.Unix(1700000000, 0)

	if _, ready, _ := store.Collect(1, []byte("old-0"), 0, 2, now, 5*time.Minute); ready {
		t.Fatal("first fragment should be incomplete")
	}
	if len(store.items) != 1 {
		t.Fatalf("unexpected item count after first fragment: %d", len(store.items))
	}

	if _, ready, _ := store.Collect(2, []byte("new-0"), 0, 2, now.Add(time.Second), 5*time.Minute); ready {
		t.Fatal("second key first fragment should be incomplete")
	}
	if len(store.items) != 1 {
		t.Fatalf("capacity must cap incomplete entries, got %d", len(store.items))
	}
	if _, ok := store.items[1]; ok {
		t.Fatal("oldest incomplete entry was not evicted")
	}
	if _, ok := store.items[2]; !ok {
		t.Fatal("new incomplete entry was not retained")
	}
}

func TestStoreCapacityEvictsOldestCompletedEntry(t *testing.T) {
	store := New[int](1)
	now := time.Unix(1700000000, 0)

	if _, ready, completed := store.Collect(1, []byte("one"), 0, 1, now, 5*time.Minute); !ready || completed {
		t.Fatal("first single-fragment key should complete")
	}
	if _, ready, completed := store.Collect(2, []byte("two"), 0, 1, now.Add(time.Second), 5*time.Minute); !ready || completed {
		t.Fatal("second single-fragment key should complete")
	}
	if len(store.completed) != 1 {
		t.Fatalf("capacity must cap completed entries, got %d", len(store.completed))
	}
	if _, ok := store.completed[1]; ok {
		t.Fatal("oldest completed entry was not evicted")
	}
	if _, ok := store.completed[2]; !ok {
		t.Fatal("new completed entry was not retained")
	}

	if payload, ready, completed := store.Collect(1, []byte("one-again"), 0, 1, now.Add(2*time.Second), 5*time.Minute); !ready || completed || string(payload) != "one-again" {
		t.Fatalf("evicted completed key should be accepted as new, ready=%v completed=%v payload=%q", ready, completed, string(payload))
	}
}
