package cache

import (
	"testing"
	"time"
)

func TestStoreIfDoesNotOverwriteNewerOrFlushedEntry(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024})
	defer c.Close()
	const k testKey = 19
	deadline := time.Now().Add(time.Minute)
	if c.StoreIf(k, 2, deadline, func(old int) bool { return true }) {
		t.Fatal("StoreIf unexpectedly created an absent key")
	}
	c.Store(k, 1, deadline)
	if !c.StoreIf(k, 2, deadline, func(old int) bool { return old == 1 }) {
		t.Fatal("StoreIf refused unchanged entry")
	}
	if c.StoreIf(k, 3, deadline, func(old int) bool { return old == 1 }) {
		t.Fatal("StoreIf overwrote a newer entry")
	}
	if got, _, ok := c.Get(k); !ok || got != 2 {
		t.Fatalf("unexpected entry after stale update: (%d, %v)", got, ok)
	}
	c.Flush()
	if c.StoreIf(k, 4, deadline, func(old int) bool { return true }) {
		t.Fatal("StoreIf repopulated flushed entry")
	}
	if _, _, ok := c.Get(k); ok {
		t.Fatal("flushed entry reappeared")
	}
}
