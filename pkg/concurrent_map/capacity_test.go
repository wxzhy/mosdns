package concurrent_map

import (
	"fmt"
	"testing"
)

func TestMapCachePositiveCapacity(t *testing.T) {
	for _, test := range []struct{ size, capacity int }{{1, 64}, {63, 64}, {64, 64}, {65, 64}, {1024, 1024}} {
		t.Run(fmt.Sprint(test.size), func(t *testing.T) {
			m := NewMapCache[testMapHashable, int](test.size)
			for i := 0; i < 4096; i++ {
				m.Set(testMapHashable(i), i)
			}
			if got := m.Len(); got != test.capacity {
				t.Fatalf("size=%d: actual capacity=%d, want %d", test.size, got, test.capacity)
			}
		})
	}
}

func TestMapCacheNonpositiveCapacityRemainsUnbounded(t *testing.T) {
	for _, size := range []int{0, -1} {
		m := NewMapCache[testMapHashable, int](size)
		for i := 0; i < 4096; i++ {
			m.Set(testMapHashable(i), i)
		}
		if got := m.Len(); got != 4096 {
			t.Fatalf("size=%d: unbounded map lost entries: %d", size, got)
		}
	}
}

func TestUpdatingFullShardPreservesOtherEntries(t *testing.T) {
	const capacity = 1024
	m := NewMapCache[testMapHashable, int](capacity)
	for i := 0; i < capacity; i++ {
		m.Set(testMapHashable(i), i)
	}
	for i := 0; i < MapShardSize; i++ {
		// Replace one entry in every full shard, leaving its other 15 entries
		// untouched. No insertion should be necessary for any of these writes.
		m.Set(testMapHashable(i), -i)
	}
	for i := 0; i < capacity; i++ {
		want := i
		if i < MapShardSize {
			want = -i
		}
		if got, ok := m.Get(testMapHashable(i)); !ok || got != want {
			t.Fatalf("existing key %d after update = %d, %v; want %d", i, got, ok, want)
		}
	}
}
