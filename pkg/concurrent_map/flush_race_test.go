package concurrent_map

import (
	"sync"
	"testing"
)

// Run with -race: Flush must exclude all readers and writers while replacing
// the shard map. Keeping a read lock here would race with Get.
func TestMapConcurrentFlush(t *testing.T) {
	m := NewMap[testMapHashable, int]()
	for i := 0; i < 64; i++ {
		m.Set(testMapHashable(i), i)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 12; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				k := testMapHashable((worker*17 + i) % 128)
				switch worker % 3 {
				case 0:
					m.Get(k)
				case 1:
					m.Set(k, i)
				default:
					m.Flush()
				}
			}
		}(worker)
	}
	wg.Wait()
	m.Set(1, 42)
	if got, ok := m.Get(1); !ok || got != 42 {
		t.Fatalf("map unusable after concurrent flush: (%d, %v)", got, ok)
	}
}
