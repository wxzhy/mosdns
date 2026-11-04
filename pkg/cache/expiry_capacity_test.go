package cache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The second hash lookup is expiry cleanup, after Get has read the old value.
// Holding it lets Store publish a replacement before cleanup acquires its lock.
type expiryCleanupKey struct{ gate *expiryCleanupGate }

type expiryCleanupGate struct {
	enabled atomic.Bool
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (k expiryCleanupKey) Sum() uint64 {
	if k.gate.enabled.Load() && k.gate.calls.Add(1) == 2 {
		close(k.gate.entered)
		<-k.gate.release
	}
	return 0
}

func TestExpiredGetPreservesConcurrentReplacement(t *testing.T) {
	c := New[expiryCleanupKey, int](Opts{CleanerInterval: time.Hour})
	defer c.Close()
	gate := &expiryCleanupGate{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	k := expiryCleanupKey{gate: gate}
	c.m.Set(k, &elem[int]{v: 1, expirationTime: time.Now().Add(-time.Hour)})
	gate.enabled.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Get(k)
	}()
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("expired read did not reach cleanup")
	}
	deadline := time.Now().Add(time.Hour)
	c.Store(k, 2, deadline)
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expired read did not finish")
	}
	if got, expiration, ok := c.Get(k); !ok || got != 2 || expiration != deadline {
		t.Fatalf("concurrent replacement lost: value=%d expiration=%v ok=%v", got, expiration, ok)
	}
}

func TestCacheMinimumCapacity(t *testing.T) {
	for _, size := range []int{-1, 0, 1, 63, 64, 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			c := New[testKey, int](Opts{Size: size})
			defer c.Close()
			deadline := time.Now().Add(time.Hour)
			for i := 0; i < 4096; i++ {
				c.Store(testKey(i), i, deadline)
			}
			if got := c.Len(); got != 1024 {
				t.Fatalf("size=%d: actual capacity=%d, want documented minimum 1024", size, got)
			}
		})
	}
}
