package cache

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func cacheTestResponse(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
		A:   net.IPv4(192, 0, 2, 5),
	}}
	return r
}

func TestPrefetchWorkerConcurrencyAndDedup(t *testing.T) {
	c := NewCache(&Args{Prefetch: true, PrefetchBeforeExpire: 10, PrefetchMinHits: 2, PrefetchScanInterval: 1}, Opts{})
	t.Cleanup(func() { _ = c.Close() })
	var isRefresh atomic.Bool
	var running atomic.Int32
	var maxRunning atomic.Int32
	var refreshes atomic.Int32
	release := make(chan struct{})
	defer close(release)

	exec := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		if isRefresh.Load() {
			now := running.Add(1)
			for {
				max := maxRunning.Load()
				if now <= max || maxRunning.CompareAndSwap(max, now) {
					break
				}
			}
			refreshes.Add(1)
			select {
			case <-ctx.Done():
				running.Add(-1)
				return ctx.Err()
			case <-release:
			}
			running.Add(-1)
		}
		q.SetResponse(cacheTestResponse(q.Q()))
		return nil
	})
	chain := sequence.NewChainWalker([]*sequence.ChainNode{{E: exec}}, nil)

	for i := 0; i < 12; i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("prefetch-%d.test.", i), dns.TypeA)
		if err := c.Exec(context.Background(), query_context.NewContext(q), chain); err != nil {
			t.Fatal(err)
		}
		v, _, ok := c.backend.Get(key(getMsgKey(q)))
		if !ok || v == nil {
			t.Fatal("initial entry not cached")
		}
		v.hitCount.Store(3)
	}
	isRefresh.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for maxRunning.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	if maxRunning.Load() < 2 {
		t.Fatalf("prefetch still executes serially; max concurrent = %d", maxRunning.Load())
	}
	// While the first wave is blocked, the second scan must not launch a
	// second refresh for any key already queued or running.
	time.Sleep(1200 * time.Millisecond)
	if n := refreshes.Load(); n > prefetchWorkerCount {
		t.Fatalf("prefetch exceeded bounded workers: %d", n)
	}
}

func TestPrefetchCannotRestoreFlushedEntry(t *testing.T) {
	c := NewCache(&Args{Prefetch: true, PrefetchBeforeExpire: 10, PrefetchMinHits: 1, PrefetchScanInterval: 1}, Opts{})
	t.Cleanup(func() { _ = c.Close() })
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWorker()
	var count atomic.Int32
	exec := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		if count.Add(1) > 1 {
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		q.SetResponse(cacheTestResponse(q.Q()))
		return nil
	})
	chain := sequence.NewChainWalker([]*sequence.ChainNode{{E: exec}}, nil)
	q := new(dns.Msg)
	q.SetQuestion("flush.test.", dns.TypeA)
	if err := c.Exec(context.Background(), query_context.NewContext(q), chain); err != nil {
		t.Fatal(err)
	}
	k := key(getMsgKey(q))
	v, _, ok := c.backend.Get(k)
	if !ok || v == nil {
		t.Fatal("initial entry not cached")
	}
	v.hitCount.Store(3)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("prefetch did not start")
	}
	c.Flush()
	releaseWorker()
	// The worker may still be completing its response; StoreIf must fail.
	time.Sleep(80 * time.Millisecond)
	if _, _, exists := c.backend.Get(k); exists {
		t.Fatal("a completed prefetch repopulated a flushed cache")
	}
}
