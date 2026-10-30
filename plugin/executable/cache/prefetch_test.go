package cache

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestProactivePrefetchReplacesNearExpiryEntry(t *testing.T) {
	c := NewCache(&Args{Prefetch: true, PrefetchBeforeExpire: 10, PrefetchMinHits: 2, PrefetchScanInterval: 1}, Opts{})
	t.Cleanup(func() { _ = c.Close() })
	var calls atomic.Int32
	executor := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		n := calls.Add(1)
		r := new(dns.Msg)
		r.SetReply(q.Q())
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.IPv4(192, 0, 2, byte(n))}}
		q.SetResponse(r)
		return nil
	})
	chain := sequence.NewChainWalker([]*sequence.ChainNode{{E: executor}}, nil)
	query := new(dns.Msg)
	query.SetQuestion("prefetch.example.", dns.TypeA)
	qCtx := query_context.NewContext(query)
	if err := c.Exec(context.Background(), qCtx, chain); err != nil {
		t.Fatal(err)
	}
	k := key(getMsgKey(query))
	v, _, ok := c.backend.Get(k)
	if !ok || v == nil {
		t.Fatal("initial response not cached")
	}
	v.hitCount.Store(3)
	deadline := time.After(4 * time.Second)
	for {
		newer, _, ok := c.backend.Get(k)
		if ok && newer != nil && newer != v && calls.Load() >= 2 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("prefetch did not update cache, calls=%d", calls.Load())
		case <-time.After(30 * time.Millisecond):
		}
	}
}
