package cache

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestOptionalSequenceScopedCache(t *testing.T) {
	c := NewCache(&Args{Scope: "sequence"}, Opts{})
	defer c.Close()
	callCount := [2]int{}
	makeChain := func(i byte) sequence.ChainWalker {
		return sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
			if q.R() != nil {
				return nil
			}
			callCount[i-1]++
			r := new(dns.Msg).SetReply(q.Q())
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, i)}}
			q.SetResponse(r)
			return nil
		})}}, nil)
	}
	a, b := makeChain(1), makeChain(2)
	if a.CacheScope() == b.CacheScope() {
		t.Fatal("two independent continuations got the same cache scope")
	}
	for _, tc := range []struct {
		chain sequence.ChainWalker
		want  byte
		hit   bool
	}{
		{a, 1, false}, {b, 2, false}, {a, 1, true}, {b, 2, true},
	} {
		q := cacheSafetyQuery(dns.ClassINET)
		if err := c.Exec(context.Background(), q, tc.chain); err != nil {
			t.Fatal(err)
		}
		if got := q.R().Answer[0].(*dns.A).A.To4()[3]; got != tc.want || q.CacheState.Hit != tc.hit {
			t.Fatalf("scope leaked: got %d hit=%v, want %d hit=%v", got, q.CacheState.Hit, tc.want, tc.hit)
		}
	}
	if callCount != [2]int{1, 1} {
		t.Fatalf("unexpected executions %v", callCount)
	}
	// Dump and restore preserve the partition in its stored key.
	var dump bytes.Buffer
	if _, err := c.writeDump(&dump); err != nil {
		t.Fatal(err)
	}
	restored := NewCache(&Args{Scope: "sequence"}, Opts{})
	defer restored.Close()
	if _, err := restored.readDump(&dump); err != nil {
		t.Fatal(err)
	}
	q := cacheSafetyQuery(dns.ClassINET)
	if err := restored.Exec(context.Background(), q, b); err != nil {
		t.Fatal(err)
	}
	if !q.CacheState.Hit || q.R().Answer[0].(*dns.A).A.To4()[3] != 2 {
		t.Fatal("restored cache lost sequence partition")
	}
}

func TestSequenceScopedPrefetchPreservesDNSFlags(t *testing.T) {
	c := NewCache(&Args{Scope: "sequence", Prefetch: true, PrefetchBeforeExpire: 90, PrefetchMinHits: 1, PrefetchScanInterval: 60}, Opts{})
	defer c.Close()
	chain := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		if q.R() == nil {
			r := new(dns.Msg).SetReply(q.Q())
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 8)}}
			q.SetResponse(r)
		}
		return nil
	})}}, nil)
	q := cacheSafetyQuery(dns.ClassINET)
	q.Q().SetEdns0(1232, true)
	q.Q().CheckingDisabled = true
	if err := c.Exec(context.Background(), q, chain); err != nil {
		t.Fatal(err)
	}
	k := key(c.queryKey(q.Q(), chain))
	v, _, ok := c.backend.Get(k)
	if !ok || v.next == nil {
		t.Fatal("scoped DNSSEC entry not stored")
	}
	v.hitCount.Store(2)
	c.doPrefetch(prefetchCandidate{key: k, item: v, next: *v.next})
	updated, _, ok := c.backend.Get(k)
	if !ok || updated == v {
		t.Fatal("prefetch did not refresh scoped DNSSEC cache entry")
	}
}
