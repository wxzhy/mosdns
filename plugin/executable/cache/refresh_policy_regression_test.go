package cache

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func policyResponse(q *dns.Msg, ip net.IP, ttl uint32) *dns.Msg {
	r := new(dns.Msg).SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: q.Question[0].Qclass, Ttl: ttl}, A: ip}}
	return r
}

func policyChain(fn func(*query_context.Context)) sequence.ChainWalker {
	return sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		if q.R() == nil {
			fn(q)
		}
		return nil
	})}}, nil)
}

func TestPrefetchUsesEntryProducingContinuation(t *testing.T) {
	c := NewCache(&Args{Prefetch: true, PrefetchBeforeExpire: 20, PrefetchMinHits: 1, PrefetchScanInterval: 60}, Opts{})
	defer c.Close()
	a := policyChain(func(q *query_context.Context) { q.SetResponse(policyResponse(q.Q(), net.IPv4(192, 0, 2, 1), 10)) })
	b := policyChain(func(q *query_context.Context) { q.SetResponse(policyResponse(q.Q(), net.IPv4(192, 0, 2, 2), 10)) })
	qa, qb := new(dns.Msg).SetQuestion("a.prefetch.test.", dns.TypeA), new(dns.Msg).SetQuestion("b.prefetch.test.", dns.TypeA)
	if err := c.Exec(context.Background(), query_context.NewContext(qa), a); err != nil {
		t.Fatal(err)
	}
	if err := c.Exec(context.Background(), query_context.NewContext(qb), b); err != nil {
		t.Fatal(err)
	}
	k := key(getMsgKey(qb))
	v, _, ok := c.backend.Get(k)
	if !ok || v.next == nil {
		t.Fatal("producing continuation not attached")
	}
	v.hitCount.Store(2)
	c.doPrefetch(prefetchCandidate{key: k, item: v, next: *v.next})
	got, _, exists := c.backend.Get(k)
	if !exists || !got.resp.Answer[0].(*dns.A).A.Equal(net.IPv4(192, 0, 2, 2)) {
		t.Fatalf("prefetch executed unrelated A continuation: %+v", got)
	}
}

func TestBackgroundRefreshRejectsDownstreamECS(t *testing.T) {
	c := NewCache(&Args{Prefetch: true, PrefetchBeforeExpire: 20, PrefetchMinHits: 1, PrefetchScanInterval: 60, LazyCacheTTL: 30}, Opts{})
	defer c.Close()
	var changed bool
	chain := policyChain(func(q *query_context.Context) {
		if changed {
			q.Q().SetEdns0(1232, false)
			q.Q().IsEdns0().Option = append(q.Q().IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 1)})
		}
		q.SetResponse(policyResponse(q.Q(), net.IPv4(192, 0, 2, 3), 10))
	})
	q := new(dns.Msg).SetQuestion("ecs.prefetch.test.", dns.TypeA)
	if err := c.Exec(context.Background(), query_context.NewContext(q), chain); err != nil {
		t.Fatal(err)
	}
	k := key(getMsgKey(q))
	v, _, ok := c.backend.Get(k)
	if !ok || v.next == nil {
		t.Fatal("missing initial entry")
	}
	v.hitCount.Store(2)
	changed = true
	c.doPrefetch(prefetchCandidate{key: k, item: v, next: *v.next})
	if current, _, _ := c.backend.Get(k); current != v {
		t.Fatal("prefetch cached an ECS-mutated response under ordinary key")
	}
	c.doLazyUpdate(string(k), query_context.NewContext(q.Copy()), chain)
	c.lazyWG.Wait()
	if current, _, _ := c.backend.Get(k); current != v {
		t.Fatal("lazy refresh cached an ECS-mutated response under ordinary key")
	}
}

func TestNegativeSOATTLAndCachedClassificationSurviveDump(t *testing.T) {
	c := NewCache(&Args{}, Opts{})
	defer c.Close()
	q := new(dns.Msg).SetQuestion("block.negative.test.", dns.TypeA)
	w := policyChain(func(q *query_context.Context) {
		r := new(dns.Msg).SetReply(q.Q())
		r.Rcode = dns.RcodeNameError
		r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "negative.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 15}, Ns: "ns.negative.test.", Mbox: "hostmaster.negative.test.", Minttl: 5}}
		q.SetResponse(r)
	})
	if err := c.Exec(context.Background(), query_context.NewContext(q.Copy()), w); err != nil {
		t.Fatal(err)
	}
	k := key(getMsgKey(q))
	v, _, ok := c.backend.Get(k)
	if !ok {
		t.Fatal("valid NXDOMAIN with SOA was not cached")
	}
	if got := v.expirationTime.Sub(v.storedTime); got != 5*time.Second {
		t.Fatalf("negative TTL=%v, want 5s", got)
	}
	if soa := v.resp.Ns[0].(*dns.SOA); soa.Hdr.Ttl != 5 {
		t.Fatalf("cached SOA TTL = %d, want 5", soa.Hdr.Ttl)
	}
	cacheHit := query_context.NewContext(q.Copy())
	if err := c.Exec(context.Background(), cacheHit, w); err != nil {
		t.Fatal(err)
	}
	if !cacheHit.CacheState.Hit || !cacheHit.CacheState.LocalNegative {
		t.Fatal("cached local negative response lost blocked source")
	}
	if ttl := cacheHit.R().Ns[0].Header().Ttl; ttl > 5 {
		t.Fatalf("cached negative response returned SOA TTL %d > 5", ttl)
	}
	var data bytes.Buffer
	if _, err := c.writeDump(&data); err != nil {
		t.Fatal(err)
	}
	restored := NewCache(&Args{}, Opts{})
	defer restored.Close()
	if _, err := restored.readDump(&data); err != nil {
		t.Fatal(err)
	}
	recovered := query_context.NewContext(q.Copy())
	if err := restored.Exec(context.Background(), recovered, w); err != nil {
		t.Fatal(err)
	}
	if !recovered.CacheState.Hit || !recovered.CacheState.LocalNegative {
		t.Fatal("cache dump lost negative source classification")
	}
	// Without an SOA, a negative response has no trustworthy cache lifetime.
	r := new(dns.Msg).SetReply(q)
	r.Rcode = dns.RcodeNameError
	if saveRespToCache(getMsgKey(q), r, c.backend, 0) {
		t.Fatal("NXDOMAIN without SOA must not be cached")
	}
}
