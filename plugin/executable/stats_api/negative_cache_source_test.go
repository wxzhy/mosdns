package stats_api

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	cacheexec "github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestLocalNegativeCachedResponseRemainsBlocked(t *testing.T) {
	c := cacheexec.NewCache(&cacheexec.Args{}, cacheexec.Opts{})
	defer c.Close()
	s := NewStatsAPI(&Args{}, nil)
	defer s.Close()
	var calls int
	upstream := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		if q.R() != nil {
			return nil
		}
		calls++
		r := new(dns.Msg).SetReply(q.Q())
		r.Rcode = dns.RcodeNameError
		r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.test.", Mbox: "hostmaster.test.", Minttl: 60}}
		q.SetResponse(r)
		return nil
	})}}, nil)
	cacheNext := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		return c.Exec(ctx, q, upstream)
	})}}, nil)
	for i := range 2 {
		q := query_context.NewContext(new(dns.Msg).SetQuestion("blocked.test.", dns.TypeA))
		if err := s.Exec(context.Background(), q, cacheNext); err != nil {
			t.Fatal(err)
		}
		if q.CacheState.Hit != (i == 1) {
			t.Fatalf("query %d wrong cache hit: %+v", i, q.CacheState)
		}
	}
	if calls != 1 || s.blockedQueries.Load() != 2 || s.cachedQueries.Load() != 0 {
		t.Fatalf("local cached NXDOMAIN misclassified: calls=%d blocked=%d cached=%d", calls, s.blockedQueries.Load(), s.cachedQueries.Load())
	}
	_, logs := s.ringBuffer.QueryLogs(2, 0, "", "all")
	if len(logs) != 2 || !logs[0].IsBlocked || !logs[1].IsBlocked {
		t.Fatalf("cached and uncached negative log classification mismatch: %+v", logs)
	}
}
