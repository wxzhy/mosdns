package cache

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func clientContext(t *testing.T, client string, marker uint32, valueKey uint32) *query_context.Context {
	t.Helper()
	q := query_context.NewContext(new(dns.Msg).SetQuestion("client.policy.test.", dns.TypeA))
	q.ServerMeta.ClientAddr = netip.MustParseAddr(client)
	q.SetMark(marker)
	q.StoreValue(valueKey, "allowed")
	return q
}

func TestClientsShareDNSCacheWithOrWithoutSequenceScope(t *testing.T) {
	for _, scope := range []string{"shared", "sequence"} {
		t.Run(scope, func(t *testing.T) {
			c := NewCache(&Args{Scope: scope, Prefetch: true, PrefetchBeforeExpire: 90, PrefetchMinHits: 1, PrefetchScanInterval: 60}, Opts{})
			defer c.Close()
			valueKey := query_context.RegKey()
			const mark uint32 = 762
			calls, clientExecutions := 0, 0
			chain := policyChain(func(q *query_context.Context) {
				calls++
				if q.ServerMeta.ClientAddr.IsValid() {
					clientExecutions++
				}
				q.SetResponse(policyResponse(q.Q(), net.IPv4(192, 0, 2, 42), 60))
			})
			first := clientContext(t, "192.0.2.1", mark, valueKey)
			second := clientContext(t, "192.0.2.2", mark, valueKey)
			if k1, k2 := c.queryKey(first.Q(), chain), c.queryKey(second.Q(), chain); k1 != k2 {
				t.Fatal("same DNS question must not be partitioned by client address")
			}
			for i, q := range []*query_context.Context{first, second} {
				if err := c.Exec(context.Background(), q, chain); err != nil {
					t.Fatal(err)
				}
				if got := q.R().Answer[0].(*dns.A).A.To4()[3]; got != 42 || q.CacheState.Hit != (i == 1) {
					t.Fatalf("query %d: last octet %d hit=%v", i, got, q.CacheState.Hit)
				}
			}
			if calls != 1 {
				t.Fatalf("shared DNS record must be computed once, got %d", calls)
			}
			k := key(c.queryKey(first.Q(), chain))
			v, _, ok := c.backend.Get(k)
			if !ok || v.next == nil {
				t.Fatal("cache item missing prefetch continuation")
			}
			v.hitCount.Store(2)
			c.doPrefetch(prefetchCandidate{key: k, item: v, next: *v.next})
			if calls != 2 || clientExecutions != 1 {
				t.Fatalf("prefetch replayed client context: calls=%d client-executions=%d", calls, clientExecutions)
			}
			if err := c.Exec(context.Background(), clientContext(t, "192.0.2.3", mark, valueKey), chain); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatal("another client failed to hit refreshed shared cache")
			}
		})
	}
}

func TestFirstNegativeSOATTLMatchesCachedAnswer(t *testing.T) {
	c := NewCache(&Args{}, Opts{})
	defer c.Close()
	var upstreamResponse *dns.Msg
	w := policyChain(func(q *query_context.Context) {
		r := new(dns.Msg).SetReply(q.Q())
		r.Rcode = dns.RcodeNameError
		r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "policy.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 15}, Ns: "ns.policy.test.", Mbox: "root.policy.test.", Minttl: 5}}
		upstreamResponse = r
		q.SetResponse(r)
	})
	for i := 0; i < 2; i++ {
		q := query_context.NewContext(new(dns.Msg).SetQuestion("neg.policy.test.", dns.TypeA))
		q.SetMark(43)
		if err := c.Exec(context.Background(), q, w); err != nil {
			t.Fatal(err)
		}
		if !q.HasMark(43) {
			t.Fatal("SOA normalization dropped query marks")
		}
		if ttl := q.R().Ns[0].Header().Ttl; ttl > 5 {
			t.Fatalf("query %d SOA TTL %d exceeds 5", i, ttl)
		}
	}
	if ttl := upstreamResponse.Ns[0].Header().Ttl; ttl != 15 {
		t.Fatalf("upstream-owned response was mutated: TTL=%d", ttl)
	}
}

func TestDumpRejectsMismatchedQuestionAtomically(t *testing.T) {
	c := NewCache(&Args{}, Opts{})
	defer c.Close()
	good := new(dns.Msg).SetQuestion("valid.policy.test.", dns.TypeA)
	bad := new(dns.Msg).SetQuestion("other.policy.test.", dns.TypeA)
	now := time.Now().Unix()
	makeEntry := func(k *dns.Msg, response *dns.Msg) *CachedEntry {
		packed, err := response.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return &CachedEntry{Key: encodeDumpEntryKey(key(getMsgKey(k)), false), Msg: packed,
			MsgStoredTime: now, MsgExpirationTime: now + 60, CacheExpirationTime: now + 60}
	}
	goodResponse := policyResponse(good, net.IPv4(192, 0, 2, 1), 60)
	badResponse := policyResponse(bad, net.IPv4(192, 0, 2, 2), 60)
	block, err := proto.Marshal(&CacheDumpBlock{Entries: []*CachedEntry{
		makeEntry(good, goodResponse),
		makeEntry(good, badResponse),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	gw.Name = dumpHeader
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(block)))
	_, _ = gw.Write(length[:])
	_, _ = gw.Write(block)
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.readDump(bytes.NewReader(compressed.Bytes())); err == nil {
		t.Fatal("mismatched DNS question was imported")
	}
	if _, _, exists := c.backend.Get(key(getMsgKey(good))); exists {
		t.Fatal("failed import partially stored the valid first record")
	}
}
