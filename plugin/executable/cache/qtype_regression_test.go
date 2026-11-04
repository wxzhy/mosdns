package cache

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func qtypeResponse(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg).SetReply(q)
	hdr := dns.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: q.Question[0].Qclass, Ttl: 60}
	if hdr.Rrtype == dns.TypeA {
		r.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4(192, 0, 2, 1)}}
	} else {
		r.Answer = []dns.RR{&dns.CAA{Hdr: hdr, Tag: "issue", Value: "ca.example"}}
	}
	return r
}

func TestCacheSeparatesAAndCAA(t *testing.T) {
	for _, scope := range []string{"shared", "sequence"} {
		t.Run(scope, func(t *testing.T) {
			c := NewCache(&Args{Scope: scope}, Opts{})
			defer c.Close()
			calls := 0
			chain := sequence.NewChainWalker([]*sequence.ChainNode{
				{Matches: []sequence.Matcher{sequence.MatchFunc(func(_ context.Context, qc *query_context.Context) (bool, error) {
					return qc.R() != nil, nil
				})}, RE: sequence.ActionAccept{}},
				{E: sequence.ExecutableFunc(func(_ context.Context, qc *query_context.Context) error {
					calls++
					qc.SetResponse(qtypeResponse(qc.Q()))
					return nil
				})},
			}, nil)
			for i, typ := range []uint16{dns.TypeA, dns.TypeCAA, dns.TypeA, dns.TypeCAA} {
				q := new(dns.Msg).SetQuestion("types.example.", typ)
				qc := query_context.NewContext(q)
				if err := c.Exec(context.Background(), qc, chain); err != nil {
					t.Fatal(err)
				}
				if r := qc.R(); r == nil || len(r.Question) != 1 || r.Question[0].Qtype != typ || len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != typ {
					t.Fatalf("query type %d received mismatched response: %v", typ, r)
				}
				if qc.CacheState.Hit != (i >= 2) {
					t.Fatalf("query %d cache hit=%v", i, qc.CacheState.Hit)
				}
			}
			if calls != 2 {
				t.Fatalf("upstream calls=%d, want one per type", calls)
			}
		})
	}
}

func TestHighQtypeDumpRoundTrip(t *testing.T) {
	for _, scope := range []string{"", "resolver-chain"} {
		t.Run("scope="+scope, func(t *testing.T) {
			src := NewCache(&Args{}, Opts{})
			defer src.Close()
			for _, typ := range []uint16{dns.TypeA, dns.TypeCAA} {
				q := new(dns.Msg).SetQuestion("types.example.", typ)
				if !saveRespToCache(scopedCacheKey(getMsgKey(q), scope), qtypeResponse(q), src.backend, 0) {
					t.Fatal("could not cache response")
				}
			}
			var dump bytes.Buffer
			if n, err := src.writeDump(&dump); err != nil || n != 2 {
				t.Fatalf("write entries=%d, err=%v", n, err)
			}
			dst := NewCache(&Args{}, Opts{})
			defer dst.Close()
			if n, err := dst.readDump(&dump); err != nil || n != 2 {
				t.Fatalf("read entries=%d, err=%v", n, err)
			}
			for _, typ := range []uint16{dns.TypeA, dns.TypeCAA} {
				q := new(dns.Msg).SetQuestion("types.example.", typ)
				r, _ := getRespFromCache(scopedCacheKey(getMsgKey(q), scope), dst.backend, false, 5)
				if r == nil || r.Question[0].Qtype != typ || r.Answer[0].Header().Rrtype != typ {
					t.Fatalf("restored type %d: %v", typ, r)
				}
			}
		})
	}
}

func TestDumpMigratesTruncatedHighQtype(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, scope := range []string{"", "resolver-chain"} {
			q := new(dns.Msg).SetQuestion("legacy-types.example.", dns.TypeCAA)
			q.Question[0].Qclass = dns.ClassCHAOS
			q.AuthenticatedData, q.CheckingDisabled = true, true
			q.SetEdns0(1232, true)
			name := q.Question[0].Name
			raw := make([]byte, 7+len(name))
			raw[0], raw[2] = 7, byte(q.Question[0].Qtype)
			binary.BigEndian.PutUint16(raw[3:5], q.Question[0].Qclass)
			binary.BigEndian.PutUint16(raw[5:7], uint16(len(name)))
			copy(raw[7:], name)
			if legacy {
				raw = append([]byte{7, 0, byte(q.Question[0].Qtype), byte(len(name))}, name...)
			}
			oldKey := scopedCacheKey(string(raw), scope)
			src := NewCache(&Args{}, Opts{})
			if !saveRespToCache(oldKey, qtypeResponse(q), src.backend, 0) {
				t.Fatal("could not cache legacy response")
			}
			var dump bytes.Buffer
			_, err := src.writeDump(&dump)
			src.Close()
			if err != nil {
				t.Fatal(err)
			}
			dst := NewCache(&Args{}, Opts{})
			n, err := dst.readDump(&dump)
			if err != nil || n != 1 {
				dst.Close()
				t.Fatalf("legacy=%v scope=%q: read entries=%d, err=%v", legacy, scope, n, err)
			}
			want := key(scopedCacheKey(getMsgKey(q), scope))
			v, _, ok := dst.backend.Get(want)
			dst.Close()
			if !ok || v.resp.Question[0].Qtype != dns.TypeCAA {
				t.Fatalf("legacy=%v scope=%q: migrated entry missing", legacy, scope)
			}
		}
	}
}

func TestDumpQtypeMigrationStillRejectsMismatchedFields(t *testing.T) {
	q := new(dns.Msg).SetQuestion("types.example.", dns.TypeCAA)
	for _, tc := range []struct {
		name  string
		alter func([]byte)
	}{
		{"other high byte", func(raw []byte) { raw[1] = 2 }},
		{"other low byte", func(raw []byte) { raw[2] = byte(dns.TypeAAAA) }},
		{"other class", func(raw []byte) { raw[4] = byte(dns.ClassCHAOS) }},
		{"other name", func(raw []byte) { raw[7] = 'x' }},
		{"wrong name length", func(raw []byte) { raw[6]++ }},
		{"invalid flags", func(raw []byte) { raw[0] = 8 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(getMsgKey(q))
			raw[1] = 0 // simulate the old high-byte truncation
			tc.alter(raw)
			if _, _, err := validateDumpEntryKey(encodeDumpEntryKey(key(raw), false), qtypeResponse(q)); err == nil {
				t.Fatal("unrelated serialized key was accepted")
			}
		})
	}
}
