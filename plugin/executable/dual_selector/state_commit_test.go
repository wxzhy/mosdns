package dual_selector

import (
	"context"
	"net"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestPreferIPv4CommitsOnlyPassingOriginalContext(t *testing.T) {
	for _, block := range []bool{false, true} {
		t.Run(map[bool]string{false: "pass", true: "block"}[block], func(t *testing.T) {
			selector := NewPreferIpv4(sequence.NewBQ(coremain.NewTestMosdnsWithPlugins(nil), zap.NewNop()))
			defer selector.Close()
			valueKey, retainedKey := query_context.RegKey(), query_context.RegKey()
			q := query_context.NewContext(new(dns.Msg).SetQuestion("example.", dns.TypeAAAA))
			q.SetMark(7)
			q.StoreValue(valueKey, "parent")
			q.StoreValue(retainedKey, "parent-only")
			worker := sequence.ExecutableFunc(func(_ context.Context, branch *query_context.Context) error {
				r := new(dns.Msg).SetReply(branch.Q())
				if branch.QQuestion().Qtype == dns.TypeA {
					branch.SetMark(99)
					branch.StoreValue(valueKey, "reference")
					if block {
						r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
					}
				} else {
					branch.DeleteMark(7)
					branch.SetMark(8)
					branch.StoreValue(valueKey, "original")
					branch.DeleteValue(retainedKey)
					branch.Q().RecursionDesired = false
					branch.ServerMeta.UrlPath = "/modified"
					r.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
				}
				branch.SetResponse(r)
				return nil
			})
			chain := sequence.NewChainWalker([]*sequence.ChainNode{{E: worker}}, nil)
			if err := selector.Exec(context.Background(), q, chain); err != nil {
				t.Fatal(err)
			}
			if q.HasMark(99) {
				t.Fatal("reference branch mark escaped")
			}
			if block {
				if !q.HasMark(7) || q.HasMark(8) {
					t.Fatal("blocked response changed parent marks")
				}
				if v, _ := q.GetValue(valueKey); v != "parent" {
					t.Fatalf("blocked response changed parent KV: %v", v)
				}
				return
			}
			if q.HasMark(7) || !q.HasMark(8) || q.Q().RecursionDesired || q.ServerMeta.UrlPath != "/modified" {
				t.Fatal("passing original branch was not fully committed")
			}
			if v, _ := q.GetValue(valueKey); v != "original" {
				t.Fatalf("original KV was not committed: %v", v)
			}
			if _, exists := q.GetValue(retainedKey); exists {
				t.Fatal("original branch KV deletion was not committed")
			}
		})
	}
}
