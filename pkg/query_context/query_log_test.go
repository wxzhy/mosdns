package query_context

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"go.uber.org/zap/zapcore"
)

func TestQueryLogIncludesHistoricalFieldsWithoutChangingContext(t *testing.T) {
	q := new(dns.Msg).SetQuestion("alias.example.", dns.TypeA)
	q.SetEdns0(1232, true)
	c := NewContext(q)
	c.ServerMeta.Protocol = "DoH"
	c.SetUpstreamSelected("https://dns.example/dns-query", "DoH", "remote", "forward_remote")
	c.SetCacheState(true, true, 120, 5)
	c.AddRuleHit("main", []string{"qname $remote_domains"}, "$forward_remote")
	r := new(dns.Msg).SetReply(c.Q())
	for _, record := range []string{"alias.example. 120 IN CNAME target.example.", "target.example. 60 IN A 192.0.2.5", "target.example. 60 IN AAAA 2001:db8::5"} {
		rr, err := dns.NewRR(record)
		if err != nil {
			t.Fatal(err)
		}
		r.Answer = append(r.Answer, rr)
	}
	c.SetResponse(r)
	before := c.SnapshotResponse()
	queryBefore := c.Q().String()
	for _, detailed := range []bool{false, true} {
		enc := zapcore.NewMapObjectEncoder()
		if err := c.QueryLogObject(c.R(), detailed).MarshalLogObject(enc); err != nil {
			t.Fatal(err)
		}
		if enc.Fields["qname"] != "alias.example." || enc.Fields["qtype"] != "A" || enc.Fields["protocol"] != "DoH" || enc.Fields["rcode"] != dns.RcodeSuccess || enc.Fields["resp_size"] != r.Len() || enc.Fields["original_ttl"] != uint32(60) {
			t.Fatalf("missing historical query fields: %+v", enc.Fields)
		}
		if _, present := enc.Fields["rule_hits"]; present != detailed {
			t.Fatalf("rule detail = %v, want %v", present, detailed)
		}
		if !reflect.DeepEqual(enc.Fields["ips"], []any{"192.0.2.5", "2001:db8::5"}) || !reflect.DeepEqual(enc.Fields["cnames"], []any{"target.example."}) {
			t.Fatalf("missing response answers: %+v", enc.Fields)
		}
		upstream, ok := enc.Fields["upstream"].(map[string]any)
		if !ok || upstream["addr"] != "https://dns.example/dns-query" || upstream["protocol"] != "DoH" || upstream["plugin"] != "forward_remote" {
			t.Fatalf("upstream detail = %v", enc.Fields["upstream"])
		}
		cache, ok := enc.Fields["cache"].(map[string]any)
		if !ok || cache["hit"] != true || cache["lazy_hit"] != true || cache["ttl"] != 120 || cache["remaining_ttl"] != 5 {
			t.Fatalf("cache detail = %v", enc.Fields["cache"])
		}
	}
	if c.Q().String() != queryBefore || !reflect.DeepEqual(before, c.SnapshotResponse()) {
		t.Fatal("query logging modified query, lifetime, EDNS or metadata")
	}
}

func TestQueryLogUsesFinalResponseAndProtocolFallbacks(t *testing.T) {
	for _, fromUDP := range []bool{false, true} {
		q := new(dns.Msg).SetQuestion("unknown.example.", 65534)
		c := NewContext(q)
		c.ServerMeta.FromUDP = fromUDP
		c.SetFromHosts()
		c.SetResponse(new(dns.Msg).SetReply(c.Q()))
		final := new(dns.Msg).SetRcode(c.Q(), dns.RcodeServerFailure)
		enc := zapcore.NewMapObjectEncoder()
		if err := c.QueryLogObject(final, true).MarshalLogObject(enc); err != nil {
			t.Fatal(err)
		}
		wantProtocol := "TCP"
		if fromUDP {
			wantProtocol = "UDP"
		}
		if enc.Fields["qtype"] != "TYPE65534" || enc.Fields["protocol"] != wantProtocol || enc.Fields["rcode"] != dns.RcodeServerFailure || enc.Fields["hosts"] != true || c.R().Rcode != dns.RcodeSuccess {
			t.Fatalf("final response/fallback detail = %+v", enc.Fields)
		}
	}
}
