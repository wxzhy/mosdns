package ip_replace

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func intPointer(n int) *int { return &n }

func testReplacer(t *testing.T, rules ...Rule) *Replacer {
	t.Helper()
	p, err := New(nil, &Args{ReplaceMap: rules})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testContext(qtype uint16, ips ...string) *query_context.Context {
	q := new(dns.Msg).SetQuestion("cdn.example.", qtype)
	q.SetEdns0(1232, false)
	qCtx := query_context.NewContext(q)
	r := new(dns.Msg).SetReply(qCtx.Q())
	for _, ip := range ips {
		h := dns.RR_Header{Name: "cdn.example.", Rrtype: qtype, Class: dns.ClassINET, Ttl: 300}
		if qtype == dns.TypeA {
			r.Answer = append(r.Answer, &dns.A{Hdr: h, A: net.ParseIP(ip)})
		} else {
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: h, AAAA: net.ParseIP(ip)})
		}
	}
	qCtx.SetResponse(r)
	return qCtx
}

func addressStrings(q *query_context.Context) []string {
	var out []string
	for _, rr := range q.R().Answer {
		switch rr := rr.(type) {
		case *dns.A:
			out = append(out, rr.A.String())
		case *dns.AAAA:
			out = append(out, rr.AAAA.String())
		}
	}
	return out
}

func TestPrefixes(t *testing.T) {
	for _, tt := range []struct {
		name, original, target, expected string
		prefix                           *int
		qtype                            uint16
	}{
		{"v4_default_fixed", "192.0.2.42", "203.0.113.99", "203.0.113.99", nil, dns.TypeA},
		{"v4_full", "192.0.2.42", "203.0.113.99", "203.0.113.99", intPointer(32), dns.TypeA},
		{"v4_zero", "192.0.2.42", "203.0.113.99", "192.0.2.42", intPointer(0), dns.TypeA},
		{"v4_normalized", "192.0.2.42", "203.0.113.99", "203.0.113.42", intPointer(24), dns.TypeA},
		{"v4_non_byte", "192.0.2.200", "203.0.113.99", "203.0.113.72", intPointer(25), dns.TypeA},
		{"v4_one_bit", "192.0.2.42", "1.1.1.1", "64.0.2.42", intPointer(1), dns.TypeA},
		{"v4_last_bit", "192.0.2.43", "203.0.113.98", "203.0.113.99", intPointer(31), dns.TypeA},
		{"v6_default_fixed", "2001:db8:20:1::abcd", "2001:db8:100::99", "2001:db8:100::99", nil, dns.TypeAAAA},
		{"v6_full", "2001:db8:20:1::abcd", "2001:db8:100::99", "2001:db8:100::99", intPointer(128), dns.TypeAAAA},
		{"v6_zero", "2001:db8:20:1::abcd", "2001:db8:100::99", "2001:db8:20:1::abcd", intPointer(0), dns.TypeAAAA},
		{"v6_normalized", "2001:db8:20:1:1234:5678:9abc:def0", "2001:db8:100:2:ffff::99", "2001:db8:100:2:1234:5678:9abc:def0", intPointer(64), dns.TypeAAAA},
		{"v6_non_byte", "2001:db8:20:1:9234:5678:9abc:def0", "2001:db8:100:2:1000::99", "2001:db8:100:2:1234:5678:9abc:def0", intPointer(65), dns.TypeAAAA},
		{"v6_last_bit", "2001:db8::1", "2001:db8:100::98", "2001:db8:100::99", intPointer(127), dns.TypeAAAA},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{MatchIP: []string{tt.original}}
			if tt.qtype == dns.TypeA {
				rule.IPv4, rule.IPv4PrefixLen = []string{tt.target}, tt.prefix
			} else {
				rule.IPv6, rule.IPv6PrefixLen = []string{tt.target}, tt.prefix
			}
			q := testContext(tt.qtype, tt.original)
			if err := testReplacer(t, rule).Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if got := addressStrings(q); !slices.Equal(got, []string{tt.expected}) {
				t.Fatalf("addresses %v, want %s", got, tt.expected)
			}
		})
	}
}

func TestRuleAndRecordPriority(t *testing.T) {
	tests := []struct {
		name  string
		ips   []string
		rules []Rule
		want  []string
	}{
		{"rule_before_record", []string{"192.0.2.1", "198.51.100.42"}, []Rule{
			{MatchIP: []string{"198.51.100.0/24"}, IPv4PrefixLen: intPointer(24), IPv4: []string{"203.0.113.0"}},
			{MatchIP: []string{"192.0.2.0/24"}, IPv4: []string{"203.0.113.99"}},
		}, []string{"203.0.113.42"}},
		{"first_record_drives_all_targets", []string{"192.0.2.42", "192.0.2.20"}, []Rule{
			{MatchIP: []string{"192.0.2.0/24"}, IPv4PrefixLen: intPointer(24), IPv4: []string{"203.0.113.99", "198.51.100.0"}},
		}, []string{"203.0.113.42", "198.51.100.42"}},
		{"exclude_skips_single_address", []string{"192.0.2.42", "192.0.2.20"}, []Rule{
			{MatchIP: []string{"192.0.2.0/24"}, ExcludeIP: []string{"192.0.2.42"}, IPv4PrefixLen: intPointer(24), IPv4: []string{"203.0.113.0"}},
		}, []string{"203.0.113.20"}},
		{"or_match", []string{"198.51.100.42"}, []Rule{
			{MatchIP: []string{"192.0.2.0/24", "198.51.100.0/24"}, IPv4: []string{"203.0.113.99"}},
		}, []string{"203.0.113.99"}},
		{"empty_family_target_stops_rules", []string{"192.0.2.42"}, []Rule{
			{MatchIP: []string{"192.0.2.0/24"}, IPv6: []string{"2001:db8::1"}},
			{MatchIP: []string{"192.0.2.0/24"}, IPv4: []string{"203.0.113.99"}},
		}, []string{"192.0.2.42"}},
		{"excluded_all_tries_next_rule", []string{"192.0.2.42"}, []Rule{
			{MatchIP: []string{"192.0.2.0/24"}, ExcludeIP: []string{"192.0.2.42"}, IPv4: []string{"198.51.100.99"}},
			{MatchIP: []string{"192.0.2.0/24"}, IPv4: []string{"203.0.113.99"}},
		}, []string{"203.0.113.99"}},
		{"normalized_targets_deduplicated_stably", []string{"192.0.2.42"}, []Rule{
			{MatchIP: []string{"192.0.2.0/24"}, IPv4PrefixLen: intPointer(24), IPv4: []string{"203.0.113.99", "198.51.100.13", "203.0.113.1", "198.51.100.12"}},
		}, []string{"203.0.113.42", "198.51.100.42"}},
		{"zero_prefix_deduplicates", []string{"192.0.2.42"}, []Rule{
			{MatchIP: []string{"192.0.2.0/24"}, IPv4PrefixLen: intPointer(0), IPv4: []string{"203.0.113.99", "198.51.100.13"}},
		}, []string{"192.0.2.42"}},
		{"no_match", []string{"192.0.2.42"}, []Rule{
			{MatchIP: []string{"198.51.100.0/24"}, IPv4: []string{"203.0.113.99"}},
		}, []string{"192.0.2.42"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := testContext(dns.TypeA, tt.ips...)
			if err := testReplacer(t, tt.rules...).Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if got := addressStrings(q); !slices.Equal(got, tt.want) {
				t.Fatalf("addresses %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name string
		rule Rule
	}{
		{"missing_match", Rule{}},
		{"empty_match", Rule{MatchIP: []string{""}}},
		{"invalid_match", Rule{MatchIP: []string{"no-such-ip"}}},
		{"invalid_exclude", Rule{MatchIP: []string{"192.0.2.0/24"}, ExcludeIP: []string{"invalid"}}},
		{"missing_provider_context", Rule{MatchIP: []string{"$existing"}}},
		{"empty_provider", Rule{MatchIP: []string{"$"}}},
		{"empty_file", Rule{MatchIP: []string{"&"}}},
		{"missing_file", Rule{MatchIP: []string{"&does-not-exist-123456789"}}},
		{"v4_negative", Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4PrefixLen: intPointer(-1)}},
		{"v4_overflow", Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4PrefixLen: intPointer(33)}},
		{"v6_negative", Rule{MatchIP: []string{"::/0"}, IPv6PrefixLen: intPointer(-1)}},
		{"v6_overflow", Rule{MatchIP: []string{"::/0"}, IPv6PrefixLen: intPointer(129)}},
		{"v4_target_v6", Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"2001:db8::1"}}},
		{"v6_target_v4", Rule{MatchIP: []string{"::/0"}, IPv6: []string{"192.0.2.1"}}},
		{"target_prefix", Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"192.0.2.0/24"}}},
		{"target_zone", Rule{MatchIP: []string{"::/0"}, IPv6: []string{"fe80::1%eth0"}}},
		{"target_mapped_v6", Rule{MatchIP: []string{"::/0"}, IPv6: []string{"::ffff:192.0.2.1"}}},
		{"target_empty", Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{""}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(nil, &Args{ReplaceMap: []Rule{tt.rule}}); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
	if _, err := New(nil, nil); err == nil {
		t.Fatal("nil args accepted")
	}
}

func TestFileMatcherAndImmutableArguments(t *testing.T) {
	file := filepath.Join(t.TempDir(), "networks.txt")
	if err := os.WriteFile(file, []byte("192.0.2.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prefix := 24
	args := &Args{ReplaceMap: []Rule{{MatchIP: []string{"&" + file}, IPv4PrefixLen: &prefix, IPv4: []string{"203.0.113.99"}}}}
	p, err := New(nil, args)
	if err != nil {
		t.Fatal(err)
	}
	prefix = 32
	args.ReplaceMap[0].IPv4[0] = "198.51.100.1"
	args.ReplaceMap[0].MatchIP[0] = "invalid"
	if err := os.WriteFile(file, []byte("198.51.100.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	q := testContext(dns.TypeA, "192.0.2.42")
	if err := p.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if got := addressStrings(q); !slices.Equal(got, []string{"203.0.113.42"}) {
		t.Fatal(got)
	}
}

func TestNoOpCases(t *testing.T) {
	p := testReplacer(t, Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"203.0.113.99"}})
	for _, tt := range []struct {
		name string
		edit func(*query_context.Context)
	}{
		{"no_response", func(q *query_context.Context) { q.SetResponse(nil) }},
		{"nxdomain", func(q *query_context.Context) { q.R().Rcode = dns.RcodeNameError; q.R().Answer = nil }},
		{"nodata", func(q *query_context.Context) { q.R().Answer = nil }},
		{"servfail", func(q *query_context.Context) { q.R().Rcode = dns.RcodeServerFailure; q.R().Answer = nil }},
		{"truncated", func(q *query_context.Context) { q.R().Truncated = true }},
		{"non_in", func(q *query_context.Context) {
			q.Q().Question[0].Qclass = dns.ClassCHAOS
			q.R().Question[0].Qclass = dns.ClassCHAOS
		}},
		{"non_address", func(q *query_context.Context) {
			q.Q().Question[0].Qtype = dns.TypeHTTPS
			q.R().Question[0].Qtype = dns.TypeHTTPS
		}},
		{"query_do", func(q *query_context.Context) { q.QOpt().SetDo() }},
		{"dname", func(q *query_context.Context) {
			q.R().Answer = append(q.R().Answer, &dns.DNAME{Hdr: dns.RR_Header{Name: "unrelated.example.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 1}, Target: "elsewhere.example."})
		}},
		{"tsig", func(q *query_context.Context) {
			q.R().Extra = append(q.R().Extra, &dns.TSIG{Hdr: dns.RR_Header{Name: "key.example.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			q := testContext(dns.TypeA, "192.0.2.42")
			tt.edit(q)
			before := q.SnapshotResponse()
			if err := p.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if before.Response == nil {
				if q.R() != nil {
					t.Fatal("created an unsolicited response")
				}
			} else if before.Response.String() != q.R().String() || before.ReceivedAt != q.ResponseReceivedAt() {
				t.Fatal("no-op changed response or timing")
			}
		})
	}
	q := testContext(dns.TypeA, "192.0.2.42")
	if err := testReplacer(t).Exec(context.Background(), q); err != nil || addressStrings(q)[0] != "192.0.2.42" {
		t.Fatal("empty rule set must be a no-op", err)
	}
}

func TestClientDOProtectsResponseEvenAfterQueryDOChanged(t *testing.T) {
	query := new(dns.Msg).SetQuestion("cdn.example.", dns.TypeA)
	query.SetEdns0(1232, true)
	q := query_context.NewContext(query)
	q.QOpt().SetDo(false)
	r := new(dns.Msg).SetReply(q.Q())
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.42")}}
	q.SetResponse(r)
	p := testReplacer(t, Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"203.0.113.99"}})
	if err := p.Exec(context.Background(), q); err != nil || addressStrings(q)[0] != "192.0.2.42" {
		t.Fatal("client DO must protect original RRset", err)
	}
}

func TestInvalidResponseAndCancellation(t *testing.T) {
	p := testReplacer(t, Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"203.0.113.99"}})
	for _, edit := range []func(*query_context.Context){
		func(q *query_context.Context) { q.Q().Question = nil },
		func(q *query_context.Context) { q.Q().Question = append(q.Q().Question, q.QQuestion()) },
		func(q *query_context.Context) { q.Q().Response = true },
		func(q *query_context.Context) { q.R().Response = false },
		func(q *query_context.Context) { q.R().Id++ },
		func(q *query_context.Context) { q.R().Question[0].Name = "different.example." },
		func(q *query_context.Context) { q.R().Answer[0].(*dns.A).A = nil },
		func(q *query_context.Context) {
			q.R().Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: "cdn.example."}}
		},
	} {
		q := testContext(dns.TypeA, "192.0.2.42")
		edit(q)
		if err := p.Exec(context.Background(), q); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
	q := testContext(dns.TypeA, "192.0.2.42")
	before := q.R().String()
	ctx, cancel := context.WithCancelCause(context.Background())
	want := errors.New("request abandoned")
	cancel(want)
	if err := p.Exec(ctx, q); !errors.Is(err, want) || q.R().String() != before {
		t.Fatal("cancellation must propagate without changing response", err)
	}
}

type matcherFunc func(netip.Addr) bool

func (f matcherFunc) Match(ip netip.Addr) bool { return f(ip) }

func TestCancellationDuringMatchDoesNotCommit(t *testing.T) {
	q := testContext(dns.TypeA, "192.0.2.42")
	original := q.R()
	before := q.SnapshotResponse()
	ctx, cancel := context.WithCancelCause(context.Background())
	want := errors.New("request expired during policy evaluation")
	p := testReplacer(t, Rule{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"203.0.113.99"}})
	p.rules[0].match = matcherFunc(func(netip.Addr) bool { cancel(want); return true })
	if err := p.Exec(ctx, q); !errors.Is(err, want) {
		t.Fatalf("cancellation error %v, want %v", err, want)
	}
	if q.R() != original || q.R().String() != before.Response.String() || q.ResponseReceivedAt() != before.ReceivedAt {
		t.Fatal("canceled replacement committed response state")
	}
}

func TestTerminalOnlyAndIndependentResponse(t *testing.T) {
	q := testContext(dns.TypeA, "192.0.2.42")
	q.R().Answer[0].Header().Name = "terminal.example."
	q.R().Answer = append([]dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "unrelated.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("198.51.100.1")},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "terminal.example."},
	}, q.R().Answer...)
	q.R().Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "terminal.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("198.51.100.2")}}
	q.R().AuthenticatedData, q.R().Authoritative = true, true
	original := q.R()
	originalBefore, queryBefore := original.String(), q.Q().Copy()
	queryOptBefore := q.QOpt()
	p := testReplacer(t,
		Rule{MatchIP: []string{"198.51.100.0/24"}, IPv4: []string{"203.0.113.1"}},
		Rule{MatchIP: []string{"192.0.2.0/24"}, IPv4PrefixLen: intPointer(24), IPv4: []string{"203.0.113.99"}},
	)
	if err := p.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if got := addressStrings(q); !slices.Equal(got, []string{"203.0.113.42"}) {
		t.Fatal(got)
	}
	if q.R().Answer[0].(*dns.CNAME).Target != "terminal.example." || q.R().Answer[1].Header().Name != "terminal.example." || q.R().AuthenticatedData || q.R().Authoritative {
		t.Fatal("chain, terminal owner, or authentication state is incorrect")
	}
	if q.Q().String() != queryBefore.String() || q.QOpt() != queryOptBefore {
		t.Fatal("replacement changed query state")
	}
	if original.String() != originalBefore || original == q.R() {
		t.Fatal("replacement changed original response")
	}
	if len(q.R().Extra) != 0 {
		t.Fatal("unrelated Additional address survived rebuilding")
	}
}

func TestRemainingTTLAndZeroTTL(t *testing.T) {
	for _, ttl := range []uint32{0, 1, 30} {
		q := testContext(dns.TypeA, "192.0.2.42")
		q.R().Answer[0].Header().Ttl = ttl
		snapshot := q.SnapshotResponse()
		snapshot.ReceivedAt = time.Now().Add(-1500 * time.Millisecond)
		q.CommitResponse(snapshot)
		p := testReplacer(t, Rule{MatchIP: []string{"192.0.2.0/24"}, IPv4: []string{"203.0.113.99"}})
		err := p.Exec(context.Background(), q)
		if ttl == 1 {
			if err == nil || q.R().Answer[0].Header().Ttl != 1 || !slices.Equal(addressStrings(q), []string{"192.0.2.42"}) || q.ResponseReceivedAt() != snapshot.ReceivedAt {
				t.Fatal("expired source was rewritten or its original state changed")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		want := uint32(0)
		if ttl > 1 {
			want = ttl - 2
		}
		if got := q.R().Answer[0].Header().Ttl; got != want {
			t.Fatalf("original TTL %d aged to %d, want %d", ttl, got, want)
		}
	}
}

func TestReplacementBitBoundaries(t *testing.T) {
	// Check every prefix, including those whose host bits straddle a byte.
	for _, pair := range [][2]string{{"192.173.82.213", "203.69.113.99"}, {"2001:db8:20:1234:9234:5678:9abc:def0", "2001:db8:100:5678:ffff:aaaa:bbbb:cccc"}} {
		original, target := netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])
		for prefix := 0; prefix <= original.BitLen(); prefix++ {
			base := netip.PrefixFrom(target, prefix).Masked().Addr()
			got := replaceIP(original, base, prefix)
			if !netip.PrefixFrom(target, prefix).Contains(got) {
				t.Fatalf("/%d result %s escaped target network", prefix, got)
			}
			originalBits, targetBits, gotBits := addressBits(original), addressBits(target), addressBits(got)
			if gotBits != targetBits[:prefix]+originalBits[prefix:] {
				t.Fatalf("/%d result %s has incorrect host bits", prefix, got)
			}
		}
	}
}

func addressBits(ip netip.Addr) string {
	var out strings.Builder
	for _, b := range ip.AsSlice() {
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<bit) == 0 {
				out.WriteByte('0')
			} else {
				out.WriteByte('1')
			}
		}
	}
	return out.String()
}
