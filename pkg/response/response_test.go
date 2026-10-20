package response

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

var testNow = time.Unix(1_700_000_000, 0)

func testQuery(name string, typ uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	q.Id = 123
	return q
}

func testRR(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func testSnapshot(t *testing.T, q *dns.Msg, answers ...string) query_context.ResponseSnapshot {
	t.Helper()
	r := new(dns.Msg)
	r.SetReply(q)
	r.RecursionAvailable = true
	for _, text := range answers {
		r.Answer = append(r.Answer, testRR(t, text))
	}
	return query_context.ResponseSnapshot{Response: r}
}

func testCandidate(t *testing.T, q *dns.Msg, s query_context.ResponseSnapshot, at time.Time) *Candidate {
	t.Helper()
	c, err := Analyze(q, s, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnalyzeReachableAddresses(t *testing.T) {
	q := testQuery("Example.test.", dns.TypeA)
	s := testSnapshot(t, q,
		"cdn.test. 100 IN A 192.0.2.1",
		"unrelated.test. 1 IN A 192.0.2.99",
		"example.test. 60 IN CNAME CDN.test.",
		"cdn.test. 40 IN A 192.0.2.1",
		"cdn.test. 90 IN A 192.0.2.2",
		"cdn.test. 10 CH A 192.0.2.98",
		"cdn.test. 10 IN AAAA 2001:db8::1")
	s.Response.Extra = []dns.RR{testRR(t, "cdn.test. 1 IN A 192.0.2.97")}
	c := testCandidate(t, q, s, testNow)
	if c.Terminal != "cdn.test." || len(c.Addresses) != 2 || !c.Rewritable || c.Negative {
		t.Fatalf("unexpected candidate: %+v", c)
	}
	for i, address := range c.Addresses {
		if address.IP != netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i+1)) || !address.ExpiresAt.Equal(testNow.Add(40*time.Second)) {
			t.Fatalf("unrelated address or incorrect RRset expiry: %+v", address)
		}
	}
	// Analyze takes an independent snapshot rather than retaining upstream data.
	s.Response.Answer[0].(*dns.A).A[0] = 1
	if got := c.Snapshot.Response.Answer[0].(*dns.A).A.String(); got != "192.0.2.1" {
		t.Fatalf("candidate aliases input: %s", got)
	}
}

func TestAnalyzeUsesRecordedReceiveTime(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	s := testSnapshot(t, q, "example.test. 10 IN A 192.0.2.1")
	s.ReceivedAt = testNow
	// Work after SetResponse must not reset the response's TTL baseline.
	c := testCandidate(t, q, s, testNow.Add(3*time.Second))
	if !c.ReceivedAt.Equal(testNow) || !c.Addresses[0].ExpiresAt.Equal(testNow.Add(10*time.Second)) {
		t.Fatal("analysis reset the recorded receive time")
	}
	got := Replay(c, testNow.Add(4*time.Second))
	if got.Response.Answer[0].Header().Ttl != 6 {
		t.Fatal("post-response sequence work extended TTL")
	}
}

func TestAnalyzeCorrelation(t *testing.T) {
	tests := map[string]func(*dns.Msg){
		"QR":      func(r *dns.Msg) { r.Response = false },
		"ID":      func(r *dns.Msg) { r.Id++ },
		"opcode":  func(r *dns.Msg) { r.Opcode = dns.OpcodeStatus },
		"count":   func(r *dns.Msg) { r.Question = nil },
		"name":    func(r *dns.Msg) { r.Question[0].Name = "other.test." },
		"type":    func(r *dns.Msg) { r.Question[0].Qtype = dns.TypeAAAA },
		"class":   func(r *dns.Msg) { r.Question[0].Qclass = dns.ClassCHAOS },
		"raw OPT": func(r *dns.Msg) { r.SetEdns0(1232, false) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			q := testQuery("example.test.", dns.TypeA)
			s := testSnapshot(t, q, "example.test. 100 IN A 192.0.2.1")
			change(s.Response)
			if _, err := Analyze(q, s, testNow); err == nil {
				t.Fatal("accepted an uncorrelated or invalid snapshot")
			}
		})
	}
	q := testQuery("EXAMPLE.test.", dns.TypeA)
	s := testSnapshot(t, q, "example.test. 100 IN A 192.0.2.1")
	s.Response.Question[0].Name = "example.TEST."
	if _, err := Analyze(q, s, testNow); err != nil {
		t.Fatalf("DNS question names are case insensitive: %v", err)
	}
}

func TestAnalyzeCNAMEInvalid(t *testing.T) {
	tests := map[string][]string{
		"cycle":              {"a.test. 60 IN CNAME b.test.", "b.test. 60 IN CNAME a.test."},
		"conflict":           {"a.test. 60 IN CNAME b.test.", "a.test. 60 IN CNAME c.test."},
		"coexisting address": {"a.test. 60 IN CNAME b.test.", "a.test. 60 IN A 192.0.2.1"},
	}
	for name, records := range tests {
		t.Run(name, func(t *testing.T) {
			q := testQuery("a.test.", dns.TypeA)
			if _, err := Analyze(q, testSnapshot(t, q, records...), testNow); err == nil {
				t.Fatal("accepted malformed alias chain")
			}
		})
	}
	for _, count := range []int{16, 17} {
		t.Run(fmt.Sprintf("%d hops", count), func(t *testing.T) {
			q := testQuery("n0.test.", dns.TypeA)
			var records []string
			for i := 0; i < count; i++ {
				records = append(records, fmt.Sprintf("n%d.test. 60 IN CNAME n%d.test.", i, i+1))
			}
			records = append(records, fmt.Sprintf("n%d.test. 60 IN A 192.0.2.1", count))
			_, err := Analyze(q, testSnapshot(t, q, records...), testNow)
			if (err == nil) != (count == 16) {
				t.Fatalf("hop bound: %v", err)
			}
		})
	}
}

func TestAnalyzeNegativeAndOpaque(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	t.Run("NODATA", func(t *testing.T) {
		c := testCandidate(t, q, testSnapshot(t, q, "example.test. 60 IN CNAME empty.test."), testNow)
		if !c.Negative || c.Rewritable || len(c.Addresses) != 0 || c.Terminal != "empty.test." {
			t.Fatalf("incorrect NODATA: %+v", c)
		}
	})
	t.Run("NXDOMAIN", func(t *testing.T) {
		s := testSnapshot(t, q)
		s.Response.Rcode = dns.RcodeNameError
		if !testCandidate(t, q, s, testNow).Negative {
			t.Fatal("NXDOMAIN is a negative candidate")
		}
	})
	t.Run("SERVFAIL", func(t *testing.T) {
		s := testSnapshot(t, q)
		s.Response.Rcode = dns.RcodeServerFailure
		if c := testCandidate(t, q, s, testNow); c.Negative || c.Rewritable {
			t.Fatal("transient failure was classified as negative data")
		}
	})
	for name, opaqueRR := range map[string]dns.RR{
		"DNAME": &dns.DNAME{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 60}, Target: "other."},
		"TSIG":  &dns.TSIG{Hdr: dns.RR_Header{Name: "key.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}},
		"SIG0":  &dns.SIG{RRSIG: dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY}}},
	} {
		t.Run(name, func(t *testing.T) {
			s := testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1")
			s.Response.Extra = []dns.RR{opaqueRR}
			c := testCandidate(t, q, s, testNow)
			if c.Rewritable || c.Negative || len(c.Addresses) != 1 {
				t.Fatalf("opaque positive candidate was not preserved: %+v", c)
			}
		})
	}
	t.Run("other type", func(t *testing.T) {
		q := testQuery("example.test.", dns.TypeMX)
		c := testCandidate(t, q, testSnapshot(t, q, "example.test. 60 IN MX 10 mail.test."), testNow)
		if c.Rewritable || c.Negative || len(c.Addresses) != 0 {
			t.Fatalf("non-address query should remain opaque: %+v", c)
		}
	})
}

func TestReplayPreservesDNSSECAndAges(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	q.SetEdns0(1232, true)
	s := testSnapshot(t, q, "example.test. 10 IN A 192.0.2.1")
	s.Response.AuthenticatedData = true
	s.Response.Answer = append(s.Response.Answer, &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 10},
		TypeCovered: dns.TypeA, OrigTtl: 100,
	})
	s.Response.Ns = []dns.RR{testRR(t, "example.test. 1 IN NS ns.test.")}
	s.Response.Extra = []dns.RR{testRR(t, "ns.test. 0 IN A 192.0.2.2")}
	s.UpstreamOpt, s.RespOpt = testOPT(), testOPT()
	s.UpstreamOpt.SetDo()
	s.RespOpt.SetDo()
	s.RespOpt.Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: []byte{0, 0}}}
	c := testCandidate(t, q, s, testNow)
	if c.Rewritable || len(c.Addresses) != 1 {
		t.Fatal("DO response must be available for whole-source ranking only")
	}
	got := Replay(c, testNow.Add(1500*time.Millisecond))
	if !got.ReceivedAt.Equal(testNow.Add(1500 * time.Millisecond)) {
		t.Fatal("replayed TTLs must have a new received-at baseline")
	}
	if !got.Response.AuthenticatedData || len(got.Response.Answer) != 2 || got.Response.Answer[0].Header().Ttl != 8 {
		t.Fatalf("replay changed signed content or aged incorrectly: %v", got.Response)
	}
	if sig := got.Response.Answer[1].(*dns.RRSIG); sig.OrigTtl != 100 || sig.Hdr.Ttl != 8 {
		t.Fatal("RRSIG Original TTL was modified")
	}
	if got.Response.Ns[0].Header().Ttl != 0 || got.Response.Extra[0].Header().Ttl != 0 || !got.RespOpt.Do() {
		t.Fatal("expired TTL must remain zero; OPT flags must not be aged")
	}
	got.Response.Answer[0].(*dns.A).A[0] = 1
	got.RespOpt.Option[0].(*dns.EDNS0_PADDING).Padding[0] = 1
	if c.Snapshot.Response.Answer[0].(*dns.A).A.String() != "192.0.2.1" ||
		c.Snapshot.RespOpt.Option[0].(*dns.EDNS0_PADDING).Padding[0] != 0 {
		t.Fatal("replay aliases candidate data")
	}
}

func TestRebuildMultiSourceProvenance(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	s1 := testSnapshot(t, q, "example.test. 100 IN CNAME cdn.test.", "cdn.test. 100 IN A 192.0.2.1")
	s1.Response.AuthenticatedData, s1.Response.Authoritative = true, true
	s1.Response.Answer = append(s1.Response.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "cdn.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 100}, TypeCovered: dns.TypeA})
	s1.Response.Ns = []dns.RR{testRR(t, "test. 100 IN SOA ns.test. hostmaster.test. 1 2 3 4 5")}
	s1.Response.Extra = []dns.RR{testRR(t, "unrelated.test. 100 IN A 192.0.2.99")}
	a := testCandidate(t, q, s1, testNow)
	s2 := testSnapshot(t, q, "example.test. 8 IN CNAME CDN.test.", "cdn.test. 80 IN A 192.0.2.2")
	b := testCandidate(t, q, s2, testNow.Add(2*time.Second))
	if !Compatible(a, b) {
		t.Fatal("equivalent complete alias chains should combine")
	}
	selected := []SelectedAddress{{Candidate: b, Address: b.Addresses[0]}, {Candidate: a, Address: a.Addresses[0]}}
	// A forged longer expiry cannot extend the stored address provenance.
	selected[0].Address.ExpiresAt = testNow.Add(24 * time.Hour)
	got, err := Rebuild(a, selected, testNow.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !got.ReceivedAt.Equal(testNow.Add(4 * time.Second)) {
		t.Fatal("rebuilt TTLs must have a new received-at baseline")
	}
	if len(got.Response.Answer) != 3 || len(got.Response.Ns) != 0 || len(got.Response.Extra) != 0 || got.Response.AuthenticatedData || got.Response.Authoritative {
		t.Fatalf("rebuild retained source-specific authentication/proofs: %v", got.Response)
	}
	for _, rr := range got.Response.Answer {
		if rr.Header().Ttl != 6 {
			t.Fatalf("contributing alias expiry did not cap all output records: %v", rr)
		}
	}
	if ip := got.Response.Answer[1].(*dns.A).A.String(); ip != "192.0.2.2" {
		t.Fatalf("selection order not preserved: %s", ip)
	}
	if s1.Response.Answer[0].Header().Ttl != 100 || !s1.Response.AuthenticatedData || a.Snapshot.Response.Answer[0].Header().Ttl != 100 {
		t.Fatal("rebuild mutated a source or candidate")
	}
	zero, err := Rebuild(a, selected, testNow.Add(10*time.Second))
	if err != nil || zero.Response.Answer[0].Header().Ttl != 0 {
		t.Fatalf("expired provenance was extended: %v, %v", zero.Response, err)
	}
}

func TestRebuildRejectsIncompatibleAndForeignAddress(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	a := testCandidate(t, q, testSnapshot(t, q, "example.test. 60 IN CNAME cdn.test.", "cdn.test. 60 IN A 192.0.2.1"), testNow)
	b := testCandidate(t, q, testSnapshot(t, q,
		"example.test. 60 IN CNAME middle.test.", "middle.test. 60 IN CNAME cdn.test.", "cdn.test. 60 IN A 192.0.2.2"), testNow)
	if a.Terminal != b.Terminal || Compatible(a, b) {
		t.Fatal("different intermediate aliases must not merge despite equal terminal")
	}
	if _, err := Rebuild(a, []SelectedAddress{{Candidate: b, Address: b.Addresses[0]}}, testNow); err == nil {
		t.Fatal("merged incompatible chain")
	}
	if _, err := Rebuild(a, []SelectedAddress{{Candidate: a, Address: Address{IP: netip.MustParseAddr("192.0.2.99"), Index: 1}}}, testNow); err == nil {
		t.Fatal("accepted foreign address provenance")
	}
	if _, err := Rebuild(a, nil, testNow); err == nil {
		t.Fatal("accepted empty selection")
	}
}

func TestRebuildDuplicateAndIPv6(t *testing.T) {
	q := testQuery("example.test.", dns.TypeAAAA)
	a := testCandidate(t, q, testSnapshot(t, q, "example.test. 60 IN AAAA 2001:db8::1"), testNow)
	b := testCandidate(t, q, testSnapshot(t, q, "example.test. 10 IN AAAA 2001:db8::1"), testNow)
	got, err := Rebuild(a, []SelectedAddress{{Candidate: a, Address: a.Addresses[0]}, {Candidate: b, Address: b.Addresses[0]}}, testNow)
	if err != nil || len(got.Response.Answer) != 1 || got.Response.Answer[0].Header().Ttl != 10 {
		t.Fatalf("duplicate provenance must retain minimum TTL: %v, %v", got.Response, err)
	}
	if rr, ok := got.Response.Answer[0].(*dns.AAAA); !ok || rr.AAAA.String() != "2001:db8::1" {
		t.Fatal("IPv6 answer changed family")
	}
}

func testOPT() *dns.OPT {
	opt := new(dns.OPT)
	opt.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}
	opt.SetUDPSize(1232)
	return opt
}

func testECS(addr string, source, scope uint8) *dns.EDNS0_SUBNET {
	family := uint16(2)
	if net.ParseIP(addr).To4() != nil {
		family = 1
	}
	return &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: source, SourceScope: scope, Address: net.ParseIP(addr)}
}

func TestECSValidationAndRebuild(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = []dns.EDNS0{testECS("192.0.2.50", 24, 0)}
	snapshot := func(scope uint8, ip string) query_context.ResponseSnapshot {
		s := testSnapshot(t, q, "example.test. 60 IN A "+ip)
		s.UpstreamOpt, s.RespOpt = testOPT(), testOPT()
		s.UpstreamOpt.Option = []dns.EDNS0{testECS("192.0.2.0", 24, scope), &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "deadbeef"}}
		s.RespOpt.Option = []dns.EDNS0{testECS("192.0.2.0", 24, scope), &dns.EDNS0_PADDING{Padding: make([]byte, 16)}, &dns.EDNS0_EDE{InfoCode: 0, ExtraText: "source"}}
		return s
	}
	a := testCandidate(t, q, snapshot(16, "192.0.2.1"), testNow)
	b := testCandidate(t, q, snapshot(24, "192.0.2.2"), testNow)
	if !Compatible(a, b) {
		t.Fatal("compatible response scopes from the same query should combine")
	}
	got, err := Rebuild(a, []SelectedAddress{{Candidate: a, Address: a.Addresses[0]}, {Candidate: b, Address: b.Addresses[0]}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []*dns.OPT{got.UpstreamOpt, got.RespOpt} {
		if opt == nil || len(opt.Option) != 1 {
			t.Fatalf("source-specific OPT leaked: %v", opt)
		}
		ecs := opt.Option[0].(*dns.EDNS0_SUBNET)
		if ecs.SourceScope != 24 || ecs.SourceNetmask != 24 || ecs.Address.String() != "192.0.2.0" {
			t.Fatalf("incorrect combined ECS scope: %v", ecs)
		}
	}
	// A policy that did not forward ECS downstream must not start echoing it.
	a.Snapshot.RespOpt.Option = nil
	got, err = Rebuild(a, []SelectedAddress{{Candidate: a, Address: a.Addresses[0]}, {Candidate: b, Address: b.Addresses[0]}}, testNow)
	if err != nil || len(got.RespOpt.Option) != 0 {
		t.Fatalf("introduced an unsolicited downstream ECS: %v, %v", got.RespOpt, err)
	}
	for name, mutate := range map[string]func(*dns.Msg, *query_context.ResponseSnapshot){
		"unsolicited": func(q *dns.Msg, s *query_context.ResponseSnapshot) { q.IsEdns0().Option = nil },
		"wrong prefix": func(q *dns.Msg, s *query_context.ResponseSnapshot) {
			s.UpstreamOpt.Option[0] = testECS("192.0.3.0", 24, 24)
		},
		"wrong source mask": func(q *dns.Msg, s *query_context.ResponseSnapshot) {
			s.UpstreamOpt.Option[0] = testECS("192.0.2.0", 25, 24)
		},
		"duplicate": func(q *dns.Msg, s *query_context.ResponseSnapshot) {
			q.IsEdns0().Option = append(q.IsEdns0().Option, testECS("192.0.2.0", 24, 0))
		},
		"query scope": func(q *dns.Msg, s *query_context.ResponseSnapshot) {
			q.IsEdns0().Option[0].(*dns.EDNS0_SUBNET).SourceScope = 24
		},
		"conflicting downstream": func(q *dns.Msg, s *query_context.ResponseSnapshot) {
			s.RespOpt.Option[0].(*dns.EDNS0_SUBNET).SourceScope = 20
		},
	} {
		t.Run(name, func(t *testing.T) {
			qc, s := q.Copy(), snapshot(24, "192.0.2.1")
			mutate(qc, &s)
			if _, err := Analyze(qc, s, testNow); err == nil {
				t.Fatal("accepted inconsistent ECS")
			}
		})
	}
}

func TestECSViewIsolation(t *testing.T) {
	makeCandidate := func(addr string) *Candidate {
		q := testQuery("example.test.", dns.TypeA)
		q.SetEdns0(1232, false)
		q.IsEdns0().Option = []dns.EDNS0{testECS(addr, 24, 0)}
		return testCandidate(t, q, testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1"), testNow)
	}
	a, b, c := makeCandidate("192.0.2.1"), makeCandidate("192.0.2.2"), makeCandidate("192.0.3.1")
	if !Compatible(a, b) || Compatible(a, c) {
		t.Fatal("effective ECS request prefixes were not isolated")
	}
}

func TestECSResponseScopeMayExceedSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		addr   string
		source uint8
		scope  uint8
		bits   uint8
	}{
		{name: "IPv4", addr: "192.0.2.0", source: 24, scope: 32, bits: 32},
		{name: "IPv6", addr: "2001:db8:1200::", source: 56, scope: 64, bits: 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := testQuery("example.test.", dns.TypeA)
			q.SetEdns0(1232, false)
			q.IsEdns0().Option = []dns.EDNS0{testECS(tc.addr, tc.source, 0)}
			s := testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1")
			s.UpstreamOpt, s.RespOpt = testOPT(), testOPT()
			s.UpstreamOpt.Option = []dns.EDNS0{testECS(tc.addr, tc.source, tc.scope)}
			s.RespOpt.Option = []dns.EDNS0{testECS(tc.addr, tc.source, tc.scope)}
			c := testCandidate(t, q, s, testNow)
			got, err := Rebuild(c, []SelectedAddress{{Candidate: c, Address: c.Addresses[0]}}, testNow)
			if err != nil {
				t.Fatal(err)
			}
			ecs := got.RespOpt.Option[0].(*dns.EDNS0_SUBNET)
			if ecs.SourceScope != tc.scope || ecs.SourceNetmask != tc.source {
				t.Fatal("legitimate longer scope was rejected or truncated")
			}
			// No extra address bits are added when encoding the larger scope.
			wireMsg := got.Response.Copy()
			wireMsg.Extra = append(wireMsg.Extra, got.RespOpt)
			wire, err := wireMsg.Pack()
			if err != nil {
				t.Fatal(err)
			}
			decoded := new(dns.Msg)
			if err := decoded.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			decodedECS := decoded.IsEdns0().Option[0].(*dns.EDNS0_SUBNET)
			if decodedECS.SourceNetmask != tc.source || decodedECS.SourceScope != tc.scope {
				t.Fatal("wire roundtrip changed ECS prefix lengths")
			}
			s.UpstreamOpt.Option[0].(*dns.EDNS0_SUBNET).SourceScope = tc.bits + 1
			if _, err := Analyze(q, s, testNow); err == nil {
				t.Fatal("accepted a scope exceeding the address family's bit length")
			}
		})
	}
}

func TestParallelReplayAndRebuildOwnTheirRecords(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	q.CheckingDisabled = true
	s := testSnapshot(t, q, "example.test. 60 IN CNAME cdn.test.", "cdn.test. 60 IN A 192.0.2.1")
	// Upstream header flags must not override the request's CD/RD in a fresh
	// policy answer.
	s.Response.CheckingDisabled = false
	s.Response.RecursionDesired = false
	s.RespOpt = testOPT()
	s.RespOpt.Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: []byte{0}}}
	c := testCandidate(t, q, s, testNow)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				replay := Replay(c, testNow.Add(time.Second))
				replay.Response.Answer[1].(*dns.A).A[0] = 1
				replay.RespOpt.Option[0].(*dns.EDNS0_PADDING).Padding[0] = 1
				built, err := Rebuild(c, []SelectedAddress{{Candidate: c, Address: c.Addresses[0]}}, testNow.Add(time.Second))
				if err != nil {
					t.Error(err)
					return
				}
				if !built.Response.CheckingDisabled || !built.Response.RecursionDesired {
					t.Error("rebuilt flags do not follow query")
				}
				built.Response.Answer[1].(*dns.A).A[0] = 2
			}
		}()
	}
	wg.Wait()
	if got := c.Snapshot.Response.Answer[1].(*dns.A).A.String(); got != "192.0.2.1" {
		t.Fatalf("concurrent output mutation reached the candidate: %s", got)
	}
}
