package response

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestReplayPreservesPositiveLifetimeAfterRoundingToZero(t *testing.T) {
	for _, do := range []bool{false, true} {
		q := testQuery("example.test.", dns.TypeA)
		q.SetEdns0(1232, do)
		s := testSnapshot(t, q, "example.test. 1 IN A 192.0.2.1")
		if !do {
			s.Response.Extra = []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Name: "key.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}}}
		}
		c := testCandidate(t, q, s, testNow)
		for _, elapsed := range []time.Duration{600 * time.Millisecond, 900 * time.Millisecond, 1100 * time.Millisecond} {
			s = Replay(c, testNow.Add(elapsed))
			if !s.ValidUntil.Equal(testNow.Add(time.Second)) || s.Response.Answer[0].Header().Ttl != 0 {
				t.Fatalf("DO=%v repeated full replay lost source lifetime: %+v", do, s)
			}
			c = testCandidate(t, q, s, testNow.Add(elapsed))
		}
	}
}

func TestReplaceAddressesPreservesChainAndReplacementOrder(t *testing.T) {
	for _, tc := range []struct {
		name, source, unrelated string
		typ                     uint16
		ips                     []netip.Addr
	}{
		{
			name: "IPv4", source: "192.0.2.42", unrelated: "192.0.2.99", typ: dns.TypeA,
			ips: []netip.Addr{netip.MustParseAddr("203.0.113.42"), netip.MustParseAddr("198.51.100.42"), netip.MustParseAddr("203.0.113.42")},
		},
		{
			name: "IPv6", source: "2001:db8::42", unrelated: "2001:db8::99", typ: dns.TypeAAAA,
			ips: []netip.Addr{netip.MustParseAddr("2001:db8:1::42"), netip.MustParseAddr("2001:db8:2::42"), netip.MustParseAddr("2001:db8:1::42")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := testQuery("Example.test.", tc.typ)
			q.CheckingDisabled = true
			typeName := dns.TypeToString[tc.typ]
			s := testSnapshot(t, q,
				"Example.test. 60 IN CNAME CDN.test.",
				"CDN.test. 50 IN "+typeName+" "+tc.source,
				"unrelated.test. 1 IN "+typeName+" "+tc.unrelated)
			s.Response.Authoritative, s.Response.AuthenticatedData = true, true
			s.Response.CheckingDisabled, s.Response.RecursionDesired = false, false
			s.Response.Answer = append(s.Response.Answer, &dns.RRSIG{
				Hdr: dns.RR_Header{Name: "CDN.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 50}, TypeCovered: tc.typ,
			})
			s.Response.Ns = []dns.RR{testRR(t, "test. 1 IN NSEC next.test. A AAAA RRSIG")}
			s.Response.Extra = []dns.RR{testRR(t, "glue.test. 1 IN A 192.0.2.100")}
			c := testCandidate(t, q, s, testNow)
			before := c.Snapshot.Clone()
			ipsBefore := append([]netip.Addr(nil), tc.ips...)
			now := testNow.Add(2 * time.Second)
			got, err := ReplaceAddresses(c, tc.ips, now)
			if err != nil {
				t.Fatal(err)
			}
			r := got.Response
			if len(r.Answer) != 3 || len(r.Ns) != 0 || len(r.Extra) != 0 {
				t.Fatalf("retained source records or lost deduplicated addresses: %v", r)
			}
			if r.AuthenticatedData || r.Authoritative || !r.CheckingDisabled || !r.RecursionDesired || !r.RecursionAvailable || r.Id != q.Id {
				t.Fatalf("incorrect synthesized header: %+v", r.MsgHdr)
			}
			if !reflect.DeepEqual(r.Question, q.Question) || !got.ReceivedAt.Equal(now) {
				t.Fatal("query or TTL baseline changed")
			}
			if cn := r.Answer[0].(*dns.CNAME); cn.Hdr.Name != "Example.test." || cn.Target != "CDN.test." {
				t.Fatalf("alias text changed: %v", cn)
			}
			for i, rr := range r.Answer {
				if rr.Header().Ttl != 48 {
					t.Fatalf("unrelated TTL capped response or original TTL extended: %v", rr)
				}
				if i == 0 {
					continue
				}
				if rr.Header().Name != "cdn.test." || rr.Header().Class != dns.ClassINET || rr.Header().Rrtype != tc.typ {
					t.Fatalf("replacement changed owner, class or address family: %v", rr)
				}
				var ip netip.Addr
				switch rr := rr.(type) {
				case *dns.A:
					ip, _ = netip.AddrFromSlice(rr.A)
				case *dns.AAAA:
					ip, _ = netip.AddrFromSlice(rr.AAAA)
				}
				if ip != tc.ips[i-1] {
					t.Fatalf("replacement order changed: %s", ip)
				}
			}
			if !reflect.DeepEqual(c.Snapshot, before) || !reflect.DeepEqual(tc.ips, ipsBefore) {
				t.Fatal("replacement mutated candidate or address input")
			}
			// Each result also owns its generated IP bytes and cloned CNAMEs.
			r.Answer[0].(*dns.CNAME).Target = "changed.test."
			switch rr := r.Answer[1].(type) {
			case *dns.A:
				rr.A[0] = 1
			case *dns.AAAA:
				rr.AAAA[0] = 1
			}
			if !reflect.DeepEqual(c.Snapshot, before) || !reflect.DeepEqual(tc.ips, ipsBefore) {
				t.Fatal("returned response aliases candidate or address input")
			}
		})
	}
}

func TestReplaceAddressesExpiryUsesOriginalRRsetAndReceiveTime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		answers   []string
		now       time.Time
		wantTTL   uint32
		wantUntil time.Time
	}{
		{"short address", []string{"example.test. 12 IN CNAME cdn.test.", "cdn.test. 4 IN A 192.0.2.1"}, testNow.Add(1500 * time.Millisecond), 2, testNow.Add(4 * time.Second)},
		{"short alias", []string{"example.test. 3 IN CNAME cdn.test.", "cdn.test. 10 IN A 192.0.2.1"}, testNow.Add(1500 * time.Millisecond), 1, testNow.Add(3 * time.Second)},
		{"zero alias", []string{"example.test. 0 IN CNAME cdn.test.", "cdn.test. 10 IN A 192.0.2.1"}, testNow, 0, testNow.Add(10 * time.Second)},
		{"zero duplicate", []string{"example.test. 10 IN A 192.0.2.1", "example.test. 0 IN A 192.0.2.1"}, testNow, 0, time.Time{}},
		{"whole RRset", []string{"example.test. 10 IN A 192.0.2.1", "example.test. 3 IN A 192.0.2.2"}, testNow.Add(time.Second), 2, testNow.Add(3 * time.Second)},
		{"recorded receive time", []string{"example.test. 10 IN A 192.0.2.1"}, testNow.Add(6 * time.Second), 4, testNow.Add(10 * time.Second)},
		{"fractional remainder", []string{"example.test. 1 IN A 192.0.2.1"}, testNow.Add(600 * time.Millisecond), 0, testNow.Add(time.Second)},
		{"expired", []string{"example.test. 2 IN A 192.0.2.1"}, testNow.Add(3 * time.Second), 0, testNow.Add(2 * time.Second)},
		{"genuine zero", []string{"example.test. 0 IN A 192.0.2.1"}, testNow.Add(10 * time.Millisecond), 0, time.Time{}},
		{"clock before receive", []string{"example.test. 2 IN A 192.0.2.1"}, testNow.Add(-time.Second), 2, testNow.Add(2 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := testQuery("example.test.", dns.TypeA)
			s := testSnapshot(t, q, tc.answers...)
			s.ReceivedAt = testNow
			// A delayed post-response action must retain the original TTL clock.
			c := testCandidate(t, q, s, testNow.Add(4*time.Second))
			got, err := ReplaceAddresses(c, []netip.Addr{netip.MustParseAddr("203.0.113.1")}, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			for _, rr := range got.Response.Answer {
				if rr.Header().Ttl != tc.wantTTL {
					t.Fatalf("TTL=%d, want %d: %v", rr.Header().Ttl, tc.wantTTL, rr)
				}
			}
			if !got.ReceivedAt.Equal(tc.now) {
				t.Fatal("replacement did not reset aged TTL baseline")
			}
			if !got.ValidUntil.Equal(tc.wantUntil) {
				t.Fatalf("validity deadline=%v, want %v", got.ValidUntil, tc.wantUntil)
			}
		})
	}
}

func TestRepeatedReplaceAndRebuildPreserveAbsoluteValidity(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	c := testCandidate(t, q, testSnapshot(t, q, "example.test. 10 IN A 192.0.2.1"), testNow)
	deadline := testNow.Add(10 * time.Second)
	initialSelection, err := Rebuild(c, []SelectedAddress{{Candidate: c, Address: c.Addresses[0]}}, testNow.Add(time.Second))
	if err != nil || !initialSelection.ValidUntil.Equal(deadline) {
		t.Fatalf("selection rebuild lost original positive-TTL deadline: %+v, %v", initialSelection, err)
	}
	first, err := ReplaceAddresses(c, []netip.Addr{netip.MustParseAddr("203.0.113.1")}, testNow.Add(9600*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if first.Response.Answer[0].Header().Ttl != 0 || !first.ValidUntil.Equal(deadline) {
		t.Fatal("sub-second remainder lost its positive-TTL provenance")
	}
	c = testCandidate(t, q, first, testNow.Add(9700*time.Millisecond))
	for _, now := range []time.Time{testNow.Add(9800 * time.Millisecond), testNow.Add(11 * time.Second)} {
		second, err := ReplaceAddresses(c, []netip.Addr{netip.MustParseAddr("198.51.100.1")}, now)
		if err != nil {
			t.Fatal(err)
		}
		if !second.ValidUntil.Equal(deadline) || second.Response.Answer[0].Header().Ttl != 0 {
			t.Fatal("repeated replacement extended absolute validity")
		}
		selected, err := Rebuild(c, []SelectedAddress{{Candidate: c, Address: c.Addresses[0]}}, now)
		if err != nil {
			t.Fatal(err)
		}
		if !selected.ValidUntil.Equal(deadline) || selected.Response.Answer[0].Header().Ttl != 0 {
			t.Fatal("selection rebuild extended absolute validity")
		}
	}
	// An already inherited, earlier deadline also caps a fresh wire TTL.
	s := testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1")
	s.ValidUntil = testNow.Add(3 * time.Second)
	c = testCandidate(t, q, s, testNow)
	got, err := ReplaceAddresses(c, []netip.Addr{netip.MustParseAddr("203.0.113.1")}, testNow.Add(time.Second))
	if err != nil || !got.ValidUntil.Equal(s.ValidUntil) || got.Response.Answer[0].Header().Ttl != 2 {
		t.Fatalf("inherited deadline did not cap replacement: %+v, %v", got, err)
	}
}

func TestReplaceAddressesRejectsUnsupportedCandidatesAndAddresses(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	valid := testCandidate(t, q, testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1"), testNow)
	validIP := []netip.Addr{netip.MustParseAddr("203.0.113.1")}
	for name, ips := range map[string][]netip.Addr{
		"empty":            nil,
		"invalid":          {{}},
		"wrong family":     {netip.MustParseAddr("2001:db8::1")},
		"mapped IPv6 in A": {netip.MustParseAddr("::ffff:192.0.2.1")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplaceAddresses(valid, ips, testNow); err == nil {
				t.Fatal("accepted invalid replacement")
			}
		})
	}
	q6 := testQuery("example.test.", dns.TypeAAAA)
	c6 := testCandidate(t, q6, testSnapshot(t, q6, "example.test. 60 IN AAAA 2001:db8::1"), testNow)
	for name, ips := range map[string][]netip.Addr{
		"IPv4 in AAAA": validIP,
		"zone":         {netip.MustParseAddr("fe80::1%eth0")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplaceAddresses(c6, ips, testNow); err == nil {
				t.Fatal("accepted invalid IPv6 replacement")
			}
		})
	}
	for name, makeCandidate := range map[string]func() *Candidate{
		"nil": func() *Candidate { return nil },
		"DNSSEC DO": func() *Candidate {
			q := q.Copy()
			q.SetEdns0(1232, true)
			return testCandidate(t, q, testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1"), testNow)
		},
		"truncated": func() *Candidate {
			s := testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1")
			s.Response.Truncated = true
			return testCandidate(t, q, s, testNow)
		},
		"NXDOMAIN": func() *Candidate {
			s := testSnapshot(t, q)
			s.Response.Rcode = dns.RcodeNameError
			return testCandidate(t, q, s, testNow)
		},
		"NODATA": func() *Candidate { return testCandidate(t, q, testSnapshot(t, q), testNow) },
		"MX": func() *Candidate {
			q := testQuery("example.test.", dns.TypeMX)
			return testCandidate(t, q, testSnapshot(t, q, "example.test. 60 IN MX 10 mail.test."), testNow)
		},
		"opaque": func() *Candidate {
			s := testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1")
			s.Response.Extra = []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Name: "key.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}}}
			return testCandidate(t, q, s, testNow)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplaceAddresses(makeCandidate(), validIP, testNow); err == nil {
				t.Fatal("accepted non-rewritable response")
			}
		})
	}
}

func TestReplaceAddressesUsesExistingECSPolicyAndClonesOPTs(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = []dns.EDNS0{testECS("192.0.2.51", 24, 0)}
	s := testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1")
	s.UpstreamOpt, s.RespOpt = testOPT(), testOPT()
	s.UpstreamOpt.Option = []dns.EDNS0{testECS("192.0.2.0", 24, 28), &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "deadbeef"}}
	s.RespOpt.Option = []dns.EDNS0{testECS("192.0.2.0", 24, 28), &dns.EDNS0_PADDING{Padding: []byte{0}}}
	c := testCandidate(t, q, s, testNow)
	before := c.Snapshot.Clone()
	got, err := ReplaceAddresses(c, []netip.Addr{netip.MustParseAddr("203.0.113.1")}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []*dns.OPT{got.UpstreamOpt, got.RespOpt} {
		if opt == nil || len(opt.Option) != 1 {
			t.Fatalf("retained connection-specific EDNS options: %v", opt)
		}
		ecs := opt.Option[0].(*dns.EDNS0_SUBNET)
		if ecs.Address.String() != "192.0.2.0" || ecs.SourceNetmask != 24 || ecs.SourceScope != 28 || ecs.Family != 1 {
			t.Fatalf("ECS view changed during address replacement: %v", ecs)
		}
		ecs.Address[0] = 1
	}
	if !reflect.DeepEqual(c.Snapshot, before) {
		t.Fatal("replacement OPTs alias original ECS or response state")
	}
	// Respect an existing policy that suppressed ECS on the downstream path.
	s.RespOpt.Option = nil
	c = testCandidate(t, q, s, testNow)
	got, err = ReplaceAddresses(c, []netip.Addr{netip.MustParseAddr("203.0.113.1")}, testNow)
	if err != nil || len(got.RespOpt.Option) != 0 {
		t.Fatalf("introduced downstream ECS: %v, %v", got.RespOpt, err)
	}
}
