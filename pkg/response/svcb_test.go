package response

import (
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func bindingCandidate(t *testing.T, q *dns.Msg, answers ...string) *BindingCandidate {
	t.Helper()
	c, err := AnalyzeBindings(q, testSnapshot(t, q, answers...), testNow)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func bindingParam[T dns.SVCBKeyValue](binding *dns.SVCB) (T, bool) {
	for _, value := range binding.Value {
		if p, ok := value.(T); ok {
			return p, true
		}
	}
	var zero T
	return zero, false
}

func TestAnalyzeBindingsUsesOnlyTerminalRRset(t *testing.T) {
	for _, typ := range []uint16{dns.TypeHTTPS, dns.TypeSVCB} {
		t.Run(dns.TypeToString[typ], func(t *testing.T) {
			q := testQuery("Example.test.", typ)
			typeName := dns.TypeToString[typ]
			s := testSnapshot(t, q,
				"example.test. 10 IN CNAME CDN.test.",
				"unrelated.test. 1 IN "+typeName+" 1 . ipv4hint=192.0.2.99",
				"CDN.test. 30 IN "+typeName+" 1 . alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.1 ipv6hint=2001:db8::1",
				"cdn.test. 20 IN "+typeName+" 2 Edge.test. ipv4hint=192.0.2.2")
			s.Response.Extra = []dns.RR{testRR(t, "glue.test. 1 IN A 192.0.2.100")}
			c, err := AnalyzeBindings(q, s, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if c.NODATA || c.Negative || !c.HasService || !c.Rewritable || c.Terminal != "cdn.test." || len(c.Records) != 2 {
				t.Fatalf("incorrect binding candidate: %+v", c)
			}
			if c.Records[0].Index != 2 || c.Records[0].Target != "cdn.test." || c.Records[1].Target != "edge.test." {
				t.Fatalf("incorrect target or source index: %+v", c.Records)
			}
			want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.2")}
			if !slices.Equal(c.Hints, want) || !c.Snapshot.ValidUntil.Equal(testNow.Add(10*time.Second)) {
				t.Fatalf("unrelated hints or incorrect alias deadline: %+v", c)
			}
			originalHint, _ := bindingParam[*dns.SVCBIPv4Hint](bindingValue(s.Response.Answer[2]))
			originalHint.Hint[0][0] = 1
			copyHint, _ := bindingParam[*dns.SVCBIPv4Hint](bindingValue(c.Snapshot.Response.Answer[2]))
			if copyHint.Hint[0].String() != "192.0.2.1" {
				t.Fatal("candidate aliases upstream parameter bytes")
			}
		})
	}
}

func TestRewriteBindingsHasPerRecordECHAndIndependentParameters(t *testing.T) {
	q := testQuery("example.test.", dns.TypeHTTPS)
	s := testSnapshot(t, q,
		"example.test. 40 IN CNAME cdn.test.",
		"cdn.test. 30 IN HTTPS 1 . mandatory=alpn,ipv4hint alpn=h2,h3 no-default-alpn ipv4hint=192.0.2.1",
		"cdn.test. 30 IN HTTPS 2 other.test. alpn=h3,h3-29 ipv4hint=192.0.2.2 ech=YWJj")
	s.Response.AuthenticatedData, s.Response.Authoritative = true, true
	s.Response.Answer = append(s.Response.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "cdn.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 30}})
	s.Response.Ns = []dns.RR{testRR(t, "test. 60 IN NSEC next.test. HTTPS RRSIG")}
	s.Response.Extra = []dns.RR{testRR(t, "other.test. 1 IN A 192.0.2.99")}
	c, err := AnalyzeBindings(q, s, testNow)
	if err != nil {
		t.Fatal(err)
	}
	before := c.Snapshot.Clone()
	ech := []byte{0, 1, 2}
	capTTL := uint32(6)
	got, changed, err := RewriteBindings(c, map[int]BindingEdit{
		1: {RemoveHints: true, RemoveH3: true, ECH: ech, ECHTTL: &capTTL, ECHValidUntil: testNow.Add(4 * time.Second)},
		2: {RemoveH3: true, ECH: []byte("do not overwrite"), ECHValidUntil: testNow.Add(-time.Second)},
	}, testNow.Add(time.Second))
	if err != nil || !changed {
		t.Fatalf("rewrite failed: %v, %v", changed, err)
	}
	if len(got.Response.Answer) != 3 || len(got.Response.Ns) != 0 || len(got.Response.Extra) != 0 || got.Response.AuthenticatedData || got.Response.Authoritative {
		t.Fatalf("retained authentication/proofs or unrelated records: %v", got.Response)
	}
	first := bindingValue(got.Response.Answer[1])
	second := bindingValue(got.Response.Answer[2])
	if _, ok := bindingParam[*dns.SVCBIPv4Hint](first); ok {
		t.Fatal("first service retained removed hint")
	}
	if hint, ok := bindingParam[*dns.SVCBIPv4Hint](second); !ok || hint.Hint[0].String() != "192.0.2.2" {
		t.Fatal("independent record edit removed second service's hint")
	}
	if p, _ := bindingParam[*dns.SVCBAlpn](first); !slices.Equal(p.Alpn, []string{"h2"}) {
		t.Fatal("ALPN filtering changed retained protocol order")
	}
	if p, _ := bindingParam[*dns.SVCBAlpn](second); !slices.Equal(p.Alpn, []string{"h3-29"}) {
		t.Fatal("h3 deletion must match exact protocol ID")
	}
	if p, _ := bindingParam[*dns.SVCBMandatory](first); !slices.Equal(p.Code, []dns.SVCBKey{dns.SVCB_ALPN}) {
		t.Fatal("mandatory retained a deleted key or introduced ECH")
	}
	if p, _ := bindingParam[*dns.SVCBECHConfig](first); !slices.Equal(p.ECH, ech) {
		t.Fatal("first record lost its ECH injection")
	}
	if p, _ := bindingParam[*dns.SVCBECHConfig](second); string(p.ECH) != "abc" {
		t.Fatal("existing ECH was replaced")
	}
	if !got.ValidUntil.Equal(testNow.Add(4 * time.Second)) {
		t.Fatal("an unused ECH source changed RRset lifetime")
	}
	for _, rr := range got.Response.Answer {
		if rr.Header().Ttl != 3 {
			t.Fatalf("ECH/source TTL not bounded: %v", rr)
		}
	}
	firstECH, _ := bindingParam[*dns.SVCBECHConfig](first)
	firstECH.ECH[0] = 9
	first.Target = "changed.test."
	if ech[0] != 0 || !reflect.DeepEqual(c.Snapshot, before) {
		t.Fatal("mutable rewritten parameters alias input or shared source")
	}
	if wire, err := got.Response.Pack(); err != nil {
		t.Fatal(err)
	} else if err := new(dns.Msg).Unpack(wire); err != nil {
		t.Fatal(err)
	}
}

func TestBindingDependenciesAndAliasMode(t *testing.T) {
	q := testQuery("example.test.", dns.TypeSVCB)
	t.Run("remove all ALPN", func(t *testing.T) {
		c := bindingCandidate(t, q, "example.test. 60 IN SVCB 1 . mandatory=alpn,no-default-alpn alpn=h2,h3 no-default-alpn")
		got, changed, err := RewriteBindings(c, map[int]BindingEdit{0: {RemoveH3: true, RemoveALPN: []string{"h2"}}}, testNow)
		if err != nil || !changed || len(bindingValue(got.Response.Answer[0]).Value) != 0 {
			t.Fatalf("dependent parameters survived empty ALPN: %v, %v", got.Response, err)
		}
	})
	t.Run("unknown required parameter", func(t *testing.T) {
		c := bindingCandidate(t, q, "example.test. 60 IN SVCB 1 . mandatory=key65400,ipv4hint ipv4hint=192.0.2.1 key65400=opaque")
		got, changed, err := RewriteBindings(c, map[int]BindingEdit{0: {RemoveHints: true}}, testNow)
		if err != nil || !changed {
			t.Fatal(err)
		}
		p, _ := bindingParam[*dns.SVCBMandatory](bindingValue(got.Response.Answer[0]))
		if !slices.Equal(p.Code, []dns.SVCBKey{65400}) {
			t.Fatal("discarded an unknown but retained mandatory parameter")
		}
	})
	t.Run("AliasMode unchanged", func(t *testing.T) {
		c := bindingCandidate(t, q, "example.test. 60 IN SVCB 0 alias.test.")
		if c.HasService || c.NODATA || len(c.Hints) != 0 || c.Records[0].Target != "alias.test." {
			t.Fatal("AliasMode treated as an address service")
		}
		got, changed, err := RewriteBindings(c, map[int]BindingEdit{0: {RemoveHints: true, ECH: []byte{1}, ECHValidUntil: testNow.Add(-time.Second)}}, testNow)
		if err != nil || changed || bindingValue(got.Response.Answer[0]).Priority != 0 || len(bindingValue(got.Response.Answer[0]).Value) != 0 {
			t.Fatal("AliasMode was rewritten")
		}
		if _, err := SynthesizeBinding(c, []byte{1}, 60, time.Time{}, testNow); err == nil {
			t.Fatal("synthesized a service over an alias answer")
		}
	})
}

func TestBindingsRetainAbsoluteLifetimeAcrossZeroWireTTL(t *testing.T) {
	q := testQuery("example.test.", dns.TypeHTTPS)
	c := bindingCandidate(t, q, "example.test. 1 IN HTTPS 1 . alpn=h2,h3 ipv4hint=192.0.2.1")
	got, _, err := RewriteBindings(c, map[int]BindingEdit{0: {RemoveHints: true}}, testNow.Add(600*time.Millisecond))
	if err != nil || got.Response.Answer[0].Header().Ttl != 0 || !got.ValidUntil.Equal(testNow.Add(time.Second)) {
		t.Fatalf("rounding lost original lifetime: %+v, %v", got, err)
	}
	c, err = AnalyzeBindings(q, got, testNow.Add(700*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	got, _, err = RewriteBindings(c, map[int]BindingEdit{0: {RemoveH3: true}}, testNow.Add(900*time.Millisecond))
	if err != nil || !got.ValidUntil.Equal(testNow.Add(time.Second)) || got.Response.Answer[0].Header().Ttl != 0 {
		t.Fatal("repeated binding rewrite extended original lease")
	}
	t.Run("genuine ECH zero", func(t *testing.T) {
		c := bindingCandidate(t, q, "example.test. 60 IN HTTPS 1 . alpn=h2")
		zero := uint32(0)
		got, changed, err := RewriteBindings(c, map[int]BindingEdit{0: {ECH: []byte{1, 2}, ECHTTL: &zero}}, testNow)
		if err != nil || !changed || got.Response.Answer[0].Header().Ttl != 0 || !got.ValidUntil.Equal(testNow.Add(60*time.Second)) {
			t.Fatalf("genuine zero ECH lease was extended: %+v, %v", got, err)
		}
	})
}

func TestSynthesizeBindingKeepsNODATAChainAndSOALifetime(t *testing.T) {
	for _, typ := range []uint16{dns.TypeHTTPS, dns.TypeSVCB} {
		t.Run(dns.TypeToString[typ], func(t *testing.T) {
			q := testQuery("example.test.", typ)
			s := testSnapshot(t, q, "example.test. 5 IN CNAME leaf.test.")
			s.Response.Ns = []dns.RR{
				testRR(t, "test. 60 IN SOA ns.test. hostmaster.test. 1 2 3 4 3"),
				testRR(t, "unrelated. 1 IN SOA ns.unrelated. hostmaster.unrelated. 1 2 3 4 1"),
				testRR(t, "test. 60 IN NSEC next.test. HTTPS RRSIG"),
			}
			c, err := AnalyzeBindings(q, s, testNow)
			if err != nil || !c.NODATA || !c.Rewritable {
				t.Fatalf("NODATA not available for synthesis: %+v, %v", c, err)
			}
			before := c.Snapshot.Clone()
			ech := []byte{1, 2, 3}
			got, err := SynthesizeBinding(c, ech, 300, testNow.Add(10*time.Second), testNow.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Response.Answer) != 2 || len(got.Response.Ns) != 0 || !got.ValidUntil.Equal(testNow.Add(3*time.Second)) {
				t.Fatalf("negative proofs retained or source deadlines extended: %+v", got)
			}
			binding := bindingValue(got.Response.Answer[1])
			if binding.Hdr.Name != "leaf.test." || binding.Hdr.Rrtype != typ || binding.Priority != 1 || binding.Target != "." || len(binding.Value) != 1 {
				t.Fatalf("incorrect synthesized record: %v", got.Response.Answer[1])
			}
			for _, rr := range got.Response.Answer {
				if rr.Header().Ttl != 2 {
					t.Fatal("NODATA source lifetime not enforced")
				}
			}
			p, _ := bindingParam[*dns.SVCBECHConfig](binding)
			p.ECH[0] = 9
			if ech[0] != 1 || !reflect.DeepEqual(c.Snapshot, before) {
				t.Fatal("synthesis mutated ECH source or NODATA")
			}
		})
	}
}

func TestBindingDNSSECAndFailureProtection(t *testing.T) {
	for _, name := range []string{"DO", "NXDOMAIN", "TC", "opaque"} {
		t.Run(name, func(t *testing.T) {
			q := testQuery("example.test.", dns.TypeHTTPS)
			if name == "DO" {
				q.SetEdns0(1232, true)
			}
			s := testSnapshot(t, q)
			switch name {
			case "NXDOMAIN":
				s.Response.Rcode = dns.RcodeNameError
			case "TC":
				s.Response.Truncated = true
			case "opaque":
				s.Response.Extra = []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Name: "key.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}}}
			}
			c, err := AnalyzeBindings(q, s, testNow)
			if err != nil || c.Rewritable {
				t.Fatalf("accepted protected binding source: %+v, %v", c, err)
			}
			if _, err := SynthesizeBinding(c, []byte{1}, 60, time.Time{}, testNow); err == nil {
				t.Fatal("synthesized a protected/failed response")
			}
			if _, changed, err := RewriteBindings(c, map[int]BindingEdit{0: {RemoveH3: true}}, testNow); err != nil || changed {
				t.Fatal("rewrote a protected/failed response")
			}
		})
	}
}

func TestBindingRewriteUsesExistingECSPolicy(t *testing.T) {
	q := testQuery("example.test.", dns.TypeHTTPS)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = []dns.EDNS0{testECS("192.0.2.51", 24, 0)}
	s := testSnapshot(t, q, "example.test. 60 IN HTTPS 1 . alpn=h3")
	s.UpstreamOpt, s.RespOpt = testOPT(), testOPT()
	s.UpstreamOpt.Option = []dns.EDNS0{testECS("192.0.2.0", 24, 28), &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "abcd"}}
	s.RespOpt.Option = []dns.EDNS0{testECS("192.0.2.0", 24, 28), &dns.EDNS0_PADDING{Padding: []byte{0}}}
	c, err := AnalyzeBindings(q, s, testNow)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := RewriteBindings(c, map[int]BindingEdit{0: {RemoveH3: true}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []*dns.OPT{got.UpstreamOpt, got.RespOpt} {
		if len(opt.Option) != 1 {
			t.Fatal("leaked connection-specific EDNS options")
		}
		ecs := opt.Option[0].(*dns.EDNS0_SUBNET)
		if ecs.SourceNetmask != 24 || ecs.SourceScope != 28 || ecs.Address.String() != "192.0.2.0" {
			t.Fatal("rewrite changed ECS view")
		}
	}
}

func TestParallelBindingEditsOwnMutableParameters(t *testing.T) {
	q := testQuery("example.test.", dns.TypeHTTPS)
	c := bindingCandidate(t, q, "example.test. 60 IN HTTPS 1 . mandatory=alpn,ipv4hint alpn=h2,h3 ipv4hint=192.0.2.1")
	before := c.Snapshot.Clone()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				got, changed, err := RewriteBindings(c, map[int]BindingEdit{0: {RemoveHints: true, RemoveH3: true, ECH: []byte{1, 2, 3}}}, testNow)
				if err != nil || !changed {
					t.Errorf("rewrite: %v, %v", changed, err)
					return
				}
				binding := bindingValue(got.Response.Answer[0])
				ech, _ := bindingParam[*dns.SVCBECHConfig](binding)
				ech.ECH[0] = 9
				alpn, _ := bindingParam[*dns.SVCBAlpn](binding)
				alpn.Alpn[0] = "changed"
			}
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(c.Snapshot, before) {
		t.Fatal("parallel clients mutated the shared source")
	}
}

func TestBindingAnalysisAndEditsRejectForeignInput(t *testing.T) {
	q := testQuery("example.test.", dns.TypeHTTPS)
	if _, err := AnalyzeBindings(q, testSnapshot(t, q,
		"example.test. 60 IN CNAME other.test.", "other.test. 60 IN CNAME example.test."), testNow); err == nil {
		t.Fatal("accepted cyclic binding alias chain")
	}
	s := testSnapshot(t, q, "example.test. 60 IN HTTPS 1 . alpn=h2")
	bindingValue(s.Response.Answer[0]).Value = append(bindingValue(s.Response.Answer[0]).Value, &dns.SVCBAlpn{Alpn: []string{"h3"}})
	if _, err := AnalyzeBindings(q, s, testNow); err == nil {
		t.Fatal("accepted duplicate service parameter keys")
	}
	c := bindingCandidate(t, q, "example.test. 60 IN HTTPS 1 . alpn=h2", "unrelated.test. 60 IN HTTPS 1 . alpn=h3")
	if _, _, err := RewriteBindings(c, map[int]BindingEdit{1: {RemoveH3: true}}, testNow); err == nil {
		t.Fatal("allowed an edit outside the terminal RRset")
	}
}
