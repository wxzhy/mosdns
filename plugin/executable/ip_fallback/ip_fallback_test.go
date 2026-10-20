package ip_fallback

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
)

func ttlPointer(ttl int64) *int64 { return &ttl }

func newFallback(t *testing.T, args Args) *Fallback {
	t.Helper()
	f, err := New(&args)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func fallbackContext(qtype uint16, ips ...string) *query_context.Context {
	query := new(dns.Msg).SetQuestion("fallback.example.", qtype)
	query.SetEdns0(1232, false)
	q := query_context.NewContext(query)
	r := new(dns.Msg).SetReply(q.Q())
	for _, ip := range ips {
		hdr := dns.RR_Header{Name: "fallback.example.", Rrtype: qtype, Class: dns.ClassINET, Ttl: 300}
		if qtype == dns.TypeA {
			r.Answer = append(r.Answer, &dns.A{Hdr: hdr, A: net.ParseIP(ip)})
		} else {
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(ip)})
		}
	}
	q.SetResponse(r)
	return q
}

func putStatus(q *query_context.Context, status string) {
	s := q.SnapshotResponse()
	switch status {
	case "unknown":
		s.ProbeStatus = query_context.ProbeUnknown
	case "success":
		s.ProbeStatus = query_context.ProbeSucceeded
	case "failed":
		s.ProbeStatus = query_context.ProbeFailed
	case "unmeasured":
		s.ProbeStatus = query_context.ProbeUnmeasured
	default:
		panic(status)
	}
	q.CommitResponse(s)
}

func answerIPs(q *query_context.Context) []string {
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

func TestTriggerModes(t *testing.T) {
	for _, mode := range []struct {
		name string
		on   []string
	}{
		{"default", nil}, {"disabled", []string{}},
		{"all_probes_failed", []string{"all_probes_failed"}},
		{"nodata", []string{"nodata"}}, {"no_rtt", []string{"no_rtt"}},
	} {
		for _, status := range []string{"unknown", "success", "failed", "unmeasured"} {
			for _, nodata := range []bool{false, true} {
				name := mode.name + "/" + status + "/positive"
				if nodata {
					name = mode.name + "/" + status + "/nodata"
				}
				t.Run(name, func(t *testing.T) {
					q := fallbackContext(dns.TypeA, "192.0.2.1")
					if nodata {
						q.R().Answer = nil
					}
					putStatus(q, status)
					original := q.R()
					f := newFallback(t, Args{IPv4: []string{"203.0.113.42"}, On: mode.on})
					if err := f.Exec(context.Background(), q); err != nil {
						t.Fatal(err)
					}
					want := mode.name == "default" && (nodata || status == "failed") ||
						mode.name == "all_probes_failed" && status == "failed" ||
						mode.name == "nodata" && nodata ||
						mode.name == "no_rtt" && (status == "failed" || status == "unmeasured")
					if want {
						if got := answerIPs(q); !slices.Equal(got, []string{"203.0.113.42"}) || q.R() == original {
							t.Fatalf("expected new fallback response, got %v", got)
						}
					} else if q.R() != original {
						t.Fatal("nontriggering fallback replaced the response")
					}
				})
			}
		}
	}
}

func TestFamilyTargetsOrderAndImmutability(t *testing.T) {
	ttl := int64(60)
	args := Args{IPv4: []string{"203.0.113.42", "198.51.100.42", "203.0.113.42"},
		IPv6: []string{"2001:db8::42", "2001:db8::99", "2001:db8::42"}, TTL: &ttl}
	f := newFallback(t, args)
	ttl = 1
	args.IPv4[0], args.IPv6[0] = "192.0.2.99", "2001:db8:ffff::1"
	for _, tc := range []struct {
		qtype uint16
		ip    string
		want  []string
	}{
		{dns.TypeA, "192.0.2.1", []string{"203.0.113.42", "198.51.100.42"}},
		{dns.TypeAAAA, "2001:db8:1::1", []string{"2001:db8::42", "2001:db8::99"}},
	} {
		q := fallbackContext(tc.qtype, tc.ip)
		putStatus(q, "failed")
		if err := f.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if got := answerIPs(q); !slices.Equal(got, tc.want) {
			t.Fatalf("addresses %v, want %v", got, tc.want)
		}
		if got := q.R().Answer[0].Header().Ttl; got != 60 {
			t.Fatalf("TTL %d, want 60", got)
		}
	}
	q := fallbackContext(dns.TypeAAAA, "2001:db8:1::1")
	putStatus(q, "failed")
	original := q.R()
	if err := newFallback(t, Args{IPv4: []string{"203.0.113.42"}}).Exec(context.Background(), q); err != nil || q.R() != original {
		t.Fatal("missing address family must preserve response", err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, args := range []Args{
		{IPv4: []string{""}}, {IPv4: []string{"bad"}}, {IPv4: []string{"2001:db8::1"}},
		{IPv4: []string{"192.0.2.0/24"}}, {IPv6: []string{"192.0.2.1"}},
		{IPv6: []string{"fe80::1%eth0"}}, {IPv6: []string{"::ffff:192.0.2.1"}},
		{On: []string{"unknown"}}, {On: []string{""}},
		{TTL: ttlPointer(-1)}, {TTL: ttlPointer(4294967296)},
	} {
		if _, err := New(&args); err == nil {
			t.Fatalf("invalid args accepted: %+v", args)
		}
	}
	if _, err := New(nil); err == nil {
		t.Fatal("nil args accepted")
	}
	if _, err := New(&Args{}); err != nil {
		t.Fatal("empty target lists must be valid", err)
	}
}

func TestDecodedTTLRange(t *testing.T) {
	for _, value := range []int64{-1, 0, 4294967295, 4294967296} {
		var args Args
		if err := utils.WeakDecode(map[string]any{"ipv4": []string{"203.0.113.42"}, "ttl": value}, &args); err != nil {
			t.Fatal(err)
		}
		f, err := New(&args)
		invalid := value < 0 || value > 4294967295
		if invalid {
			if err == nil {
				t.Fatalf("decoded out-of-range TTL %d accepted", value)
			}
		} else if err != nil || uint64(f.ttl) != uint64(value) {
			t.Fatalf("decoded TTL %d changed or failed: %v", value, err)
		}
	}
}

func TestFallbackUsesFreshTTLAndDoesNotRepeat(t *testing.T) {
	for _, configured := range []*int64{nil, ttlPointer(0), ttlPointer(60)} {
		q := fallbackContext(dns.TypeA, "192.0.2.1")
		q.R().Answer[0].Header().Ttl = 1
		putStatus(q, "failed")
		// The fresh static address is independent of the old address's TTL.
		s := q.SnapshotResponse()
		s.ReceivedAt = time.Now().Add(-1500 * time.Millisecond)
		q.CommitResponse(s)
		f := newFallback(t, Args{IPv4: []string{"203.0.113.42"}, TTL: configured})
		if err := f.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		want := uint32(86400)
		if configured != nil {
			want = uint32(*configured)
		}
		if got := q.R().Answer[0].Header().Ttl; got != want {
			t.Fatalf("fresh fallback TTL %d, want %d", got, want)
		}
		if q.SnapshotResponse().ProbeStatus != query_context.ProbeUnknown {
			t.Fatal("static fallback inherited the original probe failure")
		}
		first := q.R()
		firstSnapshot := q.SnapshotResponse()
		if err := f.Exec(context.Background(), q); err != nil || q.R() != first || q.ResponseReceivedAt() != firstSnapshot.ReceivedAt {
			t.Fatal("repeated fallback renewed the static response", err)
		}
	}
}

func TestNoOpResponsesAndDNSSEC(t *testing.T) {
	f := newFallback(t, Args{IPv4: []string{"203.0.113.42"}})
	for _, tc := range []struct {
		name string
		edit func(*query_context.Context)
	}{
		{"missing", func(q *query_context.Context) { q.SetResponse(nil) }},
		{"nxdomain", func(q *query_context.Context) { q.R().Rcode = dns.RcodeNameError }},
		{"servfail", func(q *query_context.Context) { q.R().Rcode = dns.RcodeServerFailure }},
		{"truncated", func(q *query_context.Context) { q.R().Truncated = true }},
		{"query_do", func(q *query_context.Context) { q.QOpt().SetDo() }},
		{"not_in", func(q *query_context.Context) { q.Q().Question[0].Qclass = dns.ClassCHAOS }},
		{"not_address", func(q *query_context.Context) { q.Q().Question[0].Qtype = dns.TypeHTTPS }},
		{"not_query", func(q *query_context.Context) { q.Q().Opcode = dns.OpcodeStatus }},
		{"dname", func(q *query_context.Context) {
			q.R().Answer = append(q.R().Answer, &dns.DNAME{Hdr: dns.RR_Header{Name: "other.example.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET}, Target: "alias.example."})
		}},
		{"tsig_nodata", func(q *query_context.Context) {
			q.R().Answer = nil
			q.R().Extra = []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Name: "key.example.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}}}
		}},
		{"sig0", func(q *query_context.Context) {
			q.R().Extra = []dns.RR{&dns.SIG{RRSIG: dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := fallbackContext(dns.TypeA, "192.0.2.1")
			putStatus(q, "failed")
			tc.edit(q)
			original := q.R()
			before := q.SnapshotResponse()
			if err := f.Exec(context.Background(), q); err != nil || q.R() != original || q.ResponseReceivedAt() != before.ReceivedAt {
				t.Fatal("no-op changed response", err)
			}
		})
	}
	query := new(dns.Msg).SetQuestion("fallback.example.", dns.TypeA)
	query.SetEdns0(1232, true)
	q := query_context.NewContext(query)
	q.SetResponse(new(dns.Msg).SetReply(q.Q()))
	q.QOpt().SetDo(false)
	original := q.R()
	if err := f.Exec(context.Background(), q); err != nil || q.R() != original {
		t.Fatal("client DO must protect NODATA even when outgoing DO was cleared", err)
	}
}

func TestFallbackPreservesAliasAndParentState(t *testing.T) {
	q := fallbackContext(dns.TypeA)
	q.SetMark(37)
	key := query_context.RegKey()
	q.StoreValue(key, "parent")
	q.R().Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "fallback.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "leaf.example."}}
	q.R().Ns = []dns.RR{
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 15}, Ns: "ns.example.", Mbox: "hostmaster.example."},
		&dns.NSEC{Hdr: dns.RR_Header{Name: "fallback.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 15}, NextDomain: "next.example."},
	}
	q.R().Answer = append(q.R().Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "fallback.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 30}, TypeCovered: dns.TypeCNAME})
	q.R().AuthenticatedData, q.R().Authoritative = true, true
	original := q.R()
	originalText, queryText := original.String(), q.Q().String()
	f := newFallback(t, Args{IPv4: []string{"203.0.113.42"}, TTL: ttlPointer(60)})
	if err := f.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if len(q.R().Answer) != 2 || q.R().Answer[0].(*dns.CNAME).Target != "leaf.example." || q.R().Answer[1].Header().Name != "leaf.example." {
		t.Fatal("fallback did not use CNAME terminal owner")
	}
	if q.R().Answer[0].Header().Ttl > 30 || q.R().Answer[1].Header().Ttl > 60 || len(q.R().Ns) != 0 || q.R().AuthenticatedData || q.R().Authoritative {
		t.Fatal("fallback extended aliases or retained negative/authenticated data")
	}
	stored, _ := q.GetValue(key)
	if original.String() != originalText || q.Q().String() != queryText || !q.HasMark(37) || stored != "parent" {
		t.Fatal("fallback changed shared response or parent state")
	}
}

func TestEDNSOptionsAndExpiredAlias(t *testing.T) {
	q := fallbackContext(dns.TypeA)
	q.RespOpt().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"}}
	f := newFallback(t, Args{IPv4: []string{"203.0.113.42"}})
	if err := f.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if q.RespOpt() == nil || len(q.RespOpt().Option) != 0 || q.QOpt() == nil {
		t.Fatal("static fallback kept a connection-specific cookie or removed query OPT")
	}
	withoutEDNS := query_context.NewContext(new(dns.Msg).SetQuestion("fallback.example.", dns.TypeA))
	withoutEDNS.SetResponse(new(dns.Msg).SetReply(withoutEDNS.Q()))
	if err := f.Exec(context.Background(), withoutEDNS); err != nil || withoutEDNS.RespOpt() != nil {
		t.Fatal("static fallback invented client EDNS support", err)
	}
	q = fallbackContext(dns.TypeA)
	q.R().Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "fallback.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: "leaf.example."}}
	s := q.SnapshotResponse()
	s.ReceivedAt = time.Now().Add(-1500 * time.Millisecond)
	q.CommitResponse(s)
	original := q.R()
	if err := f.Exec(context.Background(), q); err == nil || q.R() != original {
		t.Fatal("expired alias was reused or source state changed")
	}
}

func TestInvalidResponseAndCancellation(t *testing.T) {
	f := newFallback(t, Args{IPv4: []string{"203.0.113.42"}})
	for _, edit := range []func(*query_context.Context){
		func(q *query_context.Context) { q.Q().Question = nil },
		func(q *query_context.Context) { q.R().Id++ },
		func(q *query_context.Context) { q.R().Response = false },
		func(q *query_context.Context) { q.R().Question[0].Name = "wrong.example." },
		func(q *query_context.Context) { q.R().Answer[0].(*dns.A).A = nil },
		func(q *query_context.Context) {
			q.R().Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "fallback.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "fallback.example."}}
		},
	} {
		q := fallbackContext(dns.TypeA, "192.0.2.1")
		putStatus(q, "failed")
		edit(q)
		if err := f.Exec(context.Background(), q); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
	q := fallbackContext(dns.TypeA)
	original := q.R()
	ctx, cancel := context.WithCancelCause(context.Background())
	want := errors.New("parent canceled")
	cancel(want)
	if err := f.Exec(ctx, q); !errors.Is(err, want) || q.R() != original {
		t.Fatal("parent cancellation was lost or response changed", err)
	}
}

func TestInvalidHeadersAreNotHiddenByPassthroughFlags(t *testing.T) {
	f := newFallback(t, Args{IPv4: []string{"203.0.113.42"}})
	for _, passthrough := range []struct {
		name string
		edit func(*dns.Msg)
	}{
		{"truncated", func(r *dns.Msg) { r.Truncated = true }},
		{"negative", func(r *dns.Msg) { r.Rcode = dns.RcodeNameError }},
		{"opaque", func(r *dns.Msg) {
			r.Extra = append(r.Extra, &dns.TSIG{Hdr: dns.RR_Header{Name: "key.example.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}})
		}},
	} {
		for _, malformed := range []struct {
			name string
			edit func(*dns.Msg)
		}{
			{"id", func(r *dns.Msg) { r.Id++ }},
			{"qr", func(r *dns.Msg) { r.Response = false }},
			{"question", func(r *dns.Msg) { r.Question[0].Name = "different.example." }},
		} {
			t.Run(passthrough.name+"/"+malformed.name, func(t *testing.T) {
				q := fallbackContext(dns.TypeA, "192.0.2.1")
				passthrough.edit(q.R())
				malformed.edit(q.R())
				original := q.R()
				if err := f.Exec(context.Background(), q); err == nil || q.R() != original {
					t.Fatal("passthrough flags concealed an invalid header or modified source")
				}
			})
		}
	}
}
