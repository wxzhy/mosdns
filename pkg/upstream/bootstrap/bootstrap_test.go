package bootstrap

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestBootstrapAddressUsesReachableRRset(t *testing.T) {
	q := new(dns.Msg).SetQuestion("bootstrap.example.test.", dns.TypeA)
	r := new(dns.Msg).SetReply(q)
	r.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "other.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(192, 0, 2, 1)},
		&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 45}, Target: "resolver.example.test."},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "resolver.example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1}, AAAA: net.ParseIP("2001:db8::2")},
		&dns.A{Hdr: dns.RR_Header{Name: "RESOLVER.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 2)},
	}
	addr, ttl, err := bootstrapAddress(q, r)
	if err != nil || addr != netip.MustParseAddr("192.0.2.2") || ttl != 45 {
		t.Fatalf("resolved %v with TTL %d, error: %v", addr, ttl, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*dns.Msg)
	}{
		{"wrong transaction", func(m *dns.Msg) { m.Id++ }},
		{"wrong question", func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }},
		{"truncated", func(m *dns.Msg) { m.Truncated = true }},
		{"unreachable address", func(m *dns.Msg) { m.Answer = m.Answer[:3] }},
		{"error rcode", func(m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := r.Copy()
			tc.change(reply)
			if _, _, err := bootstrapAddress(q, reply); err == nil {
				t.Fatal("accepted invalid bootstrap reply")
			}
		})
	}
}
