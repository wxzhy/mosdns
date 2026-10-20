package response

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStaticAddressesResetsOnlyAddressLifetime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		answers   []string
		ttl       uint32
		wantTTL   uint32
		wantUntil time.Time
	}{
		{"replace without alias", []string{"example.test. 1 IN A 192.0.2.1"}, 60, 60, testNow.Add(62 * time.Second)},
		{"fill NODATA", nil, 60, 60, testNow.Add(62 * time.Second)},
		{"short alias", []string{"example.test. 5 IN CNAME cdn.test.", "cdn.test. 50 IN A 192.0.2.1"}, 60, 3, testNow.Add(5 * time.Second)},
		{"zero alias", []string{"example.test. 0 IN CNAME cdn.test."}, 60, 0, testNow.Add(62 * time.Second)},
		{"zero configured ttl", []string{"example.test. 50 IN A 192.0.2.1"}, 0, 0, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := testQuery("example.test.", dns.TypeA)
			c := testCandidate(t, q, testSnapshot(t, q, tc.answers...), testNow)
			got, err := StaticAddresses(c, []netip.Addr{netip.MustParseAddr("203.0.113.42")}, tc.ttl, testNow.Add(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if !got.ValidUntil.Equal(tc.wantUntil) {
				t.Fatalf("deadline %v want %v", got.ValidUntil, tc.wantUntil)
			}
			for _, rr := range got.Response.Answer {
				if rr.Header().Ttl != tc.wantTTL {
					t.Fatalf("TTL %d want %d: %v", rr.Header().Ttl, tc.wantTTL, rr)
				}
			}
			last := got.Response.Answer[len(got.Response.Answer)-1].(*dns.A)
			if last.Hdr.Name != c.Terminal || last.A.String() != "203.0.113.42" {
				t.Fatal("static address lost terminal or configured address")
			}
		})
	}
}

func TestStaticAddressesKeepsRoundedChainDeadline(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	c := testCandidate(t, q, testSnapshot(t, q, "example.test. 1 IN CNAME cdn.test.", "cdn.test. 60 IN A 192.0.2.1"), testNow)
	s := Replay(c, testNow.Add(600*time.Millisecond))
	c = testCandidate(t, q, s, testNow.Add(600*time.Millisecond))
	got, err := StaticAddresses(c, []netip.Addr{netip.MustParseAddr("203.0.113.42")}, 60, testNow.Add(700*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if !got.ValidUntil.Equal(testNow.Add(time.Second)) || got.Response.Answer[0].Header().Ttl != 0 {
		t.Fatal("static override revived a rounded alias")
	}
}

func TestStaticAddressesProtectsDNSSECAndOpaque(t *testing.T) {
	for _, name := range []string{"DO", "TC", "NXDOMAIN", "TSIG"} {
		t.Run(name, func(t *testing.T) {
			q := testQuery("example.test.", dns.TypeA)
			if name == "DO" {
				q.SetEdns0(1232, true)
			}
			s := testSnapshot(t, q)
			switch name {
			case "TC":
				s.Response.Truncated = true
			case "NXDOMAIN":
				s.Response.Rcode = dns.RcodeNameError
			case "TSIG":
				s.Response.Extra = []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Name: "key.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}}}
			}
			c := testCandidate(t, q, s, testNow)
			if _, err := StaticAddresses(c, []netip.Addr{netip.MustParseAddr("203.0.113.42")}, 60, testNow); err == nil {
				t.Fatal("rewrote protected response")
			}
		})
	}
}
