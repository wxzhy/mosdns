package response

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAddressRemainingTTLIncludesNormalizedRRsetAndEveryAlias(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []string
		at      time.Time
		want    uint32
	}{
		{"duplicate zero", []string{"example.test. 60 IN A 192.0.2.1", "example.test. 0 IN A 192.0.2.1"}, testNow, 0},
		{"zero alias", []string{"example.test. 0 IN CNAME cdn.test.", "cdn.test. 60 IN A 192.0.2.1"}, testNow, 0},
		{"short alias", []string{"example.test. 3 IN CNAME cdn.test.", "cdn.test. 60 IN A 192.0.2.1"}, testNow.Add(1500 * time.Millisecond), 1},
		{"fractional remainder", []string{"example.test. 1 IN A 192.0.2.1"}, testNow.Add(600 * time.Millisecond), 0},
		{"expired", []string{"example.test. 1 IN A 192.0.2.1"}, testNow.Add(2 * time.Second), 0},
		{"before zero receive baseline", []string{"example.test. 60 IN A 192.0.2.1", "example.test. 0 IN A 192.0.2.1"}, testNow.Add(-time.Second), 0},
		{"before positive receive baseline", []string{"example.test. 3 IN A 192.0.2.1"}, testNow.Add(-time.Second), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := testQuery("example.test.", dns.TypeA)
			c := testCandidate(t, q, testSnapshot(t, q, tc.answers...), testNow)
			if got := c.RemainingTTL(tc.at); got != tc.want {
				t.Fatalf("TTL %d want %d", got, tc.want)
			}
		})
	}
}

func TestBindingRemainingTTLIncludesZeroAliasesAndDuplicateRecords(t *testing.T) {
	for _, typ := range []uint16{dns.TypeHTTPS, dns.TypeSVCB} {
		t.Run(dns.TypeToString[typ], func(t *testing.T) {
			q := testQuery("example.test.", typ)
			typeName := dns.TypeToString[typ]
			for _, answers := range [][]string{
				{"example.test. 0 IN CNAME cdn.test.", "cdn.test. 60 IN " + typeName + " 1 . ech=AAEC"},
				{"example.test. 60 IN " + typeName + " 1 . ech=AAEC", "example.test. 0 IN " + typeName + " 2 . ech=AAEC"},
			} {
				c := bindingCandidate(t, q, answers...)
				if got := c.RemainingTTL(testNow.Add(time.Millisecond)); got != 0 {
					t.Fatalf("zero source TTL grew to %d", got)
				}
			}
		})
	}
}

func TestRemainingTTLDoesNotRecoverRoundedWireTTLFromAbsoluteLease(t *testing.T) {
	q := testQuery("example.test.", dns.TypeA)
	c := testCandidate(t, q, testSnapshot(t, q, "example.test. 1 IN A 192.0.2.1"), testNow)
	s := Replay(c, testNow.Add(600*time.Millisecond))
	c = testCandidate(t, q, s, testNow.Add(600*time.Millisecond))
	if c.RemainingTTL(testNow.Add(700*time.Millisecond)) != 0 || !c.Snapshot.ValidUntil.Equal(testNow.Add(time.Second)) {
		t.Fatal("rounded source TTL was revived or absolute expiry lost")
	}
	q = testQuery("example.test.", dns.TypeHTTPS)
	b := bindingCandidate(t, q, "example.test. 1 IN HTTPS 1 . alpn=h3")
	s, _, err := RewriteBindings(b, map[int]BindingEdit{0: {RemoveH3: true}}, testNow.Add(600*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	b, err = AnalyzeBindings(q, s, testNow.Add(600*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if b.RemainingTTL(testNow.Add(700*time.Millisecond)) != 0 || !b.Snapshot.ValidUntil.Equal(testNow.Add(time.Second)) {
		t.Fatal("rounded binding TTL was revived or absolute expiry lost")
	}
}

func TestBindingRemainingTTLUsesRelevantNegativeSOA(t *testing.T) {
	q := testQuery("example.test.", dns.TypeHTTPS)
	s := testSnapshot(t, q, "example.test. 4 IN CNAME leaf.test.")
	s.Response.Ns = []dns.RR{testRR(t, "test. 60 IN SOA ns.test. hostmaster.test. 1 2 3 4 3")}
	c, err := AnalyzeBindings(q, s, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RemainingTTL(testNow.Add(time.Second)); got != 2 {
		t.Fatalf("negative TTL=%d want2", got)
	}
}
