package integration_test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/speedcheck"
	"github.com/miekg/dns"
)

// Retained text exports are an independent audit input for this test only.
// Runtime policies load the bundle without depending on the domains directory.
func TestSmartdnsGeositeDataEquivalent(t *testing.T) {
	if os.Getenv("MOSDNS_SMARTDNS_LOCAL_DATA") != "1" {
		t.Skip("set MOSDNS_SMARTDNS_LOCAL_DATA=1 to compare the GeoSite bundle with retained text exports")
	}
	bundles := make(map[string]map[string]struct{})
	for _, path := range smartdnsMigrationConfigs {
		cfg := smartdnsMigrationConfig(t, path)
		labels := bundles[cfg.Geodata.GeoSite]
		if labels == nil {
			labels = make(map[string]struct{})
			bundles[cfg.Geodata.GeoSite] = labels
		}
		for _, label := range smartdnsMigrationSiteLabels(t, cfg) {
			labels[label] = struct{}{}
		}
	}
	typeNames := map[geodata.DomainType]string{
		geodata.TypeFull: "full", geodata.TypeDomain: "domain",
		geodata.TypeRegex: "regexp", geodata.TypeSubstr: "keyword",
	}
	var paths []string
	for path := range bundles {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	totalRules := 0
	for _, path := range paths {
		var labels []string
		for label := range bundles[path] {
			labels = append(labels, label)
		}
		slices.Sort(labels)
		if len(labels) != 19 {
			t.Fatalf("bundle has %d referenced labels, want all 19 deployment labels", len(labels))
		}
		for _, label := range labels {
			t.Run(label, func(t *testing.T) {
				text, err := os.ReadFile(filepath.Join("data", "smartdns", "domains", label+".txt"))
				if err != nil {
					t.Fatal(err)
				}
				want := make(map[string]struct{})
				for _, raw := range strings.Split(string(text), "\n") {
					expression := strings.TrimSpace(raw)
					if expression == "" || strings.HasPrefix(expression, "#") {
						continue
					}
					kind, value, ok := strings.Cut(expression, ":")
					if !ok || value == "" || kind != "full" && kind != "domain" && kind != "regexp" && kind != "keyword" {
						t.Fatalf("unknown or invalid text rule %q", expression)
					}
					if _, duplicate := want[expression]; duplicate {
						t.Fatalf("duplicate text rule %q", expression)
					}
					want[expression] = struct{}{}
				}
				got := make(map[string]struct{})
				if err := geodata.LoadSite(path, label, nil, func(kind geodata.DomainType, value string) error {
					name, ok := typeNames[kind]
					if !ok {
						return fmt.Errorf("unknown GeoSite domain type %d", kind)
					}
					expression := name + ":" + value
					if _, duplicate := got[expression]; duplicate {
						return fmt.Errorf("duplicate GeoSite rule %q", expression)
					}
					got[expression] = struct{}{}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if len(got) != len(want) {
					t.Fatalf("GeoSite has %d rules, retained text has %d", len(got), len(want))
				}
				for expression := range want {
					if _, ok := got[expression]; !ok {
						t.Fatalf("GeoSite is missing retained text rule %q", expression)
					}
				}
				totalRules += len(got)
				t.Logf("%s: %d rules agree", label, len(got))
			})
		}
	}
	t.Logf("compared %d rules across %d GeoSite bundles", totalRules, len(paths))
}

// These tests consume the exported, ignored deployment data. No DNS request or
// real probe is sent: the checked-in policies and actual matchers remain intact.
// Export the data first, then opt in with MOSDNS_SMARTDNS_LOCAL_DATA=1.
func TestSmartdnsRealDataPolicies(t *testing.T) {
	if os.Getenv("MOSDNS_SMARTDNS_LOCAL_DATA") != "1" {
		t.Skip("set MOSDNS_SMARTDNS_LOCAL_DATA=1 to test exported SmartDNS rules and MMDBs")
	}
	for _, path := range []string{"data/smartdns/Country.mmdb", "data/smartdns/ASN.mmdb", "data/smartdns/geosite.dat", "data/smartdns/ips/github-raw.txt"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("export the SmartDNS deployment data before opting in: %s: %v", path, err)
		}
	}
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cernet := strings.Contains(path, "cernet")
			cf6, cloudfront6 := "2606:4700:52::", "2600:9000:2755::"
			github6, fastly6 := "2a04:4e42:7c::133", "2a04:4e42:7c:0:1122:3344:5566:7788"
			if cernet {
				cf6, cloudfront6 = "2606:4700:10::", "2600:9000:2939::"
				github6, fastly6 = "2a04:4e42:200::133", "2a04:4e42:200:0:1122:3344:5566:7788"
			}
			cases := []struct {
				name, original, want string
			}{
				{"cloudflare_v4", "1.1.1.1", "172.64.145.0"},
				{"cloudflare_v6", "2606:4700:4700::1111", cf6},
				{"cloudfront_v4", "3.168.241.42", "3.168.241.0"},
				{"cloudfront_v6", "2600:9000:22a3::1", cloudfront6},
				// These also match the real Fastly database and broad GitHub set.
				// The earlier GitHub raw rule must win over the Fastly rule.
				{"github_raw_v4_priority", "185.199.108.133", "146.75.50.132"},
				{"github_raw_v6_priority", "2606:50c0:8000::154", github6},
				// Fastly's IPv4 /22 keeps ten host bits, including a partial byte.
				{"fastly_v4_prefix22", "146.75.55.42", "146.75.51.42"},
				{"fastly_v6_prefix64", "2a04:4e42:1234:abcd:1122:3344:5566:7788", fastly6},
				{"github_nonraw_excluded_from_fastly", "185.199.108.42", "185.199.108.42"},
				{"asn33191_v4", "208.103.161.1", "172.64.145.0"},
				{"asn33191_v6", "2602:f79a::1", cf6},
			}
			if cernet {
				for i := range cases {
					if strings.HasPrefix(cases[i].name, "asn33191_") {
						cases[i].want = cases[i].original
					}
				}
			}
			originals := make(map[string]string)
			for _, tc := range cases {
				originals[tc.name+".policy.example.com."] = tc.original
			}
			cfg := smartdnsMigrationConfig(t, path)
			f := smartdnsPolicyInstanceWithData(t, cfg, func(_ string, query *dns.Msg) *dns.Msg {
				name := query.Question[0].Name
				if strings.HasPrefix(name, "nxdomain.") {
					r := new(dns.Msg).SetRcode(query, dns.RcodeNameError)
					r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.com.", Mbox: "hostmaster.example.com.", Minttl: 60}}
					return r
				}
				if ip := originals[name]; ip != "" {
					return smartdnsPolicyAddressReply(query, "", ip)
				}
				switch name {
				case "private4.policy.example.com.":
					return smartdnsPolicyAddressReply(query, "", "10.0.0.42")
				case "private6.policy.example.com.":
					return smartdnsPolicyAddressReply(query, "", "fc00::42")
				case "asn19679.policy.example.com.", "www.dropbox.com.":
					return smartdnsPolicyAddressReply(query, "", "162.125.1.1", "8.8.8.8")
				}
				return smartdnsPolicyAddressReply(query, "", "8.8.8.8")
			}, nil, true)

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					qtype := uint16(dns.TypeA)
					if netip.MustParseAddr(tc.original).Is6() {
						qtype = dns.TypeAAAA
					}
					q, err := f.exec(t, "main", tc.name+".policy.example.com.", qtype, false)
					smartdnsPolicyRequireSuccess(t, q, err)
					if got := smartdnsMigrationAnswerIPs(q); !slices.Equal(got, []string{tc.want}) {
						t.Fatalf("real data selected %v, want %s from %s", got, tc.want, tc.original)
					}
					if !q.HasMark(smartdnsMigrationRouteMarks["route_default"]) {
						t.Fatal("replacement test did not exercise the default route")
					}
					if q.SnapshotResponse().ProbeStatus != query_context.ProbeSucceeded {
						t.Fatal("selected answer did not carry a successful measurement")
					}
					_, probes := f.observations()
					if tc.original != tc.want && slices.Contains(probes, netip.MustParseAddr(tc.original)) {
						t.Fatalf("measured original %s before replacement", tc.original)
					}
				})
			}

			t.Run("private_addresses_remain_unmeasured", func(t *testing.T) {
				for _, tc := range []struct {
					name, ip string
					qtype    uint16
				}{
					{"private4", "10.0.0.42", dns.TypeA},
					{"private6", "fc00::42", dns.TypeAAAA},
				} {
					_, before := f.observations()
					q, err := f.exec(t, "main", tc.name+".policy.example.com.", tc.qtype, false)
					smartdnsPolicyRequireSuccess(t, q, err)
					if got := smartdnsMigrationAnswerIPs(q); !slices.Equal(got, []string{tc.ip}) {
						t.Fatalf("private answer changed: %v", got)
					}
					_, after := f.observations()
					if len(after) != len(before) || q.SnapshotResponse().ProbeStatus != query_context.ProbeUnmeasured {
						t.Fatalf("real private classification did not skip probes for %s", tc.ip)
					}
				}
			})

			t.Run("asn19679_rejects_whole_default_response", func(t *testing.T) {
				_, before := f.observations()
				q, err := f.exec(t, "main", "asn19679.policy.example.com.", dns.TypeA, false)
				if !errors.Is(err, speedcheck.ErrNoCandidates) || q.R() != nil {
					t.Fatalf("ASN-excluded mixed RRset survived: err=%v response=%v", err, q.R())
				}
				_, after := f.observations()
				if len(after) != len(before) {
					t.Fatal("rejected ASN response reached measurements")
				}
				// Invoke an actual default source to validate the Dropbox domain
				// exemption before selector trimming or alternate route selection.
				checkedExemption := false
				for _, p := range cfg.Plugins {
					if p.Tag != "select_default" {
						continue
					}
					source := smartdnsMigrationArgs(t, p).(*speedcheck.Args).Sources[0]
					q, err = f.exec(t, source, "www.dropbox.com.", dns.TypeA, false)
					smartdnsPolicyRequireSuccess(t, q, err)
					if got := smartdnsMigrationAnswerIPs(q); !slices.Equal(got, []string{"162.125.1.1", "8.8.8.8"}) {
						t.Fatalf("real Dropbox exemption changed the source RRset: %v", got)
					}
					checkedExemption = true
					break
				}
				if !checkedExemption {
					t.Fatal("configuration has no default selector for the exemption test")
				}
			})

			t.Run("actual_domain_route_priority", func(t *testing.T) {
				for _, tc := range []struct{ name, route string }{
					{"doubleclick.net.", "route_block"},
					{"anthropic.com.", "route_proxy"},
					{"google.cn.", "route_google_cn"},
					{"fonts.googleapis.com.", "route_google_cn"},
					{"www.baidu.com.", "route_cn"},
					{"www.apple.com.", "route_cn"},
					{"google.com.", "route_global"},
					{"twitter.com.", "route_global"},
					{"raw.githubusercontent.com.", "route_global"},
					{"example.geek.", "route_opennic"},
					{"example.com.", "route_default"},
				} {
					q, err := f.exec(t, "main", tc.name, dns.TypeA, false)
					smartdnsPolicyRequireSuccess(t, q, err)
					if !q.HasMark(smartdnsMigrationRouteMarks[tc.route]) {
						t.Fatalf("%s did not use %s", tc.name, tc.route)
					}
					if tc.route == "route_block" && !slices.Equal(smartdnsMigrationAnswerIPs(q), []string{"127.0.0.1"}) {
						t.Fatal("real ads rule did not return the configured static answer")
					}
					if tc.route == "route_proxy" {
						want := "9.0.0.0"
						if cernet {
							want = "192.168.8.64"
						}
						if !slices.Equal(smartdnsMigrationAnswerIPs(q), []string{want}) {
							t.Fatal("real proxy rule did not return the configured static answer")
						}
					}
				}
			})

			t.Run("legal_nxdomain_does_not_fall_through", func(t *testing.T) {
				for _, tc := range []struct{ name, route string }{
					{"nxdomain.google.com.", "route_global"},
					{"nxdomain.policy.example.com.", "route_default"},
				} {
					_, before := f.observations()
					q, err := f.exec(t, "main", tc.name, dns.TypeAAAA, false)
					if err != nil || q.R() == nil || q.R().Rcode != dns.RcodeNameError || len(q.R().Answer) != 0 || len(q.R().Ns) != 1 {
						t.Fatalf("legal NXDOMAIN changed: err=%v response=%v", err, q.R())
					}
					if !q.HasMark(smartdnsMigrationRouteMarks[tc.route]) || tc.route != "route_default" && q.HasMark(smartdnsMigrationRouteMarks["route_default"]) {
						t.Fatal("negative response fell through its matched route")
					}
					_, after := f.observations()
					if len(after) != len(before) {
						t.Fatal("legal NXDOMAIN reached measurements or static fallback")
					}
				}
			})
		})
	}
}
