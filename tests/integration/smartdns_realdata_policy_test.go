package integration_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/speedcheck"
	"github.com/miekg/dns"
)

// Exercise the actual Google rules and complete policy graph with identical
// measurement outcomes for the apex, a direct subdomain and a CNAME subdomain.
// Network I/O is controlled; the exported deployment databases stay intact.
func TestSmartdnsRealDataGoogleFallbackNames(t *testing.T) {
	if os.Getenv("MOSDNS_SMARTDNS_LOCAL_DATA") != "1" {
		t.Skip("set MOSDNS_SMARTDNS_LOCAL_DATA=1 to test Google fallback against exported data")
	}
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			targetName := "goog-ct.my.cn.eu.org."
			if strings.Contains(path, "cernet") {
				targetName = "goog-cernet.my.cn.eu.org."
			}
			for _, tc := range []struct {
				name     string
				outcome  speedtest.Outcome
				qtype    uint16
				nodata   bool
				do       bool
				fallback bool
			}{
				{"failed", speedtest.Failed, dns.TypeAAAA, false, false, true},
				{"success", speedtest.Success, dns.TypeAAAA, false, false, false},
				{"unmeasured", speedtest.Unmeasured, dns.TypeAAAA, false, false, true},
				{"nodata", speedtest.Unmeasured, dns.TypeAAAA, true, false, true},
				{"dnssec", speedtest.Failed, dns.TypeAAAA, false, true, false},
				{"ipv4", speedtest.Failed, dns.TypeA, false, false, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					originalIP, targetIP := "2404:6800:4008:c03::8a", "2001:db8:ffff::42"
					if tc.qtype == dns.TypeA {
						originalIP, targetIP = "142.250.1.1", "192.0.2.42"
					}
					f := smartdnsPolicyInstanceWithData(t, cfg, func(tag string, query *dns.Msg) *dns.Msg {
						if tag == "upstream_dnspod_1" && query.Question[0].Name == targetName {
							return smartdnsPolicyAddressReply(query, "", targetIP)
						}
						terminal := ""
						if query.Question[0].Name == "earth.google.com." {
							terminal = "www3.l.google.com."
						}
						if tc.nodata {
							return smartdnsPolicyAddressReply(query, terminal)
						}
						return smartdnsPolicyAddressReply(query, terminal, originalIP)
					}, func(context.Context, netip.Addr, speedtest.Config) speedtest.Result {
						return speedtest.Result{Outcome: tc.outcome, RTT: 0}
					}, true)
					for _, name := range []string{"google.com.", "www.google.com.", "earth.google.com."} {
						t.Run(name, func(t *testing.T) {
							q, err := f.exec(t, "main", name, tc.qtype, tc.do)
							smartdnsPolicyRequireSuccess(t, q, err)
							if !q.HasMark(smartdnsMigrationRouteMarks["route_global"]) {
								t.Fatal("Google name did not enter the global route")
							}
							want := []string{originalIP}
							if tc.fallback {
								want = []string{targetIP}
							}
							got := smartdnsMigrationAnswerIPs(q)
							if !slices.Equal(got, want) {
								t.Fatalf("addresses %v, want %v (probe status %v)", got, want, q.SnapshotResponse().ProbeStatus)
							}
							owner := name
							if name == "earth.google.com." {
								owner = "www3.l.google.com."
								if len(q.R().Answer) < 2 || q.R().Answer[0].(*dns.CNAME).Target != owner {
									t.Fatal("fallback lost the original CNAME chain")
								}
							}
							for _, rr := range q.R().Answer {
								if rr.Header().Rrtype == tc.qtype && rr.Header().Name != owner {
									t.Fatalf("address owner %q, want %q", rr.Header().Name, owner)
								}
							}
							t.Logf("route=global probe_status=%v addresses=%v", q.SnapshotResponse().ProbeStatus, got)
						})
					}
				})
			}
		})
	}
}

func TestSmartdnsDeploymentGeoSiteReferences(t *testing.T) {
	if os.Getenv("MOSDNS_SMARTDNS_LOCAL_DATA") != "1" {
		t.Skip("set MOSDNS_SMARTDNS_LOCAL_DATA=1 after preparing the deployment databases")
	}
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			attributes := smartdnsMigrationSiteAttributes(t, cfg)
			for _, code := range smartdnsMigrationSiteLabels(t, cfg) {
				check := func(attrs []string) {
					t.Helper()
					count := 0
					err := geodata.LoadSite(cfg.Geodata.GeoSite, code, attrs, func(geodata.DomainType, string) error {
						count++
						return nil
					})
					if err != nil {
						t.Fatalf("load %s with attributes %v: %v", code, attrs, err)
					}
					if count == 0 {
						t.Fatalf("%s has no rules for attributes %v", code, attrs)
					}
				}
				check(nil)
				for _, attr := range attributes[code] {
					check([]string{attr})
				}
			}
		})
	}
}

// These tests consume the exported, ignored deployment data. No DNS request or
// real probe is sent: the checked-in policies and actual matchers remain intact.
// Export the data first, then opt in with MOSDNS_SMARTDNS_LOCAL_DATA=1.
func TestSmartdnsRealDataPolicies(t *testing.T) {
	if os.Getenv("MOSDNS_SMARTDNS_LOCAL_DATA") != "1" {
		t.Skip("set MOSDNS_SMARTDNS_LOCAL_DATA=1 to test exported SmartDNS rules and MMDBs")
	}
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cernet := strings.Contains(path, "cernet")
			const cf4, cloudfront4 = "172.64.145.0", "3.168.241.0"
			cfTarget, cloudfrontTarget := "cf-ct.my.cn.eu.org.", "cft-ct.my.cn.eu.org."
			cf6, cloudfront6 := "2606:4700:52::", "2600:9000:2755::"
			github6, fastly6 := "2a04:4e42:7c::133", "2a04:4e42:7c:0:1122:3344:5566:7788"
			if cernet {
				cfTarget, cloudfrontTarget = "cf-bgp.my.cn.eu.org.", "cft-bgp.my.cn.eu.org."
				cf6, cloudfront6 = "2606:4700:10::", "2600:9000:2939::"
				github6, fastly6 = "2a04:4e42:200::133", "2a04:4e42:200:0:1122:3344:5566:7788"
			}
			cases := []struct {
				name, original, want string
			}{
				{"cloudflare_v4", "1.1.1.1", cf4},
				{"cloudflare_v6", "2606:4700:4700::1111", cf6},
				{"cloudfront_v4", "3.168.241.42", cloudfront4},
				{"cloudfront_v6", "2600:9000:22a3::1", cloudfront6},
				// These also match the real Fastly database and broad GitHub set.
				// The earlier GitHub raw rule must win over the Fastly rule.
				{"github_raw_v4_priority", "185.199.108.133", "146.75.50.132"},
				{"github_raw_v6_priority", "2606:50c0:8000::154", github6},
				// Fastly's IPv4 /22 keeps ten host bits, including a partial byte.
				{"fastly_v4_prefix22", "146.75.55.42", "146.75.51.42"},
				{"fastly_v6_prefix64", "2a04:4e42:1234:abcd:1122:3344:5566:7788", fastly6},
				{"github_nonraw_excluded_from_fastly", "185.199.108.42", "185.199.108.42"},
				{"asn33191_v4", "208.103.161.1", cf4},
				{"asn33191_v6", "2602:f79a::1", cf6},
			}
			originals := make(map[string]string)
			for _, tc := range cases {
				originals[tc.name+".policy.example.com."] = tc.original
			}
			cfg := smartdnsMigrationConfig(t, path)
			qtypeIP := func(query *dns.Msg, ipv4, ipv6 string) *dns.Msg {
				if query.Question[0].Qtype == dns.TypeAAAA {
					return smartdnsPolicyAddressReply(query, "", ipv6)
				}
				return smartdnsPolicyAddressReply(query, "", ipv4)
			}
			f := smartdnsPolicyInstanceWithData(t, cfg, func(tag string, query *dns.Msg) *dns.Msg {
				name := query.Question[0].Name
				if tag == "upstream_dnspod_1" {
					switch name {
					case cfTarget:
						return qtypeIP(query, cf4, cf6)
					case cloudfrontTarget:
						return qtypeIP(query, cloudfront4, cloudfront6)
					}
				}
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
						if !slices.Equal(smartdnsMigrationAnswerIPs(q), []string{"9.0.0.0"}) {
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
