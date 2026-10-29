package integration_test

import (
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/matcher/qname"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/tcp_server"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/udp_server"
	"github.com/miekg/dns"
)

// This opt-in test uses the exported production databases and the unchanged
// policy chains. Queries are confined to routes that answer locally: proxy
// TXT is deliberately absent because the source configuration forwards it.
func TestSmartdnsMigrationLocalWire(t *testing.T) {
	if os.Getenv("MOSDNS_SMARTDNS_LOCAL_DATA") != "1" {
		t.Skip("set MOSDNS_SMARTDNS_LOCAL_DATA=1 after exporting data/smartdns")
	}
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			cfg.Log.Level, cfg.Log.File, cfg.API.HTTP = "error", "", ""
			addresses := make(map[string]string)
			for i, p := range cfg.Plugins {
				args := smartdnsMigrationArgs(t, p)
				switch a := args.(type) {
				case *udp_server.Args:
					a.Listen = smartdnsWireFreeAddress(t, "udp")
					addresses["udp"] = a.Listen
				case *tcp_server.Args:
					a.Listen = smartdnsWireFreeAddress(t, "tcp")
					addresses["tcp"] = a.Listen
				case *cache.Args:
					a.DumpFile = ""
				}
				cfg.Plugins[i].Args = args
			}
			m, err := coremain.NewMosdns(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				m.CloseWithErr(nil)
				done := make(chan error, 1)
				go func() { done <- m.GetSafeClose().WaitClosed() }()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("instance shutdown did not finish within five seconds")
					return
				}
				for network, addr := range addresses {
					if network == "udp" {
						c, err := net.ListenPacket(network, addr)
						if err != nil {
							t.Errorf("UDP listener was not released: %v", err)
						} else {
							_ = c.Close()
						}
					} else {
						l, err := net.Listen(network, addr)
						if err != nil {
							t.Errorf("TCP listener was not released: %v", err)
						} else {
							_ = l.Close()
						}
					}
				}
			})

			ads := smartdnsWireDomain(t, cfg, m, []string{"category-ads-all", "category-ads", "ads"}, nil)
			proxy := smartdnsWireDomain(t, cfg, m, []string{"proxy"}, []string{"category-ads-all", "category-ads", "ads"})
			t.Logf("real-rule domains: ads=%s proxy=%s", ads, proxy)
			proxy4, proxy6 := "9.0.0.0", "2620::"
			if strings.Contains(path, "cernet") {
				proxy4, proxy6 = "192.168.8.64", "2001:db8::64"
			}
			cases := []struct {
				name, domain, ip string
				qtype            uint16
			}{
				{"ads_A", ads, "127.0.0.1", dns.TypeA},
				{"ads_AAAA", ads, "::1", dns.TypeAAAA},
				{"ads_TXT", ads, "", dns.TypeTXT},
				{"proxy_A", proxy, proxy4, dns.TypeA},
				{"proxy_AAAA", proxy, proxy6, dns.TypeAAAA},
			}
			for _, network := range []string{"udp", "tcp"} {
				if addresses[network] == "" {
					t.Fatalf("missing %s listener", network)
				}
				for i, tc := range cases {
					t.Run(network+"/"+tc.name, func(t *testing.T) {
						client := &dns.Client{Net: network, Timeout: time.Second}
						var firstTTL uint32
						before := smartdnsWireCacheHits(t, m)
						for attempt := range 2 {
							q := new(dns.Msg).SetQuestion(tc.domain, tc.qtype)
							q.Id = uint16(0x7100 + 2*i + attempt)
							r, _, err := client.Exchange(q, addresses[network])
							if err != nil {
								t.Fatal(err)
							}
							if !r.Response || r.Id != q.Id || r.Opcode != q.Opcode || len(r.Question) != 1 || r.Question[0] != q.Question[0] {
								t.Fatalf("invalid response header/question: query=%v response=%v", q, r)
							}
							if r.Rcode != dns.RcodeSuccess || r.Truncated {
								t.Fatalf("unexpected response status: %v", r)
							}
							if tc.ip == "" {
								if len(r.Answer) != 0 {
									t.Fatalf("ads TXT must be NOERROR/NODATA, got %v", r.Answer)
								}
								continue
							}
							if len(r.Answer) != 1 {
								t.Fatalf("want one static address, got %v", r.Answer)
							}
							var got string
							switch rr := r.Answer[0].(type) {
							case *dns.A:
								got = rr.A.String()
							case *dns.AAAA:
								got = rr.AAAA.String()
							}
							if got != tc.ip || r.Answer[0].Header().Name != tc.domain || r.Answer[0].Header().Class != dns.ClassINET {
								t.Fatalf("want %s %s, got %v", tc.domain, tc.ip, r.Answer)
							}
							ttl := r.Answer[0].Header().Ttl
							if ttl < 86390 || ttl > 86400 || (attempt != 0 && ttl > firstTTL) {
								t.Fatalf("static/cache TTL is invalid or increased: first=%d now=%d", firstTTL, ttl)
							}
							firstTTL = ttl
						}
						if tc.ip != "" {
							after := smartdnsWireCacheHits(t, m)
							if after < before+1 {
								t.Fatalf("second query did not hit the final response cache: before=%v after=%v", before, after)
							}
						}
					})
				}
			}
			if stats := m.ProbeManager().Stats(); stats.Probes != 0 || stats.Active != 0 || stats.Flights != 0 {
				t.Fatalf("local static routes unexpectedly started probes: %+v", stats)
			}
		})
	}
}

func smartdnsWireFreeAddress(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := c.LocalAddr().String()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		return addr
	}
	l, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func smartdnsWireDomain(t *testing.T, cfg coremain.Config, m *coremain.Mosdns, include, exclude []string) string {
	t.Helper()
	compile := func(labels []string) sequence.Matcher {
		if len(labels) == 0 {
			return nil
		}
		expressions := make([]string, len(labels))
		for i, label := range labels {
			expressions[i] = "geosite:" + label
		}
		matcher, err := qname.QuickSetup(coremain.NewBP("wire_candidate", m), strings.Join(expressions, " "))
		if err != nil {
			t.Fatal(err)
		}
		return matcher
	}
	included, excluded := compile(include), compile(exclude)
	match := func(name string, matcher sequence.Matcher) bool {
		if matcher == nil {
			return false
		}
		q := query_context.NewContext(new(dns.Msg).SetQuestion(name, dns.TypeA))
		ok, err := matcher.Match(t.Context(), q)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	found := errors.New("found local-route candidate")
	for _, label := range include {
		var candidate string
		err := geodata.LoadSite(cfg.Geodata.GeoSite, label, nil, func(kind geodata.DomainType, value string) error {
			if kind != geodata.TypeDomain && kind != geodata.TypeFull {
				return nil
			}
			name := dns.Fqdn(value)
			if match(name, included) && !match(name, excluded) {
				candidate = name
				return found
			}
			return nil
		})
		if errors.Is(err, found) {
			return candidate
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("no real-rule candidate for include=%v exclude=%v", include, exclude)
	return ""
}

func smartdnsWireCacheHits(t *testing.T, m *coremain.Mosdns) float64 {
	t.Helper()
	r := httptest.NewRecorder()
	m.GetAPIRouter().ServeHTTP(r, httptest.NewRequest("GET", "/metrics", nil))
	if r.Code != 200 {
		t.Fatalf("metrics request failed: %d", r.Code)
	}
	for _, line := range strings.Split(r.Body.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == `mosdns_cache_hit_total{tag="response_cache"}` {
			v, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	t.Fatalf("response cache hit metric is missing: %s", r.Body.String())
	return 0
}
