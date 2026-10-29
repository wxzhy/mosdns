package integration_test

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	forward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/speedcheck"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/tcp_server"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/udp_server"
	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/encoding/protowire"
)

var smartdnsMigrationConfigs = []string{"examples/smartdns/config.yaml", "examples/smartdns/config-cernet.yaml"}

var smartdnsMigrationRouteMarks = map[string]uint32{
	"route_block": 1, "route_proxy": 2, "route_google_cn": 3, "route_cn": 4,
	"route_global": 5, "route_opennic": 6, "route_default": 7,
}

func smartdnsMigrationConfig(t *testing.T, path string) coremain.Config {
	t.Helper()
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg coremain.Config
	if err := v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) { c.TagName = "yaml" }); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Include) != 0 {
		t.Fatal("migration examples must have self-contained plugin lists")
	}
	if cfg.Geodata.GeoSite == "" {
		t.Fatal("migration examples must declare their GeoSite bundle")
	}
	seen := make(map[string]bool)
	byTag := make(map[string]coremain.PluginConfig)
	for _, p := range cfg.Plugins {
		if p.Type == "domain_set" {
			t.Fatalf("%s: migration rules must reference geosite entries directly", p.Tag)
		}
		if p.Tag == "" || seen[p.Tag] {
			t.Fatalf("empty or duplicate plugin tag %q", p.Tag)
		}
		seen[p.Tag] = true
		byTag[p.Tag] = p
		args := smartdnsMigrationArgs(t, p)
		if f, ok := args.(*forward.Args); ok && len(f.Upstreams) != 1 && p.Tag != "upstream_google_cn" && p.Tag != "upstream_opennic" && p.Tag != "ech_lookup" {
			t.Fatalf("%s: each forward must retain exactly one upstream, got %d", p.Tag, len(f.Upstreams))
		}
	}
	for _, p := range cfg.Plugins {
		if !strings.HasPrefix(p.Tag, "source_") {
			continue
		}
		rules, ok := smartdnsMigrationArgs(t, p).(*sequence.Args)
		if !ok || len(*rules) == 0 {
			t.Fatalf("%s must be a complete executable source sequence", p.Tag)
		}
		upstreamTag := strings.TrimPrefix((*rules)[0].Exec, "$")
		upstream, exists := byTag[upstreamTag]
		if !exists || upstream.Type != "forward" {
			t.Fatalf("%s does not begin with a named forward", p.Tag)
		}
		if a := smartdnsMigrationArgs(t, upstream).(*forward.Args); len(a.Upstreams) != 1 {
			t.Fatalf("%s begins with a multi-upstream forward and loses candidates", p.Tag)
		}
	}
	return cfg
}

func smartdnsMigrationArgs(t *testing.T, p coremain.PluginConfig) any {
	t.Helper()
	info, ok := coremain.GetPluginType(p.Type)
	if !ok {
		t.Fatalf("%s: unregistered plugin type %s", p.Tag, p.Type)
	}
	args := info.NewArgs()
	if err := utils.WeakDecode(p.Args, args); err != nil {
		t.Fatalf("%s (%s): %v", p.Tag, p.Type, err)
	}
	return args
}

// The tests retain the actual policy sequences, filters, replacements and
// selectors. Only external DNS and measurement I/O are replaced. Synthetic
// database matches intentionally test routing, not third-party database content.
type smartdnsMigrationFixture struct {
	plugins map[string]any
	mu      sync.Mutex
	called  map[string]int
	probed  []netip.Addr
	answer  func(string, string, uint16) []netip.Addr
}

func smartdnsMigrationInstance(t *testing.T, cfg coremain.Config, answer func(string, string, uint16) []netip.Addr) *smartdnsMigrationFixture {
	t.Helper()
	f := &smartdnsMigrationFixture{plugins: make(map[string]any), called: make(map[string]int), answer: answer}
	dir := t.TempDir()
	cfg.Geodata.GeoSite = smartdnsMigrationSiteFixture(t, cfg, dir)
	m := coremain.NewTestMosdnsWithPlugins(f.plugins, cfg.Geodata)
	var closers []io.Closer
	t.Cleanup(func() {
		for _, c := range slices.Backward(closers) {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}
		m.CloseWithErr(nil)
		if err := m.GetSafeClose().WaitClosed(); err != nil {
			t.Error(err)
		}
	})
	for _, p := range cfg.Plugins {
		args := smartdnsMigrationArgs(t, p)
		bp := coremain.NewBP(p.Tag, m)
		var instance any
		var err error
		switch a := args.(type) {
		case *ip_set.Args:
			for i, file := range a.Files {
				a.Files[i] = filepath.Join(dir, "ips", filepath.Base(file))
				smartdnsMigrationWrite(t, a.Files[i], smartdnsMigrationIPs(p.Tag))
			}
			var ips []string
			for _, expression := range a.IPs {
				if strings.HasPrefix(expression, "ext:") || strings.HasPrefix(expression, "geoip:") || strings.HasPrefix(expression, "asn:") {
					ips = append(ips, strings.Fields(smartdnsMigrationIPs(p.Tag))...)
				} else {
					ips = append(ips, expression)
				}
			}
			a.IPs = ips
		case *cache.Args:
			a.DumpFile = ""
		case *forward.Args:
			tag := p.Tag
			instance = sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
				f.mu.Lock()
				f.called[tag]++
				f.mu.Unlock()
				r := new(dns.Msg).SetReply(q.Q())
				for _, ip := range f.answer(tag, q.QQuestion().Name, q.QQuestion().Qtype) {
					h := dns.RR_Header{Name: q.QQuestion().Name, Class: dns.ClassINET, Ttl: 60}
					if ip.Is4() && q.QQuestion().Qtype == dns.TypeA {
						h.Rrtype = dns.TypeA
						r.Answer = append(r.Answer, &dns.A{Hdr: h, A: ip.AsSlice()})
					} else if ip.Is6() && q.QQuestion().Qtype == dns.TypeAAAA {
						h.Rrtype = dns.TypeAAAA
						r.Answer = append(r.Answer, &dns.AAAA{Hdr: h, AAAA: ip.AsSlice()})
					}
				}
				q.SetResponse(r)
				return nil
			})
		case *speedcheck.Args:
			var sources []speedcheck.Source
			for _, tag := range a.Sources {
				s := sequence.ToExecutable(f.plugins[tag])
				if s == nil {
					t.Fatalf("%s: source %q is not defined earlier", p.Tag, tag)
				}
				sources = append(sources, speedcheck.Source{Tag: tag, Exec: s})
			}
			labels := make(map[string]netlist.Matcher)
			for tag, expressions := range a.Labels {
				labels[tag], err = ip_set.CompileExpressions(bp, expressions)
				if err != nil {
					t.Fatalf("%s label %s: %v", p.Tag, tag, err)
				}
			}
			asns := make(map[uint32]netlist.Matcher)
			emptyASN := netlist.NewList()
			emptyASN.Sort()
			for asn := range a.ASNMultipliers {
				asns[asn] = emptyASN
			}
			for _, filter := range []*speedcheck.IPFilter{a.CandidateFilter, a.ProbeMatch} {
				if filter != nil {
					for _, asn := range append(slices.Clone(filter.ASNInclude), filter.ASNExclude...) {
						asns[asn] = emptyASN
					}
				}
			}
			instance, err = speedcheck.New(*a, sources, speedcheck.Options{Labels: labels, ASNMatchers: asns,
				Probe: func(_ context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
					f.mu.Lock()
					f.probed = append(f.probed, ip)
					f.mu.Unlock()
					return speedtest.Result{Outcome: speedtest.Success, RTT: time.Millisecond}
				},
			})
		}
		if p.Type == "udp_server" || p.Type == "tcp_server" || p.Type == "http_server" || p.Type == "quic_server" {
			continue // Check argument decoding, without binding configured ports.
		}
		if instance == nil && err == nil {
			info, _ := coremain.GetPluginType(p.Type)
			instance, err = info.NewPlugin(bp, args)
		}
		if err != nil {
			t.Fatalf("%s (%s): %v", p.Tag, p.Type, err)
		}
		f.plugins[p.Tag] = instance
		if c, ok := instance.(io.Closer); ok {
			closers = append(closers, c)
		}
	}
	return f
}

func smartdnsMigrationWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func smartdnsMigrationSiteLabels(t *testing.T, cfg coremain.Config) []string {
	t.Helper()
	labels := make(map[string]struct{})
	for _, plugin := range cfg.Plugins {
		rules, ok := smartdnsMigrationArgs(t, plugin).(*sequence.Args)
		if !ok {
			continue
		}
		for _, rule := range *rules {
			for _, match := range rule.Matches {
				for _, expression := range strings.Fields(match) {
					if strings.HasPrefix(expression, "$domain_") {
						t.Fatalf("%s retains a domain provider reference %q", plugin.Tag, expression)
					}
					if !strings.HasPrefix(expression, "geosite:") {
						continue
					}
					_, code, attrs, ok, err := geodata.ParseDomainExp(expression)
					if err != nil || !ok || len(attrs) != 0 {
						t.Fatalf("unsupported synthetic GeoSite expression %q: %v", expression, err)
					}
					labels[strings.ToLower(code)] = struct{}{}
				}
			}
		}
	}
	if len(labels) == 0 {
		t.Fatal("migration sequences contain no direct geosite references")
	}
	var codes []string
	for code := range labels {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}

// Build a small, instance-local GeoSite database from the entries referenced by
// the real sequences. This keeps the direct geosite: compilation path intact
// while synthetic routing tests stay independent of exported deployment data.
func smartdnsMigrationSiteFixture(t *testing.T, cfg coremain.Config, dir string) string {
	t.Helper()
	bytesField := func(dst []byte, number protowire.Number, value []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(dst, number, protowire.BytesType), value)
	}
	var data []byte
	for _, code := range smartdnsMigrationSiteLabels(t, cfg) {
		domain := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), uint64(geodata.TypeFull))
		domain = bytesField(domain, 2, []byte(code+".migration.invalid"))
		entry := bytesField(nil, 1, []byte(strings.ToUpper(code)))
		entry = bytesField(entry, 2, domain)
		data = bytesField(data, 1, entry)
	}
	path := filepath.Join(dir, "geosite.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func smartdnsMigrationIPs(tag string) string {
	switch strings.TrimPrefix(tag, "ip_") {
	case "cn", "cernet":
		return "192.0.2.0/24\n2001:db8:c::/48\n"
	case "private":
		return "10.0.0.0/8\nfc00::/7\n"
	case "cloudflare", "asn33191":
		return "104.16.0.0/13\n2606:4700::/32\n"
	case "fastly":
		return "151.101.0.0/16\n2a04:4e42::/32\n"
	case "cloudfront":
		return "13.32.0.0/15\n2600:9000::/32\n"
	case "github", "github-raw":
		return "198.51.100.0/24\n"
	}
	return "198.18.0.0/15\n"
}

func (f *smartdnsMigrationFixture) exec(t *testing.T, tag, name string, qtype uint16) *query_context.Context {
	t.Helper()
	e := sequence.ToExecutable(f.plugins[tag])
	if e == nil {
		t.Fatalf("%s is not executable", tag)
	}
	q := query_context.NewContext(new(dns.Msg).SetQuestion(name, qtype))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := e.Exec(ctx, q); err != nil {
		t.Fatalf("%s(%s, %d): %v", tag, name, qtype, err)
	}
	return q
}

func smartdnsMigrationAnswerIPs(q *query_context.Context) []string {
	var ips []string
	if q.R() != nil {
		for _, rr := range q.R().Answer {
			switch rr := rr.(type) {
			case *dns.A:
				ips = append(ips, rr.A.String())
			case *dns.AAAA:
				ips = append(ips, rr.AAAA.String())
			}
		}
	}
	return ips
}

func (f *smartdnsMigrationFixture) observations() (int, []netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.called), slices.Clone(f.probed)
}

func TestSmartdnsMigrationConfigsLoadWithoutNetwork(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			f := smartdnsMigrationInstance(t, cfg, func(_, _ string, _ uint16) []netip.Addr { return nil })
			if calls, probes := f.observations(); calls != 0 || len(probes) != 0 {
				t.Fatal("initializing migration configuration performed I/O")
			}
			if len(f.plugins) < 10 {
				t.Fatalf("unexpectedly small migration graph: %d plugins", len(f.plugins))
			}
		})
	}
}

func TestSmartdnsMigrationRouting(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			for _, tc := range []struct {
				name, route string
				qtype       uint16
				static      string
			}{
				{"category-ads-all", "route_block", dns.TypeA, "127.0.0.1"},
				{"category-ads-all", "route_block", dns.TypeAAAA, "::1"},
				{"proxy", "route_proxy", dns.TypeA, "9.0.0.0"},
				{"proxy", "route_proxy", dns.TypeAAAA, "2620::"},
				{"google-cn", "route_google_cn", dns.TypeA, ""},
				{"cn", "route_cn", dns.TypeA, ""},
				{"cn", "route_cn", dns.TypeAAAA, ""},
				{"gfw", "route_global", dns.TypeA, ""},
				{"tld-opennic", "route_opennic", dns.TypeA, ""},
				{"unlisted", "route_default", dns.TypeA, ""},
			} {
				t.Run(tc.name+"/"+dns.TypeToString[tc.qtype], func(t *testing.T) {
					if strings.Contains(path, "cernet") && tc.route == "route_proxy" {
						if tc.qtype == dns.TypeA {
							tc.static = "192.168.8.64"
						} else {
							tc.static = "2001:db8::64"
						}
					}
					f := smartdnsMigrationInstance(t, cfg, func(_, name string, qtype uint16) []netip.Addr {
						if qtype == dns.TypeAAAA {
							return []netip.Addr{netip.MustParseAddr("2001:db8:c::42")}
						}
						return []netip.Addr{netip.MustParseAddr("192.0.2.42")}
					})
					q := f.exec(t, "main", tc.name+".migration.invalid.", tc.qtype)
					for tag, mark := range smartdnsMigrationRouteMarks {
						if q.HasMark(mark) != (tag == tc.route) {
							t.Errorf("route %s selected=%v, want route %s", tag, q.HasMark(mark), tc.route)
						}
					}
					if q.R() == nil {
						t.Fatal("missing response")
					}
					got := smartdnsMigrationAnswerIPs(q)
					calls, probes := f.observations()
					if tc.route == "route_block" || tc.route == "route_proxy" {
						if calls != 0 || len(probes) != 0 {
							t.Fatal("static route unexpectedly queried or probed an upstream")
						}
						if tc.static != "" && !slices.Equal(got, []string{tc.static}) {
							t.Fatalf("static route returned %v, want %s", got, tc.static)
						}
						if tc.static == "" && len(got) != 0 {
							t.Fatalf("blocked name returned addresses %v", got)
						}
					} else if len(got) == 0 || calls == 0 {
						t.Fatalf("route did not resolve using local sources: %v", q.R())
					}
				})
			}
		})
	}
}

// Opt-in startup validation uses the actual exported rules and MMDBs. The
// production constructors defer DNS/ECH queries until execution; ICMP capability
// detection only probes loopback. No deployment listener or cache file is used.
func TestSmartdnsMigrationLocalData(t *testing.T) {
	if os.Getenv("MOSDNS_SMARTDNS_LOCAL_DATA") != "1" {
		t.Skip("set MOSDNS_SMARTDNS_LOCAL_DATA=1 after exporting data/smartdns")
	}
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			cfg.Log.Level, cfg.Log.File, cfg.API.HTTP = "error", "", ""
			for i, p := range cfg.Plugins {
				args := smartdnsMigrationArgs(t, p)
				switch a := args.(type) {
				case *udp_server.Args:
					a.Listen = "127.0.0.1:0"
				case *tcp_server.Args:
					a.Listen = "127.0.0.1:0"
				case *cache.Args:
					a.DumpFile = ""
				}
				cfg.Plugins[i].Args = args
			}
			m, err := coremain.NewMosdns(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				m.CloseWithErr(nil)
				if err := m.GetSafeClose().WaitClosed(); err != nil {
					t.Error(err)
				}
			}()
			if sequence.ToExecutable(m.GetPlugin("main")) == nil {
				t.Fatal("configured entry is not executable")
			}
			if stats := m.ProbeManager().Stats(); stats.Probes != 0 || stats.Active != 0 || stats.Flights != 0 {
				t.Fatalf("initialization started candidate probes: %+v", stats)
			}
		})
	}
}

func TestSmartdnsMigrationReplacementFeedsSelector(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			for _, tc := range []struct {
				name, raw, first string
				qtype            uint16
			}{
				{"ipv4_prefix22", "151.101.2.42", "146.75.50.42", dns.TypeA},
				{"ipv6_prefix64", "2a04:4e42:1234:5678::42", "2a04:4e42:7c::42", dns.TypeAAAA},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if strings.Contains(path, "cernet") && tc.qtype == dns.TypeAAAA {
						tc.first = "2a04:4e42:200::42"
					}
					raw := netip.MustParseAddr(tc.raw)
					f := smartdnsMigrationInstance(t, cfg, func(_, _ string, _ uint16) []netip.Addr {
						return []netip.Addr{raw}
					})
					q := f.exec(t, "select_default", "unlisted.migration.invalid.", tc.qtype)
					got := smartdnsMigrationAnswerIPs(q)
					if len(got) == 0 || got[0] != tc.first || slices.Contains(got, tc.raw) {
						t.Fatalf("replacement selector returned %v, want first %s without raw %s", got, tc.first, tc.raw)
					}
					_, probes := f.observations()
					if len(probes) == 0 {
						t.Fatal("selector did not measure replacement addresses")
					}
					for _, ip := range probes {
						if ip == raw {
							t.Fatalf("selector measured original %s before replacement", ip)
						}
						if tc.qtype == dns.TypeA && ip.String() != tc.first {
							t.Fatalf("incorrect /22 replacement was measured: %s", ip)
						}
						if tc.qtype == dns.TypeAAAA && (!ip.Is6() || ip.As16()[15] != 0x42) {
							t.Fatalf("/64 replacement lost host bits: %s", ip)
						}
					}
				})
			}
		})
	}
}

func TestSmartdnsMigrationFilterPrecedesReplacement(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			var source string
			for _, p := range cfg.Plugins {
				if p.Tag == "select_default" {
					source = smartdnsMigrationArgs(t, p).(*speedcheck.Args).Sources[0]
					break
				}
			}
			if source == "" {
				t.Fatal("missing default source chain")
			}
			f := smartdnsMigrationInstance(t, cfg, func(_, _ string, _ uint16) []netip.Addr {
				return []netip.Addr{netip.MustParseAddr("151.101.2.42"), netip.MustParseAddr("198.18.0.42")}
			})
			q := f.exec(t, source, "unlisted.migration.invalid.", dns.TypeA)
			if q.R() != nil {
				t.Fatalf("filtered source survived replacement: %v", q.R())
			}
			if _, probes := f.observations(); len(probes) != 0 {
				t.Fatalf("a rejected source started probes: %v", probes)
			}
		})
	}
}
