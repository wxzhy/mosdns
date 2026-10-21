package integration_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata/internal/mmdbbuild"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/domain_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/https_record"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/ip_replace"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/speedcheck"
	"github.com/IrineSistiana/mosdns/v5/plugin/matcher/qname"
	"github.com/IrineSistiana/mosdns/v5/plugin/matcher/resp_ip"
	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protowire"
)

type pathFixture struct {
	paths geodata.Paths
	name  string
	ip    string
}

func newPathFixture(t *testing.T, name, ip string) pathFixture {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	field := func(b []byte, number protowire.Number, value []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(b, number, protowire.BytesType), value)
	}
	entry := field(nil, 1, []byte("SHARED"))
	domain := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), uint64(geodata.TypeFull))
	domain = field(domain, 2, []byte(name))
	site := field(nil, 1, field(entry, 2, domain))
	addr := netip.MustParseAddr(ip)
	cidr := field(nil, 1, addr.AsSlice())
	cidr = protowire.AppendVarint(protowire.AppendTag(cidr, 2, protowire.VarintType), uint64(addr.BitLen()))
	geoip := field(nil, 1, field(entry, 2, cidr))
	w := mmdbbuild.New("GeoLite2-ASN", 6)
	record := mmdbbuild.Map(
		mmdbbuild.F("autonomous_system_number", mmdbbuild.Uint32(64512)),
		mmdbbuild.F("autonomous_system_organization", mmdbbuild.String("TEST-ASN")),
	)
	// The minimal fixture writer emits data on the children of its prefix
	// node. A /24 leaves room for that node within the IPv4 lookup depth.
	if err := w.Add(netip.PrefixFrom(addr, 24), record); err != nil {
		t.Fatal(err)
	}
	asn, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return pathFixture{
		paths: geodata.Paths{GeoSite: write("geosite.dat", site), GeoIP: write("geoip.dat", geoip), ASN: write("ASN.mmdb", asn)},
		name:  name, ip: ip,
	}
}

func newConfiguredInstance(t *testing.T, paths geodata.Paths, plugins ...coremain.PluginConfig) *coremain.Mosdns {
	t.Helper()
	m, err := coremain.NewMosdns(&coremain.Config{Geodata: paths, Log: mlog.LogConfig{Level: "error"}, Plugins: plugins})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.CloseWithErr(nil)
		if err := m.GetSafeClose().WaitClosed(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func addressContext(name string, ips ...string) *query_context.Context {
	qCtx := query_context.NewContext(new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA))
	r := new(dns.Msg).SetReply(qCtx.Q())
	for _, ip := range ips {
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: qCtx.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip),
		})
	}
	qCtx.SetResponse(r)
	return qCtx
}

func TestConfiguredGeodataPathsInstanceIsolation(t *testing.T) {
	fixtures := []pathFixture{newPathFixture(t, "one.test", "192.0.2.1"), newPathFixture(t, "two.test", "198.51.100.1")}
	for i, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			other := fixtures[1-i]
			m := newConfiguredInstance(t, fixture.paths,
				coremain.PluginConfig{Tag: "sites", Type: domain_set.PluginType, Args: &domain_set.Args{Exps: []string{"geosite:shared"}}},
				coremain.PluginConfig{Tag: "countries", Type: ip_set.PluginType, Args: &ip_set.Args{IPs: []string{"geoip:shared"}}},
				coremain.PluginConfig{Tag: "asns", Type: ip_set.PluginType, Args: &ip_set.Args{IPs: []string{"asn:64512"}}},
			)
			if m.GeodataPaths() != fixture.paths {
				t.Fatalf("instance paths = %+v, want %+v", m.GeodataPaths(), fixture.paths)
			}
			matcher := m.GetPlugin("sites").(*domain_set.DomainSet).GetDomainMatcher()
			if _, ok := matcher.Match(fixture.name + "."); !ok {
				t.Fatal("configured geosite did not match its own domain")
			}
			if _, ok := matcher.Match(other.name + "."); ok {
				t.Fatal("geosite leaked between instances")
			}
			for _, tag := range []string{"countries", "asns"} {
				matcher := m.GetPlugin(tag).(*ip_set.IPSet).GetIPMatcher()
				if !matcher.Match(netip.MustParseAddr(fixture.ip)) || matcher.Match(netip.MustParseAddr(other.ip)) {
					t.Errorf("%s did not isolate configured database", tag)
				}
			}
			bp := coremain.NewBP("quick", m)
			for _, setup := range []struct {
				name string
				new  func(sequence.BQ, string) (sequence.Matcher, error)
				exp  string
			}{
				{"qname", qname.QuickSetup, "geosite:shared"},
				{"resp_geoip", resp_ip.QuickSetup, "geoip:shared"},
				{"resp_asn", resp_ip.QuickSetup, "asn:64512"},
			} {
				matcher, err := setup.new(bp, setup.exp)
				if err != nil {
					t.Fatal(err)
				}
				for _, tc := range []struct {
					fixture pathFixture
					want    bool
				}{{fixture, true}, {other, false}} {
					got, err := matcher.Match(t.Context(), addressContext(tc.fixture.name, tc.fixture.ip))
					if err != nil || got != tc.want {
						t.Errorf("%s match %s = %v, %v; want %v", setup.name, tc.fixture.name, got, err, tc.want)
					}
				}
			}
			// Numeric ASN selection follows this instance's library even though
			// both sources contain the same two addresses. No socket is needed:
			// an explicit empty probe include keeps both candidates unmeasured.
			plugins := map[string]any{"source": sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				r := addressContext(qCtx.QQuestion().Name, fixtures[0].ip, fixtures[1].ip).R()
				r.Id = qCtx.Q().Id
				qCtx.SetResponse(r)
				return nil
			})}
			testInstance := coremain.NewTestMosdnsWithPlugins(plugins, fixture.paths)
			value, err := speedcheck.Init(coremain.NewBP("selector", testInstance), &speedcheck.Args{
				Sources: []string{"source"}, Mode: speedcheck.ModeWaitAll,
				ASNMultipliers: map[uint32]float64{64512: 0.1},
				ProbeMatch:     &speedcheck.IPFilter{ASNInclude: []uint32{}},
			})
			if err != nil {
				t.Fatal(err)
			}
			selector := value.(*speedcheck.Selector)
			t.Cleanup(func() {
				_ = selector.Close()
				testInstance.CloseWithErr(nil)
				_ = testInstance.GetSafeClose().WaitClosed()
			})
			query := query_context.NewContext(new(dns.Msg).SetQuestion("selector.test.", dns.TypeA))
			if err := selector.Exec(t.Context(), query); err != nil {
				t.Fatal(err)
			}
			if len(query.R().Answer) != 1 || query.R().Answer[0].(*dns.A).A.String() != fixture.ip {
				t.Fatalf("numeric ASN selected %v, want %s", query.R().Answer, fixture.ip)
			}
			if stats := testInstance.ProbeManager().Stats(); stats.Probes != 0 || stats.Active != 0 {
				t.Fatalf("disabled probes created sockets: %+v", stats)
			}
		})
	}
}

func TestConfiguredGeodataPathsPluginExpressions(t *testing.T) {
	fixture := newPathFixture(t, "one.test", "192.0.2.1")
	plugins := map[string]any{"ech": sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		r := new(dns.Msg).SetReply(qCtx.Q())
		r.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
			Hdr: dns.RR_Header{Name: qCtx.QQuestion().Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60}, Priority: 1, Target: ".",
			Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: []byte{0, 4, 0xfe, 0xff, 0, 0}}},
		}}}
		qCtx.SetResponse(r)
		return nil
	})}
	m := coremain.NewTestMosdnsWithPlugins(plugins, fixture.paths)
	bp := coremain.NewBP("expressions", m)
	for _, expression := range []string{"geoip:shared", "asn:64512"} {
		replacer, err := ip_replace.New(bp, &ip_replace.Args{ReplaceMap: []ip_replace.Rule{{MatchIP: []string{expression}, IPv4: []string{"203.0.113.7"}}}})
		if err != nil {
			t.Fatal(err)
		}
		query := addressContext(fixture.name, fixture.ip)
		if err := replacer.Exec(t.Context(), query); err != nil {
			t.Fatal(err)
		}
		if got := query.R().Answer[0].(*dns.A).A.String(); got != "203.0.113.7" {
			t.Errorf("ip_replace %s = %s", expression, got)
		}
	}
	disabled := false
	policy, err := https_record.New(bp, &https_record.Args{
		ECHSource: "ech", EnableSubquery: &disabled, MatchName: []string{"geosite:shared"}, MatchIP: []string{"geoip:shared"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = policy.Close() })
	for _, tc := range []struct {
		name, ip string
		wantECH  bool
	}{{fixture.name, fixture.ip, true}, {"other.test", fixture.ip, false}, {fixture.name, "198.51.100.1", false}} {
		qCtx := query_context.NewContext(new(dns.Msg).SetQuestion(dns.Fqdn(tc.name), dns.TypeHTTPS))
		r := new(dns.Msg).SetReply(qCtx.Q())
		r.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
			Hdr: dns.RR_Header{Name: qCtx.QQuestion().Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60}, Priority: 1, Target: ".",
			Value: []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP(tc.ip)}}},
		}}}
		qCtx.SetResponse(r)
		if err := policy.Exec(t.Context(), qCtx); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, value := range qCtx.R().Answer[0].(*dns.HTTPS).Value {
			found = found || value.Key() == dns.SVCB_ECHCONFIG
		}
		if found != tc.wantECH {
			t.Errorf("https_record name %s IP %s ECH = %v, want %v", tc.name, tc.ip, found, tc.wantECH)
		}
	}
}

func TestConfiguredGeodataPathsExplicitOverrideAndErrors(t *testing.T) {
	fixture := newPathFixture(t, "one.test", "192.0.2.1")
	// Conventional files are deliberately present: an explicit missing path
	// must report that exact file rather than falling back to these databases.
	t.Chdir(filepath.Dir(fixture.paths.GeoSite))
	missing := filepath.Join(t.TempDir(), "missing.db")
	m := newConfiguredInstance(t, geodata.Paths{GeoSite: missing, GeoIP: missing, ASN: missing})
	bp := coremain.NewBP("expressions", m)
	// An unused default is not opened during startup. Explicit expressions
	// work even when all configured shortcut defaults point to missing files.
	matcher, err := domain_set.CompileExpressions(bp, []string{"ext:" + fixture.paths.GeoSite + ":shared"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := matcher.Match(fixture.name + "."); !ok {
		t.Fatal("explicit geosite did not override instance default")
	}
	for _, fileCode := range []string{fixture.paths.GeoIP + ":shared", fixture.paths.ASN + ":AS64512"} {
		matcher, err := ip_set.CompileExpressions(bp, []string{"ext:" + fileCode})
		if err != nil || !matcher.Match(netip.MustParseAddr(fixture.ip)) {
			t.Fatalf("explicit IP expression %s: %v", fileCode, err)
		}
	}
	_, err = domain_set.CompileExpressions(bp, []string{"geosite:shared"})
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing configured geosite = %v", err)
	}
	for _, exp := range []string{"geoip:shared", "asn:64512"} {
		_, err := ip_set.CompileExpressions(bp, []string{exp})
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("missing configured %s = %v", exp, err)
		}
	}
	// A different, unconfigured instance still uses the existing conventional
	// working-directory defaults, unaffected by the configured instance.
	legacy := coremain.NewBP("legacy", coremain.NewTestMosdnsWithPlugins(nil))
	domainMatcher, err := domain_set.CompileExpressions(legacy, []string{"geosite:shared"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := domainMatcher.Match(fixture.name + "."); !ok {
		t.Fatal("omitted geosite path no longer uses conventional defaults")
	}
	for _, exp := range []string{"geoip:shared", "asn:64512"} {
		matcher, err := ip_set.CompileExpressions(legacy, []string{exp})
		if err != nil || !matcher.Match(netip.MustParseAddr(fixture.ip)) {
			t.Fatalf("omitted %s path did not use conventional defaults: %v", exp, err)
		}
	}
}

func TestConfiguredGeodataPathsIncludeInheritance(t *testing.T) {
	fixture := newPathFixture(t, "one.test", "192.0.2.1")
	writeInclude := func(name string, paths geodata.Paths) string {
		t.Helper()
		data, err := yaml.Marshal(&coremain.Config{Geodata: paths, Plugins: []coremain.PluginConfig{{
			Tag: "included", Type: "domain_set", Args: map[string]any{"exps": []string{"geosite:shared"}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), name+".yaml")
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	include := writeInclude("inherit", geodata.Paths{})
	cfg := &coremain.Config{Geodata: fixture.paths, Log: mlog.LogConfig{Level: "error"}, Include: []string{include}}
	m, err := coremain.NewMosdns(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.CloseWithErr(nil)
	if err := m.GetSafeClose().WaitClosed(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.GetPlugin("included").(*domain_set.DomainSet).GetDomainMatcher().Match(fixture.name + "."); !ok {
		t.Fatal("included plugin did not inherit main configuration paths")
	}
	for _, field := range []geodata.Paths{{GeoSite: fixture.paths.GeoSite}, {GeoIP: fixture.paths.GeoIP}, {ASN: fixture.paths.ASN}} {
		cfg.Include = []string{writeInclude(fmt.Sprintf("override-%d", len(field.GeoSite)+len(field.GeoIP)+len(field.ASN)), field)}
		m, err := coremain.NewMosdns(cfg)
		if err == nil {
			m.CloseWithErr(nil)
			_ = m.GetSafeClose().WaitClosed()
			t.Fatal("included configuration unexpectedly changed instance defaults")
		}
		if !strings.Contains(err.Error(), "root config") {
			t.Errorf("include override error = %v", err)
		}
	}
}
