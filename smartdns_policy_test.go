package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	forward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/speedcheck"
	"github.com/miekg/dns"
)

type smartdnsPolicyCall struct {
	tag, name string
	qtype     uint16
	do        bool
}

// Keep the checked-in policy graph intact, including the response cache and
// optional HTTPS lookups. Only upstream DNS and measurement I/O are controlled.
// The synthetic database entries exercise policy, not database classification.
type smartdnsPolicyFixture struct {
	plugins map[string]any
	mu      sync.Mutex
	calls   []smartdnsPolicyCall
	probes  []netip.Addr
	answer  func(string, *dns.Msg) *dns.Msg
	probe   speedcheck.ProbeFunc
}

func smartdnsPolicyInstance(t *testing.T, cfg coremain.Config, answer func(string, *dns.Msg) *dns.Msg, probe speedcheck.ProbeFunc) *smartdnsPolicyFixture {
	t.Helper()
	return smartdnsPolicyInstanceWithData(t, cfg, answer, probe, false)
}

// realData retains the configured GeoSite bundle and GeoIP/ASN databases.
// Both modes replace network I/O and never bind deployment listener ports.
func smartdnsPolicyInstanceWithData(t *testing.T, cfg coremain.Config, answer func(string, *dns.Msg) *dns.Msg, probe speedcheck.ProbeFunc, realData bool) *smartdnsPolicyFixture {
	t.Helper()
	f := &smartdnsPolicyFixture{plugins: make(map[string]any), answer: answer, probe: probe}
	dir := t.TempDir()
	if !realData {
		cfg.Geodata.GeoSite = smartdnsMigrationSiteFixture(t, cfg, dir)
	}
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
			if realData {
				break
			}
			for i, file := range a.Files {
				a.Files[i] = filepath.Join(dir, "ips", filepath.Base(file))
				smartdnsMigrationWrite(t, a.Files[i], smartdnsPolicyIPs(p.Tag))
			}
			var ips []string
			for _, expression := range a.IPs {
				if strings.HasPrefix(expression, "ext:") || strings.HasPrefix(expression, "geoip:") || strings.HasPrefix(expression, "asn:") {
					ips = append(ips, strings.Fields(smartdnsPolicyIPs(p.Tag))...)
				} else {
					ips = append(ips, expression)
				}
			}
			a.IPs = ips
		case *cache.Args:
			a.DumpFile = ""
		case *forward.Args:
			tag := p.Tag
			instance = sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				f.mu.Lock()
				f.calls = append(f.calls, smartdnsPolicyCall{tag, q.QQuestion().Name, q.QQuestion().Qtype, q.QOpt().Do()})
				f.mu.Unlock()
				r := f.answer(tag, q.Q())
				if r != nil {
					r = r.Copy()
				}
				q.SetResponse(r)
				return nil
			})
		case *speedcheck.Args:
			var sources []speedcheck.Source
			for _, tag := range a.Sources {
				e := sequence.ToExecutable(f.plugins[tag])
				if e == nil {
					t.Fatalf("%s: missing source %s", p.Tag, tag)
				}
				sources = append(sources, speedcheck.Source{Tag: tag, Exec: e})
			}
			labels := make(map[string]netlist.Matcher)
			for tag, expressions := range a.Labels {
				labels[tag], err = ip_set.CompileExpressions(bp, expressions)
				if err != nil {
					t.Fatalf("%s label %s: %v", p.Tag, tag, err)
				}
			}
			instance, err = speedcheck.New(*a, sources, speedcheck.Options{Labels: labels,
				Probe: func(ctx context.Context, ip netip.Addr, config speedtest.Config) speedtest.Result {
					f.mu.Lock()
					f.probes = append(f.probes, ip)
					f.mu.Unlock()
					if f.probe != nil {
						return f.probe(ctx, ip, config)
					}
					return speedtest.Result{Outcome: speedtest.Success, RTT: time.Millisecond}
				},
			})
		}
		if p.Type == "udp_server" || p.Type == "tcp_server" || p.Type == "http_server" || p.Type == "quic_server" {
			continue
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

func smartdnsPolicyIPs(tag string) string {
	if tag == "ip_cloudflare" || tag == "ip_asn_33191" {
		// Both the original and generated Cloudflare addresses are in this set.
		return "104.16.0.0/13\n172.64.0.0/13\n2606:4700::/32\n"
	}
	return smartdnsMigrationIPs(tag)
}

func (f *smartdnsPolicyFixture) exec(t *testing.T, tag, name string, qtype uint16, do bool) (*query_context.Context, error) {
	t.Helper()
	e := sequence.ToExecutable(f.plugins[tag])
	if e == nil {
		t.Fatalf("%s is not executable", tag)
	}
	msg := new(dns.Msg).SetQuestion(name, qtype)
	msg.SetEdns0(1232, do)
	q := query_context.NewContext(msg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return q, e.Exec(ctx, q)
}

func (f *smartdnsPolicyFixture) observations() ([]smartdnsPolicyCall, []netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls), slices.Clone(f.probes)
}

func smartdnsPolicyAddressReply(query *dns.Msg, terminal string, ips ...string) *dns.Msg {
	r := new(dns.Msg).SetReply(query)
	name := query.Question[0].Name
	if terminal != "" && terminal != name {
		r.Answer = append(r.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: terminal})
		name = terminal
	}
	for _, value := range ips {
		ip := netip.MustParseAddr(value)
		h := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: 60}
		if ip.Is4() {
			h.Rrtype = dns.TypeA
			r.Answer = append(r.Answer, &dns.A{Hdr: h, A: ip.AsSlice()})
		} else {
			h.Rrtype = dns.TypeAAAA
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: h, AAAA: ip.AsSlice()})
		}
	}
	return r
}

func smartdnsPolicyRequireSuccess(t *testing.T, q *query_context.Context, err error) {
	t.Helper()
	if err != nil || q.R() == nil || q.R().Rcode != dns.RcodeSuccess {
		t.Fatalf("query failed: error=%v response=%v", err, q.R())
	}
}

func TestSmartdnsPolicyMainCache(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			f := smartdnsPolicyInstance(t, smartdnsMigrationConfig(t, path), func(_ string, query *dns.Msg) *dns.Msg {
				return smartdnsPolicyAddressReply(query, "", "192.0.2.42")
			}, nil)
			first, err := f.exec(t, "main", "unlisted.migration.invalid.", dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, first, err)
			calls, probes := f.observations()
			if len(calls) == 0 || len(probes) == 0 {
				t.Fatal("cold query skipped DNS or measurements")
			}
			second, err := f.exec(t, "main", "unlisted.migration.invalid.", dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, second, err)
			afterCalls, afterProbes := f.observations()
			if len(calls) != len(afterCalls) || len(probes) != len(afterProbes) {
				t.Fatalf("cached request performed I/O: DNS %d -> %d, probe %d -> %d", len(calls), len(afterCalls), len(probes), len(afterProbes))
			}
			if !slices.Equal(smartdnsMigrationAnswerIPs(first), smartdnsMigrationAnswerIPs(second)) {
				t.Fatal("cache changed selected address")
			}
		})
	}
}

func TestSmartdnsPolicyFilterWholeResponseAndExemptions(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			exempt := "meta"
			if strings.Contains(path, "cernet") {
				exempt = "facebook"
			}
			for _, tc := range []struct {
				name, terminal string
				keep           bool
			}{
				{"unlisted", "", false},
				{exempt, "", true},
				{"dropbox", "", true},
				{"alias", exempt + ".migration.invalid.", true},
			} {
				t.Run(tc.name+tc.terminal, func(t *testing.T) {
					f := smartdnsPolicyInstance(t, cfg, func(_ string, query *dns.Msg) *dns.Msg {
						return smartdnsPolicyAddressReply(query, tc.terminal, "192.0.2.42", "198.18.0.42")
					}, nil)
					// This is the real mandatory source filter, before replacement.
					var source string
					for _, p := range cfg.Plugins {
						if p.Tag == "select_default" {
							source = smartdnsMigrationArgs(t, p).(*speedcheck.Args).Sources[0]
						}
					}
					q, err := f.exec(t, source, tc.name+".migration.invalid.", dns.TypeA, false)
					if err != nil {
						t.Fatal(err)
					}
					if (q.R() != nil) != tc.keep {
						t.Fatalf("response retained=%v, want %v: %v", q.R() != nil, tc.keep, q.R())
					}
					if tc.keep && len(smartdnsMigrationAnswerIPs(q)) != 2 {
						t.Fatalf("exempt response RRset changed: %v", q.R())
					}
					_, probes := f.observations()
					if len(probes) != 0 {
						t.Fatal("source-only evaluation started measurements")
					}
				})
			}
		})
	}
}

func TestSmartdnsPolicyCNAMEReplacementExclusionAndDO(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			for _, tc := range []struct {
				name, terminal string
				do, replaced   bool
			}{
				{"ordinary", "edge.migration.invalid.", false, true},
				{"excluded_qname", "edge.migration.invalid.", false, false},
				{"excluded_cname", "mozilla.migration.invalid.", false, false},
				{"dnssec", "edge.migration.invalid.", true, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := smartdnsPolicyInstance(t, cfg, func(_ string, query *dns.Msg) *dns.Msg {
						r := smartdnsPolicyAddressReply(query, tc.terminal, "104.16.0.42", "104.16.0.43")
						r.AuthenticatedData = true
						return r
					}, nil)
					name := "unlisted.migration.invalid."
					if tc.name == "excluded_qname" {
						name = "mozilla.migration.invalid."
					}
					q, err := f.exec(t, "main", name, dns.TypeA, tc.do)
					smartdnsPolicyRequireSuccess(t, q, err)
					got := smartdnsMigrationAnswerIPs(q)
					if tc.replaced {
						if !slices.Equal(got, []string{"172.64.145.0"}) {
							t.Fatalf("replacement not selected: %v", got)
						}
					} else if tc.do {
						if !slices.Equal(got, []string{"104.16.0.42", "104.16.0.43"}) || !q.R().AuthenticatedData {
							t.Fatalf("DO response was trimmed, rewritten or lost AD: %v", q.R())
						}
					} else if !slices.Equal(got, []string{"104.16.0.42"}) {
						t.Fatalf("name exclusion did not retain original IP: %v", got)
					}
					if len(q.R().Answer) == 0 || q.R().Answer[0].Header().Rrtype != dns.TypeCNAME {
						t.Fatal("lost original CNAME chain")
					}
					calls, probes := f.observations()
					if len(probes) == 0 {
						t.Fatal("no measurement was performed")
					}
					for _, call := range calls {
						if call.do != tc.do {
							t.Fatal("DO was not propagated to a source")
						}
					}
					for _, ip := range probes {
						if tc.replaced && strings.HasPrefix(ip.String(), "104.16.") {
							t.Fatal("measured original address before replacement")
						}
					}
				})
			}
		})
	}
}

func TestSmartdnsPolicyNXDOMAINStopsRouting(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			for _, domain := range []string{"google-cn", "google", "cn"} {
				t.Run(domain, func(t *testing.T) {
					f := smartdnsPolicyInstance(t, smartdnsMigrationConfig(t, path), func(_ string, query *dns.Msg) *dns.Msg {
						r := new(dns.Msg).SetRcode(query, dns.RcodeNameError)
						r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.migration.invalid.", Mbox: "hostmaster.migration.invalid.", Minttl: 60}}
						return r
					}, nil)
					q, err := f.exec(t, "main", domain+".migration.invalid.", dns.TypeAAAA, false)
					if err != nil || q.R() == nil || q.R().Rcode != dns.RcodeNameError || len(q.R().Answer) != 0 {
						t.Fatalf("negative response was changed or treated as failure: %v, %v", err, q.R())
					}
					if q.HasMark(smartdnsMigrationRouteMarks["route_default"]) {
						t.Fatal("legal NXDOMAIN fell through to default route")
					}
					_, probes := f.observations()
					if len(probes) != 0 {
						t.Fatal("negative response triggered a probe")
					}
				})
			}
		})
	}
}

func TestSmartdnsPolicyGoogleFallback(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			for _, tc := range []struct {
				name, ip string
				outcome  speedtest.Outcome
				fallback bool
			}{
				{"failed", "2001:4860:4860::42", speedtest.Failed, true},
				{"success", "2001:4860:4860::42", speedtest.Success, false},
				{"unmeasured", "2001:4860:4860::42", speedtest.Unmeasured, false},
				{"private", "fc00::42", speedtest.Failed, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := smartdnsPolicyInstance(t, cfg, func(_ string, query *dns.Msg) *dns.Msg {
						return smartdnsPolicyAddressReply(query, "", tc.ip)
					}, func(context.Context, netip.Addr, speedtest.Config) speedtest.Result {
						return speedtest.Result{Outcome: tc.outcome, RTT: time.Millisecond}
					})
					q, err := f.exec(t, "main", "google.migration.invalid.", dns.TypeAAAA, false)
					smartdnsPolicyRequireSuccess(t, q, err)
					got := smartdnsMigrationAnswerIPs(q)
					if tc.fallback {
						prefix := "2607:f8b0:4007:"
						if strings.Contains(path, "cernet") {
							prefix = "2404:6800:4005:"
						}
						if len(got) != 6 || !strings.HasPrefix(got[0], prefix) {
							t.Fatalf("real measurement failure did not trigger configured fallback: %v", got)
						}
						if q.R().Answer[0].Header().Ttl != 86400 {
							t.Fatalf("fallback TTL=%d, want 86400", q.R().Answer[0].Header().Ttl)
						}
					} else if !slices.Equal(got, []string{tc.ip}) {
						t.Fatalf("unexpected fallback: %v", got)
					}
					_, probes := f.observations()
					if (len(probes) == 0) != (tc.name == "private") {
						t.Fatalf("incorrect private-address probe behavior: %v", probes)
					}
				})
			}
		})
	}
}

var smartdnsPolicyECH = []byte{0, 7, 0xfe, 0x0d, 0, 3, 'a', 'b', 'c'}

func smartdnsPolicyHTTPSReply(query *dns.Msg, hints ...string) *dns.Msg {
	r := new(dns.Msg).SetReply(query)
	values := []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}}
	if len(hints) > 0 {
		var ips []net.IP
		for _, hint := range hints {
			ips = append(ips, net.ParseIP(hint).To4())
		}
		values = append(values, &dns.SVCBIPv4Hint{Hint: ips})
	}
	r.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
		Priority: 1, Target: ".", Value: values,
	}}}
	return r
}

func smartdnsPolicyECHReply(query *dns.Msg) *dns.Msg {
	r := smartdnsPolicyHTTPSReply(query)
	r.Answer[0].(*dns.HTTPS).Value = []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: slices.Clone(smartdnsPolicyECH)}}
	return r
}

func smartdnsPolicyAssertHTTPS(t *testing.T, q *query_context.Context, wantECH bool) {
	t.Helper()
	if len(q.R().Answer) != 1 {
		t.Fatalf("unexpected binding answer: %v", q.R())
	}
	rr, ok := q.R().Answer[0].(*dns.HTTPS)
	if !ok {
		t.Fatalf("unexpected binding type: %T", q.R().Answer[0])
	}
	gotECH := false
	for _, option := range rr.Value {
		switch option := option.(type) {
		case *dns.SVCBIPv4Hint, *dns.SVCBIPv6Hint:
			t.Fatal("address hint was not cleaned")
		case *dns.SVCBAlpn:
			if slices.Contains(option.Alpn, "h3") || !slices.Contains(option.Alpn, "h2") {
				t.Fatalf("incorrect ALPN cleanup: %v", option.Alpn)
			}
		case *dns.SVCBECHConfig:
			gotECH = true
			if !slices.Equal(option.ECH, smartdnsPolicyECH) {
				t.Fatal("ECH bytes changed")
			}
		}
	}
	if gotECH != wantECH {
		t.Fatalf("ECH present=%v, want %v", gotECH, wantECH)
	}
}

func TestSmartdnsPolicyHTTPSCleanupAndHintFiltering(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			for _, tc := range []struct {
				name, hint string
				wantECH    bool
			}{
				{"unlisted", "104.16.0.42", true},
				{"cn", "104.16.0.42", false},
				{"unlisted", "192.0.2.42", false},
			} {
				t.Run(tc.name+"/"+tc.hint, func(t *testing.T) {
					f := smartdnsPolicyInstance(t, cfg, func(tag string, query *dns.Msg) *dns.Msg {
						if tag == "ech_lookup" {
							return smartdnsPolicyECHReply(query)
						}
						return smartdnsPolicyHTTPSReply(query, tc.hint)
					}, nil)
					q, err := f.exec(t, "main", tc.name+".migration.invalid.", dns.TypeHTTPS, false)
					smartdnsPolicyRequireSuccess(t, q, err)
					smartdnsPolicyAssertHTTPS(t, q, tc.wantECH)
					calls, probes := f.observations()
					for _, call := range calls {
						if call.qtype == dns.TypeA {
							t.Fatal("a binding with an existing hint triggered an A lookup")
						}
						if !tc.wantECH && call.tag == "ech_lookup" {
							t.Fatal("name/IP-excluded binding fetched ECH")
						}
					}
					if len(probes) != 0 {
						t.Fatal("selector measured HTTPS hint as address data")
					}
				})
			}
			t.Run("blocked_hint_rejects_source_before_cleanup", func(t *testing.T) {
				f := smartdnsPolicyInstance(t, cfg, func(_ string, query *dns.Msg) *dns.Msg {
					return smartdnsPolicyHTTPSReply(query, "104.16.0.42", "198.18.0.42")
				}, nil)
				q, err := f.exec(t, "main", "unlisted.migration.invalid.", dns.TypeHTTPS, false)
				if err == nil || q.R() != nil {
					t.Fatalf("blocked hint survived by cleanup: error=%v response=%v", err, q.R())
				}
				calls, _ := f.observations()
				for _, call := range calls {
					if call.tag == "ech_lookup" {
						t.Fatal("rejected response fetched ECH")
					}
				}
			})
		})
	}
}

func TestSmartdnsPolicyHTTPSAuxiliaryAFollowsFullRoute(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := smartdnsMigrationConfig(t, path)
			var sourceCount int
			for _, p := range cfg.Plugins {
				if p.Tag == "select_default" {
					sourceCount = len(smartdnsMigrationArgs(t, p).(*speedcheck.Args).Sources)
				}
			}
			f := smartdnsPolicyInstance(t, cfg, func(tag string, query *dns.Msg) *dns.Msg {
				if tag == "ech_lookup" {
					return smartdnsPolicyECHReply(query)
				}
				if query.Question[0].Qtype == dns.TypeA {
					return smartdnsPolicyAddressReply(query, "", "104.16.0.42")
				}
				return smartdnsPolicyHTTPSReply(query)
			}, nil)
			q, err := f.exec(t, "main", "unlisted.migration.invalid.", dns.TypeHTTPS, false)
			smartdnsPolicyRequireSuccess(t, q, err)
			smartdnsPolicyAssertHTTPS(t, q, true)
			calls, probes := f.observations()
			var ech, address, binding int
			for _, call := range calls {
				switch {
				case call.tag == "ech_lookup":
					ech++
				case call.qtype == dns.TypeA:
					address++
				case call.qtype == dns.TypeHTTPS:
					binding++
				}
			}
			if ech != 1 || address != sourceCount || binding == 0 || binding > sourceCount {
				t.Fatalf("unexpected optional lookup graph or recursion: ECH=%d A=%d HTTPS=%d", ech, address, binding)
			}
			if len(probes) == 0 {
				t.Fatal("auxiliary A query bypassed the speed selector")
			}
			for _, ip := range probes {
				if ip.String() == "104.16.0.42" {
					t.Fatal("auxiliary A query bypassed CDN replacement")
				}
			}
			// The A result is cached through resolve_cached, and the finalized
			// HTTPS result is cached through main. Neither needs a second query.
			cached, err := f.exec(t, "main", "unlisted.migration.invalid.", dns.TypeHTTPS, false)
			smartdnsPolicyRequireSuccess(t, cached, err)
			smartdnsPolicyAssertHTTPS(t, cached, true)
			afterCalls, afterProbes := f.observations()
			if len(afterCalls) != len(calls) || len(afterProbes) != len(probes) {
				t.Fatal("cached HTTPS result repeated DNS, ECH or measurement work")
			}
			a, err := f.exec(t, "main", "unlisted.migration.invalid.", dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, a, err)
			afterCalls, afterProbes = f.observations()
			if len(afterCalls) != len(calls) || len(afterProbes) != len(probes) {
				t.Fatal("auxiliary A result did not enter the shared response cache")
			}
		})
	}
}
