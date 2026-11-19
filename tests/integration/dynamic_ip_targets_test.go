package integration_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/hosts"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/ip_fallback"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/ip_replace"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/speedcheck"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/server_utils"
	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func dynamicSource(t *testing.T, source sequence.Executable, cached bool) (*coremain.BP, map[string]any) {
	var args *cache.Args
	if cached {
		args = &cache.Args{Size: 16, Scope: "sequence"}
	}
	return dynamicSourceCache(t, source, args)
}

func dynamicSourceCache(t *testing.T, source sequence.Executable, args *cache.Args) (*coremain.BP, map[string]any) {
	t.Helper()
	plugins := map[string]any{"source_body": source}
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	bp := coremain.NewBP("dynamic_test", m)
	rules := []sequence.RuleArgs{}
	if args != nil {
		c := cache.NewCache(args, cache.Opts{})
		t.Cleanup(func() { _ = c.Close() })
		plugins["target_cache"] = c
		rules = append(rules, sequence.RuleArgs{Exec: "$target_cache"}, sequence.RuleArgs{Matches: []string{"has_resp"}, Exec: "accept"})
	}
	rules = append(rules, sequence.RuleArgs{Exec: "$source_body"})
	s, err := sequence.NewSequence(bp, rules)
	if err != nil {
		t.Fatal(err)
	}
	plugins["target_resolve"] = s
	t.Cleanup(func() { _ = s.Close() })
	return bp, plugins
}

func dynamicFallback(t *testing.T, bp *coremain.BP, args ip_fallback.Args) *ip_fallback.Fallback {
	t.Helper()
	v, err := ip_fallback.Init(bp, &args)
	if err != nil {
		t.Fatal(err)
	}
	f := v.(*ip_fallback.Fallback)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func dynamicReplacer(t *testing.T, bp *coremain.BP, args ip_replace.Args) *ip_replace.Replacer {
	t.Helper()
	p, err := ip_replace.New(bp, &args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func dynamicResponse(q *query_context.Context, ttl uint32, alias string, ips ...string) {
	r := new(dns.Msg).SetReply(q.Q())
	owner := q.QQuestion().Name
	if alias != "" {
		r.Answer = append(r.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}, Target: alias})
		owner = alias
	}
	for _, ip := range ips {
		h := dns.RR_Header{Name: owner, Rrtype: q.QQuestion().Qtype, Class: dns.ClassINET, Ttl: ttl}
		if h.Rrtype == dns.TypeA {
			r.Answer = append(r.Answer, &dns.A{Hdr: h, A: net.ParseIP(ip)})
		} else {
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: h, AAAA: net.ParseIP(ip)})
		}
	}
	q.SetResponse(r)
}

func dynamicIPs(q *query_context.Context) []string {
	var ips []string
	for _, rr := range q.R().Answer {
		switch rr := rr.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.AAAA:
			ips = append(ips, rr.AAAA.String())
		}
	}
	return ips
}

func TestDynamicIPCacheRefreshAndSpeedcheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, err := hosts.NewHosts(&hosts.Args{Entries: []string{"target.example 203.0.113.99 2001:db8:100::99"}})
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		var queries atomic.Int32
		bp, _ := dynamicSource(t, sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
			queries.Add(1)
			if err := h.Exec(ctx, q); err != nil {
				return err
			}
			for _, rr := range q.R().Answer {
				rr.Header().Ttl = 2
			}
			q.SetMark(99)
			return nil
		}), true)
		prefix4, prefix6 := 24, 64
		rp := dynamicReplacer(t, bp, ip_replace.Args{IPSource: "target_resolve", ReplaceMap: []ip_replace.Rule{{MatchIP: []string{"192.0.2.0/24", "2001:db8:20::/48"}, IPv4PrefixLen: &prefix4, IPv6PrefixLen: &prefix6, IPv4: []string{"domain:target.example"}, IPv6: []string{"domain:target.example"}}}})
		fb := dynamicFallback(t, bp, ip_fallback.Args{IPSource: "target_resolve", IPv4: []string{"domain:target.example"}, IPv6: []string{"domain:target.example"}})
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
			original, want, full := "192.0.2.42", "203.0.113.42", "203.0.113.99"
			if typ == dns.TypeAAAA {
				original, want, full = "2001:db8:20::42", "2001:db8:100::42", "2001:db8:100::99"
			}
			var probes atomic.Int32
			s, err := speedcheck.New(speedcheck.Args{Mode: speedcheck.ModeWaitAll, MaxNum: 1}, []speedcheck.Source{{Tag: "replaced", Exec: sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
				dynamicResponse(q, 300, "", original)
				return rp.Exec(ctx, q)
			})}}, speedcheck.Options{Probe: func(ctx context.Context, ip netip.Addr, c speedtest.Config) speedtest.Result {
				probes.Add(1)
				if ip.String() != want {
					t.Errorf("probed %s want replaced %s", ip, want)
				}
				return speedtest.Result{Outcome: speedtest.Success, RTT: time.Millisecond}
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			before := queries.Load()
			for i := 0; i < 2; i++ {
				q := query_context.NewContext(new(dns.Msg).SetQuestion("user.example.", typ))
				q.SetMark(37)
				if err := s.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(dynamicIPs(q), []string{want}) || !q.HasMark(37) || q.HasMark(99) {
					t.Fatalf("selection/state: %v", q.R())
				}
			}
			q := query_context.NewContext(new(dns.Msg).SetQuestion("empty.example.", typ))
			dynamicResponse(q, 300, "")
			if err := fb.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(dynamicIPs(q), []string{full}) || queries.Load() != before+1 {
				t.Fatalf("dedicated source cache not shared: %d %v", queries.Load(), q.R())
			}
			time.Sleep(2500 * time.Millisecond)
			q = query_context.NewContext(new(dns.Msg).SetQuestion("empty.example.", typ))
			dynamicResponse(q, 300, "")
			if err := fb.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if queries.Load() != before+2 || probes.Load() == 0 {
				t.Fatal("expired source did not refresh or replacement not probed")
			}
		}
	})
}

func TestDynamicIPLazyLookupFirstRuleAndRecursion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fb *ip_fallback.Fallback
		var rp *ip_replace.Replacer
		var calls atomic.Int32
		bp, _ := dynamicSource(t, sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
			calls.Add(1)
			if q.QQuestion().Name == "bad.example." {
				time.Sleep(1200 * time.Millisecond)
				return errors.New("offline NXDOMAIN equivalent")
			}
			dynamicResponse(q, 30, "target-end.example.", "203.0.113.42")
			s := q.SnapshotResponse()
			s.ProbeStatus = query_context.ProbeFailed
			q.CommitResponse(s)
			// Both rewrites would recursively invoke this same source without
			// their shared context flag (one with no_rtt, the other with any IP).
			if err := fb.Exec(ctx, q); err != nil {
				return err
			}
			return rp.Exec(ctx, q)
		}), false)
		fb = dynamicFallback(t, bp, ip_fallback.Args{IPSource: "target_resolve", On: []string{"no_rtt"}, IPv4: []string{"domain:target.example"}})
		rp = dynamicReplacer(t, bp, ip_replace.Args{IPSource: "target_resolve", Timeout: 2 * time.Second, ReplaceMap: []ip_replace.Rule{
			{MatchIP: []string{"192.0.2.0/24", "203.0.113.0/24"}, IPv4: []string{"domain:bad.example"}},
			{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"198.51.100.42"}},
		}})
		q := query_context.NewContext(new(dns.Msg).SetQuestion("user.example.", dns.TypeA))
		dynamicResponse(q, 30, "original-end.example.", "192.0.2.42")
		if err := fb.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 0 {
			t.Fatal("lookup before fallback trigger")
		}
		s := q.SnapshotResponse()
		s.ProbeStatus = query_context.ProbeUnmeasured
		q.CommitResponse(s)
		if err := fb.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 1 || !slices.Equal(dynamicIPs(q), []string{"203.0.113.42"}) || len(q.R().Answer) != 2 || q.R().Answer[1].Header().Name != "original-end.example." {
			t.Fatalf("recursion/owner: %v calls=%d", q.R(), calls.Load())
		}
		q = query_context.NewContext(new(dns.Msg).SetQuestion("user.example.", dns.TypeA))
		dynamicResponse(q, 30, "", "192.0.2.42")
		if err := rp.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(dynamicIPs(q), []string{"192.0.2.42"}) || q.R().Answer[0].Header().Ttl != 28 || calls.Load() != 2 {
			t.Fatalf("failed first rule must age and retain original: %v", q.R())
		}
	})
}

func TestDynamicIPTTLZeroAndOriginalLifetime(t *testing.T) {
	for _, kind := range []string{"fallback", "replace"} {
		for _, targetTTL := range []uint32{0, 1, 20} {
			t.Run(fmt.Sprintf("%s/%d", kind, targetTTL), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					bp, _ := dynamicSource(t, sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
						dynamicResponse(q, 30, "target-end.example.", "203.0.113.9")
						q.R().Answer[0].Header().Ttl = targetTTL
						time.Sleep(1200 * time.Millisecond)
						return nil
					}), false)
					q := query_context.NewContext(new(dns.Msg).SetQuestion("user.example.", dns.TypeA))
					dynamicResponse(q, 10, "user-end.example.", "192.0.2.1")
					s := q.SnapshotResponse()
					s.ProbeStatus = query_context.ProbeFailed
					q.CommitResponse(s)
					var plugin sequence.Executable
					if kind == "fallback" {
						ttl := int64(60)
						plugin = dynamicFallback(t, bp, ip_fallback.Args{IPSource: "target_resolve", Timeout: 2 * time.Second, TTL: &ttl, IPv4: []string{"domain:target.example"}})
					} else {
						plugin = dynamicReplacer(t, bp, ip_replace.Args{IPSource: "target_resolve", Timeout: 2 * time.Second, ReplaceMap: []ip_replace.Rule{{MatchIP: []string{"192.0.2.0/24"}, IPv4: []string{"domain:target.example"}}}})
					}
					start := time.Now()
					if err := plugin.Exec(context.Background(), q); err != nil {
						t.Fatal(err)
					}
					wantIP, wantTTL := "203.0.113.9", uint32(8)
					if targetTTL == 0 {
						wantTTL = 0
					}
					if targetTTL == 1 {
						wantIP = "192.0.2.1"
					}
					if !slices.Equal(dynamicIPs(q), []string{wantIP}) || q.R().Answer[0].Header().Ttl != wantTTL || len(q.R().Answer) != 2 || q.R().Answer[1].Header().Name != "user-end.example." {
						t.Fatalf("lease/owner: %v", q.R())
					}
					if !q.SnapshotResponse().ValidUntil.Equal(start.Add(10 * time.Second)) {
						t.Fatalf("wrong absolute lease: %s", q.SnapshotResponse().ValidUntil)
					}
				})
			})
		}
	}
}

func TestDynamicIPConfigurationErrors(t *testing.T) {
	bp, plugins := dynamicSource(t, sequence.ExecutableFunc(func(context.Context, *query_context.Context) error { return nil }), false)
	plugins["wrong_type"] = sequence.ExecutableFunc(func(context.Context, *query_context.Context) error { return nil })
	for _, source := range []string{"", "missing", "$target_resolve", "wrong_type"} {
		if _, err := ip_fallback.Init(bp, &ip_fallback.Args{IPSource: source, IPv4: []string{"domain:target.example"}}); err == nil {
			t.Errorf("fallback accepted %q", source)
		}
		if _, err := ip_replace.New(bp, &ip_replace.Args{IPSource: source, ReplaceMap: []ip_replace.Rule{{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"domain:target.example"}}}}); err == nil {
			t.Errorf("replace accepted %q", source)
		}
	}
	for _, timeout := range []string{"bad", "-1ms"} {
		var a ip_fallback.Args
		err := utils.WeakDecode(map[string]any{"timeout": timeout}, &a)
		if err == nil {
			_, err = ip_fallback.Init(bp, &a)
		}
		if err == nil {
			t.Errorf("invalid timeout %q accepted", timeout)
		}
	}
}

func TestDynamicIPCacheRefreshPreservesRecursionGuard(t *testing.T) {
	for _, mode := range []string{"lazy", "prefetch"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				args := &cache.Args{Size: 16, Scope: "sequence"}
				ttl := uint32(1)
				if mode == "lazy" {
					args.LazyCacheTTL = 30
				} else {
					ttl = 5
					args.Prefetch = true
					args.PrefetchBeforeExpire = 4
					args.PrefetchMinHits = 1
					args.PrefetchScanInterval = 1
				}
				var fb *ip_fallback.Fallback
				var rp *ip_replace.Replacer
				var calls atomic.Int32
				bp, _ := dynamicSourceCache(t, sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
					calls.Add(1)
					if !query_policy.AddressTargetLookup(ctx) {
						t.Error("cache refresh lost recursion guard")
						return errors.New("missing guard")
					}
					dynamicResponse(q, ttl, "", "203.0.113.9")
					s := q.SnapshotResponse()
					s.ProbeStatus = query_context.ProbeFailed
					q.CommitResponse(s)
					if err := fb.Exec(ctx, q); err != nil {
						return err
					}
					return rp.Exec(ctx, q)
				}), args)
				fb = dynamicFallback(t, bp, ip_fallback.Args{IPSource: "target_resolve", On: []string{"no_rtt", "nodata"}, IPv4: []string{"domain:target.example"}})
				rp = dynamicReplacer(t, bp, ip_replace.Args{IPSource: "target_resolve", ReplaceMap: []ip_replace.Rule{{MatchIP: []string{"0.0.0.0/0"}, IPv4: []string{"domain:target.example"}}}})
				lookup := func() {
					q := query_context.NewContext(new(dns.Msg).SetQuestion("user.example.", dns.TypeA))
					dynamicResponse(q, 300, "")
					if err := fb.Exec(context.Background(), q); err != nil {
						t.Fatal(err)
					}
					if !slices.Equal(dynamicIPs(q), []string{"203.0.113.9"}) {
						t.Fatal(q.R())
					}
				}
				lookup()
				lookup()
				if calls.Load() != 1 {
					t.Fatal("source not cached")
				}
				if mode == "lazy" {
					time.Sleep(1200 * time.Millisecond)
					lookup()
				} else {
					time.Sleep(2 * time.Second)
				}
				synctest.Wait()
				if calls.Load() != 2 {
					t.Fatalf("refresh calls=%d, want 2", calls.Load())
				}
			})
		})
	}
}

func TestDynamicIPDuplicateContributorsAndPrefixMapping(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bp, _ := dynamicSource(t, sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
					ips := []string{"203.0.113.9"}
					if extra {
						ips = append(ips, "198.51.100.9")
					}
					dynamicResponse(q, 0, "", ips...)
					return nil
				}), false)
				prefix := 24
				rp := dynamicReplacer(t, bp, ip_replace.Args{IPSource: "target_resolve", ReplaceMap: []ip_replace.Rule{{MatchIP: []string{"192.0.2.0/24"}, IPv4PrefixLen: &prefix, IPv4: []string{"203.0.113.99", "domain:target.example"}}}})
				fb := dynamicFallback(t, bp, ip_fallback.Args{IPSource: "target_resolve", On: []string{"no_rtt"}, IPv4: []string{"203.0.113.9", "domain:target.example"}})
				for _, plugin := range []sequence.Executable{rp, fb} {
					q := query_context.NewContext(new(dns.Msg).SetQuestion("user.example.", dns.TypeA))
					dynamicResponse(q, 300, "", "192.0.2.42", "192.0.2.43")
					s := q.SnapshotResponse()
					s.ProbeStatus = query_context.ProbeFailed
					q.CommitResponse(s)
					if err := plugin.Exec(context.Background(), q); err != nil {
						t.Fatal(err)
					}
					want := []string{"203.0.113.42"}
					wantTTL := uint32(300)
					if plugin == fb {
						want = []string{"203.0.113.9"}
						wantTTL = 86400
					}
					if extra {
						wantTTL = 0
						if plugin == fb {
							want = append(want, "198.51.100.9")
						} else {
							want = append(want, "198.51.100.42")
						}
					}
					if !slices.Equal(dynamicIPs(q), want) || q.R().Answer[0].Header().Ttl != wantTTL {
						t.Fatalf("duplicate provenance/prefix: %v", q.R())
					}
				}
			})
		})
	}
}

func TestDynamicIPFractionalLeaseSurvivesRewriteAndProbe(t *testing.T) {
	for _, kind := range []string{"fallback", "replace"} {
		for _, tc := range []struct {
			name     string
			ttl      uint32
			probe    time.Duration
			succeeds bool
		}{
			{"fractional", 1, 100 * time.Millisecond, true},
			{"expires during probe", 1, 700 * time.Millisecond, false},
			{"native zero", 0, 700 * time.Millisecond, true},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					bp, _ := dynamicSource(t, sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
						dynamicResponse(q, tc.ttl, "", "203.0.113.9")
						time.Sleep(600 * time.Millisecond)
						return nil
					}), false)
					var rewrite sequence.Executable
					if kind == "fallback" {
						rewrite = dynamicFallback(t, bp, ip_fallback.Args{IPSource: "target_resolve", Timeout: time.Second, IPv4: []string{"domain:target.example"}})
					} else {
						rewrite = dynamicReplacer(t, bp, ip_replace.Args{IPSource: "target_resolve", Timeout: time.Second, ReplaceMap: []ip_replace.Rule{{MatchIP: []string{"192.0.2.0/24"}, IPv4: []string{"domain:target.example"}}}})
					}
					var probes atomic.Int32
					s, err := speedcheck.New(speedcheck.Args{Mode: speedcheck.ModeWaitAll}, []speedcheck.Source{{Tag: "rewritten", Exec: sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
						dynamicResponse(q, 300, "", "192.0.2.1")
						snapshot := q.SnapshotResponse()
						snapshot.ProbeStatus = query_context.ProbeFailed
						q.CommitResponse(snapshot)
						return rewrite.Exec(ctx, q)
					})}}, speedcheck.Options{Probe: func(ctx context.Context, ip netip.Addr, c speedtest.Config) speedtest.Result {
						probes.Add(1)
						if ip.String() != "203.0.113.9" {
							t.Error("probed original address")
						}
						time.Sleep(tc.probe)
						return speedtest.Result{Outcome: speedtest.Success, RTT: tc.probe}
					}})
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					q := query_context.NewContext(new(dns.Msg).SetQuestion("user.example.", dns.TypeA))
					err = s.Exec(context.Background(), q)
					if tc.succeeds {
						if err != nil || q.R() == nil || q.R().Answer[0].Header().Ttl != 0 {
							t.Fatalf("fractional/zero lease: %v %v", q.R(), err)
						}
					} else if !errors.Is(err, speedcheck.ErrNoCandidates) {
						t.Fatalf("expired candidate revived: %v %v", q.R(), err)
					}
					if probes.Load() != 1 {
						t.Fatalf("probe count=%d", probes.Load())
					}
				})
			})
		}
	}
}

func TestDynamicIPExampleDNSRoundTrip(t *testing.T) {
	v := viper.New()
	v.SetConfigFile("examples/dynamic-ip-targets.yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg coremain.Config
	if err := v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) { c.TagName = "yaml" }); err != nil {
		t.Fatal(err)
	}
	cfg.Log.Level = "error"
	var plugins []coremain.PluginConfig
	for _, p := range cfg.Plugins {
		if p.Type != "udp_server" && p.Type != "tcp_server" {
			plugins = append(plugins, p)
		}
	}
	cfg.Plugins = plugins
	m, err := coremain.NewMosdns(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.CloseWithErr(nil)
		if err := m.GetSafeClose().WaitClosed(); err != nil {
			t.Error(err)
		}
	})
	h, err := server_utils.NewHandler(coremain.NewBP("roundtrip", m), "main")
	if err != nil {
		t.Fatal(err)
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = u.Close()
		t.Fatal(err)
	}
	ud, td := make(chan struct{}), make(chan struct{})
	go func() { defer close(ud); _ = server.ServeUDP(u, h, server.UDPServerOpts{}) }()
	go func() { defer close(td); _ = server.ServeTCP(tcp, h, server.TCPServerOpts{}) }()
	t.Cleanup(func() { _ = u.Close(); _ = tcp.Close(); <-ud; <-td })
	for _, transport := range []struct{ network, addr string }{{"udp", u.LocalAddr().String()}, {"tcp", tcp.Addr().String()}} {
		for _, name := range []string{"fallback", "nodata", "replace"} {
			for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
				msg := new(dns.Msg).SetQuestion(name+".dynamic-ip.invalid.", typ)
				msg.SetEdns0(1232, false)
				r, _, err := (&dns.Client{Net: transport.network, Timeout: 2 * time.Second}).Exchange(msg, transport.addr)
				if err != nil {
					t.Fatal(err)
				}
				want := []string{"203.0.113.42", "198.51.100.42"}
				if typ == dns.TypeAAAA {
					want = []string{"2001:db8:ffff::42"}
					if name == "replace" {
						want = []string{"2001:db8:100::42"}
					}
				}
				q := query_context.NewContext(msg.Copy())
				q.SetResponse(r.Copy())
				if r.Id != msg.Id || r.Rcode != dns.RcodeSuccess || !slices.Equal(r.Question, msg.Question) || !slices.Equal(dynamicIPs(q), want) || r.IsEdns0() == nil {
					t.Fatalf("%s/%s/%d: %v", transport.network, name, typ, r)
				}
				for _, rr := range r.Answer {
					if rr.Header().Name != msg.Question[0].Name || rr.Header().Ttl > 30 {
						t.Fatalf("owner/target lifetime: %v", r)
					}
				}
			}
		}
	}
	if stats := m.ProbeManager().Stats(); stats.Probes != 0 || stats.Active != 0 {
		t.Fatalf("offline example probed: %+v", stats)
	}
}
