package integration_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	forward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const luciConfigPath = "tests/integration/testdata/luci-config.json"

func luciConfig(t *testing.T) coremain.Config {
	t.Helper()
	v := viper.New()
	v.SetConfigFile(luciConfigPath)
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg coremain.Config
	if err := v.Unmarshal(&cfg, func(c *mapstructure.DecoderConfig) {
		c.ErrorUnused = true
		c.TagName = "yaml"
		c.WeaklyTypedInput = true
	}); err != nil {
		t.Fatal(err)
	}
	if v.GetString("log.size") != "1" || len(cfg.Plugins) != 39 {
		t.Fatal("the original LuCI log size and complete plugin list must remain in the fixture")
	}
	return cfg
}

func TestLuCIConfigStrictDecode(t *testing.T) {
	cfg := luciConfig(t)
	for _, p := range cfg.Plugins {
		info, ok := coremain.GetPluginType(p.Type)
		if !ok {
			t.Fatalf("LuCI plugin type %q is unavailable", p.Type)
		}
		if err := utils.WeakDecode(p.Args, info.NewArgs()); err != nil {
			t.Fatalf("LuCI plugin %s (%s): %v", p.Tag, p.Type, err)
		}
	}
}

// This is the complete supplied JSON, including its dormant Apple/media chains.
// The wire test substitutes loopback UDP endpoints for the public resolvers;
// HTTPS/bootstrap/DoT transport behavior is covered by TestLegacyConfigRoutesAndPersistence.
// Forward fan-out, pipeline settings, plugin order and every routing rule remain intact.
func TestLuCIConfigWireCompatibility(t *testing.T) {
	cfg := luciConfig(t)
	dir := t.TempDir()
	files := map[string]string{
		"/var/mosdns/geosite_cn.txt":              "domain:cn.luci.invalid\n",
		"/var/mosdns/geoip_cn.txt":                "192.0.2.0/24\n",
		"/var/mosdns/geosite_apple.txt":           "domain:apple.luci.invalid\n",
		"/var/mosdns/geosite_geolocation-!cn.txt": "domain:foreign.luci.invalid\n",
		"/etc/mosdns/rule/whitelist.txt":          "domain:white.luci.invalid\n",
		"/etc/mosdns/rule/greylist.txt":           "domain:grey.luci.invalid\n",
		"/etc/mosdns/rule/ddnslist.txt":           "domain:ddns.luci.invalid\n",
		"/etc/mosdns/rule/local-ptr.txt":          "full:1.0.0.127.in-addr.arpa\n",
		"/var/mosdns/geosite_disney.txt":          "domain:disney.luci.invalid\n",
		"/var/mosdns/geosite_netflix.txt":         "domain:netflix.luci.invalid\n",
		"/var/mosdns/geosite_hulu.txt":            "domain:hulu.luci.invalid\n",
		"/etc/mosdns/rule/streaming.txt":          "domain:media.luci.invalid\n",
		"/etc/mosdns/rule/cloudflare-cidr.txt":    "198.51.100.0/24\n",
		"/etc/mosdns/rule/hosts.txt":              "hosts-udp.luci.invalid 192.0.2.123 2001:db8::123\nhosts-tcp.luci.invalid 192.0.2.123 2001:db8::123\n",
		"/etc/mosdns/rule/redirect.txt":           "redirect-udp.luci.invalid target-udp.cn.luci.invalid\nredirect-tcp.luci.invalid target-tcp.cn.luci.invalid\n",
		"/etc/mosdns/rule/blocklist.txt":          "! LuCI user blocklist\nplain-block.luci.invalid\n||abp-block.luci.invalid^\n0.0.0.0 hosts-block-udp.luci.invalid hosts-block-tcp.luci.invalid # shared hosts line\n||block.luci.invalid^\n@@||allow.block.luci.invalid^\n",
		"/var/mosdns/disable-ads.txt":             "# downloaded ad list\nplain-ad.luci.invalid\n||abp-ad.luci.invalid^\n127.0.0.1 hosts-ad-udp.luci.invalid hosts-ad-tcp.luci.invalid\n||ads.luci.invalid^\n@@||allow.ads.luci.invalid^\n",
	}
	paths := make(map[string]string, len(files))
	for old, content := range files {
		path := filepath.Join(dir, filepath.Base(old))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[old] = path
	}
	var countsMu sync.Mutex
	counts := make(map[string]int)
	count := func(sources []string, name string, qtype uint16) int {
		countsMu.Lock()
		defer countsMu.Unlock()
		var n int
		for _, source := range sources {
			n += counts[fmt.Sprintf("%s/%s/%d", source, name, qtype)]
		}
		return n
	}
	standbyRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseStandby := func() { releaseOnce.Do(func() { close(standbyRelease) }) }
	sources := []string{"local1", "local2", "remote", "stream", "xinfeng1", "xinfeng2"}
	upstreams := make(map[string]string, len(sources))
	for _, source := range sources {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		upstreams[source] = pc.LocalAddr().String()
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			question := q.Question[0]
			countsMu.Lock()
			counts[fmt.Sprintf("%s/%s/%d", source, question.Name, question.Qtype)]++
			countsMu.Unlock()
			if source == "remote" && strings.HasPrefix(question.Name, "primary-") {
				<-standbyRelease
			}
			r := new(dns.Msg).SetReply(q)
			var data string
			switch question.Qtype {
			case dns.TypeA:
				data = "198.51.100.10"
				if source == "remote" {
					data = "203.0.113.20"
				} else if source == "stream" {
					data = "198.51.100.60"
				} else if strings.HasPrefix(source, "xinfeng") {
					data = "192.0.2.60"
				} else if strings.Contains(question.Name, ".cn.luci.invalid.") || strings.Contains(question.Name, ".white.luci.invalid.") || strings.Contains(question.Name, ".ddns.luci.invalid.") || strings.HasPrefix(question.Name, "primary-") {
					data = "192.0.2.10"
				}
			case dns.TypeAAAA:
				data = "2001:db8::10"
			case dns.TypeTXT:
				data = `"fixture"`
			}
			if data != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s 120 IN %s %s", question.Name, dns.TypeToString[question.Qtype], data))
				if err != nil {
					panic(err)
				}
				r.Answer = []dns.RR{rr}
			}
			_ = w.WriteMsg(r)
		})}
		startLegacyDNSServer(t, srv)
	}
	cfg.API.HTTP = smartdnsWireFreeAddress(t, "tcp")
	cfg.Log.File = filepath.Join(dir, "mosdns.log")
	addresses := map[string]string{"udp": smartdnsWireFreeAddress(t, "udp"), "tcp": smartdnsWireFreeAddress(t, "tcp")}
	for i, p := range cfg.Plugins {
		if p.Type == "forward" {
			var args forward.Args
			if err := utils.WeakDecode(p.Args, &args); err != nil {
				t.Fatal(err)
			}
			var endpoints []string
			switch p.Tag {
			case "forward_local":
				endpoints = []string{upstreams["local1"], upstreams["local2"]}
			case "forward_remote":
				endpoints = []string{upstreams["remote"]}
			case "forward_stream_media":
				endpoints = []string{upstreams["stream"]}
			case "forward_xinfeng_udp":
				endpoints = []string{upstreams["xinfeng1"], upstreams["xinfeng2"]}
			default:
				t.Fatalf("unexpected forward tag %s", p.Tag)
			}
			if args.Concurrent != 2 || len(endpoints) != len(args.Upstreams) {
				t.Fatalf("the supplied upstream fan-out must remain unchanged: %s", p.Tag)
			}
			for j := range args.Upstreams {
				args.Upstreams[j].Addr = endpoints[j]
			}
			cfg.Plugins[i].Args = &args
			continue
		}
		args, ok := p.Args.(map[string]any)
		if !ok {
			continue
		}
		if raw, ok := args["files"]; ok {
			var originals []string
			if err := utils.WeakDecode(raw, &originals); err != nil {
				t.Fatal(err)
			}
			localFiles := make([]string, len(originals))
			for j, old := range originals {
				path, ok := paths[old]
				if !ok {
					t.Fatalf("no loopback fixture for %s", old)
				}
				localFiles[j] = path
			}
			args["files"] = localFiles
		}
		switch p.Type {
		case "udp_server":
			args["listen"] = addresses["udp"]
		case "tcp_server":
			args["listen"] = addresses["tcp"]
		}
	}
	m, err := coremain.NewMosdns(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	var closeOnce sync.Once
	stop := func() { closeOnce.Do(func() { closeLegacyMosdns(t, m) }) }
	t.Cleanup(stop)
	t.Cleanup(releaseStandby)
	m.Logger().Error("LuCI fixture log-file lifecycle probe")
	var queries, blocked, cacheHits, hosts uint64
	exchange := func(t *testing.T, network, name string, qtype uint16, rcode int, ip string, ttl uint32) *dns.Msg {
		t.Helper()
		q := new(dns.Msg).SetQuestion(name, qtype)
		r, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(q, addresses[network])
		if err != nil {
			t.Fatal(err)
		}
		queries++
		if !r.Response || r.Id != q.Id || len(r.Question) != 1 || r.Question[0] != q.Question[0] || r.Rcode != rcode || r.Truncated {
			t.Fatalf("invalid %s %s %s response: %v", network, name, dns.TypeToString[qtype], r)
		}
		if ip == "" {
			if len(r.Answer) != 0 {
				t.Fatalf("expected an empty answer for %s: %v", name, r)
			}
			return r
		}
		if len(r.Answer) != 1 || r.Answer[0].Header().Name != name {
			t.Fatalf("expected one answer for %s: %v", name, r)
		}
		var got string
		switch rr := r.Answer[0].(type) {
		case *dns.A:
			got = rr.A.String()
		case *dns.AAAA:
			got = rr.AAAA.String()
		}
		if got != ip || (ttl != 0 && r.Answer[0].Header().Ttl != ttl) {
			t.Fatalf("%s %s: want %s TTL %d, got %v", network, name, ip, ttl, r.Answer)
		}
		return r
	}
	localSources := []string{"local1", "local2"}
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			for _, route := range []struct {
				name string
				ip   string
				src  []string
			}{{network + ".cn.luci.invalid.", "192.0.2.10", localSources}, {network + ".foreign.luci.invalid.", "203.0.113.20", []string{"remote"}}} {
				exchange(t, network, route.name, dns.TypeA, dns.RcodeSuccess, route.ip, 120)
				legacyEventually(t, func() bool { return count(route.src, route.name, dns.TypeA) >= 2 }, func() string {
					return "concurrent: 2 did not send both configured requests for " + route.name
				})
				exchange(t, network, route.name, dns.TypeA, dns.RcodeSuccess, route.ip, 0)
				cacheHits++
				if n := count(route.src, route.name, dns.TypeA); n != 2 {
					t.Fatalf("cache hit or original fan-out changed for %s: upstream requests=%d", route.name, n)
				}
			}
			exchange(t, network, network+".white.luci.invalid.", dns.TypeA, dns.RcodeSuccess, "192.0.2.10", 120)
			exchange(t, network, network+".grey.luci.invalid.", dns.TypeA, dns.RcodeSuccess, "203.0.113.20", 120)
			ddns := network + ".ddns.luci.invalid."
			for want := 2; want <= 4; want += 2 {
				exchange(t, network, ddns, dns.TypeA, dns.RcodeSuccess, "192.0.2.10", 5)
				legacyEventually(t, func() bool { return count(localSources, ddns, dns.TypeA) >= want }, func() string {
					return "DDNS must bypass the cache and query both local upstreams"
				})
			}
			exchange(t, network, "primary-"+network+".luci.invalid.", dns.TypeA, dns.RcodeSuccess, "192.0.2.10", 120)
			exchange(t, network, "drop-"+network+".luci.invalid.", dns.TypeA, dns.RcodeSuccess, "203.0.113.20", 120)
			for _, question := range []struct {
				typ uint16
				ip  string
			}{{dns.TypeA, "192.0.2.123"}, {dns.TypeAAAA, "2001:db8::123"}} {
				exchange(t, network, "hosts-"+network+".luci.invalid.", question.typ, dns.RcodeSuccess, question.ip, 10)
				hosts++
			}
			redirectName := "redirect-" + network + ".luci.invalid."
			q := new(dns.Msg).SetQuestion(redirectName, dns.TypeA)
			r, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(q, addresses[network])
			if err != nil {
				t.Fatal(err)
			}
			queries++
			if r.Id != q.Id || r.Rcode != dns.RcodeSuccess || len(r.Question) != 1 || r.Question[0] != q.Question[0] || len(r.Answer) != 2 {
				t.Fatalf("redirect changed the DNS response identity: %v", r)
			}
			alias, ok := r.Answer[0].(*dns.CNAME)
			if !ok || alias.Hdr.Name != redirectName || alias.Target != "target-"+network+".cn.luci.invalid." || alias.Hdr.Ttl != 1 {
				t.Fatalf("redirect CNAME semantics changed: %v", r)
			}
			if a, ok := r.Answer[1].(*dns.A); !ok || a.A.String() != "192.0.2.10" {
				t.Fatalf("redirect did not use the domestic target: %v", r)
			}
			for _, name := range []string{network + ".allow.block.luci.invalid.", network + ".allow.ads.luci.invalid."} {
				exchange(t, network, name, dns.TypeA, dns.RcodeSuccess, "203.0.113.20", 120)
			}
			for _, name := range []string{
				network + ".abp-block.luci.invalid.", network + ".plain-block.luci.invalid.", "hosts-block-" + network + ".luci.invalid.",
				network + ".abp-ad.luci.invalid.", network + ".plain-ad.luci.invalid.", "hosts-ad-" + network + ".luci.invalid.",
			} {
				for _, question := range []struct {
					typ   uint16
					ip    string
					rcode int
				}{{dns.TypeA, "0.0.0.0", dns.RcodeSuccess}, {dns.TypeAAAA, "::", dns.RcodeSuccess}, {dns.TypeTXT, "", dns.RcodeNameError}} {
					exchange(t, network, name, question.typ, question.rcode, question.ip, 3600)
					blocked++
					if n := count(sources, name, question.typ); n != 0 {
						t.Fatalf("blocked domain reached an upstream: %s %s requests=%d", name, dns.TypeToString[question.typ], n)
					}
				}
			}
			exchange(t, network, network+".https.luci.invalid.", dns.TypeHTTPS, dns.RcodeNameError, "", 0)
			exchange(t, network, "1.0.0.127.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError, "", 0)
			blocked++
			// Neither special chain is called by the supplied main_sequence.
			for _, name := range []string{network + ".apple.luci.invalid.", network + ".media.luci.invalid."} {
				exchange(t, network, name, dns.TypeA, dns.RcodeSuccess, "203.0.113.20", 120)
				if n := count([]string{"stream", "xinfeng1", "xinfeng2"}, name, dns.TypeA); n != 0 {
					t.Fatalf("the dormant Apple/media route became active: %s requests=%d", name, n)
				}
			}
		})
	}
	releaseStandby()
	if queries != 74 || cacheHits != 4 || blocked != 38 || hosts != 4 {
		t.Fatalf("wire test coverage changed: queries=%d cache=%d blocked=%d hosts=%d", queries, cacheHits, blocked, hosts)
	}
	luciCheckStats(t, cfg.API.HTTP, queries, cacheHits, blocked, hosts)
	metric := httptest.NewRecorder()
	m.GetAPIRouter().ServeHTTP(metric, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metric.Code != http.StatusOK || !strings.Contains(metric.Body.String(), "mosdns_cache_hit_total{tag=\"lazy_cache\"} 4\n") {
		t.Fatalf("the LuCI response cache did not preserve the four wire hits: %s", metric.Body.String())
	}
	stop()
	data, err := os.ReadFile(cfg.Log.File)
	if err != nil || !strings.Contains(string(data), "LuCI fixture log-file lifecycle probe") {
		t.Fatalf("the configured rotating log did not write the probe: %v", err)
	}
	if err := os.Rename(cfg.Log.File, cfg.Log.File+".closed"); err != nil {
		t.Fatalf("the configured rotating log file was not released on shutdown: %v", err)
	}
}

func luciCheckStats(t *testing.T, addr string, total, cached, blocked, hosts uint64) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	var lastErr error
	legacyEventually(t, func() bool {
		resp, err := client.Get("http://" + addr + "/plugins/stats_collector/api/v1/stats")
		if err != nil {
			lastErr = err
			return false
		}
		defer resp.Body.Close()
		var stats struct {
			TotalQueries   uint64 `json:"total_queries"`
			CachedQueries  uint64 `json:"cached_queries"`
			BlockedQueries uint64 `json:"blocked_queries"`
			HostsQueries   uint64 `json:"hosts_queries"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
			lastErr = err
			return false
		}
		lastErr = fmt.Errorf("status=%d stats=%+v, want total=%d cached=%d blocked=%d hosts=%d", resp.StatusCode, stats, total, cached, blocked, hosts)
		return resp.StatusCode == http.StatusOK && stats.TotalQueries == total && stats.CachedQueries == cached && stats.BlockedQueries == blocked && stats.HostsQueries == hosts
	}, func() string { return fmt.Sprintf("LuCI full-chain statistics mismatch: %v", lastErr) })
}
