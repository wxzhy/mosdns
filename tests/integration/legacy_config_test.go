package integration_test

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

const legacyConfigPath = "tests/integration/testdata/legacy-config.yaml"

func legacyConfig(t *testing.T) coremain.Config {
	t.Helper()
	v := viper.New()
	v.SetConfigFile(legacyConfigPath)
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg coremain.Config
	// Match coremain.loadConfig, including strict field checking and the yaml tag.
	if err := v.Unmarshal(&cfg, func(c *mapstructure.DecoderConfig) {
		c.ErrorUnused = true
		c.TagName = "yaml"
		c.WeaklyTypedInput = true
	}); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLegacyConfigStrictDecode(t *testing.T) {
	cfg := legacyConfig(t)
	for _, p := range cfg.Plugins {
		info, ok := coremain.GetPluginType(p.Type)
		if !ok {
			t.Fatalf("historical plugin type %q is unavailable", p.Type)
		}
		if info.NewArgs != nil {
			if err := utils.WeakDecode(p.Args, info.NewArgs()); err != nil {
				t.Fatalf("historical plugin %s (%s): %v", p.Tag, p.Type, err)
			}
		}
	}
}

// Keep the supplied production fixture intact. Only paths, bind addresses and
// upstream endpoints/certificate trust change for the loopback environment.
func TestLegacyConfigRoutesAndPersistence(t *testing.T) {
	cfg := legacyConfig(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	localDomains := write("geosite_cn.txt", "domain:local.legacy.invalid\n")
	remoteDomains := write("geosite_geolocation-!cn.txt", "domain:remote.legacy.invalid\n")
	localIPs := write("geoip_cn.txt", "192.0.2.0/24\n")
	statsDump, cacheDump := filepath.Join(dir, "stats.dump"), filepath.Join(dir, "cache.dump")
	var countsMu sync.Mutex
	counts := make(map[string]int)
	count := func(source, name string, qtype uint16) int {
		countsMu.Lock()
		defer countsMu.Unlock()
		return counts[fmt.Sprintf("%s/%s/%d", source, name, qtype)]
	}
	standbyRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseStandby := func() { releaseOnce.Do(func() { close(standbyRelease) }) }
	answer := func(source string, q *dns.Msg) *dns.Msg {
		question := q.Question[0]
		countsMu.Lock()
		counts[fmt.Sprintf("%s/%s/%d", source, question.Name, question.Qtype)]++
		countsMu.Unlock()
		if source == "remote" && strings.HasPrefix(question.Name, "primary-") {
			// A successful primary must return while the standby is still pending.
			<-standbyRelease
		}
		r := new(dns.Msg).SetReply(q)
		var ip string
		switch question.Qtype {
		case dns.TypeA:
			ip = "192.0.2.10"
			if question.Name == "doh.legacy.invalid." {
				ip = "127.0.0.1"
			} else if source == "remote" {
				ip = "203.0.113.20"
			} else if strings.HasPrefix(question.Name, "drop-") {
				ip = "198.51.100.10"
			}
		case dns.TypeAAAA:
			ip = "2001:db8::10"
		}
		if ip != "" {
			rr, err := dns.NewRR(fmt.Sprintf("%s 120 IN %s %s", question.Name, dns.TypeToString[question.Qtype], ip))
			if err != nil {
				panic(err)
			}
			r.Answer = []dns.RR{rr}
		}
		return r
	}

	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	localUDP := &dns.Server{PacketConn: udpConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		_ = w.WriteMsg(answer("local_udp", q))
	})}
	startLegacyDNSServer(t, localUDP)

	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var wire []byte
		var err error
		if req.Method == http.MethodGet {
			wire, err = base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
		} else {
			wire, err = io.ReadAll(req.Body)
		}
		q := new(dns.Msg)
		if err != nil || q.Unpack(wire) != nil {
			http.Error(w, "invalid DNS query", http.StatusBadRequest)
			return
		}
		wire, err = answer("local_doh", q).Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	t.Cleanup(doh.Close)
	_, dohPort, err := net.SplitHostPort(doh.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsListener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: doh.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	remoteTLS := &dns.Server{Listener: tlsListener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		_ = w.WriteMsg(answer("remote", q))
	})}
	startLegacyDNSServer(t, remoteTLS)

	addresses := map[string]string{
		"udp": smartdnsWireFreeAddress(t, "udp"),
		"tcp": smartdnsWireFreeAddress(t, "tcp"),
	}
	cfg.API.HTTP = smartdnsWireFreeAddress(t, "tcp")
	cfg.Log.File = filepath.Join(dir, "mosdns.log")
	for i, p := range cfg.Plugins {
		if p.Type == "forward" {
			var args forward.Args
			if err := utils.WeakDecode(p.Args, &args); err != nil {
				t.Fatal(err)
			}
			if p.Tag == "forward_local" {
				args.Upstreams[0].Addr = "https://doh.legacy.invalid:" + dohPort + "/dns-query"
				args.Upstreams[0].Bootstrap = udpConn.LocalAddr().String()
				args.Upstreams[0].InsecureSkipVerify = true
				args.Upstreams[1].Addr = udpConn.LocalAddr().String()
			} else {
				args.Upstreams[0].Addr = "tls://" + tlsListener.Addr().String()
				args.Upstreams[0].InsecureSkipVerify = true
			}
			cfg.Plugins[i].Args = &args
			continue
		}
		args, ok := p.Args.(map[string]any)
		if !ok {
			continue // sequence rules remain the original decoded list.
		}
		switch p.Tag {
		case "stats_collector":
			args["dump_file"] = statsDump
		case "lazy_cache":
			args["dump_file"] = cacheDump
		case "geosite_cn":
			args["files"] = []string{localDomains}
		case "geosite_no_cn":
			args["files"] = []string{remoteDomains}
		case "geoip_cn":
			args["files"] = []string{localIPs}
		case "udp_server":
			args["listen"] = addresses["udp"]
		case "tcp_server":
			args["listen"] = addresses["tcp"]
		}
	}

	start := func() *coremain.Mosdns {
		t.Helper()
		m, err := coremain.NewMosdns(&cfg)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := start()
	var closeOnce sync.Once
	stop := func() {
		closeOnce.Do(func() { closeLegacyMosdns(t, m) })
	}
	t.Cleanup(stop)
	t.Cleanup(releaseStandby)
	queries := uint64(0)
	exchange := func(t *testing.T, network, name string, qtype uint16, expectedIP string) {
		t.Helper()
		q := new(dns.Msg).SetQuestion(name, qtype)
		r, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(q, addresses[network])
		if err != nil {
			t.Fatal(err)
		}
		queries++
		if !r.Response || r.Id != q.Id || len(r.Question) != 1 || r.Question[0] != q.Question[0] || r.Rcode != dns.RcodeSuccess || r.Truncated {
			t.Fatalf("invalid %s reply for %s: %v", network, name, r)
		}
		if expectedIP == "" {
			if len(r.Answer) != 0 {
				t.Fatalf("prefer_ipv4 must suppress remote AAAA: %v", r)
			}
			return
		}
		if len(r.Answer) != 1 || r.Answer[0].Header().Name != name {
			t.Fatalf("expected one answer for %s: %v", name, r)
		}
		var gotIP string
		switch rr := r.Answer[0].(type) {
		case *dns.A:
			gotIP = rr.A.String()
		case *dns.AAAA:
			gotIP = rr.AAAA.String()
		}
		if gotIP != expectedIP {
			t.Fatalf("%s %s: want %s, got %s", network, name, expectedIP, gotIP)
		}
	}

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			localName := network + ".local.legacy.invalid."
			exchange(t, network, localName, dns.TypeA, "192.0.2.10")
			exchange(t, network, localName, dns.TypeA, "192.0.2.10") // has_resp/accept must retain a cache hit.
			exchange(t, network, localName, dns.TypeAAAA, "2001:db8::10")
			exchange(t, network, network+".remote.legacy.invalid.", dns.TypeA, "203.0.113.20")
			exchange(t, network, "dual-"+network+".remote.legacy.invalid.", dns.TypeAAAA, "")
			exchange(t, network, "primary-"+network+".legacy.invalid.", dns.TypeA, "192.0.2.10")
			exchange(t, network, "drop-"+network+".legacy.invalid.", dns.TypeA, "203.0.113.20")
			if n := count("remote", localName, dns.TypeA); n != 0 {
				t.Fatalf("domestic domain escaped to remote upstream: %d", n)
			}
			if n := count("local_udp", network+".remote.legacy.invalid.", dns.TypeA) + count("local_doh", network+".remote.legacy.invalid.", dns.TypeA); n != 0 {
				t.Fatalf("foreign domain escaped to local upstreams: %d", n)
			}
		})
	}
	releaseStandby()
	metric := httptest.NewRecorder()
	m.GetAPIRouter().ServeHTTP(metric, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metric.Code != http.StatusOK || !strings.Contains(metric.Body.String(), "mosdns_cache_hit_total{tag=\"lazy_cache\"} 2\n") {
		t.Fatalf("historical cache did not retain both wire cache hits: %s", metric.Body.String())
	}
	legacyCheckStats(t, cfg.API.HTTP, queries, 2)
	legacyCheckLogs(t, cfg.API.HTTP, queries, 2,
		[]string{"https://doh.legacy.invalid:" + dohPort + "/dns-query", udpConn.LocalAddr().String()},
		"tls://"+tlsListener.Addr().String())
	stop()
	for _, path := range []string{statsDump, cacheDump, cfg.Log.File} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("historical persistence path %s was not written: %v", path, err)
		}
	}

	// The unchanged cache/stats dump paths must restore state on a new instance.
	m = start()
	closeOnce = sync.Once{}
	legacyCheckStats(t, cfg.API.HTTP, queries, 2)
	exchange(t, "tcp", "udp.local.legacy.invalid.", dns.TypeA, "192.0.2.10")
	legacyCheckStats(t, cfg.API.HTTP, queries, 3)
	legacyCheckLogs(t, cfg.API.HTTP, queries, 3,
		[]string{"https://doh.legacy.invalid:" + dohPort + "/dns-query", udpConn.LocalAddr().String()},
		"tls://"+tlsListener.Addr().String())
	metric = httptest.NewRecorder()
	m.GetAPIRouter().ServeHTTP(metric, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metric.Body.String(), "mosdns_cache_hit_total{tag=\"lazy_cache\"} 1\n") {
		t.Fatalf("cache.dump was not restored: %s", metric.Body.String())
	}

	// The historical statistics API must clear the actual response cache, not
	// merely acknowledge the request. Counters retain their accumulated values.
	client := &http.Client{Timeout: time.Second}
	clearResp, err := client.Post("http://"+cfg.API.HTTP+"/plugins/stats_collector/api/v1/cache/clear", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var cleared struct {
		Success bool `json:"success"`
	}
	decodeErr := json.NewDecoder(clearResp.Body).Decode(&cleared)
	_ = clearResp.Body.Close()
	if decodeErr != nil || clearResp.StatusCode != http.StatusOK || !cleared.Success {
		t.Fatalf("historical cache-clear API failed: status=%d response=%+v error=%v", clearResp.StatusCode, cleared, decodeErr)
	}
	name := "udp.local.legacy.invalid."
	before := count("local_udp", name, dns.TypeA) + count("local_doh", name, dns.TypeA)
	exchange(t, "tcp", name, dns.TypeA, "192.0.2.10")
	if after := count("local_udp", name, dns.TypeA) + count("local_doh", name, dns.TypeA); after != before+1 {
		t.Fatalf("cache clear did not cause exactly one fresh upstream query: before=%d after=%d", before, after)
	}
	legacyCheckStats(t, cfg.API.HTTP, queries, 3)
	metric = httptest.NewRecorder()
	m.GetAPIRouter().ServeHTTP(metric, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metric.Body.String(), "mosdns_cache_hit_total{tag=\"lazy_cache\"} 1\n") {
		t.Fatalf("cache clear still served the old cache entry: %s", metric.Body.String())
	}
}

func startLegacyDNSServer(t *testing.T, srv *dns.Server) {
	t.Helper()
	ready := make(chan struct{})
	done := make(chan error, 1)
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { done <- srv.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("fixture DNS server failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("fixture DNS server did not start")
	}
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func closeLegacyMosdns(t *testing.T, m *coremain.Mosdns) {
	t.Helper()
	m.CloseWithErr(nil)
	done := make(chan error, 1)
	go func() { done <- m.GetSafeClose().WaitClosed() }()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("historical configuration did not shut down within five seconds")
	}
}

func legacyCheckStats(t *testing.T, addr string, expected, expectedCached uint64) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	for _, path := range []string{"/plugins/stats_collector/api/v1/stats", "/plugins/stats_collector/stats"} {
		var lastErr error
		legacyEventually(t, func() bool {
			resp, err := client.Get("http://" + addr + path)
			if err != nil {
				lastErr = err
				return false
			}
			defer resp.Body.Close()
			var stats struct {
				TotalQueries   uint64  `json:"total_queries"`
				CachedQueries  *uint64 `json:"cached_queries"`
				BlockedQueries *uint64 `json:"blocked_queries"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
				lastErr = err
				return false
			}
			lastErr = fmt.Errorf("status=%d stats=%+v, want total=%d cached=%d blocked=0", resp.StatusCode, stats, expected, expectedCached)
			return resp.StatusCode == http.StatusOK && stats.TotalQueries == expected &&
				stats.CachedQueries != nil && *stats.CachedQueries == expectedCached &&
				stats.BlockedQueries != nil && *stats.BlockedQueries == 0
		}, func() string {
			return fmt.Sprintf("stats API %s failed to count downstream queries including cache hits (last result: %v)", path, lastErr)
		})
	}
}

func legacyCheckLogs(t *testing.T, addr string, expected, expectedCached uint64, localUpstreams []string, remoteUpstream string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	for _, prefix := range []string{"/plugins/stats_collector/api/v1", "/plugins/stats_collector"} {
		for _, filter := range []string{"all", "cached"} {
			resp, err := client.Get("http://" + addr + prefix + "/logs?limit=500&filter=" + filter)
			if err != nil {
				t.Fatal(err)
			}
			var logs struct {
				Total uint64 `json:"total"`
				Items []struct {
					Domain    string `json:"domain"`
					QType     string `json:"qtype"`
					Status    string `json:"status"`
					IsCached  bool   `json:"is_cached"`
					IsBlocked bool   `json:"is_blocked"`
					ClientIP  string `json:"client_ip"`
					Upstream  string `json:"upstream"`
					Rule      string `json:"rule"`
				} `json:"items"`
			}
			decodeErr := json.NewDecoder(resp.Body).Decode(&logs)
			_ = resp.Body.Close()
			if decodeErr != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("historical query log API %s failed: status=%d error=%v", prefix, resp.StatusCode, decodeErr)
			}
			wantTotal := expected
			if filter == "cached" {
				wantTotal = expectedCached
			}
			if logs.Total != wantTotal || uint64(len(logs.Items)) != wantTotal {
				t.Fatalf("historical query log %s/%s returned %d total/%d items, want %d", prefix, filter, logs.Total, len(logs.Items), wantTotal)
			}
			cached := uint64(0)
			for _, entry := range logs.Items {
				if entry.Status != "NOERROR" || entry.IsBlocked || entry.ClientIP != "127.0.0.1" {
					t.Fatalf("query log status/client changed: %+v", entry)
				}
				if entry.IsCached {
					cached++
					if entry.Upstream != "cache" {
						t.Fatalf("cached query lost its source: %+v", entry)
					}
					continue
				}
				if filter == "cached" {
					t.Fatalf("cached query log filter returned a non-cache entry: %+v", entry)
				}
				if strings.HasPrefix(entry.Domain, "dual-") {
					continue // prefer_ipv4 synthesizes the successful empty AAAA reply.
				}
				if entry.Rule == "" || entry.Rule == "-" || entry.Rule == "$stats_collector" {
					t.Fatalf("query log lost the executed rule: %+v", entry)
				}
				wantRemote := strings.HasSuffix(entry.Domain, ".remote.legacy.invalid.") || strings.HasPrefix(entry.Domain, "drop-")
				if wantRemote {
					if entry.Upstream != remoteUpstream {
						t.Fatalf("remote/fallback query lost selected upstream metadata: %+v", entry)
					}
				} else if entry.Upstream != localUpstreams[0] && entry.Upstream != localUpstreams[1] {
					t.Fatalf("local/fallback query lost selected upstream metadata: %+v", entry)
				}
			}
			if cached != expectedCached {
				t.Fatalf("query log %s/%s contains %d cache hits, want %d", prefix, filter, cached, expectedCached)
			}
		}
	}
}

func legacyEventually(t *testing.T, condition func() bool, message func() string) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-timer.C:
			t.Fatal(message())
		case <-ticker.C:
		}
	}
}
