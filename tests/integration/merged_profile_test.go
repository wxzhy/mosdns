package integration_test

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/stats_api"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func mergedProfileConfig(t *testing.T, path string) coremain.Config {
	t.Helper()
	cfg := smartdnsMigrationConfig(t, path)
	if cfg.Log.Level != "info" || cfg.Log.File != "/var/log/mosdns.log" || cfg.API.HTTP != "127.0.0.1:9091" || len(cfg.Include) != 0 {
		t.Fatalf("shared logging/API basics were not merged: log=%+v api=%+v include=%v", cfg.Log, cfg.API, cfg.Include)
	}
	if len(cfg.Plugins) == 0 || cfg.Plugins[0].Tag != "stats_collector" || cfg.Plugins[0].Type != "stats_api" {
		t.Fatal("the statistics collector must precede every caller")
	}
	suffix := ""
	if strings.Contains(path, "cernet") {
		suffix = "-cernet"
	}
	var seenStats, seenCache, seenMain, seenAux bool
	for _, p := range cfg.Plugins {
		switch p.Tag {
		case "stats_collector":
			a := smartdnsMigrationArgs(t, p).(*stats_api.Args)
			if seenStats || a.Capacity != 2000 || a.DumpInterval != 600 || a.DumpFile != "/etc/mosdns/stats"+suffix+".dump" {
				t.Fatalf("statistics defaults or profile isolation changed: %+v", a)
			}
			seenStats = true
		case "response_cache":
			a := smartdnsMigrationArgs(t, p).(*cache.Args)
			if seenCache || a.Size != 20000 || a.LazyCacheTTL != 86400 || a.DumpInterval != 600 || a.DumpFile != "/etc/mosdns/cache"+suffix+".dump" {
				t.Fatalf("existing response cache was not reused with the shared defaults: %+v", a)
			}
			seenCache = true
		case "main":
			rules := *smartdnsMigrationArgs(t, p).(*sequence.Args)
			if len(rules) < 2 || rules[0].Exec != "$stats_collector" || rules[1].Exec != "$response_cache" {
				t.Fatal("main must wrap the response cache with statistics")
			}
			seenMain = true
		case "resolve_cached":
			rules := *smartdnsMigrationArgs(t, p).(*sequence.Args)
			if len(rules) == 0 || rules[0].Exec != "$response_cache" {
				t.Fatal("the auxiliary resolver must retain the shared response cache")
			}
			for _, rule := range rules {
				if rule.Exec == "$stats_collector" {
					t.Fatal("auxiliary DNS work must not count as another client query")
				}
			}
			seenAux = true
		}
	}
	if !seenStats || !seenCache || !seenMain || !seenAux {
		t.Fatal("the merged profile is missing a required entry")
	}
	return cfg
}

func mergedProfileStats(t *testing.T, f *smartdnsPolicyFixture, total, cached uint64) {
	t.Helper()
	collector, ok := f.plugins["stats_collector"].(*stats_api.StatsAPI)
	if !ok {
		t.Fatal("the full policy graph did not initialize its statistics collector")
	}
	w := httptest.NewRecorder()
	collector.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil))
	var response struct {
		Total  uint64 `json:"total_queries"`
		Cached uint64 `json:"cached_queries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK {
		t.Fatalf("statistics API failed: status=%d error=%v body=%s", w.Code, err, w.Body.String())
	}
	if response.Total != total || response.Cached != cached {
		t.Fatalf("main/auxiliary accounting changed: total=%d cached=%d, want total=%d cached=%d", response.Total, response.Cached, total, cached)
	}
}

func TestMergedProfilesCountClientQueriesOnce(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := mergedProfileConfig(t, path)
			f := smartdnsPolicyInstance(t, cfg, func(tag string, query *dns.Msg) *dns.Msg {
				if tag == "ech_lookup" {
					return smartdnsPolicyECHReply(query)
				}
				if query.Question[0].Qtype == dns.TypeHTTPS {
					return smartdnsPolicyHTTPSReply(query)
				}
				return smartdnsPolicyAddressReply(query, "", "104.16.0.42")
			}, nil)
			mergedProfileStats(t, f, 0, 0)
			first, err := f.exec(t, "main", "unlisted.migration.invalid.", dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, first, err)
			coldCalls, coldProbes := f.observations()
			if len(coldCalls) == 0 || len(coldProbes) == 0 {
				t.Fatal("the original resolver/selector graph was bypassed")
			}
			mergedProfileStats(t, f, 1, 0)
			second, err := f.exec(t, "main", "unlisted.migration.invalid.", dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, second, err)
			warmCalls, warmProbes := f.observations()
			if len(warmCalls) != len(coldCalls) || len(warmProbes) != len(coldProbes) || !slices.Equal(smartdnsMigrationAnswerIPs(first), smartdnsMigrationAnswerIPs(second)) {
				t.Fatal("the main cache hit repeated policy I/O or changed the selected answer")
			}
			mergedProfileStats(t, f, 2, 1)
			for range 2 {
				aux, err := f.exec(t, "resolve_cached", "direct-auxiliary.migration.invalid.", dns.TypeA, false)
				smartdnsPolicyRequireSuccess(t, aux, err)
			}
			mergedProfileStats(t, f, 2, 1)
			headerName := "https-auxiliary.migration.invalid."
			binding, err := f.exec(t, "main", headerName, dns.TypeHTTPS, false)
			smartdnsPolicyRequireSuccess(t, binding, err)
			smartdnsPolicyAssertHTTPS(t, binding, true)
			mergedProfileStats(t, f, 3, 1)
			calls, probes := f.observations()
			foundAuxiliaryA, foundECH := false, false
			for _, call := range calls {
				foundAuxiliaryA = foundAuxiliaryA || (call.name == headerName && call.qtype == dns.TypeA)
				foundECH = foundECH || call.tag == "ech_lookup"
			}
			if !foundAuxiliaryA || !foundECH {
				t.Fatal("hintless HTTPS did not use both the auxiliary policy entry and ECH pool")
			}
			cached, err := f.exec(t, "main", headerName, dns.TypeHTTPS, false)
			smartdnsPolicyRequireSuccess(t, cached, err)
			smartdnsPolicyAssertHTTPS(t, cached, true)
			afterCalls, afterProbes := f.observations()
			if len(afterCalls) != len(calls) || len(afterProbes) != len(probes) {
				t.Fatal("cached HTTPS repeated forwarding, measurement or postprocessing lookups")
			}
			mergedProfileStats(t, f, 4, 2)
		})
	}
}

func TestMergedProfilesRestoreStatisticsAndSelectedCache(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := mergedProfileConfig(t, path)
			dumpDir := t.TempDir()
			answer := func(_ string, query *dns.Msg) *dns.Msg {
				return smartdnsPolicyAddressReply(query, "", "192.0.2.42")
			}
			first := smartdnsPolicyInstanceWithDumps(t, cfg, answer, nil, false, dumpDir)
			var selected []string
			for range 2 {
				q, err := first.exec(t, "main", "persisted.migration.invalid.", dns.TypeA, false)
				smartdnsPolicyRequireSuccess(t, q, err)
				selected = smartdnsMigrationAnswerIPs(q)
			}
			mergedProfileStats(t, first, 2, 1)
			first.close()
			for _, p := range cfg.Plugins {
				var file string
				switch a := smartdnsMigrationArgs(t, p).(type) {
				case *stats_api.Args:
					file = a.DumpFile
				case *cache.Args:
					file = a.DumpFile
				}
				if file != "" {
					local := filepath.Join(dumpDir, filepath.Base(file))
					if info, err := os.Stat(local); err != nil || info.Size() == 0 {
						t.Fatalf("merged profile dump was not written: %s: %v", local, err)
					}
				}
			}
			restarted := smartdnsPolicyInstanceWithDumps(t, cfg, answer, nil, false, dumpDir)
			mergedProfileStats(t, restarted, 2, 1)
			q, err := restarted.exec(t, "main", "persisted.migration.invalid.", dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, q, err)
			if !slices.Equal(selected, smartdnsMigrationAnswerIPs(q)) {
				t.Fatal("persisted cache changed the selected policy answer")
			}
			calls, probes := restarted.observations()
			if len(calls) != 0 || len(probes) != 0 {
				t.Fatal("restored cache repeated upstream or selector I/O")
			}
			mergedProfileStats(t, restarted, 3, 2)
		})
	}
}

func TestMergedProfilesLazyRefreshCountsOnlyClient(t *testing.T) {
	for _, path := range smartdnsMigrationConfigs {
		t.Run(path, func(t *testing.T) {
			cfg := mergedProfileConfig(t, path)
			var refresh atomic.Bool
			refreshStarted := make(chan struct{})
			releaseRefresh := make(chan struct{})
			var startedOnce, releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
			f := smartdnsPolicyInstance(t, cfg, func(_ string, query *dns.Msg) *dns.Msg {
				if refresh.Load() {
					startedOnce.Do(func() { close(refreshStarted) })
					<-releaseRefresh
					return smartdnsPolicyAddressReply(query, "", "192.0.2.42")
				}
				r := smartdnsPolicyAddressReply(query, "", "192.0.2.41")
				for _, rr := range r.Answer {
					// Selectors age the response before returning it. Under
					// -race a one-second TTL can round down to zero immediately,
					// making this a timing test instead of a lazy-cache test.
					rr.Header().Ttl = 2
				}
				return r
			}, nil)
			// Release blocked fixture upstreams before the fixture's close callback.
			t.Cleanup(release)
			name := "lazy-refresh.migration.invalid."
			first, err := f.exec(t, "main", name, dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, first, err)
			if ttl := first.R().Answer[0].Header().Ttl; !slices.Equal(smartdnsMigrationAnswerIPs(first), []string{"192.0.2.41"}) || ttl == 0 || ttl > 2 {
				t.Fatalf("cold cache entry lost its initial lifetime: %v", first.R())
			}
			coldCalls, coldProbes := f.observations()
			mergedProfileStats(t, f, 1, 0)
			refresh.Store(true)
			// Wait for this real two-second DNS TTL to expire; the 86400-second lazy retention
			// must keep its stale value available while the refresh is blocked.
			expired := time.NewTimer(2200 * time.Millisecond)
			<-expired.C
			stale, err := f.exec(t, "main", name, dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, stale, err)
			if !stale.CacheState.Hit || !stale.CacheState.LazyHit || !slices.Equal(smartdnsMigrationAnswerIPs(stale), []string{"192.0.2.41"}) || stale.R().Answer[0].Header().Ttl != 5 {
				t.Fatalf("expired entry did not serve its stale answer with TTL 5: state=%+v response=%v", stale.CacheState, stale.R())
			}
			select {
			case <-refreshStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("the stale cache hit did not start the background policy chain")
			}
			mergedProfileStats(t, f, 2, 1)
			release()
			legacyEventually(t, func() bool {
				cached := mergedProfileCachedMessage(t, f, name, dns.TypeA)
				return cached != nil && len(cached.Answer) == 1 && cached.Answer[0].(*dns.A).A.String() == "192.0.2.42"
			}, func() string { return "the completed background policy did not replace the stale cache entry" })
			refreshedCalls, refreshedProbes := f.observations()
			if len(refreshedCalls) <= len(coldCalls) || len(refreshedProbes) <= len(coldProbes) {
				t.Fatal("background refresh bypassed forwarding or selection measurements")
			}
			mergedProfileStats(t, f, 2, 1)
			fresh, err := f.exec(t, "main", name, dns.TypeA, false)
			smartdnsPolicyRequireSuccess(t, fresh, err)
			if !fresh.CacheState.Hit || fresh.CacheState.LazyHit || !slices.Equal(smartdnsMigrationAnswerIPs(fresh), []string{"192.0.2.42"}) || fresh.R().Answer[0].Header().Ttl <= 5 {
				t.Fatalf("the next client did not receive the refreshed cache entry: state=%+v response=%v", fresh.CacheState, fresh.R())
			}
			afterCalls, afterProbes := f.observations()
			if len(afterCalls) != len(refreshedCalls) || len(afterProbes) != len(refreshedProbes) {
				t.Fatal("the refreshed cache hit repeated forwarding or measurements")
			}
			mergedProfileStats(t, f, 3, 2)
		})
	}
}

// Inspect the existing cache API rather than issuing extra client queries while
// waiting for refresh completion: polling must not itself change statistics.
func mergedProfileCachedMessage(t *testing.T, f *smartdnsPolicyFixture, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c, ok := f.plugins["response_cache"].(*cache.Cache)
	if !ok {
		t.Fatal("the shared response cache is missing")
	}
	w := httptest.NewRecorder()
	c.Api().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dump", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("cache dump API failed: %d", w.Code)
	}
	r, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for {
		var header [8]byte
		if _, err := io.ReadFull(r, header[:]); err == io.EOF {
			return nil
		} else if err != nil {
			t.Fatal(err)
		}
		length := binary.BigEndian.Uint64(header[:])
		if length > 1<<20 {
			t.Fatalf("invalid cache dump block length: %d", length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			t.Fatal(err)
		}
		var block cache.CacheDumpBlock
		if err := proto.Unmarshal(payload, &block); err != nil {
			t.Fatal(err)
		}
		for _, entry := range block.GetEntries() {
			msg := new(dns.Msg)
			if err := msg.Unpack(entry.GetMsg()); err != nil {
				t.Fatal(err)
			}
			if len(msg.Question) == 1 && msg.Question[0].Name == name && msg.Question[0].Qtype == qtype {
				return msg
			}
		}
	}
}
