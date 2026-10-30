package stats_api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
)

func legacyFixture(t *testing.T, name, payload string) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Name = name
	if _, err := w.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func newCompatibilityStats(t *testing.T, args *Args) *StatsAPI {
	t.Helper()
	s := NewStatsAPI(args, nil)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func compatibilityQuery(name string) *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	return query_context.NewContext(q)
}

func compatibilityChain(f sequence.ExecutableFunc) sequence.ChainWalker {
	return sequence.NewChainWalker([]*sequence.ChainNode{{E: f}}, nil)
}

func compatibilityAnswer(_ context.Context, q *query_context.Context) error {
	r := new(dns.Msg)
	r.SetReply(q.Q())
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: []byte{192, 0, 2, 9}}}
	q.SetResponse(r)
	return nil
}

func recordCompatibilityAnswer(t *testing.T, s *StatsAPI, name string) {
	t.Helper()
	if err := s.Exec(context.Background(), compatibilityQuery(name), compatibilityChain(compatibilityAnswer)); err != nil {
		t.Fatal(err)
	}
}

func TestHistoricalV1DumpWithoutLaterOptionalFields(t *testing.T) {
	// This literal is the v1 schema from patch219, before hosts/arbitrary and
	// timeout/latency_queries were added. Do not generate it using writeDump.
	const historical = `{"version":1,"timestamp":1700000000,"total_queries":5,"blocked_queries":1,"cached_queries":2,"total_latency_us":25000,"top_domains":{"last.example.":4},"top_clients":{"192.0.2.1":5},"top_blocked":{"blocked.example.":1},"logs":[{"id":"1700000000-1","timestamp":"2023-11-14T22:13:20Z","client_ip":"192.0.2.1","domain":"first.example.","qtype":"A","status":"NOERROR","is_blocked":false,"is_cached":false,"elapsed_ms":5,"answers":[]},{"id":"1700000000-2","timestamp":"2023-11-14T22:13:20Z","client_ip":"192.0.2.1","domain":"second.example.","qtype":"A","status":"NOERROR","is_blocked":false,"is_cached":true,"elapsed_ms":5,"answers":[]},{"id":"1700000000-3","timestamp":"2023-11-14T22:13:20Z","client_ip":"192.0.2.1","domain":"last.example.","qtype":"A","status":"NOERROR","is_blocked":false,"is_cached":true,"elapsed_ms":5,"answers":[]}],"seq_id":3}`
	path := filepath.Join(t.TempDir(), "stats.dump")
	if err := os.WriteFile(path, legacyFixture(t, "mosdns_stats_v1", historical), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newCompatibilityStats(t, &Args{Capacity: 2, DumpFile: path})
	total, logs := s.ringBuffer.QueryLogs(10, 0, "", "all")
	if s.totalQueries.Load() != 5 || s.blockedQueries.Load() != 1 || s.cachedQueries.Load() != 2 || s.latencyQueries.Load() != 5 || s.hostsQueries.Load() != 0 || s.timeoutQueries.Load() != 0 {
		t.Fatal("historical counters or optional-field defaults were not restored")
	}
	if total != 2 || len(logs) != 2 || logs[0].Domain != "last.example." || logs[1].Domain != "second.example." || logs[0].ID != "1700000000-3" {
		t.Fatalf("smaller capacity changed historical log order or IDs: %+v", logs)
	}
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil))
	var response map[string]float64
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || response["cached_percentage"] != 50 || response["avg_latency_ms"] != 5 || response["total_queries"] != 5 {
		t.Fatalf("historical API values changed: %s", w.Body.String())
	}
	recordCompatibilityAnswer(t, s, "after-reload.example.")
	_, logs = s.ringBuffer.QueryLogs(10, 0, "", "all")
	if logs[0].Domain != "after-reload.example." || logs[1].Domain != "last.example." || s.totalQueries.Load() != 6 {
		t.Fatalf("historical ring did not resume after import: %+v", logs)
	}
}

func TestStatsPersistencePreservesCorruptOrForeignFiles(t *testing.T) {
	valid := legacyFixture(t, "mosdns_stats_v1", `{"version":1,"total_queries":7,"total_latency_us":70}`)
	badChecksum := bytes.Clone(valid)
	badChecksum[len(badChecksum)-8] ^= 0xff
	for name, original := range map[string][]byte{
		"unknown-header":  legacyFixture(t, "unrecognized-format", `{"version":1}`),
		"unknown-version": legacyFixture(t, "mosdns_stats_v1", `{"version":2,"total_queries":7}`),
		"truncated-gzip":  valid[:len(valid)-6],
		"bad-checksum":    badChecksum,
		"trailing-json":   legacyFixture(t, "mosdns_stats_v1", `{"version":1} {"other":true}`),
		"foreign-raw":     []byte("old plugin bytes\x00\xff"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stats.dump")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			s := newCompatibilityStats(t, &Args{Capacity: 2, DumpFile: path, DumpInterval: 1})
			recordCompatibilityAnswer(t, s, "live.example.")
			if s.totalQueries.Load() != 1 {
				t.Fatal("failed import changed live statistics")
			}
			if err := s.dumpStats(); err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("old dump changed after failed load and shutdown: %v", err)
			}
		})
	}
}

func TestStatsConcurrentQueriesSnapshotsAndDNSIdentity(t *testing.T) {
	const writers, each = 8, 50
	s := newCompatibilityStats(t, &Args{Capacity: 19})
	api := s.Router()
	var wg sync.WaitGroup
	problems := make(chan error, writers+1)
	done, readerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			for _, path := range []string{"/api/v1/stats", "/api/v1/logs?limit=7", "/api/v1/dump"} {
				w := httptest.NewRecorder()
				api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				if w.Code != http.StatusOK {
					problems <- fmt.Errorf("%s status %d", path, w.Code)
					return
				}
				if path == "/api/v1/dump" {
					gr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
					if err != nil {
						problems <- err
						return
					}
					var d StatsDumpData
					err = json.NewDecoder(gr).Decode(&d)
					_ = gr.Close()
					if err != nil || d.TotalQueries != d.LatencyQueries || len(d.Logs) != min(int(d.TotalQueries), 19) {
						problems <- fmt.Errorf("inconsistent concurrent dump: total=%d latency=%d logs=%d (%v)", d.TotalQueries, d.LatencyQueries, len(d.Logs), err)
						return
					}
				}
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range each {
				q := compatibilityQuery(fmt.Sprintf("q-%d-%d.example.", i, j))
				before := q.Q().String()
				var returned *dns.Msg
				var responseBefore string
				err := s.Exec(context.Background(), q, compatibilityChain(func(ctx context.Context, q *query_context.Context) error {
					_ = compatibilityAnswer(ctx, q)
					returned, responseBefore = q.R(), q.R().String()
					return nil
				}))
				if err != nil || q.Q().String() != before || q.R() != returned || q.R().String() != responseBefore {
					problems <- errors.New("stats changed DNS execution")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	<-readerDone
	close(problems)
	for err := range problems {
		t.Error(err)
	}
	if total, logs := s.ringBuffer.QueryLogs(100, 0, "", "all"); total != 19 || len(logs) != 19 || s.totalQueries.Load() != writers*each {
		t.Fatalf("lost concurrent queries: total=%d logs=%d count=%d", total, len(logs), s.totalQueries.Load())
	}
	wantErr := errors.New("specific upstream error")
	err := s.Exec(context.Background(), compatibilityQuery("error.example."), compatibilityChain(func(context.Context, *query_context.Context) error { return wantErr }))
	if err != wantErr {
		t.Fatalf("downstream error changed: %v", err)
	}
}

func TestStatsPeriodicDumpAndInflightClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "stats.dump")
	s := newCompatibilityStats(t, &Args{Capacity: 3, DumpFile: path, DumpInterval: 1})
	recordCompatibilityAnswer(t, s, "periodic.example.")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic dump was not written for a single query")
		}
		time.Sleep(10 * time.Millisecond)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	queryDone := make(chan error, 1)
	go func() {
		queryDone <- s.Exec(context.Background(), compatibilityQuery("inflight.example."), compatibilityChain(func(ctx context.Context, q *query_context.Context) error {
			close(entered)
			<-release
			return compatibilityAnswer(ctx, q)
		}))
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned before in-flight query completed")
	case <-time.After(25 * time.Millisecond):
	}
	unblock()
	if err := <-queryDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	reloaded := newCompatibilityStats(t, &Args{Capacity: 1, DumpFile: path})
	_, logs := reloaded.ringBuffer.QueryLogs(10, 0, "", "all")
	if reloaded.totalQueries.Load() != 2 || len(logs) != 1 || logs[0].Domain != "inflight.example." {
		t.Fatalf("final dump missed completed query: count=%d logs=%+v", reloaded.totalQueries.Load(), logs)
	}
	recordCompatibilityAnswer(t, s, "after-close.example.")
	if s.totalQueries.Load() != 2 {
		t.Fatal("closed collector resumed recording")
	}
}
