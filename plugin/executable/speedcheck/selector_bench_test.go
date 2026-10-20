package speedcheck

import (
	"context"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

// BenchmarkSelectorOverhead has no injected DNS/probe delays. Its ns/op and
// benchmem figures describe selector/runtime overhead, not network latency.
func BenchmarkSelectorOverhead(b *testing.B) {
	s, err := New(Args{Mode: ModeWaitAll, Probe: speedtest.Config{TCPPorts: []uint16{}}}, []Source{delayedSource("one", 0, "192.0.2.1"), delayedSource("two", 0, "192.0.2.2")}, Options{Probe: fakeProbe(0, nil, nil)})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	b.ReportAllocs()
	cpuStart, cpuOK := processCPUTime()
	b.ResetTimer()
	for b.Loop() {
		if err := s.Exec(context.Background(), queryContext(false)); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if cpuEnd, ok := processCPUTime(); ok && cpuOK && b.N > 0 {
		b.ReportMetric(float64(cpuEnd-cpuStart)/float64(time.Millisecond)/float64(b.N), "cpu_ms/op")
	}
}

// These controlled-latency benchmarks use fake probes and therefore report
// logical probe concurrency. No claim about real socket count is made.
func BenchmarkControlledLatency(b *testing.B) {
	b.Run("streaming", func(b *testing.B) { benchmarkLatency(b, false) })
	b.Run("collect_then_probe", func(b *testing.B) { benchmarkLatency(b, true) })
}

func benchmarkLatency(b *testing.B, collect bool) {
	var calls, active, peakLogical, peakGoroutines atomic.Int64
	sample := func() {
		n := int64(runtime.NumGoroutine())
		for {
			old := peakGoroutines.Load()
			if n <= old || peakGoroutines.CompareAndSwap(old, n) {
				break
			}
		}
	}
	probe := func(ctx context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
		calls.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := peakLogical.Load()
			if n <= old || peakLogical.CompareAndSwap(old, n) {
				break
			}
		}
		sample()
		if !waitDelay(ctx, 20*time.Millisecond) {
			return speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "canceled"}
		}
		return speedtest.Result{Outcome: speedtest.Success, RTT: 20 * time.Millisecond}
	}
	newSources := func() []Source {
		sources := []Source{delayedSource("fast", 10*time.Millisecond, "192.0.2.1"), delayedSource("slow", 200*time.Millisecond, "192.0.2.1")}
		for i := range sources {
			base := sources[i].Exec
			sources[i].Exec = sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error { sample(); return base.Exec(ctx, q) })
		}
		return sources
	}
	latencies := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	cpuStart, cpuOK := processCPUTime()
	b.ResetTimer()
	for b.Loop() {
		started := time.Now()
		q := queryContext(false)
		sources := newSources()
		if collect {
			// Baseline barrier: every source finishes before any probe starts.
			var wg sync.WaitGroup
			snapshots := make([]query_context.ResponseSnapshot, len(sources))
			errs := make([]error, len(sources))
			for i, source := range sources {
				wg.Add(1)
				go func(i int, source Source) {
					defer wg.Done()
					branch := q.Copy()
					errs[i] = source.Exec.Exec(context.Background(), branch)
					snapshots[i] = branch.SnapshotResponse()
				}(i, source)
			}
			wg.Wait()
			for i := range sources {
				if errs[i] != nil {
					b.Fatal(errs[i])
				}
				snapshot := snapshots[i]
				sources[i].Exec = sequence.ExecutableFunc(func(_ context.Context, branch *query_context.Context) error {
					branch.CommitResponse(snapshot)
					return nil
				})
			}
		}
		s, err := New(Args{}, sources, Options{Probe: probe})
		if err != nil {
			b.Fatal(err)
		}
		if err := s.Exec(context.Background(), q); err != nil {
			b.Fatal(err)
		}
		s.Close()
		latencies = append(latencies, time.Since(started))
	}
	b.StopTimer()
	if cpuEnd, ok := processCPUTime(); ok && cpuOK && len(latencies) > 0 {
		b.ReportMetric(float64(cpuEnd-cpuStart)/float64(time.Millisecond)/float64(len(latencies)), "cpu_ms/op")
	}
	slices.Sort(latencies)
	percentile := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		i := int(float64(len(latencies)-1) * p)
		return float64(latencies[i]) / float64(time.Millisecond)
	}
	b.ReportMetric(percentile(.50), "p50_ms")
	b.ReportMetric(percentile(.95), "p95_ms")
	b.ReportMetric(percentile(.99), "p99_ms")
	b.ReportMetric(float64(calls.Load())/float64(len(latencies)), "probe_subscriptions/op")
	b.ReportMetric(float64(peakLogical.Load()), "peak_logical_probes")
	b.ReportMetric(float64(peakGoroutines.Load()), "sampled_peak_goroutines")
}
