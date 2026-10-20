package speedtest

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkLocalTCPProbe measures actual loopback connects separately from the
// selector's controlled, fake-latency comparison. Distinct timeout profiles
// force physical work even on platforms with a coarse monotonic clock.
func BenchmarkLocalTCPProbe(b *testing.B) {
	for _, parallel := range []bool{false, true} {
		name := "serial"
		if parallel {
			name = "parallel"
		}
		b.Run(name, func(b *testing.B) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				for {
					c, err := listener.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
			defer func() { _ = listener.Close(); <-serverDone }()
			m := NewManager(Options{CacheSize: 64})
			defer m.Close()
			var peak atomic.Int64
			realProbe := m.probe
			m.probe = func(ctx context.Context, ip netip.Addr, method probeMethod) Result {
				n := int64(m.Stats().Active)
				for old := peak.Load(); n > old; old = peak.Load() {
					if peak.CompareAndSwap(old, n) {
						break
					}
				}
				return realProbe(ctx, ip, method)
			}
			c := Config{TCPPorts: []uint16{uint16(listener.Addr().(*net.TCPAddr).Port)}, Timeout: time.Second}
			ip := netip.MustParseAddr("127.0.0.1")
			var sequence atomic.Int64
			measure := func() {
				profile := c
				profile.Timeout += time.Duration(sequence.Add(1))
				if r := m.Measure(context.Background(), ip, profile); r.Outcome != Success {
					b.Errorf("local TCP: %+v", r)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			if parallel {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						measure()
					}
				})
			} else {
				for b.Loop() {
					measure()
				}
			}
			b.StopTimer()
			stats := m.Stats()
			b.ReportMetric(float64(peak.Load()), "peak_socket_slots")
			b.ReportMetric(float64(stats.Probes)/float64(b.N), "actual_probes/op")
			b.ReportMetric(float64(stats.Shared)/float64(b.N), "shared/op")
		})
	}
}
