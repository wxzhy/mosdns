package speedcheck

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/response"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/miekg/dns"
)

// BenchmarkRefreshProbes64IPs measures admission with immutable, analyzed DNS
// candidates. Setup and completed probe states are reused; no network work runs.
func BenchmarkRefreshProbes64IPs(b *testing.B) {
	for _, sources := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("sources_%d", sources), func(b *testing.B) {
			now := time.Now()
			query := new(dns.Msg).SetQuestion("benchmark.test.", dns.TypeA)
			states := make([]*candidateState, sources)
			probes := make(map[netip.Addr]*probeState, sources*maxUniqueIPs)
			for source := range states {
				r := new(dns.Msg).SetReply(query)
				for i := range maxUniqueIPs {
					ip := netip.AddrFrom4([4]byte{192, 0, byte(source), byte(maxUniqueIPs - i)})
					r.Answer = append(r.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ^uint32(0)},
						A:   net.IP(ip.AsSlice()),
					})
					probes[ip] = &probeState{done: true, result: speedtest.Result{Outcome: speedtest.Unmeasured}}
				}
				candidate, err := response.Analyze(query, query_context.ResponseSnapshot{Response: r, ReceivedAt: now}, now)
				if err != nil {
					b.Fatal(err)
				}
				states[source] = &candidateState{source: source, readyAt: now, value: candidate}
			}
			s := new(Selector)
			ctx := context.Background()
			var admitted map[netip.Addr]bool
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				admitted = s.refreshProbes(ctx, states, probes, nil, nil, false)
			}
			b.StopTimer()
			if len(admitted) != maxUniqueIPs {
				b.Fatalf("admitted %d IPs, want %d", len(admitted), maxUniqueIPs)
			}
		})
	}
}
