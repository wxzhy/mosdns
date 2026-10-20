package speedcheck

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/arbitrary"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/ip_fallback"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence/fallback"
	"github.com/miekg/dns"
)

func TestIPFallbackUsesSelectorProbeStatus(t *testing.T) {
	for _, scenario := range []string{"all_failed", "disabled", "mixed", "pending", "zero_rtt"} {
		for _, noRTT := range []bool{false, true} {
			name := scenario + "/default"
			if noRTT {
				name = scenario + "/no_rtt"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					args := Args{Mode: ModeWaitAll}
					if scenario == "disabled" {
						args.Probe.TCPPorts = []uint16{}
					}
					if scenario == "pending" {
						args.Mode, args.SelectionTimeout = ModeBounded, 5*time.Millisecond
					}
					var calls atomic.Int64
					probe := func(ctx context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
						calls.Add(1)
						if !waitDelay(ctx, 20*time.Millisecond) {
							return speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "canceled"}
						}
						if scenario == "mixed" && ip == netip.MustParseAddr("192.0.2.2") {
							return speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "queue_full"}
						}
						if scenario == "zero_rtt" && ip == netip.MustParseAddr("192.0.2.1") {
							return speedtest.Result{Outcome: speedtest.Success, RTT: 0}
						}
						return speedtest.Result{Outcome: speedtest.Failed, Reason: "unreachable"}
					}
					selector := testSelector(t, args, []Source{delayedSource("source", 10*time.Millisecond, "192.0.2.1", "192.0.2.2")}, Options{Probe: probe})
					q := queryContext(false)
					if err := selector.Exec(context.Background(), q); err != nil {
						t.Fatal(err)
					}
					wantStatus := query_context.ProbeUnmeasured
					if scenario == "all_failed" {
						wantStatus = query_context.ProbeFailed
					} else if scenario == "zero_rtt" {
						wantStatus = query_context.ProbeSucceeded
					}
					if got := q.SnapshotResponse().ProbeStatus; got != wantStatus {
						t.Fatalf("selection status %v, want %v", got, wantStatus)
					}
					if scenario == "disabled" && calls.Load() != 0 {
						t.Fatal("disabled speedcheck launched a probe")
					}
					original := q.R()
					policy := ip_fallback.Args{IPv4: []string{"203.0.113.42"}}
					if noRTT {
						policy.On = []string{"no_rtt"}
					}
					f, err := ip_fallback.New(&policy)
					if err != nil {
						t.Fatal(err)
					}
					if err := f.Exec(context.Background(), q); err != nil {
						t.Fatal(err)
					}
					wantFallback := scenario == "all_failed" || noRTT && scenario != "zero_rtt"
					if wantFallback {
						if !slices.Equal(answerIPs(q), []string{"203.0.113.42"}) || q.SnapshotResponse().ProbeStatus != query_context.ProbeUnknown {
							t.Fatal("fallback did not use static addresses or reset probe evidence")
						}
					} else if q.R() != original {
						t.Fatal("fallback replaced an unmeasured or successful response")
					}
					synctest.Wait()
				})
			})
		}
	}
}

func TestIPFallbackAfterSelectorPreservesAliasBoundsAndDNSSEC(t *testing.T) {
	for _, do := range []bool{false, true} {
		t.Run(map[bool]string{false: "rewritable", true: "dnssec"}[do], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				source := Source{Tag: "aliased", Exec: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
					r := new(dns.Msg).SetReply(q.Q())
					r.AuthenticatedData = true
					r.Answer = []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 2}, Target: "leaf.test."},
						&dns.A{Hdr: dns.RR_Header{Name: "leaf.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")},
					}
					q.SetResponse(r)
					return nil
				})}
				selector := testSelector(t, Args{Mode: ModeWaitAll}, []Source{source}, Options{Probe: fakeProbe(20*time.Millisecond, nil, nil)})
				q := queryContext(do)
				if err := selector.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				original := q.R()
				ttl := int64(60)
				f, err := ip_fallback.New(&ip_fallback.Args{IPv4: []string{"203.0.113.42"}, TTL: &ttl})
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				if do {
					if q.R() != original || !q.R().AuthenticatedData || !slices.Equal(answerIPs(q), []string{"192.0.2.1"}) {
						t.Fatal("static fallback modified a DNSSEC response")
					}
				} else {
					if !slices.Equal(answerIPs(q), []string{"203.0.113.42"}) || len(q.R().Answer) != 2 || q.R().Answer[1].Header().Name != "leaf.test." {
						t.Fatal("fallback lost alias chain or terminal owner")
					}
					for _, rr := range q.R().Answer {
						if rr.Header().Ttl > 2 {
							t.Fatal("static fallback extended the source alias")
						}
					}
					if q.R().AuthenticatedData || q.SnapshotResponse().ValidUntil.After(time.Now().Add(2*time.Second)) {
						t.Fatal("fallback retained authentication or extended alias validity")
					}
				}
				synctest.Wait()
			})
		})
	}
}

func TestOuterFallbackPreservesProbeStatusForIPFallback(t *testing.T) {
	m, err := coremain.NewMosdns(&coremain.Config{Plugins: []coremain.PluginConfig{
		{Tag: "local", Type: arbitrary.PluginType, Args: &arbitrary.Args{Rules: []string{"example.test. 300 IN A 192.0.2.1"}}},
		{Tag: "selector", Type: PluginType, Args: &Args{Sources: []string{"local"}, Mode: ModeWaitAll, Probe: speedtest.Config{TCPPorts: []uint16{}}}},
		{Tag: "wrapped", Type: fallback.PluginType, Args: &fallback.Args{Primary: "selector", Secondary: "local", Threshold: 5000}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.CloseWithErr(nil)
		if err := m.GetSafeClose().WaitClosed(); err != nil {
			t.Error(err)
		}
	})
	q := queryContext(false)
	q.SetMark(37)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sequence.ToExecutable(m.GetPlugin("wrapped")).Exec(ctx, q); err != nil {
		t.Fatal(err)
	}
	if q.SnapshotResponse().ProbeStatus != query_context.ProbeUnmeasured || !q.HasMark(37) {
		t.Fatal("outer fallback lost selected probe evidence or copied branch state")
	}
	defaultPolicy, _ := ip_fallback.New(&ip_fallback.Args{IPv4: []string{"203.0.113.42"}})
	if err := defaultPolicy.Exec(ctx, q); err != nil || !slices.Equal(answerIPs(q), []string{"192.0.2.1"}) {
		t.Fatal("default fallback treated disabled probes as a failure", err)
	}
	explicitPolicy, _ := ip_fallback.New(&ip_fallback.Args{IPv4: []string{"203.0.113.42"}, On: []string{"no_rtt"}})
	if err := explicitPolicy.Exec(ctx, q); err != nil || !slices.Equal(answerIPs(q), []string{"203.0.113.42"}) || !q.HasMark(37) {
		t.Fatal("no_rtt did not use the status copied by outer fallback", err)
	}
	if stats := m.ProbeManager().Stats(); stats.Probes != 0 || stats.Active != 0 {
		t.Fatalf("local integration unexpectedly probed a documentation IP: %+v", stats)
	}
}
