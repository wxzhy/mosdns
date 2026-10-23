package speedcheck

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type matchIP func(netip.Addr) bool

func (f matchIP) Match(ip netip.Addr) bool { return f(ip) }
func oneIP(ip string) netlist.Matcher {
	return matchIP(func(a netip.Addr) bool { return a == netip.MustParseAddr(ip) })
}
func queryContext(do bool) *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	q.SetEdns0(1232, do)
	return query_context.NewContext(q)
}
func delayedSource(tag string, delay time.Duration, ips ...string) Source {
	return Source{Tag: tag, Exec: sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		if !waitDelay(ctx, delay) {
			return context.Cause(ctx)
		}
		r := new(dns.Msg).SetReply(q.Q())
		for _, ip := range ips {
			r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(ip)})
		}
		q.SetResponse(r)
		return nil
	})}
}
func waitDelay(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
func fakeProbe(delay time.Duration, rtts map[string]time.Duration, calls *atomic.Int64) ProbeFunc {
	return func(ctx context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
		if calls != nil {
			calls.Add(1)
		}
		if !waitDelay(ctx, delay) {
			return speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "canceled"}
		}
		if rtt, ok := rtts[ip.String()]; ok {
			return speedtest.Result{Outcome: speedtest.Success, RTT: rtt}
		}
		return speedtest.Result{Outcome: speedtest.Failed, Reason: "unreachable"}
	}
}
func testSelector(t *testing.T, args Args, sources []Source, opts Options) *Selector {
	t.Helper()
	if opts.Probe == nil {
		opts.Probe = fakeProbe(0, nil, nil)
	}
	s, err := New(args, sources, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func answerIPs(q *query_context.Context) []string {
	var out []string
	if q.R() == nil {
		return nil
	}
	for _, rr := range q.R().Answer {
		switch rr := rr.(type) {
		case *dns.A:
			out = append(out, rr.A.String())
		case *dns.AAAA:
			out = append(out, rr.AAAA.String())
		}
	}
	return out
}
func floatptr(f float64) *float64 { return &f }

func TestExpiredNODATAChainDoesNotWinNegativeSelection(t *testing.T) {
	for _, freshNegative := range []bool{false, true} {
		t.Run(fmt.Sprintf("fresh_negative=%v", freshNegative), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sources := []Source{{Tag: "expired", Exec: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
					r := new(dns.Msg).SetReply(q.Q())
					r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: "leaf.test."}}
					q.SetResponse(r)
					snapshot := q.SnapshotResponse()
					snapshot.ReceivedAt = time.Now().Add(-2 * time.Second)
					q.CommitResponse(snapshot)
					return nil
				})}}
				if freshNegative {
					sources = append(sources, Source{Tag: "fresh", Exec: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
						r := new(dns.Msg).SetReply(q.Q())
						r.Rcode = dns.RcodeNameError
						q.SetResponse(r)
						return nil
					})})
				}
				s := testSelector(t, Args{Mode: ModeWaitAll}, sources, Options{})
				q := queryContext(false)
				err := s.Exec(context.Background(), q)
				if !freshNegative {
					if !errors.Is(err, ErrNoCandidates) || q.R() != nil {
						t.Fatalf("expired NODATA was returned: response=%v err=%v", q.R(), err)
					}
				} else if err != nil || q.R() == nil || q.R().Rcode != dns.RcodeNameError || len(q.R().Answer) != 0 {
					t.Fatalf("expired source hid the fresh negative: response=%v err=%v", q.R(), err)
				}
			})
		})
	}
}

func TestExpiredPassthroughSourceDoesNotStopOtherSources(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		makeSource := func(tag string, delay time.Duration, priority uint16, expired bool) Source {
			return Source{Tag: tag, Exec: sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
				if !waitDelay(ctx, delay) {
					return context.Cause(ctx)
				}
				r := new(dns.Msg).SetReply(q.Q())
				r.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60}, Priority: priority, Target: "."}}}
				q.SetResponse(r)
				if expired {
					snapshot := q.SnapshotResponse()
					snapshot.ValidUntil = time.Now().Add(-time.Second)
					q.CommitResponse(snapshot)
				}
				return nil
			})}
		}
		s := testSelector(t, Args{Mode: ModeWaitAll}, []Source{makeSource("expired", 0, 1, true), makeSource("fresh", 20*time.Millisecond, 2, false)}, Options{})
		q := queryContext(false)
		q.Q().Question[0].Qtype = dns.TypeHTTPS
		start := time.Now()
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if len(q.R().Answer) != 1 || q.R().Answer[0].(*dns.HTTPS).Priority != 2 || time.Since(start) != 20*time.Millisecond {
			t.Fatalf("expired passthrough ended selection early: response=%v elapsed=%v", q.R(), time.Since(start))
		}
	})
}

func TestExpiredAddressesReleaseCandidateBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		oldIPs := make([]string, maxUniqueIPs)
		for i := range oldIPs {
			oldIPs[i] = fmt.Sprintf("192.0.2.%d", i+1)
		}
		old := delayedSource("old", 0, oldIPs...)
		base := old.Exec
		old.Exec = sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
			if err := base.Exec(ctx, q); err != nil {
				return err
			}
			for _, rr := range q.R().Answer {
				rr.Header().Ttl = 1
			}
			return nil
		})
		var calls atomic.Int64
		s := testSelector(t, Args{Mode: ModeWaitAll}, []Source{old, delayedSource("fresh", 1100*time.Millisecond, "198.51.100.1")}, Options{Probe: fakeProbe(time.Millisecond, nil, &calls)})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(answerIPs(q), []string{"198.51.100.1"}) || q.SnapshotResponse().ProbeStatus != query_context.ProbeUnmeasured {
			t.Fatalf("expired addresses occupied the candidate budget: %v", q.R())
		}
		if calls.Load() != maxUniqueIPs {
			t.Fatalf("probe budget changed: %d", calls.Load())
		}
	})
}

func TestStreamingOverlapsDNSAndProbe(t *testing.T) {
	for _, mode := range []string{ModeBounded, ModeWaitAll} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int64
				s := testSelector(t, Args{Mode: mode}, []Source{delayedSource("fast", 10*time.Millisecond, "192.0.2.1"), delayedSource("slow", 200*time.Millisecond, "192.0.2.1")}, Options{Probe: fakeProbe(20*time.Millisecond, map[string]time.Duration{"192.0.2.1": 20 * time.Millisecond}, &calls)})
				q := queryContext(false)
				start := time.Now()
				if err := s.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				want := 55 * time.Millisecond
				if mode == ModeWaitAll {
					want = 200 * time.Millisecond
				}
				if got := time.Since(start); got != want {
					t.Fatalf("elapsed %s, want %s", got, want)
				}
				if got := answerIPs(q); !slices.Equal(got, []string{"192.0.2.1"}) {
					t.Fatal(got)
				}
				if calls.Load() != 1 {
					t.Fatalf("same-IP probes: %d", calls.Load())
				}
				synctest.Wait()
			})
		})
	}
}

func TestWeightedRTTThresholdAndFullLabelGroup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		labels := map[string]netlist.Matcher{"preferred": matchIP(func(ip netip.Addr) bool {
			return ip.String() == "192.0.2.1" || ip.String() == "192.0.2.2" || ip.String() == "192.0.2.3"
		}), "extra": oneIP("192.0.2.3")}
		s := testSelector(t, Args{Mode: ModeWaitAll, MaxNum: 4, ThresholdMS: floatptr(5), TagMultipliers: []TagMultiplier{{Tag: "preferred", Multiplier: .25}}}, []Source{delayedSource("one", 0, "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")}, Options{Labels: labels, Probe: fakeProbe(0, map[string]time.Duration{"192.0.2.1": 40 * time.Millisecond, "192.0.2.2": 60 * time.Millisecond, "192.0.2.3": 44 * time.Millisecond, "192.0.2.4": 20 * time.Millisecond}, nil)})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if got := answerIPs(q); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
			t.Fatal(got)
		}
	})
}

func TestFirstTagThenASNAndNoRTTWeightedFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := testSelector(t, Args{Mode: ModeWaitAll, MaxNum: 3, ThresholdMS: floatptr(0), TagMultipliers: []TagMultiplier{{"a", 2}, {"b", .25}}, ASNMultipliers: map[uint32]float64{64500: .01, 64501: .5}}, []Source{delayedSource("one", 0, "192.0.2.1", "192.0.2.2", "192.0.2.3")}, Options{Labels: map[string]netlist.Matcher{"a": oneIP("192.0.2.1"), "b": oneIP("192.0.2.1")}, ASNMatchers: map[uint32]netlist.Matcher{64500: oneIP("192.0.2.1"), 64501: oneIP("192.0.2.2")}})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if got := answerIPs(q); !slices.Equal(got, []string{"192.0.2.2", "192.0.2.3", "192.0.2.1"}) {
			t.Fatal(got)
		}
	})
}

func TestCandidateFilterRejectsWholeAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		s := testSelector(t, Args{Mode: ModeWaitAll, CandidateFilter: &IPFilter{LabelsExclude: []string{"bad"}}}, []Source{delayedSource("rejected", 0, "192.0.2.1", "192.0.2.2"), delayedSource("accepted", time.Millisecond, "192.0.2.3")}, Options{Labels: map[string]netlist.Matcher{"bad": oneIP("192.0.2.2")}, Probe: fakeProbe(0, map[string]time.Duration{"192.0.2.3": time.Millisecond}, &calls)})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if got := answerIPs(q); !slices.Equal(got, []string{"192.0.2.3"}) {
			t.Fatal(got)
		}
		if calls.Load() != 1 {
			t.Fatal(calls.Load())
		}
	})
}

func TestProbeMatchSkipsWorkButCanReuseSameIP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		// The first response also contains an excluded IP, so no address is
		// measured until the later response containing only .1 becomes ready.
		s := testSelector(t, Args{Mode: ModeWaitAll, ProbeMatch: &IPFilter{LabelsExclude: []string{"skip"}}}, []Source{delayedSource("unmeasured", 0, "192.0.2.1", "192.0.2.2"), delayedSource("measured", 20*time.Millisecond, "192.0.2.1")}, Options{Labels: map[string]netlist.Matcher{"skip": oneIP("192.0.2.2")}, Probe: fakeProbe(time.Millisecond, map[string]time.Duration{"192.0.2.1": time.Millisecond}, &calls)})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 1 {
			t.Fatal(calls.Load())
		}
		if got := answerIPs(q); !slices.Equal(got, []string{"192.0.2.1"}) {
			t.Fatal(got)
		}
	})
}

func TestDisabledProbesKeepUnmeasuredAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		s := testSelector(t, Args{Probe: speedtest.Config{TCPPorts: []uint16{}}}, []Source{delayedSource("one", 0, "192.0.2.1")}, Options{Probe: fakeProbe(0, nil, &calls)})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 0 {
			t.Fatal(calls.Load())
		}
	})
}

func TestDNSSECWholeSourceAndOnlySnapshotCommit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := delayedSource("one", 0, "192.0.2.1", "192.0.2.2")
		base := first.Exec
		first.Exec = sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
			if err := base.Exec(ctx, q); err != nil {
				return err
			}
			q.SetMark(91)
			q.StoreValue(37, "child")
			q.R().AuthenticatedData = true
			q.R().Authoritative = true
			q.QOpt().SetDo(false)
			return nil
		})
		s := testSelector(t, Args{Mode: ModeWaitAll}, []Source{first}, Options{Probe: fakeProbe(0, map[string]time.Duration{"192.0.2.1": time.Millisecond, "192.0.2.2": 2 * time.Millisecond}, nil)})
		q := queryContext(true)
		before := q.Q().Copy()
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if len(answerIPs(q)) != 2 || !q.R().AuthenticatedData || !q.R().Authoritative {
			t.Fatal("DNSSEC source was rewritten")
		}
		if q.HasMark(91) {
			t.Fatal("child mark escaped")
		}
		if _, ok := q.GetValue(37); ok {
			t.Fatal("child kv escaped")
		}
		if q.Q().String() != before.String() {
			t.Fatal("parent query mutated")
		}
	})
}

func TestNegativeInvalidAndCancellationAreDistinct(t *testing.T) {
	t.Run("negative", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			negative := Source{Tag: "negative", Exec: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
				r := new(dns.Msg).SetReply(q.Q())
				r.Rcode = dns.RcodeNameError
				r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 90}, Ns: "ns.test.", Mbox: "hostmaster.test.", Minttl: 30}}
				q.SetResponse(r)
				return nil
			})}
			s := testSelector(t, Args{}, []Source{negative}, Options{})
			q := queryContext(false)
			if err := s.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if q.R().Rcode != dns.RcodeNameError || len(q.R().Ns) != 1 {
				t.Fatal(q.R())
			}
		})
	})
	t.Run("invalid", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := testSelector(t, Args{CandidateFilter: &IPFilter{LabelsInclude: []string{}}}, []Source{delayedSource("one", 0, "192.0.2.1")}, Options{})
			q := queryContext(false)
			original := new(dns.Msg).SetReply(q.Q())
			original.Rcode = dns.RcodeRefused
			q.SetResponse(original)
			if err := s.Exec(context.Background(), q); !errors.Is(err, ErrNoCandidates) {
				t.Fatal(err)
			}
			if q.R().Rcode != dns.RcodeRefused {
				t.Fatal("error committed response")
			}
		})
	})
	t.Run("canceled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := testSelector(t, Args{}, []Source{delayedSource("one", time.Second, "192.0.2.1")}, Options{})
			ctx, cancel := context.WithCancelCause(context.Background())
			sentinel := errors.New("caller canceled")
			go func() { time.Sleep(time.Millisecond); cancel(sentinel) }()
			q := queryContext(false)
			if err := s.Exec(ctx, q); !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
			if q.R() != nil {
				t.Fatal("canceled query committed")
			}
			synctest.Wait()
		})
	})
}

func TestReplyReserveAndPendingProbeFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := testSelector(t, Args{Mode: ModeWaitAll, TotalTimeout: 200 * time.Millisecond}, []Source{delayedSource("one", time.Millisecond, "192.0.2.1")}, Options{Probe: fakeProbe(time.Second, nil, nil)})
		q := queryContext(false)
		start := time.Now()
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if got := time.Since(start); got != 150*time.Millisecond {
			t.Fatal(got)
		}
		if len(answerIPs(q)) != 1 {
			t.Fatal(q.R())
		}
		synctest.Wait()
	})
}

func TestTTLProvenanceAndOriginalZero(t *testing.T) {
	for _, ttl := range []uint32{0, 3} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				first := delayedSource("one", 0, "192.0.2.1")
				second := delayedSource("two", time.Millisecond, "192.0.2.2")
				base := second.Exec
				second.Exec = sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
					if err := base.Exec(ctx, q); err != nil {
						return err
					}
					q.R().Answer[0].Header().Ttl = ttl
					return nil
				})
				s := testSelector(t, Args{Mode: ModeWaitAll, MaxNum: 2}, []Source{first, second}, Options{Probe: fakeProbe(time.Millisecond, map[string]time.Duration{"192.0.2.1": time.Millisecond, "192.0.2.2": 2 * time.Millisecond}, nil)})
				q := queryContext(false)
				if err := s.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				if len(answerIPs(q)) != 2 {
					t.Fatal(q.R())
				}
				for _, rr := range q.R().Answer {
					if rr.Header().Ttl > ttl {
						t.Fatalf("TTL %d > source %d", rr.Header().Ttl, ttl)
					}
				}
			})
		})
	}
	t.Run("nonzero_expired", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			src := delayedSource("one", 0, "192.0.2.1")
			base := src.Exec
			src.Exec = sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
				if err := base.Exec(ctx, q); err != nil {
					return err
				}
				q.R().Answer[0].Header().Ttl = 1
				return nil
			})
			s := testSelector(t, Args{Mode: ModeWaitAll}, []Source{src}, Options{Probe: fakeProbe(2*time.Second, nil, nil)})
			if err := s.Exec(context.Background(), queryContext(false)); !errors.Is(err, ErrNoCandidates) {
				t.Fatal(err)
			}
		})
	})
}

func TestChangedQuestionRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := Source{Tag: "changed", Exec: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
			q.Q().Question[0].Name = "unrelated.test."
			q.SetResponse(new(dns.Msg).SetReply(q.Q()))
			return nil
		})}
		s := testSelector(t, Args{}, []Source{src}, Options{})
		if err := s.Exec(context.Background(), queryContext(false)); !errors.Is(err, ErrNoCandidates) {
			t.Fatal(err)
		}
	})
}

func TestSameIPDeterministicSourceAndMetrics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int64
		src := delayedSource("first", 10*time.Millisecond, "192.0.2.1")
		base := src.Exec
		src.Exec = sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
			if err := base.Exec(ctx, q); err != nil {
				return err
			}
			q.R().Answer[0].Header().Ttl = 12
			return nil
		})
		s := testSelector(t, Args{Mode: ModeWaitAll}, []Source{src, delayedSource("second", 0, "192.0.2.1")}, Options{Probe: fakeProbe(time.Millisecond, map[string]time.Duration{"192.0.2.1": time.Millisecond}, &calls), MetricsTag: "test"})
		reg := prometheus.NewRegistry()
		if err := s.RegisterMetricsTo(reg); err != nil {
			t.Fatal(err)
		}
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 1 {
			t.Fatal(calls.Load())
		}
		if ttl := q.R().Answer[0].Header().Ttl; ttl > 12 {
			t.Fatal(ttl)
		}
		metrics, err := reg.Gather()
		if err != nil || len(metrics) == 0 {
			t.Fatal(err)
		}
	})
}

func TestConfigurationValidation(t *testing.T) {
	for _, args := range []Args{{Mode: "bad"}, {MaxNum: -1}, {MaxNum: 65}, {ThresholdMS: floatptr(-1)}, {ThresholdMS: floatptr(math.NaN())}, {TotalTimeout: -1}, {Probe: speedtest.Config{TCPPorts: []uint16{0}}}, {TagMultipliers: []TagMultiplier{{"unknown", 1}}}} {
		if _, err := New(args, []Source{delayedSource("one", 0, "192.0.2.1")}, Options{Probe: fakeProbe(0, nil, nil)}); err == nil {
			t.Fatalf("accepted %+v", args)
		}
	}
}

func TestLateSourceReordersCandidatesWithoutExceedingUniqueProbeBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first, second := make([]string, 70), make([]string, 70)
		for i := range first {
			first[i] = fmt.Sprintf("192.0.2.%d", i+1)
			second[i] = fmt.Sprintf("198.51.100.%d", i+1)
		}
		var mu sync.Mutex
		unique := map[netip.Addr]bool{}
		probe := func(ctx context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
			mu.Lock()
			unique[ip] = true
			mu.Unlock()
			<-ctx.Done()
			return speedtest.Result{Outcome: speedtest.Unmeasured}
		}
		s := testSelector(t, Args{Mode: ModeWaitAll, MaxNum: 64}, []Source{delayedSource("first", 10*time.Millisecond, first...), delayedSource("second", 0, second...)}, Options{Probe: probe})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if got := answerIPs(q); !slices.Equal(got, first[:64]) {
			t.Fatalf("selected %v", got)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(unique) != 64 {
			t.Fatalf("physical fake-probe unique=%d", len(unique))
		}
	})
}

func TestCloseWaitsForLosingPublishers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var sourceClosed, probeClosed atomic.Bool
		slow := Source{Tag: "slow", Exec: sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
			<-ctx.Done()
			time.Sleep(20 * time.Millisecond)
			sourceClosed.Store(true)
			return context.Cause(ctx)
		})}
		probe := func(ctx context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
			if ip.String() == "192.0.2.1" {
				waitDelay(ctx, 20*time.Millisecond)
				return speedtest.Result{Outcome: speedtest.Success, RTT: 20 * time.Millisecond}
			}
			<-ctx.Done()
			time.Sleep(30 * time.Millisecond)
			probeClosed.Store(true)
			return speedtest.Result{Outcome: speedtest.Unmeasured}
		}
		s := testSelector(t, Args{}, []Source{delayedSource("fast", 10*time.Millisecond, "192.0.2.1", "192.0.2.2"), slow}, Options{Probe: probe})
		start := time.Now()
		if err := s.Exec(context.Background(), queryContext(false)); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed != 55*time.Millisecond {
			t.Fatal(elapsed)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if !sourceClosed.Load() || !probeClosed.Load() {
			t.Fatal("Close returned before publishers stopped")
		}
		if elapsed := time.Since(start); elapsed != 85*time.Millisecond {
			t.Fatal(elapsed)
		}
		if err := s.Exec(context.Background(), queryContext(false)); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCloseCancelsActiveExecBeforeWaitingForPublishers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		cleaned := make(chan struct{})
		src := Source{Tag: "one", Exec: sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
			close(entered)
			<-ctx.Done()
			time.Sleep(10 * time.Millisecond)
			close(cleaned)
			return context.Cause(ctx)
		})}
		s := testSelector(t, Args{}, []Source{src}, Options{})
		finished := make(chan error, 1)
		go func() { finished <- s.Exec(context.Background(), queryContext(false)) }()
		<-entered
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		select {
		case <-cleaned:
		default:
			t.Fatal("publisher not cleaned")
		}
	})
}

func TestForwardThenSleepDoesNotRestartTTL(t *testing.T) {
	for _, ttl := range []uint32{1, 3} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				src := Source{Tag: "one", Exec: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
					r := new(dns.Msg).SetReply(q.Q())
					r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP("192.0.2.1")}}
					q.SetResponse(r)
					time.Sleep(2 * time.Second)
					return nil
				})}
				s := testSelector(t, Args{Mode: ModeWaitAll}, []Source{src}, Options{})
				q := queryContext(false)
				err := s.Exec(context.Background(), q)
				if ttl == 1 {
					if !errors.Is(err, ErrNoCandidates) {
						t.Fatal(err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if q.R().Answer[0].Header().Ttl > 1 {
						t.Fatal("TTL restarted after source postprocessing")
					}
				}
			})
		})
	}
}

func TestCutoffUsesEarliestEventAndFreezesOutOfOrderState(t *testing.T) {
	base := time.Unix(100, 0)
	deadline := base.Add(time.Second)
	var positive, success time.Time
	observeEarliest(&positive, base.Add(80*time.Millisecond))
	observeEarliest(&positive, base.Add(20*time.Millisecond))
	observeEarliest(&success, base.Add(70*time.Millisecond))
	old := selectionCutoff(deadline, ModeBounded, positive, success, 300*time.Millisecond, 25*time.Millisecond)
	states := []*candidateState{{readyAt: base.Add(80 * time.Millisecond)}, {readyAt: base.Add(60 * time.Millisecond)}}
	probes := map[netip.Addr]*probeState{netip.MustParseAddr("192.0.2.1"): {done: true, completedAt: base.Add(70 * time.Millisecond), result: speedtest.Result{Outcome: speedtest.Success}}, netip.MustParseAddr("192.0.2.2"): {done: true, completedAt: base.Add(60 * time.Millisecond), result: speedtest.Result{Outcome: speedtest.Success}}}
	observeEarliest(&success, base.Add(35*time.Millisecond))
	cutoff := selectionCutoff(deadline, ModeBounded, positive, success, 300*time.Millisecond, 25*time.Millisecond)
	if !cutoff.Before(old) || !cutoff.Equal(base.Add(60*time.Millisecond)) {
		t.Fatal(cutoff)
	}
	observeEarliest(&positive, base.Add(90*time.Millisecond))
	observeEarliest(&success, base.Add(100*time.Millisecond))
	if got := selectionCutoff(deadline, ModeBounded, positive, success, 300*time.Millisecond, 25*time.Millisecond); !got.Equal(cutoff) {
		t.Fatal("later event extended window")
	}
	freezeAtCutoff(states, probes, cutoff)
	if states[0] != nil || states[1] == nil || probes[netip.MustParseAddr("192.0.2.1")].done || !probes[netip.MustParseAddr("192.0.2.2")].done {
		t.Fatal("strict cutoff freeze failed")
	}
}

func TestDeadlineDrainsAlreadyPublishedProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		blocker := matchIP(func(ip netip.Addr) bool {
			if ip.String() == "192.0.2.3" {
				time.Sleep(11 * time.Millisecond)
			}
			return false
		})
		probe := func(ctx context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
			d := 5 * time.Millisecond
			rtt := 20 * time.Millisecond
			if ip.String() == "192.0.2.2" {
				d = 29 * time.Millisecond
				rtt = time.Millisecond
			}
			if ip.String() == "192.0.2.3" {
				<-ctx.Done()
				return speedtest.Result{Outcome: speedtest.Unmeasured}
			}
			if !waitDelay(ctx, d) {
				return speedtest.Result{Outcome: speedtest.Unmeasured}
			}
			return speedtest.Result{Outcome: speedtest.Success, RTT: rtt}
		}
		s := testSelector(t, Args{}, []Source{delayedSource("first", 0, "192.0.2.1", "192.0.2.2"), delayedSource("blocking_metadata", 20*time.Millisecond, "192.0.2.3")}, Options{Labels: map[string]netlist.Matcher{"blocker": blocker}, Probe: probe})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if got := answerIPs(q); !slices.Equal(got, []string{"192.0.2.2"}) {
			t.Fatal(got)
		}
	})
}

func TestFallbackReasonMetrics(t *testing.T) {
	for _, reason := range []string{"all_probes_failed", "unmeasured", "mixed", "no_candidates", "negative"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				args := Args{Mode: ModeWaitAll}
				src := delayedSource("one", 0, "192.0.2.1", "192.0.2.2")
				probe := fakeProbe(0, nil, nil)
				if reason == "unmeasured" {
					args.Probe.TCPPorts = []uint16{}
				}
				if reason == "mixed" {
					probe = func(_ context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
						if ip.String() == "192.0.2.1" {
							return speedtest.Result{Outcome: speedtest.Failed}
						}
						return speedtest.Result{Outcome: speedtest.Unmeasured}
					}
				}
				if reason == "no_candidates" {
					args.CandidateFilter = &IPFilter{LabelsInclude: []string{}}
				}
				if reason == "negative" {
					src = delayedSource("one", 0)
				}
				s := testSelector(t, args, []Source{src}, Options{Probe: probe})
				err := s.Exec(context.Background(), queryContext(false))
				if reason == "no_candidates" {
					if !errors.Is(err, ErrNoCandidates) {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				metric := new(dto.Metric)
				if err := s.metrics.fallbacks.WithLabelValues(reason).Write(metric); err != nil {
					t.Fatal(err)
				}
				if got := metric.GetCounter().GetValue(); got != 1 {
					t.Fatalf("%s count=%v", reason, got)
				}
			})
		})
	}
}

func TestHugeFiniteMultiplierKeepsMeasuredAddressPriority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := testSelector(t, Args{Mode: ModeWaitAll, TagMultipliers: []TagMultiplier{{Tag: "huge", Multiplier: 1e308}}}, []Source{delayedSource("one", 0, "192.0.2.1", "192.0.2.2")}, Options{Labels: map[string]netlist.Matcher{"huge": oneIP("192.0.2.1")}, Probe: func(_ context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
			if ip.String() == "192.0.2.1" {
				return speedtest.Result{Outcome: speedtest.Success, RTT: 100 * time.Millisecond}
			}
			return speedtest.Result{Outcome: speedtest.Unmeasured}
		}})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if got := answerIPs(q); !slices.Equal(got, []string{"192.0.2.1"}) {
			t.Fatal(got)
		}
	})
}

func TestDisplacedEarlyProbeDoesNotShortenBoundedCutoffForAdmittedCandidates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		primaryIPs := make([]string, maxUniqueIPs)
		for i := range primaryIPs {
			primaryIPs[i] = fmt.Sprintf("192.0.2.%d", i+1)
		}
		probe := func(ctx context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
			switch ip.String() {
			case "198.51.100.1":
				if !waitDelay(ctx, time.Millisecond) {
					return speedtest.Result{Outcome: speedtest.Unmeasured}
				}
				return speedtest.Result{Outcome: speedtest.Success, RTT: time.Millisecond}
			case "192.0.2.1":
				if !waitDelay(ctx, 20*time.Millisecond) {
					return speedtest.Result{Outcome: speedtest.Unmeasured}
				}
				return speedtest.Result{Outcome: speedtest.Success, RTT: 5 * time.Millisecond}
			default:
				<-ctx.Done()
				return speedtest.Result{Outcome: speedtest.Unmeasured}
			}
		}
		s := testSelector(t, Args{Mode: ModeBounded, SelectionTimeout: 300 * time.Millisecond, SettleWindow: 25 * time.Millisecond}, []Source{
			delayedSource("primary", 10*time.Millisecond, primaryIPs...),
			delayedSource("secondary", 0, "198.51.100.1"),
		}, Options{Probe: probe})
		q := queryContext(false)
		if err := s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if got := answerIPs(q); !slices.Equal(got, []string{"192.0.2.1"}) || q.SnapshotResponse().ProbeStatus != query_context.ProbeSucceeded {
			t.Fatalf("displaced probe cut off primary measurement: got=%v status=%v", got, q.SnapshotResponse().ProbeStatus)
		}
	})
}
