package speedcheck

import (
	"context"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/ip_replace"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestIPReplacementPrecedesStreamingProbe(t *testing.T) {
	for _, mode := range []string{ModeBounded, ModeWaitAll} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				prefix := 24
				replace, err := ip_replace.New(nil, &ip_replace.Args{ReplaceMap: []ip_replace.Rule{{
					MatchIP: []string{"192.0.0.0/16"}, IPv4PrefixLen: &prefix,
					IPv4: []string{"203.0.113.99", "198.51.100.0"},
				}}})
				if err != nil {
					t.Fatal(err)
				}
				withReplacement := func(tag string, delay time.Duration, ip string) Source {
					upstream := delayedSource(tag, delay, ip)
					return Source{Tag: tag, Exec: sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
						if err := upstream.Exec.Exec(ctx, q); err != nil {
							return err
						}
						return replace.Exec(ctx, q)
					})}
				}
				var calls atomic.Int64
				probe := fakeProbe(20*time.Millisecond, map[string]time.Duration{
					"203.0.113.42":  20 * time.Millisecond,
					"198.51.100.42": 30 * time.Millisecond,
				}, &calls)
				firstProbe := make(chan time.Time, 2)
				start := time.Now()
				selector := testSelector(t, Args{Mode: mode,
					TagMultipliers: []TagMultiplier{{Tag: "preferred", Multiplier: 0.25}},
				}, []Source{
					withReplacement("fast", 10*time.Millisecond, "192.0.2.42"),
					withReplacement("same_target", 15*time.Millisecond, "192.0.9.42"),
					withReplacement("slow", 200*time.Millisecond, "192.0.3.42"),
				}, Options{
					Labels: map[string]netlist.Matcher{"preferred": oneIP("198.51.100.42")},
					Probe: func(ctx context.Context, ip netip.Addr, c speedtest.Config) speedtest.Result {
						if ip != netip.MustParseAddr("203.0.113.42") && ip != netip.MustParseAddr("198.51.100.42") {
							t.Errorf("probed original or incorrect address %s", ip)
						}
						firstProbe <- time.Now()
						return probe(ctx, ip, c)
					},
				})
				q := queryContext(false)
				if err := selector.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				want := 55 * time.Millisecond
				if mode == ModeWaitAll {
					want = 200 * time.Millisecond
				}
				if elapsed := time.Since(start); elapsed != want {
					t.Fatalf("replacement delayed streaming: elapsed=%s, want %s", elapsed, want)
				}
				if elapsed := (<-firstProbe).Sub(start); elapsed != 10*time.Millisecond {
					t.Fatalf("probe did not start with first source: %s", elapsed)
				}
				if calls.Load() != 2 {
					t.Fatalf("cross-source targets did not share probes: %d", calls.Load())
				}
				if got := answerIPs(q); !slices.Equal(got, []string{"198.51.100.42"}) {
					t.Fatalf("weights did not classify replaced addresses: %v", got)
				}
				synctest.Wait()
			})
		})
	}
}

func TestIPReplacementCannotReviveExpiredSourceAsZeroTTL(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ttl, cnameTTL uint32
		before        time.Duration
		probeDelay    time.Duration
		wantSuccess   bool
		wantProbes    int64
	}{
		{"expired before replacement", 1, 5, 1500 * time.Millisecond, 0, false, 0},
		{"fractional lifetime still usable", 1, 5, 600 * time.Millisecond, 100 * time.Millisecond, true, 1},
		{"fractional lifetime expires while probing", 1, 5, 600 * time.Millisecond, 700 * time.Millisecond, false, 1},
		{"zero terminal bounded by positive alias", 0, 1, 600 * time.Millisecond, 700 * time.Millisecond, false, 1},
		{"positive terminal bounded despite zero alias", 1, 0, 600 * time.Millisecond, 700 * time.Millisecond, false, 1},
		{"original zero TTL remains usable", 0, 0, 600 * time.Millisecond, 700 * time.Millisecond, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				prefix := 24
				replacer, err := ip_replace.New(nil, &ip_replace.Args{ReplaceMap: []ip_replace.Rule{{
					MatchIP: []string{"192.0.2.0/24"}, IPv4PrefixLen: &prefix, IPv4: []string{"203.0.113.0"},
				}}})
				if err != nil {
					t.Fatal(err)
				}
				source := Source{Tag: "rewritten", Exec: sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
					r := new(dns.Msg).SetReply(q.Q())
					r.Answer = []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: tc.cnameTTL}, Target: "cdn.test."},
						&dns.A{Hdr: dns.RR_Header{Name: "cdn.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: tc.ttl}, A: netip.MustParseAddr("192.0.2.42").AsSlice()},
					}
					q.SetResponse(r)
					if !waitDelay(ctx, tc.before) {
						return ctx.Err()
					}
					return replacer.Exec(ctx, q)
				})}
				var probes atomic.Int64
				selector := testSelector(t, Args{Mode: ModeWaitAll, TotalTimeout: 3 * time.Second}, []Source{source}, Options{
					Probe: fakeProbe(tc.probeDelay, map[string]time.Duration{"203.0.113.42": time.Millisecond}, &probes),
				})
				q := queryContext(false)
				err = selector.Exec(context.Background(), q)
				if tc.wantSuccess {
					if err != nil || !slices.Equal(answerIPs(q), []string{"203.0.113.42"}) {
						t.Fatalf("valid replacement lost: %v, %v", err, q.R())
					}
					for _, rr := range q.R().Answer {
						if rr.Header().Ttl != 0 {
							t.Fatalf("zero remaining wire TTL extended: %v", rr)
						}
					}
				} else if err != ErrNoCandidates || q.R() != nil {
					t.Fatalf("expired source revived by replacement: %v, %v", err, q.R())
				}
				if probes.Load() != tc.wantProbes {
					t.Fatalf("probes=%d, want %d", probes.Load(), tc.wantProbes)
				}
				synctest.Wait()
			})
		})
	}
}

func TestRawCandidateCannotOutliveItsCNAMEChain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := Source{Tag: "short_alias", Exec: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
			r := new(dns.Msg).SetReply(q.Q())
			r.Answer = []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: "cdn.test."},
				&dns.A{Hdr: dns.RR_Header{Name: "cdn.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: netip.MustParseAddr("192.0.2.42").AsSlice()},
			}
			q.SetResponse(r)
			return nil
		})}
		selector := testSelector(t, Args{Mode: ModeWaitAll, TotalTimeout: 3 * time.Second}, []Source{source}, Options{
			Probe: fakeProbe(1500*time.Millisecond, map[string]time.Duration{"192.0.2.42": time.Millisecond}, nil),
		})
		q := queryContext(false)
		if err := selector.Exec(context.Background(), q); err != ErrNoCandidates || q.R() != nil {
			t.Fatalf("expired alias returned with live address: %v, %v", err, q.R())
		}
		synctest.Wait()
	})
}
