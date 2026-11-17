package speedcheck

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestBoundedWaitsForSuccessfulRTT(t *testing.T) {
	for _, family := range []struct {
		name  string
		qtype uint16
		early string
		good  string
	}{
		{"A", dns.TypeA, "192.0.2.1", "192.0.2.2"},
		{"AAAA", dns.TypeAAAA, "2001:db8::1", "2001:db8::2"},
	} {
		for _, scenario := range []string{"failed", "unmeasured", "unmatched", "pending", "nodata", "nxdomain", "slow_success"} {
			t.Run(family.name+"/"+scenario, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					addressSource := func(tag string, delay time.Duration, ip string) Source {
						return Source{Tag: tag, Exec: sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
							if !waitDelay(ctx, delay) {
								return context.Cause(ctx)
							}
							r := new(dns.Msg).SetReply(q.Q())
							if ip != "" {
								h := dns.RR_Header{Name: q.QQuestion().Name, Rrtype: family.qtype, Class: dns.ClassINET, Ttl: 300}
								if family.qtype == dns.TypeA {
									r.Answer = []dns.RR{&dns.A{Hdr: h, A: netip.MustParseAddr(ip).AsSlice()}}
								} else {
									r.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: netip.MustParseAddr(ip).AsSlice()}}
								}
							} else if scenario == "nxdomain" {
								r.Rcode = dns.RcodeNameError
							}
							q.SetResponse(r)
							return nil
						})}
					}
					args := Args{SelectionTimeout: 250 * time.Millisecond, TotalTimeout: time.Second}
					earlyIP := family.early
					if scenario == "nodata" || scenario == "nxdomain" {
						earlyIP = ""
					}
					goodDelay, probeDelay := 400*time.Millisecond, 20*time.Millisecond
					if scenario == "slow_success" {
						goodDelay, probeDelay = 10*time.Millisecond, 400*time.Millisecond
					}
					probe := func(ctx context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
						if ip.String() == family.good {
							if waitDelay(ctx, probeDelay) {
								return speedtest.Result{Outcome: speedtest.Success, RTT: 20 * time.Millisecond}
							}
						} else {
							switch scenario {
							case "pending":
								<-ctx.Done()
							case "unmeasured":
								return speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "queue_full"}
							case "unmatched":
								t.Error("probe_match excluded address was probed")
							default:
								return speedtest.Result{Outcome: speedtest.Failed}
							}
						}
						return speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "canceled"}
					}
					opts := Options{Probe: probe}
					if scenario == "unmatched" {
						args.ProbeMatch = &IPFilter{LabelsExclude: []string{"skip"}}
						opts.Labels = map[string]netlist.Matcher{"skip": oneIP(family.early)}
					}
					s := testSelector(t, args, []Source{
						addressSource("early", 10*time.Millisecond, earlyIP),
						addressSource("good", goodDelay, family.good),
						addressSource("blocked", 5*time.Second, family.early),
					}, opts)
					q := query_context.NewContext(new(dns.Msg).SetQuestion("example.test.", family.qtype))
					start := time.Now()
					if err := s.Exec(context.Background(), q); err != nil {
						t.Fatal(err)
					}
					if got := answerIPs(q); !slices.Equal(got, []string{family.good}) || q.SnapshotResponse().ProbeStatus != query_context.ProbeSucceeded {
						t.Fatalf("returned an answer without the successful RTT: ips=%v status=%v", got, q.SnapshotResponse().ProbeStatus)
					}
					if elapsed, want := time.Since(start), goodDelay+probeDelay+25*time.Millisecond; elapsed != want {
						t.Fatalf("elapsed=%v, want=%v", elapsed, want)
					}
					synctest.Wait()
				})
			})
		}
	}
}

func TestBoundedSelectionWindowsStartAtSuccessfulRTT(t *testing.T) {
	for _, windows := range []struct {
		selection time.Duration
		settle    time.Duration
	}{
		{5 * time.Millisecond, 25 * time.Millisecond},
		{25 * time.Millisecond, 5 * time.Millisecond},
	} {
		t.Run(windows.selection.String()+"/"+windows.settle.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := testSelector(t, Args{SelectionTimeout: windows.selection, SettleWindow: windows.settle}, []Source{
					delayedSource("good", 10*time.Millisecond, "192.0.2.1"),
					delayedSource("blocked", 5*time.Second, "192.0.2.2"),
				}, Options{Probe: func(ctx context.Context, _ netip.Addr, _ speedtest.Config) speedtest.Result {
					if waitDelay(ctx, 400*time.Millisecond) {
						return speedtest.Result{Outcome: speedtest.Success, RTT: 0, Cached: true}
					}
					return speedtest.Result{Outcome: speedtest.Unmeasured}
				}})
				q := queryContext(false)
				start := time.Now()
				if err := s.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				if elapsed, want := time.Since(start), 410*time.Millisecond+min(windows.selection, windows.settle); elapsed != want {
					t.Fatalf("elapsed=%v, want=%v", elapsed, want)
				}
				if q.SnapshotResponse().ProbeStatus != query_context.ProbeSucceeded {
					t.Fatal("zero cached RTT did not start the selection window")
				}
				synctest.Wait()
			})
		})
	}
}
