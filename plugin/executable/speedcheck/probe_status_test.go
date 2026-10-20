package speedcheck

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
)

func TestSelectionPublishesReliableProbeStatus(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  Args
		probe ProbeFunc
		want  query_context.ProbeStatus
		calls int64
	}{
		{"failed", Args{}, func(context.Context, netip.Addr, speedtest.Config) speedtest.Result {
			return speedtest.Result{Outcome: speedtest.Failed}
		}, query_context.ProbeFailed, 2},
		{"zero RTT", Args{}, func(context.Context, netip.Addr, speedtest.Config) speedtest.Result {
			return speedtest.Result{Outcome: speedtest.Success}
		}, query_context.ProbeSucceeded, 2},
		{"queue full", Args{}, func(context.Context, netip.Addr, speedtest.Config) speedtest.Result {
			return speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "queue_full"}
		}, query_context.ProbeUnmeasured, 2},
		{"mixed", Args{}, func(_ context.Context, ip netip.Addr, _ speedtest.Config) speedtest.Result {
			if ip == netip.MustParseAddr("192.0.2.1") {
				return speedtest.Result{Outcome: speedtest.Failed}
			}
			return speedtest.Result{Outcome: speedtest.Unmeasured}
		}, query_context.ProbeUnmeasured, 2},
		{"disabled", Args{Probe: speedtest.Config{TCPPorts: []uint16{}}}, nil, query_context.ProbeUnmeasured, 0},
		{"unmatched", Args{ProbeMatch: &IPFilter{LabelsInclude: []string{}}}, nil, query_context.ProbeUnmeasured, 0},
		{"pending", Args{SelectionTimeout: 5 * time.Millisecond}, func(ctx context.Context, _ netip.Addr, _ speedtest.Config) speedtest.Result {
			<-ctx.Done()
			return speedtest.Result{Outcome: speedtest.Unmeasured}
		}, query_context.ProbeUnmeasured, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int64
				s := testSelector(t, tc.args, []Source{delayedSource("source", 0, "192.0.2.1", "192.0.2.2")}, Options{Probe: func(ctx context.Context, ip netip.Addr, c speedtest.Config) speedtest.Result {
					calls.Add(1)
					if tc.probe == nil {
						t.Error("disabled or unmatched probe launched")
						return speedtest.Result{Outcome: speedtest.Unmeasured}
					}
					return tc.probe(ctx, ip, c)
				}})
				q := queryContext(false)
				if err := s.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				if got := q.SnapshotResponse().ProbeStatus; got != tc.want {
					t.Fatalf("status=%v, want=%v", got, tc.want)
				}
				if len(answerIPs(q)) != 1 {
					t.Fatal("max_num changed")
				}
				synctest.Wait()
				if calls.Load() != tc.calls {
					t.Fatalf("calls=%d, want=%d", calls.Load(), tc.calls)
				}
			})
		})
	}
}
