package fastforward

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type cancelTestUpstream struct {
	fn func(context.Context) error
}

func (u cancelTestUpstream) ExchangeContext(ctx context.Context, _ []byte) (*[]byte, error) {
	return nil, u.fn(ctx)
}
func (cancelTestUpstream) Close() error { return nil }

func TestBranchCancellationIsOptIn(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "selector"}[inherited], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started, finished, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				u := newWrapper(0, UpstreamConfig{}, "test")
				u.u = cancelTestUpstream{fn: func(ctx context.Context) error {
					close(started)
					defer close(finished)
					select {
					case <-ctx.Done():
						return context.Cause(ctx)
					case <-release:
						return context.Canceled
					}
				}}
				f := &Forward{args: &Args{}, logger: zap.NewNop()}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var callCtx context.Context = ctx
				if inherited {
					callCtx = query_policy.WithInheritedCancellation(ctx)
				}
				q := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
				result := make(chan error, 1)
				go func() {
					_, err := f.exchange(callCtx, query_context.NewContext(q), []*upstreamWrapper{u})
					result <- err
				}()
				<-started
				cancel()
				if err := <-result; err != context.Canceled {
					t.Fatalf("unexpected cancellation result: %v", err)
				}
				synctest.Wait()
				select {
				case <-finished:
					if !inherited {
						t.Fatal("ordinary forward changed transport lifetime")
					}
				default:
					if inherited {
						t.Fatal("selector forward did not cancel its transport")
					}
				}
				close(release)
			})
		})
	}
}
