package fallback

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/speedcheck"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestFallbackPreservesSelectedResponseState(t *testing.T) {
	q := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
	q.SetEdns0(1232, true)
	parent := query_context.NewContext(q)
	parent.SetMark(7)
	var received time.Time
	f := &fallback{logger: zap.NewNop(), fastFallbackDuration: time.Minute,
		primary: sequence.ExecutableFunc(func(_ context.Context, c *query_context.Context) error {
			r := new(dns.Msg).SetReply(c.Q())
			r.SetEdns0(1400, true)
			c.SetResponse(r)
			received = c.ResponseReceivedAt()
			c.RespOpt().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1}}}
			c.DeleteMark(7)
			time.Sleep(time.Millisecond)
			return nil
		}), secondary: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
			t.Error("secondary unexpectedly called")
			return nil
		}),
	}
	if err := f.Exec(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	if parent.UpstreamOpt() == nil || parent.UpstreamOpt().UDPSize() != 1400 || len(parent.RespOpt().Option) != 1 || parent.ResponseReceivedAt() != received || !parent.HasMark(7) {
		t.Fatal("fallback lost selected snapshot state or copied branch marks")
	}
}

func TestParentCancellationReachesSelectorInsideFallback(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	s, err := speedcheck.New(speedcheck.Args{}, []speedcheck.Source{{Tag: "source", Exec: sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
		close(started)
		defer close(stopped)
		<-ctx.Done()
		return ctx.Err()
	})}}, speedcheck.Options{Probe: func(context.Context, netip.Addr, speedtest.Config) speedtest.Result { return speedtest.Result{} }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f := &fallback{logger: zap.NewNop(), primary: s, secondary: s, fastFallbackDuration: time.Minute}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- f.Exec(ctx, query_context.NewContext(new(dns.Msg).SetQuestion("example.org.", dns.TypeA)))
	}()
	<-started
	cancel()
	if err := <-result; err != context.Canceled {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("nested selector retained canceled source")
	}
}
