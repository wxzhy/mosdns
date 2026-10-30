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

func TestFallbackCommitsOnlyWinningBranchMetadata(t *testing.T) {
	for _, primaryWins := range []bool{true, false} {
		name := "secondary"
		if primaryWins {
			name = "primary"
		}
		t.Run(name, func(t *testing.T) {
			parent := query_context.NewContext(new(dns.Msg).SetQuestion("example.org.", dns.TypeA))
			parent.AddRuleHit("entry", []string{"qname example.org"}, "$fallback")
			parent.SetMark(7)
			ready := make(chan struct{})
			var primaryBranch, secondaryBranch *query_context.Context
			prepare := func(c *query_context.Context, tag string) {
				c.SetResponse(new(dns.Msg).SetReply(c.Q()))
				c.SetUpstreamSelected("tls://"+tag, "DoT", tag, "forward_"+tag)
				c.AddRuleHit(tag, []string{"branch " + tag}, "$forward_"+tag)
				c.DeleteMark(7)
				c.SetMark(8)
				c.Q().Question[0].Name = tag + ".example."
				if tag == "primary" {
					c.FromHosts = true
				} else {
					c.FromArbitrary = true
					c.SetCacheState(true, true, 60, 5)
				}
			}
			f := &fallback{
				logger: zap.NewNop(), alwaysStandby: true, fastFallbackDuration: time.Minute,
				primary: sequence.ExecutableFunc(func(_ context.Context, c *query_context.Context) error {
					primaryBranch = c
					prepare(c, "primary")
					<-ready
					if !primaryWins {
						c.SetResponse(nil)
					}
					return nil
				}),
				secondary: sequence.ExecutableFunc(func(_ context.Context, c *query_context.Context) error {
					secondaryBranch = c
					prepare(c, "secondary")
					close(ready)
					return nil
				}),
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := f.Exec(ctx, parent); err != nil {
				t.Fatal(err)
			}
			winner := secondaryBranch
			if primaryWins {
				winner = primaryBranch
			}
			winner.UpstreamSelected.Tag = "mutated branch"
			winner.RuleHits[1].Matches[0] = "mutated branch"
			if parent.UpstreamSelected.Tag != name || len(parent.RuleHits) != 2 || parent.RuleHits[1].Sequence != name || parent.RuleHits[1].Matches[0] != "branch "+name {
				t.Fatalf("winner metadata lost, aliased or merged with loser: upstream=%+v rules=%+v", parent.UpstreamSelected, parent.RuleHits)
			}
			if parent.FromHosts != primaryWins || parent.FromArbitrary == primaryWins || parent.CacheState.Hit == primaryWins {
				t.Fatalf("winner source/cache state lost: hosts=%v arbitrary=%v cache=%+v", parent.FromHosts, parent.FromArbitrary, parent.CacheState)
			}
			if parent.QQuestion().Name != "example.org." || !parent.HasMark(7) || parent.HasMark(8) {
				t.Fatal("winner metadata copied branch query/marks")
			}
		})
	}
}
