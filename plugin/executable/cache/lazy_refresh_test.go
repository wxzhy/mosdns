package cache

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestLazyRefreshRetainsNewerForegroundAnswer(t *testing.T) {
	c := NewCache(&Args{LazyCacheTTL: 60}, Opts{})
	defer c.Close()
	q := new(dns.Msg).SetQuestion("lazy.audit.example.", dns.TypeA)
	// Use the internal key after query processing initializes its OPT.
	msgKey := getMsgKey(query_context.NewContext(q.Copy()).Q())
	past := time.Now().Add(-5 * time.Second)
	c.backend.Store(key(msgKey), &item{
		resp:       policyResponse(q, net.IPv4(192, 0, 2, 1), 1),
		storedTime: past, expirationTime: past.Add(time.Second),
	}, time.Now().Add(time.Minute))

	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	defer resume()
	// The cache runs the same continuation for the foreground and lazy refresh.
	// Choose independent replies by whether the stale answer was already added.
	chain := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(ctx context.Context, qc *query_context.Context) error {
		if qc.R() == nil {
			close(started)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
			}
			qc.SetResponse(policyResponse(qc.Q(), net.IPv4(192, 0, 2, 2), 30))
		} else {
			qc.SetResponse(policyResponse(qc.Q(), net.IPv4(192, 0, 2, 3), 30))
		}
		return nil
	})}}, nil)

	if err := c.Exec(context.Background(), query_context.NewContext(q.Copy()), chain); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lazy refresh did not start")
	}
	current, _, ok := c.backend.Get(key(msgKey))
	if !ok || !current.resp.Answer[0].(*dns.A).A.Equal(net.IPv4(192, 0, 2, 3)) {
		t.Fatal("foreground answer was not cached")
	}
	resume()
	c.lazyWG.Wait()
	current, _, ok = c.backend.Get(key(msgKey))
	if !ok || !current.resp.Answer[0].(*dns.A).A.Equal(net.IPv4(192, 0, 2, 3)) {
		t.Fatalf("background refresh replaced the newer foreground answer: %v", current.resp.Answer)
	}
}
