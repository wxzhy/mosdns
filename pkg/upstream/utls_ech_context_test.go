package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
)

type blockingECHUpstream struct {
	entered chan struct{}
	closed  chan struct{}
}

func (u *blockingECHUpstream) ExchangeContext(ctx context.Context, _ []byte) (*[]byte, error) {
	close(u.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (u *blockingECHUpstream) Close() error { close(u.closed); return nil }

func TestECHResolverWaitCancellationAndClose(t *testing.T) {
	r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	u := &blockingECHUpstream{entered: make(chan struct{}), closed: make(chan struct{})}
	r.u = u
	t.Cleanup(func() { r.Close() })
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		r.getConfigList(context.Background())
	}()
	select {
	case <-u.entered:
	case <-time.After(time.Second):
		t.Fatal("first ECH lookup did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	secondDone := make(chan []byte, 1)
	go func() { secondDone <- r.getConfigList(ctx) }()
	select {
	case got := <-secondDone:
		if !bytes.Equal(got, invalidECHConfigList) {
			t.Fatal("canceled lookup did not fail closed")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled lookup waited for another caller's ECH refresh")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- r.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the active ECH lookup")
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("active lookup did not stop after Close")
	}
	select {
	case <-u.closed:
	default:
		t.Fatal("Close did not release the lookup upstream")
	}
}

func TestECHResolverCoalescesConcurrentFailedLookups(t *testing.T) {
	r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	r.u = &echResponseUpstream{response: func(q *dns.Msg) *dns.Msg {
		calls++
		if calls == 1 {
			close(entered)
		}
		<-release
		return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure)
	}}
	const n = 4
	results := make(chan []byte, n)
	for range n {
		go func() {
			results <- r.getConfigList(context.Background())
		}()
	}
	<-entered
	time.Sleep(20 * time.Millisecond)
	close(release)
	for range n {
		if got := <-results; !bytes.Equal(got, invalidECHConfigList) {
			t.Fatalf("got %x, want invalidECHConfigList", got)
		}
	}
	if calls != 1 {
		t.Fatalf("concurrent callers triggered %d DNS lookups, want 1 shared flight", calls)
	}
}

type countingEventObserver struct {
	opened, closed atomic.Int32
}

func (o *countingEventObserver) OnEvent(typ Event) {
	switch typ {
	case EventConnOpen:
		o.opened.Add(1)
	case EventConnClose:
		o.closed.Add(1)
	}
}

func TestDoTSingleEventObserverWrap(t *testing.T) {
	for _, fingerprint := range []string{"", "chrome"} {
		t.Run("fingerprint="+fingerprint, func(t *testing.T) {
			addr, shutdown := newDoTTestServer(t, &vServer{})
			defer shutdown()
			obs := new(countingEventObserver)
			u, err := NewUpstream("tls://"+addr, Opt{
				TLSConfig:       &tls.Config{InsecureSkipVerify: true},
				UTLSFingerprint: fingerprint,
				EventObserver:   obs,
			})
			if err != nil {
				t.Fatal(err)
			}
			q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			wire, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resp, err := u.ExchangeContext(ctx, wire)
			if err != nil {
				t.Fatal(err)
			}
			pool.ReleaseBuf(resp)
			if err := u.Close(); err != nil {
				t.Fatal(err)
			}
			if obs.opened.Load() != 1 || obs.closed.Load() != 1 {
				t.Fatalf("DoT connection events: opened=%d closed=%d, want 1/1", obs.opened.Load(), obs.closed.Load())
			}
		})
	}
}

