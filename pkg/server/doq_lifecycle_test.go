package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type doqLifecycleHandler func(context.Context, *dns.Msg, QueryMeta, func(*dns.Msg) (*[]byte, error)) *[]byte

func (h doqLifecycleHandler) Handle(ctx context.Context, q *dns.Msg, meta QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
	return h(ctx, q, meta, pack)
}

func startDoQLifecycleServer(t *testing.T, h Handler) *quic.Conn {
	t.Helper()
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(cert.Close)
	l, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: cert.TLS.Certificates, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- ServeDoQ(l, h, DoQServerOpts{IdleTimeout: 5 * time.Second}) }()
	t.Cleanup(func() { l.Close(); checkServerStopped(t, stopped) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, l.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseWithError(0, "test complete") })
	return c
}

func sendDoQLifecycleQuery(t *testing.T, c *quic.Conn, name string) (*quic.Stream, *dns.Msg) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { s.CancelRead(0); s.CancelWrite(0) })
	q := new(dns.Msg).SetQuestion(name, dns.TypeA)
	if _, err := dnsutils.WriteMsgToTCP(s, q); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return s, q
}

func TestDoQStreamCancellationOnlyCancelsItsQuery(t *testing.T) {
	started := make(chan struct{}, 1)
	canceled := make(chan error, 1)
	h := doqLifecycleHandler(func(ctx context.Context, q *dns.Msg, _ QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
		if q.Question[0].Name == "cancel.example." {
			started <- struct{}{}
			<-ctx.Done()
			canceled <- context.Cause(ctx)
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		payload, _ := pack(new(dns.Msg).SetReply(q))
		return payload
	})
	c := startDoQLifecycleServer(t, h)
	s, _ := sendDoQLifecycleQuery(t, c, "cancel.example.")
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("query handler did not start")
	}
	s.CancelRead(7)
	select {
	case err := <-canceled:
		var streamErr *quic.StreamError
		if !errors.As(err, &streamErr) || !streamErr.Remote || streamErr.ErrorCode != 7 {
			t.Fatalf("query cancellation cause=%v, want peer stream error 7", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled response stream left query running")
	}
	// The connection and the next query survive cancellation of the first stream.
	next, q := sendDoQLifecycleQuery(t, c, "next.example.")
	r, _, err := dnsutils.ReadMsgFromTCP(next)
	if err != nil || r.Id != q.Id || !r.Response || r.Question[0] != q.Question[0] {
		t.Fatalf("next query response=%v, err=%v", r, err)
	}
}

func TestDoQRequestFINDoesNotCancelResponse(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	h := doqLifecycleHandler(func(ctx context.Context, q *dns.Msg, _ QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
		started <- ctx
		select {
		case <-release:
		case <-ctx.Done():
			return nil
		}
		payload, _ := pack(new(dns.Msg).SetReply(q))
		return payload
	})
	c := startDoQLifecycleServer(t, h)
	s, q := sendDoQLifecycleQuery(t, c, "fin.example.")
	select {
	case ctx := <-started:
		if ctx.Err() != nil {
			t.Fatalf("request FIN canceled handler: %v", ctx.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("query handler did not start")
	}
	close(release)
	r, _, err := dnsutils.ReadMsgFromTCP(s)
	if err != nil || r.Id != q.Id || !r.Response {
		t.Fatalf("response after request FIN=%v, err=%v", r, err)
	}
}
