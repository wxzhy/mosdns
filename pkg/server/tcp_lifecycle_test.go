package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
)

func TestTCPIdleTimeoutWaitsForPendingQuery(t *testing.T) {
	const idle = 100 * time.Millisecond
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}, 2), make(chan struct{})
	canceled := make(chan struct{})
	h := doqLifecycleHandler(func(ctx context.Context, q *dns.Msg, _ QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
		started <- struct{}{}
		if q.Question[0].Name == "shutdown.example.test." {
			<-ctx.Done()
			close(canceled)
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-release:
		}
		payload, _ := pack(new(dns.Msg).SetReply(q))
		return payload
	})
	stopped := make(chan error, 1)
	go func() { stopped <- ServeTCP(listener, h, TCPServerOpts{IdleTimeout: idle}) }()
	t.Cleanup(func() { _ = listener.Close(); checkServerStopped(t, stopped) })
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	q := new(dns.Msg).SetQuestion("idle.example.test.", dns.TypeA)
	if _, err := dnsutils.WriteMsgToTCP(conn, q); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	<-time.After(2 * idle)
	close(release)
	r, _, err := dnsutils.ReadMsgFromTCP(conn)
	if err != nil || !dnsutils.MatchesResponse(q, r) {
		t.Fatalf("pending query response = %v, %v", r, err)
	}
	q = new(dns.Msg).SetQuestion("shutdown.example.test.", dns.TypeA)
	if _, err := dnsutils.WriteMsgToTCP(conn, q); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("second query did not start")
	}
	_ = listener.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("listener shutdown did not cancel its pending query")
	}
	if _, _, err := dnsutils.ReadMsgFromTCP(conn); err == nil {
		t.Fatal("accepted connection stayed open after listener shutdown")
	}
}
