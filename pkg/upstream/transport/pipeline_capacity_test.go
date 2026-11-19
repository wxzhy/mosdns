package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
)

func TestPipelineOneActiveQueryUsesOneSlot(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	conn := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: true, MaxConcurrentQuery: 2}, client)
	defer conn.Close()

	slot, _ := conn.ReserveNewQuery()
	if slot == nil {
		t.Fatal("initial reservation failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := new(dns.Msg).SetQuestion("audit.example.", dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		resp, err := slot.ExchangeReserved(ctx, payload)
		if resp != nil {
			pool.ReleaseBuf(resp)
		}
		done <- err
	}()

	_ = peer.SetDeadline(time.Now().Add(time.Second))
	received, _, err := dnsutils.ReadMsgFromTCP(peer)
	if err != nil {
		t.Fatal(err)
	}
	second, closed := conn.ReserveNewQuery()
	if second == nil || closed {
		t.Fatalf("second query denied with one in flight and a limit of two (closed=%t)", closed)
	}
	if extra, closed := conn.ReserveNewQuery(); extra != nil || closed {
		t.Fatalf("expected a full, open connection, got reservation=%v, closed=%t", extra, closed)
	}
	if _, err := dnsutils.WriteMsgToTCP(peer, new(dns.Msg).SetReply(received)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	afterResponse, closed := conn.ReserveNewQuery()
	if afterResponse == nil || closed {
		t.Fatalf("completed exchange did not release its slot (closed=%t)", closed)
	}
	afterResponse.WithdrawReserved()
	second.WithdrawReserved()
}
