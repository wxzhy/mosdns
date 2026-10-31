/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package dnscrypt

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// startTestServer starts a DNSCrypt test server (udp + tcp) and returns
// its stamp string.
func startTestServer(t testing.TB, h dnscrypt.Handler, constructions ...dnscrypt.CryptoConstruction) (stampStr string) {
	t.Helper()

	rc, err := dnscrypt.GenerateResolverConfig("example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(constructions) > 0 {
		rc.ESVersion = constructions[0]
	}
	cert, err := rc.NewCert()
	if err != nil {
		t.Fatal(err)
	}

	startServer := func(proto dnscrypt.Proto, addr netip.AddrPort) (*dnscrypt.Server, error) {
		t.Helper()
		s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
			Handler:      h,
			ResolverCert: cert,
			Logger:       nil,
			ProviderName: rc.ProviderName,
			Addr:         addr,
			Proto:        proto,
		})
		if err != nil {
			return nil, err
		}
		if err := s.Start(context.Background()); err != nil {
			return nil, err
		}
		return s, nil
	}

	// UDP's ephemeral port can be unavailable to TCP, especially with Windows
	// protocol-specific excluded ranges. Hold the actual TCP listener while
	// acquiring UDP, rather than releasing probe sockets before binding again.
	const maxBindAttempts = 32
	var lastBindErr error
	for range maxBindAttempts {
		srvTCP, err := startServer(dnscrypt.ProtoTCP, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0))
		if err != nil {
			if !retryableTestServerBind(err) {
				t.Fatal(err)
			}
			lastBindErr = err
			continue
		}
		addrStr := srvTCP.LocalAddr().String()
		srvUDP, err := startServer(dnscrypt.ProtoUDP, netip.MustParseAddrPort(addrStr))
		if err != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			shutdownErr := srvTCP.Shutdown(ctx)
			cancel()
			if shutdownErr != nil {
				t.Fatalf("release partial DNSCrypt server: %v (bind error: %v)", shutdownErr, err)
			}
			if !retryableTestServerBind(err) {
				t.Fatal(err)
			}
			lastBindErr = err
			continue
		}
		t.Cleanup(func() { _ = srvTCP.Shutdown(context.Background()) })
		t.Cleanup(func() { _ = srvUDP.Shutdown(context.Background()) })
		stamp, err := rc.CreateStamp(addrStr)
		if err != nil {
			t.Fatal(err)
		}
		return stamp.String()
	}
	t.Fatalf("could not bind a shared TCP/UDP loopback port after %d attempts: %v", maxBindAttempts, lastBindErr)
	return ""
}

func retryableTestServerBind(err error) bool {
	var syscallErr *os.SyscallError
	if !errors.As(err, &syscallErr) || syscallErr.Syscall != "bind" {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return true
	}
	// syscall.E* constants on Windows are synthetic; Winsock returns its own
	// WSAEACCES (10013) and WSAEADDRINUSE (10048) codes instead.
	return runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(10013)) || errors.Is(err, syscall.Errno(10048)))
}

// testHandler replies to the query. If truncateUDP is true, udp replies
// are truncated.
type testHandler struct {
	truncateUDP bool
}

func (h testHandler) ServeDNS(_ context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
	res := (&dns.Msg{}).SetReply(r)
	res.Answer = append(res.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(1, 2, 3, 4).To4(),
	})

	if h.truncateUDP && w.RemoteAddr().Network() == "udp" {
		res.Truncated = true
	}
	return w.WriteMsg(context.Background(), res)
}

func exchange(t testing.TB, u *Upstream) *dns.Msg {
	t.Helper()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.Id = 42
	queryPayload, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	r, err := u.ExchangeContext(ctx, queryPayload)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(r)

	resp := new(dns.Msg)
	if err := resp.Unpack(*r); err != nil {
		t.Fatal(err)
	}
	if resp.Id != q.Id {
		t.Fatal(dns.ErrId)
	}
	return resp
}

func TestUpstream_Exchange(t *testing.T) {
	stampStr := startTestServer(t, testHandler{})

	u, err := NewUpstream(stampStr, Opt{})
	if err != nil {
		t.Fatal(err)
	}

	// The first query fetches the resolver certificate,
	// following ones reuse it.
	for range 3 {
		resp := exchange(t, u)
		if resp.Truncated {
			t.Fatal("unexpected truncated response")
		}
		if len(resp.Answer) == 0 {
			t.Fatal("response has no answer")
		}
	}
}

func TestUpstream_Truncated(t *testing.T) {
	stampStr := startTestServer(t, testHandler{truncateUDP: true})

	u, err := NewUpstream(stampStr, Opt{})
	if err != nil {
		t.Fatal(err)
	}

	// The udp response is truncated. The upstream should retry over tcp.
	resp := exchange(t, u)
	if resp.Truncated {
		t.Fatal("response is still truncated")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("response has no answer")
	}
}

func TestUpstream_CertExpired(t *testing.T) {
	stampStr := startTestServer(t, testHandler{})

	u, err := NewUpstream(stampStr, Opt{})
	if err != nil {
		t.Fatal(err)
	}

	if resp := exchange(t, u); len(resp.Answer) == 0 {
		t.Fatal("response has no answer")
	}

	// Expire the cached certificate. The upstream should re-fetch it.
	u.mu.Lock()
	u.ri.ResolverCert.NotAfter = 1
	u.mu.Unlock()

	if resp := exchange(t, u); len(resp.Answer) == 0 {
		t.Fatal("response has no answer")
	}
}

func TestNewUpstream_InvalidStamp(t *testing.T) {
	if _, err := NewUpstream("this-is-not-a-stamp", Opt{}); err == nil {
		t.Fatal("expected error")
	}

	// A plain stamp is not a dnscrypt stamp.
	plainStamp := (&dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypePlain,
		ServerAddrStr: "127.0.0.1:53",
	}).String()
	if _, err := NewUpstream(plainStamp, Opt{}); err == nil {
		t.Fatal("expected error")
	} else if !strings.Contains(err.Error(), "stamp protocol") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpstream_CertificateUsesConfiguredDialer(t *testing.T) {
	for _, tc := range []struct {
		name         string
		construction dnscrypt.CryptoConstruction
	}{{"xsalsa20", dnscrypt.XSalsa20Poly1305}, {"xchacha20", dnscrypt.XChacha20Poly1305}} {
		t.Run(tc.name, func(t *testing.T) {
			stampStr := startTestServer(t, testHandler{}, tc.construction)
			stamp, err := dnsstamps.NewServerStampFromString(stampStr)
			if err != nil {
				t.Fatal(err)
			}
			addr := stamp.ServerAddrStr
			stamp.ServerAddrStr = "127.0.0.2:1"
			var calls atomic.Int32
			u, err := NewUpstream(stamp.String(), Opt{UDPDialContext: func(ctx context.Context) (net.Conn, error) {
				calls.Add(1)
				return new(net.Dialer).DialContext(ctx, "udp", addr)
			}})
			if err != nil {
				t.Fatal(err)
			}
			exchange(t, u)
			if got := calls.Load(); got != 2 {
				t.Fatalf("certificate and encrypted query must both use configured route, got %d calls", got)
			}
		})
	}
}

func TestUpstream_CertificateWaitCancellation(t *testing.T) {
	stampStr := startTestServer(t, testHandler{})
	started := make(chan struct{})
	u, err := NewUpstream(stampStr, Opt{UDPDialContext: func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = u.fetchResolverInfo(ctx) }()
	<-started
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer waitCancel()
	waitDone := make(chan error, 1)
	go func() { _, err := u.fetchResolverInfo(waitCtx); waitDone <- err }()
	select {
	case err := <-waitDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("cancelled query remained blocked behind certificate refresh")
	}
	cancel()
	<-done
}

type largeResponseHandler struct{}

func (largeResponseHandler) ServeDNS(ctx context.Context, w dnscrypt.ResponseWriter, req *dns.Msg) error {
	r := new(dns.Msg).SetReply(req)
	r.SetEdns0(4096, false)
	r.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: make([]byte, 1024)}}
	return w.WriteMsg(ctx, r)
}

func TestUpstream_LargeUDPResponse(t *testing.T) {
	u, err := NewUpstream(startTestServer(t, largeResponseHandler{}), Opt{})
	if err != nil {
		t.Fatal(err)
	}
	resp := exchange(t, u)
	if resp.Len() <= 512 {
		t.Fatalf("large response was lost or truncated: %d bytes", resp.Len())
	}
}

func TestUpstream_CancelWithoutDeadline(t *testing.T) {
	u, err := NewUpstream(startTestServer(t, testHandler{}), Opt{})
	if err != nil {
		t.Fatal(err)
	}
	exchange(t, u) // Cache a valid resolver certificate.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	u.dialUDP = func(context.Context) (net.Conn, error) { return client, nil }
	received := make(chan struct{})
	go func() { _, _ = server.Read(make([]byte, dns.MaxMsgSize)); close(received) }()
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	query, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	done := make(chan error, 1)
	go func() { _, err := u.ExchangeContext(ctx, query); done <- err }()
	<-received
	want := errors.New("query withdrawn")
	cancel(want)
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("cancel cause lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled query remained blocked on network read")
	}
}
