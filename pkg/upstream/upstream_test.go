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

package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

func newUDPTestServer(t testing.TB, handler dns.Handler) (addr string, shutdownFunc func()) {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := udpConn.LocalAddr().String()
	ready := make(chan struct{})
	udpServer := dns.Server{
		PacketConn:        udpConn,
		Handler:           handler,
		NotifyStartedFunc: func() { close(ready) },
	}
	go udpServer.ActivateAndServe()
	<-ready
	return udpAddr, func() {
		udpServer.Shutdown()
	}
}

func newTCPTestServer(t testing.TB, handler dns.Handler) (addr string, shutdownFunc func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := l.Addr().String()
	ready := make(chan struct{})
	tcpServer := dns.Server{
		Listener:          l,
		Handler:           handler,
		MaxTCPQueries:     -1,
		NotifyStartedFunc: func() { close(ready) },
	}
	go tcpServer.ActivateAndServe()
	<-ready
	return tcpAddr, func() {
		tcpServer.Shutdown()
	}
}

func newDoTTestServer(t testing.TB, handler dns.Handler) (addr string, shutdownFunc func()) {
	serverName := "test"
	cert, err := utils.GenerateCertificate(serverName)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := new(tls.Config)
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	doTAddr := tlsListener.Addr().String()
	ready := make(chan struct{})
	doTServer := dns.Server{
		Net:               "tcp-tls",
		Listener:          tlsListener,
		TLSConfig:         tlsConfig,
		Handler:           handler,
		MaxTCPQueries:     -1,
		NotifyStartedFunc: func() { close(ready) },
	}
	go doTServer.ActivateAndServe()
	<-ready
	return doTAddr, func() {
		doTServer.Shutdown()
	}
}

type newTestServerFunc func(t testing.TB, handler dns.Handler) (addr string, shutdownFunc func())

var m = map[string]newTestServerFunc{
	"udp": newUDPTestServer,
	"tcp": newTCPTestServer,
	"tls": newDoTTestServer,
}

func Test_fastUpstream(t *testing.T) {

	// TODO: add test for doh
	// TODO: add test for socks5

	// server config
	for scheme, f := range m {
		for _, bigMsg := range [...]bool{true, false} {
			for _, latency := range [...]time.Duration{0, time.Millisecond * 10} {

				// client specific
				for _, idleTimeout := range [...]time.Duration{0, time.Second} {

					testName := fmt.Sprintf(
						"test: protocol: %s, bigMsg: %v, latency: %s, getIdleTimeout: %s",
						scheme,
						bigMsg,
						latency,
						idleTimeout,
					)

					t.Run(testName, func(t *testing.T) {
						addr, shutdownServer := f(t, &vServer{
							latency: latency,
							bigMsg:  bigMsg,
						})
						defer shutdownServer()
						u, err := NewUpstream(
							scheme+"://"+addr,
							Opt{
								IdleTimeout: time.Second,
								TLSConfig:   &tls.Config{InsecureSkipVerify: true},
							},
						)
						if err != nil {
							t.Fatal(err)
						}

						if err := testUpstream(u); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}

	}
}

func TestStampDialAddrOverride(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		addr, shutdown := newUDPTestServer(t, &vServer{})
		defer shutdown()
		stamp := (&dnsstamps.ServerStamp{Proto: dnsstamps.StampProtoTypePlain, ServerAddrStr: "127.0.0.2:1"}).String()
		u, err := NewUpstream(stamp, Opt{DialAddr: addr})
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		if err := testUpstream(u); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("dnscrypt", func(t *testing.T) {
		stampStr := startDNSCryptTestServer(t, dnscryptTestHandler{})
		stamp, err := dnsstamps.NewServerStampFromString(stampStr)
		if err != nil {
			t.Fatal(err)
		}
		addr := stamp.ServerAddrStr
		stamp.ServerAddrStr = "127.0.0.2:1"
		u, err := NewUpstream(stamp.String(), Opt{DialAddr: addr})
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		if err := testUpstream(u); err != nil {
			t.Fatal(err)
		}
	})
}

func TestQUICUpstreamClosesOwnedSocket(t *testing.T) {
	for _, addr := range []string{"quic://127.0.0.1", "h3://127.0.0.1/dns-query"} {
		t.Run(addr, func(t *testing.T) {
			u, err := NewUpstream(addr, Opt{})
			if err != nil {
				t.Fatal(err)
			}
			group := u.(*upstreamWithClose).closers[0].(*closeGroup)
			conn := group.closers[1].(net.PacketConn)
			if err := u.Close(); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("owned UDP socket remains open: %v", err)
			}
			if err := u.Close(); err != nil {
				t.Fatalf("second close failed: %v", err)
			}
		})
	}
}

// startDNSCryptTestServer starts a DNSCrypt test server (udp + tcp)
// and returns its stamp string.
func startDNSCryptTestServer(t testing.TB, h dnscrypt.Handler) string {
	t.Helper()

	rc, err := dnscrypt.GenerateResolverConfig("example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := rc.NewCert()
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	startServer := func(proto dnscrypt.Proto, addr netip.AddrPort) (*dnscrypt.Server, error) {
		t.Helper()
		s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
			Handler:      h,
			ResolverCert: cert,
			ProviderName: rc.ProviderName,
			Addr:         addr,
			Proto:        proto,
		})
		if err != nil {
			t.Fatal(err)
		}
		return s, s.Start(ctx)
	}

	// TCP and UDP have independent port availability. Keep the first listener
	// open while binding the second and retry if the shared port is unavailable.
	loopback := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)
	var lastBindErr error
	for range 10 {
		srvTCP, tcpErr := startServer(dnscrypt.ProtoTCP, loopback)
		if tcpErr != nil {
			t.Fatal(tcpErr)
		}
		addr := srvTCP.LocalAddr().(*net.TCPAddr).AddrPort()
		srvUDP, bindErr := startServer(dnscrypt.ProtoUDP, addr)
		if bindErr != nil {
			if shutdownErr := srvTCP.Shutdown(ctx); shutdownErr != nil {
				t.Fatal(errors.Join(bindErr, shutdownErr))
			}
			lastBindErr = bindErr
			continue
		}
		t.Cleanup(func() {
			_ = srvUDP.Shutdown(ctx)
			_ = srvTCP.Shutdown(ctx)
		})
		stamp, err := rc.CreateStamp(addr.String())
		if err != nil {
			t.Fatal(err)
		}
		return stamp.String()
	}
	t.Fatalf("could not bind a shared TCP/UDP port: %v", lastBindErr)
	return ""
}

type dnscryptTestHandler struct{ truncateUDP bool }

func (h dnscryptTestHandler) ServeDNS(_ context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
	res := (&dns.Msg{}).SetReply(r)
	res.Truncated = h.truncateUDP && w.RemoteAddr().Network() == "udp"
	res.Answer = append(res.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(1, 2, 3, 4).To4(),
	})
	return w.WriteMsg(context.Background(), res)
}

type testEventObserver func(Event)

func (f testEventObserver) OnEvent(e Event) { f(e) }

func TestDNSCryptWithConnectionObserver(t *testing.T) {
	stamp := startDNSCryptTestServer(t, dnscryptTestHandler{truncateUDP: true})
	var opens, closes atomic.Int32
	u, err := NewUpstream(stamp, Opt{EventObserver: testEventObserver(func(e Event) {
		switch e {
		case EventConnOpen:
			opens.Add(1)
		case EventConnClose:
			closes.Add(1)
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	payload, err := u.ExchangeContext(ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(payload)
	resp := new(dns.Msg)
	if err = resp.Unpack(*payload); err != nil || !resp.Response || resp.Truncated || resp.Id != q.Id || len(resp.Answer) != 1 {
		t.Fatalf("DNSCrypt reply after TCP retry: %v, error: %v", resp, err)
	}
	if opened, closed := opens.Load(), closes.Load(); opened != 3 || closed != 3 {
		t.Fatalf("expected certificate UDP, query UDP and query TCP; opened %d, closed %d", opened, closed)
	}
}

func TestUDPSimultaneousExchangesUseDistinctPorts(t *testing.T) {
	type source struct {
		name string
		port int
	}
	observed := make(chan source, 8)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	addr, stop := newUDPTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		select {
		case observed <- source{name: q.Question[0].Name, port: w.RemoteAddr().(*net.UDPAddr).Port}:
		default:
		}
		<-release
		_ = w.WriteMsg(new(dns.Msg).SetReply(q))
	}))
	defer stop()
	defer unblock()
	u, err := NewUpstream("udp://"+addr, Opt{})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	wires := make(chan error, 2)
	for i := range 2 {
		q := new(dns.Msg).SetQuestion(fmt.Sprintf("q%d.example.test.", i), dns.TypeA)
		b, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			r, err := u.ExchangeContext(ctx, b)
			if r != nil {
				pool.ReleaseBuf(r)
			}
			wires <- err
		}()
	}
	ports := make(map[string]int)
	for len(ports) != 2 {
		select {
		case src := <-observed:
			ports[src.name] = src.port
		case <-ctx.Done():
			t.Fatal("missing concurrent UDP exchange")
		}
	}
	if ports["q0.example.test."] == ports["q1.example.test."] {
		t.Fatalf("two pending DNS exchanges share a source port: %v", ports)
	}
	unblock()
	for range 2 {
		select {
		case err := <-wires:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("UDP exchange did not finish")
		}
	}
}

func Test_sdnsUpstream(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		addr, shutdownServer := newUDPTestServer(t, &vServer{})
		defer shutdownServer()
		stampStr := (&dnsstamps.ServerStamp{
			Proto:         dnsstamps.StampProtoTypePlain,
			ServerAddrStr: addr,
		}).String()

		u, err := NewUpstream(stampStr, Opt{})
		if err != nil {
			t.Fatal(err)
		}
		if err := testUpstream(u); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("dnscrypt", func(t *testing.T) {
		stampStr := startDNSCryptTestServer(t, dnscryptTestHandler{})

		u, err := NewUpstream(stampStr, Opt{})
		if err != nil {
			t.Fatal(err)
		}
		if err := testUpstream(u); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unsupported-stamp-proto", func(t *testing.T) {
		// Stamp with an unknown protocol id (0x05).
		stampStr := "sdns://" + base64.RawURLEncoding.EncodeToString([]byte{0x05})
		if _, err := NewUpstream(stampStr, Opt{}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func testUpstream(u Upstream) error {
	wg := sync.WaitGroup{}
	errs := make([]error, 0)
	errsLock := sync.Mutex{}
	logErr := func(err error) {
		errsLock.Lock()
		errs = append(errs, err)
		errsLock.Unlock()
	}
	errsToString := func() string {
		s := fmt.Sprintf("%d err(s) occured during the test: ", len(errs))
		for i := range errs {
			s = s + errs[i].Error() + "|"
		}
		return s
	}

	for i := uint16(0); i < 10; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()

			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			q.Id = i
			queryPayload, err := q.Pack()
			if err != nil {
				logErr(err)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, err := u.ExchangeContext(ctx, queryPayload)
			if err != nil {
				logErr(err)
				return
			}

			resp := new(dns.Msg)
			err = resp.Unpack(*r)
			if err != nil {
				logErr(err)
				return
			}
			if q.Id != resp.Id {
				logErr(dns.ErrId)
				return
			}
			if !resp.Response {
				logErr(fmt.Errorf("resp is not a resp bit"))
				return
			}
		}()
	}

	wg.Wait()
	if len(errs) != 0 {
		return errors.New(errsToString())
	}
	return nil
}

type vServer struct {
	latency time.Duration
	bigMsg  bool // with 1kb padding
}

var padding = make([]byte, 1024)

func (s *vServer) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	r := new(dns.Msg)
	r.SetReply(q)
	if s.bigMsg {
		r.SetEdns0(dns.MaxMsgSize, false)
		opt := r.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: padding})
	}

	time.Sleep(s.latency)
	w.WriteMsg(r)
}
