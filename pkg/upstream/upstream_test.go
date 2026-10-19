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
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
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
	udpServer := dns.Server{
		PacketConn: udpConn,
		Handler:    handler,
	}
	go udpServer.ActivateAndServe()
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
	tcpServer := dns.Server{
		Listener:      l,
		Handler:       handler,
		MaxTCPQueries: -1,
	}
	go tcpServer.ActivateAndServe()
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
	doTServer := dns.Server{
		Net:           "tcp-tls",
		Listener:      tlsListener,
		TLSConfig:     tlsConfig,
		Handler:       handler,
		MaxTCPQueries: -1,
	}
	go doTServer.ActivateAndServe()
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

// startDNSCryptTestServer starts a DNSCrypt test server (udp + tcp)
// and returns its stamp string.
func startDNSCryptTestServer(t testing.TB, h dnscrypt.Handler) (stampStr string) {
	t.Helper()

	rc, err := dnscrypt.GenerateResolverConfig("example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := rc.NewCert()
	if err != nil {
		t.Fatal(err)
	}

	startServer := func(proto dnscrypt.Proto, addr netip.AddrPort) *dnscrypt.Server {
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
		if err := s.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		return s
	}

	srvUDP := startServer(dnscrypt.ProtoUDP, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0))
	t.Cleanup(func() { _ = srvUDP.Shutdown(context.Background()) })

	addrStr := srvUDP.LocalAddr().String()
	stamp, err := rc.CreateStamp(addrStr)
	if err != nil {
		t.Fatal(err)
	}

	srvTCP := startServer(dnscrypt.ProtoTCP, netip.MustParseAddrPort(addrStr))
	t.Cleanup(func() { _ = srvTCP.Shutdown(context.Background()) })

	return stamp.String()
}

type dnscryptTestHandler struct{}

func (dnscryptTestHandler) ServeDNS(_ context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
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
	return w.WriteMsg(context.Background(), res)
}

func Test_sdnsUpstream(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		addr, shutdownServer := newUDPTestServer(t, &vServer{})
		defer shutdownServer()
		stampStr := (&dnsstamps.ServerStamp{
			Proto:        dnsstamps.StampProtoTypePlain,
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
