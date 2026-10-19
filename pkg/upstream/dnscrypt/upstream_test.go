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
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// startTestServer starts a DNSCrypt test server (udp + tcp) and returns
// its stamp string.
func startTestServer(t testing.TB, h dnscrypt.Handler) (stampStr string) {
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
			Logger:       nil,
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
