//go:build windows

package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/server_utils"
	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func TestWindowsSpeedcheckEndToEnd(t *testing.T) {
	for _, family := range []struct {
		name, network, bind, ip string
		qtype                   uint16
		icmp                    bool
	}{
		{"IPv4_TCP", "tcp4", "127.0.0.1:0", "127.0.0.1", dns.TypeA, false},
		{"IPv6_TCP", "tcp6", "[::1]:0", "::1", dns.TypeAAAA, false},
		{"IPv4_TCP_ICMP", "tcp4", "127.0.0.1:0", "127.0.0.1", dns.TypeA, true},
		{"IPv6_TCP_ICMP", "tcp6", "[::1]:0", "::1", dns.TypeAAAA, true},
	} {
		t.Run(family.name, func(t *testing.T) {
			probeListener, err := net.Listen(family.network, family.bind)
			if err != nil {
				t.Fatalf("local TCP listener: %v", err)
			}
			probeDone := make(chan struct{})
			go func() {
				defer close(probeDone)
				for {
					c, err := probeListener.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
			defer func() { _ = probeListener.Close(); <-probeDone }()
			slowStarted, releaseSlow := make(chan struct{}), make(chan struct{})
			var slowOnce sync.Once
			startDNS := func(handler dns.HandlerFunc) (*dns.Server, string) {
				t.Helper()
				pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ready := make(chan struct{})
				s := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
				go func() { _ = s.ActivateAndServe() }()
				<-ready
				return s, "udp://" + pc.LocalAddr().String()
			}
			fast, fastAddr := startDNS(func(w dns.ResponseWriter, q *dns.Msg) {
				select {
				case <-slowStarted:
				case <-releaseSlow:
					return
				}
				time.Sleep(10 * time.Millisecond)
				r := new(dns.Msg).SetReply(q)
				h := dns.RR_Header{Name: q.Question[0].Name, Rrtype: family.qtype, Class: dns.ClassINET, Ttl: 60}
				if family.qtype == dns.TypeA {
					r.Answer = []dns.RR{&dns.A{Hdr: h, A: net.ParseIP(family.ip).To4()}}
				} else {
					r.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP(family.ip)}}
				}
				_ = w.WriteMsg(r)
			})
			slow, slowAddr := startDNS(func(w dns.ResponseWriter, q *dns.Msg) {
				slowOnce.Do(func() { close(slowStarted) })
				<-releaseSlow
				_ = w.WriteMsg(new(dns.Msg).SetReply(q))
			})
			defer func() { close(releaseSlow); _ = fast.Shutdown(); _ = slow.Shutdown() }()
			v := viper.New()
			v.SetConfigFile("examples/speedcheck-windows.yaml")
			if err := v.ReadInConfig(); err != nil {
				t.Fatal(err)
			}
			var cfg coremain.Config
			if err := v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) { c.TagName = "yaml" }); err != nil {
				t.Fatal(err)
			}
			cfg.Log.Level = "error"
			var plugins []coremain.PluginConfig
			for _, p := range cfg.Plugins {
				switch p.Tag {
				case "upstream_a":
					p.Args = map[string]any{"upstreams": []map[string]any{{"addr": fastAddr}}}
				case "upstream_b":
					p.Args = map[string]any{"upstreams": []map[string]any{{"addr": slowAddr}}}
				case "select_fast_ip":
					p.Args.(map[string]any)["probe"] = map[string]any{"tcp_ports": []int{probeListener.Addr().(*net.TCPAddr).Port}, "icmp": family.icmp, "timeout": "300ms"}
				case "udp_listener", "tcp_listener":
					continue // Bind ephemeral listeners below.
				}
				plugins = append(plugins, p)
			}
			cfg.Plugins = plugins
			m, err := coremain.NewMosdns(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				m.CloseWithErr(nil)
				if err := m.GetSafeClose().WaitClosed(); err != nil {
					t.Error(err)
				}
			}()
			handler, err := server_utils.NewHandler(coremain.NewBP("windows-test", m), "main")
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				_ = udp.Close()
				t.Fatal(err)
			}
			udpDone, tcpDone := make(chan struct{}), make(chan struct{})
			go func() { defer close(udpDone); _ = server.ServeUDP(udp, handler, server.UDPServerOpts{}) }()
			go func() { defer close(tcpDone); _ = server.ServeTCP(tcp, handler, server.TCPServerOpts{}) }()
			defer func() { _ = udp.Close(); _ = tcp.Close(); <-udpDone; <-tcpDone }()
			for _, client := range []struct{ network, addr string }{{"udp", udp.LocalAddr().String()}, {"tcp", tcp.Addr().String()}} {
				q := new(dns.Msg).SetQuestion("windows.speedcheck.test.", family.qtype)
				r, rtt, err := (&dns.Client{Net: client.network, Timeout: 2 * time.Second}).Exchange(q, client.addr)
				if err != nil {
					t.Fatal(err)
				}
				if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
					t.Fatalf("invalid selected response: %v", r)
				}
				got := ""
				switch rr := r.Answer[0].(type) {
				case *dns.A:
					got = rr.A.String()
				case *dns.AAAA:
					got = rr.AAAA.String()
				}
				if got != family.ip {
					t.Fatalf("selected %q, want %q", got, family.ip)
				}
				t.Logf("%s DNS selected %s in %s while the other upstream remained blocked", client.network, got, rtt)
			}
			maxProbes := uint64(1)
			if family.icmp {
				maxProbes = 2
			}
			if stats := m.ProbeManager().Stats(); stats.Probes < 1 || stats.Probes > maxProbes || stats.CacheHits < 1 {
				t.Fatalf("raw probe cache not shared across DNS transports: %+v", stats)
			}
			m.CloseWithErr(nil)
			_ = m.GetSafeClose().WaitClosed()
			if stats := m.ProbeManager().Stats(); stats.Active != 0 || stats.Queued != 0 || stats.Flights != 0 {
				t.Fatalf("shutdown retained probes: %+v", stats)
			}
		})
	}
}
