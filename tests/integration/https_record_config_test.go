package integration_test

import (
	"net"
	"slices"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/server_utils"
	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"go.uber.org/zap/zaptest"
)

func TestHTTPSRecordExampleDNSRoundTrip(t *testing.T) {
	v := viper.New()
	v.SetConfigFile("examples/https-record.yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg coremain.Config
	if err := v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) { c.TagName = "yaml" }); err != nil {
		t.Fatal(err)
	}
	cfg.API.HTTP = ""
	cfg.Log.Level = "error"
	var plugins []coremain.PluginConfig
	for _, p := range cfg.Plugins {
		if p.Type != "udp_server" && p.Type != "tcp_server" {
			plugins = append(plugins, p)
		}
	}
	cfg.Plugins = plugins
	m, err := coremain.NewMosdns(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.CloseWithErr(nil)
		if err := m.GetSafeClose().WaitClosed(); err != nil {
			t.Error(err)
		}
	})
	h, err := server_utils.NewHandler(coremain.NewBP("roundtrip", m), "main")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	udpDone, tcpDone := make(chan struct{}), make(chan struct{})
	udpErr := make(chan error, 1)
	go func() {
		defer close(udpDone)
		udpErr <- server.ServeUDP(udp, h, server.UDPServerOpts{Logger: zaptest.NewLogger(t)})
	}()
	go func() { defer close(tcpDone); _ = server.ServeTCP(tcp, h, server.TCPServerOpts{}) }()
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close(); <-udpDone; <-tcpDone })
	for _, transport := range []struct{ network, addr string }{{"udp", udp.LocalAddr().String()}, {"tcp", tcp.Addr().String()}} {
		for _, tc := range []struct {
			name string
			typ  uint16
			do   bool
		}{
			{"hint", dns.TypeHTTPS, false},
			{"hintless", dns.TypeHTTPS, false},
			{"nodata", dns.TypeHTTPS, false},
			{"alias", dns.TypeHTTPS, false},
			{"svcb", dns.TypeSVCB, false},
			{"hint", dns.TypeHTTPS, true},
			{"nodata", dns.TypeHTTPS, true},
			{"gate-target", dns.TypeA, false},
		} {
			t.Run(transport.network+"/"+tc.name+"/"+map[bool]string{false: "policy", true: "DO"}[tc.do], func(t *testing.T) {
				q := new(dns.Msg).SetQuestion(tc.name+".https-record.invalid.", tc.typ)
				q.SetEdns0(1232, tc.do)
				r, _, err := (&dns.Client{Net: transport.network, Timeout: 2 * time.Second}).Exchange(q, transport.addr)
				if err != nil {
					if transport.network == "udp" {
						select {
						case serveErr := <-udpErr:
							t.Fatalf("UDP listener stopped: %v; exchange: %v", serveErr, err)
						default:
						}
					}
					t.Fatal(err)
				}
				if r.Rcode != dns.RcodeSuccess || r.Id != q.Id || len(r.Question) != 1 || r.Question[0] != q.Question[0] || r.Truncated {
					t.Fatalf("invalid DNS response: %v", r)
				}
				if r.IsEdns0() == nil || r.IsEdns0().Do() != tc.do {
					t.Fatal("downstream EDNS/DO was lost")
				}
				if tc.do && tc.name == "nodata" {
					if len(r.Answer) != 0 {
						t.Fatal("DO NODATA synthesized")
					}
					return
				}
				if len(r.Answer) != 1 {
					t.Fatalf("expected single RR: %v", r)
				}
				if tc.typ == dns.TypeA {
					if rr, ok := r.Answer[0].(*dns.A); !ok || rr.A.String() != "192.0.2.20" {
						t.Fatalf("A route lost: %v", r)
					}
					return
				}
				var binding *dns.SVCB
				switch rr := r.Answer[0].(type) {
				case *dns.HTTPS:
					binding = &rr.SVCB
				case *dns.SVCB:
					binding = rr
				default:
					t.Fatalf("unexpected binding type: %v", rr)
				}
				if binding.Hdr.Rrtype != tc.typ || binding.Hdr.Name != q.Question[0].Name {
					t.Fatal("binding owner/type changed")
				}
				if tc.name == "alias" {
					if binding.Priority != 0 || len(binding.Value) != 0 || binding.Target != "gate-target.https-record.invalid." {
						t.Fatal("AliasMode changed")
					}
					return
				}
				params := make(map[dns.SVCBKey]dns.SVCBKeyValue)
				for _, p := range binding.Value {
					params[p.Key()] = p
				}
				if tc.do {
					if params[dns.SVCB_ECHCONFIG] != nil || params[dns.SVCB_IPV4HINT] == nil || !slices.Contains(params[dns.SVCB_ALPN].(*dns.SVCBAlpn).Alpn, "h3") {
						t.Fatal("DO response rewritten")
					}
					return
				}
				if params[dns.SVCB_ECHCONFIG] == nil || params[dns.SVCB_IPV4HINT] != nil || params[dns.SVCB_IPV6HINT] != nil || params[dns.SVCB_NO_DEFAULT_ALPN] != nil {
					t.Fatalf("incomplete binding policy: %v", r)
				}
				if alpn, ok := params[dns.SVCB_ALPN].(*dns.SVCBAlpn); ok && slices.Contains(alpn.Alpn, "h3") {
					t.Fatal("h3 was retained")
				}
				if mandatory, ok := params[dns.SVCB_MANDATORY].(*dns.SVCBMandatory); ok {
					for _, key := range mandatory.Code {
						if params[key] == nil {
							t.Fatal("dangling mandatory key")
						}
					}
				}
				if (tc.name == "hintless" || tc.name == "nodata") && binding.Hdr.Ttl > 10 {
					t.Fatal("binding outlived A source")
				}
				if tc.name == "nodata" && (len(r.Ns) != 0 || binding.Target != "." || binding.Priority != 1) {
					t.Fatal("invalid NODATA synthesis")
				}
				if r.AuthenticatedData || r.Authoritative {
					t.Fatal("rewritten response retained AD/AA")
				}
			})
		}
	}
	if stats := m.ProbeManager().Stats(); stats.Probes != 0 || stats.Active != 0 || stats.Queued != 0 {
		t.Fatalf("offline example started probes: %+v", stats)
	}
}
