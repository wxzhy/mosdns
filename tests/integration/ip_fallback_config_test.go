package integration_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func TestIPFallbackExampleRunsWithoutProbes(t *testing.T) {
	v := viper.New()
	v.SetConfigFile("examples/ip-fallback.yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg coremain.Config
	if err := v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) { c.TagName = "yaml" }); err != nil {
		t.Fatal(err)
	}
	cfg.API.HTTP = ""
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
	main := sequence.ToExecutable(m.GetPlugin("main"))
	if main == nil {
		t.Fatal("missing example main sequence")
	}
	for _, tc := range []struct {
		name string
		typ  uint16
		ips  []string
	}{
		{"no-rtt.ip-fallback.invalid.", dns.TypeA, []string{"203.0.113.42", "198.51.100.42"}},
		{"no-rtt.ip-fallback.invalid.", dns.TypeAAAA, []string{"2001:db8:ffff::42"}},
		{"nodata.ip-fallback.invalid.", dns.TypeAAAA, []string{"2001:db8:ffff::42"}},
	} {
		q := query_context.NewContext(new(dns.Msg).SetQuestion(tc.name, tc.typ))
		q.SetMark(37)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := main.Exec(ctx, q)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if q.R() == nil {
			t.Fatal("example has no response")
		}
		var got []string
		for _, rr := range q.R().Answer {
			if rr.Header().Name != tc.name || rr.Header().Ttl != 60 {
				t.Fatalf("unexpected owner/TTL: %v", rr)
			}
			switch rr := rr.(type) {
			case *dns.A:
				got = append(got, rr.A.String())
			case *dns.AAAA:
				got = append(got, rr.AAAA.String())
			default:
				t.Fatalf("unexpected example answer: %v", rr)
			}
		}
		if !slices.Equal(got, tc.ips) || len(q.R().Ns) != 0 || !q.HasMark(37) || q.QQuestion().Name != tc.name || q.SnapshotResponse().ProbeStatus != query_context.ProbeUnknown {
			t.Fatalf("example failed static replacement: %v, %v", got, q.R())
		}
	}
	if stats := m.ProbeManager().Stats(); stats.Probes != 0 || stats.Active != 0 || stats.Queued != 0 {
		t.Fatalf("local example probed an address: %+v", stats)
	}
}
