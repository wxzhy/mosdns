package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/ip_replace"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func TestIPReplaceDecodePreservesExplicitZeroPrefix(t *testing.T) {
	var args ip_replace.Args
	if err := utils.WeakDecode(map[string]any{"replace_map": []any{map[string]any{
		"match_ip":       []any{"0.0.0.0/0", "::/0"},
		"ipv4_prefixlen": 0, "ipv6_prefixlen": 0,
		"ipv4": []any{"203.0.113.99"}, "ipv6": []any{"2001:db8::99"},
	}}}, &args); err != nil {
		t.Fatal(err)
	}
	if len(args.ReplaceMap) != 1 || args.ReplaceMap[0].IPv4PrefixLen == nil || args.ReplaceMap[0].IPv6PrefixLen == nil || *args.ReplaceMap[0].IPv4PrefixLen != 0 || *args.ReplaceMap[0].IPv6PrefixLen != 0 {
		t.Fatalf("explicit zero prefix became an omitted default: %+v", args)
	}
	if _, err := ip_replace.New(nil, &args); err != nil {
		t.Fatal(err)
	}
}

func TestIPReplaceExampleRunsWithoutNetworkQueries(t *testing.T) {
	v := viper.New()
	v.SetConfigFile("examples/ip-replace.yaml")
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
		switch p.Type {
		case "udp_server", "tcp_server":
		default:
			plugins = append(plugins, p)
		}
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
	entry := sequence.ToExecutable(m.GetPlugin("main"))
	if entry == nil {
		t.Fatal("example main is not executable")
	}
	for _, tc := range []struct {
		qtype uint16
		want  []string
	}{
		{dns.TypeA, []string{"203.0.113.42", "198.51.100.42"}},
		{dns.TypeAAAA, []string{"2001:db8:100::42"}},
	} {
		q := query_context.NewContext(new(dns.Msg).SetQuestion("cdn.ip-replace.invalid.", tc.qtype))
		q.SetMark(37)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := entry.Exec(ctx, q)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		if q.R() == nil {
			t.Fatal("missing local example response")
		}
		for _, rr := range q.R().Answer {
			if rr.Header().Name != "cdn.ip-replace.invalid." {
				t.Fatalf("replaced RRset owner changed: %v", rr)
			}
			switch rr := rr.(type) {
			case *dns.A:
				got = append(got, rr.A.String())
			case *dns.AAAA:
				got = append(got, rr.AAAA.String())
			default:
				t.Fatalf("unexpected example RR: %v", rr)
			}
		}
		if !slices.Equal(got, tc.want) || !q.HasMark(37) || q.QQuestion().Name != "cdn.ip-replace.invalid." {
			t.Fatalf("type=%d addresses=%v want=%v or parent query/marks changed", tc.qtype, got, tc.want)
		}
	}
}
