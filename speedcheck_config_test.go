package main

import (
	"context"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/speedcheck"
	"github.com/go-viper/mapstructure/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func TestSpeedcheckExampleLoadsWithoutNetworkQueries(t *testing.T) {
	for _, path := range []string{"examples/speedcheck.yaml", "examples/speedcheck-windows.yaml"} {
		t.Run(path, func(t *testing.T) { loadSpeedcheckExample(t, path) })
	}
}

func loadSpeedcheckExample(t *testing.T, path string) {
	t.Helper()
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg coremain.Config
	if err := v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) { c.TagName = "yaml" }); err != nil {
		t.Fatal(err)
	}
	// Test plugin wiring and real configuration decoding without binding a
	// public port or making any DNS requests.
	cfg.API.HTTP = ""
	var plugins []coremain.PluginConfig
	for _, p := range cfg.Plugins {
		switch p.Type {
		case "udp_server", "tcp_server", "http_server", "quic_server":
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
	if _, ok := m.GetPlugin("select_fast_ip").(*speedcheck.Selector); !ok {
		t.Fatal("speedcheck not registered")
	}
	if path == "examples/speedcheck.yaml" {
		// Both source sequences skip this reserved demonstration domain before
		// reaching forward. Exercise the documented static fallback, not a DNS
		// request to an external resolver or a probe of a documentation address.
		entry := sequence.ToExecutable(m.GetPlugin("main"))
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			q := query_context.NewContext(new(dns.Msg).SetQuestion("fallback.speedcheck.invalid.", qtype))
			err := entry.Exec(ctx, q)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if q.R() == nil || len(q.R().Answer) != 1 || q.R().Answer[0].Header().Rrtype != qtype {
				t.Fatalf("static fallback for type %d: %v", qtype, q.R())
			}
		}
		if stats := m.ProbeManager().Stats(); stats.Probes != 0 || stats.Active != 0 {
			t.Fatalf("static fallback unexpectedly started probes: %+v", stats)
		}
	}
}

func TestDocumentedExamplesUseKnownPluginParameters(t *testing.T) {
	documentedTypes := make(map[string]bool)
	for _, path := range []string{
		"examples/speedcheck.yaml",
		"examples/speedcheck-windows.yaml",
		"examples/speedcheck-full.yaml",
		"docs/examples/all-modules.yaml",
	} {
		t.Run(path, func(t *testing.T) {
			v := viper.New()
			v.SetConfigFile(path)
			if err := v.ReadInConfig(); err != nil {
				t.Fatal(err)
			}
			var cfg coremain.Config
			if err := v.UnmarshalExact(&cfg, func(c *mapstructure.DecoderConfig) { c.TagName = "yaml" }); err != nil {
				t.Fatal(err)
			}
			seen := make(map[string]bool)
			for _, p := range cfg.Plugins {
				documentedTypes[p.Type] = true
				if p.Tag == "" || seen[p.Tag] {
					t.Fatalf("empty or duplicate plugin tag %q", p.Tag)
				}
				seen[p.Tag] = true
				typeInfo, ok := coremain.GetPluginType(p.Type)
				if !ok {
					t.Fatalf("%s: unknown plugin type %q", p.Tag, p.Type)
				}
				if err := utils.WeakDecode(p.Args, typeInfo.NewArgs()); err != nil {
					t.Fatalf("%s (%s): %v", p.Tag, p.Type, err)
				}
			}
		})
	}
	for _, typ := range coremain.GetAllPluginTypes() {
		if !documentedTypes[typ] {
			t.Errorf("registered plugin %q has no documented parameter example", typ)
		}
	}
}

func TestSpeedcheckDecodePreservesEmptyInclude(t *testing.T) {
	var a speedcheck.Args
	err := utils.WeakDecode(map[string]any{
		"total_timeout":    "5s",
		"threshold_ms":     0,
		"probe":            map[string]any{"tcp_ports": []any{}, "timeout": "300ms"},
		"candidate_filter": map[string]any{"labels_include": []any{}},
	}, &a)
	if err != nil {
		t.Fatal(err)
	}
	if a.ThresholdMS == nil || *a.ThresholdMS != 0 || a.Probe.TCPPorts == nil || a.CandidateFilter == nil || a.CandidateFilter.LabelsInclude == nil {
		t.Fatal("explicit zero/empty config changed into an omitted default")
	}
}
