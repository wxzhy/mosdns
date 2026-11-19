package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestCernetGoogleCNAttributionAndRedirector(t *testing.T) {
	cfg := smartdnsMigrationConfig(t, "examples/smartdns/config-cernet.yaml")
	f := smartdnsPolicyInstance(t, cfg, func(_ string, query *dns.Msg) *dns.Msg {
		ip := "192.0.2.42"
		if query.Question[0].Qtype == dns.TypeAAAA {
			ip = "2001:db8::42"
		}
		return smartdnsPolicyAddressReply(query, "", ip)
	}, nil)
	for _, tc := range []struct {
		name  string
		route string
	}{
		{"google-cn.migration.invalid.", "route_google_cn"},
		{"google-attr.migration.invalid.", "route_google_cn"},
		{"redirector.googlevideo.com.", "route_google_cn"},
		{"google.migration.invalid.", "route_global"},
		{"notredirector.googlevideo.com.", "route_default"},
	} {
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
			t.Run(tc.name+dns.TypeToString[typ], func(t *testing.T) {
				q, err := f.exec(t, "resolve_base", tc.name, typ, false)
				smartdnsPolicyRequireSuccess(t, q, err)
				for route, mark := range smartdnsMigrationRouteMarks {
					if q.HasMark(mark) != (route == tc.route) {
						t.Fatalf("%s selected=%v, want %s", route, q.HasMark(mark), tc.route)
					}
				}
			})
		}
	}
}

func TestCernetGoogleFallbackExemptions(t *testing.T) {
	cfg := smartdnsMigrationConfig(t, "examples/smartdns/config-cernet.yaml")
	f := smartdnsPolicyInstance(t, cfg, func(_ string, query *dns.Msg) *dns.Msg {
		ip := "198.51.100.42"
		if query.Question[0].Qtype == dns.TypeAAAA {
			ip = "2001:db8:ffff::42"
		}
		return smartdnsPolicyAddressReply(query, "", ip)
	}, nil)
	entry := sequence.ToExecutable(f.plugins["apply_fallback"])
	check := func(t *testing.T, name, alias string, typ uint16, exempt bool) {
		t.Helper()
		q := query_context.NewContext(new(dns.Msg).SetQuestion(name, typ))
		// A CNAME-only NOERROR response triggers NODATA fallback unless exempt.
		// Put a synthetic Google name on the opposite side of each exemption
		// so the ordinary Google inclusion gate cannot make the test pass.
		q.SetResponse(smartdnsPolicyAddressReply(q.Q(), alias))
		before := q.R().String()
		calls, _ := f.observations()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := entry.Exec(ctx, q)
		smartdnsPolicyRequireSuccess(t, q, err)
		after, _ := f.observations()
		if exempt {
			if q.R().String() != before || len(after) != len(calls) {
				t.Fatalf("exemption changed the response or resolved fallback targets: %v", q.R())
			}
		} else if len(smartdnsMigrationAnswerIPs(q)) != 1 || len(after) != len(calls)+1 {
			t.Fatalf("control did not trigger dynamic fallback: %v", q.R())
		}
	}
	for _, domain := range []string{
		"supl.google.com", "bdn.dev", "c.chat.google.com", "c.mail.google.com",
		"c.pack.google.com", "c.play.google.com", "c.youtubeeducation.com",
		"gcpcdn.gvt1.com", "gvt1.com", "offline-maps.gvt1.com", "snap.gvt1.com",
		"xn--ngstr-lra8j.com", "googlevideo.com",
	} {
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
			t.Run(domain+"/"+dns.TypeToString[typ], func(t *testing.T) {
				for _, name := range []string{domain + ".", "sub." + domain + "."} {
					check(t, name, "google.migration.invalid.", typ, true)
					check(t, "google.migration.invalid.", name, typ, true)
				}
			})
		}
	}
	for _, name := range []string{"notsupl.google.com.", "notbdn.dev.", "googlevideo.com.evil.invalid."} {
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
			t.Run(strings.TrimSuffix(name, ".")+"/"+dns.TypeToString[typ], func(t *testing.T) {
				check(t, name, "google.migration.invalid.", typ, false)
				check(t, "google.migration.invalid.", name, typ, false)
			})
		}
	}
}
