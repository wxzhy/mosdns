package base_ip

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
)

func TestAnonymousMatcherUsesDefaultPaths(t *testing.T) {
	paths := geodata.Paths{
		GeoIP: filepath.Join(t.TempDir(), "configured-ips.dat"),
		ASN:   filepath.Join(t.TempDir(), "configured-asn.mmdb"),
	}
	bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(nil, paths))
	for _, tt := range []struct{ expression, path string }{
		{"geoip:cn", paths.GeoIP},
		{"asn:13335", paths.ASN},
	} {
		t.Run(tt.expression, func(t *testing.T) {
			_, err := NewMatcher(bp, &Args{IPs: []string{tt.expression}}, nil)
			if err == nil || !strings.Contains(err.Error(), tt.path) {
				t.Fatalf("error = %v, want a read error from configured path %q", err, tt.path)
			}
		})
	}
}

func TestLiteralMatcherWithoutContext(t *testing.T) {
	matcher, err := NewMatcher(nil, &Args{IPs: []string{"192.0.2.0/24"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.mg[0].Match(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("literal IP matcher without a plugin context did not match")
	}
}
