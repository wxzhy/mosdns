package ip_set

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
)

func TestDefaultPathsAreInstanceScoped(t *testing.T) {
	paths := make([]string, 2)
	for i, ip := range [][]byte{{192, 0, 2, 0}, {198, 51, 100, 0}} {
		paths[i] = filepath.Join(t.TempDir(), "custom-ips.dat")
		contents := appendIPEntry(nil, "TEST", appendCIDR(nil, ip, 24), false)
		if err := os.WriteFile(paths[i], contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i, path := range paths {
		t.Run(path, func(t *testing.T) {
			bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(nil, geodata.Paths{GeoIP: path}))
			set, err := NewIPSet(bp, &Args{IPs: []string{"geoip:test"}})
			if err != nil {
				t.Fatal(err)
			}
			group, err := CompileExpressions(bp, []string{"geoip:test"})
			if err != nil {
				t.Fatal(err)
			}
			for j, ip := range []string{"192.0.2.1", "198.51.100.1"} {
				for _, matcher := range []MatcherGroup{set.GetIPMatcher().(MatcherGroup), group} {
					if got := matcher.Match(netip.MustParseAddr(ip)); got != (i == j) {
						t.Errorf("instance %d Match(%q) = %v", i, ip, got)
					}
				}
			}
			if group[0] != set.GetIPMatcher().(MatcherGroup)[0] {
				t.Fatal("same instance default path did not reuse the shared matcher")
			}
			override, err := CompileExpressions(bp, []string{"ext:" + paths[1-i] + ":test"})
			if err != nil {
				t.Fatal(err)
			}
			if !override.Match(netip.MustParseAddr([]string{"192.0.2.1", "198.51.100.1"}[1-i])) {
				t.Fatal("explicit file did not override the instance default")
			}
		})
	}
}

func TestDefaultPathLoaderCopiesPaths(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ips.dat")
	if err := os.WriteFile(file, appendIPEntry(nil, "TEST", appendCIDR(nil, []byte{192, 0, 2, 0}, 24), false), 0600); err != nil {
		t.Fatal(err)
	}
	paths := geodata.Paths{GeoIP: file}
	loader := NewListLoader(paths)
	paths.GeoIP = "missing.dat"
	if err := loader.LoadFromIPs([]string{"geoip:test"}); err != nil {
		t.Fatal(err)
	}
}
