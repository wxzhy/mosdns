package ip_set

// Optional integration test against real v2fly geoip.dat, skipped unless
// REAL_GEODATA_DIR points to a directory containing geoip.dat.
// Download from https://github.com/v2fly/geoip/releases

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
)

func TestRealGeoipDat(t *testing.T) {
	dir := os.Getenv("REAL_GEODATA_DIR")
	if dir == "" {
		t.Skip("REAL_GEODATA_DIR not set")
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	l := netlist.NewList()
	start := time.Now()
	if err := LoadFromIPsAndFiles([]string{
		"geoip:cn",
		"geoip:private",
	}, nil, l); err != nil {
		t.Fatal(err)
	}
	l.Sort()
	t.Logf("loaded %d prefixes in %s", l.Len(), time.Since(start))

	for _, tt := range []struct {
		ip   string
		want bool
	}{
		{"1.2.4.8", true}, // cn
		{"114.114.114.114", true},
		{"223.5.5.5", true},
		{"8.8.8.8", false}, // google, not loaded
		{"1.1.1.1", false},
		{"10.0.0.1", true}, // private
		{"192.168.1.1", true},
		{"240e:f7:c000:fea::1", true}, // cn ipv6 (240e::/20 is china unicom range in geoip cn)
	} {
		if got := l.Match(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
