package ip_set

// Optional integration tests against real geo databases, skipped unless
// REAL_GEODATA_DIR points to a directory containing them.
// geoip.dat: https://github.com/v2fly/geoip/releases
// GeoLite2-ASN.mmdb / geoip.metadb:
// https://github.com/MetaCubeX/meta-rules-dat/releases

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

func realGeodataDir(t *testing.T) {
	t.Helper()
	dir := os.Getenv("REAL_GEODATA_DIR")
	if dir == "" {
		t.Skip("REAL_GEODATA_DIR not set")
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(wd) })
}

func TestRealGeoipDat(t *testing.T) {
	realGeodataDir(t)

	loader := NewListLoader()
	start := time.Now()
	if err := loader.LoadFromIPsAndFiles([]string{
		"geoip:cn",
		"geoip:private",
	}, nil); err != nil {
		t.Fatal(err)
	}
	mg := MatcherGroup(loader.Matchers())
	t.Logf("loaded in %s", time.Since(start))

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
		if got := mg.Match(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestRealGeoipCountryMMDB(t *testing.T) {
	realGeodataDir(t)

	// Country.mmdb is an official GeoLite2-Country database; the ext syntax
	// auto-detects the format from the file content.
	loader := NewListLoader()
	if err := loader.LoadFromIPsAndFiles([]string{"ext:Country.mmdb:cn"}, nil); err != nil {
		t.Fatal(err)
	}
	mg := MatcherGroup(loader.Matchers())
	for _, tt := range []struct {
		ip   string
		want bool
	}{
		{"1.2.4.8", true},
		{"223.5.5.5", true},
		{"240e:f7:c000:fea::1", true},
		{"8.8.8.8", false},
	} {
		if got := mg.Match(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestRealASN(t *testing.T) {
	realGeodataDir(t)

	loader := NewListLoader()
	start := time.Now()
	if err := loader.LoadFromIPsAndFiles([]string{
		"asn:13335", // cloudflare
		"asn:15169", // google
		"asn:4134",  // chinanet
	}, nil); err != nil {
		t.Fatal(err)
	}
	mg := MatcherGroup(loader.Matchers())
	t.Logf("loaded in %s", time.Since(start))

	for _, tt := range []struct {
		ip   string
		want bool
	}{
		{"1.1.1.1", true}, // as13335
		{"104.16.132.229", true},
		{"8.8.8.8", true}, // as15169
		{"8.8.4.4", true},
		{"2001:4860:4860::8888", true}, // google dns v6, as15169
		{"240e:f7::1", true},           // chinanet, as4134
		{"9.9.9.9", false},             // quad9
		{"223.5.5.5", false},           // alidns, as45102
	} {
		if got := mg.Match(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
