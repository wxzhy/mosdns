package domain_set

// Optional integration test against real v2fly dlc.dat, skipped unless
// REAL_GEODATA_DIR points to a directory containing geosite.dat.
// Download from https://github.com/v2fly/domain-list-community/releases
// (asset dlc.dat, rename to geosite.dat).

import (
	"os"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

func TestRealGeositeDat(t *testing.T) {
	dir := os.Getenv("REAL_GEODATA_DIR")
	if dir == "" {
		t.Skip("REAL_GEODATA_DIR not set")
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	m := domain.NewDomainMixMatcher()
	start := time.Now()
	err := LoadExpsAndFiles([]string{
		"geosite:cn",
		"geosite:geolocation-!cn@cn",
	}, nil, m)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded %d patterns in %s", m.Len(), elapsed)

	for _, tt := range []struct {
		qname string
		want  bool
	}{
		{"qq.com", true},
		{"www.qq.com", true},
		{"baidu.com", true},
		{"163.com", true},
		{"google.com", false},
		{"github.com", false},
	} {
		if _, got := m.Match(tt.qname); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.qname, got, tt.want)
		}
	}

	// The @ads attr filter must keep a subset of the unfiltered entry.
	unfiltered := domain.NewDomainMixMatcher()
	if err := LoadExpsAndFiles([]string{"geosite:category-ads-all"}, nil, unfiltered); err != nil {
		t.Fatal(err)
	}
	filtered := domain.NewDomainMixMatcher()
	if err := LoadExpsAndFiles([]string{"geosite:category-ads-all@ads"}, nil, filtered); err != nil {
		t.Fatal(err)
	}
	t.Logf("category-ads-all: %d patterns, @ads filtered: %d", unfiltered.Len(), filtered.Len())
	if filtered.Len() == 0 || filtered.Len() >= unfiltered.Len() {
		t.Errorf("attr filter ineffective: %d vs %d", filtered.Len(), unfiltered.Len())
	}
}
