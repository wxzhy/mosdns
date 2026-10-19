package domain_set

// Optional integration test against real v2fly dlc.dat, skipped unless
// REAL_GEODATA_DIR points to a directory containing geosite.dat.
// Download from https://github.com/v2fly/domain-list-community/releases
// (asset dlc.dat, rename to geosite.dat).

import (
	"os"
	"testing"
	"time"
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

	loader := NewMixLoader()
	start := time.Now()
	err := loader.LoadExpsAndFiles([]string{
		"geosite:cn",
		"geosite:geolocation-!cn@cn",
	}, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	mg := MatcherGroup(loader.Matchers())
	t.Logf("loaded in %s", elapsed)

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
		if _, got := mg.Match(tt.qname); got != tt.want {
			t.Errorf("Match(%s) = %v, want %v", tt.qname, got, tt.want)
		}
	}

	// The @ads attr filter must keep a subset of the unfiltered entry.
	unfiltered := NewMixLoader()
	if err := unfiltered.LoadExpsAndFiles([]string{"geosite:category-ads-all"}, nil); err != nil {
		t.Fatal(err)
	}
	filtered := NewMixLoader()
	if err := filtered.LoadExpsAndFiles([]string{"geosite:category-ads-all@ads"}, nil); err != nil {
		t.Fatal(err)
	}
	nUnfiltered, nFiltered := matcherLen(t, unfiltered), matcherLen(t, filtered)
	t.Logf("category-ads-all: %d patterns, @ads filtered: %d", nUnfiltered, nFiltered)
	if nFiltered == 0 || nFiltered >= nUnfiltered {
		t.Errorf("attr filter ineffective: %d vs %d", nFiltered, nUnfiltered)
	}
}

// matcherLen counts the patterns of a loader whose matchers are all
// *domain.MixMatcher (true for geosite entries).
func matcherLen(t *testing.T, l *MixLoader) int {
	t.Helper()
	m := l.Matchers()
	if len(m) != 1 {
		t.Fatalf("got %d matchers, want 1", len(m))
	}
	type counter interface{ Len() int }
	c, ok := m[0].(counter)
	if !ok {
		t.Fatal("matcher has no Len method")
	}
	return c.Len()
}
