package base_domain

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
)

func TestAnonymousMatcherUsesDefaultGeositePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configured-sites.dat")
	bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(nil, geodata.Paths{GeoSite: path}))
	_, err := NewMatcher(bp, &Args{Exps: []string{"geosite:cn"}}, nil)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %v, want a read error from configured path %q", err, path)
	}
}

func TestLiteralMatcherWithoutContext(t *testing.T) {
	matcher, err := NewMatcher(nil, &Args{Exps: []string{"domain:example.invalid"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := matcher.mg[0].Match("www.example.invalid"); !ok {
		t.Fatal("literal domain matcher without a plugin context did not match")
	}
}
