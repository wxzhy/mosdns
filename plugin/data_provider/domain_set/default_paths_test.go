package domain_set

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
)

func TestDefaultPathsAreInstanceScoped(t *testing.T) {
	paths := make([]string, 2)
	for i, name := range []string{"first.invalid", "second.invalid"} {
		paths[i] = filepath.Join(t.TempDir(), "custom-sites.dat")
		contents := appendSiteEntry(nil, "TEST", appendDomain(nil, geodata.TypeDomain, name))
		if err := os.WriteFile(paths[i], contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i, path := range paths {
		t.Run(path, func(t *testing.T) {
			bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(nil, geodata.Paths{GeoSite: path}))
			set, err := NewDomainSet(bp, &Args{Exps: []string{"geosite:test"}})
			if err != nil {
				t.Fatal(err)
			}
			group, err := CompileExpressions(bp, []string{"geosite:test"})
			if err != nil {
				t.Fatal(err)
			}
			for j, name := range []string{"www.first.invalid", "www.second.invalid"} {
				for _, matcher := range []MatcherGroup{*set.mg.Load(), group} {
					if _, got := matcher.Match(name); got != (i == j) {
						t.Errorf("instance %d Match(%q) = %v", i, name, got)
					}
				}
			}
			if group[0] != (*set.mg.Load())[0] {
				t.Fatal("same instance default path did not reuse the shared matcher")
			}
			// An explicit source must override a configured default, even if the
			// default file exists and has the same category name.
			override, err := CompileExpressions(bp, []string{"ext:" + paths[1-i] + ":test"})
			if err != nil {
				t.Fatal(err)
			}
			if _, got := override.Match([]string{"www.first.invalid", "www.second.invalid"}[1-i]); !got {
				t.Fatal("explicit file did not override the instance default")
			}
		})
	}
}

func TestDefaultPathLoaderCopiesPaths(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sites.dat")
	if err := os.WriteFile(file, appendSiteEntry(nil, "TEST", appendDomain(nil, geodata.TypeDomain, "example.invalid")), 0600); err != nil {
		t.Fatal(err)
	}
	paths := geodata.Paths{GeoSite: file}
	loader := NewMixLoader(paths)
	paths.GeoSite = "missing.dat"
	if err := loader.LoadExps([]string{"geosite:test"}); err != nil {
		t.Fatal(err)
	}
}
