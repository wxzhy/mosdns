package domain_set

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

type expressionDomainProvider struct{ matcher domain.Matcher[struct{}] }

func (p expressionDomainProvider) GetDomainMatcher() domain.Matcher[struct{}] { return p.matcher }

func TestCompileExpressions(t *testing.T) {
	file := filepath.Join(t.TempDir(), "domain list.txt")
	if err := os.WriteFile(file, []byte("full:from-file.invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewDomainSet(nil, &Args{Exps: []string{"domain:provider.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(map[string]any{"domains": provider}))
	group, err := CompileExpressions(bp, []string{" full:literal.invalid ", " &" + file + " ", " $domains "})
	if err != nil {
		t.Fatal(err)
	}
	if len(group) != 2 {
		t.Fatalf("got %d matchers, want provider and local loader", len(group))
	}
	if _, ok := group[0].Match("www.provider.invalid"); !ok {
		t.Fatal("provider matcher must precede the local mix matcher")
	}
	if _, ok := group[0].Match("literal.invalid"); ok {
		t.Fatal("local expression was placed before the provider")
	}
	for name, want := range map[string]bool{
		"literal.invalid": true, "from-file.invalid": true, "www.provider.invalid": true, "other.invalid": false,
	} {
		if _, got := group.Match(name); got != want {
			t.Errorf("Match(%s) = %v, want %v", name, got, want)
		}
	}
	if _, err := CompileExpressions(nil, []string{"&" + file, "full:literal.invalid"}); err != nil {
		t.Fatal(err)
	}
}

func TestCompileExpressionsEmpty(t *testing.T) {
	for _, expressions := range [][]string{nil, {}} {
		group, err := CompileExpressions(nil, expressions)
		if err != nil || len(group) != 0 {
			t.Fatalf("empty expressions: group=%v err=%v", group, err)
		}
		if _, ok := group.Match("example.invalid"); ok {
			t.Fatal("empty expression group matched a domain")
		}
	}
}

func TestCompileExpressionsErrors(t *testing.T) {
	bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(map[string]any{
		"wrong": struct{}{}, "nil_matcher": expressionDomainProvider{},
	}))
	tests := []struct {
		name, expression, message string
		bp                        *coremain.BP
	}{
		{"empty", "  ", "empty expression", nil},
		{"bare_provider", "$", "empty domain set reference", bp},
		{"bare_file", "&", "empty file expression", nil},
		{"no_context", "$domains", "without a plugin context", nil},
		{"missing", "$missing", "DomainMatcherProvider", bp},
		{"wrong_type", "$wrong", "DomainMatcherProvider", bp},
		{"nil_matcher", "$nil_matcher", "nil domain matcher", bp},
		{"bad_regexp", "regexp:[", "failed to load expression", nil},
		{"missing_file", "&" + filepath.Join(t.TempDir(), "missing.txt"), "failed to load file", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileExpressions(tt.bp, []string{tt.expression})
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("error = %v, want %q", err, tt.message)
			}
		})
	}
}

func TestCompileExpressionsGeosite(t *testing.T) {
	dat := filepath.Join(t.TempDir(), "geosite.dat")
	contents := appendSiteEntry(nil, "TEST", appendDomain(nil, geodata.TypeDomain, "example.invalid"))
	if err := os.WriteFile(dat, contents, 0600); err != nil {
		t.Fatal(err)
	}
	group, err := CompileExpressions(nil, []string{"ext:" + dat + ":test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := group.Match("www.example.invalid"); !ok {
		t.Fatal("geosite expression did not reach the existing loader")
	}
	if _, ok := group.Match("other.invalid"); ok {
		t.Fatal("geosite expression matched an unrelated domain")
	}
}
