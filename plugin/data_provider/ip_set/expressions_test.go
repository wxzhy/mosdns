package ip_set

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
)

type expressionIPProvider struct{ matcher netlist.Matcher }

func (p expressionIPProvider) GetIPMatcher() netlist.Matcher { return p.matcher }

func TestCompileExpressions(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ip list.txt")
	if err := os.WriteFile(file, []byte("198.51.100.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewIPSet(nil, &Args{IPs: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(map[string]any{"networks": provider}))
	group, err := CompileExpressions(bp, []string{" 192.0.2.0/24 ", " &" + file + " ", " $networks "})
	if err != nil {
		t.Fatal(err)
	}
	if len(group) != 2 {
		t.Fatalf("got %d matchers, want provider and local loader", len(group))
	}
	// Providers keep priority even when their references follow local inputs.
	if !group[0].Match(netip.MustParseAddr("203.0.113.1")) || group[0].Match(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("provider matcher must precede the local list")
	}
	for ip, want := range map[string]bool{
		"192.0.2.1": true, "198.51.100.1": true, "203.0.113.1": true, "192.0.3.1": false,
	} {
		if got := group.Match(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Match(%s) = %v, want %v", ip, got, want)
		}
	}
	// Files and literals do not need a plugin context.
	if _, err := CompileExpressions(nil, []string{"&" + file, "2001:db8::/32"}); err != nil {
		t.Fatal(err)
	}
}

func TestCompileExpressionsEmpty(t *testing.T) {
	for _, expressions := range [][]string{nil, {}} {
		group, err := CompileExpressions(nil, expressions)
		if err != nil || len(group) != 0 || group.Match(netip.MustParseAddr("192.0.2.1")) {
			t.Fatalf("empty expressions: group=%v err=%v", group, err)
		}
	}
}

func TestCompileExpressionsErrors(t *testing.T) {
	bp := coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(map[string]any{
		"wrong": struct{}{}, "nil_matcher": expressionIPProvider{},
	}))
	tests := []struct {
		name, expression, message string
		bp                        *coremain.BP
	}{
		{"empty", "  ", "empty expression", nil},
		{"bare_provider", "$", "empty IP set reference", bp},
		{"bare_file", "&", "empty file expression", nil},
		{"no_context", "$networks", "without a plugin context", nil},
		{"missing", "$missing", "IPMatcherProvider", bp},
		{"wrong_type", "$wrong", "IPMatcherProvider", bp},
		{"nil_matcher", "$nil_matcher", "nil IP matcher", bp},
		{"bad_ip", "not-an-ip", "invalid ip", nil},
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

func TestCompileExpressionsGeoIP(t *testing.T) {
	dat := filepath.Join(t.TempDir(), "geoip.dat")
	contents := appendIPEntry(nil, "TEST", appendCIDR(nil, []byte{192, 0, 2, 0}, 24), false)
	if err := os.WriteFile(dat, contents, 0600); err != nil {
		t.Fatal(err)
	}
	group, err := CompileExpressions(nil, []string{"ext:" + dat + ":test"})
	if err != nil {
		t.Fatal(err)
	}
	if !group.Match(netip.MustParseAddr("192.0.2.1")) || group.Match(netip.MustParseAddr("192.0.3.1")) {
		t.Fatal("geoip expression did not reach the existing loader")
	}
}
