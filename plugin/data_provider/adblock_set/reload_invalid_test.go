package adblock_set

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

func TestInvalidOnlyRulesDoNotEraseExistingMatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	writeRules(t, path, "||keep.example^\n")
	set, err := newAdblockSet(nil, &Args{Files: []string{path}}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	writeRules(t, path, "regexp:[\n")
	// Parsing errors should be retried but must never publish an empty matcher.
	time.Sleep(80 * time.Millisecond)
	if _, ok := set.Match("keep.example"); !ok {
		t.Fatal("invalid update replaced the last good rules")
	}
	writeRules(t, path, "||new.example^\n")
	waitForMatch(t, set, "new.example", true)
	waitForMatch(t, set, "keep.example", false)
	// An intentionally empty file is different from an invalid-only file.
	writeRules(t, path, "! intentionally empty\n")
	waitForMatch(t, set, "new.example", false)
}

func TestParserRejectsOnlyInvalidRulesButKeepsMixedFile(t *testing.T) {
	for _, tt := range []struct {
		input   string
		invalid bool
	}{
		{"regexp:[\n", true},
		{"regexp:[\n||valid.example^\n", false},
		{"! comments only\n", false},
	} {
		black, white := domain.NewMixMatcher[struct{}](), domain.NewMixMatcher[struct{}]()
		err := ParseRules(strings.NewReader(tt.input), black, white)
		if (err != nil) != tt.invalid {
			t.Fatalf("ParseRules(%q): error=%v", tt.input, err)
		}
	}
}
