package adblock_set

import (
 "strings"
 "testing"
 "github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

func TestRegexpDollarAnchorsArePreserved(t *testing.T) {
 for _, rule := range []string{"/^ads[.]example$/", "regexp:^ads[.]example$"} {
  black, white := domain.NewMixMatcher[struct{}](), domain.NewMixMatcher[struct{}]()
  if err := ParseRules(strings.NewReader(rule), black, white); err != nil { t.Fatal(err) }
  m := &AdblockMatcher{blacklist: black, whitelist: white}
  if _, ok := m.Match("ads.example"); !ok { t.Errorf("%s lost exact match", rule) }
  if _, ok := m.Match("ads.example.unwanted"); ok { t.Errorf("%s overmatched", rule) }
 }
}
