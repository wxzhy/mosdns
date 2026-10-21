package ip_set

import (
	"fmt"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geodata"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
)

// CompileExpressions combines IP/CIDR and geoip/ASN expressions, $provider
// references and &file paths using OR semantics. Provider matchers precede
// matchers from the local list loader. A nil bp supports expressions and files.
func CompileExpressions(bp *coremain.BP, expressions []string) (MatcherGroup, error) {
	var paths geodata.Paths
	if bp != nil {
		paths = bp.M().GeodataPaths()
	}
	loader := NewListLoader(paths)
	var group MatcherGroup
	for i, expression := range expressions {
		expression = strings.TrimSpace(expression)
		if expression == "" {
			return nil, fmt.Errorf("empty expression #%d", i)
		}
		switch expression[0] {
		case '$':
			tag := expression[1:]
			if tag == "" {
				return nil, fmt.Errorf("empty IP set reference #%d", i)
			}
			if bp == nil || bp.M() == nil {
				return nil, fmt.Errorf("cannot resolve IP set %q without a plugin context", expression)
			}
			provider, ok := bp.M().GetPlugin(tag).(data_provider.IPMatcherProvider)
			if !ok {
				return nil, fmt.Errorf("%q is not an IPMatcherProvider", tag)
			}
			matcher := provider.GetIPMatcher()
			if matcher == nil {
				return nil, fmt.Errorf("%q returned a nil IP matcher", tag)
			}
			group = append(group, matcher)
		case '&':
			if expression[1:] == "" {
				return nil, fmt.Errorf("empty file expression #%d", i)
			}
			if err := loader.LoadFromFiles([]string{expression[1:]}); err != nil {
				return nil, err
			}
		default:
			if err := loader.LoadFromIPs([]string{expression}); err != nil {
				return nil, err
			}
		}
	}
	return append(group, loader.Matchers()...), nil
}
