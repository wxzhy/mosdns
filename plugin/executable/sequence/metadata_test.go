package sequence

import (
	"context"
	"errors"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func TestRuleHitsRetainTargetAndCallerSequenceTags(t *testing.T) {
	for _, action := range []string{"jump", "goto"} {
		t.Run(action, func(t *testing.T) {
			plugins := map[string]any{
				"answer": ExecutableFunc(func(_ context.Context, c *query_context.Context) error {
					c.SetResponse(new(dns.Msg).SetReply(c.Q()))
					return nil
				}),
			}
			m := coremain.NewTestMosdnsWithPlugins(plugins)
			child, err := NewSequence(coremain.NewBP("child", m), []RuleArgs{{Exec: "$answer"}})
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			plugins["child"] = child
			main, err := NewSequence(coremain.NewBP("main", m), []RuleArgs{{Exec: action + " child"}, {Exec: "accept"}})
			if err != nil {
				t.Fatal(err)
			}
			defer main.Close()
			q := query_context.NewContext(new(dns.Msg).SetQuestion("example.org.", dns.TypeA))
			if err := main.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			wantHits := 1
			if action == "jump" {
				wantHits = 2
			}
			if len(q.RuleHits) != wantHits || q.RuleHits[0].Sequence != "child" || q.RuleHits[0].Exec != "$answer" {
				t.Fatalf("target rule trace = %+v", q.RuleHits)
			}
			if action == "jump" && (q.RuleHits[1].Sequence != "main" || q.RuleHits[1].Exec != "accept") {
				t.Fatalf("jump lost caller sequence tag: %+v", q.RuleHits)
			}
		})
	}
}

func TestRuleHitsIncludeUpstreamErrorsButSkipUnmatchedRules(t *testing.T) {
	wantErr := errors.New("upstream timeout")
	plugins := map[string]any{"failed": ExecutableFunc(func(context.Context, *query_context.Context) error { return wantErr })}
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	s, err := NewSequence(coremain.NewBP("remote_sequence", m), []RuleArgs{
		{Matches: []string{"_false"}, Exec: "$failed"},
		{Exec: "$failed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := query_context.NewContext(new(dns.Msg).SetQuestion("example.org.", dns.TypeA))
	if err := s.Exec(context.Background(), q); err != wantErr {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if len(q.RuleHits) != 1 || q.RuleHits[0].Sequence != "remote_sequence" || q.RuleHits[0].Exec != "$failed" || len(q.RuleHits[0].Matches) != 0 {
		t.Fatalf("upstream failure trace = %+v", q.RuleHits)
	}
}
