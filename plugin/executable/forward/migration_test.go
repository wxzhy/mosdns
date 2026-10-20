package fastforward

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type responseTestUpstream struct{ response *dns.Msg }

func (u responseTestUpstream) ExchangeContext(context.Context, []byte) (*[]byte, error) {
	return pool.PackBuffer(u.response)
}
func (responseTestUpstream) Close() error { return nil }

func TestForwardRejectsMismatchedResponse(t *testing.T) {
	for _, invalid := range []string{"", "query", "id", "opcode", "name", "type", "class", "missing question"} {
		t.Run(invalid, func(t *testing.T) {
			q := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
			qCtx := query_context.NewContext(q)
			r := new(dns.Msg).SetReply(q)
			switch invalid {
			case "query":
				r.Response = false
			case "id":
				r.Id++
			case "opcode":
				r.Opcode = dns.OpcodeStatus
			case "name":
				r.Question[0].Name = "other.org."
			case "type":
				r.Question[0].Qtype = dns.TypeAAAA
			case "class":
				r.Question[0].Qclass = dns.ClassCHAOS
			case "missing question":
				r.Question = nil
			default:
				r.Question[0].Name = "EXAMPLE.org."
			}
			u := newWrapper(0, UpstreamConfig{}, "test")
			u.u = responseTestUpstream{r}
			f := &Forward{args: &Args{}, logger: zap.NewNop()}
			_, err := f.exchange(context.Background(), qCtx, []*upstreamWrapper{u})
			if (err == nil) != (invalid == "") {
				t.Fatalf("response validation returned %v", err)
			}
		})
	}
}
