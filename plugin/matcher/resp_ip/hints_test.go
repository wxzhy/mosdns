package resp_ip

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

type addressMatch netip.Addr

func (m addressMatch) Match(ip netip.Addr) bool { return ip.Unmap() == netip.Addr(m).Unmap() }

func TestResponseIPMatchesReachableServiceHints(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeHTTPS, dns.TypeSVCB} {
		for _, tc := range []struct {
			name, ip       string
			answers, extra []string
			want           bool
		}{
			{"IPv4", "192.0.2.42", []string{"query.test. 120 IN CNAME service.test.", "service.test. 60 IN TYPE 1 . ipv4hint=192.0.2.42 ipv6hint=2001:db8::42"}, nil, true},
			{"IPv6", "2001:db8::42", []string{"query.test. 60 IN TYPE 1 . ipv4hint=192.0.2.42 ipv6hint=2001:db8::42"}, nil, true},
			{"unrelated answer", "192.0.2.42", []string{"query.test. 60 IN TYPE 1 . ipv4hint=198.51.100.1", "other.test. 60 IN TYPE 1 . ipv4hint=192.0.2.42"}, nil, false},
			{"additional", "192.0.2.42", []string{"query.test. 60 IN TYPE 1 ."}, []string{"query.test. 60 IN TYPE 1 . ipv4hint=192.0.2.42"}, false},
			{"alias", "192.0.2.42", []string{"query.test. 60 IN TYPE 0 alias.test."}, nil, false},
			{"NODATA", "192.0.2.42", nil, nil, false},
			{"legacy A", "192.0.2.42", []string{"unrelated.test. 60 IN A 192.0.2.42"}, nil, true},
		} {
			t.Run(dns.TypeToString[qtype]+"/"+tc.name, func(t *testing.T) {
				q := query_context.NewContext(new(dns.Msg).SetQuestion("query.test.", qtype))
				r := new(dns.Msg).SetReply(q.Q())
				parse := func(records []string) []dns.RR {
					out := make([]dns.RR, 0, len(records))
					for _, text := range records {
						text = strings.ReplaceAll(text, " IN TYPE ", " IN "+dns.TypeToString[qtype]+" ")
						rr, err := dns.NewRR(text)
						if err != nil {
							t.Fatal(err)
						}
						out = append(out, rr)
					}
					return out
				}
				r.Answer, r.Extra = parse(tc.answers), parse(tc.extra)
				q.SetResponse(r)
				before := q.SnapshotResponse()
				got, err := matchRespAddr(q, addressMatch(netip.MustParseAddr(tc.ip)))
				if err != nil || got != tc.want {
					t.Fatalf("matched=%v err=%v, want %v", got, err, tc.want)
				}
				if !reflect.DeepEqual(before, q.SnapshotResponse()) {
					t.Fatal("IP matching mutated response")
				}
			})
		}
	}
}

func TestResponseHintsRejectMismatchedQuestion(t *testing.T) {
	q := query_context.NewContext(new(dns.Msg).SetQuestion("query.test.", dns.TypeHTTPS))
	r := new(dns.Msg).SetReply(q.Q())
	r.Question[0].Name = "other.test."
	q.SetResponse(r)
	if _, err := matchRespAddr(q, addressMatch(netip.MustParseAddr("192.0.2.42"))); err == nil {
		t.Fatal("accepted mismatched HTTPS response")
	}
}

func TestResponseHintsDoNotInterpretStatusQueries(t *testing.T) {
	query := new(dns.Msg).SetQuestion("query.test.", dns.TypeHTTPS)
	query.Opcode = dns.OpcodeStatus
	query.Question = nil
	q := query_context.NewContext(query)
	q.SetResponse(new(dns.Msg).SetReply(q.Q()))
	if matched, err := matchRespAddr(q, addressMatch(netip.MustParseAddr("192.0.2.42"))); matched || err != nil {
		t.Fatalf("non-QUERY response treated as a service-binding query: %v, %v", matched, err)
	}
}
