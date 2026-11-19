package dnsutils

import "github.com/miekg/dns"

// MatchesResponse reports whether r is the response to the single-question q.
func MatchesResponse(q, r *dns.Msg) bool {
	if q.Response || !r.Response || q.Id != r.Id || q.Opcode != r.Opcode ||
		len(q.Question) != 1 || len(r.Question) != 1 {
		return false
	}
	want, got := q.Question[0], r.Question[0]
	return want.Qclass == got.Qclass && want.Qtype == got.Qtype &&
		dns.CanonicalName(want.Name) == dns.CanonicalName(got.Name)
}

// AnswerChain follows CNAMEs in the query's class. The returned TTL is bounded
// by every alias in the chain, or MaxUint32 when there are no aliases.
func AnswerChain(q dns.Question, answer []dns.RR) (terminal string, ttl uint32, valid bool) {
	name := dns.CanonicalName(q.Name)
	ttl = ^uint32(0)
	if q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeANY {
		return name, ttl, true
	}
	for hops := 0; hops <= 16; hops++ {
		var target string
		hasData := false
		for _, rr := range answer {
			h := rr.Header()
			if h.Class != q.Qclass || dns.CanonicalName(h.Name) != name {
				continue
			}
			switch rr := rr.(type) {
			case *dns.CNAME:
				next := dns.CanonicalName(rr.Target)
				if target != "" && target != next {
					return "", 0, false
				}
				target, ttl = next, min(ttl, h.Ttl)
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3:
			default:
				hasData = true
			}
		}
		if target == "" {
			return name, ttl, true
		}
		if hasData || target == name {
			return "", 0, false
		}
		if _, ok := dns.IsDomainName(target); !ok {
			return "", 0, false
		}
		name = target
	}
	return "", 0, false
}
