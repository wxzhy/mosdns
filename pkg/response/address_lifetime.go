package response

import (
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
)

// LimitAddressLifetime consumes an independently rebuilt address snapshot and
// bounds it by the complete address/CNAME leases of dynamic target sources.
// Source aliases and metadata are never copied. Wire TTL zero and a positive
// absolute deadline are intentionally independent lifetime constraints.
func LimitAddressLifetime(s query_context.ResponseSnapshot, sources []*Candidate, now time.Time) query_context.ResponseSnapshot {
	if s.Response == nil {
		return s
	}
	ttl := ^uint32(0)
	seen := make(map[*Candidate]bool)
	for _, c := range sources {
		if c == nil || seen[c] {
			continue
		}
		seen[c] = true
		ttl = min(ttl, c.RemainingTTL(now))
		until := c.Snapshot.ValidUntil
		if !until.IsZero() && (s.ValidUntil.IsZero() || until.Before(s.ValidUntil)) {
			s.ValidUntil = until
		}
	}
	for _, rr := range s.Response.Answer {
		rr.Header().Ttl = min(rr.Header().Ttl, ttl)
	}
	return s
}
