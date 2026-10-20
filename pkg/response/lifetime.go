package response

import "time"

// RemainingTTL returns the conservative wire-TTL bound of an analyzed address
// RRset and its complete CNAME chain. Address expiry is already normalized over
// the whole RRset, including duplicate records with TTL zero. Zero also covers
// a positive sub-second remainder; Snapshot.ValidUntil separately retains the
// absolute positive lease and must not be used to revive a rounded wire TTL.
func (c *Candidate) RemainingTTL(now time.Time) uint32 {
	if c == nil || len(c.Addresses) == 0 {
		return 0
	}
	ttl := ^uint32(0)
	for _, address := range c.Addresses {
		ttl = min(ttl, sourceTTLUntil(address.ExpiresAt, c.ReceivedAt, now))
	}
	for _, link := range c.chain {
		ttl = min(ttl, sourceTTLUntil(link.expiresAt, c.ReceivedAt, now))
	}
	if !c.Snapshot.ValidUntil.IsZero() {
		ttl = min(ttl, ttlUntil(c.Snapshot.ValidUntil, now))
	}
	return ttl
}

// RemainingTTL includes the terminal HTTPS/SVCB RRset, complete validated CNAME
// chain and any inherited source deadline. For NODATA it uses the relevant SOA
// negative lifetime when available; a response without any lifetime evidence
// has a conservative zero TTL. Genuine zero-TTL links always cap the wire TTL.
func (c *BindingCandidate) RemainingTTL(now time.Time) uint32 {
	if c == nil || c.base == nil {
		return 0
	}
	ttl := ^uint32(0)
	bounded := false
	include := func(expiry time.Time) {
		ttl = min(ttl, sourceTTLUntil(expiry, c.ReceivedAt, now))
		bounded = true
	}
	if len(c.Records) > 0 {
		include(c.rrsetExpiry)
	} else if c.hasNegative {
		include(c.negativeExp)
	}
	for _, link := range c.base.chain {
		include(link.expiresAt)
	}
	if !c.Snapshot.ValidUntil.IsZero() {
		ttl = min(ttl, ttlUntil(c.Snapshot.ValidUntil, now))
		bounded = true
	}
	if !bounded {
		return 0
	}
	return ttl
}

func sourceTTLUntil(expiry, receivedAt, now time.Time) uint32 {
	// A clock earlier than the source baseline cannot grow a zero TTL or
	// extend the original integer wire TTL.
	if now.Before(receivedAt) {
		now = receivedAt
	}
	return ttlUntil(expiry, now)
}
