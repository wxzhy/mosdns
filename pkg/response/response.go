// Package response validates immutable DNS candidates and constructs a selected
// response without changing the messages owned by an upstream or a cache.
package response

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

const maxCNAMEHops = 16

// Address identifies an address in Candidate.Snapshot.Response.Answer. ExpiresAt
// includes the minimum TTL of the original address RRset, including duplicates.
type Address struct {
	IP        netip.Addr
	Index     int
	ExpiresAt time.Time
}

// Candidate owns its snapshot. Treat all fields, including the snapshot's
// records and OPTs, as immutable after Analyze returns.
type Candidate struct {
	Snapshot   query_context.ResponseSnapshot
	ReceivedAt time.Time
	Question   dns.Question
	Terminal   string
	ChainKey   string
	ViewKey    string
	Addresses  []Address
	Rewritable bool
	Negative   bool

	chain    []chainLink
	ecs      *ecsView
	queryHdr dns.MsgHdr
}

type chainLink struct {
	rr        *dns.CNAME
	expiresAt time.Time
}

// Analyze checks response correlation and finds only the address RRset reachable
// from the outgoing question. It always clones snapshot before retaining it.
// A recorded response time takes precedence over at, which is only a fallback
// for snapshots without timing metadata (for example, manually built snapshots).
func Analyze(query *dns.Msg, snapshot query_context.ResponseSnapshot, at time.Time) (*Candidate, error) {
	if !snapshot.ReceivedAt.IsZero() {
		at = snapshot.ReceivedAt
	}
	if query == nil || query.Response || len(query.Question) != 1 {
		return nil, fmt.Errorf("response: expected a query with one question")
	}
	r := snapshot.Response
	if r == nil || !r.Response || r.Opcode != query.Opcode || len(r.Question) != 1 {
		return nil, fmt.Errorf("response: invalid response header or question count")
	}
	question := query.Question[0]
	if !sameQuestion(question, r.Question[0]) {
		return nil, fmt.Errorf("response: question does not match query")
	}
	if r.Id != query.Id {
		return nil, fmt.Errorf("response: ID does not match query")
	}
	for _, rr := range r.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			return nil, fmt.Errorf("response: OPT must be separated from the response")
		}
	}
	view, err := analyzeECS(query.IsEdns0(), snapshot.UpstreamOpt, snapshot.RespOpt)
	if err != nil {
		return nil, err
	}
	c := &Candidate{
		Snapshot: snapshot.Clone(), ReceivedAt: at, Question: question,
		Terminal: canonical(question.Name), ViewKey: view.key(), ecs: view,
		Negative: r.Rcode == dns.RcodeNameError,
		queryHdr: query.MsgHdr,
	}
	c.Snapshot.ReceivedAt = at
	r = c.Snapshot.Response
	addressQuery := query.Opcode == dns.OpcodeQuery && question.Qclass == dns.ClassINET &&
		(question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA)
	if !addressQuery {
		return c, nil
	}
	if err := c.findChain(); err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess || r.Truncated {
		return c, nil
	}
	if err := c.findAddresses(); err != nil {
		return nil, err
	}
	// Capture the source lease before any Replay or rewrite can round a short
	// positive TTL to zero. This also bounds an otherwise long-lived address
	// by the nonzero lifetime of the aliases needed to reach it.
	if len(c.Addresses) > 0 {
		var bounds ttlBounds
		bounds.includeValidity(c.Snapshot.ValidUntil)
		for _, address := range c.Addresses {
			if address.ExpiresAt.After(c.ReceivedAt) {
				bounds.includeValidity(address.ExpiresAt)
			}
		}
		for _, link := range c.chain {
			if link.expiresAt.After(c.ReceivedAt) {
				bounds.includeValidity(link.expiresAt)
			}
		}
		c.Snapshot.ValidUntil = bounds.validUntil
	}
	c.Negative = len(c.Addresses) == 0
	c.Rewritable = !c.Negative && !opaque(r)
	if opt := query.IsEdns0(); opt != nil && opt.Do() {
		c.Rewritable = false
	}
	return c, nil
}

func (c *Candidate) findChain() error {
	r := c.Snapshot.Response
	name := c.Terminal
	seen := make(map[string]bool)
	var key strings.Builder
	for {
		if seen[name] {
			return fmt.Errorf("response: CNAME cycle at %s", name)
		}
		seen[name] = true
		var link *dns.CNAME
		var minTTL uint32
		otherData := false
		for _, rr := range r.Answer {
			h := rr.Header()
			if h.Class != c.Question.Qclass || canonical(h.Name) != name {
				continue
			}
			if cn, ok := rr.(*dns.CNAME); ok {
				if link != nil && canonical(link.Target) != canonical(cn.Target) {
					return fmt.Errorf("response: conflicting CNAME targets at %s", name)
				}
				if link == nil || cn.Hdr.Ttl < minTTL {
					link, minTTL = cn, cn.Hdr.Ttl
				}
			} else if h.Rrtype != dns.TypeRRSIG && h.Rrtype != dns.TypeNSEC && h.Rrtype != dns.TypeNSEC3 {
				otherData = true
			}
		}
		if link == nil {
			break
		}
		if otherData {
			return fmt.Errorf("response: CNAME coexists with other data at %s", name)
		}
		if len(c.chain) == maxCNAMEHops {
			return fmt.Errorf("response: CNAME chain exceeds %d hops", maxCNAMEHops)
		}
		target := canonical(link.Target)
		if _, ok := dns.IsDomainName(target); !ok {
			return fmt.Errorf("response: invalid CNAME target %s", link.Target)
		}
		c.chain = append(c.chain, chainLink{rr: link, expiresAt: c.ReceivedAt.Add(time.Duration(minTTL) * time.Second)})
		key.WriteString(name)
		key.WriteByte(0)
		key.WriteString(target)
		key.WriteByte(0)
		name = target
	}
	c.Terminal, c.ChainKey = name, key.String()
	return nil
}

func (c *Candidate) findAddresses() error {
	r := c.Snapshot.Response
	minTTL := ^uint32(0)
	seen := make(map[netip.Addr]bool)
	for i, rr := range r.Answer {
		h := rr.Header()
		if h.Class != c.Question.Qclass || h.Rrtype != c.Question.Qtype || canonical(h.Name) != c.Terminal {
			continue
		}
		var addr netip.Addr
		var ok bool
		switch rr := rr.(type) {
		case *dns.A:
			addr, ok = netip.AddrFromSlice(rr.A.To4())
		case *dns.AAAA:
			addr, ok = netip.AddrFromSlice(rr.AAAA.To16())
		}
		if !ok {
			return fmt.Errorf("response: invalid address at answer index %d", i)
		}
		if h.Ttl < minTTL {
			minTTL = h.Ttl
		}
		if !seen[addr] {
			c.Addresses = append(c.Addresses, Address{IP: addr, Index: i})
			seen[addr] = true
		}
	}
	for i := range c.Addresses {
		c.Addresses[i].ExpiresAt = c.ReceivedAt.Add(time.Duration(minTTL) * time.Second)
	}
	return nil
}

// Compatible permits combining only identical questions, complete alias chains,
// terminal owners and effective client-subnet views.
func Compatible(a, b *Candidate) bool {
	return a != nil && b != nil && a.Rewritable && b.Rewritable &&
		a.Snapshot.Response != nil && b.Snapshot.Response != nil &&
		sameQuestion(a.Question, b.Question) && a.Terminal == b.Terminal &&
		a.ChainKey == b.ChainKey && a.ViewKey == b.ViewKey
}

// SelectedAddress retains the candidate that contributed an address. Changing
// Address.ExpiresAt cannot extend its original expiry; Rebuild reads provenance.
type SelectedAddress struct {
	Candidate *Candidate
	Address   Address
}

// Replay returns a full independent response state, aging all non-OPT RR TTLs
// with a floor of zero. It does not remove records or change authentication bits.
func Replay(c *Candidate, now time.Time) query_context.ResponseSnapshot {
	if c == nil {
		return query_context.ResponseSnapshot{}
	}
	s := c.Snapshot.Clone()
	if s.Response == nil {
		return s
	}
	for _, section := range [][]dns.RR{s.Response.Answer, s.Response.Ns, s.Response.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype != dns.TypeOPT {
				h.Ttl = agedTTL(h.Ttl, c.ReceivedAt, now)
			}
		}
	}
	s.ReceivedAt = now
	return s
}

// Rebuild creates a policy response consisting of the anchor's alias chain and
// selected terminal addresses. All contributing chain and address expiries bound
// its TTL. Source proofs and connection-specific OPT options are not copied.
func Rebuild(anchor *Candidate, selected []SelectedAddress, now time.Time) (query_context.ResponseSnapshot, error) {
	if anchor == nil || !anchor.Rewritable || len(selected) == 0 {
		return query_context.ResponseSnapshot{}, fmt.Errorf("response: no rewritable selection")
	}
	var bounds ttlBounds
	contributors := make(map[*Candidate]bool)
	seen := make(map[netip.Addr]bool)
	var records []dns.RR
	for _, item := range selected {
		c := item.Candidate
		if !Compatible(anchor, c) {
			return query_context.ResponseSnapshot{}, fmt.Errorf("response: incompatible selected candidate")
		}
		address, ok := c.address(item.Address)
		if !ok {
			return query_context.ResponseSnapshot{}, fmt.Errorf("response: address does not belong to candidate")
		}
		rr := c.Snapshot.Response.Answer[address.Index]
		bounds.include(address.ExpiresAt, rr.Header().Ttl)
		if address.ExpiresAt.After(c.ReceivedAt) {
			bounds.includeValidity(address.ExpiresAt)
		}
		contributors[c] = true
		if seen[address.IP] {
			continue
		}
		seen[address.IP] = true
		copyRR := dns.Copy(rr)
		copyRR.Header().Name = anchor.Terminal
		records = append(records, copyRR)
	}
	return rebuildRecords(anchor, records, contributors, bounds, now), nil
}

// ReplaceAddresses creates a policy response with new terminal addresses rather
// than selecting addresses from source candidates. The original complete RRset
// and alias chain bound every replacement's lifetime. Only an address candidate
// that Analyze marked rewritable can be used; in particular, DNSSEC requests,
// truncated replies and opaque responses cannot be replaced.
func ReplaceAddresses(anchor *Candidate, ips []netip.Addr, now time.Time) (query_context.ResponseSnapshot, error) {
	if anchor == nil || !anchor.Rewritable || anchor.Snapshot.Response == nil ||
		anchor.Question.Qclass != dns.ClassINET ||
		(anchor.Question.Qtype != dns.TypeA && anchor.Question.Qtype != dns.TypeAAAA) ||
		anchor.Snapshot.Response.Rcode != dns.RcodeSuccess || anchor.Snapshot.Response.Truncated ||
		len(anchor.Addresses) == 0 || len(ips) == 0 {
		return query_context.ResponseSnapshot{}, fmt.Errorf("response: no rewritable address replacement")
	}
	var records []dns.RR
	seen := make(map[netip.Addr]bool)
	for _, ip := range ips {
		if !ip.IsValid() || ip.Zone() != "" ||
			(anchor.Question.Qtype == dns.TypeA && !ip.Is4()) ||
			(anchor.Question.Qtype == dns.TypeAAAA && !ip.Is6()) {
			return query_context.ResponseSnapshot{}, fmt.Errorf("response: invalid replacement address %s for %s", ip, dns.TypeToString[anchor.Question.Qtype])
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true
		hdr := dns.RR_Header{Name: anchor.Terminal, Rrtype: anchor.Question.Qtype, Class: anchor.Question.Qclass}
		if ip.Is4() {
			records = append(records, &dns.A{Hdr: hdr, A: ip.AsSlice()})
		} else {
			records = append(records, &dns.AAAA{Hdr: hdr, AAAA: ip.AsSlice()})
		}
	}
	var bounds ttlBounds
	for _, address := range anchor.Addresses {
		rr := anchor.Snapshot.Response.Answer[address.Index]
		bounds.include(address.ExpiresAt, rr.Header().Ttl)
		if address.ExpiresAt.After(anchor.ReceivedAt) {
			bounds.includeValidity(address.ExpiresAt)
		}
	}
	return rebuildRecords(anchor, records, map[*Candidate]bool{anchor: true}, bounds, now), nil
}

type ttlBounds struct {
	expiry     time.Time
	set        bool
	minTTL     uint32
	validUntil time.Time
}

func (b *ttlBounds) include(expiresAt time.Time, originalTTL uint32) {
	if !b.set || expiresAt.Before(b.expiry) {
		b.expiry = expiresAt
	}
	if !b.set || originalTTL < b.minTTL {
		b.minTTL = originalTTL
	}
	b.set = true
}

func (b *ttlBounds) includeValidity(deadline time.Time) {
	if !deadline.IsZero() && (b.validUntil.IsZero() || deadline.Before(b.validUntil)) {
		b.validUntil = deadline
	}
}

// records are already independent of all candidates. Both selection and address
// replacement use this path so aliases, authentication flags and EDNS policy
// cannot drift between the two kinds of synthesized response.
func rebuildRecords(anchor *Candidate, records []dns.RR, contributors map[*Candidate]bool, bounds ttlBounds, now time.Time) query_context.ResponseSnapshot {
	// The anchor supplies the aliases even when all selected records came from
	// another compatible candidate.
	contributors[anchor] = true
	for c := range contributors {
		bounds.includeValidity(c.Snapshot.ValidUntil)
		for _, link := range c.chain {
			bounds.include(link.expiresAt, link.rr.Hdr.Ttl)
			if link.expiresAt.After(c.ReceivedAt) {
				bounds.includeValidity(link.expiresAt)
			}
		}
	}
	ttl := ttlUntil(bounds.expiry, now)
	if !bounds.validUntil.IsZero() {
		ttl = min(ttl, ttlUntil(bounds.validUntil, now))
	}
	if ttl > bounds.minTTL {
		ttl = bounds.minTTL
	}
	r := new(dns.Msg)
	r.MsgHdr = dns.MsgHdr{
		Id: anchor.queryHdr.Id, Opcode: anchor.queryHdr.Opcode, Response: true,
		Rcode: dns.RcodeSuccess, RecursionDesired: anchor.queryHdr.RecursionDesired,
		RecursionAvailable: anchor.Snapshot.Response.RecursionAvailable,
		CheckingDisabled:   anchor.queryHdr.CheckingDisabled,
	}
	r.Question = []dns.Question{anchor.Question}
	r.Compress = anchor.Snapshot.Response.Compress
	for _, link := range anchor.chain {
		rr := dns.Copy(link.rr)
		rr.Header().Ttl = ttl
		r.Answer = append(r.Answer, rr)
	}
	for _, rr := range records {
		rr.Header().Ttl = ttl
		r.Answer = append(r.Answer, rr)
	}
	upstreamOpt, respOpt := rebuiltOpts(anchor, contributors)
	return query_context.ResponseSnapshot{Response: r, UpstreamOpt: upstreamOpt, RespOpt: respOpt, ReceivedAt: now, ValidUntil: bounds.validUntil}
}

func (c *Candidate) address(want Address) (Address, bool) {
	for _, address := range c.Addresses {
		if address.Index == want.Index && address.IP == want.IP {
			return address, true
		}
	}
	return Address{}, false
}

func sameQuestion(a, b dns.Question) bool {
	return a.Qtype == b.Qtype && a.Qclass == b.Qclass && canonical(a.Name) == canonical(b.Name)
}

func canonical(name string) string { return dns.CanonicalName(name) }

func opaque(m *dns.Msg) bool {
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			switch rr := rr.(type) {
			case *dns.DNAME, *dns.TSIG:
				return true
			case *dns.SIG:
				if rr.TypeCovered == 0 {
					return true
				}
			}
		}
	}
	return false
}

func agedTTL(ttl uint32, receivedAt, now time.Time) uint32 {
	if !now.After(receivedAt) {
		return ttl
	}
	return ttlUntil(receivedAt.Add(time.Duration(ttl)*time.Second), now)
}

func ttlUntil(expiry, now time.Time) uint32 {
	if !expiry.After(now) {
		return 0
	}
	seconds := expiry.Sub(now) / time.Second
	if seconds > time.Duration(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(seconds)
}
