package https_record

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/IrineSistiana/mosdns/v5/pkg/response"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

type subqueryKey struct{}

type echCacheKey struct {
	wire string
	meta query_context.ServerMeta
}

type echData struct {
	value      []byte
	ttl        uint32
	validUntil time.Time
}

type echCacheEntry struct {
	value []byte
	until time.Time
	order uint64
}

type ipData struct {
	ips        []netip.Addr
	ttl        uint32
	validUntil time.Time
}

// validateECHConfigList checks the complete outer RFC 9849 list and each
// length-prefixed config. Unknown versions remain valid for future clients.
func validateECHConfigList(value []byte) bool {
	if len(value) < 6 || int(binary.BigEndian.Uint16(value)) != len(value)-2 {
		return false
	}
	for offset := 2; offset < len(value); {
		if len(value)-offset < 4 {
			return false
		}
		version := binary.BigEndian.Uint16(value[offset:])
		length := int(binary.BigEndian.Uint16(value[offset+2:]))
		if (length == 0 && version == 0xfe0d) || length > len(value)-offset-4 {
			return false
		}
		offset += 4 + length
		if offset == len(value) {
			return true
		}
	}
	return false
}

func serviceValue(rr dns.RR) *dns.SVCB {
	switch rr := rr.(type) {
	case *dns.HTTPS:
		return &rr.SVCB
	case *dns.SVCB:
		return rr
	default:
		return nil
	}
}

func hasECH(rr dns.RR) bool {
	if rr := serviceValue(rr); rr != nil {
		for _, value := range rr.Value {
			if value.Key() == dns.SVCB_ECHCONFIG {
				return true
			}
		}
	}
	return false
}

// ECH queries are dedicated queries: DNS/EDNS and server metadata are retained,
// but caller-local marks and opaque values cannot affect a shared cached key.
// A queries instead retain the complete caller context for normal routing.
func serviceQuery(parent *query_context.Context, name string, typ uint16, inherit bool) *query_context.Context {
	if inherit {
		branch := parent.Copy()
		branch.CommitResponse(query_context.ResponseSnapshot{})
		branch.Q().Question = []dns.Question{{Name: dns.CanonicalName(name), Qtype: typ, Qclass: dns.ClassINET}}
		branch.Q().Id = dns.Id()
		return branch
	}
	q := parent.Q().Copy()
	q.Id = dns.Id()
	q.Question = []dns.Question{{Name: dns.CanonicalName(name), Qtype: typ, Qclass: dns.ClassINET}}
	opt := q.IsEdns0()
	var outgoing *dns.OPT
	if opt != nil {
		outgoing = dns.Copy(opt).(*dns.OPT)
	}
	branch := query_context.NewContext(q)
	if outgoing != nil {
		*branch.QOpt() = *outgoing
	}
	branch.ServerMeta = parent.ServerMeta
	return branch
}

func (p *Record) resolveECH(ctx context.Context, parent *query_context.Context) (echData, error) {
	branch := serviceQuery(parent, p.echDomain, dns.TypeHTTPS, false)
	keyQuery := branch.Q().Copy()
	keyQuery.Id = 0
	wire, err := keyQuery.Pack()
	if err != nil {
		return echData{}, err
	}
	key := echCacheKey{wire: string(wire), meta: branch.ServerMeta}
	if data, ok := p.cachedECH(key, p.now()); ok {
		return data, ctx.Err()
	}
	expected := branch.Q().Copy()
	ctx = query_policy.WithInheritedCancellation(context.WithValue(ctx, subqueryKey{}, true))
	if err := runSource(ctx, p.echSource, branch); err != nil {
		return echData{}, err
	}
	if err := ctx.Err(); err != nil {
		return echData{}, context.Cause(ctx)
	}
	if branch.R() == nil {
		return echData{}, errors.New("ECH source returned no response")
	}
	if err := validateSourceQuestion(expected, branch.Q()); err != nil {
		return echData{}, err
	}
	c, err := response.AnalyzeBindings(branch.Q(), branch.SnapshotResponse(), p.now())
	if err != nil {
		return echData{}, err
	}
	if c.Snapshot.Response.Rcode != dns.RcodeSuccess || c.Snapshot.Response.Truncated {
		return echData{}, errors.New("ECH source did not return a complete positive response")
	}
	var value []byte
	for _, record := range c.Records {
		if record.Priority == 0 {
			continue
		}
		rr := serviceValue(c.Snapshot.Response.Answer[record.Index])
		for _, option := range rr.Value {
			if ech, ok := option.(*dns.SVCBECHConfig); ok && validateECHConfigList(ech.ECH) {
				value = append([]byte(nil), ech.ECH...)
				break
			}
		}
		if value != nil {
			break
		}
	}
	if value == nil {
		return echData{}, errors.New("ECH source returned no usable ECHConfigList")
	}
	now := p.now()
	until := c.Snapshot.ValidUntil
	if !until.IsZero() && !now.Before(until) {
		return echData{}, errors.New("ECH source expired")
	}
	ttl := min(c.RemainingTTL(now), uint32(maxECHCacheTTL/time.Second))
	if ttl > 0 || !until.IsZero() {
		until = earlier(until, now.Add(maxECHCacheTTL))
	}
	data := echData{value: value, ttl: ttl, validUntil: until}
	if ttl > 0 {
		cacheUntil := earlier(until, now.Add(maxECHCacheTTL))
		p.storeECH(ctx, key, value, cacheUntil, now)
	}
	return data, nil
}

func (p *Record) cachedECH(key echCacheKey, now time.Time) (echData, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.cache[key]
	if !ok {
		return echData{}, false
	}
	if !now.Before(entry.until) {
		delete(p.cache, key)
		return echData{}, false
	}
	p.cacheOrder++
	entry.order = p.cacheOrder
	p.cache[key] = entry
	return echData{value: append([]byte(nil), entry.value...), ttl: remaining(entry.until, now), validUntil: entry.until}, true
}

func (p *Record) storeECH(ctx context.Context, key echCacheKey, value []byte, until, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || ctx.Err() != nil || until.IsZero() || !now.Before(until) {
		return
	}
	for oldKey, entry := range p.cache {
		if !now.Before(entry.until) {
			delete(p.cache, oldKey)
		}
	}
	if len(p.cache) >= maxECHCacheEntries {
		var oldest echCacheKey
		order := ^uint64(0)
		for oldKey, entry := range p.cache {
			if entry.order < order {
				oldest, order = oldKey, entry.order
			}
		}
		delete(p.cache, oldest)
	}
	p.cacheOrder++
	p.cache[key] = echCacheEntry{value: append([]byte(nil), value...), until: until, order: p.cacheOrder}
}

func (p *Record) resolveIP(ctx context.Context, parent *query_context.Context, target string) (ipData, error) {
	branch := serviceQuery(parent, target, dns.TypeA, true)
	expected := branch.Q().Copy()
	ctx = query_policy.WithInheritedCancellation(context.WithValue(ctx, subqueryKey{}, true))
	if err := runSource(ctx, p.ipSource, branch); err != nil {
		return ipData{}, err
	}
	if err := ctx.Err(); err != nil {
		return ipData{}, context.Cause(ctx)
	}
	if branch.R() == nil {
		return ipData{}, errors.New("IP source returned no response")
	}
	if err := validateSourceQuestion(expected, branch.Q()); err != nil {
		return ipData{}, err
	}
	c, err := response.Analyze(branch.Q(), branch.SnapshotResponse(), p.now())
	if err != nil {
		return ipData{}, err
	}
	if c.Snapshot.Response.Rcode != dns.RcodeSuccess || c.Snapshot.Response.Truncated || len(c.Addresses) == 0 {
		return ipData{}, errors.New("IP source returned no A addresses")
	}
	now := p.now()
	until := c.Snapshot.ValidUntil
	if !until.IsZero() && !now.Before(until) {
		return ipData{}, errors.New("IP source expired")
	}
	data := ipData{validUntil: until}
	for _, address := range c.Addresses {
		data.ips = append(data.ips, address.IP)
	}
	// Include the complete original RRset, duplicates and every alias, including
	// native zero TTLs which intentionally have no positive ValidUntil deadline.
	data.ttl = c.RemainingTTL(now)
	return data, nil
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func remaining(until, now time.Time) uint32 {
	if !until.After(now) {
		return 0
	}
	return uint32(min(until.Sub(now)/time.Second, time.Duration(^uint32(0))))
}

// Optional source failures, including an executable panic, must not erase the
// already validated and cleaned main response or crash a lookup goroutine.
func runSource(ctx context.Context, source sequence.Executable, q *query_context.Context) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("https_record: optional source panic: %v", value)
		}
	}()
	return source.Exec(ctx, q)
}

func validateSourceQuestion(expected, actual *dns.Msg) error {
	if actual == nil || actual.Response || actual.Id != expected.Id || actual.Opcode != expected.Opcode || len(actual.Question) != 1 ||
		actual.Question[0].Qtype != expected.Question[0].Qtype || actual.Question[0].Qclass != expected.Question[0].Qclass ||
		dns.CanonicalName(actual.Question[0].Name) != dns.CanonicalName(expected.Question[0].Name) {
		return errors.New("https_record: source changed query correlation")
	}
	return nil
}
