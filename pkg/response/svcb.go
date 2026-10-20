package response

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

// BindingRecord describes one record in the terminal HTTPS/SVCB RRset. Index
// refers to the immutable snapshot's Answer. Target is the effective service
// name: ServiceMode's root target names the terminal owner. AliasMode is never
// followed or rewritten by this package, and its target is left as an alias.
type BindingRecord struct {
	Index    int
	Priority uint16
	Target   string
	Hints    []netip.Addr
}

// BindingCandidate owns an independent, correlated service-binding response.
// Rewritable permits NOERROR/NODATA synthesis too; NODATA distinguishes it from
// an existing RRset. Treat the snapshot and exported slices as immutable.
type BindingCandidate struct {
	Snapshot    query_context.ResponseSnapshot
	ReceivedAt  time.Time
	Question    dns.Question
	Terminal    string
	ChainKey    string
	ViewKey     string
	Records     []BindingRecord
	Hints       []netip.Addr
	NODATA      bool
	Negative    bool
	HasService  bool
	Rewritable  bool
	base        *Candidate
	rrsetTTL    uint32
	rrsetExpiry time.Time
	negativeTTL uint32
	negativeExp time.Time
	hasNegative bool
}

// BindingEdit applies only to the named Answer index. A missing edit preserves
// that record. Existing ECH is never replaced. ECHTTL optionally caps the wire
// TTL, including a genuine zero TTL; ECHValidUntil carries a positive source's
// absolute deadline independently of integer wire-TTL rounding.
type BindingEdit struct {
	RemoveHints   bool
	RemoveH3      bool
	RemoveALPN    []string
	ECH           []byte
	ECHTTL        *uint32
	ECHValidUntil time.Time
}

func AnalyzeBindings(query *dns.Msg, snapshot query_context.ResponseSnapshot, at time.Time) (*BindingCandidate, error) {
	base, err := analyzeEnvelope(query, snapshot, at)
	if err != nil {
		return nil, err
	}
	if base.Question.Qclass != dns.ClassINET || query.Opcode != dns.OpcodeQuery ||
		(base.Question.Qtype != dns.TypeHTTPS && base.Question.Qtype != dns.TypeSVCB) {
		return nil, fmt.Errorf("response: expected an IN HTTPS or SVCB query")
	}
	if err := base.findChain(); err != nil {
		return nil, err
	}
	c := &BindingCandidate{
		Snapshot: base.Snapshot, ReceivedAt: base.ReceivedAt, Question: base.Question,
		Terminal: base.Terminal, ChainKey: base.ChainKey, ViewKey: base.ViewKey, base: base,
		Negative: base.Snapshot.Response.Rcode == dns.RcodeNameError,
	}
	r := base.Snapshot.Response
	if r.Rcode != dns.RcodeSuccess || r.Truncated {
		return c, nil
	}
	minTTL := ^uint32(0)
	for index, rr := range r.Answer {
		h := rr.Header()
		if h.Class != c.Question.Qclass || h.Rrtype != c.Question.Qtype || canonical(h.Name) != c.Terminal {
			continue
		}
		binding := bindingValue(rr)
		if binding == nil {
			return nil, fmt.Errorf("response: invalid service-binding record at answer index %d", index)
		}
		target := canonical(binding.Target)
		if _, valid := dns.IsDomainName(binding.Target); !valid {
			return nil, fmt.Errorf("response: invalid service target at answer index %d", index)
		}
		record := BindingRecord{Index: index, Priority: binding.Priority, Target: target}
		if binding.Priority > 0 {
			c.HasService = true
			if target == "." {
				record.Target = c.Terminal
			}
			hints, err := bindingHints(binding.Value)
			if err != nil {
				return nil, fmt.Errorf("response: answer index %d: %w", index, err)
			}
			record.Hints = hints
			c.Hints = append(c.Hints, hints...)
		}
		c.Records = append(c.Records, record)
		minTTL = min(minTTL, h.Ttl)
	}
	c.NODATA = len(c.Records) == 0
	c.Negative = c.NODATA
	c.Rewritable = !base.queryDO && !opaque(r)
	var bounds ttlBounds
	bounds.includeValidity(c.Snapshot.ValidUntil)
	if !c.NODATA {
		c.rrsetTTL = minTTL
		c.rrsetExpiry = c.ReceivedAt.Add(time.Duration(minTTL) * time.Second)
		if minTTL > 0 {
			bounds.includeValidity(c.rrsetExpiry)
		}
	} else {
		// RFC 2308's negative lifetime belongs to the authoritative zone that
		// covers the terminal owner, not an unrelated SOA in Authority.
		for _, rr := range r.Ns {
			soa, ok := rr.(*dns.SOA)
			if !ok || soa.Hdr.Class != c.Question.Qclass || !dns.IsSubDomain(soa.Hdr.Name, c.Terminal) {
				continue
			}
			ttl := min(soa.Hdr.Ttl, soa.Minttl)
			if !c.hasNegative || ttl < c.negativeTTL {
				c.hasNegative, c.negativeTTL = true, ttl
				c.negativeExp = c.ReceivedAt.Add(time.Duration(ttl) * time.Second)
			}
		}
		if c.hasNegative && c.negativeTTL > 0 {
			bounds.includeValidity(c.negativeExp)
		}
	}
	for _, link := range base.chain {
		if link.expiresAt.After(base.ReceivedAt) {
			bounds.includeValidity(link.expiresAt)
		}
	}
	c.Snapshot.ValidUntil = bounds.validUntil
	base.Snapshot = c.Snapshot
	return c, nil
}

func bindingValue(rr dns.RR) *dns.SVCB {
	switch rr := rr.(type) {
	case *dns.HTTPS:
		return &rr.SVCB
	case *dns.SVCB:
		return rr
	default:
		return nil
	}
}

func bindingHints(values []dns.SVCBKeyValue) ([]netip.Addr, error) {
	seenKeys := make(map[dns.SVCBKey]bool)
	seenIPs := make(map[netip.Addr]bool)
	var hints []netip.Addr
	for _, value := range values {
		if value == nil || seenKeys[value.Key()] {
			return nil, fmt.Errorf("duplicate or invalid service parameter")
		}
		seenKeys[value.Key()] = true
		var ips []netip.Addr
		switch value := value.(type) {
		case *dns.SVCBIPv4Hint:
			if len(value.Hint) == 0 {
				return nil, fmt.Errorf("empty IPv4 hint")
			}
			for _, raw := range value.Hint {
				ip, ok := netip.AddrFromSlice(raw.To4())
				if !ok {
					return nil, fmt.Errorf("invalid IPv4 hint")
				}
				ips = append(ips, ip)
			}
		case *dns.SVCBIPv6Hint:
			if len(value.Hint) == 0 {
				return nil, fmt.Errorf("empty IPv6 hint")
			}
			for _, raw := range value.Hint {
				ip, ok := netip.AddrFromSlice(raw.To16())
				if !ok {
					return nil, fmt.Errorf("invalid IPv6 hint")
				}
				ips = append(ips, ip)
			}
		case *dns.SVCBAlpn:
			if len(value.Alpn) == 0 || slices.Contains(value.Alpn, "") {
				return nil, fmt.Errorf("empty ALPN protocol identifier")
			}
		}
		for _, ip := range ips {
			if !seenIPs[ip] {
				hints = append(hints, ip)
				seenIPs[ip] = true
			}
		}
	}
	return hints, nil
}

// RewriteBindings applies independent service-record edits. AliasMode parameters
// are never changed. Source RRset/alias leases and any actually injected ECH
// source lease bound the result; no source proofs or unrelated records survive
// a changed policy response. An unchanged response is replayed in full.
func RewriteBindings(c *BindingCandidate, edits map[int]BindingEdit, now time.Time) (query_context.ResponseSnapshot, bool, error) {
	if c == nil || c.base == nil {
		return query_context.ResponseSnapshot{}, false, fmt.Errorf("response: no service-binding candidate")
	}
	if !c.Rewritable || c.NODATA || len(edits) == 0 {
		return Replay(c.base, now), false, nil
	}
	known := make(map[int]bool, len(c.Records))
	for _, record := range c.Records {
		known[record.Index] = true
	}
	for index := range edits {
		if !known[index] {
			return query_context.ResponseSnapshot{}, false, fmt.Errorf("response: edit index %d is not a terminal binding", index)
		}
	}
	var bounds ttlBounds
	bounds.include(c.rrsetExpiry, c.rrsetTTL)
	if c.rrsetTTL > 0 {
		bounds.includeValidity(c.rrsetExpiry)
	}
	changed := false
	var records []dns.RR
	for _, record := range c.Records {
		rr := dns.Copy(c.Snapshot.Response.Answer[record.Index])
		binding := bindingValue(rr)
		edit, ok := edits[record.Index]
		if ok && record.Priority > 0 {
			itemChanged, injected := rewriteBinding(binding, edit)
			changed = changed || itemChanged
			if injected {
				bounds.includeValidity(edit.ECHValidUntil)
				if edit.ECHTTL != nil {
					expiry := now.Add(time.Duration(*edit.ECHTTL) * time.Second)
					bounds.include(expiry, *edit.ECHTTL)
					if *edit.ECHTTL > 0 {
						bounds.includeValidity(expiry)
					}
				}
			}
		}
		rr.Header().Name = c.Terminal
		records = append(records, rr)
	}
	if !changed {
		return Replay(c.base, now), false, nil
	}
	s := rebuildRecords(c.base, records, map[*Candidate]bool{c.base: true}, bounds, now, true)
	return s, true, nil
}

func rewriteBinding(binding *dns.SVCB, edit BindingEdit) (changed, injected bool) {
	values := make([]dns.SVCBKeyValue, 0, len(binding.Value)+1)
	var mandatory *dns.SVCBMandatory
	hasALPN, hasECH := false, false
	for _, value := range binding.Value {
		switch param := value.(type) {
		case *dns.SVCBIPv4Hint, *dns.SVCBIPv6Hint:
			if edit.RemoveHints {
				changed = true
				continue
			}
		case *dns.SVCBAlpn:
			protocols := make([]string, 0, len(param.Alpn))
			for _, protocol := range param.Alpn {
				if (edit.RemoveH3 && protocol == "h3") || slices.Contains(edit.RemoveALPN, protocol) {
					changed = true
					continue
				}
				protocols = append(protocols, protocol)
			}
			if len(protocols) == 0 {
				changed = true
				continue
			}
			param.Alpn = protocols
			hasALPN = true
		case *dns.SVCBECHConfig:
			hasECH = true
		case *dns.SVCBMandatory:
			mandatory = param
		}
		values = append(values, value)
	}
	if !hasALPN {
		values = slices.DeleteFunc(values, func(value dns.SVCBKeyValue) bool {
			if value.Key() == dns.SVCB_NO_DEFAULT_ALPN {
				changed = true
				return true
			}
			return false
		})
	}
	if len(edit.ECH) > 0 && !hasECH {
		values = append(values, &dns.SVCBECHConfig{ECH: slices.Clone(edit.ECH)})
		changed, injected = true, true
	}
	if mandatory != nil {
		keys := make([]dns.SVCBKey, 0, len(mandatory.Code))
		seen := make(map[dns.SVCBKey]bool)
		for _, key := range mandatory.Code {
			if key != dns.SVCB_MANDATORY && !seen[key] && slices.ContainsFunc(values, func(value dns.SVCBKeyValue) bool { return value.Key() == key }) {
				keys = append(keys, key)
				seen[key] = true
			}
		}
		if !slices.Equal(keys, mandatory.Code) {
			changed = true
		}
		if len(keys) == 0 {
			values = slices.DeleteFunc(values, func(value dns.SVCBKeyValue) bool { return value.Key() == dns.SVCB_MANDATORY })
			changed = true
		} else {
			slices.Sort(keys)
			mandatory.Code = keys
		}
	}
	if changed {
		slices.SortFunc(values, func(a, b dns.SVCBKeyValue) int { return int(a.Key()) - int(b.Key()) })
		binding.Value = values
	}
	return changed, injected
}

// SynthesizeBinding upgrades only NOERROR/NODATA after the plugin has confirmed
// a matching address source and ECH source. It never upgrades NXDOMAIN or an
// AliasMode answer. TTL and absolute leases supplied by those sources are
// further bounded by the original negative SOA and CNAME lifetimes.
func SynthesizeBinding(c *BindingCandidate, ech []byte, ttl uint32, validUntil time.Time, now time.Time) (query_context.ResponseSnapshot, error) {
	if c == nil || c.base == nil || !c.Rewritable || !c.NODATA || len(ech) == 0 {
		return query_context.ResponseSnapshot{}, fmt.Errorf("response: no safe binding synthesis")
	}
	var bounds ttlBounds
	expiry := now.Add(time.Duration(ttl) * time.Second)
	bounds.include(expiry, ttl)
	if ttl > 0 {
		bounds.includeValidity(expiry)
	}
	bounds.includeValidity(validUntil)
	if c.hasNegative {
		bounds.include(c.negativeExp, c.negativeTTL)
		if c.negativeTTL > 0 {
			bounds.includeValidity(c.negativeExp)
		}
	}
	binding := dns.SVCB{
		Hdr:      dns.RR_Header{Name: c.Terminal, Rrtype: c.Question.Qtype, Class: c.Question.Qclass},
		Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: slices.Clone(ech)}},
	}
	var rr dns.RR = &binding
	if c.Question.Qtype == dns.TypeHTTPS {
		rr = &dns.HTTPS{SVCB: binding}
	}
	return rebuildRecords(c.base, []dns.RR{rr}, map[*Candidate]bool{c.base: true}, bounds, now, true), nil
}
