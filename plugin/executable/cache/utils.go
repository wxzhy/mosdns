/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package cache

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"golang.org/x/exp/constraints"
)

type key string

// A scope prefix is intentionally outside the ordinary DNS question key.
// The format is also preserved in cache dumps to partition restored entries.
func scopedCacheKey(dnsKey, scope string) string {
	if dnsKey == "" || scope == "" {
		return dnsKey
	}
	if len(scope) > 65535 {
		return "" // never silently share an oversize scope
	}
	buf := make([]byte, 3+len(scope)+len(dnsKey))
	buf[0] = 0xfe // outside the 0..7 DNS key flag range
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(scope)))
	copy(buf[3:], scope)
	copy(buf[3+len(scope):], dnsKey)
	return string(buf)
}

func rawDNSCacheKey(raw string) string {
	if len(raw) < 3 || raw[0] != 0xfe {
		return raw
	}
	scopeLen := int(binary.BigEndian.Uint16([]byte(raw[1:3])))
	if len(raw) <= 3+scopeLen {
		return "" // corrupted scoped key
	}
	return raw[3+scopeLen:]
}

var seed = maphash.MakeSeed()

func (k key) Sum() uint64 {
	return maphash.String(seed, string(k))
}

// getMsgKey returns a string key for the query msg, or an empty
// string if query should not be cached.
func getMsgKey(q *dns.Msg) string {
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return ""
	}

	const (
		adBit = 1 << iota
		cdBit
		doBit
	)

	question := q.Question[0]
	// EDNS options such as ECS can change an upstream answer. Without a
	// corresponding partition they must not share ordinary cached responses.
	// Padding has no bearing on the DNS answer and may safely be ignored.
	if opt := q.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() != dns.EDNS0PADDING {
				return ""
			}
		}
	}
	// QCLASS is part of the DNS question. Include it to prevent IN and
	// CHAOS/HESIOD queries from sharing cached responses.
	buf := make([]byte, 1+2+2+2+len(question.Name)) // flags, type, class, name length, name
	b := byte(0)
	// RFC 6840 5.7: The AD bit in a query as a signal
	// indicating that the requester understands and is interested in the
	// value of the AD bit in the response.
	if q.AuthenticatedData {
		b = b | adBit
	}
	if q.CheckingDisabled {
		b = b | cdBit
	}
	if opt := q.IsEdns0(); opt != nil && opt.Do() {
		b = b | doBit
	}
	buf[0] = b
	buf[1] = byte(question.Qtype << 8)
	buf[2] = byte(question.Qtype)
	buf[3] = byte(question.Qclass >> 8)
	buf[4] = byte(question.Qclass)
	buf[5] = byte(len(question.Name) >> 8)
	buf[6] = byte(len(question.Name))
	copy(buf[7:], question.Name)
	return utils.BytesToStringUnsafe(buf)
}

// migratedDumpKey upgrades the pre-QCLASS layout used by existing
// mosdns_cache_v2 dumps. The old key contained flags, type, one-byte name
// length and name; reconstruct the class from the stored DNS question.
// Unrecognized keys are left unchanged for backward-compatible imports.
func migratedDumpKey(raw []byte, response *dns.Msg) key {
	if response == nil || len(response.Question) != 1 {
		return key(raw)
	}
	question := response.Question[0]
	if len(raw) != 4+len(question.Name) || raw[0]&^byte(7) != 0 ||
		uint16(raw[1])<<8|uint16(raw[2]) != question.Qtype ||
		int(raw[3]) != len(question.Name)&0xff ||
		string(raw[4:]) != question.Name {
		return key(raw)
	}
	q := new(dns.Msg).SetQuestion(question.Name, question.Qtype)
	q.Question[0].Qclass = question.Qclass
	q.AuthenticatedData = raw[0]&1 != 0
	q.CheckingDisabled = raw[0]&2 != 0
	if raw[0]&4 != 0 {
		q.SetEdns0(1232, true)
	}
	return key(getMsgKey(q))
}

type item struct {
	resp           *dns.Msg
	storedTime     time.Time
	expirationTime time.Time
	hitCount       atomic.Uint32
	next           *sequence.ChainWalker // nil for restored or test-only entries.
	localNegative  bool
}

// The v2 dump message has no dedicated source-classification field.
// Reserve an impossible cache-key first byte (normal flags use only 0..7)
// for a versioned key envelope, preserving compatibility with old dumps.
func encodeDumpEntryKey(k key, localNegative bool) []byte {
	flags := byte(0)
	if localNegative {
		flags = 1
	}
	return append([]byte{0xff, flags}, []byte(k)...)
}

func decodeDumpEntryKey(raw []byte, resp *dns.Msg) (key, bool) {
	if len(raw) > 2 && raw[0] == 0xff && raw[1]&^byte(1) == 0 {
		return migratedDumpKey(raw[2:], resp), raw[1]&1 != 0
	}
	return migratedDumpKey(raw, resp), false
}

// validateDumpEntryKey accepts the legacy, QCLASS-aware and scoped key
// layouts, but never trusts a serialized key to identify an unrelated DNS
// response. Validation runs before any imported entry is published.
func validateDumpEntryKey(raw []byte, resp *dns.Msg) (key, bool, error) {
	if resp == nil || !resp.Response || resp.Opcode != dns.OpcodeQuery ||
		resp.Truncated || len(resp.Question) != 1 {
		return "", false, fmt.Errorf("invalid cached DNS response")
	}
	k, localNegative := decodeDumpEntryKey(raw, resp)
	encoded := string(k)
	if len(encoded) > 0 && encoded[0] == 0xfe {
		if len(encoded) < 4 {
			return "", false, fmt.Errorf("invalid scoped cache key length")
		}
		scopeLen := int(binary.BigEndian.Uint16([]byte(encoded[1:3])))
		if scopeLen == 0 || len(encoded) <= 3+scopeLen {
			return "", false, fmt.Errorf("invalid scoped cache key")
		}
		encoded = encoded[3+scopeLen:]
	}
	question := resp.Question[0]
	if len(encoded) != 7+len(question.Name) || encoded[0]&^byte(7) != 0 ||
		binary.BigEndian.Uint16([]byte(encoded[1:3])) != question.Qtype ||
		binary.BigEndian.Uint16([]byte(encoded[3:5])) != question.Qclass ||
		int(binary.BigEndian.Uint16([]byte(encoded[5:7]))) != len(question.Name) ||
		encoded[7:] != question.Name {
		return "", false, fmt.Errorf("cache key does not match DNS question")
	}
	if localNegative && resp.Rcode != dns.RcodeNameError && resp.Rcode != dns.RcodeRefused {
		return "", false, fmt.Errorf("negative source flag inconsistent with response")
	}
	return k, localNegative, nil
}

func copyNoOpt(m *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}

	m2 := new(dns.Msg)
	m2.MsgHdr = m.MsgHdr
	m2.Compress = m.Compress

	if len(m.Question) > 0 {
		m2.Question = make([]dns.Question, len(m.Question))
		copy(m2.Question, m.Question)
	}

	lenExtra := len(m.Extra)
	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			lenExtra--
		}
	}

	s := make([]dns.RR, len(m.Answer)+len(m.Ns)+lenExtra)
	m2.Answer, s = s[:0:len(m.Answer)], s[len(m.Answer):]
	m2.Ns, s = s[:0:len(m.Ns)], s[len(m.Ns):]
	m2.Extra = s[:0:lenExtra]

	for _, r := range m.Answer {
		m2.Answer = append(m2.Answer, dns.Copy(r))
	}
	for _, r := range m.Ns {
		m2.Ns = append(m2.Ns, dns.Copy(r))
	}

	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			continue
		}
		m2.Extra = append(m2.Extra, dns.Copy(r))
	}
	return m2
}

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

// getRespFromCache returns the cached response from cache.
// The ttl of returned msg will be changed properly.
// Returned bool indicates whether this response is hit by lazy cache.
// Note: Caller SHOULD change the msg id because it's not same as query's.
func getRespFromCache(msgKey string, backend *cache.Cache[key, *item], lazyCacheEnabled bool, lazyTtl int) (*dns.Msg, bool) {
	// Lookup cache
	v, _, _ := backend.Get(key(msgKey))

	// Cache hit
	if v != nil {
		now := time.Now()

		// Not expired.
		if now.Before(v.expirationTime) {
			r := v.resp.Copy()
			dnsutils.SubtractTTL(r, uint32(now.Sub(v.storedTime).Seconds()))
			return r, false
		}

		// Msg expired but cache isn't. This is a lazy cache enabled entry.
		// If lazy cache is enabled, return the response.
		if lazyCacheEnabled {
			r := v.resp.Copy()
			dnsutils.SetTTL(r, uint32(lazyTtl))
			return r, true
		}
	}

	// cache miss
	return nil, false
}

// saveRespToCache saves r to cache backend. It returns false if r
// should not be cached and was skipped.
func saveRespToCache(msgKey string, r *dns.Msg, backend *cache.Cache[key, *item], lazyCacheTtl int) bool {
	return saveRespToCacheIf(msgKey, r, backend, lazyCacheTtl, nil)
}

// expected != nil means a background refresh may only replace that exact
// cache entry. A concurrent update or Flush must not be undone by prefetch.
func saveRespToCacheIf(msgKey string, r *dns.Msg, backend *cache.Cache[key, *item], lazyCacheTtl int, expected *item) bool {
	return saveRespToCacheWithSource(msgKey, r, backend, lazyCacheTtl, expected, nil, false)
}

// The continuation and source classification are immutable once published.
func saveRespToCacheWithSource(msgKey string, r *dns.Msg, backend *cache.Cache[key, *item], lazyCacheTtl int, expected *item, next *sequence.ChainWalker, localNegative bool) bool {
	if r.Truncated != false {
		return false
	}

	var msgTtl time.Duration
	var cacheTtl time.Duration
	negativeTTL := func() time.Duration {
		for _, rr := range r.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				return time.Duration(min(soa.Hdr.Ttl, soa.Minttl)) * time.Second
			}
		}
		return 0
	}
	switch r.Rcode {
	case dns.RcodeNameError:
		msgTtl = negativeTTL()
		cacheTtl = msgTtl
	case dns.RcodeServerFailure:
		msgTtl = time.Second * 5
		cacheTtl = msgTtl
	case dns.RcodeSuccess:
		minTTL := dnsutils.GetMinimalTTL(r)
		if len(r.Answer) == 0 && negativeTTL() > 0 {
			msgTtl = negativeTTL()
			cacheTtl = msgTtl
		} else if len(r.Answer) == 0 {
			// Do not cache an indeterminate empty answer without an SOA.
			msgTtl = 0
			cacheTtl = msgTtl
		} else {
			msgTtl = time.Duration(minTTL) * time.Second
			if lazyCacheTtl > 0 {
				cacheTtl = time.Duration(lazyCacheTtl) * time.Second
			} else {
				cacheTtl = msgTtl
			}
		}
	}
	if msgTtl <= 0 || cacheTtl <= 0 {
		return false
	}

	now := time.Now()
	storedResponse := copyNoOpt(r)
	if r.Rcode == dns.RcodeNameError || (r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0) {
		// RFC 2308: the SOA in a cached negative reply must advertise no
		// longer than the negative cache lifetime, not its original RR TTL.
		for _, rr := range storedResponse.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
			}
		}
	}
	v := &item{
		resp:           storedResponse,
		storedTime:     now,
		expirationTime: now.Add(msgTtl),
		next:           next,
		localNegative:  localNegative,
	}
	if expected != nil {
		return backend.StoreIf(key(msgKey), v, now.Add(cacheTtl), func(old *item) bool {
			return old == expected
		})
	}
	backend.Store(key(msgKey), v, now.Add(cacheTtl))
	return true
}

// normalizeNegativeSOA clones a negative response only if it needs an SOA
// TTL correction. The caller must preserve the other QueryContext metadata
// when committing the copy. Upstream-owned response objects are not mutated.
func normalizeNegativeSOA(r *dns.Msg) *dns.Msg {
	if r == nil || (r.Rcode != dns.RcodeNameError && (r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0)) {
		return r
	}
	var normalized *dns.Msg
	for i, rr := range r.Ns {
		if soa, ok := rr.(*dns.SOA); ok && soa.Hdr.Ttl > soa.Minttl {
			if normalized == nil {
				normalized = r.Copy()
			}
			normalized.Ns[i].Header().Ttl = soa.Minttl
		}
	}
	if normalized != nil {
		return normalized
	}
	return r
}
