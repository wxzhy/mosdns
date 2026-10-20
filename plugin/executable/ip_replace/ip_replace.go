// Package ip_replace replaces the terminal address RRset using configured
// network prefixes and the host bits of the first matching original address.
package ip_replace

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/response"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "ip_replace"

type Args struct {
	ReplaceMap []Rule `yaml:"replace_map"`
}

// Rule uses full-length prefixes by default, producing fixed replacement IPs.
// Pointer lengths distinguish an omitted default from an explicit /0.
type Rule struct {
	MatchIP       []string `yaml:"match_ip"`
	ExcludeIP     []string `yaml:"exclude_ip"`
	IPv4PrefixLen *int     `yaml:"ipv4_prefixlen"`
	IPv6PrefixLen *int     `yaml:"ipv6_prefixlen"`
	IPv4          []string `yaml:"ipv4"`
	IPv6          []string `yaml:"ipv6"`
}

type compiledRule struct {
	match, exclude netlist.Matcher
	ipv4, ipv6     []netip.Addr
	prefix4        int
	prefix6        int
}

// Replacer is immutable after construction and may be shared by query branches.
type Replacer struct {
	rules []compiledRule
}

var _ sequence.Executable = (*Replacer)(nil)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	return New(bp, args.(*Args))
}

func New(bp *coremain.BP, args *Args) (*Replacer, error) {
	if args == nil {
		return nil, fmt.Errorf("ip_replace: args must not be nil")
	}
	p := &Replacer{rules: make([]compiledRule, 0, len(args.ReplaceMap))}
	for i, rule := range args.ReplaceMap {
		compiled, err := compileRule(bp, rule)
		if err != nil {
			return nil, fmt.Errorf("ip_replace: replace_map #%d: %w", i, err)
		}
		p.rules = append(p.rules, compiled)
	}
	return p, nil
}

func compileRule(bp *coremain.BP, rule Rule) (compiledRule, error) {
	var out compiledRule
	if len(rule.MatchIP) == 0 {
		return out, fmt.Errorf("match_ip must not be empty")
	}
	var err error
	if out.match, err = ip_set.CompileExpressions(bp, rule.MatchIP); err != nil {
		return out, fmt.Errorf("match_ip: %w", err)
	}
	if out.exclude, err = ip_set.CompileExpressions(bp, rule.ExcludeIP); err != nil {
		return out, fmt.Errorf("exclude_ip: %w", err)
	}
	if out.prefix4, err = prefixLength(rule.IPv4PrefixLen, 32); err != nil {
		return out, fmt.Errorf("ipv4_prefixlen: %w", err)
	}
	if out.prefix6, err = prefixLength(rule.IPv6PrefixLen, 128); err != nil {
		return out, fmt.Errorf("ipv6_prefixlen: %w", err)
	}
	if out.ipv4, err = compileTargets(rule.IPv4, out.prefix4, true); err != nil {
		return out, fmt.Errorf("ipv4: %w", err)
	}
	if out.ipv6, err = compileTargets(rule.IPv6, out.prefix6, false); err != nil {
		return out, fmt.Errorf("ipv6: %w", err)
	}
	return out, nil
}

func prefixLength(value *int, bits int) (int, error) {
	if value == nil {
		return bits, nil
	}
	if *value < 0 || *value > bits {
		return 0, fmt.Errorf("must be within 0..%d", bits)
	}
	return *value, nil
}

func compileTargets(values []string, prefix int, ipv4 bool) ([]netip.Addr, error) {
	var out []netip.Addr
	seen := make(map[netip.Addr]bool)
	for i, value := range values {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.Is4() != ipv4 || ip.Is4In6() {
			return nil, fmt.Errorf("invalid address #%d %q for this address family", i, value)
		}
		base := netip.PrefixFrom(ip, prefix).Masked().Addr()
		if !seen[base] {
			out = append(out, base)
			seen[base] = true
		}
	}
	return out, nil
}

// replaceIP combines normalized target network bits and original host bits.
// It deliberately does not add an offset, which could carry into network bits.
func replaceIP(original, base netip.Addr, prefix int) netip.Addr {
	if original.Is4() {
		host, network := original.As4(), base.As4()
		for i := range network {
			bits := min(8, max(0, prefix-i*8))
			mask := byte(0xff << (8 - bits))
			network[i] |= host[i] & ^mask
		}
		return netip.AddrFrom4(network)
	}
	host, network := original.As16(), base.As16()
	for i := range network {
		bits := min(8, max(0, prefix-i*8))
		mask := byte(0xff << (8 - bits))
		network[i] |= host[i] & ^mask
	}
	return netip.AddrFrom16(network)
}

func (p *Replacer) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if len(p.rules) == 0 || qCtx.R() == nil {
		return nil
	}
	query := qCtx.Q()
	if query == nil || query.Response || len(query.Question) != 1 {
		return fmt.Errorf("ip_replace: expected a query with one question")
	}
	question := query.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	// Client DO remains authoritative even if another executable changed QOpt.
	if opt := qCtx.ClientOpt(); opt != nil && opt.Do() {
		return nil
	}
	if opt := query.IsEdns0(); opt != nil && opt.Do() {
		return nil
	}
	candidate, err := response.Analyze(query, qCtx.SnapshotResponse(), time.Now())
	if err != nil {
		return fmt.Errorf("ip_replace: %w", err)
	}
	if !candidate.Rewritable {
		return nil
	}
	for _, rule := range p.rules {
		for _, address := range candidate.Addresses {
			if rule.exclude.Match(address.IP) || !rule.match.Match(address.IP) {
				continue
			}
			targets, prefix := rule.ipv4, rule.prefix4
			if question.Qtype == dns.TypeAAAA {
				targets, prefix = rule.ipv6, rule.prefix6
			}
			// First matching rule/IP owns the decision, including an empty
			// target list for this family.
			if len(targets) == 0 {
				return nil
			}
			ips := make([]netip.Addr, 0, len(targets))
			for _, target := range targets {
				ips = append(ips, replaceIP(address.IP, target, prefix))
			}
			snapshot, err := response.ReplaceAddresses(candidate, ips, time.Now())
			if err != nil {
				return fmt.Errorf("ip_replace: %w", err)
			}
			if err := ctx.Err(); err != nil {
				return context.Cause(ctx)
			}
			if until := snapshot.ValidUntil; !until.IsZero() && !time.Now().Before(until) {
				return fmt.Errorf("ip_replace: source response expired before replacement")
			}
			qCtx.CommitResponse(snapshot)
			return nil
		}
	}
	return nil
}
