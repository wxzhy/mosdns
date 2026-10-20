// Package https_record applies HTTPS/SVCB response policy without changing the
// messages owned by an upstream, another source branch or a response cache.
package https_record

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/domain_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "https_record"

const (
	defaultOptionalTimeout = 500 * time.Millisecond
	maxECHCacheEntries     = 100
	maxECHCacheTTL         = 300 * time.Second
	maxConcurrentIPLookups = 8
)

type Args struct {
	RemoveHint     *bool         `yaml:"remove_hint"`
	RemoveH3       *bool         `yaml:"remove_h3"`
	RemoveALPN     []string      `yaml:"remove_alpn"`
	AddECH         *bool         `yaml:"add_ech"`
	EnableSubquery *bool         `yaml:"enable_subquery"`
	ECHSource      string        `yaml:"ech_source"`
	ECHDomain      string        `yaml:"ech_domain"`
	IPSource       string        `yaml:"ip_source"`
	MatchName      []string      `yaml:"match_name"`
	MatchIP        []string      `yaml:"match_ip"`
	ExcludeIP      []string      `yaml:"exclude_ip"`
	Timeout        time.Duration `yaml:"timeout"`
}

type Record struct {
	removeHint, removeH3, addECH, subquery bool
	removeALPN                             []string
	echDomain                              string
	timeout                                time.Duration
	echSource, ipSource                    sequence.Executable
	nameMatch                              domain.Matcher[struct{}]
	matchName                              bool
	ipMatch, ipExclude                     netlist.Matcher
	includeConfigured, ipGate              bool

	life       context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	active     sync.WaitGroup
	cache      map[echCacheKey]echCacheEntry
	cacheOrder uint64
	now        func() time.Time
}

var _ sequence.Executable = (*Record)(nil)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) { return New(bp, args.(*Args)) }

func New(bp *coremain.BP, args *Args) (*Record, error) {
	if args == nil {
		return nil, fmt.Errorf("https_record: args must not be nil")
	}
	p := &Record{
		removeHint: enabled(args.RemoveHint), removeH3: enabled(args.RemoveH3),
		addECH: enabled(args.AddECH), subquery: enabled(args.EnableSubquery),
		removeALPN: append([]string(nil), args.RemoveALPN...),
		echDomain:  args.ECHDomain, timeout: args.Timeout,
		matchName:         args.MatchName != nil,
		includeConfigured: args.MatchIP != nil,
		ipGate:            args.MatchIP != nil || len(args.ExcludeIP) > 0,
		cache:             make(map[echCacheKey]echCacheEntry), now: time.Now,
	}
	if p.echDomain == "" {
		p.echDomain = "crypto.cloudflare.com"
	}
	p.echDomain = dns.CanonicalName(p.echDomain)
	if _, ok := dns.IsDomainName(p.echDomain); !ok {
		return nil, fmt.Errorf("https_record: invalid ech_domain %q", args.ECHDomain)
	}
	if p.timeout == 0 {
		p.timeout = defaultOptionalTimeout
	}
	if p.timeout < 0 {
		return nil, fmt.Errorf("https_record: timeout must be positive")
	}
	for _, alpn := range p.removeALPN {
		if len(alpn) == 0 || len(alpn) > 255 {
			return nil, fmt.Errorf("https_record: remove_alpn IDs must be 1..255 bytes")
		}
	}
	var err error
	if p.nameMatch, err = compileDomains(bp, args.MatchName); err != nil {
		return nil, fmt.Errorf("https_record: match_name: %w", err)
	}
	if p.ipMatch, err = compileIPs(bp, args.MatchIP); err != nil {
		return nil, fmt.Errorf("https_record: match_ip: %w", err)
	}
	if p.ipExclude, err = compileIPs(bp, args.ExcludeIP); err != nil {
		return nil, fmt.Errorf("https_record: exclude_ip: %w", err)
	}
	if p.addECH {
		if p.echSource, err = source(bp, args.ECHSource); err != nil {
			return nil, fmt.Errorf("https_record: ech_source: %w", err)
		}
		if p.subquery {
			if p.ipSource, err = source(bp, args.IPSource); err != nil {
				return nil, fmt.Errorf("https_record: ip_source: %w", err)
			}
		}
	}
	p.life, p.cancel = context.WithCancel(context.Background())
	return p, nil
}

func enabled(value *bool) bool { return value == nil || *value }

func source(bp *coremain.BP, tag string) (sequence.Executable, error) {
	if tag == "" || bp == nil {
		return nil, fmt.Errorf("requires a previously defined executable tag")
	}
	s := sequence.ToExecutable(bp.M().GetPlugin(tag))
	if s == nil {
		return nil, fmt.Errorf("%q is not an executable", tag)
	}
	return s, nil
}

func compileDomains(bp *coremain.BP, expressions []string) (domain.Matcher[struct{}], error) {
	l := domain_set.NewMixLoader()
	var group domain_set.MatcherGroup
	for i, exp := range expressions {
		exp = strings.TrimSpace(exp)
		if exp == "" {
			return nil, fmt.Errorf("empty expression #%d", i)
		}
		switch exp[0] {
		case '$':
			if bp == nil {
				return nil, fmt.Errorf("cannot resolve domain set %q", exp)
			}
			provider, ok := bp.M().GetPlugin(exp[1:]).(data_provider.DomainMatcherProvider)
			if !ok {
				return nil, fmt.Errorf("%q is not a DomainMatcherProvider", exp)
			}
			m := provider.GetDomainMatcher()
			if m == nil {
				return nil, fmt.Errorf("%q returned a nil domain matcher", exp)
			}
			group = append(group, m)
		case '&':
			if exp[1:] == "" {
				return nil, fmt.Errorf("empty file expression")
			}
			if err := l.LoadFiles([]string{exp[1:]}); err != nil {
				return nil, err
			}
		default:
			if err := l.LoadExps([]string{exp}); err != nil {
				return nil, err
			}
		}
	}
	return append(group, l.Matchers()...), nil
}

func compileIPs(bp *coremain.BP, expressions []string) (netlist.Matcher, error) {
	l := ip_set.NewListLoader()
	var group ip_set.MatcherGroup
	for i, exp := range expressions {
		exp = strings.TrimSpace(exp)
		if exp == "" {
			return nil, fmt.Errorf("empty expression #%d", i)
		}
		switch exp[0] {
		case '$':
			if bp == nil {
				return nil, fmt.Errorf("cannot resolve IP set %q", exp)
			}
			provider, ok := bp.M().GetPlugin(exp[1:]).(data_provider.IPMatcherProvider)
			if !ok {
				return nil, fmt.Errorf("%q is not an IPMatcherProvider", exp)
			}
			m := provider.GetIPMatcher()
			if m == nil {
				return nil, fmt.Errorf("%q returned a nil IP matcher", exp)
			}
			group = append(group, m)
		case '&':
			if exp[1:] == "" {
				return nil, fmt.Errorf("empty file expression")
			}
			if err := l.LoadFromFiles([]string{exp[1:]}); err != nil {
				return nil, err
			}
		default:
			if err := l.LoadFromIPs([]string{exp}); err != nil {
				return nil, err
			}
		}
	}
	return append(group, l.Matchers()...), nil
}

// allowedIPs applies a policy to one complete ServiceMode record or A result.
// An excluded address vetoes the record even if another address is included.
func (p *Record) allowedIPs(ips []netip.Addr) bool {
	included := !p.includeConfigured
	for _, ip := range ips {
		if p.ipExclude.Match(ip) {
			return false
		}
		included = included || p.ipMatch.Match(ip)
	}
	return included && (!p.ipGate || len(ips) > 0)
}

func (p *Record) begin() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.active.Add(1)
	return true
}

func (p *Record) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.cancel()
	}
	p.mu.Unlock()
	p.active.Wait()
	p.mu.Lock()
	clear(p.cache)
	p.mu.Unlock()
	return nil
}
