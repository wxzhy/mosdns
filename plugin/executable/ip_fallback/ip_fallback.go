// Package ip_fallback applies configured addresses when the
// current response has no address data or a preceding speedcheck failed.
package ip_fallback

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/response"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/internal/iptarget"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "ip_fallback"

type Args struct {
	IPSource string        `yaml:"ip_source"`
	Timeout  time.Duration `yaml:"timeout"`
	IPv4     []string      `yaml:"ipv4"`
	IPv6     []string      `yaml:"ipv6"`
	TTL      *int64        `yaml:"ttl"`
	// A nil On uses all_probes_failed and nodata. An empty list disables the
	// fallback; no_rtt also includes explicitly unmeasured speedcheck results.
	On []string `yaml:"on"`
}

type Fallback struct {
	ipv4, ipv6               iptarget.List
	targets                  *iptarget.Resolver
	ttl                      uint32
	allFailed, nodata, noRTT bool
}

var _ sequence.Executable = (*Fallback)(nil)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	return newConfiguredFallback(bp, args.(*Args))
}

func New(args *Args) (*Fallback, error) {
	return newConfiguredFallback(nil, args)
}

func newConfiguredFallback(bp *coremain.BP, args *Args) (*Fallback, error) {
	if args == nil {
		return nil, fmt.Errorf("ip_fallback: args must not be nil")
	}
	f := &Fallback{ttl: 86400}
	if args.TTL != nil {
		if *args.TTL < 0 || uint64(*args.TTL) > uint64(^uint32(0)) {
			return nil, fmt.Errorf("ip_fallback: ttl must be within 0..4294967295")
		}
		f.ttl = uint32(*args.TTL)
	}
	var err error
	if f.ipv4, err = iptarget.Compile(args.IPv4, true); err != nil {
		return nil, fmt.Errorf("ip_fallback: ipv4: %w", err)
	}
	if f.ipv6, err = iptarget.Compile(args.IPv6, false); err != nil {
		return nil, fmt.Errorf("ip_fallback: ipv6: %w", err)
	}
	on := args.On
	if on == nil {
		on = []string{"all_probes_failed", "nodata"}
	}
	for _, condition := range on {
		switch condition {
		case "all_probes_failed":
			f.allFailed = true
		case "nodata":
			f.nodata = true
		case "no_rtt":
			f.noRTT = true
		default:
			return nil, fmt.Errorf("ip_fallback: unknown on condition %q", condition)
		}
	}
	if f.targets, err = iptarget.New(bp, args.IPSource, args.Timeout, f.ipv4.Dynamic() || f.ipv6.Dynamic()); err != nil {
		return nil, fmt.Errorf("ip_fallback: %w", err)
	}
	return f, nil
}

func (f *Fallback) Close() error { return f.targets.Close() }

func (f *Fallback) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if iptarget.IsSubquery(ctx) {
		return nil
	}
	if qCtx.R() == nil || (!f.allFailed && !f.nodata && !f.noRTT) {
		return nil
	}
	query := qCtx.Q()
	if query == nil || query.Response || len(query.Question) != 1 {
		return fmt.Errorf("ip_fallback: expected a query with one question")
	}
	question := query.Question[0]
	if query.Opcode != dns.OpcodeQuery || question.Qclass != dns.ClassINET ||
		(question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	if opt := qCtx.ClientOpt(); opt != nil && opt.Do() {
		return nil
	}
	if opt := query.IsEdns0(); opt != nil && opt.Do() {
		return nil
	}
	snapshot := qCtx.SnapshotResponse()
	candidate, err := response.Analyze(query, snapshot, time.Now())
	if err != nil {
		return fmt.Errorf("ip_fallback: %w", err)
	}
	if snapshot.Response.Rcode != dns.RcodeSuccess || snapshot.Response.Truncated || opaque(snapshot.Response) {
		return nil
	}
	trigger := f.nodata && candidate.Negative ||
		f.allFailed && snapshot.ProbeStatus == query_context.ProbeFailed ||
		f.noRTT && (snapshot.ProbeStatus == query_context.ProbeFailed || snapshot.ProbeStatus == query_context.ProbeUnmeasured)
	if !trigger {
		return nil
	}
	list := f.ipv4
	if question.Qtype == dns.TypeAAAA {
		list = f.ipv6
	}
	if len(list) == 0 {
		return nil
	}
	targets, err := f.targets.Resolve(ctx, qCtx, list, question.Qtype)
	if err != nil {
		return err
	}
	keepOriginal := func() error {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if list.Dynamic() {
			qCtx.CommitResponse(response.Replay(candidate, time.Now()))
		}
		return nil
	}
	if len(targets) == 0 {
		return keepOriginal()
	}
	var ips []netip.Addr
	var sources []*response.Candidate
	for _, target := range targets {
		ips = append(ips, target.IP)
		if target.Source != nil {
			sources = append(sources, target.Source)
		}
	}
	replacement, err := response.StaticAddresses(candidate, ips, f.ttl, time.Now())
	if err != nil {
		return fmt.Errorf("ip_fallback: %w", err)
	}
	replacement = response.LimitAddressLifetime(replacement, sources, time.Now())
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if until := replacement.ValidUntil; !until.IsZero() && !time.Now().Before(until) {
		if list.Dynamic() {
			return keepOriginal()
		}
		return fmt.Errorf("ip_fallback: alias chain expired before fallback")
	}
	qCtx.CommitResponse(replacement)
	return nil
}

// Authenticated or alias forms whose semantics cannot be reconstructed are
// passed through. This includes opaque NODATA, for which Rewritable is false
// independently of whether it contains a TSIG or DNAME.
func opaque(msg *dns.Msg) bool {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
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
