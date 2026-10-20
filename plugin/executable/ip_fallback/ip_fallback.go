// Package ip_fallback applies explicitly configured static addresses when the
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
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "ip_fallback"

type Args struct {
	IPv4 []string `yaml:"ipv4"`
	IPv6 []string `yaml:"ipv6"`
	TTL  *int64   `yaml:"ttl"`
	// A nil On uses all_probes_failed and nodata. An empty list disables the
	// fallback; no_rtt also includes explicitly unmeasured speedcheck results.
	On []string `yaml:"on"`
}

type Fallback struct {
	ipv4, ipv6               []netip.Addr
	ttl                      uint32
	allFailed, nodata, noRTT bool
}

var _ sequence.Executable = (*Fallback)(nil)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(_ *coremain.BP, args any) (any, error) {
	return New(args.(*Args))
}

func New(args *Args) (*Fallback, error) {
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
	if f.ipv4, err = compileIPs(args.IPv4, true); err != nil {
		return nil, fmt.Errorf("ip_fallback: ipv4: %w", err)
	}
	if f.ipv6, err = compileIPs(args.IPv6, false); err != nil {
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
	return f, nil
}

func compileIPs(values []string, ipv4 bool) ([]netip.Addr, error) {
	var out []netip.Addr
	seen := make(map[netip.Addr]bool)
	for i, value := range values {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.Is4() != ipv4 || ip.Is4In6() {
			return nil, fmt.Errorf("invalid address #%d %q for this address family", i, value)
		}
		if !seen[ip] {
			out = append(out, ip)
			seen[ip] = true
		}
	}
	return out, nil
}

func (f *Fallback) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
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
	ips := f.ipv4
	if question.Qtype == dns.TypeAAAA {
		ips = f.ipv6
	}
	if len(ips) == 0 {
		return nil
	}
	replacement, err := response.StaticAddresses(candidate, ips, f.ttl, time.Now())
	if err != nil {
		return fmt.Errorf("ip_fallback: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if until := replacement.ValidUntil; !until.IsZero() && !time.Now().Before(until) {
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
