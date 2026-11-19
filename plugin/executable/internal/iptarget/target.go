// Package iptarget implements optional, isolated address lookups shared by
// ip_fallback and ip_replace. It deliberately owns no response cache.
package iptarget

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/IrineSistiana/mosdns/v5/pkg/response"
	forward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type Entry struct {
	IP     netip.Addr
	Domain string
}

type List []Entry

func (l List) Dynamic() bool {
	for _, e := range l {
		if e.Domain != "" {
			return true
		}
	}
	return false
}

// Compile retains configuration order, including the provenance of duplicates.
// Names are ASCII hostnames (international names must use their A-label form).
func Compile(values []string, ipv4 bool) (List, error) {
	var list List
	for i, value := range values {
		if name, ok := strings.CutPrefix(value, "domain:"); ok {
			name = dns.CanonicalName(name)
			if !hostname(name) {
				return nil, fmt.Errorf("invalid domain target #%d %q", i, value)
			}
			list = append(list, Entry{Domain: name})
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.Is4() != ipv4 {
			return nil, fmt.Errorf("invalid address #%d %q for this address family", i, value)
		}
		list = append(list, Entry{IP: ip})
	}
	return list, nil
}

func hostname(name string) bool {
	if name == "." {
		return false
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// IsSubquery skips both rewriting plugins, even through an indirect source.
func IsSubquery(ctx context.Context) bool { return query_policy.AddressTargetLookup(ctx) }

var ErrClosed = errors.New("ip target resolver is closed")

type Resolver struct {
	source  sequence.Executable
	timeout time.Duration
	log     *zap.Logger
	life    context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	active  sync.WaitGroup
}

func New(bp *coremain.BP, tag string, timeout time.Duration, required bool) (*Resolver, error) {
	if timeout < 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}
	r := &Resolver{timeout: timeout, log: zap.NewNop()}
	if required || tag != "" {
		if bp == nil || tag == "" || strings.HasPrefix(tag, "$") {
			return nil, fmt.Errorf("ip_source requires a previously defined forward or sequence tag, without $")
		}
		p := bp.M().GetPlugin(tag)
		switch p.(type) {
		case *forward.Forward, *sequence.Sequence:
		default:
			return nil, fmt.Errorf("ip_source %q is not a previously defined forward or sequence", tag)
		}
		r.source = sequence.ToExecutable(p)
	}
	if bp != nil {
		r.log = bp.L()
	}
	r.life, r.cancel = context.WithCancel(context.Background())
	return r, nil
}

func (r *Resolver) Close() error {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.mu.Unlock()
	r.active.Wait()
	return nil
}

// Target keeps the source candidate so TTLs can be recomputed after every
// lookup finishes, instead of restarting a sampled integer TTL at commit time.
type Target struct {
	IP     netip.Addr
	Source *response.Candidate
}

// Resolve uses at most eight workers and one shared deadline. Every worker is
// joined before returning; configured executables must honor cancellation.
func (r *Resolver) Resolve(ctx context.Context, parent *query_context.Context, list List, typ uint16) ([]Target, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, ErrClosed
	}
	r.active.Add(1)
	r.mu.Unlock()
	defer r.active.Done()
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	var names []string
	indexes := make(map[string]int)
	for _, entry := range list {
		if entry.Domain != "" {
			if _, ok := indexes[entry.Domain]; !ok {
				indexes[entry.Domain] = len(names)
				names = append(names, entry.Domain)
			}
		}
	}
	results := make([]*response.Candidate, len(names))
	if len(names) > 0 {
		budget := r.timeout
		if deadline, ok := ctx.Deadline(); ok {
			left := time.Until(deadline)
			budget = min(budget, left-min(25*time.Millisecond, left/2))
		}
		optional, cancel := context.WithTimeout(ctx, max(0, budget))
		stop := context.AfterFunc(r.life, cancel)
		defer stop()
		defer cancel()
		optional = query_policy.WithInheritedCancellation(query_policy.WithAddressTargetLookup(optional))
		// Build isolated contexts before launching workers. Context is not safe
		// for concurrent access, even for a lazy read by a source executable.
		branches := make([]*query_context.Context, len(names))
		for i, name := range names {
			branches[i] = subquery(parent, name, typ)
		}
		jobs := make(chan int, len(names))
		for i := range names {
			jobs <- i
		}
		close(jobs)
		var workers sync.WaitGroup
		for n := 0; n < min(8, len(names)); n++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for i := range jobs {
					c, err := r.lookup(optional, branches[i])
					if err != nil {
						r.log.Debug("optional IP target lookup failed", zap.String("domain", names[i]), zap.Uint16("qtype", typ), zap.Error(err))
					} else {
						results[i] = c
					}
				}
			}()
		}
		workers.Wait()
		cancel()
	}
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	if r.life.Err() != nil {
		return nil, ErrClosed
	}
	var out []Target
	seen := make(map[netip.Addr]bool)
	add := func(ip netip.Addr, c *response.Candidate) {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, Target{IP: ip, Source: c})
		}
	}
	now := time.Now()
	for _, entry := range list {
		if entry.Domain == "" {
			add(entry.IP, nil)
			continue
		}
		c := results[indexes[entry.Domain]]
		if c == nil {
			continue
		}
		if until := c.Snapshot.ValidUntil; !until.IsZero() && !now.Before(until) {
			r.log.Debug("optional IP target expired", zap.String("domain", entry.Domain))
			continue
		}
		for _, address := range c.Addresses {
			add(address.IP, c)
		}
	}
	return out, nil
}

func subquery(parent *query_context.Context, name string, typ uint16) *query_context.Context {
	q := parent.Q().Copy()
	q.Id = dns.Id()
	q.Question = []dns.Question{{Name: name, Qtype: typ, Qclass: dns.ClassINET}}
	// Preserve the original client's EDNS separately from outgoing EDNS (which
	// may already include ECS or other route-specific policy).
	var outgoing *dns.OPT
	if opt := q.IsEdns0(); opt != nil {
		outgoing = cloneOPT(opt)
		for i, rr := range q.Extra {
			if rr == opt {
				q.Extra = append(q.Extra[:i], q.Extra[i+1:]...)
				break
			}
		}
	}
	if opt := parent.ClientOpt(); opt != nil {
		q.Extra = append(q.Extra, cloneOPT(opt))
	}
	branch := query_context.NewContext(q)
	if outgoing != nil {
		*branch.QOpt() = *outgoing
	}
	branch.ServerMeta = parent.ServerMeta
	return branch
}

// The pinned dns version copies these EDNS option structs but shares their
// byte slices. Clone those slices as well, including the client's original OPT.
func cloneOPT(opt *dns.OPT) *dns.OPT {
	out := dns.Copy(opt).(*dns.OPT)
	for _, option := range out.Option {
		switch o := option.(type) {
		case *dns.EDNS0_SUBNET:
			o.Address = slices.Clone(o.Address)
		case *dns.EDNS0_DAU:
			o.AlgCode = slices.Clone(o.AlgCode)
		case *dns.EDNS0_DHU:
			o.AlgCode = slices.Clone(o.AlgCode)
		case *dns.EDNS0_N3U:
			o.AlgCode = slices.Clone(o.AlgCode)
		}
	}
	return out
}

func (r *Resolver) lookup(ctx context.Context, q *query_context.Context) (c *response.Candidate, err error) {
	defer func() {
		if p := recover(); p != nil {
			c = nil
			err = fmt.Errorf("optional IP source panic: %v", p)
		}
	}()
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	if r.source == nil {
		return nil, errors.New("missing IP source")
	}
	expected := q.Q().Copy()
	if err := r.source.Exec(ctx, q); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	actual := q.Q()
	if actual == nil || actual.Response || actual.Id != expected.Id || actual.Opcode != expected.Opcode || len(actual.Question) != 1 || actual.Question[0] != expected.Question[0] {
		return nil, errors.New("IP source changed query correlation")
	}
	// Correlation is fixed above, but a configured ECS source may legitimately
	// change outgoing EDNS. Validate the response against that final DNS view.
	c, err = response.Analyze(actual, q.SnapshotResponse(), time.Now())
	if err != nil {
		return nil, err
	}
	if c.Snapshot.Response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("IP source returned rcode %d (%s)", c.Snapshot.Response.Rcode, dns.RcodeToString[c.Snapshot.Response.Rcode])
	}
	if c.Snapshot.Response.Truncated {
		return nil, errors.New("IP source returned a truncated response")
	}
	if len(c.Addresses) == 0 {
		return nil, errors.New("IP source returned no terminal addresses (NODATA)")
	}
	// The source is read, not rewritten. In particular, a dedicated resolver
	// may set DO itself; the user's original DO guard belongs to the caller.
	if until := c.Snapshot.ValidUntil; !until.IsZero() && !time.Now().Before(until) {
		return nil, errors.New("IP source expired")
	}
	return c, nil
}
