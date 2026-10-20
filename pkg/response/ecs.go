package response

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

type subnet struct {
	family uint16
	source uint8
	scope  uint8
	prefix netip.Prefix
}

type ecsView struct {
	query *subnet
	reply *subnet
}

func (v *ecsView) key() string {
	if v == nil || v.query == nil {
		return "no-ecs"
	}
	q := v.query
	return fmt.Sprintf("ecs:%d:%d:%s", q.family, q.source, q.prefix.Addr())
}

func analyzeECS(queryOpt, upstreamOpt, respOpt *dns.OPT) (*ecsView, error) {
	q, err := readSubnet(queryOpt, true)
	if err != nil {
		return nil, err
	}
	u, err := readSubnet(upstreamOpt, false)
	if err != nil {
		return nil, err
	}
	r, err := readSubnet(respOpt, false)
	if err != nil {
		return nil, err
	}
	for _, received := range []*subnet{u, r} {
		if received == nil {
			continue
		}
		if q == nil || q.family != received.family || q.source != received.source || q.prefix != received.prefix {
			return nil, fmt.Errorf("response: ECS does not match query")
		}
	}
	if u == nil {
		u = r
	} else if r != nil && u.scope != r.scope {
		return nil, fmt.Errorf("response: conflicting upstream and downstream ECS scope")
	}
	return &ecsView{query: q, reply: u}, nil
}

func readSubnet(opt *dns.OPT, query bool) (*subnet, error) {
	var result *subnet
	if opt == nil {
		return nil, nil
	}
	for _, option := range opt.Option {
		if option.Option() != dns.EDNS0SUBNET {
			continue
		}
		ecs, ok := option.(*dns.EDNS0_SUBNET)
		if !ok || result != nil {
			return nil, fmt.Errorf("response: invalid or duplicate ECS option")
		}
		var ip net.IP
		var bits int
		switch ecs.Family {
		case 1:
			ip, bits = ecs.Address.To4(), 32
		case 2:
			ip, bits = ecs.Address.To16(), 128
		default:
			return nil, fmt.Errorf("response: invalid ECS family %d", ecs.Family)
		}
		addr, ok := netip.AddrFromSlice(ip)
		// RFC 7871 sections 7.2.1 and 7.3.1 explicitly allow a response's
		// scope to exceed its source prefix. The view key retains the exact
		// source length/address; it never invents the undisclosed scope bits.
		// https://www.rfc-editor.org/rfc/rfc7871.html#section-7.2.1
		if !ok || int(ecs.SourceNetmask) > bits || int(ecs.SourceScope) > bits || (query && ecs.SourceScope != 0) {
			return nil, fmt.Errorf("response: invalid ECS address or prefix")
		}
		prefix := netip.PrefixFrom(addr, int(ecs.SourceNetmask)).Masked()
		result = &subnet{family: ecs.Family, source: ecs.SourceNetmask, scope: ecs.SourceScope, prefix: prefix}
	}
	return result, nil
}

// Only ECS is safe to retain in a synthesized response. Other options may name
// an upstream server, describe a discarded failure, or authenticate a connection.
func rebuiltOpts(anchor *Candidate, contributors map[*Candidate]bool) (*dns.OPT, *dns.OPT) {
	var scope uint8
	var hasReply bool
	for c := range contributors {
		if c.ecs != nil && c.ecs.reply != nil {
			hasReply = true
			if c.ecs.reply.scope > scope {
				scope = c.ecs.reply.scope
			}
		}
	}
	upstreamOpt := cleanOpt(anchor.Snapshot.UpstreamOpt)
	respOpt := cleanOpt(anchor.Snapshot.RespOpt)
	if hasReply && anchor.ecs != nil && anchor.ecs.query != nil {
		if upstreamOpt == nil {
			upstreamOpt = new(dns.OPT)
			upstreamOpt.Hdr.Name = "."
			upstreamOpt.Hdr.Rrtype = dns.TypeOPT
			upstreamOpt.SetUDPSize(1232)
		}
		upstreamOpt.Option = append(upstreamOpt.Option, makeSubnet(anchor.ecs.query, scope))
		// Preserve whether the branch's EDNS policy allowed ECS downstream.
		if respOpt != nil && optHasECS(anchor.Snapshot.RespOpt) {
			respOpt.Option = append(respOpt.Option, makeSubnet(anchor.ecs.query, scope))
		}
	}
	return upstreamOpt, respOpt
}

func cleanOpt(opt *dns.OPT) *dns.OPT {
	if opt == nil {
		return nil
	}
	copyOPT := dns.Copy(opt).(*dns.OPT)
	copyOPT.Option = nil
	// A synthesized NOERROR response has no source extended RCODE, EDNS
	// version or reserved flags. Preserve only the policy's DO echo.
	copyOPT.Hdr.Ttl = 0
	if opt.Do() {
		copyOPT.SetDo()
	}
	return copyOPT
}

func makeSubnet(q *subnet, scope uint8) *dns.EDNS0_SUBNET {
	return &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: q.family, SourceNetmask: q.source,
		SourceScope: scope, Address: net.IP(q.prefix.Addr().AsSlice()),
	}
}

func optHasECS(opt *dns.OPT) bool {
	if opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0SUBNET {
				return true
			}
		}
	}
	return false
}
