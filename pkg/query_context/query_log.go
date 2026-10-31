package query_context

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap/zapcore"
)

// QueryLogObject describes the response actually prepared for the client.
// includeRules is chosen by the instance's logger, rather than a global level.
// Neither marshaling nor this wrapper changes query or response ownership.
func (ctx *Context) QueryLogObject(response *dns.Msg, includeRules bool) zapcore.ObjectMarshaler {
	return queryLogObject{ctx: ctx, response: response, includeRules: includeRules}
}

type queryLogObject struct {
	ctx          *Context
	response     *dns.Msg
	includeRules bool
}

func (o queryLogObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return o.ctx.marshalQueryLog(enc, o.response, o.includeRules)
}

func (ctx *Context) marshalQueryLog(enc zapcore.ObjectEncoder, response *dns.Msg, includeRules bool) error {
	enc.AddUint32("uqid", ctx.id)
	if addr := ctx.ServerMeta.ClientAddr; addr.IsValid() {
		enc.AddString("client", addr.String())
	}
	question := ctx.QQuestion()
	enc.AddString("qname", question.Name)
	qtype := dns.TypeToString[question.Qtype]
	if qtype == "" {
		qtype = fmt.Sprintf("TYPE%d", question.Qtype)
	}
	enc.AddString("qtype", qtype)
	enc.AddUint16("qclass", question.Qclass)
	protocol := ctx.ServerMeta.Protocol
	if protocol == "" {
		protocol = "TCP"
		if ctx.ServerMeta.FromUDP {
			protocol = "UDP"
		}
	}
	enc.AddString("protocol", protocol)
	if includeRules && len(ctx.RuleHits) > 0 {
		_ = enc.AddArray("rule_hits", zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
			for _, hit := range ctx.RuleHits {
				if err := arr.AppendObject(zapcore.ObjectMarshalerFunc(func(e zapcore.ObjectEncoder) error {
					e.AddString("sequence", hit.Sequence)
					_ = e.AddArray("matches", stringArray(hit.Matches))
					e.AddString("exec", hit.Exec)
					return nil
				})); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	if u := ctx.UpstreamSelected; u != nil {
		_ = enc.AddObject("upstream", zapcore.ObjectMarshalerFunc(func(e zapcore.ObjectEncoder) error {
			e.AddString("addr", u.Addr)
			e.AddString("protocol", u.Protocol)
			e.AddString("tag", u.Tag)
			e.AddString("plugin", u.Plugin)
			return nil
		}))
	}
	_ = enc.AddObject("cache", zapcore.ObjectMarshalerFunc(func(e zapcore.ObjectEncoder) error {
		e.AddBool("hit", ctx.CacheState.Hit)
		e.AddBool("lazy_hit", ctx.CacheState.LazyHit)
		e.AddInt("ttl", ctx.CacheState.TTL)
		e.AddInt("remaining_ttl", ctx.CacheState.RemainingTTL)
		return nil
	}))
	if ctx.FromHosts {
		enc.AddBool("hosts", true)
	}
	if ctx.FromArbitrary {
		enc.AddBool("arbitrary", true)
	}
	if response != nil {
		enc.AddInt("rcode", response.Rcode)
		enc.AddInt("resp_size", response.Len())
		var ips, cnames []string
		var ttl uint32
		for _, rr := range response.Answer {
			ttl = rr.Header().Ttl
			switch r := rr.(type) {
			case *dns.A:
				ips = append(ips, r.A.String())
			case *dns.AAAA:
				ips = append(ips, r.AAAA.String())
			case *dns.CNAME:
				cnames = append(cnames, r.Target)
			}
		}
		if len(ips) > 0 {
			_ = enc.AddArray("ips", stringArray(ips))
		}
		if len(cnames) > 0 {
			_ = enc.AddArray("cnames", stringArray(cnames))
		}
		if len(response.Answer) > 0 {
			enc.AddUint32("original_ttl", ttl)
		}
	}
	enc.AddDuration("elapsed", time.Since(ctx.startTime))
	return nil
}

func stringArray(values []string) zapcore.ArrayMarshaler {
	return zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
		for _, value := range values {
			arr.AppendString(value)
		}
		return nil
	})
}
