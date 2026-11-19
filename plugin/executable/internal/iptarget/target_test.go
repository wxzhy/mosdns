package iptarget

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/IrineSistiana/mosdns/v5/pkg/response"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func resolver(t *testing.T, fn sequence.ExecutableFunc) *Resolver {
	t.Helper()
	r, err := New(nil, "", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	r.source = fn
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func parent(typ uint16) *query_context.Context {
	return query_context.NewContext(new(dns.Msg).SetQuestion("user.example.", typ))
}

func answer(q *query_context.Context, ttl uint32, ips ...string) {
	r := new(dns.Msg).SetReply(q.Q())
	for _, ip := range ips {
		h := dns.RR_Header{Name: q.QQuestion().Name, Class: dns.ClassINET, Rrtype: q.QQuestion().Qtype, Ttl: ttl}
		if h.Rrtype == dns.TypeA {
			r.Answer = append(r.Answer, &dns.A{Hdr: h, A: net.ParseIP(ip)})
		} else {
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: h, AAAA: net.ParseIP(ip)})
		}
	}
	q.SetResponse(r)
}

func compile(t *testing.T, values []string, ipv4 bool) List {
	t.Helper()
	l, err := Compile(values, ipv4)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestCompileAndValidation(t *testing.T) {
	l := compile(t, []string{"domain:BACKUP.Example", "domain:backup.example.", "203.0.113.1"}, true)
	if l[0].Domain != "backup.example." || l[1].Domain != l[0].Domain || !l.Dynamic() {
		t.Fatal(l)
	}
	for _, value := range []string{"domain:", "domain:.", "domain:a..b", "domain: bad.example", "domain:*.example", "domain:-bad.example", "domain:bad-.example", "domain:example:53", "domain:域名.example", "::ffff:192.0.2.1", "fe80::1%eth0", "2001:db8::1", "bad"} {
		if _, err := Compile([]string{value}, true); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	if _, err := Compile([]string{"192.0.2.1"}, false); err == nil {
		t.Fatal("wrong family accepted")
	}
	for _, tc := range []struct {
		tag      string
		timeout  time.Duration
		required bool
	}{{"", -1, false}, {"", 0, true}, {"$resolver", 0, true}, {"missing", 0, false}} {
		if _, err := New(nil, tc.tag, tc.timeout, tc.required); err == nil {
			t.Errorf("accepted invalid source/timeout: %+v", tc)
		}
	}
}

func TestStableOrderFamilyDedupAndConcurrency(t *testing.T) {
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		t.Run(dns.TypeToString[typ], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var active, peak, calls atomic.Int32
				r := resolver(t, func(ctx context.Context, q *query_context.Context) error {
					calls.Add(1)
					n := active.Add(1)
					for old := peak.Load(); n > old; old = peak.Load() {
						if peak.CompareAndSwap(old, n) {
							break
						}
					}
					defer active.Add(-1)
					if q.QQuestion().Qtype != typ || !IsSubquery(ctx) || !query_policy.InheritCancellation(ctx) {
						t.Error("missing family/recursion/cancellation policy")
					}
					time.Sleep(10 * time.Millisecond)
					if typ == dns.TypeA {
						answer(q, 60, "203.0.113.2", "203.0.113.1", "203.0.113.2")
					} else {
						answer(q, 60, "2001:db8::2", "2001:db8::1")
					}
					return nil
				})
				literal, second := "203.0.113.1", "203.0.113.2"
				if typ == dns.TypeAAAA {
					literal, second = "2001:db8::1", "2001:db8::2"
				}
				values := []string{literal, "domain:SAME.example", "domain:same.example."}
				for i := 0; i < 12; i++ {
					values = append(values, fmt.Sprintf("domain:d%d.example", i))
				}
				got, err := r.Resolve(context.Background(), parent(typ), compile(t, values, typ == dns.TypeA), typ)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 2 || got[0].IP.String() != literal || got[0].Source != nil || got[1].IP.String() != second || got[1].Source == nil {
					t.Fatalf("order/provenance: %+v", got)
				}
				if calls.Load() != 13 || peak.Load() != 8 || active.Load() != 0 {
					t.Fatalf("calls=%d peak=%d active=%d", calls.Load(), peak.Load(), active.Load())
				}
			})
		})
	}
}

func TestSubqueryStateAndEDNSIsolation(t *testing.T) {
	key := query_context.RegKey()
	msg := new(dns.Msg).SetQuestion("user.example.", dns.TypeA)
	msg.CheckingDisabled = true
	msg.SetEdns0(1400, false)
	msg.IsEdns0().Option = append(msg.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"})
	p := query_context.NewContext(msg)
	p.QOpt().SetUDPSize(1232)
	p.QOpt().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.0.2.0")}}
	p.SetMark(37)
	p.StoreValue(key, &struct{ n int }{42})
	p.ServerMeta = query_context.ServerMeta{ClientAddr: netip.MustParseAddr("192.0.2.8"), FromUDP: true, Protocol: "udp", ServerName: "dns.example", UrlPath: "/dns-query"}
	answer(p, 300, "192.0.2.1")
	s := p.SnapshotResponse()
	s.ProbeStatus = query_context.ProbeFailed
	p.CommitResponse(s)
	r := resolver(t, func(ctx context.Context, q *query_context.Context) error {
		if q.R() != nil || q.HasMark(37) || q.SnapshotResponse().ProbeStatus != query_context.ProbeUnknown {
			t.Error("inherited parent state")
		}
		if _, ok := q.GetValue(key); ok {
			t.Error("inherited private values")
		}
		if q.ServerMeta != p.ServerMeta || !q.Q().CheckingDisabled || q.ClientOpt().UDPSize() != 1400 || q.QOpt().UDPSize() != 1232 {
			t.Error("lost DNS/client metadata")
		}
		q.ClientOpt().Option[0].(*dns.EDNS0_COOKIE).Cookie = "modified"
		q.QOpt().Option[0].(*dns.EDNS0_SUBNET).Address[0] = 99
		q.SetMark(99)
		q.StoreValue(key, "leak")
		answer(q, 60, "203.0.113.9")
		return nil
	})
	if _, err := r.Resolve(context.Background(), p, compile(t, []string{"domain:target.example"}, true), dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if p.HasMark(99) || p.ClientOpt().Option[0].(*dns.EDNS0_COOKIE).Cookie != "0123456789abcdef" || p.QOpt().Option[0].(*dns.EDNS0_SUBNET).Address[0] == 99 || p.R().Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatal("auxiliary query modified parent")
	}
}

func TestPartialFailureAndResponseValidation(t *testing.T) {
	r := resolver(t, func(ctx context.Context, q *query_context.Context) error {
		answer(q, 60, "203.0.113.2")
		switch q.QQuestion().Name {
		case "error.example.":
			return errors.New("offline failure")
		case "panic.example.":
			panic("optional source")
		case "nx.example.":
			q.R().Rcode = dns.RcodeNameError
		case "empty.example.":
			q.R().Answer = nil
		case "tc.example.":
			q.R().Truncated = true
		case "id.example.":
			q.R().Id++
		case "mutate.example.":
			q.Q().Question[0].Name = "wrong.example."
			q.R().Question[0].Name = "wrong.example."
		case "unrelated.example.":
			q.R().Answer[0].Header().Name = "unreachable.example."
		case "loop.example.":
			q.R().Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "loop.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "loop.example."}}
		}
		return nil
	})
	values := []string{"203.0.113.1"}
	for _, name := range []string{"error", "panic", "nx", "empty", "tc", "id", "mutate", "unrelated", "loop", "ok"} {
		values = append(values, "domain:"+name+".example")
	}
	got, err := r.Resolve(context.Background(), parent(dns.TypeA), compile(t, values, true), dns.TypeA)
	if err != nil || len(got) != 2 || got[1].IP.String() != "203.0.113.2" {
		t.Fatalf("partial results=%+v err=%v", got, err)
	}
	got, err = r.Resolve(context.Background(), parent(dns.TypeA), compile(t, []string{"domain:nx.example"}, true), dns.TypeA)
	if err != nil || len(got) != 0 {
		t.Fatalf("all failed=%+v err=%v", got, err)
	}
}

func TestTimeoutCancellationAndCloseJoinWorkers(t *testing.T) {
	for _, mode := range []string{"timeout", "parent", "close"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var active atomic.Int32
				r := resolver(t, func(ctx context.Context, q *query_context.Context) error {
					active.Add(1)
					defer active.Add(-1)
					<-ctx.Done()
					return context.Cause(ctx)
				})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				start := time.Now()
				done := make(chan error, 1)
				go func() {
					got, err := r.Resolve(ctx, parent(dns.TypeA), compile(t, []string{"domain:slow.example", "203.0.113.1"}, true), dns.TypeA)
					if mode == "timeout" && (len(got) != 1 || got[0].IP.String() != "203.0.113.1") {
						t.Error("timeout lost fixed target")
					}
					done <- err
				}()
				synctest.Wait()
				if mode == "parent" {
					cancel()
				} else if mode == "close" {
					_ = r.Close()
				}
				err := <-done
				if mode == "timeout" && (err != nil || time.Since(start) != 500*time.Millisecond) {
					t.Fatalf("budget: %s %v", time.Since(start), err)
				}
				if mode == "parent" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if mode == "close" && !errors.Is(err, ErrClosed) {
					t.Fatal(err)
				}
				if active.Load() != 0 {
					t.Fatal("leaked lookup")
				}
			})
		})
	}
}

func TestTargetLifetimeCNAMEZeroAndExpiryDuringLookup(t *testing.T) {
	for _, ttl := range []uint32{0, 1, 5} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := resolver(t, func(ctx context.Context, q *query_context.Context) error {
					if q.QQuestion().Name == "wait.example." {
						time.Sleep(1500 * time.Millisecond)
						return errors.New("failed after wait")
					}
					answer(q, 30, "203.0.113.2")
					q.R().Answer[0].Header().Name = "terminal.example."
					q.R().Answer = append([]dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}, Target: "terminal.example."}}, q.R().Answer...)
					return nil
				})
				r.timeout = 2 * time.Second
				p := parent(dns.TypeA)
				answer(p, 300, "192.0.2.1")
				c, err := response.Analyze(p.Q(), p.SnapshotResponse(), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				got, err := r.Resolve(context.Background(), p, compile(t, []string{"domain:target.example", "domain:wait.example", "203.0.113.1"}, true), dns.TypeA)
				if err != nil {
					t.Fatal(err)
				}
				if ttl == 1 {
					if len(got) != 1 || got[0].Source != nil {
						t.Fatal("expired domain retained", got)
					}
					return
				}
				if len(got) != 2 {
					t.Fatal(got)
				}
				s, err := response.StaticAddresses(c, []netip.Addr{got[0].IP, got[1].IP}, 60, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				s = response.LimitAddressLifetime(s, []*response.Candidate{got[0].Source}, time.Now())
				wantTTL := uint32(3)
				wantUntil := start.Add(5 * time.Second)
				if ttl == 0 {
					wantTTL = 0
					wantUntil = start.Add(30 * time.Second)
				}
				if s.Response.Answer[0].Header().Ttl != wantTTL || !s.ValidUntil.Equal(wantUntil) || len(s.Response.Answer) != 2 {
					t.Fatalf("TTL/deadline: %+v %s", s, s.ValidUntil)
				}
				if !slices.Equal(s.Response.Question, p.Q().Question) || s.Response.Answer[0].Header().Name != "user.example." {
					t.Fatal("target aliases leaked")
				}
			})
		})
	}
}

func TestParentDeadlineBoundsWholeLookupBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := resolver(t, func(ctx context.Context, q *query_context.Context) error { <-ctx.Done(); return context.Cause(ctx) })
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		got, err := r.Resolve(ctx, parent(dns.TypeA), compile(t, []string{"domain:slow.example", "203.0.113.1"}, true), dns.TypeA)
		if err != nil || len(got) != 1 || time.Since(start) != 75*time.Millisecond || ctx.Err() != nil {
			t.Fatalf("parent budget/reserve: results=%v err=%v elapsed=%s", got, err, time.Since(start))
		}
	})
}

func TestSourceCanConfigureItsOwnEDNSView(t *testing.T) {
	p := parent(dns.TypeA)
	r := resolver(t, func(ctx context.Context, q *query_context.Context) error {
		ecs := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 0)}
		q.QOpt().Option = append(q.QOpt().Option, ecs)
		q.QOpt().SetDo()
		answer(q, 60, "203.0.113.9")
		s := q.SnapshotResponse()
		s.UpstreamOpt = cloneOPT(q.QOpt())
		q.CommitResponse(s)
		return nil
	})
	got, err := r.Resolve(context.Background(), p, compile(t, []string{"domain:target.example"}, true), dns.TypeA)
	if err != nil || len(got) != 1 || got[0].IP.String() != "203.0.113.9" {
		t.Fatalf("configured source EDNS rejected: %v %v", got, err)
	}
	if len(p.QOpt().Option) != 0 || p.QOpt().Do() {
		t.Fatal("source EDNS leaked to parent")
	}
}
