package https_record

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

// The policy validates the list/config framing; cryptographic contents are
// opaque here, just as unknown future config versions are opaque to a client.
var testECH = []byte{0, 7, 0xfe, 0x0d, 0, 3, 'a', 'b', 'c'}

func boolValue(value bool) *bool { return &value }

func recordPlugin(t *testing.T, args Args, ech, ip sequence.Executable) *Record {
	t.Helper()
	plugins := make(map[string]any)
	if ech != nil {
		args.ECHSource = "ech"
		plugins["ech"] = ech
	}
	if ip != nil {
		args.IPSource = "ip"
		plugins["ip"] = ip
	}
	if ip == nil && args.EnableSubquery == nil {
		args.EnableSubquery = boolValue(false)
	}
	bp := coremain.NewBP("test_https_record", coremain.NewTestMosdnsWithPlugins(plugins))
	p, err := New(bp, &args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func bindingContext(t *testing.T, typ uint16, records ...string) *query_context.Context {
	t.Helper()
	q := new(dns.Msg).SetQuestion("example.test.", typ)
	q.SetEdns0(1232, false)
	qCtx := query_context.NewContext(q)
	r := new(dns.Msg).SetReply(qCtx.Q())
	r.Authoritative, r.AuthenticatedData = true, true
	for _, value := range records {
		rr, err := dns.NewRR(value)
		if err != nil {
			t.Fatal(err)
		}
		r.Answer = append(r.Answer, rr)
	}
	qCtx.SetResponse(r)
	return qCtx
}

func setECH(q *query_context.Context, ttl uint32, value []byte) {
	r := new(dns.Msg).SetReply(q.Q())
	r.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: ttl},
		Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: append([]byte(nil), value...)}},
	}}}
	q.SetResponse(r)
}

func setA(q *query_context.Context, ttl uint32, addresses ...string) {
	r := new(dns.Msg).SetReply(q.Q())
	for _, addr := range addresses {
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP(addr)})
	}
	q.SetResponse(r)
}

func echSource(ttl uint32, calls *atomic.Int32) sequence.Executable {
	return sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		if !query_policy.InheritCancellation(ctx) {
			return errors.New("source did not inherit cancellation")
		}
		if calls != nil {
			calls.Add(1)
		}
		setECH(q, ttl, testECH)
		return nil
	})
}

func bindingKeys(rr dns.RR) []dns.SVCBKey {
	var keys []dns.SVCBKey
	for _, value := range serviceValue(rr).Value {
		keys = append(keys, value.Key())
	}
	return keys
}

func TestCleanupIsCopyOnWriteAndKeepsDependenciesValid(t *testing.T) {
	for _, typ := range []uint16{dns.TypeHTTPS, dns.TypeSVCB} {
		t.Run(dns.TypeToString[typ], func(t *testing.T) {
			p := recordPlugin(t, Args{AddECH: boolValue(false), RemoveALPN: []string{"h2"}}, nil, nil)
			q := bindingContext(t, typ, fmt.Sprintf("example.test. 60 IN %s 1 . mandatory=alpn,no-default-alpn,ipv4hint alpn=h2,h3 no-default-alpn ipv4hint=192.0.2.1 ipv6hint=2001:db8::1", dns.TypeToString[typ]))
			original := q.R()
			before := original.String()
			if err := p.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if original.String() != before {
				t.Fatal("mutated the original response")
			}
			if keys := bindingKeys(q.R().Answer[0]); len(keys) != 0 {
				t.Fatalf("remaining keys %v", keys)
			}
			if q.R().AuthenticatedData || q.R().Authoritative {
				t.Fatal("synthetic response retained AD/AA")
			}
		})
	}
}

func TestPerRecordHintPolicyAndExistingECH(t *testing.T) {
	var calls atomic.Int32
	p := recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}, ExcludeIP: []string{"192.0.2.9"}}, echSource(30, &calls), nil)
	existing := base64.StdEncoding.EncodeToString([]byte{0, 5, 0xfe, 0x0e, 0, 1, 'x'})
	q := bindingContext(t, dns.TypeHTTPS,
		"example.test. 60 IN HTTPS 1 a.test. ipv4hint=192.0.2.1",
		"example.test. 60 IN HTTPS 2 b.test. ipv4hint=198.51.100.1",
		"example.test. 60 IN HTTPS 3 c.test. ipv4hint=192.0.2.1,192.0.2.9",
		"example.test. 60 IN HTTPS 4 d.test. ipv4hint=192.0.2.2 ech="+existing)
	if err := p.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	for i, want := range []bool{true, false, false, true} {
		if got := hasECH(q.R().Answer[i]); got != want {
			t.Fatalf("record %d ECH=%v, want %v", i, got, want)
		}
		if slices.Contains(bindingKeys(q.R().Answer[i]), dns.SVCB_IPV4HINT) {
			t.Fatal("hint survived cleanup")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("ECH lookups=%d", calls.Load())
	}
	last := serviceValue(q.R().Answer[3]).Value
	for _, value := range last {
		if ech, ok := value.(*dns.SVCBECHConfig); ok && base64.StdEncoding.EncodeToString(ech.ECH) != existing {
			t.Fatal("replaced existing ECH")
		}
	}
}

func TestAliasDOAndNameMissDoNotFetchECH(t *testing.T) {
	var calls atomic.Int32
	p := recordPlugin(t, Args{MatchName: []string{"full:allowed.test"}}, echSource(30, &calls), nil)
	alias := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 0 alias.test.")
	before := alias.R().String()
	if err := p.Exec(context.Background(), alias); err != nil || alias.R().String() != before {
		t.Fatalf("alias changed: %v", err)
	}
	nameMiss := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.1 alpn=h2,h3")
	if err := p.Exec(context.Background(), nameMiss); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(bindingKeys(nameMiss.R().Answer[0]), dns.SVCB_IPV4HINT) {
		t.Fatal("name gate incorrectly skipped cleanup")
	}
	do := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.1")
	do.QOpt().SetDo()
	before = do.R().String()
	if err := p.Exec(context.Background(), do); err != nil || do.R().String() != before {
		t.Fatalf("DO response changed: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("unexpected ECH lookups=%d", calls.Load())
	}
	empty := recordPlugin(t, Args{MatchName: []string{}}, echSource(30, &calls), nil)
	q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.1")
	if err := empty.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if len(bindingKeys(q.R().Answer[0])) != 0 || calls.Load() != 0 {
		t.Fatal("explicit empty match_name enabled global injection or skipped cleanup")
	}
}

func TestTargetQueriesDeduplicateAndOverlapECH(t *testing.T) {
	var aCalls, echCalls atomic.Int32
	startedA, startedECH := make(chan struct{}), make(chan struct{})
	var once sync.Once
	ip := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		if !query_policy.InheritCancellation(ctx) || q.QQuestion().Name != "target.test." || !q.HasMark(7) {
			return errors.New("lost complete target routing context")
		}
		aCalls.Add(1)
		once.Do(func() { close(startedA) })
		select {
		case <-startedECH:
		case <-ctx.Done():
			return ctx.Err()
		}
		setA(q, 10, "192.0.2.1")
		return nil
	})
	ech := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		if !query_policy.InheritCancellation(ctx) || q.HasMark(7) || q.QQuestion().Name != "crypto.cloudflare.com." {
			return errors.New("ECH source is not isolated")
		}
		echCalls.Add(1)
		close(startedECH)
		select {
		case <-startedA:
		case <-ctx.Done():
			return ctx.Err()
		}
		setECH(q, 30, testECH)
		return nil
	})
	p := recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}}, ech, ip)
	q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 target.test. alpn=h3", "example.test. 60 IN HTTPS 2 TARGET.test.")
	q.SetMark(7)
	if err := p.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if aCalls.Load() != 1 || echCalls.Load() != 1 {
		t.Fatalf("A=%d ECH=%d", aCalls.Load(), echCalls.Load())
	}
	for _, rr := range q.R().Answer {
		if !hasECH(rr) || rr.Header().Ttl > 10 {
			t.Fatalf("wrong injected record: %s", rr)
		}
	}
	if q.QQuestion().Name != "example.test." || !q.HasMark(7) {
		t.Fatal("source overwrote parent query or marks")
	}
}

func TestSynthesisNeedsAAndHonorsNativeZeroTTL(t *testing.T) {
	for _, ttl := range []uint32{0, 2, 30} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			ip := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error { setA(q, ttl, "192.0.2.1"); return nil })
			p := recordPlugin(t, Args{}, echSource(20, nil), ip)
			q := bindingContext(t, dns.TypeHTTPS)
			q.R().Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 15}, Ns: "ns.test.", Mbox: "hostmaster.test.", Minttl: 15}}
			if err := p.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if len(q.R().Answer) != 1 || !hasECH(q.R().Answer[0]) || len(q.R().Ns) != 0 {
				t.Fatalf("bad synthesis %s", q.R())
			}
			if got := q.R().Answer[0].Header().Ttl; got > min(ttl, uint32(15)) || (ttl == 0 && got != 0) {
				t.Fatalf("TTL %d source %d", got, ttl)
			}
		})
	}
	var calls atomic.Int32
	ip := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error { setA(q, 30); return nil })
	p := recordPlugin(t, Args{}, echSource(30, &calls), ip)
	q := bindingContext(t, dns.TypeHTTPS)
	if err := p.Exec(context.Background(), q); err != nil || len(q.R().Answer) != 0 {
		t.Fatalf("NODATA without A changed: %v, %s", err, q.R())
	}
}

func TestECHCacheViewIsolationExpiryAndNoErrorCaching(t *testing.T) {
	var calls atomic.Int32
	var current atomic.Int64
	current.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, current.Load()) }
	ech := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		count := calls.Add(1)
		if count == 1 {
			setECH(q, 30, []byte("broken"))
			return nil
		}
		setECH(q, 2, testECH)
		snapshot := q.SnapshotResponse()
		snapshot.ReceivedAt = now()
		q.CommitResponse(snapshot)
		return nil
	})
	p := recordPlugin(t, Args{}, ech, nil)
	p.now = now
	run := func(view string, subnet string) *query_context.Context {
		q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 .")
		q.ServerMeta.ServerName = view
		if subnet != "" {
			q.QOpt().Option = append(q.QOpt().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP(subnet)})
		}
		snapshot := q.SnapshotResponse()
		snapshot.ReceivedAt = now()
		q.CommitResponse(snapshot)
		if err := p.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	if hasECH(run("one", "").R().Answer[0]) {
		t.Fatal("injected malformed ECH")
	}
	if !hasECH(run("one", "").R().Answer[0]) {
		t.Fatal("error result was cached")
	}
	run("one", "")
	if calls.Load() != 2 {
		t.Fatalf("cache missed: %d", calls.Load())
	}
	run("two", "")
	run("one", "192.0.2.0")
	if calls.Load() != 4 {
		t.Fatalf("views shared cache: %d", calls.Load())
	}
	current.Add(int64(3 * time.Second))
	run("one", "")
	if calls.Load() != 5 {
		t.Fatalf("cache outlived source: %d", calls.Load())
	}
}

func TestCleanupSurvivesOptionalTimeoutAndCancellation(t *testing.T) {
	for _, parentCancel := range []bool{false, true} {
		t.Run(fmt.Sprint(parentCancel), func(t *testing.T) {
			started := make(chan struct{})
			var finished atomic.Bool
			ech := sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
				close(started)
				<-ctx.Done()
				finished.Store(true)
				return ctx.Err()
			})
			p := recordPlugin(t, Args{Timeout: 15 * time.Millisecond}, ech, nil)
			q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.1 alpn=h2,h3")
			ctx, cancel := context.WithCancelCause(context.Background())
			cause := errors.New("caller left")
			if parentCancel {
				go func() { <-started; cancel(cause) }()
			}
			err := p.Exec(ctx, q)
			cancel(nil)
			if parentCancel && !errors.Is(err, cause) {
				t.Fatalf("cancel cause=%v", err)
			}
			if !parentCancel && err != nil {
				t.Fatal(err)
			}
			if !finished.Load() || hasECH(q.R().Answer[0]) || slices.Contains(bindingKeys(q.R().Answer[0]), dns.SVCB_IPV4HINT) {
				t.Fatal("cleanup lost or source leaked")
			}
			if len(p.cache) != 0 {
				t.Fatal("cancelled ECH was cached")
			}
		})
	}
}

func TestCloseCancelsAndJoinsSource(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	ech := sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
		close(started)
		<-ctx.Done()
		close(finished)
		return ctx.Err()
	})
	p := recordPlugin(t, Args{}, ech, nil)
	q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 .")
	done := make(chan error, 1)
	go func() { done <- p.Exec(context.Background(), q) }()
	<-started
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("Close returned before source cleanup")
	}
	if err := <-done; !errors.Is(err, errClosed) {
		t.Fatalf("closed query=%v", err)
	}
	if err := p.Exec(context.Background(), q); !errors.Is(err, errClosed) {
		t.Fatalf("query after Close=%v", err)
	}
}

func TestECHFraming(t *testing.T) {
	for _, value := range [][]byte{nil, {}, []byte("abc"), {0, 0}, {0, 4, 0xfe, 0x0d, 0, 0}, {0, 6, 0xfe, 0x0d, 0, 3, 1, 2}, {0, 7, 0xfe, 0x0d, 0, 2, 1, 2, 3}} {
		if validateECHConfigList(value) {
			t.Fatalf("accepted broken list %v", value)
		}
	}
	for _, value := range [][]byte{testECH, {0, 4, 0xfe, 0x0e, 0, 0}} {
		if !validateECHConfigList(value) {
			t.Fatalf("rejected framed list %v", value)
		}
	}
}

func TestIPLookupsHaveBoundedParallelism(t *testing.T) {
	started := make(chan struct{}, 16)
	release := make(chan struct{})
	var active, peak, calls atomic.Int32
	ip := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		n := active.Add(1)
		defer active.Add(-1)
		calls.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		setA(q, 30, "192.0.2.1")
		return nil
	})
	p := recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}, Timeout: 2 * time.Second}, echSource(30, nil), ip)
	var records []string
	for i := 0; i < 12; i++ {
		records = append(records, fmt.Sprintf("example.test. 60 IN HTTPS %d target%d.test.", i+1, i))
	}
	q := bindingContext(t, dns.TypeHTTPS, records...)
	done := make(chan error, 1)
	go func() { done <- p.Exec(context.Background(), q) }()
	for i := 0; i < maxConcurrentIPLookups; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("A lookups did not start in parallel")
		}
	}
	if active.Load() != maxConcurrentIPLookups {
		close(release)
		t.Fatalf("active A queries=%d", active.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 12 || peak.Load() > maxConcurrentIPLookups || active.Load() != 0 {
		t.Fatalf("calls=%d peak=%d active=%d", calls.Load(), peak.Load(), active.Load())
	}
	for _, rr := range q.R().Answer {
		if !hasECH(rr) {
			t.Fatalf("target was skipped: %s", rr)
		}
	}
}

func TestNativeZeroECHIsImmediateAndNotCached(t *testing.T) {
	var calls atomic.Int32
	p := recordPlugin(t, Args{}, echSource(0, &calls), nil)
	for i := 0; i < 2; i++ {
		q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 .")
		if err := p.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if !hasECH(q.R().Answer[0]) || q.R().Answer[0].Header().Ttl != 0 {
			t.Fatalf("TTL0 ECH was dropped or extended: %s", q.R())
		}
	}
	if calls.Load() != 2 || len(p.cache) != 0 {
		t.Fatalf("native zero ECH cached: calls=%d entries=%d", calls.Load(), len(p.cache))
	}
}

func TestCacheCapacityAndSnapshotIsolation(t *testing.T) {
	var calls atomic.Int32
	p := recordPlugin(t, Args{}, echSource(3600, &calls), nil)
	for i := 0; i < maxECHCacheEntries+2; i++ {
		q := bindingContext(t, dns.TypeHTTPS, "example.test. 3600 IN HTTPS 1 .")
		q.ServerMeta.UrlPath = fmt.Sprint(i)
		if err := p.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if q.R().Answer[0].Header().Ttl > 300 {
			t.Fatal("ECH cache cap exceeded")
		}
		for _, option := range serviceValue(q.R().Answer[0]).Value {
			if value, ok := option.(*dns.SVCBECHConfig); ok {
				value.ECH[0] = 255
			}
		}
	}
	if len(p.cache) != maxECHCacheEntries {
		t.Fatalf("cache size=%d", len(p.cache))
	}
	for _, entry := range p.cache {
		if !validateECHConfigList(entry.value) {
			t.Fatal("response shared mutable ECH with cache")
		}
	}
}

func TestMalformedSourceCorrelationAndPanicsKeepCleanup(t *testing.T) {
	for _, mode := range []string{"question", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ech := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
				if mode == "panic" {
					panic("optional source failed")
				}
				q.Q().Question[0].Name = "other.test."
				setECH(q, 30, testECH)
				return nil
			})
			p := recordPlugin(t, Args{}, ech, nil)
			q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.1")
			if err := p.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if len(bindingKeys(q.R().Answer[0])) != 0 || len(p.cache) != 0 {
				t.Fatal("bad source injected, cached, or erased cleanup")
			}
		})
	}
}

func TestSourceMayAdjustECSWithoutChangingQuestion(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(fmt.Sprint(override), func(t *testing.T) {
			setView := func(q *query_context.Context) {
				q.QOpt().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("198.51.100.0")}}
			}
			echoView := func(q *query_context.Context) {
				snapshot := q.SnapshotResponse()
				snapshot.UpstreamOpt = dns.Copy(q.QOpt()).(*dns.OPT)
				q.CommitResponse(snapshot)
			}
			ech := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
				setView(q)
				setECH(q, 30, testECH)
				echoView(q)
				return nil
			})
			ip := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
				setView(q)
				setA(q, 30, "192.0.2.1")
				echoView(q)
				return nil
			})
			p := recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}}, ech, ip)
			q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 target.test.")
			if override {
				q.QOpt().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("203.0.113.0")}}
			}
			originalQuery := q.Q().String()
			if err := p.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if !hasECH(q.R().Answer[0]) {
				t.Fatal("source-local ECS was rejected")
			}
			if q.Q().String() != originalQuery {
				t.Fatal("source changed parent's ECS")
			}
		})
	}
}

func TestDuplicateAddressZeroTTLCapsECH(t *testing.T) {
	ip := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		setA(q, 60, "192.0.2.1", "192.0.2.1")
		q.R().Answer[1].Header().Ttl = 0
		return nil
	})
	p := recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}}, echSource(30, nil), ip)
	q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 target.test.")
	if err := p.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if !hasECH(q.R().Answer[0]) || q.R().Answer[0].Header().Ttl != 0 {
		t.Fatalf("duplicate TTL0 was extended: %s", q.R())
	}
}

func TestSourceZeroTTLAliasesCapInjectionAndCaching(t *testing.T) {
	for _, zeroSource := range []string{"A", "ECH"} {
		t.Run(zeroSource, func(t *testing.T) {
			var calls atomic.Int32
			alias := func(q *query_context.Context) {
				terminal := "source-terminal.test."
				for _, rr := range q.R().Answer {
					rr.Header().Name = terminal
				}
				q.R().Answer = append([]dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.QQuestion().Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 0}, Target: terminal}}, q.R().Answer...)
			}
			ech := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
				calls.Add(1)
				setECH(q, 60, testECH)
				if zeroSource == "ECH" {
					alias(q)
				}
				return nil
			})
			ip := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
				setA(q, 60, "192.0.2.1")
				if zeroSource == "A" {
					alias(q)
				}
				return nil
			})
			p := recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}}, ech, ip)
			for i := 0; i < 2; i++ {
				q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 target.test.")
				if err := p.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				if !hasECH(q.R().Answer[0]) || q.R().Answer[0].Header().Ttl != 0 {
					t.Fatalf("zero alias lifetime extended: %s", q.R())
				}
			}
			if zeroSource == "ECH" && (calls.Load() != 2 || len(p.cache) != 0) {
				t.Fatal("ECH source with zero alias cached")
			}
		})
	}
}

func TestQueuedQueriesStopBeforeCallerReusesInput(t *testing.T) {
	var calls, active atomic.Int32
	ip := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		calls.Add(1)
		active.Add(1)
		defer active.Add(-1)
		original := q.QQuestion().Name
		<-ctx.Done()
		if q.QQuestion().Name != original {
			return errors.New("queued source input changed")
		}
		return ctx.Err()
	})
	p := recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}, Timeout: 20 * time.Millisecond}, echSource(30, nil), ip)
	var records []string
	for i := 0; i < 16; i++ {
		records = append(records, fmt.Sprintf("example.test. 60 IN HTTPS %d target%d.test. alpn=h3", i+1, i))
	}
	q := bindingContext(t, dns.TypeHTTPS, records...)
	if err := p.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	q.Q().Question[0].Name = "caller-reused.test."
	q.SetResponse(nil)
	if active.Load() != 0 || calls.Load() > maxConcurrentIPLookups {
		t.Fatalf("late source work: active=%d calls=%d", active.Load(), calls.Load())
	}
}

func TestImpossibleInjectionCancelsOtherOptionalWork(t *testing.T) {
	for _, failure := range []string{"ECH", "A"} {
		t.Run(failure, func(t *testing.T) {
			aStarted, echStarted := make(chan struct{}), make(chan struct{})
			ech := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
				close(echStarted)
				select {
				case <-aStarted:
				case <-ctx.Done():
					return ctx.Err()
				}
				if failure == "ECH" {
					return errors.New("no ECH")
				}
				<-ctx.Done()
				return ctx.Err()
			})
			ip := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
				close(aStarted)
				select {
				case <-echStarted:
				case <-ctx.Done():
					return ctx.Err()
				}
				if failure == "A" {
					setA(q, 30)
					return nil
				}
				<-ctx.Done()
				return ctx.Err()
			})
			p := recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}, Timeout: 2 * time.Second}, ech, ip)
			q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 target.test. alpn=h3")
			start := time.Now()
			if err := p.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("waited out budget after injection became impossible")
			}
			if hasECH(q.R().Answer[0]) || len(bindingKeys(q.R().Answer[0])) != 0 {
				t.Fatal("failed query erased cleanup or injected ECH")
			}
		})
	}
}

func TestFreshECHLimitDoesNotSlideWhileWaitingForA(t *testing.T) {
	initial := time.Now()
	var offset atomic.Int64
	now := func() time.Time { return initial.Add(time.Duration(offset.Load())) }
	var p *Record
	ech := sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		setECH(q, 3600, testECH)
		s := q.SnapshotResponse()
		s.ReceivedAt = initial
		q.CommitResponse(s)
		return nil
	})
	ip := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		// Cache publication happens after the ECH source lifetime has been
		// computed. Only then let this independent A source finish later.
		for {
			p.mu.Lock()
			ready := len(p.cache) > 0
			p.mu.Unlock()
			if ready {
				break
			}
			select {
			case <-time.After(time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		offset.Store(int64(400 * time.Millisecond))
		setA(q, 3600, "192.0.2.1")
		s := q.SnapshotResponse()
		s.ReceivedAt = now()
		q.CommitResponse(s)
		return nil
	})
	p = recordPlugin(t, Args{MatchIP: []string{"192.0.2.0/24"}}, ech, ip)
	p.now = now
	q := bindingContext(t, dns.TypeHTTPS, "example.test. 3600 IN HTTPS 1 target.test.")
	s := q.SnapshotResponse()
	s.ReceivedAt = initial
	q.CommitResponse(s)
	if err := p.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	s = q.SnapshotResponse()
	if !hasECH(q.R().Answer[0]) || s.ValidUntil.IsZero() || s.ValidUntil.After(initial.Add(maxECHCacheTTL)) {
		t.Fatalf("ECH lease slid while awaiting A: %+v", s)
	}
}

func TestConfigurationAndWholeRecordIPGate(t *testing.T) {
	if _, err := New(nil, &Args{}); err == nil {
		t.Fatal("accepted missing ECH source")
	}
	for _, args := range []Args{{AddECH: boolValue(false), Timeout: -time.Second}, {AddECH: boolValue(false), RemoveALPN: []string{""}}, {AddECH: boolValue(false), ECHDomain: "bad..test."}, {AddECH: boolValue(false), MatchIP: []string{""}}} {
		if _, err := New(nil, &args); err == nil {
			t.Fatalf("accepted bad args %+v", args)
		}
	}
	p := recordPlugin(t, Args{AddECH: boolValue(false), MatchIP: []string{"192.0.2.0/24"}, ExcludeIP: []string{"192.0.2.9"}}, nil, nil)
	if p.allowedIPs([]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.9")}) {
		t.Fatal("include defeated exclude")
	}
	if !p.allowedIPs([]netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
		t.Fatal("include did not match")
	}
	if p.allowedIPs(nil) {
		t.Fatal("empty evidence matched IP gate")
	}
	empty := recordPlugin(t, Args{AddECH: boolValue(false), MatchIP: []string{}}, nil, nil)
	if empty.allowedIPs([]netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
		t.Fatal("explicit empty include was unrestricted")
	}
}

func TestYAMLShapePreservesExplicitFalseAndEmptyLists(t *testing.T) {
	var args Args
	if err := utils.WeakDecode(map[string]any{"remove_hint": false, "remove_h3": false, "add_ech": false, "enable_subquery": false, "match_name": []any{}, "match_ip": []any{}, "timeout": "123ms"}, &args); err != nil {
		t.Fatal(err)
	}
	if args.RemoveHint == nil || *args.RemoveHint || args.RemoveH3 == nil || *args.RemoveH3 || args.AddECH == nil || *args.AddECH || args.EnableSubquery == nil || *args.EnableSubquery || args.MatchName == nil || args.MatchIP == nil || args.Timeout != 123*time.Millisecond {
		t.Fatalf("decoded defaults replaced explicit values: %+v", args)
	}
	p, err := New(nil, &args)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if !p.matchName || !p.includeConfigured || p.removeHint || p.removeH3 || p.addECH || p.subquery {
		t.Fatal("construction lost explicit settings")
	}
}

func TestOriginalClientDOIsAuthoritative(t *testing.T) {
	p := recordPlugin(t, Args{AddECH: boolValue(false)}, nil, nil)
	request := new(dns.Msg).SetQuestion("example.test.", dns.TypeHTTPS)
	request.SetEdns0(1232, true)
	q := query_context.NewContext(request)
	q.QOpt().Hdr.Ttl &^= 1 << 15
	r := new(dns.Msg).SetReply(q.Q())
	rr, err := dns.NewRR("example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.1 alpn=h3")
	if err != nil {
		t.Fatal(err)
	}
	r.Answer = []dns.RR{rr}
	q.SetResponse(r)
	before := q.R().String()
	if err := p.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if q.R().String() != before {
		t.Fatal("client DO was overridden by source query changes")
	}
}

func TestNonQueryOpcodePassesThroughWithoutOptionalQueries(t *testing.T) {
	var calls atomic.Int32
	p := recordPlugin(t, Args{}, echSource(30, &calls), nil)
	for _, noQuestion := range []bool{false, true} {
		q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.1 alpn=h3")
		q.Q().Opcode, q.R().Opcode = dns.OpcodeStatus, dns.OpcodeStatus
		if noQuestion {
			q.Q().Question, q.R().Question = nil, nil
		}
		original := q.R()
		before := original.String()
		if err := p.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		if q.R() != original || q.R().String() != before {
			t.Fatal("non-QUERY response was modified")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("non-QUERY request launched an optional query")
	}
	for _, malformed := range []string{"qr", "no_question", "multiple_questions"} {
		q := bindingContext(t, dns.TypeHTTPS, "example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.1")
		switch malformed {
		case "qr":
			q.Q().Response = true
		case "no_question":
			q.Q().Question = nil
		case "multiple_questions":
			q.Q().Question = append(q.Q().Question, q.Q().Question[0])
		}
		if err := p.Exec(context.Background(), q); err == nil {
			t.Fatalf("accepted malformed QUERY: %s", malformed)
		}
	}
}

func TestOptionalFailureAgesMainLeaseEvenWithoutInitialCleanup(t *testing.T) {
	for _, parameters := range []string{"alpn=h2", "alpn=h2,h3 ipv4hint=192.0.2.1"} {
		t.Run(parameters, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ech := sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
					time.Sleep(100 * time.Millisecond)
					return errors.New("ECH source unavailable")
				})
				p := recordPlugin(t, Args{}, ech, nil)
				q := bindingContext(t, dns.TypeHTTPS, "example.test. 1 IN HTTPS 1 . "+parameters)
				initial := q.ResponseReceivedAt()
				if err := p.Exec(context.Background(), q); err != nil {
					t.Fatal(err)
				}
				snapshot := q.SnapshotResponse()
				if hasECH(q.R().Answer[0]) || q.R().Answer[0].Header().Ttl != 0 {
					t.Fatalf("optional wait did not age source TTL: %s", q.R())
				}
				if !snapshot.ValidUntil.Equal(initial.Add(time.Second)) || !snapshot.ReceivedAt.Equal(initial.Add(100*time.Millisecond)) {
					t.Fatalf("lease reset after failed lookup: received=%v until=%v", snapshot.ReceivedAt, snapshot.ValidUntil)
				}
				if slices.Contains(bindingKeys(q.R().Answer[0]), dns.SVCB_IPV4HINT) {
					t.Fatal("failed lookup restored original hints")
				}
			})
		})
	}
}
