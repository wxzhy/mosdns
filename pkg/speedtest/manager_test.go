package speedtest

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

var testIP = netip.MustParseAddr("192.0.2.1")

func config(port uint16) Config { return Config{TCPPorts: []uint16{port}} }

func measureAsync(m *Manager, ctx context.Context, ip netip.Addr, c Config) <-chan Result {
	done := make(chan Result, 1)
	go func() { done <- m.Measure(ctx, ip, c) }()
	return done
}

func TestPrepare(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	m := NewManager(Options{Logger: zap.New(core)})
	defer m.Close()
	var checks int
	m.detectICMP = func() (string, string, error) { checks++; return "", "", errors.New("permission denied") }
	c, err := m.Prepare(Config{})
	if err != nil || c.Timeout != 300*time.Millisecond || len(c.TCPPorts) != 2 || c.TCPPorts[0] != 80 || c.TCPPorts[1] != 443 {
		t.Fatalf("defaults: %#v, %v", c, err)
	}
	input := []uint16{443, 80, 443}
	c, err = m.Prepare(Config{TCPPorts: input, ICMP: true})
	if err != nil || c.ICMP || len(c.TCPPorts) != 2 || input[0] != 443 {
		t.Fatalf("normalization/fallback: %#v, %v", c, err)
	}
	if _, err := m.Prepare(Config{TCPPorts: []uint16{}, ICMP: true}); err == nil {
		t.Fatal("ICMP-only configuration must fail without capability")
	}
	if checks != 1 || logs.Len() != 1 {
		t.Fatalf("capability checks=%d warnings=%d", checks, logs.Len())
	}
	for _, c := range []Config{{TCPPorts: []uint16{0}}, {Timeout: -time.Second}} {
		if _, err := m.Prepare(c); err == nil {
			t.Fatalf("accepted invalid config %#v", c)
		}
	}
	r := m.Measure(context.Background(), testIP, Config{TCPPorts: []uint16{}})
	if r.Outcome != Unmeasured || r.Reason != "disabled" || m.Stats().Probes != 0 {
		t.Fatalf("disabled: %#v", r)
	}
}

func TestSharedFlightSubscriberCancellationAndCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{})
		defer m.Close()
		release := make(chan struct{})
		var calls, canceled atomic.Int32
		m.probe = func(ctx context.Context, _ netip.Addr, _ probeMethod) Result {
			calls.Add(1)
			select {
			case <-release:
				return Result{Outcome: Success, RTT: 12 * time.Millisecond}
			case <-ctx.Done():
				canceled.Add(1)
				return unmeasuredContext(ctx.Err())
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		a := measureAsync(m, ctx, testIP, config(443))
		synctest.Wait()
		b := measureAsync(m, context.Background(), testIP, Config{TCPPorts: []uint16{443, 443}})
		synctest.Wait()
		if calls.Load() != 1 || m.Stats().Shared != 1 {
			t.Fatalf("not shared: %#v calls=%d", m.Stats(), calls.Load())
		}
		cancel()
		synctest.Wait()
		if r := <-a; r.Outcome != Unmeasured {
			t.Fatalf("canceled subscriber: %#v", r)
		}
		if canceled.Load() != 0 {
			t.Fatal("one subscriber canceled shared work")
		}
		close(release)
		synctest.Wait()
		if r := <-b; r.Outcome != Success || r.Cached || r.RTT != 12*time.Millisecond {
			t.Fatalf("subscriber: %#v", r)
		}
		r := m.Measure(context.Background(), netip.MustParseAddr("::ffff:192.0.2.1"), config(443))
		if !r.Cached || r.Outcome != Success || calls.Load() != 1 {
			t.Fatalf("cache: %#v calls=%d", r, calls.Load())
		}
	})
}

func TestLastWaiterCancellationDiscardsLateSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{})
		defer m.Close()
		var calls atomic.Int32
		m.probe = func(ctx context.Context, _ netip.Addr, _ probeMethod) Result {
			if calls.Add(1) == 1 {
				<-ctx.Done()
			} // intentionally swallow cancellation
			return Result{Outcome: Success, RTT: time.Millisecond}
		}
		ctx, cancel := context.WithCancel(context.Background())
		a := measureAsync(m, ctx, testIP, config(443))
		synctest.Wait()
		cancel()
		synctest.Wait()
		if r := <-a; r.Outcome != Unmeasured {
			t.Fatalf("canceled: %#v", r)
		}
		if s := m.Stats(); s.CacheEntries != 0 || s.Flights != 0 || s.Active != 0 {
			t.Fatalf("late result leaked: %#v", s)
		}
		if r := m.Measure(context.Background(), testIP, config(443)); r.Cached || r.Outcome != Success || calls.Load() != 2 {
			t.Fatalf("replacement: %#v calls=%d", r, calls.Load())
		}
	})
}

func TestFirstSuccessfulMethodCancelsAndDrainsOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{})
		defer m.Close()
		release := make(chan struct{})
		var canceled atomic.Int32
		m.probe = func(ctx context.Context, _ netip.Addr, method probeMethod) Result {
			if method.port == 443 {
				<-release
				return Result{Outcome: Success, RTT: 9 * time.Millisecond}
			}
			<-ctx.Done()
			canceled.Add(1)
			return unmeasuredContext(ctx.Err())
		}
		a := measureAsync(m, context.Background(), testIP, Config{TCPPorts: []uint16{80, 443}})
		synctest.Wait()
		if m.Stats().Active != 2 {
			t.Fatalf("methods are not parallel: %#v", m.Stats())
		}
		close(release)
		synctest.Wait()
		if r := <-a; r.Outcome != Success || r.RTT != 9*time.Millisecond {
			t.Fatalf("winner: %#v", r)
		}
		if canceled.Load() != 1 || m.Stats().Active != 0 {
			t.Fatalf("loser not cleaned: %#v", m.Stats())
		}
	})
}

func TestQueueBoundsAndQueuedDeadlineDoNotCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{MaxConcurrent: 1, QueueSize: 1})
		defer m.Close()
		release := make(chan struct{})
		var calls atomic.Int32
		m.probe = func(ctx context.Context, _ netip.Addr, _ probeMethod) Result {
			calls.Add(1)
			select {
			case <-release:
				return Result{Outcome: Success, RTT: time.Millisecond}
			case <-ctx.Done():
				return networkFailure(ctx, ctx.Err())
			}
		}
		a := measureAsync(m, context.Background(), testIP, Config{TCPPorts: []uint16{443}, Timeout: time.Second})
		synctest.Wait()
		queuedIP := netip.MustParseAddr("192.0.2.2")
		b := measureAsync(m, context.Background(), queuedIP, Config{TCPPorts: []uint16{443}, Timeout: 50 * time.Millisecond})
		synctest.Wait()
		if s := m.Stats(); s.Active != 1 || s.Queued != 1 {
			t.Fatalf("bounds: %#v", s)
		}
		c := m.Measure(context.Background(), netip.MustParseAddr("192.0.2.3"), config(443))
		if c.Outcome != Unmeasured || c.Reason != "queue_full" {
			t.Fatalf("overflow: %#v", c)
		}
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if r := <-b; r.Outcome != Unmeasured || r.Reason != "queue_deadline" {
			t.Fatalf("queued timeout: %#v", r)
		}
		if calls.Load() != 1 || m.Stats().CacheEntries != 0 || m.Stats().Queued != 0 {
			t.Fatalf("queue failure cached/probed: %#v", m.Stats())
		}
		close(release)
		synctest.Wait()
		if r := <-a; r.Outcome != Success {
			t.Fatalf("active: %#v", r)
		}
		if r := m.Measure(context.Background(), queuedIP, config(443)); r.Cached || r.Outcome != Success {
			t.Fatalf("queued address must retry: %#v", r)
		}
	})
}

func TestEarlyReplyKeepsSocketReservedUntilLibraryCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{MaxConcurrent: 1})
		defer m.Close()
		cleanup := make(chan struct{})
		m.probe = func(ctx context.Context, _ netip.Addr, _ probeMethod) Result {
			r := Result{Outcome: Success, RTT: time.Millisecond}
			if !reportProbeResult(ctx, r) {
				t.Error("missing result reporter")
			}
			<-cleanup
			return r // A second report must not publish or overwrite anything.
		}
		profile := config(443)
		if r := m.Measure(context.Background(), testIP, profile); r.Outcome != Success {
			t.Fatal(r)
		}
		if stats := m.Stats(); stats.Active != 1 {
			t.Fatalf("socket slot released before cleanup: %+v", stats)
		}
		if r := m.Measure(context.Background(), testIP, profile); r.Outcome != Success || !r.Cached {
			t.Fatalf("early result unavailable: %+v", r)
		}
		closed := make(chan struct{})
		go func() { _ = m.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("Close did not wait for library cleanup")
		default:
		}
		close(cleanup)
		<-closed
		if stats := m.Stats(); stats.Active != 0 || stats.Queued != 0 {
			t.Fatalf("resources retained: %+v", stats)
		}
	})
}

func TestQueueWaitDoesNotConsumePhysicalProbeTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{MaxConcurrent: 1, QueueSize: 1})
		defer m.Close()
		m.probe = func(ctx context.Context, _ netip.Addr, _ probeMethod) Result {
			select {
			case <-time.After(80 * time.Millisecond):
				return Result{Outcome: Success, RTT: 80 * time.Millisecond}
			case <-ctx.Done():
				return networkFailure(ctx, ctx.Err())
			}
		}
		a := measureAsync(m, context.Background(), testIP, Config{TCPPorts: []uint16{80}, Timeout: time.Second})
		synctest.Wait()
		profile := Config{TCPPorts: []uint16{443}, Timeout: 100 * time.Millisecond}
		b := measureAsync(m, context.Background(), netip.MustParseAddr("192.0.2.2"), profile)
		synctest.Wait()
		if s := m.Stats(); s.Queued != 1 {
			t.Fatalf("not queued: %+v", s)
		}
		if r := <-a; r.Outcome != Success {
			t.Fatal(r)
		}
		if r := <-b; r.Outcome != Success || r.RTT != 80*time.Millisecond {
			t.Fatalf("80ms queue residence consumed the 100ms physical timeout: %+v", r)
		}
		r := m.Measure(context.Background(), netip.MustParseAddr("192.0.2.2"), profile)
		if r.Outcome != Success || !r.Cached {
			t.Fatalf("wrong cached outcome: %+v", r)
		}
	})
}

func TestPhysicalTimeoutCacheExpiryAndConfigurationIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{FailureTTL: 5 * time.Second})
		defer m.Close()
		var calls atomic.Int32
		m.probe = func(ctx context.Context, _ netip.Addr, method probeMethod) Result {
			calls.Add(1)
			if method.port == 80 {
				return Result{Outcome: Success, RTT: 2 * time.Millisecond}
			}
			<-ctx.Done()
			return networkFailure(ctx, ctx.Err())
		}
		if r := m.Measure(context.Background(), testIP, config(443)); r.Outcome != Failed || r.Cached {
			t.Fatalf("real timeout: %#v", r)
		}
		if r := m.Measure(context.Background(), testIP, config(443)); r.Outcome != Failed || !r.Cached || calls.Load() != 1 {
			t.Fatalf("failure cache: %#v", r)
		}
		if r := m.Measure(context.Background(), testIP, config(80)); r.Outcome != Success || r.Cached {
			t.Fatalf("port must isolate cache: %#v", r)
		}
		time.Sleep(5 * time.Second)
		if r := m.Measure(context.Background(), testIP, config(443)); r.Cached || calls.Load() != 3 {
			t.Fatalf("failure expiry: %#v calls=%d", r, calls.Load())
		}
	})
}

func TestLateEarlyReplyCannotPopulateSuccessCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{})
		defer m.Close()
		m.probe = func(ctx context.Context, _ netip.Addr, _ probeMethod) Result {
			<-ctx.Done()
			reportProbeResult(ctx, Result{Outcome: Success, RTT: time.Millisecond})
			return Result{Outcome: Success, RTT: time.Millisecond}
		}
		if r := m.Measure(context.Background(), testIP, config(443)); r.Outcome != Failed || r.Cached {
			t.Fatalf("late reply succeeded: %#v", r)
		}
		if r := m.Measure(context.Background(), testIP, config(443)); r.Outcome != Failed || !r.Cached {
			t.Fatalf("timeout must retain failure semantics: %#v", r)
		}
	})
}

func TestSuccessCacheLRUAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{CacheSize: 2, SuccessTTL: time.Second})
		defer m.Close()
		m.probe = func(context.Context, netip.Addr, probeMethod) Result {
			return Result{Outcome: Success, RTT: time.Millisecond}
		}
		ip2, ip3 := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
		m.Measure(context.Background(), testIP, config(443))
		m.Measure(context.Background(), ip2, config(443))
		m.Measure(context.Background(), testIP, config(443)) // ip2 becomes the LRU
		m.Measure(context.Background(), ip3, config(443))
		if r := m.Measure(context.Background(), testIP, config(443)); !r.Cached {
			t.Fatal("MRU was evicted")
		}
		if r := m.Measure(context.Background(), ip2, config(443)); r.Cached {
			t.Fatal("LRU was not evicted")
		}
		if s := m.Stats(); s.CacheEntries != 2 {
			t.Fatalf("unbounded cache: %#v", s)
		}
		time.Sleep(time.Second)
		if r := m.Measure(context.Background(), ip2, config(443)); r.Cached {
			t.Fatal("expired success reused")
		}
	})
}

func TestCloseCancelsAndWaitsForActiveAndQueued(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{MaxConcurrent: 1, QueueSize: 1})
		var cleaned atomic.Bool
		m.probe = func(ctx context.Context, _ netip.Addr, _ probeMethod) Result {
			<-ctx.Done()
			time.Sleep(10 * time.Millisecond)
			cleaned.Store(true)
			return unmeasuredContext(ctx.Err())
		}
		a := measureAsync(m, context.Background(), testIP, config(443))
		synctest.Wait()
		b := measureAsync(m, context.Background(), netip.MustParseAddr("192.0.2.2"), config(443))
		synctest.Wait()
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		if !cleaned.Load() || m.Stats().Active != 0 || m.Stats().Queued != 0 {
			t.Fatalf("Close returned early: %#v", m.Stats())
		}
		if (<-a).Outcome != Unmeasured || (<-b).Outcome != Unmeasured {
			t.Fatal("closed callers must be unmeasured")
		}
		if r := m.Measure(context.Background(), testIP, config(443)); r.Reason != "closed" {
			t.Fatalf("new work after Close: %#v", r)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCachedResultBypassesSaturatedBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{MaxConcurrent: 1, QueueSize: 1})
		defer m.Close()
		release := make(chan struct{})
		m.probe = func(ctx context.Context, ip netip.Addr, _ probeMethod) Result {
			if ip == testIP {
				return Result{Outcome: Success, RTT: time.Millisecond}
			}
			select {
			case <-release:
				return Result{Outcome: Success, RTT: time.Millisecond}
			case <-ctx.Done():
				return unmeasuredContext(ctx.Err())
			}
		}
		m.Measure(context.Background(), testIP, config(443))
		a := measureAsync(m, context.Background(), netip.MustParseAddr("192.0.2.2"), config(443))
		synctest.Wait()
		b := measureAsync(m, context.Background(), netip.MustParseAddr("192.0.2.3"), config(443))
		synctest.Wait()
		if r := m.Measure(context.Background(), testIP, config(443)); !r.Cached || r.Outcome != Success {
			t.Fatalf("cache waited for capacity: %#v", r)
		}
		close(release)
		synctest.Wait()
		<-a
		<-b
	})
}

func TestMeasureCanCancelWhileInitialICMPCapabilityCheckWaitsForBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{MaxConcurrent: 1, QueueSize: 1})
		defer m.Close()
		m.detectICMP = func() (string, string, error) { return "fake4", "fake6", nil }
		m.probe = func(ctx context.Context, _ netip.Addr, _ probeMethod) Result {
			<-ctx.Done()
			return unmeasuredContext(ctx.Err())
		}
		a := measureAsync(m, context.Background(), testIP, config(443))
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		b := measureAsync(m, ctx, netip.MustParseAddr("192.0.2.2"), Config{TCPPorts: []uint16{}, ICMP: true})
		synctest.Wait()
		cancel()
		synctest.Wait()
		if r := <-b; r.Outcome != Unmeasured || r.Reason != "canceled" {
			t.Fatalf("capability wait ignored subscriber cancellation: %#v", r)
		}
		m.Close()
		<-a
	})
}

func TestTCPAndICMPMethodsRunTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := NewManager(Options{})
		defer m.Close()
		m.detectICMP = func() (string, string, error) { return "fake4", "fake6", nil }
		c, err := m.Prepare(Config{TCPPorts: []uint16{80, 443}, ICMP: true})
		if err != nil {
			t.Fatal(err)
		}
		release := make(chan struct{})
		var canceled atomic.Int32
		m.probe = func(ctx context.Context, _ netip.Addr, method probeMethod) Result {
			if method.port == 0 {
				<-release
				return Result{Outcome: Success, RTT: time.Millisecond}
			}
			<-ctx.Done()
			canceled.Add(1)
			return unmeasuredContext(ctx.Err())
		}
		a := measureAsync(m, context.Background(), testIP, c)
		synctest.Wait()
		if m.Stats().Active != 3 {
			t.Fatalf("methods not parallel: %#v", m.Stats())
		}
		close(release)
		synctest.Wait()
		if r := <-a; r.Outcome != Success || canceled.Load() != 2 {
			t.Fatalf("ICMP winner/losers: %#v canceled=%d", r, canceled.Load())
		}
	})
}
