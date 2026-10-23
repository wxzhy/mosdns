// Package speedtest measures address reachability without coupling measurements
// to DNS responses or response selection policy.
package speedtest

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type Outcome string

const (
	Success    Outcome = "success"
	Failed     Outcome = "failed"
	Unmeasured Outcome = "unmeasured"
)

type Result struct {
	Outcome Outcome
	RTT     time.Duration
	Cached  bool
	Reason  string
}

type Config struct {
	TCPPorts []uint16      `yaml:"tcp_ports"`
	ICMP     bool          `yaml:"icmp"`
	Timeout  time.Duration `yaml:"timeout"`
}

type Options struct {
	Logger                              *zap.Logger
	MaxConcurrent, QueueSize, CacheSize int
	SuccessTTL, FailureTTL              time.Duration
}

// Statistics counts physical methods, rather than logical Measure callers.
// CacheHits and Shared count callers served by the cache and an existing flight.
type Statistics struct {
	Active, Queued, Flights, CacheEntries int
	CacheHits, Shared, Probes             uint64
}

type probeMethod struct {
	port uint16 // zero denotes ICMP
}

type probeReporterKey struct{}

// A library may observe a reply before its receive goroutine has stopped. The
// result can be published immediately while the worker keeps its socket slot
// until all library cleanup has finished.
func reportProbeResult(ctx context.Context, result Result) bool {
	report, ok := ctx.Value(probeReporterKey{}).(func(Result))
	if ok {
		report(result)
	}
	return ok
}

type probeKey struct {
	ip      netip.Addr
	ports   string
	icmp    bool
	timeout time.Duration
}

type flight struct {
	ctx     context.Context
	cancel  context.CancelCauseFunc
	done    chan struct{}
	waiters int    // protected by Manager.mu
	result  Result // published by closing done
}

type cacheEntry struct {
	key     probeKey
	result  Result
	expires time.Time
}

var (
	errClosed   = errors.New("speedtest manager closed")
	errNoWaiter = errors.New("speedtest has no waiters")
	errWinner   = errors.New("speedtest method succeeded")
)

// Manager owns the physical probe budget, cache, and shared flights. Each
// physical method reserves one active slot or one bounded queue slot. No socket
// is opened while queued. All sockets are private to their physical method.
type Manager struct {
	logger *zap.Logger
	ctx    context.Context
	cancel context.CancelCauseFunc
	active chan struct{}
	queue  chan struct{}
	opts   Options

	mu        sync.Mutex
	closed    bool
	flights   map[probeKey]*flight
	cache     map[probeKey]*list.Element
	lru       list.List
	flightWG  sync.WaitGroup
	probeWG   sync.WaitGroup
	closeOnce sync.Once
	closeDone chan struct{}

	capOnce      sync.Once
	capDone      chan struct{}
	icmp4, icmp6 string
	capErr       error
	// Unexported hooks permit deterministic tests without real network delays.
	probe      func(context.Context, netip.Addr, probeMethod) Result
	detectICMP func() (string, string, error)

	cacheHits atomic.Uint64
	shared    atomic.Uint64
	probes    atomic.Uint64
}

func NewManager(o Options) *Manager {
	if o.Logger == nil {
		o.Logger = zap.NewNop()
	}
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = 128
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 1024
	}
	if o.CacheSize <= 0 {
		o.CacheSize = 10000
	}
	if o.SuccessTTL <= 0 {
		o.SuccessTTL = 60 * time.Second
	}
	if o.FailureTTL <= 0 {
		o.FailureTTL = 5 * time.Second
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	m := &Manager{
		logger: o.Logger, ctx: ctx, cancel: cancel, opts: o,
		active: make(chan struct{}, o.MaxConcurrent), queue: make(chan struct{}, o.QueueSize),
		flights: make(map[probeKey]*flight), cache: make(map[probeKey]*list.Element),
		closeDone: make(chan struct{}), capDone: make(chan struct{}), detectICMP: detectICMP,
	}
	m.probe = m.probeNetwork
	return m
}

// Prepare returns an owned, normalized configuration. A nil TCPPorts selects
// ports 80 and 443; a non-nil empty slice explicitly disables TCP. With both
// methods disabled the configuration is valid, and Measure returns Unmeasured.
func (m *Manager) Prepare(c Config) (Config, error) {
	return m.prepare(m.ctx, c)
}

func (m *Manager) prepare(ctx context.Context, c Config) (Config, error) {
	if m.ctx.Err() != nil {
		return Config{}, errClosed
	}
	if c.Timeout == 0 {
		c.Timeout = 300 * time.Millisecond
	}
	if c.Timeout < 0 {
		return Config{}, errors.New("speedtest timeout must be positive")
	}
	if c.TCPPorts == nil {
		c.TCPPorts = []uint16{80, 443}
	} else {
		// Preserve the distinction between nil and explicitly empty.
		c.TCPPorts = append([]uint16{}, c.TCPPorts...)
	}
	slices.Sort(c.TCPPorts)
	c.TCPPorts = slices.Compact(c.TCPPorts)
	if len(c.TCPPorts) > 0 && c.TCPPorts[0] == 0 {
		return Config{}, errors.New("speedtest TCP port must be between 1 and 65535")
	}
	if c.ICMP {
		m.capOnce.Do(func() {
			m.mu.Lock()
			if m.closed {
				m.capErr = errClosed
				m.mu.Unlock()
				close(m.capDone)
				return
			}
			m.probeWG.Add(1)
			m.mu.Unlock()
			go func() {
				defer m.probeWG.Done()
				defer close(m.capDone)
				select {
				case m.active <- struct{}{}:
					defer func() { <-m.active }()
				case <-m.ctx.Done():
					m.capErr = errClosed
					return
				}
				m.icmp4, m.icmp6, m.capErr = m.detectICMP()
				if m.icmp4 == "" && m.icmp6 == "" {
					if m.capErr == nil {
						m.capErr = errors.New("no ICMP socket is available")
					}
					m.logger.Warn("ICMP speedtest is unavailable", zap.Error(m.capErr))
				}
			}()
		})
		select {
		case <-ctx.Done():
			return Config{}, ctx.Err()
		case <-m.ctx.Done():
			return Config{}, errClosed
		case <-m.capDone:
		}
		if m.icmp4 == "" && m.icmp6 == "" {
			if len(c.TCPPorts) == 0 {
				return Config{}, fmt.Errorf("ICMP speedtest is unavailable: %w", m.capErr)
			}
			c.ICMP = false
		}
	}
	return c, nil
}

func makeKey(ip netip.Addr, c Config) probeKey {
	b := make([]byte, len(c.TCPPorts)*2)
	for i, p := range c.TCPPorts {
		b[i*2], b[i*2+1] = byte(p>>8), byte(p)
	}
	return probeKey{ip: ip, ports: string(b), icmp: c.ICMP, timeout: c.Timeout}
}

// Measure subscribes to a shared address/configuration flight. Canceling one
// subscriber never cancels another. When the last subscriber leaves, its flight
// is removed before cancellation so a late result cannot enter the cache or
// overwrite a replacement flight.
func (m *Manager) Measure(ctx context.Context, ip netip.Addr, c Config) Result {
	if err := ctx.Err(); err != nil {
		return unmeasuredContext(err)
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return Result{Outcome: Unmeasured, Reason: "invalid_ip"}
	}
	c, err := m.prepare(ctx, c)
	if err != nil {
		if ctx.Err() != nil {
			return unmeasuredContext(ctx.Err())
		}
		reason := "invalid_config"
		if errors.Is(err, errClosed) {
			reason = "closed"
		}
		return Result{Outcome: Unmeasured, Reason: reason}
	}
	if len(c.TCPPorts) == 0 && !c.ICMP {
		return Result{Outcome: Unmeasured, Reason: "disabled"}
	}
	if c.ICMP && m.icmpNetwork(ip) == "" {
		if len(c.TCPPorts) == 0 {
			return Result{Outcome: Unmeasured, Reason: "icmp_family_unavailable"}
		}
		c.ICMP = false
	}
	key := makeKey(ip, c)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Result{Outcome: Unmeasured, Reason: "closed"}
	}
	if result, ok := m.cachedLocked(key); ok {
		m.mu.Unlock()
		m.cacheHits.Add(1)
		result.Cached = true
		return result
	}
	f := m.flights[key]
	if f == nil {
		workCtx, cancel := context.WithCancelCause(m.ctx)
		f = &flight{ctx: workCtx, cancel: cancel, done: make(chan struct{})}
		m.flights[key] = f
		m.flightWG.Add(1)
		go m.runFlight(key, f, ip, c)
	} else {
		m.shared.Add(1)
	}
	f.waiters++
	m.mu.Unlock()
	defer m.release(key, f)
	select {
	case <-ctx.Done():
		return unmeasuredContext(ctx.Err())
	case <-m.ctx.Done():
		return Result{Outcome: Unmeasured, Reason: "closed"}
	case <-f.done:
		return f.result
	}
}

func unmeasuredContext(err error) Result {
	reason := "canceled"
	if errors.Is(err, context.DeadlineExceeded) {
		reason = "deadline_exceeded"
	}
	return Result{Outcome: Unmeasured, Reason: reason}
}

func (m *Manager) release(key probeKey, f *flight) {
	m.mu.Lock()
	f.waiters--
	if f.waiters == 0 && m.flights[key] == f {
		delete(m.flights, key)
		f.cancel(errNoWaiter)
	}
	m.mu.Unlock()
}

func (m *Manager) runFlight(key probeKey, f *flight, ip netip.Addr, c Config) {
	defer m.flightWG.Done()
	n := len(c.TCPPorts)
	if c.ICMP {
		n++
	}
	results := make(chan Result, n)
	for _, port := range c.TCPPorts {
		m.schedule(f.ctx, ip, probeMethod{port: port}, c.Timeout, results)
	}
	if c.ICMP {
		m.schedule(f.ctx, ip, probeMethod{}, c.Timeout, results)
	}
	result := Result{Outcome: Failed, Reason: "all_probes_failed"}
	published := false
	for range n {
		r := <-results
		if r.Outcome == Success && result.Outcome != Success {
			result = r
			f.cancel(errWinner)
			m.publish(key, f, result)
			published = true
		} else if r.Outcome == Unmeasured && result.Outcome != Success {
			result = r // an unattempted method prevents negative caching
		}
	}
	if !published {
		m.publish(key, f, result)
	}
	f.cancel(nil)
}

func (m *Manager) publish(key probeKey, f *flight, result Result) {
	m.mu.Lock()
	if m.flights[key] == f {
		delete(m.flights, key)
		if !m.closed && f.waiters > 0 && (result.Outcome == Success || result.Outcome == Failed) {
			m.storeLocked(key, result)
		}
	}
	if m.closed {
		result = Result{Outcome: Unmeasured, Reason: "closed"}
	}
	f.result = result
	close(f.done)
	m.mu.Unlock()
}

// schedule reserves a physical or queue slot synchronously, so both physical
// sockets and queued goroutines stay bounded even for large port lists.
func (m *Manager) schedule(ctx context.Context, ip netip.Addr, method probeMethod, timeout time.Duration, results chan<- Result) {
	if err := ctx.Err(); err != nil {
		results <- unmeasuredContext(err)
		return
	}
	queued := false
	var queueDeadline time.Time
	select {
	case m.active <- struct{}{}:
	default:
		select {
		case m.queue <- struct{}{}:
			queued = true
			queueDeadline = time.Now().Add(timeout)
		default:
			results <- Result{Outcome: Unmeasured, Reason: "queue_full"}
			return
		}
	}
	m.probeWG.Add(1)
	go func() {
		defer m.probeWG.Done()
		if queued {
			queueCtx, cancel := context.WithDeadline(ctx, queueDeadline)
			select {
			case m.active <- struct{}{}:
				<-m.queue
				if queueCtx.Err() != nil {
					cancel()
					<-m.active
					if ctx.Err() != nil {
						results <- unmeasuredContext(ctx.Err())
					} else {
						results <- Result{Outcome: Unmeasured, Reason: "queue_deadline"}
					}
					return
				}
				cancel()
			case <-ctx.Done():
				<-m.queue
				cancel()
				results <- unmeasuredContext(ctx.Err())
				return
			case <-queueCtx.Done():
				<-m.queue
				cancel()
				if ctx.Err() != nil {
					results <- unmeasuredContext(ctx.Err())
				} else {
					results <- Result{Outcome: Unmeasured, Reason: "queue_deadline"}
				}
				return
			}
		}
		defer func() { <-m.active }()
		if err := ctx.Err(); err != nil {
			results <- unmeasuredContext(err)
			return
		}
		m.probes.Add(1)
		// Queue residence is not evidence of network failure. Each physical
		// method receives its complete timeout only after acquiring a slot.
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var reported atomic.Bool
		report := func(r Result) {
			if r.Outcome == Success {
				if err := probeCtx.Err(); err != nil {
					r = networkFailure(probeCtx, err)
				} else if deadline, ok := probeCtx.Deadline(); ok && !time.Now().Before(deadline) {
					// The timer callback may not have canceled the context yet.
					// A reply observed after the physical budget cannot succeed.
					r = Result{Outcome: Failed, Reason: "timeout"}
				}
			}
			if r.Outcome == Success && r.RTT < 0 {
				r = Result{Outcome: Unmeasured, Reason: "invalid_rtt"}
			}
			if reported.CompareAndSwap(false, true) {
				results <- r
			}
		}
		probeCtx = context.WithValue(probeCtx, probeReporterKey{}, report)
		r := m.probe(probeCtx, ip, method)
		report(r)
	}()
}

func (m *Manager) cachedLocked(key probeKey) (Result, bool) {
	e := m.cache[key]
	if e == nil {
		return Result{}, false
	}
	c := e.Value.(*cacheEntry)
	if !time.Now().Before(c.expires) {
		delete(m.cache, key)
		m.lru.Remove(e)
		return Result{}, false
	}
	m.lru.MoveToFront(e)
	return c.result, true
}

func (m *Manager) storeLocked(key probeKey, r Result) {
	ttl := m.opts.SuccessTTL
	if r.Outcome == Failed {
		ttl = m.opts.FailureTTL
	}
	c := &cacheEntry{key: key, result: r, expires: time.Now().Add(ttl)}
	if e := m.cache[key]; e != nil {
		e.Value = c
		m.lru.MoveToFront(e)
	} else {
		m.cache[key] = m.lru.PushFront(c)
	}
	for len(m.cache) > m.opts.CacheSize {
		e := m.lru.Back()
		delete(m.cache, e.Value.(*cacheEntry).key)
		m.lru.Remove(e)
	}
}

func (m *Manager) Stats() Statistics {
	m.mu.Lock()
	s := Statistics{Active: len(m.active), Queued: len(m.queue), Flights: len(m.flights), CacheEntries: len(m.cache)}
	m.mu.Unlock()
	s.CacheHits, s.Shared, s.Probes = m.cacheHits.Load(), m.shared.Load(), m.probes.Load()
	return s
}

// Close is idempotent. It rejects new work, cancels shared probes, and waits for
// every flight and physical method (including queued methods) to finish.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.cancel(errClosed)
		m.mu.Unlock()
		m.flightWG.Wait() // no schedule/Add calls remain after flights finish
		m.probeWG.Wait()
		m.mu.Lock()
		clear(m.cache)
		m.lru.Init()
		m.mu.Unlock()
		close(m.closeDone)
	})
	<-m.closeDone
	return nil
}
