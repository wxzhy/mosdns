package speedcheck

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/IrineSistiana/mosdns/v5/pkg/response"
	"github.com/IrineSistiana/mosdns/v5/pkg/speedtest"
	"github.com/miekg/dns"
)

var ErrNoCandidates = errors.New("speedcheck: no accepted DNS response")

type Selector struct {
	args       Args
	sources    []Source
	probe      ProbeFunc
	labels     map[string]netlist.Matcher
	asns       map[uint32]netlist.Matcher
	labelNames []string
	metrics    selectorMetrics
	lifetime   context.Context
	close      context.CancelFunc
	mu         sync.Mutex
	closed     bool
	active     sync.WaitGroup
	publishers sync.WaitGroup
	closeOnce  sync.Once
	closeDone  chan struct{}
}

func New(args Args, sources []Source, opts Options) (*Selector, error) {
	args, err := normalize(args)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, errors.New("speedcheck: sources must not be empty")
	}
	if opts.Probe == nil {
		return nil, errors.New("speedcheck: probe manager is required")
	}
	seen := make(map[string]bool)
	for i, source := range sources {
		if source.Tag == "" || source.Exec == nil {
			return nil, fmt.Errorf("speedcheck: invalid source #%d", i)
		}
		if seen[source.Tag] {
			return nil, fmt.Errorf("speedcheck: duplicate source %q", source.Tag)
		}
		seen[source.Tag] = true
	}
	if opts.Prepare != nil {
		args.Probe, err = opts.Prepare(args.Probe)
		if err != nil {
			return nil, err
		}
	}
	life, cancel := context.WithCancel(context.Background())
	s := &Selector{args: args, sources: slices.Clone(sources), probe: opts.Probe, labels: cloneMatchers(opts.Labels), asns: cloneASNMatchers(opts.ASNMatchers), metrics: newMetrics(opts.MetricsTag), lifetime: life, close: cancel, closeDone: make(chan struct{})}
	if err := s.validateMatchers(); err != nil {
		cancel()
		return nil, err
	}
	return s, nil
}

func cloneMatchers(in map[string]netlist.Matcher) map[string]netlist.Matcher {
	out := make(map[string]netlist.Matcher, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func cloneASNMatchers(in map[uint32]netlist.Matcher) map[uint32]netlist.Matcher {
	out := make(map[uint32]netlist.Matcher, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Close cancels queries and waits for their source/probe publishers. Exec itself
// does not wait for losing branches, preserving bounded response latency.
// As with other executables, custom sources must honor their context.
func (s *Selector) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.close()
		s.mu.Unlock()
		// All publisher Add calls happen inside active Exec calls. Waiting in
		// this order prevents Add racing with a zero-count publishers.Wait.
		s.active.Wait()
		s.publishers.Wait()
		close(s.closeDone)
	})
	<-s.closeDone
	return nil
}

type sourceEvent struct {
	index     int
	candidate *response.Candidate
	err       error
	at        time.Time
}
type probeEvent struct {
	ip         netip.Addr
	generation uint64
	result     speedtest.Result
	at         time.Time
}
type ipMetadata struct {
	labels     []string
	asns       []uint32
	multiplier float64
}
type candidateState struct {
	source       int
	readyAt      time.Time
	value        *response.Candidate
	metadata     map[netip.Addr]ipMetadata
	probeAllowed bool
}
type probeState struct {
	result      speedtest.Result
	done        bool
	cancel      context.CancelFunc
	generation  uint64
	completedAt time.Time
}
type rankedAddress struct {
	candidate *candidateState
	address   response.Address
	metadata  ipMetadata
	result    speedtest.Result
	valid     bool
	score     float64
}

// Exec owns every candidate, subscription, and selection mutation in this
// goroutine. Sources and probes publish immutable events and never see qCtx.
func (s *Selector) Exec(parent context.Context, qCtx *query_context.Context) (err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return context.Canceled
	}
	s.active.Add(1)
	s.mu.Unlock()
	defer s.active.Done()
	started := time.Now()
	s.metrics.active.Inc()
	outcome := "error"
	defer func() {
		s.metrics.active.Dec()
		s.metrics.duration.Observe(time.Since(started).Seconds())
		s.metrics.queries.WithLabelValues(outcome).Inc()
	}()
	if err := parent.Err(); err != nil {
		return context.Cause(parent)
	}
	if err := s.lifetime.Err(); err != nil {
		return err
	}
	end := started.Add(s.args.TotalTimeout)
	if d, ok := parent.Deadline(); ok && d.Before(end) {
		end = d
	}
	// Leave the caller time to rebuild, run its fallback, and send a reply.
	reserve := min(50*time.Millisecond, max(time.Duration(0), time.Until(end)/2))
	work, cancel := context.WithDeadline(parent, end.Add(-reserve))
	stopClose := context.AfterFunc(s.lifetime, cancel)
	defer stopClose()
	defer cancel()
	work = query_policy.WithInheritedCancellation(work)
	ready := make(chan sourceEvent, len(s.sources))
	probed := make(chan probeEvent, maxUniqueIPs*2)
	// Copy contexts before starting any source, so none can race with parent
	// mutation. Response and options from a previous executable are discarded.
	parentQuestion := qCtx.QQuestion()
	for i, source := range s.sources {
		branch := qCtx.Copy()
		branch.SetResponse(nil)
		if opt := branch.RespOpt(); opt != nil {
			opt.Option = nil
		}
		s.publishers.Add(1)
		go func(index int, source Source, branch *query_context.Context) {
			defer s.publishers.Done()
			e := source.Exec.Exec(work, branch)
			event := sourceEvent{index: index, err: e, at: time.Now()}
			if e == nil {
				if len(branch.Q().Question) != 1 {
					event.err = errors.New("speedcheck: source changed the question count")
				} else if question := branch.QQuestion(); !strings.EqualFold(question.Name, parentQuestion.Name) || question.Qtype != parentQuestion.Qtype || question.Qclass != parentQuestion.Qclass {
					event.err = errors.New("speedcheck: source changed the requested question")
				} else {
					received := branch.ResponseReceivedAt()
					if received.IsZero() {
						received = event.at
					}
					event.candidate, event.err = response.Analyze(branch.Q(), branch.SnapshotResponse(), received)
				}
			}
			// One event per source, and the channel has exactly that capacity.
			ready <- event
		}(i, source, branch)
	}
	states := make([]*candidateState, len(s.sources))
	probes := make(map[netip.Addr]*probeState)
	startedIPs := make(map[netip.Addr]bool)
	admitted := make(map[netip.Addr]bool)
	defer func() {
		for _, p := range probes {
			if p.cancel != nil {
				p.cancel()
			}
		}
	}()
	metadata := make(map[netip.Addr]ipMetadata)
	doneSources := 0
	var firstPositive, firstSuccess time.Time
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	// Internal deadlines still preserve a complete usable answer. Parent
	// cancellation and plugin shutdown instead abort without committing.
	deadline := time.Now().Add(s.args.TotalTimeout)
	if d, ok := work.Deadline(); ok {
		deadline = d
	}
	cutoff := deadline
	updateCutoff := func() {
		cutoff = minTime(cutoff, selectionCutoff(deadline, s.args.Mode, firstPositive, firstSuccess, s.args.SelectionTimeout, s.args.SettleWindow))
	}
	resetTimer := func() {
		updateCutoff()
		if timer == nil {
			timer = time.NewTimer(time.Until(cutoff))
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(time.Until(cutoff))
		}
		timerC = timer.C
	}
	resetTimer()
	question := qCtx.QQuestion()
	addressQuery := question.Qclass == dns.ClassINET && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA)
	acceptSource := func(event sourceEvent, launch bool) bool {
		doneSources++
		if event.at.After(cutoff) {
			return false
		}
		result := "accepted"
		accepted := false
		if event.err != nil || event.candidate == nil || event.candidate.Snapshot.Response == nil {
			result = "error"
		} else {
			c := event.candidate
			if r := c.Snapshot.Response.Rcode; r != dns.RcodeSuccess && r != dns.RcodeNameError {
				result = "rcode"
			} else {
				cs := &candidateState{source: event.index, readyAt: event.at, value: c, metadata: make(map[netip.Addr]ipMetadata)}
				for _, address := range c.Addresses {
					m, ok := metadata[address.IP]
					if !ok {
						m = s.classify(address.IP)
						metadata[address.IP] = m
					}
					cs.metadata[address.IP] = m
				}
				if len(c.Addresses) > 0 && !s.matches(s.args.CandidateFilter, cs) {
					result = "filtered"
				} else {
					cs.probeAllowed = s.matches(s.args.ProbeMatch, cs)
					states[event.index] = cs
					accepted = true
					if len(c.Addresses) > 0 && observeEarliest(&firstPositive, event.at) {
						if launch {
							resetTimer()
						} else {
							updateCutoff()
						}
					}
					admitted = s.refreshProbes(work, states, probes, startedIPs, probed, launch)
				}
			}
		}
		s.metrics.sources.WithLabelValues(s.sources[event.index].Tag, result).Inc()
		return accepted
	}
	acceptProbe := func(event probeEvent, reschedule bool) {
		p := probes[event.ip]
		if p == nil || p.generation != event.generation || event.at.After(cutoff) {
			return
		}
		p.result = event.result
		p.done = true
		p.cancel = nil
		p.completedAt = event.at
		s.metrics.probes.WithLabelValues(string(event.result.Outcome), strconv.FormatBool(event.result.Cached)).Inc()
		if admitted[event.ip] && validRTT(event.result) && observeEarliest(&firstSuccess, event.at) {
			if reschedule {
				resetTimer()
			} else {
				updateCutoff()
			}
		}
	}
	finish := func() error {
		if parent.Err() != nil {
			outcome = "canceled"
			return context.Cause(parent)
		}
		if s.lifetime.Err() != nil {
			outcome = "closed"
			return s.lifetime.Err()
		}
		// Freeze after consuming already published, in-window events. Do not
		// wait for uncompleted branches or launch new optional work here.
		for {
			select {
			case event := <-ready:
				acceptSource(event, false)
			case event := <-probed:
				acceptProbe(event, false)
			default:
				goto drained
			}
		}
	drained:
		// A previously processed event may have been inside the old cutoff
		// before an out-of-order, earlier success shortened it during drain.
		freezeAtCutoff(states, probes, cutoff)
		admitted = s.refreshProbes(work, states, probes, startedIPs, probed, false)
		s.metrics.addresses.Observe(float64(len(admitted)))
		snapshot, kind, e := s.selectResponse(states, probes, admitted, qCtx, time.Now())
		if e != nil {
			return e
		}
		if parent.Err() != nil {
			outcome = "canceled"
			return context.Cause(parent)
		}
		if s.lifetime.Err() != nil {
			outcome = "closed"
			return s.lifetime.Err()
		}
		qCtx.CommitResponse(snapshot)
		outcome = kind
		return nil
	}
	for {
		select {
		case event := <-ready:
			if accepted := acceptSource(event, true); accepted && !addressQuery {
				return finish()
			}
		case event := <-probed:
			acceptProbe(event, true)
		case <-timerC:
			return finish()
		case <-work.Done():
			return finish()
		}
		if doneSources == len(s.sources) && allProbesDone(probes, admitted) {
			return finish()
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func selectionCutoff(deadline time.Time, mode string, positive, success time.Time, selection, settle time.Duration) time.Time {
	if mode != ModeBounded {
		return deadline
	}
	if !positive.IsZero() {
		deadline = minTime(deadline, positive.Add(selection))
	}
	if !success.IsZero() {
		deadline = minTime(deadline, success.Add(settle))
	}
	return deadline
}

func observeEarliest(current *time.Time, at time.Time) bool {
	if current.IsZero() || at.Before(*current) {
		*current = at
		return true
	}
	return false
}

func freezeAtCutoff(states []*candidateState, probes map[netip.Addr]*probeState, cutoff time.Time) {
	for i, c := range states {
		if c != nil && c.readyAt.After(cutoff) {
			states[i] = nil
		}
	}
	for _, p := range probes {
		if p.done && !p.completedAt.IsZero() && p.completedAt.After(cutoff) {
			p.done = false
			p.result = speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "after_selection_window"}
		}
	}
}
func validRTT(r speedtest.Result) bool { return r.Outcome == speedtest.Success && r.RTT >= 0 }
func allProbesDone(probes map[netip.Addr]*probeState, admitted map[netip.Addr]bool) bool {
	for ip := range admitted {
		if p := probes[ip]; p != nil && !p.done {
			return false
		}
	}
	return true
}

// refreshProbes always computes the 64-IP set from source/record order rather
// than arrival order. An earlier source can displace a later source's IPs.
func (s *Selector) refreshProbes(ctx context.Context, states []*candidateState, probes map[netip.Addr]*probeState, startedIPs map[netip.Addr]bool, events chan<- probeEvent, launch bool) map[netip.Addr]bool {
	admitted := make(map[netip.Addr]bool)
	allowed := make(map[netip.Addr]bool)
	var ordered []netip.Addr
	for _, c := range states {
		if c == nil {
			continue
		}
		addresses := slices.Clone(c.value.Addresses)
		sort.SliceStable(addresses, func(i, j int) bool {
			if addresses[i].Index != addresses[j].Index {
				return addresses[i].Index < addresses[j].Index
			}
			return addresses[i].IP.Less(addresses[j].IP)
		})
		for _, a := range addresses {
			if !admitted[a.IP] && len(admitted) >= maxUniqueIPs {
				continue
			}
			if !admitted[a.IP] {
				ordered = append(ordered, a.IP)
			}
			admitted[a.IP] = true
			allowed[a.IP] = allowed[a.IP] || c.probeAllowed
		}
	}
	for ip, p := range probes {
		if (!admitted[ip] || !allowed[ip]) && p.cancel != nil {
			p.cancel()
			p.cancel = nil
			p.generation++
			p.done = false
		}
	}
	for _, ip := range ordered {
		p := probes[ip]
		if p == nil {
			p = &probeState{}
			probes[ip] = p
		}
		if p.done && p.result.Reason == "disabled_or_unmatched" && allowed[ip] && (s.args.Probe.ICMP || len(s.args.Probe.TCPPorts) > 0) {
			p.done = false
		}
		if p.done || p.cancel != nil {
			continue
		}
		if !launch {
			continue
		}
		if !allowed[ip] || (!s.args.Probe.ICMP && len(s.args.Probe.TCPPorts) == 0) {
			p.done = true
			p.result = speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "disabled_or_unmatched"}
			continue
		}
		if !startedIPs[ip] && len(startedIPs) >= maxUniqueIPs {
			p.done = true
			p.result = speedtest.Result{Outcome: speedtest.Unmeasured, Reason: "request_ip_budget"}
			continue
		}
		startedIPs[ip] = true
		probeCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel
		p.generation++
		generation := p.generation
		s.publishers.Add(1)
		go func(ip netip.Addr) {
			defer s.publishers.Done()
			result := s.probe(probeCtx, ip, s.args.Probe)
			event := probeEvent{ip: ip, generation: generation, result: result, at: time.Now()}
			select {
			case events <- event:
				return
			default:
			}
			select {
			case events <- event:
			case <-ctx.Done():
			}
		}(ip)
	}
	return admitted
}

func (s *Selector) classify(ip netip.Addr) ipMetadata {
	m := ipMetadata{multiplier: 1}
	for _, name := range s.labelNames {
		if s.labels[name].Match(ip) {
			m.labels = append(m.labels, name)
		}
	}
	for n, matcher := range s.asns {
		if matcher.Match(ip) {
			m.asns = append(m.asns, n)
		}
	}
	slices.Sort(m.asns)
	for _, w := range s.args.TagMultipliers {
		if slices.Contains(m.labels, w.Tag) {
			m.multiplier = w.Multiplier
			return m
		}
	}
	for _, n := range m.asns {
		if w, ok := s.args.ASNMultipliers[n]; ok {
			m.multiplier = w
			break
		}
	}
	return m
}

func (s *Selector) matches(f *IPFilter, c *candidateState) bool {
	if f == nil {
		return true
	}
	hasInclude := f.LabelsInclude != nil || f.ASNInclude != nil
	included := !hasInclude
	for _, m := range c.metadata {
		for _, label := range m.labels {
			if slices.Contains(f.LabelsExclude, label) {
				return false
			}
			if slices.Contains(f.LabelsInclude, label) {
				included = true
			}
		}
		for _, asn := range m.asns {
			if slices.Contains(f.ASNExclude, asn) {
				return false
			}
			if slices.Contains(f.ASNInclude, asn) {
				included = true
			}
		}
	}
	return included
}

func (s *Selector) selectResponse(states []*candidateState, probes map[netip.Addr]*probeState, admitted map[netip.Addr]bool, qCtx *query_context.Context, now time.Time) (query_context.ResponseSnapshot, string, error) {
	var ranked []rankedAddress
	for _, c := range states {
		if c == nil {
			continue
		}
		for _, a := range c.value.Addresses {
			// An original TTL zero answer is valid for this reply. A nonzero
			// address that expired while collecting sources cannot be revived.
			if !admitted[a.IP] || (!a.ExpiresAt.After(now) && !a.ExpiresAt.Equal(c.value.ReceivedAt)) {
				continue
			}
			r := speedtest.Result{Outcome: speedtest.Unmeasured}
			// probe_match controls new work, not reuse of an IP's shared result.
			if p := probes[a.IP]; p != nil && p.done {
				r = p.result
			}
			m := c.metadata[a.IP]
			valid := validRTT(r)
			score := m.multiplier
			if valid {
				score = float64(r.RTT) / float64(time.Millisecond) * m.multiplier
			}
			if math.IsInf(score, 1) && valid {
				// A large finite multiplier can overflow the product; it must
				// not make an actually measured address look unmeasured.
				score = math.MaxFloat64
			} else if math.IsNaN(score) || math.IsInf(score, 0) {
				valid = false
				score = m.multiplier
			}
			ranked = append(ranked, rankedAddress{candidate: c, address: a, metadata: m, result: r, valid: valid, score: score})
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if a.valid != b.valid {
			return a.valid
		}
		if a.score != b.score {
			return a.score < b.score
		}
		if a.candidate.source != b.candidate.source {
			return a.candidate.source < b.candidate.source
		}
		if a.address.Index != b.address.Index {
			return a.address.Index < b.address.Index
		}
		return a.address.IP.Less(b.address.IP)
	})
	if len(ranked) > 0 {
		best := ranked[0]
		anchor := best.candidate.value
		kind := "weighted"
		if best.valid {
			kind = "rtt"
		} else {
			s.metrics.fallbacks.WithLabelValues(weightedReason(ranked)).Inc()
		}
		if (qCtx.ClientOpt() != nil && qCtx.ClientOpt().Do()) || !anchor.Rewritable {
			return response.Replay(anchor, now), kind, nil
		}
		selected := make([]response.SelectedAddress, 0, s.args.MaxNum)
		seen := make(map[netip.Addr]bool)
		for _, a := range ranked {
			if seen[a.address.IP] || !a.candidate.value.Rewritable || !response.Compatible(anchor, a.candidate.value) {
				continue
			}
			if best.valid && (!a.valid || !slices.Equal(a.metadata.labels, best.metadata.labels) || a.score-best.score > *s.args.ThresholdMS) {
				continue
			}
			selected = append(selected, response.SelectedAddress{Candidate: a.candidate.value, Address: a.address})
			seen[a.address.IP] = true
			if len(selected) == s.args.MaxNum {
				break
			}
		}
		if len(selected) > 0 {
			snapshot, err := response.Rebuild(anchor, selected, now)
			if err == nil {
				return snapshot, kind, nil
			}
			return query_context.ResponseSnapshot{}, "error", fmt.Errorf("speedcheck: rebuild: %w", err)
		}
		return response.Replay(anchor, now), kind, nil
	}
	for _, c := range states {
		if c != nil && c.value.Negative {
			s.metrics.fallbacks.WithLabelValues("negative").Inc()
			return response.Replay(c.value, now), "negative", nil
		}
	}
	// Non-address queries remain whole messages; no synthetic response is made.
	q := qCtx.QQuestion()
	if q.Qclass != dns.ClassINET || (q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) {
		for _, c := range states {
			if c != nil {
				return response.Replay(c.value, now), "passthrough", nil
			}
		}
	}
	s.metrics.fallbacks.WithLabelValues("no_candidates").Inc()
	return query_context.ResponseSnapshot{}, "error", ErrNoCandidates
}

func weightedReason(ranked []rankedAddress) string {
	failed, unmeasured := false, false
	for _, a := range ranked {
		if a.result.Outcome == speedtest.Failed {
			failed = true
		} else {
			unmeasured = true
		}
	}
	if failed && unmeasured {
		return "mixed"
	}
	if failed {
		return "all_probes_failed"
	}
	return "unmeasured"
}
