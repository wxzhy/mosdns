package https_record

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/response"
	"github.com/miekg/dns"
)

var errClosed = errors.New("https_record: plugin is closed")

type lookupResult struct {
	target string
	ip     ipData
	ech    echData
	err    error
	forECH bool
}

func (p *Record) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if !p.begin() {
		return errClosed
	}
	defer p.active.Done()
	if qCtx.R() == nil {
		return nil
	}
	q := qCtx.Q()
	if q == nil || q.Response {
		return errors.New("https_record: expected a query")
	}
	if q.Opcode != dns.OpcodeQuery {
		return nil
	}
	if len(q.Question) != 1 {
		return errors.New("https_record: expected a query with one question")
	}
	question := q.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeHTTPS && question.Qtype != dns.TypeSVCB) {
		return nil
	}
	if opt := qCtx.ClientOpt(); opt != nil && opt.Do() {
		return nil
	}
	if opt := q.IsEdns0(); opt != nil && opt.Do() {
		return nil
	}
	candidate, err := response.AnalyzeBindings(q, qCtx.SnapshotResponse(), p.now())
	if err != nil {
		return err
	}
	if !candidate.Rewritable {
		return nil
	}
	edits := make(map[int]response.BindingEdit)
	for _, record := range candidate.Records {
		if record.Priority == 0 {
			continue
		}
		edits[record.Index] = response.BindingEdit{RemoveHints: p.removeHint, RemoveH3: p.removeH3, RemoveALPN: p.removeALPN}
	}
	cleaned, changed, err := response.RewriteBindings(candidate, edits, p.now())
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if changed {
		if until := cleaned.ValidUntil; !until.IsZero() && !p.now().Before(until) {
			return errors.New("https_record: source response expired before cleanup")
		}
		qCtx.CommitResponse(cleaned)
	}
	// A dedicated source may contain this plugin itself. The source's complete
	// ordinary routing remains available, but optional queries cannot recurse.
	if !p.addECH || ctx.Value(subqueryKey{}) != nil {
		return nil
	}

	eligible := make(map[int]bool)
	ipBounds := make(map[int]ipData)
	jobRecords := make(map[string][]int)
	for _, record := range candidate.Records {
		if record.Priority == 0 || hasECH(candidate.Snapshot.Response.Answer[record.Index]) || !p.allowedName(candidate, record.Target) {
			continue
		}
		if len(record.Hints) > 0 {
			if p.allowedIPs(record.Hints) {
				eligible[record.Index] = true
			}
		} else if !p.ipGate {
			eligible[record.Index] = true
		} else if p.subquery {
			jobRecords[record.Target] = append(jobRecords[record.Target], record.Index)
		}
	}
	synthesisTarget := ""
	if candidate.NODATA && p.subquery && p.allowedName(candidate, candidate.Terminal) {
		// Preserve original-name routing for the NODATA fallback; the source
		// itself resolves and validates its complete A/CNAME chain.
		synthesisTarget = dns.CanonicalName(candidate.Question.Name)
		if _, ok := jobRecords[synthesisTarget]; !ok {
			jobRecords[synthesisTarget] = nil
		}
	}
	if len(eligible) == 0 && len(jobRecords) == 0 {
		return nil
	}

	budget := p.timeout
	if deadline, ok := ctx.Deadline(); ok {
		left := time.Until(deadline)
		reserve := min(25*time.Millisecond, left/2)
		budget = min(budget, left-reserve)
	}
	if budget <= 0 {
		return nil
	}
	optional, cancel := context.WithTimeout(ctx, budget)
	stopClose := context.AfterFunc(p.life, cancel)
	defer stopClose()
	defer cancel()
	// Fork before any source worker starts. Sources and queued jobs read only
	// this immutable input, never a context still owned by the calling chain.
	parentFork := qCtx.Copy()

	results := make(chan lookupResult, len(jobRecords)+1)
	jobs := make(chan string, len(jobRecords))
	for target := range jobRecords {
		jobs <- target
	}
	close(jobs)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		value, lookupErr := p.resolveECH(optional, parentFork)
		results <- lookupResult{ech: value, err: lookupErr, forECH: true}
	}()
	for i := 0; i < min(maxConcurrentIPLookups, len(jobRecords)); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				if optional.Err() != nil {
					results <- lookupResult{target: target, err: context.Cause(optional)}
					continue
				}
				value, lookupErr := p.resolveIP(optional, parentFork, target)
				results <- lookupResult{target: target, ip: value, err: lookupErr}
			}
		}()
	}
	var ech echData
	var synthesis ipData
	left := len(jobRecords) + 1
	pendingIPs := len(jobRecords)
	for left > 0 {
		select {
		case result := <-results:
			if optional.Err() != nil {
				cancel()
				left = 0
				continue
			}
			left--
			if result.forECH {
				if result.err != nil || len(result.ech.value) == 0 {
					cancel()
					left = 0
					continue
				}
				ech = result.ech
				continue
			}
			pendingIPs--
			if result.err == nil && p.allowedIPs(result.ip.ips) {
				for _, index := range jobRecords[result.target] {
					eligible[index] = true
					ipBounds[index] = result.ip
				}
				// An explicit main alias must not borrow IP authorization from a
				// different A endpoint. With no main alias, retain original-name
				// routing, including ordinary CNAMEs in the complete A source.
				if result.target == synthesisTarget && (candidate.ChainKey == "" || result.ip.terminal == candidate.Terminal) {
					synthesis = result.ip
				}
			}
			if pendingIPs == 0 && len(eligible) == 0 && len(synthesis.ips) == 0 {
				cancel()
				left = 0
			}
		case <-optional.Done():
			cancel()
			left = 0
		}
	}
	// No source goroutine may retain a request after Exec or instance Close.
	// Sources are normal executables and must respect inherited cancellation.
	cancel()
	workers.Wait()
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if p.life.Err() != nil {
		return errClosed
	}
	// Optional lookups consumed part of the source lease even when they failed
	// or the first cleanup had nothing to change. Replay the cleanup at the
	// final time before taking any success/failure exit, preserving its original
	// absolute deadline and aging every retained wire TTL.
	now := p.now()
	agedSnapshot, _, ageErr := response.RewriteBindings(candidate, edits, now)
	if ageErr != nil {
		return ageErr
	}
	qCtx.CommitResponse(agedSnapshot)
	if len(ech.value) == 0 {
		return nil
	}
	if !ech.validUntil.IsZero() && !now.Before(ech.validUntil) {
		return nil
	}
	if candidate.NODATA {
		if len(synthesis.ips) == 0 {
			return nil
		}
		if !synthesis.validUntil.IsZero() && !now.Before(synthesis.validUntil) {
			return nil
		}
		ttl := min(uint32(maxECHCacheTTL/time.Second), ech.ttl, synthesis.ttl)
		until := earlier(ech.validUntil, synthesis.validUntil)
		if !until.IsZero() {
			ttl = min(ttl, remaining(until, now))
		}
		snapshot, synthErr := response.SynthesizeBinding(candidate, ech.value, ttl, until, now)
		if synthErr != nil {
			return nil
		}
		if until := snapshot.ValidUntil; !until.IsZero() && !p.now().Before(until) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		qCtx.CommitResponse(snapshot)
		return nil
	}
	for index := range eligible {
		edit := edits[index]
		ttl, until := ech.ttl, ech.validUntil
		if bounds, ok := ipBounds[index]; ok {
			if !bounds.validUntil.IsZero() && !now.Before(bounds.validUntil) {
				continue
			}
			ttl, until = min(ttl, bounds.ttl), earlier(until, bounds.validUntil)
		}
		edit.ECH, edit.ECHTTL, edit.ECHValidUntil = ech.value, &ttl, until
		edits[index] = edit
	}
	snapshot, injected, rewriteErr := response.RewriteBindings(candidate, edits, now)
	if rewriteErr != nil {
		return nil
	}
	if until := snapshot.ValidUntil; !until.IsZero() && !p.now().Before(until) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if injected {
		qCtx.CommitResponse(snapshot)
	}
	return nil
}

func (p *Record) allowedName(candidate *response.BindingCandidate, target string) bool {
	if !p.matchName {
		return true
	}
	names := append([]string{candidate.Question.Name, candidate.Terminal, target}, strings.Split(candidate.ChainKey, "\x00")...)
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := p.nameMatch.Match(name); ok {
			return true
		}
	}
	return false
}
