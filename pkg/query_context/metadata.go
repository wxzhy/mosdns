package query_context

import "slices"

type UpstreamLog struct {
	Addr     string
	Protocol string
	Tag      string
	Plugin   string
}

type RuleHit struct {
	Sequence string
	Matches  []string
	Exec     string
}

type CacheLog struct {
	Hit          bool
	LazyHit      bool
	TTL          int
	RemainingTTL int
}

func (ctx *Context) AddRuleHit(seq string, matches []string, exec string) {
	ctx.RuleHits = append(ctx.RuleHits, RuleHit{Sequence: seq, Matches: slices.Clone(matches), Exec: exec})
}

func (ctx *Context) SetUpstreamSelected(addr, protocol, tag, plugin string) {
	ctx.UpstreamSelected = &UpstreamLog{Addr: addr, Protocol: protocol, Tag: tag, Plugin: plugin}
}

func (ctx *Context) SetCacheState(hit, lazyHit bool, ttl, remainingTTL int) {
	ctx.CacheState = CacheLog{Hit: hit, LazyHit: lazyHit, TTL: ttl, RemainingTTL: remainingTTL}
}

func (ctx *Context) SetFromHosts() {
	ctx.FromHosts, ctx.FromArbitrary = true, false
	ctx.UpstreamSelected = nil
	ctx.CacheState = CacheLog{}
}

func (ctx *Context) SetFromArbitrary() {
	ctx.FromArbitrary, ctx.FromHosts = true, false
	ctx.UpstreamSelected = nil
	ctx.CacheState = CacheLog{}
}

// CopyMetadataFrom copies only execution details. It deliberately retains the
// destination's query, response lifetime, EDNS state, marks and plugin values.
// Response selection should use SnapshotResponse and CommitResponse instead.
func (ctx *Context) CopyMetadataFrom(src *Context) {
	if src == nil {
		return
	}
	ctx.UpstreamSelected = cloneUpstreamLog(src.UpstreamSelected)
	ctx.RuleHits = cloneRuleHits(src.RuleHits)
	ctx.CacheState = src.CacheState
	ctx.FromHosts = src.FromHosts
	ctx.FromArbitrary = src.FromArbitrary
}

// CopyMetadataFrom retains this snapshot's DNS response and lifetime while
// replacing its statistics with independently owned details from the source.
func (s *ResponseSnapshot) CopyMetadataFrom(src ResponseSnapshot) {
	s.UpstreamSelected = cloneUpstreamLog(src.UpstreamSelected)
	s.RuleHits = cloneRuleHits(src.RuleHits)
	s.CacheState = src.CacheState
	s.FromHosts = src.FromHosts
	s.FromArbitrary = src.FromArbitrary
}

func cloneUpstreamLog(src *UpstreamLog) *UpstreamLog {
	if src == nil {
		return nil
	}
	u := *src
	return &u
}

func cloneRuleHits(src []RuleHit) []RuleHit {
	dst := slices.Clone(src)
	for i := range dst {
		dst[i].Matches = slices.Clone(src[i].Matches)
	}
	return dst
}
