package query_context

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func metadataTestContext() *Context {
	q := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
	q.SetEdns0(1232, true)
	c := NewContext(q)
	c.SetResponse(new(dns.Msg).SetReply(c.Q()))
	c.SetUpstreamSelected("https://doh.example/dns-query", "DoH", "remote", "forward_remote")
	c.AddRuleHit("main", []string{"qname example.org"}, "$forward_remote")
	c.SetCacheState(true, true, 300, 5)
	// Populate every field independently to exercise ownership of the metadata.
	c.FromHosts = true
	return c
}

func TestLocalSourceSettersClearPreviousUpstreamAndCache(t *testing.T) {
	for _, source := range []string{"hosts", "arbitrary"} {
		t.Run(source, func(t *testing.T) {
			c := metadataTestContext()
			response := c.R()
			receivedAt := c.ResponseReceivedAt()
			if source == "hosts" {
				c.FromArbitrary = true
				c.SetFromHosts()
			} else {
				c.SetFromArbitrary()
			}
			if c.UpstreamSelected != nil || c.CacheState != (CacheLog{}) || c.FromHosts != (source == "hosts") || c.FromArbitrary != (source == "arbitrary") {
				t.Fatal("local source retained previous upstream/cache attribution")
			}
			if c.R() != response || c.ResponseReceivedAt() != receivedAt || len(c.RuleHits) != 1 {
				t.Fatal("local source attribution changed response lifetime or rule trace")
			}
		})
	}
}

func TestMetadataCopiesOwnUpstreamAndNestedRuleMatches(t *testing.T) {
	source := metadataTestContext()
	callerMatches := []string{"caller-owned"}
	source.AddRuleHit("main", callerMatches, "accept")
	callerMatches[0] = "changed by caller"
	if source.RuleHits[1].Matches[0] != "caller-owned" {
		t.Fatal("AddRuleHit retained caller's match slice")
	}
	for name, copyContext := range map[string]func() *Context{
		"Copy":   source.Copy,
		"CopyTo": func() *Context { return source.CopyTo(new(Context)) },
		"CopyMetadataFrom": func() *Context {
			d := NewContext(source.Q().Copy())
			d.CopyMetadataFrom(source)
			return d
		},
	} {
		t.Run(name, func(t *testing.T) {
			copied := copyContext()
			copied.UpstreamSelected.Addr = "copy-only"
			copied.RuleHits[0].Matches[0] = "copy-only"
			copied.CacheState.TTL = 1
			copied.SetFromArbitrary()
			if source.UpstreamSelected.Addr != "https://doh.example/dns-query" || source.RuleHits[0].Matches[0] != "qname example.org" || source.CacheState.TTL != 300 || !source.FromHosts || source.FromArbitrary {
				t.Fatal("context copy aliased source metadata")
			}
		})
	}
	empty := NewContext(source.Q().Copy())
	empty.CopyTo(source)
	if source.UpstreamSelected != nil || source.RuleHits != nil || source.CacheState != (CacheLog{}) || source.FromHosts || source.FromArbitrary {
		t.Fatal("CopyTo retained previous destination metadata")
	}
}

func TestResponseSnapshotOwnsSelectedMetadataAndRetainsResponseState(t *testing.T) {
	source := metadataTestContext()
	source.validUntil = time.Now().Add(time.Minute)
	source.probeStatus = ProbeSucceeded
	source.Q().Question[0].Name = "branch.example."
	parent := NewContext(new(dns.Msg).SetQuestion("example.org.", dns.TypeA))
	parent.SetMark(7)
	key := RegKey()
	parent.StoreValue(key, "parent")
	source.SetMark(8)
	source.StoreValue(key, "branch")
	snapshot := source.SnapshotResponse()
	source.UpstreamSelected.Addr = "changed source"
	source.RuleHits[0].Matches[0] = "changed source"
	clone := snapshot.Clone()
	clone.UpstreamSelected.Addr = "changed clone"
	clone.RuleHits[0].Matches[0] = "changed clone"
	parent.CommitResponse(snapshot)
	snapshot.UpstreamSelected.Addr = "changed snapshot"
	snapshot.RuleHits[0].Matches[0] = "changed snapshot"
	if parent.UpstreamSelected.Addr != "https://doh.example/dns-query" || parent.RuleHits[0].Matches[0] != "qname example.org" || !parent.CacheState.LazyHit || !parent.FromHosts || parent.FromArbitrary {
		t.Fatal("snapshot or commit aliased/lost winner metadata")
	}
	if parent.QQuestion().Name != "example.org." || !parent.HasMark(7) || parent.HasMark(8) {
		t.Fatal("metadata commit changed parent query or marks")
	}
	if value, _ := parent.GetValue(key); value != "parent" {
		t.Fatal("metadata commit changed parent plugin state")
	}
	if parent.ResponseReceivedAt() != source.ResponseReceivedAt() || parent.SnapshotResponse().ValidUntil != source.validUntil || parent.SnapshotResponse().ProbeStatus != ProbeSucceeded || parent.RespOpt() != nil {
		t.Fatal("metadata commit changed response lifetime/probe/EDNS behavior")
	}
	parent.CommitResponse(ResponseSnapshot{})
	if parent.UpstreamSelected != nil || parent.RuleHits != nil || parent.CacheState != (CacheLog{}) || parent.FromHosts || parent.FromArbitrary {
		t.Fatal("empty snapshot retained metadata from the previous source")
	}
}
