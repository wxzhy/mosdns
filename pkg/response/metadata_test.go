package response

import (
	"net/netip"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func withTestMetadata(s query_context.ResponseSnapshot, tag string) query_context.ResponseSnapshot {
	s.UpstreamSelected = &query_context.UpstreamLog{Addr: "tls://" + tag, Protocol: "DoT", Tag: tag, Plugin: "forward_" + tag}
	s.RuleHits = []query_context.RuleHit{{Sequence: tag, Matches: []string{"qname example.test"}, Exec: "$forward_" + tag}}
	s.CacheState = query_context.CacheLog{Hit: true, LazyHit: true, TTL: 60, RemainingTTL: 5}
	s.FromArbitrary = true
	s.ProbeStatus = query_context.ProbeSucceeded
	return s
}

func withTestBranchState(q *dns.Msg, snapshot query_context.ResponseSnapshot, mark, key uint32, value string) query_context.ResponseSnapshot {
	branch := query_context.NewContext(q.Copy())
	branch.CommitResponse(snapshot)
	branch.SetMark(mark)
	branch.StoreValue(key, value)
	return branch.SnapshotResponse()
}

func assertRebuiltMetadata(t *testing.T, got *query_context.ResponseSnapshot, source query_context.ResponseSnapshot) {
	t.Helper()
	if got.UpstreamSelected == nil || got.UpstreamSelected.Tag != "anchor" || len(got.RuleHits) != 1 || got.RuleHits[0].Sequence != "anchor" || got.RuleHits[0].Matches[0] != "qname example.test" || got.CacheState != source.CacheState || !got.FromArbitrary || got.FromHosts {
		t.Fatalf("rebuilt response lost or merged anchor statistics: %+v", got)
	}
	if got.ProbeStatus != query_context.ProbeUnknown {
		t.Fatal("copying metadata changed existing synthesized probe status")
	}
	got.UpstreamSelected.Tag = "mutated output"
	got.RuleHits[0].Matches[0] = "mutated output"
	if source.UpstreamSelected.Tag != "anchor" || source.RuleHits[0].Matches[0] != "qname example.test" {
		t.Fatal("rebuilt statistics aliased source metadata")
	}
}

func TestRebuiltAddressResponsesRetainOnlyAnchorMetadata(t *testing.T) {
	for _, operation := range []string{"select", "replace", "static"} {
		t.Run(operation, func(t *testing.T) {
			q := testQuery("example.test.", dns.TypeA)
			s := withTestMetadata(testSnapshot(t, q, "example.test. 60 IN A 192.0.2.1"), "anchor")
			key := query_context.RegKey()
			s = withTestBranchState(q, s, 91, key, "anchor")
			anchor := testCandidate(t, q, s, testNow)
			now := testNow.Add(time.Second)
			var got query_context.ResponseSnapshot
			var err error
			switch operation {
			case "select":
				otherState := withTestBranchState(q, withTestMetadata(testSnapshot(t, q, "example.test. 60 IN A 192.0.2.2"), "other"), 92, key, "other")
				other := testCandidate(t, q, otherState, testNow)
				got, err = Rebuild(anchor, []SelectedAddress{{Candidate: other, Address: other.Addresses[0]}}, now)
			case "replace":
				got, err = ReplaceAddresses(anchor, []netip.Addr{netip.MustParseAddr("192.0.2.3")}, now)
			case "static":
				got, err = StaticAddresses(anchor, []netip.Addr{netip.MustParseAddr("192.0.2.4")}, 30, now)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertRebuiltMetadata(t, &got, anchor.Snapshot)
			parent := query_context.NewContext(q.Copy())
			parent.SetMark(7)
			parent.StoreValue(key, "parent")
			parent.CommitResponse(got, query_context.CommitMerge)
			if !parent.HasMark(7) || !parent.HasMark(91) || parent.HasMark(92) {
				t.Fatal("rebuilt response lost anchor marks or merged another source")
			}
			if value, ok := parent.GetValue(key); !ok || value != "anchor" {
				t.Fatalf("rebuilt response lost anchor KV: %v", value)
			}
		})
	}
}

func TestSynthesizedBindingsRetainAnchorMetadata(t *testing.T) {
	q := testQuery("example.test.", dns.TypeHTTPS)
	s := withTestMetadata(testSnapshot(t, q), "anchor")
	key := query_context.RegKey()
	s = withTestBranchState(q, s, 37, key, "binding")
	candidate, err := AnalyzeBindings(q, s, testNow)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SynthesizeBinding(candidate, []byte{1, 2}, 30, testNow.Add(30*time.Second), testNow)
	if err != nil {
		t.Fatal(err)
	}
	assertRebuiltMetadata(t, &got, candidate.Snapshot)
	parent := query_context.NewContext(q.Copy())
	parent.CommitResponse(got, query_context.CommitMerge)
	if !parent.HasMark(37) {
		t.Fatal("synthesized binding lost anchor mark")
	}
	if value, _ := parent.GetValue(key); value != "binding" {
		t.Fatalf("synthesized binding lost anchor KV: %v", value)
	}
}
