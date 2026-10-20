package query_context

import (
	"testing"

	"github.com/miekg/dns"
)

func TestProbeStatusFollowsOnlyItsResponse(t *testing.T) {
	q := NewContext(new(dns.Msg).SetQuestion("example.test.", dns.TypeA))
	q.SetMark(41)
	s := ResponseSnapshot{Response: new(dns.Msg).SetReply(q.Q()), ProbeStatus: ProbeFailed}
	q.CommitResponse(s)
	for _, c := range []*Context{q, q.Copy()} {
		if c.SnapshotResponse().Clone().ProbeStatus != ProbeFailed {
			t.Fatal("response commit or copy lost probe evidence")
		}
	}
	branch := q.Copy()
	branch.SetResponse(new(dns.Msg).SetReply(branch.Q()))
	if branch.SnapshotResponse().ProbeStatus != ProbeUnknown || q.SnapshotResponse().ProbeStatus != ProbeFailed {
		t.Fatal("new response retained old evidence or modified parent")
	}
	q.CommitResponse(branch.SnapshotResponse())
	if q.SnapshotResponse().ProbeStatus != ProbeUnknown || !q.HasMark(41) {
		t.Fatal("response-only commit retained old probe evidence or lost marks")
	}
	q.CommitResponse(s)
	q.CommitResponse(ResponseSnapshot{ProbeStatus: ProbeFailed})
	if q.SnapshotResponse().ProbeStatus != ProbeUnknown {
		t.Fatal("empty response retained probe evidence")
	}
	q.CommitResponse(s)
	q.SetResponse(nil)
	d := NewContext(new(dns.Msg).SetQuestion("other.test.", dns.TypeAAAA))
	d.CommitResponse(s)
	q.CopyTo(d)
	if d.SnapshotResponse().ProbeStatus != ProbeUnknown {
		t.Fatal("CopyTo retained destination probe evidence")
	}
}
