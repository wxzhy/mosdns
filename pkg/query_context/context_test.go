package query_context

import (
	"testing"

	"github.com/miekg/dns"
)

func TestResponseSnapshotCommitsOnlyResponse(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	q.SetEdns0(1232, true)
	parent := NewContext(q)
	parent.SetMark(7)
	key := RegKey()
	parent.StoreValue(key, "parent")
	branch := parent.Copy()
	branch.Q().Question[0].Name = "branch.example."
	branch.DeleteMark(7)
	branch.StoreValue(key, "branch")
	r := new(dns.Msg)
	r.SetReply(q)
	rr, _ := dns.NewRR("example.org. 60 IN A 192.0.2.1")
	r.Answer = []dns.RR{rr}
	r.SetEdns0(1400, true)
	branch.SetResponse(r)
	branch.RespOpt().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1}}}
	snapshot := branch.SnapshotResponse()
	branch.R().Answer[0].Header().Ttl = 1
	parent.CommitResponse(snapshot)
	snapshot.Response.Answer[0].Header().Ttl = 2
	snapshot.UpstreamOpt.SetUDPSize(512)
	snapshot.RespOpt.Option[0].(*dns.EDNS0_LOCAL).Data[0] = 9
	if parent.R().Answer[0].Header().Ttl != 60 || parent.UpstreamOpt().UDPSize() != 1400 || parent.RespOpt().Option[0].(*dns.EDNS0_LOCAL).Data[0] != 1 {
		t.Fatal("response snapshot was aliased")
	}
	if parent.QQuestion().Name != "example.org." || !parent.HasMark(7) {
		t.Fatal("branch overwrote query or marks")
	}
	if v, _ := parent.GetValue(key); v != "parent" {
		t.Fatal("branch overwrote plugin state")
	}
	if parent.R().IsEdns0() != nil || !parent.QOpt().Do() || !parent.RespOpt().Do() {
		t.Fatal("OPT ownership or DO propagation is broken")
	}
}

func TestCopyToClearsResponseAndClientWithoutEDNS(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	a := NewContext(q)
	bq := q.Copy()
	bq.SetEdns0(1232, true)
	b := NewContext(bq)
	b.SetResponse(new(dns.Msg).SetReply(bq))
	a.CopyTo(b)
	if b.R() != nil || b.RespOpt() != nil {
		t.Fatal("CopyTo retained previous destination response")
	}
	a.CommitResponse(ResponseSnapshot{Response: new(dns.Msg).SetReply(q), RespOpt: newOpt()})
	if a.RespOpt() != nil {
		t.Fatal("EDNS response added for client without EDNS")
	}
}

func TestCommitMissingOptionsClearsStaleResponseState(t *testing.T) {
	q := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
	q.SetEdns0(1232, true)
	c := NewContext(q)
	c.RespOpt().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1}}}
	c.CommitResponse(ResponseSnapshot{})
	if c.R() != nil || c.UpstreamOpt() != nil || c.RespOpt() == nil || !c.RespOpt().Do() || len(c.RespOpt().Option) != 0 {
		t.Fatal("commit retained stale response state or lost required DO")
	}
}
