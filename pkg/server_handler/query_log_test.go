package server_handler

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func queryLogEntry(_ context.Context, c *query_context.Context) error {
	c.SetUpstreamSelected("tls://192.0.2.53", "DoT", "remote", "forward_remote")
	c.AddRuleHit("main_sequence", []string{"qname $remote"}, "$forward_remote")
	r := new(dns.Msg).SetReply(c.Q())
	rr, err := dns.NewRR(c.QQuestion().Name + " 60 IN A 192.0.2.7")
	if err != nil {
		return err
	}
	r.Answer = []dns.RR{rr}
	c.SetResponse(r)
	return nil
}

func TestQueryLogsExactlyOnceForSuccessErrorAndEmptyReply(t *testing.T) {
	for _, level := range []zapcore.Level{zap.InfoLevel, zap.DebugLevel} {
		for _, behavior := range []string{"success", "error", "empty"} {
			t.Run(level.String()+"/"+behavior, func(t *testing.T) {
				core, logs := observer.New(level)
				entry := sequence.ExecutableFunc(func(ctx context.Context, c *query_context.Context) error {
					if behavior == "empty" {
						return nil
					}
					if err := queryLogEntry(ctx, c); err != nil {
						return err
					}
					if behavior == "error" {
						return errors.New("specific upstream failure")
					}
					return nil
				})
				h := NewEntryHandler(EntryHandlerOpts{Entry: entry, Logger: zap.New(core)})
				q := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
				q.SetEdns0(1232, true)
				meta := server.QueryMeta{ClientAddr: netip.MustParseAddr("192.0.2.17"), FromUDP: true, Protocol: "UDP"}
				payload := h.Handle(context.Background(), q, meta, pool.PackBuffer)
				if payload == nil {
					t.Fatal("missing DNS payload")
				}
				defer pool.ReleaseBuf(payload)
				response := new(dns.Msg)
				if err := response.Unpack(*payload); err != nil {
					t.Fatal(err)
				}
				wantRcode := dns.RcodeSuccess
				if behavior == "error" {
					wantRcode = dns.RcodeServerFailure
				} else if behavior == "empty" {
					wantRcode = dns.RcodeRefused
				}
				if !response.Response || response.Id != q.Id || len(response.Question) != 1 || response.Question[0] != q.Question[0] || response.Rcode != wantRcode || !response.RecursionAvailable || response.IsEdns0() == nil || !response.IsEdns0().Do() {
					t.Fatalf("logging changed wire response: %v", response)
				}
				queries := logs.FilterMessage("query log").All()
				if len(queries) != 1 || queries[0].Level != level {
					t.Fatalf("query records = %+v, want exactly one at %s", queries, level)
				}
				fields := queries[0].ContextMap()
				if fields["qname"] != "example.org." || fields["qtype"] != "A" || fields["protocol"] != "UDP" || fields["client"] != "192.0.2.17" || fields["rcode"] != wantRcode {
					t.Fatalf("query log missed final wire fields: %+v", fields)
				}
				_, hasRules := fields["rule_hits"]
				if hasRules != (level == zap.DebugLevel && behavior != "empty") {
					t.Fatalf("rule details do not follow instance level: %+v", fields)
				}
				if behavior == "error" && len(logs.FilterMessage("entry err").All()) != 1 {
					t.Fatal("query logging suppressed the existing execution error log")
				}
			})
		}
	}
}

func TestQueryLogLevelIsIndependentAcrossInstances(t *testing.T) {
	var wg sync.WaitGroup
	for _, level := range []zapcore.Level{zap.InfoLevel, zap.DebugLevel, zap.WarnLevel} {
		core, logs := observer.New(level)
		h := NewEntryHandler(EntryHandlerOpts{Entry: sequence.ExecutableFunc(queryLogEntry), Logger: zap.New(core)})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 30 {
				q := new(dns.Msg).SetQuestion(fmt.Sprintf("q-%d.example.org.", i), dns.TypeA)
				payload := h.Handle(context.Background(), q, server.QueryMeta{Protocol: "DoT"}, pool.PackBuffer)
				if payload == nil {
					t.Error("missing wire response")
					return
				}
				pool.ReleaseBuf(payload)
			}
			queries := logs.FilterMessage("query log").All()
			wantCount := 30
			if level == zap.WarnLevel {
				wantCount = 0
			}
			if len(queries) != wantCount {
				t.Errorf("%s query count = %d, want %d", level, len(queries), wantCount)
			}
			for _, query := range queries {
				_, rules := query.ContextMap()["rule_hits"]
				if query.Level != level || rules != (level == zap.DebugLevel) {
					t.Errorf("%s logger inherited another instance's level: %+v", level, query)
				}
			}
		}()
	}
	wg.Wait()
}

func TestFailedPackingAndInvalidInputDoNotEmitCompletedQueryLog(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	h := NewEntryHandler(EntryHandlerOpts{Entry: sequence.ExecutableFunc(queryLogEntry), Logger: zap.New(core)})
	q := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
	payload := h.Handle(context.Background(), q, server.QueryMeta{}, func(*dns.Msg) (*[]byte, error) { return nil, errors.New("packing failed") })
	if payload != nil || logs.FilterMessage("query log").Len() != 0 || logs.FilterMessage("internal err: failed to pack resp msg").Len() != 1 {
		t.Fatal("failed packing emitted a completed query or suppressed the packing error")
	}
	invalid := new(dns.Msg)
	if h.Handle(context.Background(), invalid, server.QueryMeta{}, pool.PackBuffer) != nil || logs.FilterMessage("query log").Len() != 0 {
		t.Fatal("invalid query emitted a completion record")
	}
}
