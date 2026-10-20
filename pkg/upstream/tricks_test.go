/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package upstream

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
)

// countHandler counts received queries and forwards them to vServer.
type countHandler struct {
	n *atomic.Int64
}

func (h countHandler) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	h.n.Add(1)
	(&vServer{}).ServeDNS(w, q)
}

func Test_UDP_repeat(t *testing.T) {
	var n atomic.Int64
	addr, shutdownServer := newUDPTestServer(t, countHandler{n: &n})
	defer shutdownServer()

	u, err := NewUpstream("udp://"+addr, Opt{Repeat: 2})
	if err != nil {
		t.Fatal(err)
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	payload, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	if _, err := u.ExchangeContext(ctx, payload); err != nil {
		t.Fatal(err)
	}

	// The query was sent 1 + Repeat times.
	// (Check before the 1s resend ticker kicks in.)
	time.Sleep(time.Millisecond * 200)
	if got := n.Load(); got < 3 {
		t.Fatalf("expected at least 3 copies of the query, got %d", got)
	}
}

// ednsHandler replies with a response carrying EDNS0, i.e. exactly one
// additional record.
type ednsHandler struct{}

func (ednsHandler) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	r := new(dns.Msg)
	r.SetReply(q)
	r.SetEdns0(4096, false)
	w.WriteMsg(r)
}

func Test_UDP_use_tricks(t *testing.T) {
	exchangeOnce := func(t *testing.T, u Upstream, timeout time.Duration) error {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		payload, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, err = u.ExchangeContext(ctx, payload)
		return err
	}

	t.Run("accept_edns_resp", func(t *testing.T) {
		addr, shutdownServer := newUDPTestServer(t, ednsHandler{})
		defer shutdownServer()
		u, err := NewUpstream("udp://"+addr, Opt{UseTricks: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := exchangeOnce(t, u, time.Second*3); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("drop_spoofed_resp", func(t *testing.T) {
		// vServer replies without EDNS0. Such responses are shorter than
		// 32 bytes and have no additional record. They are dropped.
		addr, shutdownServer := newUDPTestServer(t, &vServer{})
		defer shutdownServer()
		u, err := NewUpstream("udp://"+addr, Opt{UseTricks: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := exchangeOnce(t, u, time.Second); err == nil {
			t.Fatal("expected the response to be dropped")
		}
	})
}

func Test_TCP_use_tricks(t *testing.T) {
	for _, pipeline := range [...]bool{false, true} {
		t.Run(fmt.Sprintf("pipeline_%v", pipeline), func(t *testing.T) {
			addr, shutdownServer := newTCPTestServer(t, &vServer{})
			defer shutdownServer()
			u, err := NewUpstream(
				"tcp://"+addr,
				Opt{UseTricks: true, EnablePipeline: pipeline},
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := testUpstream(u); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func Test_TCP_use_tricks_long_pipeline(t *testing.T) {
	addr, shutdown := newTCPTestServer(t, &vServer{})
	defer shutdown()
	u, err := NewUpstream("tcp://"+addr, Opt{UseTricks: true, EnablePipeline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			q := new(dns.Msg)
			q.SetQuestion(fmt.Sprintf("query-%d.long-domain-for-tcp-trick.example.", i), dns.TypeA)
			payload, err := q.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			r, err := u.ExchangeContext(ctx, payload)
			if err != nil {
				t.Error(err)
				return
			}
			defer pool.ReleaseBuf(r)
			resp := new(dns.Msg)
			if err := resp.Unpack(*r); err != nil {
				t.Error(err)
				return
			}
			if len(resp.Question) != 1 || resp.Question[0] != q.Question[0] {
				t.Errorf("response question mismatch: %v", resp.Question)
			}
		})
	}
	wg.Wait()
}
