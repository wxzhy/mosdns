package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/miekg/dns"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type reusableTransport struct {
	closed atomic.Bool
	fn     roundTripFunc
}

func (r *reusableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.closed.Load() {
		return nil, errors.New("shared transport closed")
	}
	return r.fn(req)
}

func (r *reusableTransport) Close() error { r.closed.Store(true); return nil }

func testQuery(t *testing.T) []byte {
	t.Helper()
	q := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
	q.Id = 123
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestControlledHTTPAgeAndClientID(t *testing.T) {
	for _, age := range []string{"20", "100"} {
		t.Run(age, func(t *testing.T) {
			u, err := NewUpstream("https://test.invalid/dns-query", roundTripFunc(func(req *http.Request) (*http.Response, error) {
				wire, _ := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
				q := new(dns.Msg)
				if err := q.Unpack(wire); err != nil {
					t.Fatal(err)
				}
				if q.Id != 0 {
					t.Error("DoH request ID should be zero")
				}
				r := new(dns.Msg).SetReply(q)
				rr, _ := dns.NewRR("example.org. 60 IN A 192.0.2.1")
				r.Answer = []dns.RR{rr}
				r.SetEdns0(1232, true)
				b, _ := r.Pack()
				return &http.Response{StatusCode: 200, Header: http.Header{"Age": []string{age}}, Body: io.NopCloser(bytes.NewReader(b))}, nil
			}), nil)
			if err != nil {
				t.Fatal(err)
			}
			b, err := u.ExchangeContext(query_policy.WithInheritedCancellation(context.Background()), testQuery(t))
			if err != nil {
				t.Fatal(err)
			}
			defer pool.ReleaseBuf(b)
			r := new(dns.Msg)
			if err := r.Unpack(*b); err != nil {
				t.Fatal(err)
			}
			wantTTL := uint32(40)
			if age == "100" {
				wantTTL = 0
			}
			if r.Id != 123 || r.Answer[0].Header().Ttl != wantTTL || !r.IsEdns0().Do() {
				t.Fatalf("unexpected response: %v", r)
			}
		})
	}
}

func TestControlledCancellationAndClientReuse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, stopped := make(chan struct{}), make(chan struct{})
		var calls int
		rt := &reusableTransport{fn: func(req *http.Request) (*http.Response, error) {
			calls++
			if calls > 1 {
				wire, _ := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
				q := new(dns.Msg)
				if err := q.Unpack(wire); err != nil {
					return nil, err
				}
				wire, _ = new(dns.Msg).SetReply(q).Pack()
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(wire))}, nil
			}
			close(started)
			defer close(stopped)
			<-req.Context().Done()
			return nil, req.Context().Err()
		}}
		u, _ := NewUpstream("https://test.invalid/dns-query", rt, nil)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := u.ExchangeContext(query_policy.WithInheritedCancellation(ctx), testQuery(t))
			result <- err
		}()
		<-started
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
		<-stopped
		// A second request must still work through the same shared client.
		b, err := u.ExchangeContext(query_policy.WithInheritedCancellation(context.Background()), testQuery(t))
		if err != nil {
			t.Fatal(err)
		}
		pool.ReleaseBuf(b)
	})
}

func TestRejectOversizedDoHBody(t *testing.T) {
	u, _ := NewUpstream("https://test.invalid/dns-query", roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", dns.MaxMsgSize+1)))}, nil
	}), nil)
	if _, err := u.ExchangeContext(query_policy.WithInheritedCancellation(context.Background()), testQuery(t)); err == nil {
		t.Fatal("accepted oversized DNS body")
	}
}
