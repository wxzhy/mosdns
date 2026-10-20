package doh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"testing/synctest"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/miekg/dns"
)

type closingTransport struct {
	roundTripFunc
	closed bool
}

func (t *closingTransport) Close() error { t.closed = true; return nil }

type idleClosingTransport struct {
	roundTripFunc
	closed bool
}

func (t *idleClosingTransport) CloseIdleConnections() { t.closed = true }

func TestDoHCloseReleasesTransport(t *testing.T) {
	t.Run("close", func(t *testing.T) {
		rt := new(closingTransport)
		u, err := NewUpstream("https://test.invalid/dns-query", rt, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := u.Close(); err != nil || !rt.closed {
			t.Fatalf("transport was not closed: %v", err)
		}
	})
	t.Run("idle connections", func(t *testing.T) {
		rt := new(idleClosingTransport)
		u, err := NewUpstream("https://test.invalid/dns-query", rt, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := u.Close(); err != nil || !rt.closed {
			t.Fatalf("idle connections were not closed: %v", err)
		}
	})
}

func TestLegacyDoHTimeoutReturns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u, err := NewUpstream("https://test.invalid/dns-query", roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}), nil)
		if err != nil {
			t.Fatal(err)
		}
		// A timed-out request must always deliver its error to a live caller.
		// The old send-vs-request-timeout select could silently discard it.
		for i := 0; i < 32; i++ {
			if _, err := u.ExchangeContext(context.Background(), testQuery(t)); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("request %d: got %v", i, err)
			}
		}
	})
}

func TestDoHValidationAndAgeForEveryPolicy(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		for _, invalid := range []string{"", "query", "id", "wire"} {
			name := map[bool]string{false: "ordinary", true: "selector"}[inherited] + "/" + invalid
			t.Run(name, func(t *testing.T) {
				q := new(dns.Msg)
				if err := q.Unpack(testQuery(t)); err != nil {
					t.Fatal(err)
				}
				q.Id = 0
				r := new(dns.Msg).SetReply(q)
				rr, _ := dns.NewRR("example.org. 60 IN A 192.0.2.1")
				r.Answer = []dns.RR{rr}
				r.SetEdns0(1232, true)
				switch invalid {
				case "query":
					r.Response = false
				case "id":
					r.Id = 42
				}
				wire, err := r.Pack()
				if err != nil {
					t.Fatal(err)
				}
				if invalid == "wire" {
					wire = wire[:len(wire)-1]
				}
				u, err := NewUpstream("https://test.invalid/dns-query?token=kept&dns=old", roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.Query().Get("token") != "kept" || len(req.URL.Query()["dns"]) != 1 || req.URL.Query().Get("dns") == "old" {
						t.Errorf("lost endpoint query parameters: %s", req.URL.RawQuery)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Age": []string{"20"}}, Body: io.NopCloser(bytes.NewReader(wire))}, nil
				}), nil)
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if inherited {
					ctx = query_policy.WithInheritedCancellation(ctx)
				}
				payload, err := u.ExchangeContext(ctx, testQuery(t))
				if payload != nil {
					defer pool.ReleaseBuf(payload)
				}
				if invalid != "" {
					if err == nil {
						t.Fatal("accepted invalid response")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := r.Unpack(*payload); err != nil {
					t.Fatal(err)
				}
				if r.Id != 123 || r.Answer[0].Header().Ttl != 40 || !r.IsEdns0().Do() {
					t.Fatalf("unexpected response: %v", r)
				}
			})
		}
	}
}
