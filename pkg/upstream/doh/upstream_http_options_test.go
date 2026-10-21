package doh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
)

func TestHTTPOptionsValidation(t *testing.T) {
	for _, options := range []Options{
		{HTTPMethod: "PUT"},
		{HTTPMethod: "PATCH"},
		{HTTPMethod: "GET POST"},
		{HTTPHost: "resolver.example\r\nX-Injected: value"},
		{HTTPHost: "resolver.example/path"},
	} {
		if _, err := NewUpstreamWithOptions("https://front.example/dns-query", nil, nil, options); err == nil {
			t.Errorf("accepted invalid options: %+v", options)
		}
	}
	for _, method := range []string{"", "GET", "POST", "post"} {
		u, err := NewUpstreamWithOptions("https://front.example/dns-query", nil, nil, Options{HTTPHost: "resolver.example:8443", HTTPMethod: method})
		if err != nil {
			t.Fatalf("method %q: %v", method, err)
		}
		if u.reqTemplate.Host != "resolver.example:8443" || u.reqTemplate.URL.Host != "front.example" {
			t.Fatalf("HTTP Host changed endpoint: %+v", u.reqTemplate)
		}
	}
}

func TestPOSTBodySurvivesCallerCancellation(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		name := map[bool]string{false: "ordinary", true: "selector"}[inherited]
		t.Run(name, func(t *testing.T) {
			query := testQuery(t)
			want := bytes.Clone(query)
			want[0], want[1] = 0, 0
			started, release := make(chan struct{}), make(chan struct{})
			transportDone := make(chan struct{})
			type bodyResult struct {
				body, replay []byte
				err          error
			}
			observed := make(chan bodyResult, 1)
			rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				defer close(transportDone)
				if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/dns-message" || req.ContentLength != int64(len(want)) {
					t.Errorf("invalid POST framing: %s, headers=%v, length=%d", req.Method, req.Header, req.ContentLength)
				}
				go func() {
					<-release
					body, err := io.ReadAll(req.Body)
					_ = req.Body.Close()
					replay, replayErr := req.GetBody()
					if replayErr != nil {
						observed <- bodyResult{err: replayErr}
						return
					}
					replayBody, replayErr := io.ReadAll(replay)
					_ = replay.Close()
					observed <- bodyResult{body: body, replay: replayBody, err: errors.Join(err, replayErr)}
				}()
				close(started)
				if inherited {
					<-req.Context().Done()
					return nil, req.Context().Err()
				}
				<-release
				return nil, errors.New("late transport failure")
			})
			u, err := NewUpstreamWithOptions("https://front.example/dns-query", rt, nil, Options{HTTPMethod: "POST"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if inherited {
				ctx = query_policy.WithInheritedCancellation(ctx)
			}
			result := make(chan error, 1)
			go func() {
				_, err := u.ExchangeContext(ctx, query)
				result <- err
			}()
			<-started
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Errorf("canceled query returned %v", err)
			}
			// Returning from ExchangeContext lets its caller recycle the source.
			// A transport may nevertheless read and close the POST body later.
			for i := range query {
				query[i] = 0xff
			}
			for range 32 {
				buffer := pool.GetBuf(len(query))
				for i := range *buffer {
					(*buffer)[i] = 0xaa
				}
				pool.ReleaseBuf(buffer)
			}
			close(release)
			got := <-observed
			<-transportDone
			if got.err != nil || !bytes.Equal(got.body, want) || !bytes.Equal(got.replay, want) {
				t.Fatalf("POST body recycled after cancellation: body=%x replay=%x err=%v", got.body, got.replay, got.err)
			}
		})
	}
}
