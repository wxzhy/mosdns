package fastforward

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/miekg/dns"
)

func TestDoHHTTPOptionsPreserveSNIAndDNSBody(t *testing.T) {
	for _, fingerprint := range []string{"", "chrome"} {
		for _, method := range []string{"", http.MethodPost} {
			name := fingerprint + "/" + method
			t.Run(name, func(t *testing.T) {
				type observation struct {
					method, host, sni, token, contentType string
					protocol, dnsQueryCount               int
					id                                    uint16
				}
				observed := make(chan observation, 1)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					var wire []byte
					var err error
					if req.Method == http.MethodPost {
						wire, err = io.ReadAll(req.Body)
					} else {
						wire, err = base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
					}
					query := new(dns.Msg)
					if err == nil {
						err = query.Unpack(wire)
					}
					if err != nil {
						t.Errorf("invalid DoH DNS payload: %v", err)
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					observed <- observation{method: req.Method, host: req.Host, sni: req.TLS.ServerName, token: req.URL.Query().Get("token"), contentType: req.Header.Get("Content-Type"), protocol: req.ProtoMajor, dnsQueryCount: len(req.URL.Query()["dns"]), id: query.Id}
					response := new(dns.Msg).SetReply(query)
					rr, _ := dns.NewRR("example.org. 60 IN A 192.0.2.1")
					response.Answer = []dns.RR{rr}
					wire, err = response.Pack()
					if err != nil {
						t.Error(err)
						return
					}
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(wire)
				}))
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				forward, err := NewForward(&Args{Upstreams: []UpstreamConfig{{
					Addr: "https://front.example.invalid/dns-query?token=kept", DialAddr: server.Listener.Addr().String(),
					InsecureSkipVerify: true, Fingerprint: fingerprint,
					HTTPHost: "resolver.example.invalid", HTTPMethod: method,
				}}}, Opts{})
				if err != nil {
					t.Fatal(err)
				}
				defer forward.Close()
				query := new(dns.Msg).SetQuestion("example.org.", dns.TypeA)
				query.Id = 123
				queryContext := query_context.NewContext(query)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := forward.Exec(query_policy.WithInheritedCancellation(ctx), queryContext); err != nil {
					t.Fatal(err)
				}
				response := queryContext.R()
				if response == nil || response.Id != 123 || len(response.Answer) != 1 || query.Id != 123 {
					t.Fatalf("invalid forwarded response: %v; input=%v", response, query)
				}
				got := <-observed
				wantMethod, wantDNSQueries := http.MethodGet, 1
				if method == http.MethodPost {
					wantMethod, wantDNSQueries = http.MethodPost, 0
				}
				if got.method != wantMethod || got.host != "resolver.example.invalid" || got.sni != "front.example.invalid" || got.token != "kept" || got.id != 0 || got.protocol != 2 || got.dnsQueryCount != wantDNSQueries {
					t.Fatalf("HTTP options changed endpoint/TLS or payload: %+v", got)
				}
				if method == http.MethodPost && got.contentType != "application/dns-message" {
					t.Fatalf("invalid POST Content-Type: %q", got.contentType)
				}
			})
		}
	}
}

func TestForwardRejectsInvalidHTTPOptions(t *testing.T) {
	for _, config := range []UpstreamConfig{
		{Addr: "https://resolver.example/dns-query", HTTPMethod: "PUT"},
		{Addr: "https://resolver.example/dns-query", HTTPHost: "bad\r\nhost"},
	} {
		if forward, err := NewForward(&Args{Upstreams: []UpstreamConfig{config}}, Opts{}); err == nil {
			_ = forward.Close()
			t.Fatalf("accepted invalid HTTP options: %+v", config)
		}
	}
}
