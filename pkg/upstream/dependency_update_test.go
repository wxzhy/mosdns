package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_policy"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream/doh"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream/transport"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// These tests exercise the project's wire adapters against actual local QUIC
// peers. They own the sockets explicitly; NewUpstream's resource assembly is
// covered separately, without coupling this dependency regression to it.
func TestDependencyUpdateQUICAdapters(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(*testing.T, *dependencyQUICPeer, *tls.Config, *tls.Config) dependencyQUICExchanger
	}{
		{"doq", startDependencyDoQ},
		{"http3", startDependencyHTTP3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverTLS, clientTLS := dependencyQUICCertificates(t)
			peer := &dependencyQUICPeer{started: make(chan struct{}), canceled: make(chan struct{})}
			u := tc.start(t, peer, serverTLS, clientTLS)
			dependencyQUICExchange(t, u, "before-cancel.dependency.invalid.", 0x1234)

			ctx, cancel := context.WithCancel(query_policy.WithInheritedCancellation(context.Background()))
			defer cancel()
			query := new(dns.Msg).SetQuestion("cancel.dependency.invalid.", dns.TypeA)
			query.Id = 0x5678
			wire, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(wire)
			result := make(chan error, 1)
			exchanged := make(chan struct{})
			go func() {
				defer close(exchanged)
				resp, err := u.ExchangeContext(ctx, wire)
				if resp != nil {
					pool.ReleaseBuf(resp)
				}
				result <- err
			}()
			t.Cleanup(func() {
				cancel()
				dependencyQUICWait(t, exchanged, "canceled exchange shutdown")
			})
			dependencyQUICWait(t, peer.started, "request reaching the peer")
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled exchange returned %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("exchange did not return after cancellation")
			}
			dependencyQUICWait(t, peer.canceled, "peer observing stream cancellation")
			if !bytes.Equal(wire, original) {
				t.Fatal("canceled exchange modified the query buffer")
			}
			// Canceling one query must not close the shared transport or prevent
			// another request from completing on the same upstream instance.
			dependencyQUICExchange(t, u, "after-cancel.dependency.invalid.", 0x9abc)
		})
	}
}

type dependencyQUICPeer struct {
	started, canceled       chan struct{}
	startOnce, canceledOnce sync.Once
}

type dependencyQUICExchanger interface {
	ExchangeContext(context.Context, []byte) (*[]byte, error)
}

func (p *dependencyQUICPeer) answer(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if q.Id != 0 || q.Response || len(q.Question) != 1 {
		return nil, fmt.Errorf("invalid wire query: %v", q)
	}
	if q.Question[0].Name == "cancel.dependency.invalid." {
		p.startOnce.Do(func() { close(p.started) })
		<-ctx.Done()
		p.canceledOnce.Do(func() { close(p.canceled) })
		return nil, ctx.Err()
	}
	r := new(dns.Msg).SetReply(q)
	r.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.IPv4(192, 0, 2, 20),
	}}
	return r, nil
}

func dependencyQUICCertificates(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	const name = "dependency.invalid"
	cert, err := utils.GenerateCertificate(name)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		&tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS13}
}

func startDependencyDoQ(t *testing.T, peer *dependencyQUICPeer, serverTLS, clientTLS *tls.Config) dependencyQUICExchanger {
	t.Helper()
	serverTLS.NextProtos, clientTLS.NextProtos = []string{"doq"}, []string{"doq"}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{MaxIncomingUniStreams: -1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	accepted := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.CloseWithError(0, "test finished")
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer stream.Close()
						defer stream.CancelRead(0)
						q, _, err := dnsutils.ReadMsgFromTCP(stream)
						if err != nil {
							t.Errorf("read DoQ query: %v", err)
							return
						}
						r, err := peer.answer(stream.Context(), q)
						if err != nil {
							if !errors.Is(err, context.Canceled) {
								t.Errorf("DoQ peer: %v", err)
							}
							return
						}
						if _, err := dnsutils.WriteMsgToTCP(stream, r); err != nil {
							t.Errorf("write DoQ response: %v", err)
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		dependencyQUICWait(t, accepted, "DoQ listener shutdown")
		workers.Wait()
	})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client := &quic.Transport{Conn: packet}
	t.Cleanup(func() {
		_ = client.Close()
		_ = packet.Close()
	})
	u := transport.NewPipelineTransport(transport.PipelineOpts{
		DialContext: func(ctx context.Context) (transport.DnsConn, error) {
			conn, err := client.Dial(ctx, listener.Addr(), clientTLS, &quic.Config{})
			if err != nil {
				return nil, err
			}
			return transport.NewQuicDnsConn(conn), nil
		},
	})
	t.Cleanup(func() { _ = u.Close() })
	return u
}

func startDependencyHTTP3(t *testing.T, peer *dependencyQUICPeer, serverTLS, clientTLS *tls.Config) dependencyQUICExchanger {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{TLSConfig: serverTLS, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.ProtoMajor != 3 || req.TLS == nil || req.TLS.NegotiatedProtocol != http3.NextProtoH3 {
			t.Error("request did not use HTTP/3 over TLS")
			http.Error(w, "wrong transport", http.StatusBadRequest)
			return
		}
		q, err := server.ReadMsgFromReq(req)
		if err != nil {
			t.Errorf("read HTTP/3 DNS query: %v", err)
			return
		}
		r, err := peer.answer(req.Context(), q)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Errorf("HTTP/3 peer: %v", err)
			}
			return
		}
		wire, err := r.Pack()
		if err != nil {
			t.Errorf("pack HTTP/3 DNS response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		if _, err := w.Write(wire); err != nil {
			t.Errorf("write HTTP/3 DNS response: %v", err)
		}
	})}
	served := make(chan struct{})
	go func() {
		defer close(served)
		if err := srv.Serve(packet); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("HTTP/3 server: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = packet.Close()
		dependencyQUICWait(t, served, "HTTP/3 server shutdown")
	})
	client := &http3.Transport{TLSClientConfig: clientTLS}
	t.Cleanup(func() { _ = client.Close() })
	u, err := doh.NewUpstream("https://"+packet.LocalAddr().String()+"/dns-query", client, nil)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func dependencyQUICExchange(t *testing.T, u dependencyQUICExchanger, name string, id uint16) {
	t.Helper()
	q := new(dns.Msg).SetQuestion(name, dns.TypeA)
	q.Id = id
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(wire)
	ctx, cancel := context.WithTimeout(query_policy.WithInheritedCancellation(context.Background()), 5*time.Second)
	defer cancel()
	raw, err := u.ExchangeContext(ctx, wire)
	if raw != nil {
		defer pool.ReleaseBuf(raw)
	}
	if err != nil {
		t.Fatal(err)
	}
	if raw == nil {
		t.Fatal("exchange returned no response")
	}
	r := new(dns.Msg)
	if err := r.Unpack(*raw); err != nil {
		t.Fatal(err)
	}
	if !r.Response || r.Id != id || r.Rcode != dns.RcodeSuccess || len(r.Question) != 1 || r.Question[0] != q.Question[0] || len(r.Answer) != 1 {
		t.Fatalf("response failed DNS round trip: %v", r)
	}
	a, ok := r.Answer[0].(*dns.A)
	if !ok || a.Hdr.Name != name || !a.A.Equal(net.IPv4(192, 0, 2, 20)) || a.Hdr.Ttl != 30 {
		t.Fatalf("unexpected address response: %v", r)
	}
	if !bytes.Equal(wire, original) {
		t.Fatal("exchange modified the query buffer")
	}
}

func dependencyQUICWait(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}
