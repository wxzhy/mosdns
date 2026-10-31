package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type metadataHandler struct {
	seen chan QueryMeta
}

func (h metadataHandler) Handle(_ context.Context, q *dns.Msg, meta QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
	h.seen <- meta
	payload, _ := pack(new(dns.Msg).SetReply(q))
	return payload
}

func checkTransportMeta(t *testing.T, seen <-chan QueryMeta, protocol string) QueryMeta {
	t.Helper()
	select {
	case meta := <-seen:
		if meta.Protocol != protocol || !meta.ClientAddr.IsValid() || meta.FromUDP != (protocol == "UDP") {
			t.Fatalf("%s query metadata = %+v", protocol, meta)
		}
		return meta
	case <-time.After(3 * time.Second):
		t.Fatal("transport did not execute its DNS handler")
		return QueryMeta{}
	}
}

func checkServerStopped(t *testing.T, stopped <-chan error) {
	t.Helper()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Error("transport listener did not stop")
	}
}

func TestTransportQueryMetadata(t *testing.T) {
	t.Run("UDP", func(t *testing.T) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		h := metadataHandler{seen: make(chan QueryMeta, 1)}
		stopped := make(chan error, 1)
		go func() { stopped <- ServeUDP(conn, h, UDPServerOpts{}) }()
		t.Cleanup(func() { _ = conn.Close(); checkServerStopped(t, stopped) })
		q := new(dns.Msg).SetQuestion("udp.example.", dns.TypeA)
		response, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, conn.LocalAddr().String())
		if err != nil || response.Id != q.Id || !response.Response {
			t.Fatalf("UDP response = %v, %v", response, err)
		}
		checkTransportMeta(t, h.seen, "UDP")
	})
	for _, useTLS := range []bool{false, true} {
		name := "TCP"
		if useTLS {
			name = "DoT without SNI"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			protocol, network := "TCP", "tcp"
			if useTLS {
				cert := httptest.NewTLSServer(http.NotFoundHandler())
				t.Cleanup(cert.Close)
				listener = tls.NewListener(listener, &tls.Config{Certificates: cert.TLS.Certificates})
				protocol, network = "DoT", "tcp-tls"
			}
			h := metadataHandler{seen: make(chan QueryMeta, 1)}
			stopped := make(chan error, 1)
			go func() { stopped <- ServeTCP(listener, h, TCPServerOpts{IdleTimeout: time.Second}) }()
			t.Cleanup(func() { _ = listener.Close(); checkServerStopped(t, stopped) })
			q := new(dns.Msg).SetQuestion("tcp.example.", dns.TypeA)
			client := &dns.Client{Net: network, Timeout: time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
			response, _, err := client.Exchange(q, listener.Addr().String())
			if err != nil || response.Id != q.Id || !response.Response {
				t.Fatalf("TCP/DoT response = %v, %v", response, err)
			}
			meta := checkTransportMeta(t, h.seen, protocol)
			if useTLS && meta.ServerName != "" {
				t.Fatalf("test must exercise TLS without SNI, got %q", meta.ServerName)
			}
		})
	}
	t.Run("DoH", func(t *testing.T) {
		h := metadataHandler{seen: make(chan QueryMeta, 1)}
		q := new(dns.Msg).SetQuestion("https.example.", dns.TypeA)
		wire, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "https://dns.example/dns-query", bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
		req.RemoteAddr = "192.0.2.17:12345"
		w := httptest.NewRecorder()
		NewHttpHandler(h, HttpHandlerOpts{}).ServeHTTP(w, req)
		response := new(dns.Msg)
		if w.Code != http.StatusOK || response.Unpack(w.Body.Bytes()) != nil || response.Id != q.Id || !response.Response {
			t.Fatalf("DoH response = %d %v", w.Code, response)
		}
		meta := checkTransportMeta(t, h.seen, "DoH")
		if meta.UrlPath != "/dns-query" {
			t.Fatalf("DoH URL metadata changed: %+v", meta)
		}
	})
	t.Run("DoQ", func(t *testing.T) {
		cert := httptest.NewTLSServer(http.NotFoundHandler())
		t.Cleanup(cert.Close)
		listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: cert.TLS.Certificates, NextProtos: []string{"doq"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		h := metadataHandler{seen: make(chan QueryMeta, 1)}
		stopped := make(chan error, 1)
		go func() { stopped <- ServeDoQ(listener, h, DoQServerOpts{IdleTimeout: time.Second}) }()
		t.Cleanup(func() { _ = listener.Close(); checkServerStopped(t, stopped) })
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseWithError(0, "test complete")
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.CancelRead(0)
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		q := new(dns.Msg).SetQuestion("quic.example.", dns.TypeA)
		if _, err := dnsutils.WriteMsgToTCP(stream, q); err != nil {
			t.Fatal(err)
		}
		_ = stream.Close()
		response, _, err := dnsutils.ReadMsgFromTCP(stream)
		if err != nil || response.Id != q.Id || !response.Response {
			t.Fatalf("DoQ response = %v, %v", response, err)
		}
		checkTransportMeta(t, h.seen, "DoQ")
	})
}

func TestDoHBadRequestPreservesHistoricalBody(t *testing.T) {
	h := NewHttpHandler(metadataHandler{seen: make(chan QueryMeta, 1)}, HttpHandlerOpts{})
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{1, 2, 3}))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || w.Body.String() != "Bad Request" {
		t.Fatalf("historical invalid DoH response changed: %d %q", w.Code, w.Body.String())
	}
}
