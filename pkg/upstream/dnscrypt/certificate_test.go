package dnscrypt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

const testProvider = "2.dnscrypt-cert.example.test."

func testCertificate(t *testing.T, serial uint32, private ed25519.PrivateKey, extension []byte) []byte {
	t.Helper()
	rc, err := dnscrypt.GenerateResolverConfig("example.test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	rc.ESVersion = dnscrypt.XChacha20Poly1305
	cert, err := rc.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	cert.Serial = serial
	data, err := cert.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, extension...)
	copy(data[8:certificateSignedOffset], ed25519.Sign(private, data[certificateSignedOffset:]))
	return data
}

func testCertificateStamp(key ed25519.PublicKey) string {
	return (&dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
		ServerAddrStr: "127.0.0.1:443",
		ServerPk:      key,
		ProviderName:  testProvider,
	}).String()
}

func testCertificateResponse(tcp bool, response func(*dns.Msg) *dns.Msg) func(context.Context) (net.Conn, error) {
	return func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if tcp {
				if q, _, err := dnsutils.ReadMsgFromTCP(server); err == nil {
					_, _ = dnsutils.WriteMsgToTCP(server, response(q))
				}
			} else if q, _, err := dnsutils.ReadMsgFromUDP(server, 1232); err == nil {
				_, _ = dnsutils.WriteMsgToUDP(server, response(q))
			}
		}()
		return client, nil
	}
}

func testCertificateTXT(q *dns.Msg, cert []byte) *dns.TXT {
	// Split even small certificates across TXT strings to exercise assembly.
	parts := make([]string, 0, 2)
	for _, chunk := range [][]byte{cert[:64], cert[64:]} {
		var s strings.Builder
		for _, b := range chunk {
			fmt.Fprintf(&s, "\\%03d", b)
		}
		parts = append(parts, s.String())
	}
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: parts,
	}
}

func TestCertificateTCPFallback(t *testing.T) {
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := testCertificate(t, 7, private, nil)
	t.Run("UDP timeout", func(t *testing.T) {
		testCertificateFallback(t, key, cert, func(ctx context.Context) (net.Conn, error) {
			<-ctx.Done()
			return nil, context.Cause(ctx)
		})
	})
	t.Run("UDP truncation", func(t *testing.T) {
		testCertificateFallback(t, key, cert, testCertificateResponse(false, func(q *dns.Msg) *dns.Msg {
			r := new(dns.Msg).SetReply(q)
			r.Truncated = true
			r.Question = nil
			return r
		}))
	})
}

func testCertificateFallback(t *testing.T, key ed25519.PublicKey, cert []byte, udpDial func(context.Context) (net.Conn, error)) {
	t.Helper()
	u, err := NewUpstream(testCertificateStamp(key), Opt{
		UDPDialContext: udpDial,
		TCPDialContext: testCertificateResponse(true, func(q *dns.Msg) *dns.Msg {
			r := new(dns.Msg).SetReply(q)
			r.Answer = []dns.RR{testCertificateTXT(q, cert)}
			return r
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	ri, err := u.fetchResolverInfo(ctx)
	if err != nil || ri.ResolverCert.Serial != 7 {
		t.Fatalf("TCP certificate: %v, error: %v", ri, err)
	}
}

func TestCertificateSignedExtensions(t *testing.T) {
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extended := testCertificate(t, 2, private, []byte{0x99, 0x00, 0xdd})
	tampered := testCertificate(t, 3, private, []byte{0x99, 0x00, 0xdd})
	tampered[len(tampered)-1] ^= 1
	// A certificate signed over the original base fields cannot authenticate
	// any bytes appended later, even if the extension is unknown.
	unsignedExtension := append(testCertificate(t, 4, private, nil), 0xff)
	u, err := NewUpstream(testCertificateStamp(key), Opt{
		UDPDialContext: testCertificateResponse(false, func(q *dns.Msg) *dns.Msg {
			r := new(dns.Msg).SetReply(q)
			for _, cert := range [][]byte{extended, tampered, unsignedExtension} {
				r.Answer = append(r.Answer, testCertificateTXT(q, cert))
			}
			return r
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ri, err := u.fetchResolverInfo(context.Background())
	if err != nil || ri.ResolverCert.Serial != 2 {
		t.Fatalf("expected the only certificate with a valid extended signature: %v, error: %v", ri, err)
	}
}

func TestCertificateRefreshBeforeExpiry(t *testing.T) {
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old, next := testCertificate(t, 1, private, nil), testCertificate(t, 2, private, nil)
	var calls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	u, err := NewUpstream(testCertificateStamp(key), Opt{
		UDPDialContext: func(ctx context.Context) (net.Conn, error) {
			cert := old
			if calls.Add(1) == 2 {
				close(refreshStarted)
				select {
				case <-releaseRefresh:
					cert = next
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			}
			return testCertificateResponse(false, func(q *dns.Msg) *dns.Msg {
				r := new(dns.Msg).SetReply(q)
				r.Answer = []dns.RR{testCertificateTXT(q, cert)}
				return r
			})(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	initial, err := u.fetchResolverInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	u.refreshAt = time.Now().Add(-time.Second)
	u.mu.Unlock()
	for range 8 {
		if current, err := u.fetchResolverInfo(ctx); err != nil || current != initial {
			t.Fatalf("valid old certificate unavailable during refresh, error: %v", err)
		}
	}
	select {
	case <-refreshStarted:
	case <-ctx.Done():
		t.Fatal("background refresh did not start")
	}
	close(releaseRefresh)
	for ctx.Err() == nil {
		current, err := u.fetchResolverInfo(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if current.ResolverCert.Serial == 2 {
			if got := calls.Load(); got != 2 {
				t.Fatalf("expected one initial fetch and one refresh, got %d", got)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("new certificate was not published")
}

func TestCloseCancelsCertificateFetch(t *testing.T) {
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	u, err := NewUpstream(testCertificateStamp(key), Opt{
		UDPDialContext: func(ctx context.Context) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, context.Cause(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	q := new(dns.Msg).SetQuestion("example.test.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := u.ExchangeContext(context.Background(), wire)
		result <- err
	}()
	<-started
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("active exchange ended with %v, want net.ErrClosed", err)
	}
	if _, err := u.ExchangeContext(context.Background(), wire); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed upstream accepted an exchange: %v", err)
	}
}
