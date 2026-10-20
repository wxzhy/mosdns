package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
)

func handshakeFingerprint(t *testing.T, clientConfig, serverConfig *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	cert, _, err := generateTestCert("test")
	if err != nil {
		t.Fatal(err)
	}
	serverConfig = serverConfig.Clone()
	serverConfig.Certificates = []tls.Certificate{cert}
	l, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.(*tls.Conn).Handshake()
	}()
	defer func() { <-done }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	fp, err := getFingerprint("chrome")
	if err != nil {
		t.Fatal(err)
	}
	uconn, err := utlsClientHandshake(ctx, c, clientConfig, fp, nil)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer uconn.Close()
	return (&utlsConn{uconn}).ConnectionState(), nil
}

func TestUTLSConfiguredALPN(t *testing.T) {
	s, err := handshakeFingerprint(t,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}},
		&tls.Config{NextProtos: []string{"dot"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if s.NegotiatedProtocol != "dot" {
		t.Fatalf("negotiated protocol = %q, want dot", s.NegotiatedProtocol)
	}
	if s.CipherSuite == 0 {
		t.Fatal("adapted connection state dropped the negotiated cipher suite")
	}
}

func TestUTLSVerifyConnection(t *testing.T) {
	rejected := errors.New("rejected by configured verifier")
	_, err := handshakeFingerprint(t,
		&tls.Config{InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
			if s.CipherSuite == 0 || len(s.PeerCertificates) == 0 {
				t.Error("incomplete verifier connection state")
			}
			return rejected
		}}, &tls.Config{},
	)
	if !errors.Is(err, rejected) {
		t.Fatalf("handshake error = %v, want configured verifier rejection", err)
	}
}

func TestUTLSConfiguredVersions(t *testing.T) {
	t.Run("minimum", func(t *testing.T) {
		_, err := handshakeFingerprint(t,
			&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
			&tls.Config{MaxVersion: tls.VersionTLS12},
		)
		if err == nil {
			t.Fatal("TLS 1.2 server bypassed the configured TLS 1.3 minimum")
		}
	})
	t.Run("maximum", func(t *testing.T) {
		s, err := handshakeFingerprint(t,
			&tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, &tls.Config{},
		)
		if err != nil {
			t.Fatal(err)
		}
		if s.Version != tls.VersionTLS12 {
			t.Fatalf("negotiated version = %#x, want TLS 1.2", s.Version)
		}
	})
}

func TestDoHUTLSDefaultServerName(t *testing.T) {
	cert, roots, err := generateTestCert("test")
	if err != nil {
		t.Fatal(err)
	}
	serverURL := newDoHTestServer(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	dialAddr := strings.TrimPrefix(serverURL, "https://")
	_, port, err := net.SplitHostPort(dialAddr)
	if err != nil {
		t.Fatal(err)
	}
	u, err := NewUpstream("https://test:"+port+"/dns-query", Opt{
		DialAddr: dialAddr, TLSConfig: &tls.Config{RootCAs: roots}, UTLSFingerprint: "chrome",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

type echResponseUpstream struct {
	response func(*dns.Msg) *dns.Msg
	closed   int
}

func (u *echResponseUpstream) ExchangeContext(_ context.Context, wire []byte) (*[]byte, error) {
	q := new(dns.Msg)
	if err := q.Unpack(wire); err != nil {
		return nil, err
	}
	b, err := u.response(q).Pack()
	if err != nil {
		return nil, err
	}
	buf := pool.GetBuf(len(b))
	copy(*buf, b)
	return buf, nil
}

func (u *echResponseUpstream) Close() error { u.closed++; return nil }

func TestECHDNSAliasesAndCase(t *testing.T) {
	want := []byte{1, 2, 3}
	u := &echResponseUpstream{response: func(q *dns.Msg) *dns.Msg {
		if q.IsEdns0() == nil || q.IsEdns0().UDPSize() != 1232 {
			t.Error("ECH query must advertise EDNS0 size 1232")
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: "TeSt.ExAmPlE.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 50}, Target: "alias.example."},
			&dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: "ALIAS.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60}, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: want}}}},
		}
		return r
	}}
	r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.u = u
	got, ttl, err := r.query(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || ttl != 50 {
		t.Fatalf("ECH query = %v, ttl %d; want %v, ttl 50", got, ttl, want)
	}
}

func TestVerifyPeerCertByNameMalformedCertificate(t *testing.T) {
	verify := newVerifyPeerCertByNameFunc([]string{"test"}, nil)
	if err := verify([][]byte{{1, 2, 3}}, nil); err == nil {
		t.Fatal("malformed certificate accepted")
	}
}

func TestECHResolverRejectsEmptyConfig(t *testing.T) {
	if _, err := newECHConfigResolver("", nil); err == nil {
		t.Fatal("empty static ECH config must be rejected")
	}
	r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.u = &echResponseUpstream{response: func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
			Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{}},
		}}}
		return m
	}}
	if got := r.getConfigList(context.Background()); len(got) == 0 {
		t.Fatal("missing ECH config must fail closed instead of returning an empty list")
	}
}

func TestECHResolverClose(t *testing.T) {
	r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	u := &echResponseUpstream{}
	r.u = u
	for i := 0; i < 2; i++ {
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if u.closed != 1 {
		t.Fatalf("lookup upstream closed %d times, want once", u.closed)
	}
	if got := r.getConfigList(context.Background()); !bytes.Equal(got, invalidECHConfigList) {
		t.Fatalf("closed resolver returned %v", got)
	}
}
