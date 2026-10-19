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
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"golang.org/x/crypto/cryptobyte"
)

// generateECHConfig generates an ECHConfig with the given public name.
// It returns the serialized ECHConfigList (with the length prefix), the
// individual ECHConfig (without the list prefix), and the marshalled
// private key. This mirrors xray-core's "xray tls ech" key generation.
func generateECHConfig(publicName string) (echConfigList, echConfig, privateKey []byte, err error) {
	priv := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, nil, err
	}
	privKey, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, nil, nil, err
	}
	pub := privKey.PublicKey().Bytes()

	var b cryptobyte.Builder
	b.AddUint16(0xfe0d) // version, encrypted client hello
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // config id
		b.AddUint16(hpke.DHKEM(ecdh.X25519()).ID())
		b.AddUint16(uint16(len(pub)))
		b.AddBytes(pub)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, kdf := range []hpke.KDF{hpke.HKDFSHA256(), hpke.HKDFSHA384(), hpke.HKDFSHA512()} {
				for _, aead := range []hpke.AEAD{hpke.AES128GCM(), hpke.AES256GCM(), hpke.ChaCha20Poly1305()} {
					b.AddUint16(kdf.ID())
					b.AddUint16(aead.ID())
				}
			}
		})
		b.AddUint8(0) // max name length
		b.AddUint8(uint8(len(publicName)))
		b.AddBytes([]byte(publicName))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {}) // empty extensions
	})

	echConfig, err = b.Bytes()
	if err != nil {
		return nil, nil, nil, err
	}

	var lb cryptobyte.Builder
	lb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(echConfig)
	})
	echConfigList, err = lb.Bytes()
	if err != nil {
		return nil, nil, nil, err
	}
	return echConfigList, echConfig, priv, nil
}

// newECHDoTTestServer starts a DoT test server that accepts ECH.
func newECHDoTTestServer(t testing.TB, handler dns.Handler, echConfig, privateKey []byte) (addr string, shutdownFunc func()) {
	t.Helper()
	serverName := "test"
	cert, err := utils.GenerateCertificate(serverName)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:      echConfig,
			PrivateKey:  privateKey,
			SendAsRetry: true,
		}},
	}
	tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	doTAddr := tlsListener.Addr().String()
	doTServer := dns.Server{
		Net:           "tcp-tls",
		Listener:      tlsListener,
		TLSConfig:     tlsConfig,
		Handler:       handler,
		MaxTCPQueries: -1,
	}
	go doTServer.ActivateAndServe()
	return doTAddr, func() {
		doTServer.Shutdown()
	}
}

// newDoHTestServer starts a DoH test server. If tlsConfig is not nil, it
// is used as the server's tls config (for ECH tests).
func newDoHTestServer(t testing.TB, tlsConfig *tls.Config) (addr string) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		if err := m.Unpack(wire); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.IPv4(1, 2, 3, 4).To4(),
		})
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	})

	srv := httptest.NewUnstartedServer(handler)
	if tlsConfig != nil {
		srv.TLS = tlsConfig
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

func Test_DoT_fingerprint(t *testing.T) {
	addr, shutdownServer := newDoTTestServer(t, &vServer{})
	defer shutdownServer()

	u, err := NewUpstream(
		"tls://"+addr,
		Opt{
			TLSConfig:       &tls.Config{InsecureSkipVerify: true},
			UTLSFingerprint: "chrome",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

func Test_DoT_alpn(t *testing.T) {
	addr, shutdownServer := newDoTTestServer(t, &vServer{})
	defer shutdownServer()

	u, err := NewUpstream(
		"tls://"+addr,
		Opt{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"dot"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

// generateTestCert generates a test CA and a leaf certificate for dnsName
// signed by it.
func generateTestCert(dnsName string) (leaf tls.Certificate, roots *x509.CertPool, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return
	}
	roots = x509.NewCertPool()
	roots.AddCert(caCert)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return
	}
	leaf = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	return leaf, roots, nil
}

// newDoTTestServerWithCert starts a DoT test server using the given cert.
func newDoTTestServerWithCert(t testing.TB, handler dns.Handler, cert tls.Certificate) (addr string, shutdownFunc func()) {
	t.Helper()
	tlsConfig := new(tls.Config)
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	doTAddr := tlsListener.Addr().String()
	doTServer := dns.Server{
		Net:           "tcp-tls",
		Listener:      tlsListener,
		TLSConfig:     tlsConfig,
		Handler:       handler,
		MaxTCPQueries: -1,
	}
	go doTServer.ActivateAndServe()
	return doTAddr, func() {
		doTServer.Shutdown()
	}
}

func Test_verifyPeerCertByName(t *testing.T) {
	// The test server's certificate is issued by a private CA for "test".
	leaf, roots, err := generateTestCert("test")
	if err != nil {
		t.Fatal(err)
	}
	addr, shutdownServer := newDoTTestServerWithCert(t, &vServer{}, leaf)
	defer shutdownServer()

	t.Run("ok", func(t *testing.T) {
		// The server address is 127.0.0.1, which does not match the
		// certificate. Standard verification fails, but verification
		// by name "test" succeeds.
		u, err := NewUpstream(
			"tls://"+addr,
			Opt{
				TLSConfig:            &tls.Config{RootCAs: roots},
				VerifyPeerCertByName: []string{"test"},
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := testUpstream(u); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bad_name", func(t *testing.T) {
		u, err := NewUpstream(
			"tls://"+addr,
			Opt{
				TLSConfig:            &tls.Config{RootCAs: roots},
				VerifyPeerCertByName: []string{"bad.name"},
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := testUpstream(u); err == nil {
			t.Fatal("expected handshake to fail")
		}
	})
}

func Test_DoT_ech(t *testing.T) {
	echConfigList, echConfig, priv, err := generateECHConfig("cloudflare-ech.com")
	if err != nil {
		t.Fatal(err)
	}
	addr, shutdownServer := newECHDoTTestServer(t, &vServer{}, echConfig, priv)
	defer shutdownServer()

	u, err := NewUpstream(
		"tls://"+addr,
		Opt{
			TLSConfig:     &tls.Config{InsecureSkipVerify: true},
			ECHConfigList: base64.StdEncoding.EncodeToString(echConfigList),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

func Test_DoT_ech_no_ech_server(t *testing.T) {
	// If the server rejects ECH, the handshake must fail instead of
	// falling back to a plaintext (non-ECH) connection.
	echConfigList, _, _, err := generateECHConfig("cloudflare-ech.com")
	if err != nil {
		t.Fatal(err)
	}
	addr, shutdownServer := newDoTTestServer(t, &vServer{})
	defer shutdownServer()

	u, err := NewUpstream(
		"tls://"+addr,
		Opt{
			TLSConfig:     &tls.Config{InsecureSkipVerify: true},
			ECHConfigList: base64.StdEncoding.EncodeToString(echConfigList),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := testUpstream(u); err == nil {
		t.Fatal("expected handshake to fail")
	}
}

func Test_DoH_utls(t *testing.T) {
	addr := newDoHTestServer(t, nil)

	u, err := NewUpstream(
		addr,
		Opt{
			TLSConfig:       &tls.Config{InsecureSkipVerify: true},
			UTLSFingerprint: "chrome",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

func Test_DoH_ech(t *testing.T) {
	echConfigList, echConfig, priv, err := generateECHConfig("cloudflare-ech.com")
	if err != nil {
		t.Fatal(err)
	}
	serverName := "test"
	cert, err := utils.GenerateCertificate(serverName)
	if err != nil {
		t.Fatal(err)
	}
	addr := newDoHTestServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:      echConfig,
			PrivateKey:  priv,
			SendAsRetry: true,
		}},
	})

	u, err := NewUpstream(
		addr,
		Opt{
			TLSConfig:     &tls.Config{InsecureSkipVerify: true},
			ECHConfigList: base64.StdEncoding.EncodeToString(echConfigList),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

// echDNSHandler answers HTTPS queries with an ech config.
type echDNSHandler struct {
	echConfigList []byte
	ttl           uint32
}

func (h echDNSHandler) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(q)
	if len(q.Question) > 0 && q.Question[0].Qtype == dns.TypeHTTPS {
		https := new(dns.HTTPS)
		https.Hdr = dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeHTTPS,
			Class:  dns.ClassINET,
			Ttl:    h.ttl,
		}
		https.Priority = 1
		https.Target = "."
		https.Value = append(https.Value, &dns.SVCBECHConfig{ECH: h.echConfigList})
		resp.Answer = append(resp.Answer, https)
	}
	w.WriteMsg(resp)
}

func Test_DoT_ech_dns_query(t *testing.T) {
	echConfigList, echConfig, priv, err := generateECHConfig("cloudflare-ech.com")
	if err != nil {
		t.Fatal(err)
	}

	// The DoT server that accepts ECH.
	doTAddr, shutdownDoT := newECHDoTTestServer(t, &vServer{}, echConfig, priv)
	defer shutdownDoT()

	// The dns server that serves the ech config list.
	dnsAddr, shutdownDNS := newUDPTestServer(t, echDNSHandler{echConfigList: echConfigList, ttl: 60})
	defer shutdownDNS()

	// The ech config is queried from the dns server at handshake time.
	u, err := NewUpstream(
		"tls://"+doTAddr,
		Opt{
			TLSConfig:     &tls.Config{InsecureSkipVerify: true},
			ECHConfigList: "test.example.com+udp://" + dnsAddr,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

func Test_echConfigResolver_queryTTL(t *testing.T) {
	echConfigList, _, _, err := generateECHConfig("cloudflare-ech.com")
	if err != nil {
		t.Fatal(err)
	}
	dnsAddr, shutdownDNS := newUDPTestServer(t, echDNSHandler{echConfigList: echConfigList, ttl: 60})
	defer shutdownDNS()

	r, err := newECHConfigResolver("test.example.com+udp://"+dnsAddr, nil)
	if err != nil {
		t.Fatal(err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	got, ttl, err := r.query(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, echConfigList) {
		t.Fatal("queried ech config list mismatch")
	}
	if ttl != 60 {
		t.Fatalf("unexpected record ttl %d, want 60", ttl)
	}
}

func Test_TLSOpt_invalid(t *testing.T) {
	badECHList := base64.StdEncoding.EncodeToString([]byte{1, 1, 4, 5, 1, 4})

	if _, err := NewUpstream("tls://127.0.0.1", Opt{UTLSFingerprint: "no-such-fingerprint"}); err == nil {
		t.Fatal("expected error for unknown fingerprint")
	}
	if _, err := NewUpstream("tls://127.0.0.1", Opt{ECHConfigList: "not-base64*"}); err == nil {
		t.Fatal("expected error for invalid base64 ech config list")
	}
	if _, err := NewUpstream("h3://127.0.0.1", Opt{UTLSFingerprint: "chrome"}); err == nil {
		t.Fatal("expected error for h3 upstream with fingerprint")
	}
	if _, err := NewUpstream("quic://127.0.0.1", Opt{ECHConfigList: badECHList}); err == nil {
		t.Fatal("expected error for quic upstream with ech config list")
	}
}
