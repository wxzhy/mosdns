package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
)

func handshakeCompatFingerprint(t *testing.T, fp utls.ClientHelloID, clientConfig, serverConfig *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	cert, _, err := generateTestCert("test")
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.MinVersion == tls.VersionTLS10 {
		// Chrome 58 only offers RSA-authenticated suites below TLS 1.2.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		template, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		template.SignatureAlgorithm = x509.SHA256WithRSA
		template.PublicKey = &key.PublicKey
		template.PublicKeyAlgorithm = x509.RSA
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			t.Logf("server handshake: %v", err)
		}
	}()
	defer func() { <-done }()
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	uconn, err := utlsClientHandshake(ctx, conn, clientConfig, &fp, nil)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer uconn.Close()
	return stdTLSConnectionState(uconn.ConnectionState()), nil
}

func TestTLSFingerprintCompatVersions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fp      utls.ClientHelloID
		client  *tls.Config
		server  *tls.Config
		version uint16
		wantErr bool
	}{
		{"legacy-default-modern-server", utls.HelloChrome_58, &tls.Config{}, &tls.Config{}, tls.VersionTLS12, false},
		{"legacy-explicit-maximum", utls.HelloChrome_58, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}, &tls.Config{MinVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}, tls.VersionTLS11, false},
		{"legacy-default-minimum", utls.HelloChrome_58, &tls.Config{}, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}, tls.VersionTLS11, false},
		{"legacy-incompatible-minimum", utls.HelloChrome_58, &tls.Config{MinVersion: tls.VersionTLS13}, &tls.Config{}, 0, true},
		{"conflicting-bounds", utls.HelloChrome_Auto, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12}, &tls.Config{}, 0, true},
		{"modern-explicit-maximum", utls.HelloChrome_Auto, &tls.Config{MaxVersion: tls.VersionTLS12}, &tls.Config{}, tls.VersionTLS12, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.client.InsecureSkipVerify = true
			state, err := handshakeCompatFingerprint(t, tc.fp, tc.client, tc.server)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "configured TLS versions") {
					t.Fatalf("handshake error = %v, want incompatible configured versions", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if state.Version != tc.version {
				t.Fatalf("negotiated version = %#x, want %#x", state.Version, tc.version)
			}
		})
	}
}

func TestTLSFingerprintCompatNoALPN(t *testing.T) {
	for _, scheme := range []string{"tls", "https"} {
		for _, tc := range []struct {
			name string
			alpn []string
		}{
			{"omitted", nil},
			{"empty", []string{}},
			{"explicit", []string{"http/1.1"}},
		} {
			t.Run(scheme+"/"+tc.name, func(t *testing.T) {
				seen := make(chan []string, 1)
				// uTLS randomized presets can advertise ML-KEM without a matching
				// share, whose HRR path the dependency does not support. Keep this
				// ALPN fixture on classical groups independently of the random seed.
				config := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					select {
					case seen <- slices.Clone(hello.SupportedProtos):
					default:
					}
					return nil, nil
				}}
				var addr string
				if scheme == "https" {
					addr = newDoHTestServer(t, config)
				} else {
					cert, _, err := generateTestCert("test")
					if err != nil {
						t.Fatal(err)
					}
					config.Certificates = []tls.Certificate{cert}
					listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
					if err != nil {
						t.Fatal(err)
					}
					server := &dns.Server{Net: "tcp-tls", Listener: listener, Handler: &vServer{}}
					go server.ActivateAndServe()
					t.Cleanup(func() { server.Shutdown() })
					addr = "tls://" + listener.Addr().String()
				}
				u, err := NewUpstream(addr, Opt{UTLSFingerprint: "randomizednoalpn", TLSConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: tc.alpn}})
				if err != nil {
					t.Fatal(err)
				}
				defer u.Close()
				if err := testUpstream(u); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-seen:
					if !slices.Equal(got, tc.alpn) {
						t.Fatalf("offered ALPN = %v, want %v", got, tc.alpn)
					}
				case <-time.After(time.Second):
					t.Fatal("server did not inspect a ClientHello")
				}
			})
		}
	}
}

func TestTLSFingerprintCompatRandomizedALPN(t *testing.T) {
	for _, withALPN := range []bool{false, true} {
		name := "without-alpn"
		if withALPN {
			name = "with-alpn"
		}
		t.Run(name, func(t *testing.T) {
			weights := utls.DefaultWeights
			weights.Extensions_Append_ALPN = 0
			if withALPN {
				weights.Extensions_Append_ALPN = 1
			}
			// Force the randomized TLS 1.2 branch against a TLS 1.3 server,
			// covering both ALPN choices and downgrade-canary handling.
			weights.TLSVersMax_Set_VersionTLS13 = 0
			weights.CipherSuites_Remove_RandomCiphers = 0
			fp := utls.HelloRandomized
			fp.Seed = new(utls.PRNGSeed)
			fp.Weights = &weights
			var offered []string
			state, err := handshakeCompatFingerprint(t, fp, &tls.Config{InsecureSkipVerify: true}, &tls.Config{
				NextProtos: []string{"h2", "http/1.1"},
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					offered = slices.Clone(hello.SupportedProtos)
					return nil, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if (len(offered) > 0) != withALPN || (state.NegotiatedProtocol != "") != withALPN {
				t.Fatalf("offered ALPN = %v, negotiated = %q, want ALPN %v", offered, state.NegotiatedProtocol, withALPN)
			}
		})
	}
}
