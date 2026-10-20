package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
)

func TestECHSemanticsStaticConfig(t *testing.T) {
	want := []byte{0, 4, 0xfe, 0x0d, 0, 0}
	r, err := newECHConfigResolver(base64.StdEncoding.EncodeToString(want), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := r.getConfigList(context.Background()); !bytes.Equal(got, want) {
		t.Fatalf("static ECHConfigList = %x, want %x", got, want)
	}
	if r.u != nil {
		t.Fatal("static configuration unexpectedly created a DNS upstream")
	}
	// ECH without an explicit fingerprint selects the established Chrome
	// default. Existing local ECH round trips exercise this combination.
	fp, err := getFingerprint("")
	if err != nil || fp == nil || *fp != utls.HelloChrome_Auto {
		t.Fatalf("implicit ECH fingerprint = %v, error %v", fp, err)
	}
}

func echSemanticsAnswer(q *dns.Msg, config []byte, ttl uint32) *dns.Msg {
	r := new(dns.Msg).SetReply(q)
	r.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: ttl},
		Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: config}},
	}}}
	return r
}

func TestECHSemanticsRefreshTTL(t *testing.T) {
	for _, ttl := range []uint32{0, 60, 300, 600} {
		t.Run((time.Duration(ttl) * time.Second).String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				calls := 0
				want := []byte{1, 2, 3}
				r.u = &echResponseUpstream{response: func(q *dns.Msg) *dns.Msg {
					calls++
					return echSemanticsAnswer(q, want, ttl)
				}}
				start := time.Now()
				if got := r.getConfigList(context.Background()); !bytes.Equal(got, want) {
					t.Fatalf("first config = %x, want %x", got, want)
				}
				refresh := max(time.Duration(ttl)*time.Second, 5*time.Minute)
				if !r.nextRefresh.Equal(start.Add(refresh)) {
					t.Fatalf("refresh interval = %s, want %s", r.nextRefresh.Sub(start), refresh)
				}
				time.Sleep(refresh - time.Nanosecond)
				r.getConfigList(context.Background())
				if calls != 1 {
					t.Fatalf("DNS queried %d times before expiry, want 1", calls)
				}
				time.Sleep(time.Nanosecond)
				r.getConfigList(context.Background())
				if calls != 2 {
					t.Fatalf("DNS queried %d times at expiry, want 2", calls)
				}
			})
		})
	}
}

func TestECHSemanticsStaleConfigAndRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		oldConfig, newConfig := []byte{1, 2, 3}, []byte{4, 5, 6}
		calls := 0
		r.u = &echResponseUpstream{response: func(q *dns.Msg) *dns.Msg {
			calls++
			switch calls {
			case 1:
				return echSemanticsAnswer(q, oldConfig, 60)
			case 2:
				return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure)
			default:
				return echSemanticsAnswer(q, newConfig, 60)
			}
		}}
		if got := r.getConfigList(context.Background()); !bytes.Equal(got, oldConfig) {
			t.Fatalf("initial config = %x, want %x", got, oldConfig)
		}
		expiry := r.nextRefresh
		time.Sleep(5 * time.Minute)
		if got := r.getConfigList(context.Background()); !bytes.Equal(got, oldConfig) {
			t.Fatalf("failed refresh returned %x, want stale config %x", got, oldConfig)
		}
		if !r.nextRefresh.Equal(expiry) {
			t.Fatal("failed refresh postponed the next retry")
		}
		if got := r.getConfigList(context.Background()); !bytes.Equal(got, newConfig) {
			t.Fatalf("retry config = %x, want %x", got, newConfig)
		}
		if calls != 3 {
			t.Fatalf("DNS calls = %d, want initial query, failed refresh, successful retry", calls)
		}
	})
}

func TestECHSemanticsInitialDNSFailure(t *testing.T) {
	r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	calls := 0
	want := []byte{1, 2, 3}
	r.u = &echResponseUpstream{response: func(q *dns.Msg) *dns.Msg {
		calls++
		if calls == 1 {
			return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure)
		}
		return echSemanticsAnswer(q, want, 60)
	}}
	if got := r.getConfigList(context.Background()); len(got) == 0 || !bytes.Equal(got, invalidECHConfigList) {
		t.Fatalf("initial failure returned %x, want invalid nonempty ECHConfigList", got)
	}
	if got := r.getConfigList(context.Background()); !bytes.Equal(got, want) || calls != 2 {
		t.Fatalf("retry returned %x after %d queries, want %x after 2", got, calls, want)
	}
}

func TestTLSSemanticsEmptyOptionsUseStandardTLS(t *testing.T) {
	cert, roots, err := generateTestCert("test")
	if err != nil {
		t.Fatal(err)
	}
	// This explicitly configured TLS 1.2 cipher is absent from Chrome's
	// fingerprint. A successful exchange guards the ordinary crypto/tls
	// path when both fingerprint and ECHConfigList are empty.
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256},
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Net: "tcp-tls", Listener: l, TLSConfig: config, Handler: &vServer{}, MaxTCPQueries: -1}
	go server.ActivateAndServe()
	defer server.Shutdown()
	u, err := NewUpstream("tls://"+l.Addr().String(), Opt{TLSConfig: &tls.Config{
		ServerName: "test", RootCAs: roots,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

func TestTLSSemanticsFingerprintVerifyPeerCertByName(t *testing.T) {
	cert, roots, err := generateTestCert("test")
	if err != nil {
		t.Fatal(err)
	}
	addr, shutdown := newDoTTestServerWithCert(t, &vServer{}, cert)
	defer shutdown()
	for _, tc := range []struct {
		name    string
		names   []string
		wantErr bool
	}{
		{name: "matches_second_name", names: []string{"bad.name", "test"}},
		{name: "all_names_wrong", names: []string{"bad.name", "also.bad"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := NewUpstream("tls://"+addr, Opt{
				TLSConfig:       &tls.Config{ServerName: "different.sni", RootCAs: roots},
				UTLSFingerprint: "chrome", VerifyPeerCertByName: tc.names,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			if err := testUpstream(u); (err != nil) != tc.wantErr {
				t.Fatalf("exchange error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
