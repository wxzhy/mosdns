package upstream

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/ameshkov/dnsstamps"
)

func TestTrimIPv6Brackets(t *testing.T) {
	for input, want := range map[string]string{"[::1]": "::1", "[2001:db8::1234]": "2001:db8::1234", "::1": "::1", "[::1]:53": "[::1]:53"} {
		if got := tryTrimIpv6Brackets(input); got != want {
			t.Errorf("trim %q: got %q, want %q", input, got, want)
		}
	}
}

func TestStampTLSDefaultPort(t *testing.T) {
	for _, proto := range []dnsstamps.StampProtoType{dnsstamps.StampProtoTypeTLS, dnsstamps.StampProtoTypeDoQ} {
		for _, server := range []string{"127.0.0.1", "[::1]", "127.0.0.1:8853"} {
			stampStr := (&dnsstamps.ServerStamp{Proto: proto, ServerAddrStr: server, ProviderName: "dns.example.com"}).String()
			stamp, err := parseDNSStamp(stampStr)
			if err != nil {
				t.Fatal(err)
			}
			want := server
			if server == "127.0.0.1" {
				want = "127.0.0.1:853"
			}
			if server == "[::1]" {
				want = "[::1]:853"
			}
			if stamp.ServerAddrStr != want {
				t.Errorf("protocol %v server %q: got %q, want %q", proto, server, stamp.ServerAddrStr, want)
			}
		}
	}
}

func TestStampCertificateHashes(t *testing.T) {
	cert := &x509.Certificate{RawTBSCertificate: []byte("trusted certificate")}
	hash := sha256.Sum256(cert.RawTBSCertificate)
	var called bool
	config := &tls.Config{VerifyConnection: func(tls.ConnectionState) error { called = true; return nil }}
	pinned, err := tlsConfigWithStampHashes(config, [][]byte{hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, DidResume: true}
	if err := pinned.VerifyConnection(state); err != nil || !called {
		t.Fatalf("valid pin failed: %v (callback %v)", err, called)
	}
	state.PeerCertificates = []*x509.Certificate{{RawTBSCertificate: []byte("other certificate")}}
	if err := pinned.VerifyConnection(state); err == nil {
		t.Fatal("accepted mismatching certificate")
	}
	if _, err := tlsConfigWithStampHashes(nil, [][]byte{{1}}); err == nil {
		t.Fatal("accepted malformed certificate hash")
	}
	want := errors.New("caller rejected certificate")
	config.VerifyConnection = func(tls.ConnectionState) error { return want }
	pinned, err = tlsConfigWithStampHashes(config, [][]byte{hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	if err := pinned.VerifyConnection(state); !errors.Is(err, want) {
		t.Fatalf("caller verification was lost: %v", err)
	}
}
