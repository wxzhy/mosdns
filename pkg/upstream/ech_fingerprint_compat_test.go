package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"sync"
	"testing"
	"time"
)

type echAuditRecordingConn struct {
	net.Conn
	mu   sync.Mutex
	wire bytes.Buffer
}

func (c *echAuditRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.wire.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *echAuditRecordingConn) writtenBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.wire.Bytes()...)
}

// Cover both successful ECH negotiation and fingerprints that cannot carry ECH.
// A rejected fingerprint must fail before a ClientHello is sent, so rejection
// cannot silently expose the configured inner server name.
func TestECHFingerprintCompatibility(t *testing.T) {
	const innerName = "private-ech-audit.example"
	const publicName = "public-ech-audit.example"
	configList, config, privateKey, err := generateECHConfig(publicName)
	if err != nil {
		t.Fatal(err)
	}
	cert, roots, err := generateTestCert(innerName)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		fingerprint string
		accepted    bool
	}{
		{"chrome", true},
		{"hellogolang", true},
		{"firefox", true},
		{"safari", false},
		{"randomizednoalpn", false},
		{"hellochrome_58", false},
	} {
		t.Run(tc.fingerprint, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			type serverResult struct {
				state tls.ConnectionState
				err   error
			}
			serverDone := make(chan serverResult, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverDone <- serverResult{err: err}
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				server := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS13,
					NextProtos:   []string{"dot"},
					EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
						Config: config, PrivateKey: privateKey, SendAsRetry: true,
					}},
				})
				err = server.Handshake()
				serverDone <- serverResult{state: server.ConnectionState(), err: err}
			}()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			recorded := &echAuditRecordingConn{Conn: conn}
			resolver, err := newECHConfigResolver(base64.StdEncoding.EncodeToString(configList), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resolver.Close()
			fp, err := getFingerprint(tc.fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			client, handshakeErr := utlsClientHandshake(ctx, recorded, &tls.Config{
				ServerName: innerName, RootCAs: roots, NextProtos: []string{"dot"},
			}, fp, resolver)
			var clientState tls.ConnectionState
			if client != nil {
				clientState = (&utlsConn{client}).ConnectionState()
				client.Close()
			}
			conn.Close()
			server := <-serverDone
			wire := recorded.writtenBytes()
			t.Logf("handshake error: %v; server error: %v; client/server ECHAccepted: %v/%v; bytes sent: %d",
				handshakeErr, server.err, clientState.ECHAccepted, server.state.ECHAccepted, len(wire))
			if bytes.Contains(wire, []byte(innerName)) {
				t.Error("inner server name appeared in the unencrypted handshake")
			}
			if tc.accepted {
				if handshakeErr != nil || server.err != nil || !clientState.ECHAccepted || !server.state.ECHAccepted {
					t.Fatal("fingerprint did not negotiate and confirm ECH on both peers")
				}
				if clientState.ServerName != innerName || server.state.ServerName != innerName || !bytes.Contains(wire, []byte(publicName)) {
					t.Fatal("ECH did not preserve the inner server name and expose only the configured public name")
				}
				if clientState.NegotiatedProtocol != "dot" || server.state.NegotiatedProtocol != "dot" {
					t.Fatal("ECH did not preserve the configured ALPN")
				}
			} else if handshakeErr == nil || len(wire) != 0 {
				t.Fatal("unsupported ECH fingerprint must be rejected before writing a ClientHello")
			}
		})
	}
}
