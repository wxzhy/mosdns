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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
	"go.uber.org/zap"
)

// getFingerprint maps a fingerprint name to a uTLS client fingerprint.
// An empty name defaults to "chrome". Names follow xray-core's
// "fingerprint" tls option.
func getFingerprint(name string) (*utls.ClientHelloID, error) {
	id, ok := presetFingerprints[strings.ToLower(name)]
	if !ok {
		id, ok = otherFingerprints[strings.ToLower(name)]
	}
	if !ok {
		return nil, fmt.Errorf("unknown fingerprint [%s]", name)
	}
	return id, nil
}

// presetFingerprints are the recommended fingerprint names in xray-core.
// An empty name maps to chrome.
var presetFingerprints = map[string]*utls.ClientHelloID{
	"":                 &utls.HelloChrome_Auto,
	"chrome":           &utls.HelloChrome_Auto,
	"firefox":          &utls.HelloFirefox_Auto,
	"safari":           &utls.HelloSafari_Auto,
	"ios":              &utls.HelloIOS_Auto,
	"android":          &utls.HelloAndroid_11_OkHttp,
	"edge":             &utls.HelloEdge_Auto,
	"360":              &utls.Hello360_Auto,
	"qq":               &utls.HelloQQ_Auto,
	"random":           &utls.HelloRandomizedALPN,
	"randomized":       &utls.HelloRandomizedALPN,
	"randomizednoalpn": &utls.HelloRandomizedNoALPN,
}

// otherFingerprints are fingerprints referenced by their uTLS constant names.
var otherFingerprints = map[string]*utls.ClientHelloID{
	"hellogolang":                      &utls.HelloGolang,
	"hellorandomized":                  &utls.HelloRandomized,
	"hellorandomizedalpn":              &utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":            &utls.HelloRandomizedNoALPN,
	"hellofirefox_auto":                &utls.HelloFirefox_Auto,
	"hellofirefox_55":                  &utls.HelloFirefox_55,
	"hellofirefox_56":                  &utls.HelloFirefox_56,
	"hellofirefox_63":                  &utls.HelloFirefox_63,
	"hellofirefox_65":                  &utls.HelloFirefox_65,
	"hellofirefox_99":                  &utls.HelloFirefox_99,
	"hellofirefox_102":                 &utls.HelloFirefox_102,
	"hellofirefox_105":                 &utls.HelloFirefox_105,
	"hellofirefox_120":                 &utls.HelloFirefox_120,
	"hellochrome_auto":                 &utls.HelloChrome_Auto,
	"hellochrome_58":                   &utls.HelloChrome_58,
	"hellochrome_62":                   &utls.HelloChrome_62,
	"hellochrome_70":                   &utls.HelloChrome_70,
	"hellochrome_72":                   &utls.HelloChrome_72,
	"hellochrome_83":                   &utls.HelloChrome_83,
	"hellochrome_87":                   &utls.HelloChrome_87,
	"hellochrome_96":                   &utls.HelloChrome_96,
	"hellochrome_100":                  &utls.HelloChrome_100,
	"hellochrome_102":                  &utls.HelloChrome_102,
	"hellochrome_106_shuffle":          &utls.HelloChrome_106_Shuffle,
	"hellochrome_100_psk":              &utls.HelloChrome_100_PSK,
	"hellochrome_112_psk_shuf":         &utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_114_padding_psk_shuf": &utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_115_pq":               &utls.HelloChrome_115_PQ,
	"hellochrome_115_pq_psk":           &utls.HelloChrome_115_PQ_PSK,
	"hellochrome_120":                  &utls.HelloChrome_120,
	"hellochrome_120_pq":               &utls.HelloChrome_120_PQ,
	"hellochrome_131":                  &utls.HelloChrome_131,
	"hellochrome_133":                  &utls.HelloChrome_133,
	"helloios_auto":                    &utls.HelloIOS_Auto,
	"helloios_11_1":                    &utls.HelloIOS_11_1,
	"helloios_12_1":                    &utls.HelloIOS_12_1,
	"helloios_13":                      &utls.HelloIOS_13,
	"helloios_14":                      &utls.HelloIOS_14,
	"helloandroid_11_okhttp":           &utls.HelloAndroid_11_OkHttp,
	"helloedge_auto":                   &utls.HelloEdge_Auto,
	"helloedge_85":                     &utls.HelloEdge_85,
	"helloedge_106":                    &utls.HelloEdge_106,
	"hellosafari_auto":                 &utls.HelloSafari_Auto,
	"hellosafari_16_0":                 &utls.HelloSafari_16_0,
	"hello360_auto":                    &utls.Hello360_Auto,
	"hello360_7_5":                     &utls.Hello360_7_5,
	"hello360_11_0":                    &utls.Hello360_11_0,
	"helloqq_auto":                     &utls.HelloQQ_Auto,
	"helloqq_11_1":                     &utls.HelloQQ_11_1,
}

// copyStdTLSConfigToUTLS copies the fields that mosdns uses from a
// crypto/tls config to a uTLS config.
func copyStdTLSConfigToUTLS(c *tls.Config) *utls.Config {
	return &utls.Config{
		ServerName:            c.ServerName,
		NextProtos:            c.NextProtos,
		InsecureSkipVerify:    c.InsecureSkipVerify,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
		RootCAs:               c.RootCAs,
		// Note: ClientSessionCache is not copied. uTLS has its own
		// incompatible ClientSessionState type.
	}
}

// utlsClientHandshake wraps conn with a uTLS client using the given
// fingerprint and handshakes. If ech is not nil, the resolved ECHConfigList
// is applied.
func utlsClientHandshake(ctx context.Context, conn net.Conn, c *tls.Config, fp *utls.ClientHelloID, ech *echConfigResolver) (*utls.UConn, error) {
	uconfig := copyStdTLSConfigToUTLS(c)
	if ech != nil {
		uconfig.EncryptedClientHelloConfigList = ech.getConfigList(ctx)
	}
	uconn := utls.UClient(conn, uconfig, *fp)
	if err := uconn.HandshakeContext(ctx); err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
}

// utlsConn adapts *utls.UConn for net/http's connectionStater interface.
// http.Transport reads the negotiated ALPN protocol from
// ConnectionState() to decide whether to upgrade to http/2.
type utlsConn struct {
	*utls.UConn
}

func (c *utlsConn) ConnectionState() tls.ConnectionState {
	s := c.UConn.ConnectionState()
	return tls.ConnectionState{
		HandshakeComplete:           s.HandshakeComplete,
		Version:                     s.Version,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  s.NegotiatedProtocol != "",
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
		TLSUnique:                   s.TLSUnique,
	}
}

// newVerifyPeerCertByNameFunc returns a VerifyPeerCertificate callback that
// verifies the peer certificate chain against the given names, instead of
// the standard verification against ServerName. If roots is nil, the system
// root certificate pool is used. This is xray-core's "verifyPeerCertByName"
// semantics.
func newVerifyPeerCertByNameFunc(names []string, roots *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) (err error) {
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			certs[i], _ = x509.ParseCertificate(asn1Data)
		}
		if len(certs) == 0 {
			return errors.New("unexpected certs")
		}

		opts := x509.VerifyOptions{
			Roots:         roots,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		for _, opts.DNSName = range names {
			if _, err := certs[0].Verify(opts); err == nil {
				return nil
			}
		}
		return fmt.Errorf("peer cert is invalid (against verify_peer_cert_by_name %v)", names)
	}
}

// invalidECHConfigList is an intentionally malformed ECHConfigList. When we
// failed to obtain a valid one, we use it to make the handshake fail,
// instead of silently falling back to a plaintext (non-ECH) connection.
// This is xray-core's behavior.
var invalidECHConfigList = []byte{1, 1, 4, 5, 1, 4}

// echConfigResolver resolves the ECHConfigList for an upstream.
//
// s has one of the following formats:
//   - A base64 encoded ECHConfigList. (i.e. the value of a DNS HTTPS
//     record's ech param)
//   - "domain+dns_server": the HTTPS record of domain is queried from
//     dns_server (any mosdns upstream address, e.g.
//     "example.com+https://1.1.1.1/dns-query"), and its ech param is
//     used as the ECHConfigList. The result is cached respecting the
//     record's TTL, with a minimum of 5 minutes.
type echConfigResolver struct {
	// static is the decoded base64 ECHConfigList. nil if s is the
	// "domain+dns_server" query format.
	static []byte

	// domain and dnsServer are used by the query format.
	domain    string
	dnsServer string

	logger *zap.Logger // non-nil

	mu          sync.Mutex // protects followings
	u           Upstream   // the dns server upstream, lazily initialized
	config      []byte     // the last queried ECHConfigList
	nextRefresh time.Time
}

// minECHConfigTTL is the minimum cache duration for a queried
// ECHConfigList, to avoid refreshing short TTL records too frequently.
const minECHConfigTTL = time.Minute * 5

func newECHConfigResolver(s string, logger *zap.Logger) (*echConfigResolver, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	// A base64 string never contains "://". (xray-core uses the same
	// check to distinguish the two formats.)
	if !strings.Contains(s, "://") {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 ech config list, %w", err)
		}
		return &echConfigResolver{static: b, logger: logger}, nil
	}

	domain, dnsServer, ok := strings.Cut(s, "+")
	if len(domain) == 0 || len(dnsServer) == 0 || !ok {
		return nil, fmt.Errorf("invalid ech config list [%s], want \"domain+dns_server\"", s)
	}
	return &echConfigResolver{domain: domain, dnsServer: dnsServer, logger: logger}, nil
}

// getConfigList returns the ECHConfigList. It never returns nil.
func (r *echConfigResolver) getConfigList(ctx context.Context) []byte {
	if r.static != nil {
		return r.static
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().Before(r.nextRefresh) && r.config != nil {
		return r.config
	}
	config, ttl, err := r.query(ctx)
	if err != nil {
		r.logger.Warn("failed to query ech config list", zap.Error(err))
		// Keep serving the stale config if we have one.
		if r.config == nil {
			return invalidECHConfigList
		}
		return r.config
	}
	r.config = config
	refresh := time.Duration(ttl) * time.Second
	if refresh < minECHConfigTTL {
		refresh = minECHConfigTTL
	}
	r.nextRefresh = time.Now().Add(refresh)
	return r.config
}

// query queries the HTTPS record of r.domain from r.dnsServer.
// It returns the ech param of the record and the record's TTL.
// It must be called with r.mu locked.
func (r *echConfigResolver) query(ctx context.Context) ([]byte, uint32, error) {
	if r.u == nil {
		u, err := NewUpstream(r.dnsServer, Opt{Logger: r.logger})
		if err != nil {
			return nil, 0, fmt.Errorf("failed to init ech dns upstream, %w", err)
		}
		r.u = u
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(r.domain), dns.TypeHTTPS)
	// HTTPS records with ech params are often larger than 512 bytes.
	// 1232 is the recommended edns0 udp size. (DNS flag day 2020)
	m.SetEdns0(1232, false)
	payload, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}
	respPayload, err := r.u.ExchangeContext(ctx, payload)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query https record, %w", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(*respPayload); err != nil {
		return nil, 0, fmt.Errorf("failed to unpack https record resp, %w", err)
	}

	for _, answer := range resp.Answer {
		if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(r.domain) {
			for _, v := range https.Value {
				if ech, ok := v.(*dns.SVCBECHConfig); ok {
					return ech.ECH, https.Hdr.Ttl, nil
				}
			}
		}
	}
	return nil, 0, fmt.Errorf("no ech config found in https record of [%s]", r.domain)
}
