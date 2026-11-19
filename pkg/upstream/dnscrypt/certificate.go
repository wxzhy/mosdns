package dnscrypt

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/nacl/box"
)

const (
	certificateTimeout      = 3 * time.Second
	certificateUDPTimeout   = time.Second
	certificateSignedOffset = 8 + ed25519.SignatureSize
)

// fetchCertificate uses the same configured route as encrypted queries. The
// library's DialStampContext creates its own dialer, bypassing ours.
func (u *Upstream) fetchCertificate(ctx context.Context) (*dnscrypt.ResolverInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, certificateTimeout)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(u.stamp.ProviderName), dns.TypeTXT)
	q.SetEdns0(1232, false)
	deadline, _ := ctx.Deadline()
	budget := min(certificateUDPTimeout, time.Until(deadline)/2)
	udpCtx, cancelUDP := context.WithTimeout(ctx, budget)
	cert, udpErr := u.getCertificate(udpCtx, q, false)
	cancelUDP()
	if udpErr != nil {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		var tcpErr error
		cert, tcpErr = u.getCertificate(ctx, q, true)
		if tcpErr != nil {
			return nil, errors.Join(fmt.Errorf("UDP: %w", udpErr), fmt.Errorf("TCP: %w", tcpErr))
		}
	}
	return u.resolverInfo(cert)
}

func (u *Upstream) getCertificate(ctx context.Context, q *dns.Msg, tcp bool) (*dnscrypt.Certificate, error) {
	r, err := u.exchangeCertificate(ctx, q, tcp)
	if err != nil {
		return nil, err
	}
	if r.Truncated {
		return nil, fmt.Errorf("truncated DNSCrypt certificate response")
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, dnscrypt.ErrFailedToFetchCert
	}
	var cert *dnscrypt.Certificate
	for _, rr := range r.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		// Repack TXT RDATA to decode miekg/dns presentation escapes.
		packed := make([]byte, dns.Len(txt))
		n, err := dns.PackRR(txt, packed, 0, nil, false)
		if err != nil {
			continue
		}
		_, offset, err := dns.UnpackDomainName(packed[:n], 0)
		if err != nil || offset+10 > n {
			continue
		}
		var data []byte
		for p := offset + 10; p < n; {
			size := int(packed[p])
			p++
			if size > n-p {
				data = nil
				break
			}
			data = append(data, packed[p:p+size]...)
			p += size
		}
		current := new(dnscrypt.Certificate)
		// Verify the original signed bytes. The library's VerifySignature
		// rebuilds only the fixed fields and omits certificate extensions.
		if current.UnmarshalBinary(data) != nil || !current.VerifyDate() ||
			!ed25519.Verify(u.stamp.ServerPk, data[certificateSignedOffset:], current.Signature[:]) {
			continue
		}
		if cert == nil || current.Serial > cert.Serial || current.Serial == cert.Serial && current.ESVersion > cert.ESVersion {
			cert = current
		}
	}
	if cert == nil {
		return nil, fmt.Errorf("no valid certificate for provider %q", u.stamp.ProviderName)
	}
	return cert, nil
}

func (u *Upstream) resolverInfo(cert *dnscrypt.Certificate) (*dnscrypt.ResolverInfo, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ri := &dnscrypt.ResolverInfo{ResolverCert: cert, ServerAddress: u.stamp.ServerAddrStr,
		ProviderName: u.stamp.ProviderName, ServerPublicKey: u.stamp.ServerPk}
	copy(ri.SecretKey[:], private.Bytes())
	copy(ri.PublicKey[:], private.PublicKey().Bytes())
	if cert.ESVersion == dnscrypt.XSalsa20Poly1305 {
		box.Precompute(&ri.SharedKey, &cert.ResolverPk, &ri.SecretKey)
	} else {
		public, err := ecdh.X25519().NewPublicKey(cert.ResolverPk[:])
		if err != nil {
			return nil, err
		}
		shared, err := private.ECDH(public)
		if err != nil {
			return nil, err
		}
		key, err := chacha20.HChaCha20(shared, make([]byte, 16))
		if err != nil {
			return nil, err
		}
		copy(ri.SharedKey[:], key)
	}
	return ri, nil
}

func (u *Upstream) exchangeCertificate(ctx context.Context, q *dns.Msg, tcp bool) (*dns.Msg, error) {
	dial := u.dialUDP
	read := func(c io.Reader) (*dns.Msg, int, error) {
		return dnsutils.ReadMsgFromUDP(c, dns.MaxMsgSize)
	}
	if tcp {
		dial = u.dialTCP
		read = dnsutils.ReadMsgFromTCP
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := closeOnCancel(ctx, conn)
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	payload, err := q.Pack()
	if err != nil {
		return nil, err
	}
	var writer io.Writer = conn
	if tcp {
		writer = framedTCPConn{Conn: conn}
	}
	if n, err := writer.Write(payload); err != nil {
		return nil, err
	} else if n != len(payload) {
		return nil, io.ErrShortWrite
	}
	for {
		r, _, err := read(conn)
		if err != nil {
			return nil, err
		}
		if !tcp && r.Id != q.Id {
			continue
		}
		if r.Id != q.Id {
			return nil, dns.ErrId
		}
		// A UDP peer may only have space for the header of a TC reply.
		headerOnlyTC := !tcp && r.Truncated && len(r.Question) == 0
		if !r.Response || r.Opcode != q.Opcode ||
			!headerOnlyTC && !matchesCertificateQuestion(q.Question[0], r.Question) {
			return nil, fmt.Errorf("DNSCrypt certificate response does not match query")
		}
		return r, nil
	}
}

func matchesCertificateQuestion(q dns.Question, questions []dns.Question) bool {
	return len(questions) == 1 && questions[0].Qtype == q.Qtype &&
		questions[0].Qclass == q.Qclass && strings.EqualFold(questions[0].Name, q.Name)
}
