package dnscrypt

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/miekg/dns"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/nacl/box"
)

// fetchCertificate uses the same configured route as encrypted queries. The
// library's DialStampContext creates its own dialer, bypassing ours.
func (u *Upstream) fetchCertificate(ctx context.Context) (*dnscrypt.ResolverInfo, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(u.stamp.ProviderName), dns.TypeTXT)
	q.SetEdns0(1232, false)
	exchange := func(tcp bool) (*dns.Msg, error) {
		dial := u.dialUDP
		if tcp {
			dial = u.dialTCP
		}
		conn, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		stop := closeOnCancel(ctx, conn)
		defer stop()
		c := &dns.Client{UDPSize: dns.MaxMsgSize}
		if tcp {
			c.Net = "tcp"
		}
		r, _, err := c.ExchangeWithConnContext(ctx, q, &dns.Conn{Conn: conn, UDPSize: dns.MaxMsgSize})
		return r, err
	}
	r, err := exchange(false)
	if err == nil && r.Truncated {
		r, err = exchange(true)
	}
	if err != nil {
		return nil, err
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
		if current.UnmarshalBinary(data) != nil || !current.VerifyDate() || !current.VerifySignature(u.stamp.ServerPk) {
			continue
		}
		if cert == nil || current.Serial > cert.Serial || current.Serial == cert.Serial && current.ESVersion > cert.ESVersion {
			cert = current
		}
	}
	if cert == nil {
		return nil, fmt.Errorf("no valid certificate for provider %q", u.stamp.ProviderName)
	}
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
