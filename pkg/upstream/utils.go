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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ameshkov/dnsstamps"
)

// dnsstamps v1 uses obsolete DoT/DoQ default ports. Recover the address
// field from the stamp before the library adds those ports.
func parseDNSStamp(addr string) (dnsstamps.ServerStamp, error) {
	stamp, err := dnsstamps.NewServerStampFromString(addr)
	if err != nil {
		return stamp, err
	}
	if stamp.Proto == dnsstamps.StampProtoTypeTLS || stamp.Proto == dnsstamps.StampProtoTypeDoQ {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(addr, "sdns://"))
		if err != nil {
			return stamp, err
		}
		if len(raw) > 9 && int(raw[9]) <= len(raw)-10 {
			server := string(raw[10 : 10+int(raw[9])])
			if ip, err := netip.ParseAddr(tryTrimIpv6Brackets(server)); err == nil {
				stamp.ServerAddrStr = netip.AddrPortFrom(ip, 853).String()
			}
		}
	}
	return stamp, nil
}

// tlsConfigWithStampHashes adds the DNS stamp's TBS certificate pins while
// preserving normal certificate verification and the caller's callback.
func tlsConfigWithStampHashes(config *tls.Config, hashes [][]byte) (*tls.Config, error) {
	pins := make([][]byte, len(hashes))
	for i, hash := range hashes {
		if len(hash) != sha256.Size {
			return nil, fmt.Errorf("invalid dns stamp certificate hash length %d", len(hash))
		}
		pins[i] = bytes.Clone(hash)
	}
	c := config.Clone()
	if c == nil {
		c = new(tls.Config)
	}
	verify := c.VerifyConnection
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if verify != nil {
			if err := verify(state); err != nil {
				return err
			}
		}
		if verifyStampHashes(state.PeerCertificates, pins) == nil {
			return nil
		}
		for _, chain := range state.VerifiedChains {
			if verifyStampHashes(chain, pins) == nil {
				return nil
			}
		}
		return fmt.Errorf("dns stamp certificate hash mismatch")
	}
	return c, nil
}

func verifyStampHashes(certs []*x509.Certificate, hashes [][]byte) error {
	for _, cert := range certs {
		hash := sha256.Sum256(cert.RawTBSCertificate)
		for _, pin := range hashes {
			if bytes.Equal(hash[:], pin) {
				return nil
			}
		}
	}
	return fmt.Errorf("dns stamp certificate hash mismatch")
}

type socketOpts struct {
	so_mark        int
	bind_to_device string
}

func parseDialAddr(urlHost, dialAddr string, defaultPort uint16) (string, uint16, error) {
	addr := urlHost
	if len(dialAddr) > 0 {
		addr = dialAddr
	}
	host, port, err := trySplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	if port == 0 {
		port = defaultPort
	}
	return host, port, nil
}

func joinPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func tryRemovePort(s string) string {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return host
}

// trySplitHostPort splits host and port.
// If s has no port, it returns s,0,nil
func trySplitHostPort(s string) (string, uint16, error) {
	var port uint16
	host, portS, err := net.SplitHostPort(s)
	if err == nil {
		n, err := strconv.ParseUint(portS, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port, %w", err)
		}
		port = uint16(n)
		return host, port, nil
	}
	return s, 0, nil
}

func parseBootstrapAp(s string) (netip.AddrPort, error) {
	host, port, err := trySplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if port == 0 {
		port = 53
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, port), nil
}

func tryTrimIpv6Brackets(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

func msgTruncated(b []byte) bool {
	return b[2]&(1<<1) != 0
}
