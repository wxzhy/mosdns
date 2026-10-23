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

// Package dnscrypt implements a DNSCrypt v2 upstream.
package dnscrypt

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type Opt struct {
	// UDPDialContext dials the udp connection to the dns server.
	// If nil, a default net.Dialer dials the stamp server address.
	UDPDialContext func(ctx context.Context) (net.Conn, error)

	// TCPDialContext dials the tcp connection to the dns server.
	// It is used to retry truncated udp responses.
	// If nil, a default net.Dialer dials the stamp server address.
	TCPDialContext func(ctx context.Context) (net.Conn, error)

	Logger *zap.Logger
}

// Upstream is a DNSCrypt upstream. It implements the
// github.com/IrineSistiana/mosdns/v5/pkg/upstream.Upstream interface.
type Upstream struct {
	stamp   dnsstamps.ServerStamp
	logger  *zap.Logger // non-nil
	udpClt  *dnscrypt.Client
	tcpClt  *dnscrypt.Client
	dialUDP func(ctx context.Context) (net.Conn, error)
	dialTCP func(ctx context.Context) (net.Conn, error)

	// mu protects ri.
	mu       sync.RWMutex
	fetchSem chan struct{}
	// ri is the fetched resolver certificate info. May be nil.
	ri *dnscrypt.ResolverInfo
}

// NewUpstream creates a DNSCrypt upstream from a sdns:// stamp string.
func NewUpstream(stampStr string, opt Opt) (*Upstream, error) {
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dns stamp, %w", err)
	}
	if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return nil, fmt.Errorf("unexpected stamp protocol [%d]", stamp.Proto)
	}
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid dnscrypt public key length %d", len(stamp.ServerPk))
	}

	logger := opt.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	addr := stamp.ServerAddrStr
	dialUDP, dialTCP := opt.UDPDialContext, opt.TCPDialContext
	if dialUDP == nil {
		d := new(net.Dialer)
		dialUDP = func(ctx context.Context) (net.Conn, error) {
			return d.DialContext(ctx, "udp", addr)
		}
	}
	if dialTCP == nil {
		d := new(net.Dialer)
		dialTCP = func(ctx context.Context) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}

	var libLogger *slog.Logger = slog.New(slog.DiscardHandler)
	return &Upstream{
		fetchSem: make(chan struct{}, 1),
		stamp:    stamp,
		logger:   logger,
		udpClt: dnscrypt.NewClient(&dnscrypt.ClientConfig{
			Logger:  libLogger,
			Proto:   dnscrypt.ProtoUDP,
			UDPSize: dns.MaxMsgSize,
		}),
		tcpClt: dnscrypt.NewClient(&dnscrypt.ClientConfig{
			Logger: libLogger,
			Proto:  dnscrypt.ProtoTCP,
		}),
		dialUDP: dialUDP,
		dialTCP: dialTCP,
	}, nil
}

// ExchangeContext exchanges query message m to the upstream, and returns
// response. It does not keep or modify m.
func (u *Upstream) ExchangeContext(ctx context.Context, m []byte) (_ *[]byte, err error) {
	defer func() {
		if err != nil && ctx.Err() != nil {
			err = context.Cause(ctx)
		}
	}()
	req := new(dns.Msg)
	if err := req.Unpack(m); err != nil {
		return nil, fmt.Errorf("invalid query message, %w", err)
	}

	ri, err := u.fetchResolverInfo(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := u.exchange(ctx, req, ri)
	if err != nil {
		return nil, err
	}
	return pool.PackBuffer(resp)
}

func (u *Upstream) exchange(ctx context.Context, req *dns.Msg, ri *dnscrypt.ResolverInfo) (*dns.Msg, error) {
	conn, err := u.dialUDP(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to dial udp conn, %w", err)
	}
	stop := closeOnCancel(ctx, conn)
	resp, err := u.udpClt.ExchangeConnContext(ctx, conn, req, ri)
	stop()
	conn.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to exchange query, %w", err)
	}

	// Retry over tcp if the udp response is truncated.
	if resp.Truncated {
		u.logger.Debug("dnscrypt udp response truncated, retrying over tcp")
		conn, err := u.dialTCP(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to dial tcp conn, %w", err)
		}
		stop := closeOnCancel(ctx, conn)
		resp, err = u.tcpClt.ExchangeConnContext(ctx, conn, req, ri)
		stop()
		conn.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to exchange query via tcp, %w", err)
		}
	}

	if resp.Id != req.Id {
		return nil, dns.ErrId
	}
	return resp, nil
}

// fetchResolverInfo returns the resolver info with a valid (not expired)
// certificate. It fetches the certificate on first use, and re-fetches
// it when the cached one expired.
func (u *Upstream) fetchResolverInfo(ctx context.Context) (*dnscrypt.ResolverInfo, error) {
	u.mu.RLock()
	ri := u.ri
	u.mu.RUnlock()
	if ri != nil && ri.ResolverCert.VerifyDate() {
		return ri, nil
	}

	select {
	case u.fetchSem <- struct{}{}:
		defer func() { <-u.fetchSem }()
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	// Re-check. Another goroutine may have fetched it.
	u.mu.RLock()
	ri = u.ri
	u.mu.RUnlock()
	if ri != nil && ri.ResolverCert.VerifyDate() {
		return ri, nil
	}

	ri, err := u.fetchCertificate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch resolver certificate, %w", err)
	}
	u.mu.Lock()
	u.ri = ri
	u.mu.Unlock()
	return ri, nil
}

func closeOnCancel(ctx context.Context, conn net.Conn) func() bool {
	return context.AfterFunc(ctx, func() { conn.Close() })
}

// Close implements the io.Closer interface. It is a no-op.
// DNSCrypt has no persistent connection to close.
func (u *Upstream) Close() error {
	return nil
}
