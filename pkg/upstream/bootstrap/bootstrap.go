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

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	minimumUpdateInterval = time.Minute * 5
	retryInterval         = time.Second * 2
	queryTimeout          = time.Second * 3
	udpRetryInterval      = time.Millisecond * 400
)

var (
	errNoAddrInResp = errors.New("resp does not have ip address")
)

func New(
	host string,
	port uint16,
	bootstrapServer netip.AddrPort,
	bootstrapVer int, // 0,4,6
	logger *zap.Logger, // not nil
) (*Bootstrap, error) {
	dp := new(Bootstrap)
	dp.fqdn = dns.Fqdn(host)
	dp.port = port
	if !bootstrapServer.IsValid() {
		return nil, errors.New("invalid bootstrap server address")
	}
	dp.bootstrap = net.UDPAddrFromAddrPort(bootstrapServer)
	qt, ok := bootstrapVer2Qt(bootstrapVer)
	if !ok {
		return nil, fmt.Errorf("invalid bootstrap version %d", bootstrapVer)
	}
	dp.qt = qt
	dp.logger = logger

	dp.readyNotify = make(chan struct{})
	return dp, nil
}

type Bootstrap struct {
	fqdn      string
	port      uint16
	bootstrap *net.UDPAddr
	qt        uint16      // dns.TypeA or dns.TypeAAAA
	logger    *zap.Logger // not nil

	updating   atomic.Bool
	nextUpdate time.Time

	readyNotify chan struct{}
	m           sync.Mutex
	ready       bool
	addrStr     string
}

func (sp *Bootstrap) GetAddrPortStr(ctx context.Context) (string, error) {
	sp.tryUpdate()

	select {
	case <-ctx.Done():
		return "", context.Cause(ctx)
	case <-sp.readyNotify:
	}

	sp.m.Lock()
	addr := sp.addrStr
	sp.m.Unlock()
	return addr, nil
}

func (sp *Bootstrap) tryUpdate() {
	if !sp.updating.CompareAndSwap(false, true) {
		return
	}
	if !time.Now().After(sp.nextUpdate) {
		sp.updating.Store(false)
		return
	}
	go func() {
		defer sp.updating.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		defer cancel()
		start := time.Now()
		addr, ttl, err := sp.updateAddr(ctx)
		if err != nil {
			sp.logger.Check(zap.WarnLevel, "failed to update bootstrap addr").Write(
				zap.String("fqdn", sp.fqdn),
				zap.Error(err),
			)
			sp.nextUpdate = time.Now().Add(retryInterval)
		} else {
			updateInterval := time.Second * time.Duration(ttl)
			if updateInterval < minimumUpdateInterval {
				updateInterval = minimumUpdateInterval
			}
			sp.logger.Check(zap.DebugLevel, "bootstrap addr updated").Write(
				zap.String("fqdn", sp.fqdn),
				zap.Stringer("addr", addr),
				zap.Duration("ttl", updateInterval),
				zap.Duration("elapse", time.Since(start)),
			)
			sp.nextUpdate = time.Now().Add(updateInterval)
		}
	}()
}

func (sp *Bootstrap) updateAddr(ctx context.Context) (netip.Addr, uint32, error) {
	addr, ttl, err := sp.resolve(ctx, sp.qt)
	if err != nil {
		return netip.Addr{}, 0, err
	}

	addrPort := netip.AddrPortFrom(addr, sp.port).String()
	sp.m.Lock()
	sp.addrStr = addrPort
	if !sp.ready {
		sp.ready = true
		close(sp.readyNotify)
	}
	sp.m.Unlock()
	return addr, ttl, nil
}

func (sp *Bootstrap) resolve(ctx context.Context, qt uint16) (netip.Addr, uint32, error) {
	const edns0UdpSize = 1232

	q := new(dns.Msg)
	q.SetQuestion(sp.fqdn, qt)
	q.SetEdns0(edns0UdpSize, false)

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	resp, err := sp.exchangeUDP(ctx, q, edns0UdpSize)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if resp.Truncated {
		tcp := dns.Client{Net: "tcp", Timeout: queryTimeout}
		resp, _, err = tcp.ExchangeContext(ctx, q, sp.bootstrap.String())
		if err != nil {
			return netip.Addr{}, 0, fmt.Errorf("bootstrap TCP exchange: %w", err)
		}
	}
	return bootstrapAddress(q, resp)
}

func (sp *Bootstrap) exchangeUDP(ctx context.Context, q *dns.Msg, size int) (*dns.Msg, error) {
	c, err := net.DialUDP("udp", nil, sp.bootstrap)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	buf := make([]byte, size)
	for ctx.Err() == nil {
		deadline := time.Now().Add(udpRetryInterval)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err := c.SetDeadline(deadline); err != nil {
			return nil, err
		}
		if _, err := dnsutils.WriteMsgToUDP(c, q); err != nil {
			return nil, err
		}
		for ctx.Err() == nil {
			n, err := c.Read(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				if ctx.Err() != nil {
					return nil, context.Cause(ctx)
				}
				return nil, err
			}
			r := new(dns.Msg)
			if r.Unpack(buf[:n]) == nil && dnsutils.MatchesResponse(q, r) {
				return r, nil
			}
		}
	}
	return nil, context.Cause(ctx)
}

func bootstrapAddress(q, r *dns.Msg) (netip.Addr, uint32, error) {
	if !dnsutils.MatchesResponse(q, r) || r.Truncated || r.Rcode != dns.RcodeSuccess {
		return netip.Addr{}, 0, errors.New("invalid bootstrap response")
	}
	question := q.Question[0]
	terminal, ttl, ok := dnsutils.AnswerChain(question, r.Answer)
	if !ok {
		return netip.Addr{}, 0, errNoAddrInResp
	}
	var addr netip.Addr
	for _, rr := range r.Answer {
		h := rr.Header()
		if h.Class != question.Qclass || h.Rrtype != question.Qtype || dns.CanonicalName(h.Name) != terminal {
			continue
		}
		var ip netip.Addr
		switch rr := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(rr.A.To4())
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(rr.AAAA.To16())
		}
		if ip.IsValid() {
			if !addr.IsValid() {
				addr = ip
			}
			ttl = min(ttl, h.Ttl)
		}
	}
	if !addr.IsValid() {
		return netip.Addr{}, 0, errNoAddrInResp
	}
	return addr, ttl, nil
}

func bootstrapVer2Qt(ver int) (uint16, bool) {
	switch ver {
	case 0, 4:
		return dns.TypeA, true
	case 6:
		return dns.TypeAAAA, true
	default:
		return 0, false
	}
}
