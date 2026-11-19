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

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

const (
	defaultQuicIdleTimeout = time.Second * 30
	streamReadTimeout      = time.Second * 2
	streamWriteTimeout     = time.Second * 5
	quicFirstReadTimeout   = time.Second * 2
)

type DoQServerOpts struct {
	Logger      *zap.Logger
	IdleTimeout time.Duration
}

// ServeDoQ starts a server at l. It returns if l had an Accept() error.
// It always returns a non-nil error.
func ServeDoQ(l *quic.Listener, h Handler, opts DoQServerOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultQuicIdleTimeout
	}

	listenerCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(errListenerCtxCanceled)
	for {
		c, err := l.Accept(listenerCtx)
		if err != nil {
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		go serveDoQConn(listenerCtx, c, h, logger, idleTimeout)
	}
}

func serveDoQConn(parent context.Context, c *quic.Conn, h Handler, logger *zap.Logger, idleTimeout time.Duration) {
	connCtx, cancel := context.WithCancelCause(parent)
	defer c.CloseWithError(0, "")

	var idleMu sync.Mutex
	var pending int
	idleDeadline := time.Now().Add(quicFirstReadTimeout)
	idleTimer := time.AfterFunc(time.Until(idleDeadline), func() {
		idleMu.Lock()
		defer idleMu.Unlock()
		// An earlier callback may still be running after Stop or Reset.
		if !idleDeadline.IsZero() && !time.Now().Before(idleDeadline) {
			cancel(errConnectionCtxCanceled)
		}
	})
	defer func() {
		cancel(errConnectionCtxCanceled)
		idleMu.Lock()
		idleTimer.Stop()
		idleMu.Unlock()
	}()

	meta := QueryMeta{ServerName: c.ConnectionState().TLS.ServerName, Protocol: "DoQ"}
	if remote, ok := c.RemoteAddr().(*net.UDPAddr); ok {
		meta.ClientAddr = remote.AddrPort().Addr()
	}
	for {
		stream, err := c.AcceptStream(connCtx)
		if err != nil {
			return
		}
		idleMu.Lock()
		if connCtx.Err() != nil {
			idleMu.Unlock()
			return
		}
		if pending == 0 {
			idleDeadline = time.Time{}
			idleTimer.Stop()
		}
		pending++
		idleMu.Unlock()

		go func() {
			defer func() {
				idleMu.Lock()
				defer idleMu.Unlock()
				pending--
				if pending == 0 && connCtx.Err() == nil {
					idleDeadline = time.Now().Add(idleTimeout)
					idleTimer.Reset(time.Until(idleDeadline))
				}
			}()
			serveDoQStream(connCtx, c, stream, h, meta, logger)
		}()
	}
}

func serveDoQStream(connCtx context.Context, c *quic.Conn, stream *quic.Stream, h Handler, meta QueryMeta, logger *zap.Logger) {
	stream.SetReadDeadline(time.Now().Add(streamReadTimeout))
	payload, err := dnsutils.ReadDoQFrame(stream, false)
	if err != nil {
		if errors.Is(err, dnsutils.ErrDoQProtocol) {
			c.CloseWithError(dnsutils.DoQProtocolErrorCode, err.Error())
		}
		stream.CancelRead(0x3)
		stream.CancelWrite(0x3)
		return
	}
	req := new(dns.Msg)
	err = req.Unpack(*payload)
	pool.ReleaseBuf(payload)
	if err != nil {
		c.CloseWithError(dnsutils.DoQProtocolErrorCode, "malformed DNS message")
		return
	}

	// The stream context tracks our send side, including a peer's
	// cancellation of its response reader. A normal request FIN
	// only closes the receive side and must leave the query alive.
	queryCtx, cancelQuery := context.WithCancelCause(connCtx)
	defer cancelQuery(nil)
	stopStreamCancel := context.AfterFunc(stream.Context(), func() {
		cancelQuery(context.Cause(stream.Context()))
	})
	defer stopStreamCancel()
	resp := h.Handle(queryCtx, req, meta, func(m *dns.Msg) (*[]byte, error) {
		reply := *m
		reply.Id = 0
		return pool.PackTCPBuffer(&reply)
	})
	if resp == nil {
		stream.CancelWrite(0x1)
		return
	}
	defer pool.ReleaseBuf(resp)
	stream.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	n, err := stream.Write(*resp)
	if err == nil && n != len(*resp) {
		err = io.ErrShortWrite
	}
	if err != nil {
		stream.CancelWrite(0x1)
		logger.Warn("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
		return
	}
	_ = stream.Close()
}
