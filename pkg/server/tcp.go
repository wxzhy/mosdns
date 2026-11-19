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
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"go.uber.org/zap"
)

const (
	defaultTCPIdleTimeout = time.Second * 10
	tcpFirstReadTimeout   = time.Second * 2
	tcpWriteTimeout       = time.Second * 5
)

type TCPServerOpts struct {
	// Nil logger == nop
	Logger *zap.Logger

	// Default is defaultTCPIdleTimeout.
	IdleTimeout time.Duration
}

// ServeTCP starts a server at l. It returns if l had an Accept() error.
// It always returns a non-nil error.
func ServeTCP(l net.Listener, h Handler, opts TCPServerOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	listenerCtx, cancel := context.WithCancelCause(context.Background())
	var connections sync.WaitGroup
	defer func() {
		cancel(errListenerCtxCanceled)
		connections.Wait()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		connections.Add(1)
		go func() {
			defer connections.Done()
			serveTCPConn(listenerCtx, c, h, logger, idleTimeout)
		}()
	}
}

func serveTCPConn(parent context.Context, c net.Conn, h Handler, logger *zap.Logger, idleTimeout time.Duration) {
	ctx, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	var queries sync.WaitGroup
	defer func() {
		stop()
		cancel(errConnectionCtxCanceled)
		_ = c.Close()
		queries.Wait()
	}()

	remote := c.RemoteAddr()
	var clientAddr netip.Addr
	if ta, ok := remote.(*net.TCPAddr); ok {
		clientAddr = ta.AddrPort().Addr()
	}
	reader := bufio.NewReader(c)
	firstDeadline := time.Now().Add(min(tcpFirstReadTimeout, idleTimeout))
	_ = c.SetReadDeadline(firstDeadline)
	var readMu sync.Mutex
	var writeMu sync.Mutex
	var pending int
	var readingFrame bool
	for ctx.Err() == nil {
		if _, err := reader.Peek(1); err != nil {
			return
		}
		// A partial frame needs a deadline even while other queries run.
		readMu.Lock()
		readingFrame = true
		frameDeadline := firstDeadline
		if frameDeadline.IsZero() {
			frameDeadline = time.Now().Add(idleTimeout)
		}
		_ = c.SetReadDeadline(frameDeadline)
		readMu.Unlock()

		req, _, err := dnsutils.ReadMsgFromTCP(reader)
		if err != nil || ctx.Err() != nil {
			return
		}
		firstDeadline = time.Time{}
		readMu.Lock()
		readingFrame = false
		pending++
		_ = c.SetReadDeadline(time.Time{})
		readMu.Unlock()

		meta := QueryMeta{ClientAddr: clientAddr, Protocol: "TCP"}
		if tlsConn, ok := c.(*tls.Conn); ok {
			meta.ServerName = tlsConn.ConnectionState().ServerName
			meta.Protocol = "DoT"
		}
		queries.Add(1)
		go func() {
			defer queries.Done()
			defer func() {
				readMu.Lock()
				pending--
				if pending == 0 && !readingFrame {
					_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
				}
				readMu.Unlock()
			}()
			if ctx.Err() != nil {
				return
			}
			r := h.Handle(ctx, req, meta, pool.PackTCPBuffer)
			if r == nil {
				_ = c.Close()
				return
			}
			defer pool.ReleaseBuf(r)

			writeMu.Lock()
			defer writeMu.Unlock()
			if ctx.Err() != nil {
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
			n, err := c.Write(*r)
			if err == nil && n != len(*r) {
				err = io.ErrShortWrite
			}
			if err != nil {
				logger.Warn("failed to write response", zap.Stringer("client", remote), zap.Error(err))
				_ = c.Close()
			}
		}()
	}
}
