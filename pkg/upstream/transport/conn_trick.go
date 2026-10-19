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

package transport

import (
	"errors"
	"net"
)

var errPartialOOBPrefix = errors.New("tcp trick: partial out-of-band prefix was sent, the dns frame is corrupted")

// TcpTrickConn is a tcp connection that sends the first 16 bytes of each
// dns frame (plus one urgent byte) as TCP out-of-band data, followed by
// the rest of the frame inline. Middleboxes that don't process urgent
// data can't reassemble the dns query from the stream. (smartdns's
// "use_tricks" tcp trick)
//
// The trick is best-effort. If the out-of-band send is not supported or
// failed without sending anything, the whole frame is sent normally.
type TcpTrickConn struct {
	net.Conn
}

var _ net.Conn = (*TcpTrickConn)(nil)

// NewTcpTrickConn wraps c with a TcpTrickConn.
func NewTcpTrickConn(c net.Conn) net.Conn {
	return &TcpTrickConn{Conn: c}
}

func (c *TcpTrickConn) Write(b []byte) (n int, err error) {
	if len(b) <= 32 {
		return c.Conn.Write(b)
	}

	// Only the last byte of an out-of-band send is carried out of the
	// normal stream (SO_OOBINLINE is off by default). Thus the first 16
	// bytes of the frame go inline, followed by one urgent byte that is
	// invisible to the stream reader, then the rest of the frame.
	prefix := make([]byte, 17)
	copy(prefix, b[:16])
	sent, err := sendOOB(c.Conn, prefix)
	if err != nil || sent == 0 {
		// Best effort. Nothing was sent, fall back to the normal send.
		return c.Conn.Write(b)
	}
	if sent != len(prefix) {
		// A partial prefix is already in the stream. Sending the frame
		// again would corrupt the length prefixed stream. Let this
		// exchange fail. The caller should drop this connection.
		return 0, errPartialOOBPrefix
	}
	if _, err := c.Conn.Write(b[16:]); err != nil {
		return 0, err
	}
	return len(b), nil
}
