//go:build windows

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
	"net"
	"syscall"
	"unsafe"
)

// Winsock's send() also works on non-blocking sockets. It returns
// WSAEWOULDBLOCK without sending anything if the socket send buffer
// is full.
var wsaSendProc = syscall.NewLazyDLL("ws2_32.dll").NewProc("send")

const msgOOB = 0x1

// sendOOB sends b to the peer as TCP out-of-band data. It does not
// change the blocking state of the Go managed socket. If the socket
// send buffer is full, it returns an error without sending anything.
func sendOOB(c net.Conn, b []byte) (n int, err error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, syscall.EINVAL
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		ret, _, e := wsaSendProc.Call(fd, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), msgOOB)
		if ret == ^uintptr(0) { // SOCKET_ERROR
			serr = e
			n = 0
		} else {
			n = int(ret)
		}
	}); err != nil {
		return 0, err
	}
	return n, serr
}
