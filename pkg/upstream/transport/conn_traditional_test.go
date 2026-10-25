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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type dummyEchoNetConn struct {
	net.Conn
	rErrProb float64
	rLatency time.Duration
	wErrProb float64

	closeOnce   sync.Once
	closeNotify chan struct{}
}

func newDummyEchoNetConn(rErrProb float64, rLatency time.Duration, wErrProb float64) NetConn {
	c1, c2 := net.Pipe()
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		defer c1.Close()
		defer c2.Close()
		for {
			m, readErr := dnsutils.ReadRawMsgFromTCP(c2)
			if m != nil {
				go func() {
					defer pool.ReleaseBuf(m)
					if rLatency > 0 {
						t := time.NewTimer(rLatency)
						defer t.Stop()
						select {
						case <-t.C:
						case <-ctx.Done():
							return
						}
					}
					latency := time.Millisecond * time.Duration(rand.Intn(20))
					time.Sleep(latency)
					_, _ = dnsutils.WriteRawMsgToTCP(c2, *m)
				}()
			}
			if readErr != nil {
				return
			}
		}
	}()
	return &dummyEchoNetConn{
		Conn:        c1,
		rErrProb:    rErrProb,
		rLatency:    rLatency,
		wErrProb:    wErrProb,
		closeNotify: make(chan struct{}),
	}
}

func probTrue(p float64) bool {
	return rand.Float64() < p
}

func (d *dummyEchoNetConn) Read(p []byte) (n int, err error) {
	if probTrue(d.rErrProb) {
		return 0, errors.New("read err")
	}
	return d.Conn.Read(p)
}

func (d *dummyEchoNetConn) Write(p []byte) (n int, err error) {
	if probTrue(d.wErrProb) {
		return 0, errors.New("write err")
	}
	return d.Conn.Write(p)
}

func (d *dummyEchoNetConn) Close() error {
	d.closeOnce.Do(func() {
		close(d.closeNotify)
	})
	return d.Conn.Close()
}

func Test_dnsConn_exchange(t *testing.T) {
	idleTimeout := time.Millisecond * 100

	tests := []struct {
		name       string
		rErrProb   float64
		rLatency   time.Duration
		wErrProb   float64
		connClosed bool // connection is closed before calling exchange()
		wantMsg    bool
		wantErr    bool
	}{
		{
			name:     "normal",
			rErrProb: 0,
			rLatency: 0,
			wErrProb: 0,
			wantMsg:  true, wantErr: false,
		},
		{
			name:     "write err",
			rErrProb: 0,
			rLatency: 0,
			wErrProb: 1,
			wantMsg:  false, wantErr: true,
		},
		{
			name:     "read err",
			rErrProb: 1,
			rLatency: 0,
			wErrProb: 0,
			wantMsg:  false, wantErr: true,
		},
		{
			name:     "read timeout",
			rErrProb: 0,
			rLatency: idleTimeout * 3,
			wErrProb: 0,
			wantMsg:  false, wantErr: true,
		},
		{
			name:       "connection closed",
			rErrProb:   0,
			rLatency:   0,
			wErrProb:   0,
			connClosed: true,
			wantMsg:    false, wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			c := newDummyEchoNetConn(tt.rErrProb, tt.rLatency, tt.wErrProb)
			defer c.Close()
			ioOpts := TraditionalDnsConnOpts{
				WithLengthHeader: true, // TODO: Test false as well
				IdleTimeout:      idleTimeout,
			}
			dc := NewDnsConn(ioOpts, c)

			if tt.connClosed {
				dc.Close()
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
			defer cancel()
			q := new(dns.Msg)
			q.SetQuestion("test.", dns.TypeA)
			queryPayload, err := q.Pack()
			r.NoError(err)

			rec, closed := dc.ReserveNewQuery()
			r.Equal(tt.connClosed, closed)
			if rec == nil {
				return
			}

			respPayload, err := rec.ExchangeReserved(ctx, queryPayload)
			if tt.wantErr {
				r.Error(err)
			} else {
				r.NoError(err)
			}

			if tt.wantMsg {
				r.NotNil(respPayload)
				r.True(bytes.Equal(queryPayload, *respPayload))

				// test idle timeout
				time.Sleep(idleTimeout + time.Millisecond*20)
				runtime.Gosched()
				r.True(dc.IsClosed(), "connection should be closed due to idle timeout")
			} else {
				r.Nil(respPayload)
			}
		})
	}
}

// TODO: 测试 maxconcurrentquery。

func Test_dnsConn_exchange_race(t *testing.T) {
	r := require.New(t)
	wg := new(sync.WaitGroup)
	for i := 0; i < 1024; i++ {
		c := newDummyEchoNetConn(0.5, time.Millisecond*20, 0.5)
		ioOpts := TraditionalDnsConnOpts{
			WithLengthHeader: true, // TODO: Test false as well
			IdleTimeout:      time.Millisecond * 50,
		}
		dc := NewDnsConn(ioOpts, c)
		for j := 0; j < 24; j++ {
			if dc.IsClosed() {
				break
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
				defer cancel()
				q := new(dns.Msg)
				q.SetQuestion("test.", dns.TypeA)
				queryPayload, err := q.Pack()
				r.NoError(err)

				rec, closed := dc.ReserveNewQuery()
				if closed {
					return
				}
				if rec != nil {
					_, _ = rec.ExchangeReserved(ctx, queryPayload)
				}
			}()
		}
	}
	wg.Wait()
}

type recordingConn struct {
	writes [][]byte
	closed chan struct{}
	once   sync.Once
}

func (c *recordingConn) Read([]byte) (int, error) { <-c.closed; return 0, io.EOF }
func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(b))
	return len(b), nil
}
func (c *recordingConn) Close() error                   { c.once.Do(func() { close(c.closed) }); return nil }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }

func TestTraditionalRepeatOnlyUDP(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		q := make([]byte, 12)
		conn := &recordingConn{closed: make(chan struct{})}
		dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: tcp, Repeat: 2}, conn)
		if err := dc.writeQuery(q, 42); err != nil {
			t.Fatal(err)
		}
		dc.Close()
		want := 3
		if tcp {
			want = 1
		}
		if len(conn.writes) != want {
			t.Fatalf("tcp=%v wrote %d copies, want %d", tcp, len(conn.writes), want)
		}
		if !bytes.Equal(q, make([]byte, 12)) {
			t.Fatal("query modified")
		}
	}
}

type gatedWriteNetConn struct {
	net.Conn
	gate chan struct{}
}

func (c *gatedWriteNetConn) Write(b []byte) (int, error) {
	<-c.gate
	return c.Conn.Write(b)
}

// A reply that arrives while exchange is briefly inside writeQuery (e.g. its
// one-second resend tick) must be retained by the per-query channel instead
// of being discarded by readLoop's non-blocking send.
func Test_dnsConn_exchange_retains_reply_during_write(t *testing.T) {
	c1, c2 := net.Pipe()
	gate := make(chan struct{})
	dc := NewDnsConn(TraditionalDnsConnOpts{}, &gatedWriteNetConn{Conn: c1, gate: gate})
	defer dc.Close()

	// Drain the query direction so exchange's (gated) writes can complete;
	// net.Pipe writes block until the peer reads.
	go func() {
		_, _ = io.Copy(io.Discard, c2)
	}()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.Id = 0x1234
	qb, err := q.Pack()
	require.NoError(t, err)

	type res struct {
		resp *[]byte
		err  error
	}
	resCh := make(chan res, 1)
	go func() {
		resp, err := dc.exchange(context.Background(), qb)
		resCh <- res{resp: resp, err: err}
	}()

	// Wait until exchange has registered its query id and is blocked in
	// writeQuery on the gate.
	require.Eventually(t, func() bool { return dc.queueLen() > 0 },
		2*time.Second, time.Millisecond, "exchange did not register its query")

	// The server replies while exchange is still writing. The first query id
	// assigned by a fresh connection is 0.
	resp := bytes.Clone(qb)
	binary.BigEndian.PutUint16(resp, 0)
	go func() {
		_, _ = c2.Write(resp)
	}()
	time.Sleep(50 * time.Millisecond)

	close(gate)
	select {
	case r := <-resCh:
		require.NoError(t, r.err)
		require.NotNil(t, r.resp)
		require.Equal(t, uint16(0x1234), binary.BigEndian.Uint16(*r.resp))
	case <-time.After(2 * time.Second):
		t.Fatal("exchange did not return the reply that arrived during writeQuery")
	}
}
