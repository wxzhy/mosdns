package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
)

type observedWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *observedWriteConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(b)
}

func cancellationQuery(t *testing.T) []byte {
	t.Helper()
	b, err := new(dns.Msg).SetQuestion("write-cancel.example.", dns.TypeA).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func waitExchangeError(t *testing.T, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("exchange error = %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("exchange did not stop promptly")
	}
}

func TestTCPActiveWriteCancellation(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(map[bool]string{false: "reuse", true: "pipeline"}[pipeline], func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			conn := &observedWriteConn{Conn: a, started: make(chan struct{})}
			var exchange func(context.Context, []byte) (*[]byte, error)
			var closeConn func() error
			if pipeline {
				dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: true}, conn)
				exchange = dc.exchange
				closeConn = dc.Close
			} else {
				tr := NewReuseConnTransport(ReuseConnOpts{DialContext: func(context.Context) (NetConn, error) { return conn, nil }})
				exchange = tr.ExchangeContext
				closeConn = tr.Close
			}
			defer closeConn()
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			cause := errors.New("caller abandoned blocked write")
			done := make(chan error, 1)
			q := cancellationQuery(t)
			go func() { _, err := exchange(ctx, q); done <- err }()
			select {
			case <-conn.started:
			case <-time.After(time.Second):
				t.Fatal("write did not start")
			}
			cancel(cause)
			waitExchangeError(t, done, cause)
		})
	}
}

func TestTCPPipelineCanceledQueuedWriterPreservesActiveQuery(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	conn := &observedWriteConn{Conn: a, started: make(chan struct{})}
	dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: true}, conn)
	defer dc.Close()
	q := cancellationQuery(t)
	first := make(chan error, 1)
	go func() {
		resp, err := dc.exchange(context.Background(), q)
		if resp != nil {
			pool.ReleaseBuf(resp)
		}
		first <- err
	}()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("first write did not start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() { _, err := dc.exchange(ctx, q); second <- err }()
	deadline := time.Now().Add(time.Second)
	for dc.queueLen() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dc.queueLen() < 2 {
		t.Fatal("second query did not enter write queue")
	}
	cancel()
	select {
	case err := <-second:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued query error = %v", err)
		}
	case <-time.After(time.Second):
		// Close the pipe so the pre-fix synchronous Write can be joined.
		b.Close()
		<-first
		<-second
		t.Fatal("canceled queued query remained blocked behind another write")
	}
	if dc.IsClosed() {
		t.Fatal("canceling queued writer closed the active connection")
	}
	request, err := dnsutils.ReadRawMsgFromTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(request)
	if _, err = dnsutils.WriteRawMsgToTCP(b, *request); err != nil {
		t.Fatal(err)
	}
	waitExchangeError(t, first, nil)
	// The canceled writer must not leave a deadline that breaks reuse.
	third := make(chan error, 1)
	go func() {
		resp, err := dc.exchange(context.Background(), q)
		if resp != nil {
			pool.ReleaseBuf(resp)
		}
		third <- err
	}()
	request2, err := dnsutils.ReadRawMsgFromTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(request2)
	if _, err = dnsutils.WriteRawMsgToTCP(b, *request2); err != nil {
		t.Fatal(err)
	}
	waitExchangeError(t, third, nil)
}

func TestTCPWriteDeadlineStopsBlockedWrite(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: true}, a)
	defer dc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	q := cancellationQuery(t)
	go func() { _, err := dc.exchange(ctx, q); done <- err }()
	waitExchangeError(t, done, context.DeadlineExceeded)
}

// A partial DNS-over-TCP frame cannot be recovered for the next query.
type partialWriteConn struct {
	net.Conn
}

func (c partialWriteConn) Write([]byte) (int, error) { return 1, io.ErrShortWrite }

func TestTCPPipelinePartialWriteClosesConnection(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: true}, partialWriteConn{a})
	defer dc.Close()
	if _, err := dc.exchange(context.Background(), cancellationQuery(t)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial write error = %v", err)
	}
	if !dc.IsClosed() {
		t.Fatal("partial TCP frame left connection reusable")
	}
}

type delayedWriteReturnConn struct {
	net.Conn
	written   chan struct{}
	finish    chan struct{}
	returnErr error
	once      sync.Once
}

func (c *delayedWriteReturnConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.once.Do(func() { close(c.written) })
	<-c.finish
	if c.returnErr != nil {
		return n, c.returnErr
	}
	return n, err
}

func TestReuseDoesNotPublishConnectionBeforeWriteFinishes(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	conn := &delayedWriteReturnConn{Conn: a, written: make(chan struct{}), finish: make(chan struct{})}
	tr := NewReuseConnTransport(ReuseConnOpts{DialContext: func(context.Context) (NetConn, error) { return conn, nil }})
	defer tr.Close()
	var finishOnce sync.Once
	defer finishOnce.Do(func() { close(conn.finish) })
	done := make(chan error, 1)
	q := cancellationQuery(t)
	go func() {
		resp, err := tr.ExchangeContext(context.Background(), q)
		if resp != nil {
			pool.ReleaseBuf(resp)
		}
		done <- err
	}()
	request, err := dnsutils.ReadRawMsgFromTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(request)
	<-conn.written
	if _, err = dnsutils.WriteRawMsgToTCP(b, *request); err != nil {
		t.Fatal(err)
	}
	// The read loop has consumed the response. Wait until it publishes to
	// the waiter, while the current Write still owns its deadline callback.
	var rc *reusableConn
	tr.m.Lock()
	for c := range tr.conns {
		rc = c
	}
	tr.m.Unlock()
	deadline := time.Now().Add(time.Second)
	for {
		rc.m.Lock()
		hasResponse := rc.waitingResp == nil
		rc.m.Unlock()
		if hasResponse {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("response was not delivered")
		}
		time.Sleep(time.Millisecond)
	}
	tr.m.Lock()
	idle := len(tr.idleConns)
	tr.m.Unlock()
	if idle != 0 {
		t.Fatal("connection published while previous Write still owns deadline")
	}
	finishOnce.Do(func() { close(conn.finish) })
	waitExchangeError(t, done, nil)
}

func TestReuseWriteCancellationDrainsEarlyResponse(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	conn := &delayedWriteReturnConn{Conn: a, written: make(chan struct{}), finish: make(chan struct{}), returnErr: io.ErrClosedPipe}
	tr := NewReuseConnTransport(ReuseConnOpts{DialContext: func(context.Context) (NetConn, error) { return conn, nil }})
	defer tr.Close()
	var finishOnce sync.Once
	defer finishOnce.Do(func() { close(conn.finish) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	q := cancellationQuery(t)
	go func() {
		resp, err := tr.ExchangeContext(ctx, q)
		if resp != nil {
			pool.ReleaseBuf(resp)
		}
		done <- err
	}()
	request, err := dnsutils.ReadRawMsgFromTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(request)
	<-conn.written
	var rc *reusableConn
	tr.m.Lock()
	for c := range tr.conns {
		rc = c
	}
	tr.m.Unlock()
	rc.m.Lock()
	waiter := rc.waitingResp
	rc.m.Unlock()
	if waiter == nil {
		t.Fatal("query waiter missing before response")
	}
	if _, err = dnsutils.WriteRawMsgToTCP(b, *request); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(waiter.ch) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(waiter.ch) == 0 {
		t.Fatal("response was not queued before Write returned")
	}
	cancel()
	finishOnce.Do(func() { close(conn.finish) })
	waitExchangeError(t, done, context.Canceled)
	waiter.mu.Lock()
	abandoned := waiter.abandoned
	remaining := len(waiter.ch)
	waiter.mu.Unlock()
	if !abandoned || remaining != 0 {
		t.Fatalf("failed write left response owned by abandoned waiter: abandoned=%v queued=%d", abandoned, remaining)
	}
	tr.m.Lock()
	remainingConns := len(tr.conns)
	tr.m.Unlock()
	if remainingConns != 0 {
		t.Fatal("canceled active write left connection reusable")
	}
}

func TestTCPPipelineWriteFailureDrainsEarlyResponse(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	conn := &delayedWriteReturnConn{Conn: a, written: make(chan struct{}), finish: make(chan struct{}), returnErr: io.ErrClosedPipe}
	dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: true}, conn)
	defer dc.Close()
	var finishOnce sync.Once
	defer finishOnce.Do(func() { close(conn.finish) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	q := cancellationQuery(t)
	go func() {
		resp, err := dc.exchange(ctx, q)
		if resp != nil {
			pool.ReleaseBuf(resp)
		}
		done <- err
	}()
	request, err := dnsutils.ReadRawMsgFromTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(request)
	<-conn.written
	dc.queueMu.RLock()
	ch := dc.queue[uint32(binary.BigEndian.Uint16(*request))]
	dc.queueMu.RUnlock()
	if ch == nil {
		t.Fatal("query queue missing before response")
	}
	if _, err = dnsutils.WriteRawMsgToTCP(b, *request); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(ch) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(ch) == 0 {
		t.Fatal("response was not queued while Write was finishing")
	}
	cancel()
	finishOnce.Do(func() { close(conn.finish) })
	waitExchangeError(t, done, context.Canceled)
	if len(ch) != 0 || dc.queueLen() != 0 {
		t.Fatal("write failure stranded queued response")
	}
}

func TestTraditionalResponseDeliveryAfterRemoval(t *testing.T) {
	conn := &recordingConn{closed: make(chan struct{})}
	dc := NewDnsConn(TraditionalDnsConnOpts{}, conn)
	defer dc.Close()
	for range 100 {
		qid, ch := dc.addQueueC()
		dc.deliverResponse(qid, pool.GetBuf(16))
		if len(ch) != 1 {
			t.Fatal("response was not retained for active query")
		}
		dc.deleteQueueC(qid)
		if len(ch) != 0 {
			t.Fatal("removing query did not drain unread response")
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() { defer wg.Done(); dc.deliverResponse(qid, pool.GetBuf(16)) }()
		}
		wg.Wait()
		if len(ch) != 0 {
			t.Fatal("late delivery published into orphan response channel")
		}
	}
}

func TestTCPPipelineCompletedWriteCancellationKeepsConnection(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	conn := &delayedWriteReturnConn{Conn: a, written: make(chan struct{}), finish: make(chan struct{})}
	dc := NewDnsConn(TraditionalDnsConnOpts{WithLengthHeader: true}, conn)
	defer dc.Close()
	var finishOnce sync.Once
	defer finishOnce.Do(func() { close(conn.finish) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	q := cancellationQuery(t)
	go func() {
		resp, err := dc.exchange(ctx, q)
		if resp != nil {
			pool.ReleaseBuf(resp)
		}
		done <- err
	}()
	request, err := dnsutils.ReadRawMsgFromTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	pool.ReleaseBuf(request)
	<-conn.written
	cancel()
	finishOnce.Do(func() { close(conn.finish) })
	waitExchangeError(t, done, context.Canceled)
	if dc.IsClosed() {
		t.Fatal("cancellation after complete successful write closed healthy connection")
	}
	next := make(chan error, 1)
	go func() {
		resp, err := dc.exchange(context.Background(), q)
		if resp != nil {
			pool.ReleaseBuf(resp)
		}
		next <- err
	}()
	request, err = dnsutils.ReadRawMsgFromTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.ReleaseBuf(request)
	if _, err = dnsutils.WriteRawMsgToTCP(b, *request); err != nil {
		t.Fatal(err)
	}
	waitExchangeError(t, next, nil)
}

func TestReuseCanceledBeforeWriteHonorsIdleTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	tr := NewReuseConnTransport(ReuseConnOpts{IdleTimeout: 20 * time.Millisecond})
	defer tr.Close()
	rc := tr.newReusableConn(a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rc.exchange(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("exchange error = %v", err)
	}
	select {
	case <-rc.closeNotify:
	case <-time.After(time.Second):
		t.Fatal("new idle connection survived its idle timeout after canceled query")
	}
}
