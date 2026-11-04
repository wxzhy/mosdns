package transport

import (
	"io"
	"sync"
	"testing"
	"time"
)

type blockingCloseConn struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*blockingCloseConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (*blockingCloseConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *blockingCloseConn) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return nil
}
func (*blockingCloseConn) SetDeadline(time.Time) error      { return nil }
func (*blockingCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingCloseConn) SetWriteDeadline(time.Time) error { return nil }

func TestReuseCloseReleasesPoolLockBeforeClosingSocket(t *testing.T) {
	tr := NewReuseConnTransport(ReuseConnOpts{})
	c := &blockingCloseConn{entered: make(chan struct{}), release: make(chan struct{})}
	rc := &reusableConn{c: c, t: tr, closeNotify: make(chan struct{})}
	tr.conns[rc] = struct{}{}
	closed := make(chan struct{})
	go func() { tr.Close(); close(closed) }()
	<-c.entered
	locked := make(chan struct{})
	go func() { tr.m.Lock(); tr.m.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		close(c.release)
		<-closed
		<-locked
		t.Fatal("transport Close held pool lock while closing socket; error-close has inverse lock order")
	}
	// Concurrent Close calls must wait until the same socket close finishes.
	second := make(chan struct{})
	go func() { tr.Close(); close(second) }()
	select {
	case <-second:
		t.Error("concurrent Close returned before socket cleanup finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(c.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("first Close stuck")
	}
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("concurrent Close stuck")
	}
}

func TestReuseConcurrentCloseAndConnectionError(t *testing.T) {
	for range 100 {
		tr := NewReuseConnTransport(ReuseConnOpts{})
		c := &blockingCloseConn{entered: make(chan struct{}), release: make(chan struct{})}
		close(c.release)
		rc := &reusableConn{c: c, t: tr, closeNotify: make(chan struct{})}
		tr.conns[rc] = struct{}{}
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); tr.Close() }()
		go func() { defer wg.Done(); rc.closeWithErr(io.EOF) }()
		go func() { defer wg.Done(); tr.Close() }()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("connection error raced with Close and deadlocked")
		}
	}
}
