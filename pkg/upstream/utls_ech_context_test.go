package upstream

import (
	"bytes"
	"context"
	"testing"
	"time"
)

type blockingECHUpstream struct {
	entered chan struct{}
	closed  chan struct{}
}

func (u *blockingECHUpstream) ExchangeContext(ctx context.Context, _ []byte) (*[]byte, error) {
	close(u.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (u *blockingECHUpstream) Close() error { close(u.closed); return nil }

func TestECHResolverWaitCancellationAndClose(t *testing.T) {
	r, err := newECHConfigResolver("test.example+udp://127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	u := &blockingECHUpstream{entered: make(chan struct{}), closed: make(chan struct{})}
	r.u = u
	t.Cleanup(func() { r.Close() })
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		r.getConfigList(context.Background())
	}()
	select {
	case <-u.entered:
	case <-time.After(time.Second):
		t.Fatal("first ECH lookup did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	secondDone := make(chan []byte, 1)
	go func() { secondDone <- r.getConfigList(ctx) }()
	select {
	case got := <-secondDone:
		if !bytes.Equal(got, invalidECHConfigList) {
			t.Fatal("canceled lookup did not fail closed")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled lookup waited for another caller's ECH refresh")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- r.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the active ECH lookup")
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("active lookup did not stop after Close")
	}
	select {
	case <-u.closed:
	default:
		t.Fatal("Close did not release the lookup upstream")
	}
}
