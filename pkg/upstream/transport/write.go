package transport

import (
	"context"
	"io"
	"time"
)

// writeWithContext runs with exclusive ownership of conn's write side. The
// caller must not publish the connection for another write until this returns.
// A canceled write may have sent part of a TCP/TLS frame, even if its returned
// byte count is zero, so callers must close the connection on any error.
func writeWithContext(ctx context.Context, conn NetConn, payload []byte, copies int, deadline time.Time) error {
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetWriteDeadline(time.Now())
		close(interrupted)
	})

	var err error
	for range copies {
		var n int
		n, err = conn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		if err != nil {
			break
		}
	}
	if !stop() {
		// stop does not join a running AfterFunc. Join before resetting the
		// deadline or handing write ownership to the next query.
		<-interrupted
	}
	resetErr := conn.SetWriteDeadline(time.Time{})
	if err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		return err
	}
	// A complete successful frame is still valid if cancellation raced with
	// its completion. Let exchange observe cancellation without needlessly
	// closing a healthy connection shared by other queries.
	return resetErr
}
