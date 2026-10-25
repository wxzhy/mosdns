package transport

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// A configured dial timeout must reach the dial context. Previously the
// parameter was normalized but the context always used defaultDialTimeout,
// silently capping every dial at 5s.
func Test_lazyDnsConn_honors_configured_dial_timeout(t *testing.T) {
	deadlineCh := make(chan time.Time, 1)
	lc := newLazyDnsConn(func(ctx context.Context) (DnsConn, error) {
		if d, ok := ctx.Deadline(); ok {
			deadlineCh <- d
		}
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}, 200*time.Millisecond, 1, zap.NewNop())
	defer lc.Close()

	select {
	case d := <-deadlineCh:
		remaining := time.Until(d)
		require.Greater(t, remaining, 100*time.Millisecond)
		require.Less(t, remaining, 2*time.Second)
	case <-time.After(2 * time.Second):
		t.Fatal("dial was not started")
	}
}
