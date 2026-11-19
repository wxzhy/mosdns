package fastforward

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestForwardRetainsDNSReplyAfterTransportError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := query_context.NewContext(new(dns.Msg).SetQuestion("example.", dns.TypeA))
		refused := newWrapper(0, UpstreamConfig{Addr: "refused.test"}, "refused")
		refused.u = responseTestUpstream{new(dns.Msg).SetRcode(q.Q(), dns.RcodeRefused)}
		releaseError := make(chan struct{})
		failed := newWrapper(1, UpstreamConfig{Addr: "failed.test"}, "failed")
		failed.u = cancelTestUpstream{fn: func(context.Context) error {
			<-releaseError
			return errors.New("simulated upstream network error")
		}}

		f := &Forward{args: &Args{Concurrent: 2}, logger: zap.NewNop()}
		result := make(chan error, 1)
		var response *dns.Msg
		go func() {
			var err error
			response, err = f.exchange(context.Background(), q, []*upstreamWrapper{refused, failed})
			result <- err
		}()
		synctest.Wait()
		close(releaseError)
		if err := <-result; err != nil || response == nil || response.Rcode != dns.RcodeRefused {
			t.Fatalf("response=%v, err=%v; want the valid REFUSED reply", response, err)
		}
		if q.UpstreamSelected == nil || q.UpstreamSelected.Addr != "refused.test" {
			t.Fatalf("incorrect upstream metadata: %+v", q.UpstreamSelected)
		}
	})
}
