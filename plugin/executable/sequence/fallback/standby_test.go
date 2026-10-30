package fallback

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// snapshotBarrierData pauses the first copy of a private RR, allowing the test
// to hold a successful primary between its completion signal and publication.
type snapshotBarrierData struct {
	onCopy func()
}

func (*snapshotBarrierData) String() string             { return "" }
func (*snapshotBarrierData) Parse([]string) error       { return nil }
func (*snapshotBarrierData) Pack([]byte) (int, error)   { return 0, nil }
func (*snapshotBarrierData) Unpack([]byte) (int, error) { return 0, nil }
func (*snapshotBarrierData) Len() int                   { return 0 }
func (r *snapshotBarrierData) Copy(dst dns.PrivateRdata) error {
	dst.(*snapshotBarrierData).onCopy = nil
	if r.onCopy != nil {
		r.onCopy()
	}
	return nil
}

func standbyTestResponse(c *query_context.Context, ip string) {
	r := new(dns.Msg).SetReply(c.Q())
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: c.QQuestion().Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip).To4()}}
	c.SetResponse(r)
}

func TestAlwaysStandbyRetainsSuccessfulPrimary(t *testing.T) {
	const rrType = 65534
	dns.PrivateHandle("FALLBACKBARRIER", rrType, func() dns.PrivateRdata { return new(snapshotBarrierData) })
	defer dns.PrivateHandleRemove(rrType)
	rr, err := dns.NewRR("example.org. 60 IN FALLBACKBARRIER barrier")
	if err != nil {
		t.Fatal(err)
	}
	copyStarted, releaseCopy := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCopy) }) }
	defer release()
	rr.(*dns.PrivateRR).Data.(*snapshotBarrierData).onCopy = func() {
		close(copyStarted)
		<-releaseCopy
	}
	secondaryReady := make(chan struct{})
	f := &fallback{
		logger: zap.NewNop(), alwaysStandby: true, fastFallbackDuration: time.Hour,
		primary: sequence.ExecutableFunc(func(_ context.Context, c *query_context.Context) error {
			<-secondaryReady
			standbyTestResponse(c, "192.0.2.1")
			c.R().Extra = append(c.R().Extra, rr)
			return nil
		}),
		secondary: sequence.ExecutableFunc(func(_ context.Context, c *query_context.Context) error {
			standbyTestResponse(c, "192.0.2.2")
			close(secondaryReady)
			return nil
		}),
	}
	q := query_context.NewContext(new(dns.Msg).SetQuestion("example.org.", dns.TypeA))
	result := make(chan error, 1)
	go func() { result <- f.Exec(context.Background(), q) }()
	select {
	case <-copyStarted:
	case <-time.After(time.Second):
		t.Fatal("primary did not reach response snapshot")
	}
	// The primary has completed successfully, but cannot publish until release.
	// A standby result must not be published merely because primDone closed.
	select {
	case err := <-result:
		t.Fatalf("standby replaced successful primary before threshold: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("primary response was not published")
	}
	if got := q.R().Answer[0].(*dns.A).A.String(); got != "192.0.2.1" {
		t.Fatalf("selected %s, want primary response", got)
	}
}

func TestAlwaysStandbyUsesSecondaryAfterPrimaryFailure(t *testing.T) {
	for _, primaryErr := range []error{nil, errors.New("primary failed")} {
		name := "no_response"
		if primaryErr != nil {
			name = "error"
		}
		t.Run(name, func(t *testing.T) {
			secondaryReady := make(chan struct{})
			f := &fallback{
				logger: zap.NewNop(), alwaysStandby: true, fastFallbackDuration: time.Hour,
				primary: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
					<-secondaryReady
					return primaryErr
				}),
				secondary: sequence.ExecutableFunc(func(_ context.Context, c *query_context.Context) error {
					standbyTestResponse(c, "192.0.2.2")
					close(secondaryReady)
					return nil
				}),
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			q := query_context.NewContext(new(dns.Msg).SetQuestion("example.org.", dns.TypeA))
			if err := f.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
			if got := q.R().Answer[0].(*dns.A).A.String(); got != "192.0.2.2" {
				t.Fatalf("selected %s, want secondary response", got)
			}
		})
	}
}

func TestAlwaysStandbyUsesSecondaryAfterThreshold(t *testing.T) {
	const threshold = 30 * time.Millisecond
	releasePrimary := make(chan struct{})
	defer close(releasePrimary)
	f := &fallback{
		logger: zap.NewNop(), alwaysStandby: true, fastFallbackDuration: threshold,
		primary: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
			<-releasePrimary
			return nil
		}),
		secondary: sequence.ExecutableFunc(func(_ context.Context, c *query_context.Context) error {
			standbyTestResponse(c, "192.0.2.2")
			return nil
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := query_context.NewContext(new(dns.Msg).SetQuestion("example.org.", dns.TypeA))
	start := time.Now()
	if err := f.Exec(ctx, q); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < threshold {
		t.Fatalf("standby returned after %v, before threshold %v", elapsed, threshold)
	}
	if got := q.R().Answer[0].(*dns.A).A.String(); got != "192.0.2.2" {
		t.Fatalf("selected %s, want secondary response", got)
	}
}
