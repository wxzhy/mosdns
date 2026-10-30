package coremain

import (
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"go.uber.org/zap"
)

var loggerTestSinkID atomic.Uint64

type lifecycleSink struct {
	closed atomic.Uint32
}

func (s *lifecycleSink) Write(p []byte) (int, error) { return len(p), nil }
func (s *lifecycleSink) Sync() error                 { return nil }
func (s *lifecycleSink) Close() error {
	s.closed.Add(1)
	return nil
}

func TestInstanceReleasesLogSink(t *testing.T) {
	for _, failInit := range []bool{false, true} {
		t.Run(fmt.Sprintf("initialization_failure=%v", failInit), func(t *testing.T) {
			sink := new(lifecycleSink)
			scheme := fmt.Sprintf("mosdnslogtest%d", loggerTestSinkID.Add(1))
			if err := zap.RegisterSink(scheme, func(*url.URL) (zap.Sink, error) { return sink, nil }); err != nil {
				t.Fatal(err)
			}
			cfg := &Config{Log: mlog.LogConfig{Level: "info", File: scheme + "://log"}}
			if failInit {
				cfg.Plugins = []PluginConfig{{Tag: "invalid", Type: "unknown_logger_lifecycle_test_type"}}
			}
			m, err := NewMosdns(cfg)
			if failInit {
				if err == nil {
					t.Fatal("invalid plugin unexpectedly initialized")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if sink.closed.Load() != 0 {
					t.Fatal("log sink closed while instance was running")
				}
				m.CloseWithErr(nil)
				if err := m.GetSafeClose().WaitClosed(); err != nil {
					t.Fatal(err)
				}
			}
			if got := sink.closed.Load(); got != 1 {
				t.Fatalf("log sink closed %d times, want exactly once", got)
			}
		})
	}
}
