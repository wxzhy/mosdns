package coremain

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

type startupCloser struct{ calls atomic.Int32 }

func (c *startupCloser) Close() error { c.calls.Add(1); return nil }

var startupPluginID atomic.Uint64

func registerStartupPlugin(t *testing.T, f NewPluginFunc) string {
	t.Helper()
	typ := fmt.Sprintf("startup_test_%s_%d", t.Name(), startupPluginID.Add(1))
	RegNewPluginFunc(typ, f, func() any { return new(struct{}) })
	t.Cleanup(func() { DelPluginType(typ) })
	return typ
}

func TestStartupRejectsBusyAPIBeforeLoadingPlugins(t *testing.T) {
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	var constructed atomic.Int32
	typ := registerStartupPlugin(t, func(*BP, any) (any, error) {
		constructed.Add(1)
		return new(startupCloser), nil
	})
	m, err := NewMosdns(&Config{API: APIConfig{HTTP: busy.Addr().String()}, Plugins: []PluginConfig{{Type: typ}}})
	if m != nil {
		m.CloseWithErr(nil)
		_ = m.GetSafeClose().WaitClosed()
	}
	if err == nil || m != nil {
		t.Errorf("busy API returned instance=%v error=%v, want initialization failure", m != nil, err)
	}
	if constructed.Load() != 0 {
		t.Errorf("constructed %d plugins despite API bind failure", constructed.Load())
	}
}

func TestStartupClosesPluginPublishedAfterShutdownSignal(t *testing.T) {
	want := errors.New("service failed while loading")
	closer := new(startupCloser)
	var laterConstructed atomic.Bool
	typ := registerStartupPlugin(t, func(bp *BP, _ any) (any, error) {
		bp.M().CloseWithErr(want)
		return closer, nil
	})
	later := registerStartupPlugin(t, func(*BP, any) (any, error) {
		laterConstructed.Store(true)
		return new(startupCloser), nil
	})
	m, err := NewMosdns(&Config{Plugins: []PluginConfig{{Tag: "late", Type: typ}, {Tag: "never", Type: later}}})
	if m != nil {
		m.CloseWithErr(nil)
		_ = m.GetSafeClose().WaitClosed()
	}
	if m != nil || !errors.Is(err, want) {
		t.Errorf("closed during initialization: instance=%v error=%v, want %v", m != nil, err, want)
	}
	if closer.calls.Load() != 1 {
		t.Errorf("late plugin Close calls=%d, want 1", closer.calls.Load())
	}
	if laterConstructed.Load() {
		t.Error("continued loading plugins after shutdown signal")
	}
}

func TestAPIDoesNotServeWhilePluginRoutesAreLoading(t *testing.T) {
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	reserved.Close()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	defer client.CloseIdleConnections()
	typ := registerStartupPlugin(t, func(bp *BP, _ any) (any, error) {
		resp, err := client.Get("http://" + addr + "/metrics")
		if err == nil {
			resp.Body.Close()
			t.Error("management API served a request before plugin initialization completed")
		}
		router := chi.NewRouter()
		router.Get("/ready", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		bp.RegAPI(router)
		return new(startupCloser), nil
	})
	m, err := NewMosdns(&Config{API: APIConfig{HTTP: addr}, Plugins: []PluginConfig{{Tag: "loaded", Type: typ}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { m.CloseWithErr(nil); _ = m.GetSafeClose().WaitClosed() }()
	readyClient := &http.Client{Timeout: time.Second}
	defer readyClient.CloseIdleConnections()
	resp, err := readyClient.Get("http://" + addr + "/plugins/loaded/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("loaded API route returned %d, want 204", resp.StatusCode)
	}
}

func TestStartupReleasesAPISocketOnPluginFailure(t *testing.T) {
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	reserved.Close()
	if m, err := NewMosdns(&Config{API: APIConfig{HTTP: addr}, Plugins: []PluginConfig{{Type: "missing_startup_test_plugin"}}}); err == nil || m != nil {
		if m != nil {
			m.CloseWithErr(nil)
			_ = m.GetSafeClose().WaitClosed()
		}
		t.Fatalf("invalid plugin returned instance=%v error=%v", m != nil, err)
	}
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("API socket still reserved after initialization failure: %v", err)
	}
	listener.Close()
}

type startupLookupWorker struct{ stop, done chan struct{} }

func (w *startupLookupWorker) Close() error {
	close(w.stop)
	<-w.done
	return nil
}

func TestStartupConcurrentPluginLookupAndFlush(t *testing.T) {
	readerType := registerStartupPlugin(t, func(bp *BP, _ any) (any, error) {
		worker := &startupLookupWorker{stop: make(chan struct{}), done: make(chan struct{})}
		started := make(chan struct{})
		go func() {
			defer close(worker.done)
			close(started)
			for {
				select {
				case <-worker.stop:
					return
				default:
					bp.M().GetPlugin("reader")
					bp.M().FlushAllCaches()
					runtime.Gosched()
				}
			}
		}()
		<-started
		return worker, nil
	})
	valueType := registerStartupPlugin(t, func(*BP, any) (any, error) {
		runtime.Gosched()
		return new(startupCloser), nil
	})
	plugins := []PluginConfig{{Tag: "reader", Type: readerType}}
	for i := 0; i < 64; i++ {
		plugins = append(plugins, PluginConfig{Tag: fmt.Sprintf("value_%d", i), Type: valueType})
	}
	m, err := NewMosdns(&Config{Plugins: plugins})
	if err != nil {
		t.Fatal(err)
	}
	m.CloseWithErr(nil)
	if err := m.GetSafeClose().WaitClosed(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		closer := m.GetPlugin(fmt.Sprintf("value_%d", i)).(*startupCloser)
		if closer.calls.Load() != 1 {
			t.Fatalf("plugin %d closed %d times, want 1", i, closer.calls.Load())
		}
	}
}
