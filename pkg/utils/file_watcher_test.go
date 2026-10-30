package utils

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileWatcherCloseWaitsForCallbackAndIsConcurrentSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	paths := []string{path}
	fw := StartFileWatcher(paths, 5*time.Millisecond, func(changed []string) {
		if len(changed) != 1 || changed[0] != path {
			t.Errorf("changed paths = %v", changed)
		}
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
	})
	defer fw.Close()
	paths[0] = "caller changed this slice"
	if err := os.WriteFile(path, []byte("new content"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("file edit did not trigger callback")
	}
	closed := make(chan struct{})
	go func() { _ = fw.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned before active callback completed")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after callback completed")
	}
	var closers sync.WaitGroup
	for range 8 {
		closers.Add(1)
		go func() { defer closers.Done(); _ = fw.Close() }()
	}
	closers.Wait()
	if err := os.WriteFile(path, []byte("after close"), 0o600); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("callback count after Close = %d", calls.Load())
	}
}
