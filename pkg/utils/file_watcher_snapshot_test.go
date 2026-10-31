package utils

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileWatcherDetectsInitializationGapAndRetriesFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline := SnapshotFileStates([]string{path})
	// Simulate a change while the provider is parsing its initial file.
	if err := os.WriteFile(path, []byte("after-init-load"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	success := make(chan struct{})
	fw := StartFileWatcherFromSnapshot([]string{path}, baseline, 5*time.Millisecond, func(changed []string) bool {
		if len(changed) != 1 || changed[0] != path {
			t.Errorf("changed files = %v", changed)
		}
		if calls.Add(1) >= 2 {
			select {
			case <-success:
			default:
				close(success)
			}
			return true
		}
		return false
	})
	defer fw.Close()
	select {
	case <-success:
	case <-time.After(time.Second):
		t.Fatal("watcher lost edit or did not retry")
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("unexpected reload calls: %d", calls.Load())
	}
}

func TestWatcherDetectsSameSizeAndTimestampEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline := SnapshotFileStates([]string{path})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("bravo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	changed := make(chan struct{}, 1)
	fw := StartFileWatcherFromSnapshot([]string{path}, baseline, 10*time.Millisecond, func(paths []string) bool {
		if len(paths) != 1 || paths[0] != path {
			t.Errorf("unexpected changed paths %v", paths)
		}
		select {
		case changed <- struct{}{}:
		default:
		}
		return true
	})
	defer fw.Close()
	select {
	case <-changed:
	case <-time.After(2 * time.Second):
		t.Fatal("content edit with unchanged file metadata not detected")
	}
}
