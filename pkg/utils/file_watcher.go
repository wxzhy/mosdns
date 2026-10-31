package utils

import (
	"os"
	"sync"
	"time"
)

// FileWatcher periodically checks the state of the specified file paths.
type FileWatcher struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// StartFileWatcher starts a new FileWatcher that checks files every 'interval'.
// If any file modification time changes or a file is missing, onChange is triggered.
// Note: onChange must be safe to run concurrently with other components.
func StartFileWatcher(files []string, interval time.Duration, onChange func(changedFiles []string)) *FileWatcher {
	if onChange == nil {
		return nil
	}
	return StartFileWatcherFromSnapshot(files, nil, interval, func(changed []string) bool {
		onChange(changed)
		return true
	})
}

// SnapshotFileStates must run BEFORE loading the files. Passing its result to
// StartFileWatcherFromSnapshot closes the gap between initial load and watcher
// installation: an edit during loading is detected at the first poll.
func SnapshotFileStates(files []string) map[string]os.FileInfo {
	states := make(map[string]os.FileInfo, len(files))
	for _, file := range files {
		if file != "" {
			if _, ok := states[file]; !ok {
				states[file] = watchedFileInfo(file)
			}
		}
	}
	return states
}

// StartFileWatcherFromSnapshot retries a failed reload on the next poll. The
// callback returns true ONLY after the new state has been published.
func StartFileWatcherFromSnapshot(files []string, initial map[string]os.FileInfo, interval time.Duration, onChange func(changedFiles []string) bool) *FileWatcher {
	// Own the path list: callers may reuse their configuration after startup.
	paths := make([]string, 0, len(files))
	states := make(map[string]os.FileInfo, len(files))
	for _, file := range files {
		if file == "" {
			continue
		}
		if _, seen := states[file]; seen {
			continue
		}
		if info, exists := initial[file]; exists {
			states[file] = info
		} else {
			states[file] = watchedFileInfo(file)
		}
		paths = append(paths, file)
	}
	if len(paths) == 0 || onChange == nil {
		return nil
	}
	if interval <= 0 {
		interval = 3 * time.Second
	}
	fw := &FileWatcher{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go func() {
		defer close(fw.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-fw.stop:
				return
			case <-ticker.C:
				var changedFiles []string
				nextStates := make(map[string]os.FileInfo)
				for _, file := range paths {
					info := watchedFileInfo(file)
					if !sameWatchedFile(states[file], info) {
						nextStates[file] = info
						changedFiles = append(changedFiles, file)
					}
				}
				if len(changedFiles) > 0 {
					select {
					case <-fw.stop:
						return
					default:
					}
					if onChange(changedFiles) {
						for _, f := range changedFiles {
							states[f] = nextStates[f]
						}
					}
				}
			}
		}
	}()
	return fw
}

func watchedFileInfo(file string) os.FileInfo {
	info, _ := os.Stat(file)
	if info != nil {
		// Windows may resolve FileInfo's identity lazily through its path.
		// Resolve it now, before a later rename can replace that path.
		_ = os.SameFile(info, info)
	}
	return info
}

func sameWatchedFile(old, current os.FileInfo) bool {
	if old == nil || current == nil {
		return old == nil && current == nil
	}
	// File identity also detects atomic replacement with equal size and mtime.
	return os.SameFile(old, current) && old.ModTime().Equal(current.ModTime()) && old.Size() == current.Size() && old.Mode() == current.Mode()
}

// Close stops the FileWatcher and waits for an in-progress callback to finish.
// It is safe to call repeatedly or concurrently, but not from onChange itself.
func (fw *FileWatcher) Close() error {
	if fw != nil {
		fw.once.Do(func() { close(fw.stop) })
		<-fw.done
	}
	return nil
}
