package mlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"go.uber.org/zap"
)

func TestHistoricalLogSizeAndDefaults(t *testing.T) {
	for input, want := range map[string]int64{
		"": 5 << 20, "1": 1 << 20, "10M": 10 << 20, "2k": 2 << 10,
		"3 KB": 3 << 10, "2MB": 2 << 20, "1G": 1 << 30, "1TB": 1 << 40,
		"0": 0, "-1M": -1 << 20,
	} {
		t.Run(input, func(t *testing.T) {
			got, err := ParseSize(input)
			if err != nil || got != want {
				t.Fatalf("ParseSize(%q) = %d, %v; want %d", input, got, err, want)
			}
		})
	}
	for _, input := range []string{"1B", "invalid", "1.5M", "M", "8796093022208M", "-8796093022209M", "8388608T"} {
		if _, err := ParseSize(input); err == nil {
			t.Errorf("invalid size accepted: %q", input)
		}
	}
	var cfg LogConfig
	if err := json.Unmarshal([]byte(`{"level":"info","file":"mosdns.log","size":"1"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Size != "1" || cfg.Backups != 0 {
		t.Fatalf("historical JSON configuration changed: %+v", cfg)
	}
	for _, input := range []any{"1", 1} {
		var decoded LogConfig
		if err := utils.WeakDecode(map[string]any{"level": "info", "size": input}, &decoded); err != nil || decoded.Size != "1" {
			t.Fatalf("weak decode size %v = %+v, %v", input, decoded, err)
		}
	}
}

func TestRotatorRetentionPreservesCompleteRecords(t *testing.T) {
	for _, backups := range []int{0, 2, -1} {
		t.Run(fmt.Sprintf("backups=%d", backups), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "app.log")
			r := &Rotator{Filename: path, MaxSize: 8, MaxBackups: backups}
			t.Cleanup(func() { _ = r.Close() })
			for i := range 6 {
				line := fmt.Sprintf("row-%03d\n", i)
				if n, err := r.Write([]byte(line)); err != nil || n != len(line) {
					t.Fatalf("write %d: %d, %v", i, n, err)
				}
			}
			if err := r.Sync(); err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
			files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "app-*.log"))
			if err != nil {
				t.Fatal(err)
			}
			wantBackups := backups
			if backups < 0 {
				wantBackups = 5
			}
			if len(files) != wantBackups {
				t.Fatalf("kept %d backups, want %d: %v", len(files), wantBackups, files)
			}
			files = append(files, path)
			wantStart := 5 - wantBackups
			for i, file := range files {
				data, err := os.ReadFile(file)
				want := fmt.Sprintf("row-%03d\n", wantStart+i)
				if err != nil || string(data) != want {
					t.Fatalf("%s contains %q, %v; want %q", file, data, err, want)
				}
			}
		})
	}
}

func TestRotatorExternalTruncationNeverPadsWithNUL(t *testing.T) {
	for _, limit := range []int64{8, 64} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mosdns.log")
			r := &Rotator{Filename: path, MaxSize: limit, MaxBackups: 2}
			t.Cleanup(func() { _ = r.Close() })
			if _, err := r.Write([]byte("abcdef\n")); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Write([]byte("next\n")); err != nil {
				t.Fatal(err)
			}
			if err := r.Sync(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "next\n" || bytes.ContainsRune(data, 0) {
				t.Fatalf("external truncate left holes: %q, %v", data, err)
			}
			files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "mosdns-*.log"))
			if len(files) != 0 {
				t.Fatalf("external truncation triggered an unnecessary backup: %v", files)
			}
		})
	}
}

func TestLoggerRotationProductionTimeAndCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "json.log")
	logger, cleanup, err := NewLoggerWithCleanup(LogConfig{Level: "info", File: path, Size: "1K", Backups: 2, Production: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	for i := range 8 {
		logger.Info("production", zap.Int("row", i), zap.String("payload", strings.Repeat("x", 450)))
	}
	cleanup()
	cleanup()
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "json-*.log"))
	if len(files) != 2 {
		t.Fatalf("production logger kept %d backups, want 2", len(files))
	}
	for _, file := range append(files, path) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			var entry map[string]any
			if err := json.Unmarshal(line, &entry); err != nil || entry["msg"] != "production" {
				t.Fatalf("invalid JSON record: %q, %v", line, err)
			}
			stamp, ok := entry["ts"].(string)
			if !ok {
				t.Fatalf("timestamp is not the original formatted string: %v", entry)
			}
			if _, err := time.ParseInLocation("2006-01-02 15:04:05", stamp, time.Local); err != nil {
				t.Fatalf("timestamp format changed: %q", stamp)
			}
		}
	}
	// Removing after cleanup must work on Windows too: no open sink remains.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func TestRotatorConcurrentWritesAndTerminalClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.log")
	r := &Rotator{Filename: path, MaxSize: 32, MaxBackups: -1}
	t.Cleanup(func() { _ = r.Close() })
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 10 {
				line := fmt.Sprintf("%d-%02d\n", i, j)
				if _, err := r.Write([]byte(line)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	_ = r.Close()
	if _, err := r.Write([]byte("after close\n")); err != os.ErrClosed {
		t.Fatalf("closed rotator reopened its sink: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "concurrent*.log"))
	seen := make(map[string]bool)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if seen[line] {
				t.Fatalf("duplicate record %q", line)
			}
			seen[line] = true
		}
	}
	if len(seen) != 40 {
		t.Fatalf("lost concurrent records: got %d, want 40", len(seen))
	}
}

func TestLoggerFailsToOpenUnusablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if logger, cleanup, err := NewLoggerWithCleanup(LogConfig{File: filepath.Join(path, "log.txt"), Size: "1"}); err == nil {
		cleanup()
		_ = logger.Sync()
		t.Fatal("unusable log file unexpectedly opened")
	}
	if data, _ := os.ReadFile(path); string(data) != "keep me" {
		t.Fatal("failed logger initialization changed an existing file")
	}
}
